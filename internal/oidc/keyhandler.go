package oidc

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/jwk"
	"go.uber.org/ratelimit"
	"golang.org/x/sync/semaphore"
)

type keyHandler struct {
	sync.RWMutex
	jwksURI            string
	disableKeyID       bool
	keySet             jwk.Set
	fetchTimeout       time.Duration
	keyUpdateSemaphore *semaphore.Weighted
	keyUpdateChannel   chan keyUpdate
	keyUpdateCount     int
	keyUpdateLimiter   ratelimit.Limiter
	httpClient         *http.Client
}

type keyUpdate struct {
	keySet jwk.Set
	err    error
}

func newKeyHandler(httpClient *http.Client, jwksUri string, fetchTimeout time.Duration, keyUpdateRPS uint, disableKeyID bool) (*keyHandler, error) {
	h := &keyHandler{
		jwksURI:            jwksUri,
		disableKeyID:       disableKeyID,
		fetchTimeout:       fetchTimeout,
		keyUpdateSemaphore: semaphore.NewWeighted(int64(1)),
		keyUpdateChannel:   make(chan keyUpdate),
		keyUpdateLimiter:   ratelimit.New(int(keyUpdateRPS)),
		httpClient:         httpClient,
	}

	ctx := context.Background()

	_, err := h.updateKeySet(ctx)
	if err != nil {
		return nil, err
	}

	return h, nil
}

func (h *keyHandler) updateKeySet(ctx context.Context) (jwk.Set, error) {
	ctx, cancel := context.WithTimeout(ctx, h.fetchTimeout)
	defer cancel()
	keySet, err := jwk.Fetch(ctx, h.jwksURI, jwk.WithHTTPClient(h.httpClient))
	if err != nil {
		return nil, fmt.Errorf("unable to fetch keys from %q: %w", h.jwksURI, err)
	}

	if h.disableKeyID && keySet.Len() != 1 {
		return nil, fmt.Errorf("keyID is disabled, but received a keySet with more than one key: %d", keySet.Len())
	}

	h.Lock()
	h.keySet = keySet
	h.keyUpdateCount++
	h.Unlock()

	return keySet, nil
}

// waitForUpdateKeySetSet handles concurrent requests to update the jwks as well as rate limiting.
func (h *keyHandler) waitForUpdateKeySetAndGetKeySet(ctx context.Context) (jwk.Set, error) {
	// ok will be false if there's already an update in progress.
	ok := h.keyUpdateSemaphore.TryAcquire(1)
	if ok {
		defer h.keyUpdateSemaphore.Release(1)
		_ = h.keyUpdateLimiter.Take()
		keySet, err := h.updateKeySet(ctx)

		result := keyUpdate{
			keySet,
			err,
		}

		// start go routine to handle all requests waiting for result.
		go func(res keyUpdate) {
			// for each request waiting for update, send result to them.
			for {
				select {
				case h.keyUpdateChannel <- res:
				default:
					return
				}
			}
		}(result)

		return keySet, err
	}

	// wait for the request that is updating keys and return the result from it
	result := <-h.keyUpdateChannel
	return result.keySet, result.err
}

func (h *keyHandler) waitForUpdateKeySetAndGetKey(ctx context.Context) (jwk.Key, error) {
	keySet, err := h.waitForUpdateKeySetAndGetKeySet(ctx)
	if err != nil {
		return nil, err
	}

	key, found := keySet.Get(0)
	if !found {
		return nil, fmt.Errorf("no key found")
	}

	return key, nil
}

func (h *keyHandler) getKey(ctx context.Context, keyID string) (jwk.Key, error) {
	if h.disableKeyID {
		return h.getKeyWithoutKeyID()
	}

	return h.getKeyFromID(ctx, keyID)
}

func (h *keyHandler) getKeySet() jwk.Set {
	h.RLock()
	defer h.RUnlock()
	return h.keySet
}

func (h *keyHandler) getKeyFromID(ctx context.Context, keyID string) (jwk.Key, error) {
	keySet := h.getKeySet()

	key, found := keySet.LookupKeyID(keyID)

	if !found {
		updatedKeySet, err := h.waitForUpdateKeySetAndGetKeySet(ctx)
		if err != nil {
			return nil, fmt.Errorf("unable to update key set for key %q: %w", keyID, err)
		}

		updatedKey, found := updatedKeySet.LookupKeyID(keyID)
		if !found {
			return nil, fmt.Errorf("unable to find key %q", keyID)
		}

		return updatedKey, nil
	}

	return key, nil
}

func (h *keyHandler) getKeyWithoutKeyID() (jwk.Key, error) {
	keySet := h.getKeySet()

	key, found := keySet.Get(0)
	if !found {
		return nil, fmt.Errorf("no key found")
	}

	return key, nil
}
