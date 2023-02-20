package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/xenitab/go-oidc-middleware/options"
)

type opaqueToken[T any] struct {
	claims  T
	created time.Time
}

type opaqueTokenCache[T any] struct {
	timeToLive time.Duration
	tokens     map[string]opaqueToken[T]
	mu         sync.RWMutex
}

func (c *opaqueTokenCache[T]) set(key string, value T) {
	c.mu.Lock()
	c.tokens[key] = opaqueToken[T]{
		claims:  value,
		created: time.Now(),
	}
	c.mu.Unlock()
}

func (c *opaqueTokenCache[T]) get(key string) (T, bool) {
	c.mu.RLock()
	now := time.Now()
	for k, v := range c.tokens {
		tokenExpiration := v.created.Add(c.timeToLive)
		if tokenExpiration.After(now) {
			delete(c.tokens, k)
		}
	}
	value, ok := c.tokens[key]
	c.mu.RUnlock()
	return value.claims, ok
}

type opaqueHandler[T any] struct {
	introspectionUri          string
	introspectionFetchTimeout time.Duration
	tokenCache                *opaqueTokenCache[T]
	tokenCacheEnabled         bool
	httpClient                *http.Client
	claimsValidationFn        options.ClaimsValidationFn[T]
}

func NewOpaqueHandler[T any](claimsValidationFn options.ClaimsValidationFn[T], setters ...options.OpaqueOption) (*opaqueHandler[T], error) {
	opts := options.NewOpaque(setters...)
	h := &opaqueHandler[T]{
		introspectionUri:          opts.IntrospectionUri,
		introspectionFetchTimeout: opts.IntrospectionFetchTimeout,
		tokenCache: &opaqueTokenCache[T]{
			timeToLive: opts.TokenCacheTimeToLive,
		},
		tokenCacheEnabled:  opts.TokenCacheTimeToLive != 0,
		httpClient:         opts.HttpClient,
		claimsValidationFn: claimsValidationFn,
	}

	err := h.populateIntrospectionUri(opts.Issuer, opts.DiscoveryUri, opts.DiscoveryFetchTimeout)
	if err != nil {
		return nil, err
	}

	return h, nil
}

func (h *opaqueHandler[T]) populateIntrospectionUri(issuerUri string, discoveryUri string, discoveryFetchTimeout time.Duration) error {
	if h.introspectionUri != "" {
		return nil
	}

	if issuerUri == "" && discoveryUri == "" {
		return fmt.Errorf("issuer and discoveryUri are both empty")
	}

	if discoveryUri == "" {
		discoveryUri = GetDiscoveryUriFromIssuer(issuerUri)
	}

	metadata, err := getOidcMetadataFromDiscoveryUri(h.httpClient, discoveryUri, discoveryFetchTimeout)
	if err != nil {
		return fmt.Errorf("unable to fetch userinfo_endpoint from discoveryUri (%s): %w", discoveryUri, err)
	}

	if metadata.UserinfoEndpoint == "" {
		return fmt.Errorf("UserinfoEndpoint is empty")
	}

	h.introspectionUri = metadata.UserinfoEndpoint

	return nil
}

func (h *opaqueHandler[T]) ParseToken(ctx context.Context, tokenString string) (T, error) {
	if h.tokenCacheEnabled {
		claims, ok := h.tokenCache.get(tokenString)
		if ok {
			return claims, nil
		}
	}

	claims, err := h.introspectToken(ctx, tokenString)
	if err != nil {
		return *new(T), fmt.Errorf("unable to introspect the token: %w", err)
	}

	err = h.validateClaims(&claims)
	if err != nil {
		return *new(T), fmt.Errorf("claims validation returned an error: %w", err)
	}

	if h.tokenCacheEnabled {
		h.tokenCache.set(tokenString, claims)
	}

	return claims, nil
}

func (h *opaqueHandler[T]) validateClaims(claims *T) error {
	if h.claimsValidationFn == nil {
		return nil
	}

	return h.claimsValidationFn(claims)
}

func (h *opaqueHandler[T]) introspectToken(ctx context.Context, tokenString string) (T, error) {
	ctx, cancel := context.WithTimeout(ctx, h.introspectionFetchTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.introspectionUri, http.NoBody)
	if err != nil {
		return *new(T), err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", tokenString))

	res, err := h.httpClient.Do(req)
	if err != nil {
		return *new(T), err
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return *new(T), err
	}

	err = res.Body.Close()
	if err != nil {
		return *new(T), err
	}

	claims := *new(T)
	err = json.Unmarshal(body, &claims)
	if err != nil {
		return *new(T), err
	}

	return claims, nil
}
