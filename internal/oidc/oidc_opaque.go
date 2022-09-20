package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/xenitab/go-oidc-middleware/options"
)

type opaqueHandler[T any] struct {
	userinfoUri          string
	userinfoFetchTimeout time.Duration
	httpClient           *http.Client
	claimsCache          *claimsCache[T]
	claimsValidator      func(ctx context.Context, claims T) error
}

func NewOpaqueHandler[T any](setters ...options.OpaqueOption[T]) (*opaqueHandler[T], error) {
	opts := options.NewOpaque(setters...)

	var (
		issuer       = opts.Issuer
		discoveryUri = opts.DiscoveryUri
	)

	h := &opaqueHandler[T]{
		userinfoUri:          opts.UserinfoUri,
		userinfoFetchTimeout: opts.UserinfoFetchTimeout,
		httpClient:           opts.HttpClient,
		claimsCache:          newClaimsCache[T](opts.TokenTTL),
		claimsValidator:      opts.ClaimsValidator,
	}

	if h.userinfoUri == "" {
		if discoveryUri == "" {
			if issuer == "" {
				return nil, fmt.Errorf("issuer is empty")
			}
			discoveryUri = GetDiscoveryUriFromIssuer(issuer)
		}

		metadata, err := getMetadataFromDiscoveryUri(h.httpClient, discoveryUri, opts.DiscoveryFetchTimeout)
		if err != nil {
			return nil, fmt.Errorf("unable to fetch UserinfoEndpoint from discoveryUri (%s): %w", discoveryUri, err)
		}
		if metadata.UserinfoEndpoint == "" {
			return nil, fmt.Errorf("received UserinfoEndpoint is empty")
		}
		h.userinfoUri = metadata.UserinfoEndpoint
	}

	return h, nil
}

type ParseOpaqueTokenFunc[T any] func(ctx context.Context, tokenString string) (T, error)

func (h *opaqueHandler[T]) ParseToken(ctx context.Context, tokenString string) (T, error) {
	cachedToken, cachedErr, ok := h.claimsCache.get(tokenString)
	if ok {
		return cachedToken, cachedErr
	}

	claims, err := h.parseToken(ctx, tokenString)
	h.claimsCache.set(tokenString, claims, err)

	return claims, err
}

func (h *opaqueHandler[T]) parseToken(ctx context.Context, tokenString string) (T, error) {
	claims, err := h.fetchClaims(ctx, tokenString)
	if err != nil {
		return *new(T), err
	}

	if h.claimsValidator != nil {
		err := h.claimsValidator(ctx, claims)
		if err != nil {
			return *new(T), err
		}
	}

	return claims, nil
}

func (h *opaqueHandler[T]) fetchClaims(ctx context.Context, tokenString string) (T, error) {
	ctx, cancel := context.WithTimeout(ctx, h.userinfoFetchTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.userinfoUri, http.NoBody)
	if err != nil {
		return *new(T), err
	}

	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", tokenString))

	res, err := h.httpClient.Do(req)
	if err != nil {
		return *new(T), err
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return *new(T), err
	}
	defer res.Body.Close()

	var userinfo T
	err = json.Unmarshal(body, &userinfo)
	if err != nil {
		return *new(T), err
	}

	return userinfo, nil
}

func (h *opaqueHandler[T]) getClaimsMap(claims T) (map[string]interface{}, error) {
	marshalledClaims, err := json.Marshal(claims)
	if err != nil {
		return nil, err
	}

	var claimsMap map[string]interface{}
	err = json.Unmarshal(marshalledClaims, &claimsMap)
	if err != nil {
		return nil, err
	}

	return claimsMap, nil
}
