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
	issuer                string
	discoveryUri          string
	discoveryFetchTimeout time.Duration
	userinfoEndpoint      string
	httpClient            *http.Client
	claimsValidationFn    options.ClaimsValidationFn[T]
}

func NewOpaqueHandler[T any](claimsValidationFn options.ClaimsValidationFn[T], setters ...options.OpaqueOption) (*opaqueHandler[T], error) {
	opts := options.NewOpaque(setters...)
	h := &opaqueHandler[T]{
		issuer:                opts.Issuer,
		discoveryUri:          opts.DiscoveryUri,
		discoveryFetchTimeout: opts.DiscoveryFetchTimeout,
		httpClient:            opts.HttpClient,
		claimsValidationFn:    claimsValidationFn,
	}

	if h.issuer == "" {
		return nil, fmt.Errorf("issuer is empty")
	}

	if h.discoveryUri == "" {
		h.discoveryUri = GetDiscoveryUriFromIssuer(h.issuer)
	}

	metadata, err := getOidcMetadataFromDiscoveryUri(h.httpClient, h.discoveryUri, h.discoveryFetchTimeout)
	if err != nil {
		return nil, fmt.Errorf("unable to fetch userinfo_endpoint from discoveryUri (%s): %w", h.discoveryUri, err)
	}
	if metadata.UserinfoEndpoint == "" {
		return nil, fmt.Errorf("UserinfoEndpoint is empty")
	}
	h.userinfoEndpoint = metadata.UserinfoEndpoint

	return h, nil
}

func (h *opaqueHandler[T]) ParseToken(ctx context.Context, tokenString string) (T, error) {
	claims, err := h.introspectToken(ctx, tokenString)
	if err != nil {
		return *new(T), fmt.Errorf("unable to introspect the token: %w", err)
	}

	err = h.validateClaims(&claims)
	if err != nil {
		return *new(T), fmt.Errorf("claims validation returned an error: %w", err)
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
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.userinfoEndpoint, http.NoBody)
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
