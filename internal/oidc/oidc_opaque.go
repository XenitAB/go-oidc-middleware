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
	userinfoUri    string
	tokenTTL       time.Duration
	requiredClaims map[string]interface{}
	httpClient     *http.Client
}

func NewOpaqueHandler[T any](setters ...options.OpaqueOption) (*opaqueHandler[T], error) {
	opts := options.NewOpaque(setters...)

	var (
		issuer       = opts.Issuer
		discoveryUri = opts.DiscoveryUri
	)

	h := &opaqueHandler[T]{
		userinfoUri:    opts.UserinfoUri,
		tokenTTL:       opts.TokenTTL,
		requiredClaims: opts.RequiredClaims,
		httpClient:     opts.HttpClient,
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

func (h *opaqueHandler[T]) ParseToken(ctx context.Context, tokenString string) (T, error) {
	claims, err := h.getClaims(ctx, tokenString)
	if err != nil {
		return h.emptyT(), err
	}

	if h.requiredClaims != nil {
		claimsMap, err := h.getClaimsMap(claims)
		if err != nil {
			return h.emptyT(), err
		}

		err = isRequiredClaimsValid(h.requiredClaims, claimsMap)
		if err != nil {
			return h.emptyT(), fmt.Errorf("unable to validate required claims: %w", err)
		}
	}

	return claims, nil
}

func (h *opaqueHandler[T]) emptyT() T {
	return *new(T)
}

func (h *opaqueHandler[T]) getClaims(ctx context.Context, tokenString string) (T, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.userinfoUri, http.NoBody)
	if err != nil {
		return h.emptyT(), err
	}

	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", tokenString))

	res, err := h.httpClient.Do(req)
	if err != nil {
		return h.emptyT(), err
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return h.emptyT(), err
	}
	defer res.Body.Close()

	var userinfo T
	err = json.Unmarshal(body, &userinfo)
	if err != nil {
		return h.emptyT(), err
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
