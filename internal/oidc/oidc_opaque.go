package oidc

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/lestrrat-go/jwx/jwt"
	"github.com/xenitab/go-oidc-middleware/options"
)

type opaqueHandler struct {
	userinfoUri    string
	tokenTTL       time.Duration
	requiredClaims map[string]interface{}
	httpClient     *http.Client
}

func NewOpaqueHandler(setters ...options.OpaqueOption) (*opaqueHandler, error) {
	opts := options.NewOpaque(setters...)

	var (
		issuer       = opts.Issuer
		discoveryUri = opts.DiscoveryUri
	)

	h := &opaqueHandler{
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

func (h *opaqueHandler) ParseToken(ctx context.Context, tokenString string) (jwt.Token, error) {
	if h.requiredClaims != nil {
		// FIXME: get the claims
		tokenClaims := map[string]interface{}{}

		err := isRequiredClaimsValid(h.requiredClaims, tokenClaims)
		if err != nil {
			return nil, fmt.Errorf("unable to validate required claims: %w", err)
		}
	}

	return token, nil
}
