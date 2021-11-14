package oidctoken

import (
	"context"

	"github.com/xenitab/go-oidc-middleware/internal/oidc"
	"github.com/xenitab/go-oidc-middleware/options"
)

type TokenHandler struct {
	parseTokenFunc oidc.ParseTokenFunc
	tokenOptions   *options.Options
}

// New returns an OpenID Connect (OIDC) discovery token handler.
// Can be used to create your own middleware.
func New(setters ...options.Option) (*TokenHandler, error) {
	oidcHandler, err := oidc.NewHandler(setters...)
	if err != nil {
		return nil, err
	}

	tokenOpts := options.New(setters...)

	return &TokenHandler{
		parseTokenFunc: oidcHandler.ParseToken,
		tokenOptions:   tokenOpts,
	}, nil
}

func (t *TokenHandler) ParseToken(ctx context.Context, tokenString string) (map[string]interface{}, error) {
	token, err := t.parseTokenFunc(ctx, tokenString)
	if err != nil {
		return nil, err
	}

	tokenClaims, err := token.AsMap(ctx)
	if err != nil {
		return nil, err
	}

	return tokenClaims, nil
}

func (t *TokenHandler) GetTokenString(getHeaderFn oidc.GetHeaderFn) (string, error) {
	return oidc.GetTokenString(getHeaderFn, t.tokenOptions.TokenString)
}
