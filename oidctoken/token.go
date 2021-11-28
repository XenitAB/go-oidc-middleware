package oidctoken

import (
	"context"

	"github.com/lestrrat-go/jwx/jwt"
	"github.com/xenitab/go-oidc-middleware/internal/oidc"
	"github.com/xenitab/go-oidc-middleware/options"
)

// TokenHandler is used to parse tokens.
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

// ParseToken takes a context and a string and returns a jwt.Token or an error.
// jwt.Token is from `github.com/lestrrat-go/jwx/jwt`.
func (t *TokenHandler) ParseToken(ctx context.Context, tokenString string) (jwt.Token, error) {
	token, err := t.parseTokenFunc(ctx, tokenString)
	if err != nil {
		return nil, err
	}

	return token, nil
}

// GetTokenString takes a GetHeaderFn `func(key string) string` and [][]options.TokenStringOption and
// returns the token as an string or an error.
func GetTokenString(getHeaderFn oidc.GetHeaderFn, tokenStringOpts [][]options.TokenStringOption) (string, error) {
	return oidc.GetTokenString(getHeaderFn, tokenStringOpts)
}
