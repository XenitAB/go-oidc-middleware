package oidctoken

import (
	"context"

	"github.com/xenitab/go-oidc-middleware/internal/oidc"
	"github.com/xenitab/go-oidc-middleware/options"
)

// TokenHandler is used to parse tokens.
type TokenHandler[T any] struct {
	parseTokenFunc oidc.ParseTokenFunc[T]
	tokenOptions   *options.Options
}

// New returns an OpenID Connect (OIDC) discovery token handler.
// Can be used to create your own middleware.
func New[T any](claimsValidationFn options.ClaimsValidationFn[T], setters ...options.Option) (*TokenHandler[T], error) {
	oidcHandler, err := oidc.NewHandler(claimsValidationFn, setters...)
	if err != nil {
		return nil, err
	}

	tokenOpts := options.New(setters...)

	return &TokenHandler[T]{
		parseTokenFunc: oidcHandler.ParseToken,
		tokenOptions:   tokenOpts,
	}, nil
}

// ParseToken takes a context and a string and returns a jwt.Token or an error.
// jwt.Token is from `github.com/lestrrat-go/jwx/jwt`.
func (t *TokenHandler[T]) ParseToken(ctx context.Context, tokenString string) (T, error) {
	claims, err := t.parseTokenFunc(ctx, tokenString)
	if err != nil {
		return *new(T), err
	}

	return claims, nil
}

// GetTokenString takes a GetHeaderFn `func(key string) string` and [][]options.TokenStringOption and
// returns the token as an string or an error.
func GetTokenString(getHeaderFn oidc.GetHeaderFn, tokenStringOpts [][]options.TokenStringOption) (string, error) {
	return oidc.GetTokenString(getHeaderFn, tokenStringOpts)
}
