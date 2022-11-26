package oidcechojwt

import (
	"fmt"

	"github.com/labstack/echo/v4"
	"github.com/xenitab/go-oidc-middleware/internal/oidc"
	"github.com/xenitab/go-oidc-middleware/options"
)

// New returns an OpenID Connect (OIDC) discovery `ParseTokenFunc`
// to be used with the the echo `JWT` middleware.
func New[T any](claimsValidationFn options.ClaimsValidationFn[T], setters ...options.Option) func(auth string, c echo.Context) (interface{}, error) {
	h, err := oidc.NewHandler(claimsValidationFn, setters...)
	if err != nil {
		panic(fmt.Sprintf("oidc discovery: %v", err))
	}

	return toEchoJWTParseTokenFunc(h.ParseToken, setters...)
}

type echoJWTParseTokenFunc func(auth string, c echo.Context) (interface{}, error)

func onError(errorHandler options.ErrorHandler, description options.ErrorDescription, err error) {
	if errorHandler != nil {
		errorHandler(description, err)
	}
}

func toEchoJWTParseTokenFunc[T any](parseToken oidc.ParseTokenFunc[T], setters ...options.Option) echoJWTParseTokenFunc {
	opts := options.New(setters...)

	echoJWTParseTokenFunc := func(auth string, c echo.Context) (interface{}, error) {
		ctx := c.Request().Context()

		claims, err := parseToken(ctx, auth)
		if err != nil {
			onError(opts.ErrorHandler, options.ParseTokenErrorDescription, err)
			return nil, err
		}

		return claims, nil
	}

	return echoJWTParseTokenFunc
}
