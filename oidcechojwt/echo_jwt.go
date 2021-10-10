package oidcechojwt

import (
	"fmt"

	"github.com/labstack/echo/v4"
	"github.com/xenitab/go-oidc-middleware/internal/oidc"
	"github.com/xenitab/go-oidc-middleware/options"
)

// New returns an OpenID Connect (OIDC) discovery `ParseTokenFunc`
// to be used with the the echo `JWT` middleware.
func New(setters ...options.Option) func(auth string, c echo.Context) (interface{}, error) {
	h, err := oidc.NewHandler(setters...)
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

func toEchoJWTParseTokenFunc(parseToken oidc.ParseTokenFunc, setters ...options.Option) echoJWTParseTokenFunc {
	opts := options.New(setters...)

	echoJWTParseTokenFunc := func(auth string, c echo.Context) (interface{}, error) {
		ctx := c.Request().Context()

		token, err := parseToken(ctx, auth)
		if err != nil {
			onError(opts.ErrorHandler, options.ParseTokenErrorDescription, err)
			return nil, err
		}

		tokenClaims, err := token.AsMap(ctx)
		if err != nil {
			onError(opts.ErrorHandler, options.ConvertTokenErrorDescription, err)
			return nil, err
		}

		return tokenClaims, nil
	}

	return echoJWTParseTokenFunc
}
