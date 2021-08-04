package oidc

import (
	"fmt"

	"github.com/labstack/echo/v4"
)

// New returns an OpenID Connect (OIDC) discovery `ParseTokenFunc` to be used
// with the `JWT` middleware.
// See: https://openid.net/connect/
func NewEchoJWTParseTokenFunc(opts *Options) func(auth string, c echo.Context) (interface{}, error) {
	h, err := newHandler(opts)
	if err != nil {
		panic(fmt.Sprintf("oidc discovery: %v", err))
	}

	return toEchoJWTParseTokenFunc(h.parseToken)
}

type echoJWTParseTokenFunc func(auth string, c echo.Context) (interface{}, error)

func toEchoJWTParseTokenFunc(parseToken parseTokenFunc) echoJWTParseTokenFunc {
	echoJWTParseTokenFunc := func(auth string, c echo.Context) (interface{}, error) {
		ctx := c.Request().Context()

		return parseToken(ctx, auth)
	}

	return echoJWTParseTokenFunc
}
