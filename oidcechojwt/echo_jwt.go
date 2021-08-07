package oidcechojwt

import (
	"fmt"

	"github.com/labstack/echo/v4"
	"github.com/xenitab/go-oidc-middleware/internal/oidc"
)

// Options takes an oidc.Options struct.
type Options oidc.Options

// New returns an OpenID Connect (OIDC) discovery `ParseTokenFunc`
// to be used with the the echo `JWT` middleware.
func New(opts *Options) func(auth string, c echo.Context) (interface{}, error) {
	oidcOpts := oidc.Options(*opts)

	h, err := oidc.NewHandler(&oidcOpts)
	if err != nil {
		panic(fmt.Sprintf("oidc discovery: %v", err))
	}

	return toEchoJWTParseTokenFunc(h.ParseToken)
}

type echoJWTParseTokenFunc func(auth string, c echo.Context) (interface{}, error)

func toEchoJWTParseTokenFunc(parseToken oidc.ParseTokenFunc) echoJWTParseTokenFunc {
	echoJWTParseTokenFunc := func(auth string, c echo.Context) (interface{}, error) {
		ctx := c.Request().Context()

		return parseToken(ctx, auth)
	}

	return echoJWTParseTokenFunc
}
