package oidcecho

import (
	"fmt"

	"github.com/labstack/echo/v4"
	"github.com/xenitab/go-oidc-middleware/internal/oidc"
	"github.com/xenitab/go-oidc-middleware/options"
)

// New returns an OpenID Connect (OIDC) discovery `ParseTokenFunc`
// to be used with the the echo `JWT` middleware.
func New[T any](claimsValidationFn options.ClaimsValidationFn[T], setters ...options.Option) echo.MiddlewareFunc {
	h, err := oidc.NewHandler(claimsValidationFn, setters...)
	if err != nil {
		panic(fmt.Sprintf("oidc discovery: %v", err))
	}

	return toEchoMiddleware(h.ParseToken, setters...)
}

func onError(errorHandler options.ErrorHandler, description options.ErrorDescription, err error) {
	if errorHandler != nil {
		errorHandler(description, err)
	}
}

func toEchoMiddleware[T any](parseToken oidc.ParseTokenFunc[T], setters ...options.Option) echo.MiddlewareFunc {
	opts := options.New(setters...)

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			ctx := c.Request().Context()

			tokenString, err := oidc.GetTokenString(c.Request().Header.Get, opts.TokenString)
			if err != nil {
				onError(opts.ErrorHandler, options.GetTokenErrorDescription, err)
				return echo.ErrBadRequest
			}

			claims, err := parseToken(ctx, tokenString)
			if err != nil {
				onError(opts.ErrorHandler, options.ParseTokenErrorDescription, err)
				return echo.ErrUnauthorized
			}
			c.Set(string(opts.ClaimsContextKeyName), claims)
			return next(c)
		}
	}
}
