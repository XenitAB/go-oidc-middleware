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

func onError(c echo.Context, errorHandler options.ErrorHandler, statusCode int, description options.ErrorDescription, err error) error {
	if errorHandler == nil {
		c.Logger().Error(err)
		return c.NoContent(statusCode)
	}
	oidcErr := options.OidcError{
		Url:     c.Request().URL,
		Headers: c.Request().Header,
		Status:  description,
		Error:   err,
	}
	response := errorHandler(c.Request().Context(), &oidcErr)
	if response == nil {
		c.Logger().Error(err)
		return c.NoContent(statusCode)
	}
	for k, v := range response.Headers {
		c.Response().Header().Set(k, v)
	}
	c.Response().Header().Set(echo.HeaderContentType, response.ContentType())
	c.Response().WriteHeader(response.StatusCode)
	_, err = c.Response().Write(response.Body)
	return err
}

func toEchoMiddleware[T any](parseToken oidc.ParseTokenFunc[T], setters ...options.Option) echo.MiddlewareFunc {
	opts := options.New(setters...)

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			ctx := c.Request().Context()

			tokenString, err := oidc.GetTokenString(c.Request().Header.Get, opts.TokenString)
			if err != nil {
				return onError(c, opts.ErrorHandler, echo.ErrBadRequest.Code, options.GetTokenErrorDescription, err)
			}

			claims, err := parseToken(ctx, tokenString)
			if err != nil {
				return onError(c, opts.ErrorHandler, echo.ErrUnauthorized.Code, options.ParseTokenErrorDescription, err)
			}
			c.Set(string(opts.ClaimsContextKeyName), claims)
			return next(c)
		}
	}
}
