package oidcfiber

import (
	"fmt"
	"net/url"

	"github.com/gofiber/fiber/v2"
	"github.com/xenitab/go-oidc-middleware/internal/oidc"
	"github.com/xenitab/go-oidc-middleware/options"
)

// New returns an OpenID Connect (OIDC) discovery handler (middleware)
// to be used with `fiber`.
func New[T any](claimsValidationFn options.ClaimsValidationFn[T], setters ...options.Option) fiber.Handler {
	oidcHandler, err := oidc.NewHandler(claimsValidationFn, setters...)
	if err != nil {
		panic(fmt.Sprintf("oidc discovery: %v", err))
	}

	return toFiberHandler(oidcHandler.ParseToken, setters...)
}

func onError(c *fiber.Ctx, errorHandler options.ErrorHandler, statusCode int, description options.ErrorDescription, err error) error {
	if errorHandler == nil {
		return c.SendStatus(statusCode)
	}
	url, _ := url.Parse(c.OriginalURL())
	oidcErr := options.OidcError{
		Url:     url,
		Headers: c.GetReqHeaders(),
		Status:  description,
		Error:   err,
	}
	response := errorHandler(c.Context(), &oidcErr)
	if response == nil {
		return c.SendStatus(statusCode)
	}
	for k, v := range response.Headers {
		c.Response().Header.Set(k, v)
	}
	c.Set("Content-Type", response.ContentType())
	return c.Status(response.StatusCode).Send(response.Body)
}

func toFiberHandler[T any](parseToken oidc.ParseTokenFunc[T], setters ...options.Option) fiber.Handler {
	opts := options.New(setters...)

	return func(c *fiber.Ctx) error {
		ctx := c.Context()

		getHeaderFn := func(key string) string {
			return c.Get(key)
		}

		tokenString, err := oidc.GetTokenString(getHeaderFn, opts.TokenString)
		if err != nil {
			return onError(c, opts.ErrorHandler, fiber.StatusBadRequest, options.GetTokenErrorDescription, err)
		}

		claims, err := parseToken(ctx, tokenString)
		if err != nil {
			return onError(c, opts.ErrorHandler, fiber.StatusUnauthorized, options.ParseTokenErrorDescription, err)
		}

		c.Locals(string(opts.ClaimsContextKeyName), claims)

		return c.Next()
	}
}
