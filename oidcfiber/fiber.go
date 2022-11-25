package oidcfiber

import (
	"fmt"

	"github.com/gofiber/fiber/v2"
	"github.com/xenitab/go-oidc-middleware/internal/oidc"
	"github.com/xenitab/go-oidc-middleware/options"
)

// New returns an OpenID Connect (OIDC) discovery handler (middleware)
// to be used with `fiber`.
func New[T any](setters ...options.Option) fiber.Handler {
	oidcHandler, err := oidc.NewHandler[T](setters...)
	if err != nil {
		panic(fmt.Sprintf("oidc discovery: %v", err))
	}

	return toFiberHandler(oidcHandler.ParseToken, setters...)
}

func onError(c *fiber.Ctx, errorHandler options.ErrorHandler, statusCode int, description options.ErrorDescription, err error) error {
	if errorHandler != nil {
		errorHandler(description, err)
	}

	return c.SendStatus(statusCode)
}

func toFiberHandler(parseToken oidc.ParseTokenFunc, setters ...options.Option) fiber.Handler {
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

		token, err := parseToken(ctx, tokenString)
		if err != nil {
			return onError(c, opts.ErrorHandler, fiber.StatusUnauthorized, options.ParseTokenErrorDescription, err)
		}

		tokenClaims, err := token.AsMap(ctx)
		if err != nil {
			return onError(c, opts.ErrorHandler, fiber.StatusUnauthorized, options.ConvertTokenErrorDescription, err)
		}

		c.Locals(string(opts.ClaimsContextKeyName), tokenClaims)

		return c.Next()
	}
}
