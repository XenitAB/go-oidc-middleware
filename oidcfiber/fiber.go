package oidcfiber

import (
	"fmt"

	"github.com/gofiber/fiber/v2"
	"github.com/xenitab/go-oidc-middleware/internal/oidc"
	"github.com/xenitab/go-oidc-middleware/options"
)

// New returns an OpenID Connect (OIDC) discovery handler (middleware)
// to be used with `fiber`.
func New(setters ...options.Option) fiber.Handler {
	oidcHandler, err := oidc.NewHandler(setters...)
	if err != nil {
		panic(fmt.Sprintf("oidc discovery: %v", err))
	}

	return toFiberHandler(oidcHandler.ParseToken, setters...)
}

func toFiberHandler(parseToken oidc.ParseTokenFunc, setters ...options.Option) fiber.Handler {
	opts := options.New(setters...)
	tokenStringOpts := options.NewTokenString(opts.TokenString...)

	return func(c *fiber.Ctx) error {
		ctx := c.Context()

		authz := c.Get(tokenStringOpts.HeaderName)

		tokenString, err := oidc.GetTokenStringFromString(authz, opts.TokenString...)
		if err != nil {
			return c.SendStatus(fiber.StatusBadRequest)
		}

		token, err := parseToken(ctx, tokenString)
		if err != nil {
			return c.SendStatus(fiber.StatusUnauthorized)
		}

		tokenClaims, err := token.AsMap(ctx)
		if err != nil {
			return c.SendStatus(fiber.StatusUnauthorized)
		}

		c.Locals(string(opts.ClaimsContextKeyName), tokenClaims)

		return c.Next()
	}
}
