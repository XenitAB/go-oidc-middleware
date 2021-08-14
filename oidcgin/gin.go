package oidcgin

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/xenitab/go-oidc-middleware/internal/oidc"
	"github.com/xenitab/go-oidc-middleware/options"
)

// New returns an OpenID Connect (OIDC) discovery handler (middleware)
// to be used with `gin`.
func New(setters ...options.Option) gin.HandlerFunc {
	oidcHandler, err := oidc.NewHandler(setters...)
	if err != nil {
		panic(fmt.Sprintf("oidc discovery: %v", err))
	}

	return toGinHandler(oidcHandler.ParseToken, setters...)
}

func toGinHandler(parseToken oidc.ParseTokenFunc, setters ...options.Option) gin.HandlerFunc {
	opts := options.New(setters...)

	return func(c *gin.Context) {
		ctx := c.Request.Context()

		tokenString, err := oidc.GetTokenStringFromRequest(c.Request, opts.TokenString...)
		if err != nil {
			c.AbortWithStatus(http.StatusBadRequest)
			return
		}

		token, err := parseToken(ctx, tokenString)
		if err != nil {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		tokenClaims, err := token.AsMap(ctx)
		if err != nil {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		c.Set(string(opts.ClaimsContextKeyName), tokenClaims)

		c.Next()
	}
}
