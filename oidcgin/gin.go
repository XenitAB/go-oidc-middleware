package oidcgin

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/xenitab/go-oidc-middleware/internal/oidc"
)

// Options takes an oidc.Options struct.
type Options oidc.Options

// New returns an OpenID Connect (OIDC) discovery handler (middleware)
// to be used with `gin`.
func New(opts *Options) gin.HandlerFunc {
	oidcOpts := oidc.Options(*opts)

	oidcHandler, err := oidc.NewHandler(&oidcOpts)
	if err != nil {
		panic(fmt.Sprintf("oidc discovery: %v", err))
	}

	return toGinHandler(oidcHandler.ParseToken)
}

func toGinHandler(parseToken oidc.ParseTokenFunc) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx := c.Request.Context()

		tokenString, err := oidc.GetTokenStringFromRequest(c.Request)
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

		c.Set("claims", tokenClaims)

		c.Next()
	}
}
