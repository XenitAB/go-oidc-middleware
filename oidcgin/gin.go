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

	opts := &options.Options{}
	for _, setter := range setters {
		setter(opts)
	}

	return toGinHandler(oidcHandler.ParseToken, opts.TokenString...)
}

func toGinHandler(parseToken oidc.ParseTokenFunc, tokenStringOptions ...options.TokenStringOption) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx := c.Request.Context()

		tokenString, err := oidc.GetTokenStringFromRequest(c.Request, tokenStringOptions...)
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
