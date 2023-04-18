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
func New[T any](claimsValidationFn options.ClaimsValidationFn[T], setters ...options.Option) gin.HandlerFunc {
	oidcHandler, err := oidc.NewHandler(claimsValidationFn, setters...)
	if err != nil {
		panic(fmt.Sprintf("oidc discovery: %v", err))
	}

	return toGinHandler(oidcHandler.ParseToken, setters...)
}

func onError(c *gin.Context, o *options.Options, statusCode int, description options.ErrorDescription, err error) {
	if o.ErrorHandler != nil {
		o.ErrorHandler(description, err)
	}

	if o.AbortHandler != nil {
		o.AbortHandler(c, statusCode, description, err)
	} else {
		c.AbortWithError(statusCode, err)
	}
}

func toGinHandler[T any](parseToken oidc.ParseTokenFunc[T], setters ...options.Option) gin.HandlerFunc {
	opts := options.New(setters...)

	return func(c *gin.Context) {
		ctx := c.Request.Context()

		tokenString, err := oidc.GetTokenString(c.Request.Header.Get, opts.TokenString)
		if err != nil {
			onError(c, opts, http.StatusBadRequest, options.GetTokenErrorDescription, err)
			return
		}

		claims, err := parseToken(ctx, tokenString)
		if err != nil {
			onError(c, opts, http.StatusUnauthorized, options.ParseTokenErrorDescription, err)
			return
		}

		c.Set(string(opts.ClaimsContextKeyName), claims)

		c.Next()
	}
}
