package oidcgin

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/xenitab/go-oidc-middleware/internal/oidc"
	"github.com/xenitab/go-oidc-middleware/options"
)

type ClaimsValidator interface {
	oidc.ClaimsValidator
}

// New returns an OpenID Connect (OIDC) discovery handler (middleware)
// to be used with `gin`.
func New[T ClaimsValidator](setters ...options.Option) gin.HandlerFunc {
	oidcHandler, err := oidc.NewHandler[T](setters...)
	if err != nil {
		panic(fmt.Sprintf("oidc discovery: %v", err))
	}

	return toGinHandler(oidcHandler.ParseToken, setters...)
}

func onError(c *gin.Context, errorHandler options.ErrorHandler, statusCode int, description options.ErrorDescription, err error) {
	if errorHandler != nil {
		errorHandler(description, err)
	}

	//nolint:errcheck // false positive
	c.AbortWithError(statusCode, err)
}

func toGinHandler[T ClaimsValidator](parseToken oidc.ParseTokenFunc[T], setters ...options.Option) gin.HandlerFunc {
	opts := options.New(setters...)

	return func(c *gin.Context) {
		ctx := c.Request.Context()

		tokenString, err := oidc.GetTokenString(c.Request.Header.Get, opts.TokenString)
		if err != nil {
			onError(c, opts.ErrorHandler, http.StatusBadRequest, options.GetTokenErrorDescription, err)
			return
		}

		claims, err := parseToken(ctx, tokenString)
		if err != nil {
			onError(c, opts.ErrorHandler, http.StatusUnauthorized, options.ParseTokenErrorDescription, err)
			return
		}

		c.Set(string(opts.ClaimsContextKeyName), claims)

		c.Next()
	}
}
