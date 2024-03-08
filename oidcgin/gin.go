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

func onError(c *gin.Context, errorHandler options.ErrorHandler, statusCode int, description options.ErrorDescription, err error) error {
	if errorHandler == nil {
		return c.AbortWithError(statusCode, err)
	}

	oidcErr := options.OidcError{
		Url:     c.Request.URL,
		Headers: c.Request.Header,
		Status:  description,
		Error:   err,
	}
	response := errorHandler(c.Request.Context(), &oidcErr)
	if response == nil {
		return c.AbortWithError(statusCode, err)
	}
	for k, v := range response.Headers {
		c.Header(k, v)
	}
	c.Data(response.StatusCode, response.ContentType(), response.Body)
	c.Error(err) //nolint: errcheck // not sure what to do with the error here
	c.Abort()
	return nil
}

func toGinHandler[T any](parseToken oidc.ParseTokenFunc[T], setters ...options.Option) gin.HandlerFunc {
	opts := options.New(setters...)

	return func(c *gin.Context) {
		ctx := c.Request.Context()

		tokenString, err := oidc.GetTokenString(c.Request.Header.Get, opts.TokenString)
		if err != nil {
			//nolint: errcheck // not sure what to do with the error here
			onError(c, opts.ErrorHandler, http.StatusBadRequest, options.GetTokenErrorDescription, err)
			return
		}

		claims, err := parseToken(ctx, tokenString)
		if err != nil {
			//nolint: errcheck // not sure what to do with the error here
			onError(c, opts.ErrorHandler, http.StatusUnauthorized, options.ParseTokenErrorDescription, err)
			return
		}

		c.Set(string(opts.ClaimsContextKeyName), claims)
	}
}
