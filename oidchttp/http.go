package oidchttp

import (
	"context"
	"fmt"
	"net/http"

	"github.com/xenitab/go-oidc-middleware/internal/oidc"
	"github.com/xenitab/go-oidc-middleware/options"
)

// New returns an OpenID Connect (OIDC) discovery handler (middleware)
// to be used with `net/http`, `mux` and `chi`.
func New[T any](h http.Handler, claimsValidationFn options.ClaimsValidationFn[T], setters ...options.Option) http.Handler {
	oidcHandler, err := oidc.NewHandler(claimsValidationFn, setters...)
	if err != nil {
		panic(fmt.Sprintf("oidc discovery: %v", err))
	}

	return toHttpHandler(h, oidcHandler.ParseToken, setters...)
}

func onError(w http.ResponseWriter, errorHandler options.ErrorHandler, statusCode int, description options.ErrorDescription, err error) {
	if errorHandler != nil {
		errorHandler(description, err)
	}

	w.WriteHeader(statusCode)
}

func toHttpHandler[T any](h http.Handler, parseToken oidc.ParseTokenFunc[T], setters ...options.Option) http.Handler {
	opts := options.New(setters...)

	fn := func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		tokenString, err := oidc.GetTokenString(r.Header.Get, opts.TokenString)
		if err != nil {
			onError(w, opts.ErrorHandler, http.StatusBadRequest, options.GetTokenErrorDescription, err)
			return
		}

		claims, err := parseToken(ctx, tokenString)
		if err != nil {
			onError(w, opts.ErrorHandler, http.StatusUnauthorized, options.ParseTokenErrorDescription, err)
			return
		}

		ctxWithClaims := context.WithValue(ctx, opts.ClaimsContextKeyName, claims)
		reqWithClaims := r.WithContext(ctxWithClaims)

		h.ServeHTTP(w, reqWithClaims)
	}

	return http.HandlerFunc(fn)
}
