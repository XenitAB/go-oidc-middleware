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

func onError(r *http.Request, w http.ResponseWriter, errorHandler options.ErrorHandler, statusCode int, description options.ErrorDescription, err error) {
	if errorHandler == nil {
		w.WriteHeader(statusCode)
		return
	}
	error := options.OidcError{
		Url:     r.URL,
		Headers: r.Header,
		Status:  description,
		Error:   err,
	}
	response := errorHandler(r.Context(), &error)
	if response == nil {
		w.WriteHeader(statusCode)
		return
	}
	for k, v := range response.Headers {
		w.Header().Add(k, v)
	}
	w.Header().Set("Content-Type", response.ContentType())
	w.WriteHeader(response.StatusCode)
	w.Write(response.Body)
}

func toHttpHandler[T any](h http.Handler, parseToken oidc.ParseTokenFunc[T], setters ...options.Option) http.Handler {
	opts := options.New(setters...)

	fn := func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		tokenString, err := oidc.GetTokenString(r.Header.Get, opts.TokenString)
		if err != nil {
			onError(r, w, opts.ErrorHandler, http.StatusBadRequest, options.GetTokenErrorDescription, err)
			return
		}

		claims, err := parseToken(ctx, tokenString)
		if err != nil {
			onError(r, w, opts.ErrorHandler, http.StatusUnauthorized, options.ParseTokenErrorDescription, err)
			return
		}

		ctxWithClaims := context.WithValue(ctx, opts.ClaimsContextKeyName, claims)
		reqWithClaims := r.WithContext(ctxWithClaims)

		h.ServeHTTP(w, reqWithClaims)
	}

	return http.HandlerFunc(fn)
}
