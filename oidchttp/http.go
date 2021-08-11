package oidchttp

import (
	"context"
	"fmt"
	"net/http"

	"github.com/xenitab/go-oidc-middleware/internal/oidc"
	"github.com/xenitab/go-oidc-middleware/options"
)

// ContextKey is the type for they key value used to pass claims using request context.
type ContextKey string

const (
	// ClaimsContextKey is the key (`claims`) that will be used to pass claims using request context.
	ClaimsContextKey ContextKey = "claims"
)

// New returns an OpenID Connect (OIDC) discovery handler (middleware)
// to be used with `net/http` and `mux`.
func New(h http.Handler, setters ...options.Option) http.Handler {
	oidcHandler, err := oidc.NewHandler(setters...)
	if err != nil {
		panic(fmt.Sprintf("oidc discovery: %v", err))
	}

	return toHttpHandler(h, oidcHandler.ParseToken)
}

func toHttpHandler(h http.Handler, parseToken oidc.ParseTokenFunc) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		tokenString, err := oidc.GetTokenStringFromRequest(r)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		token, err := parseToken(ctx, tokenString)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		tokenClaims, err := token.AsMap(ctx)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		ctxWithClaims := context.WithValue(ctx, ClaimsContextKey, tokenClaims)
		reqWithClaims := r.WithContext(ctxWithClaims)

		h.ServeHTTP(w, reqWithClaims)
	}

	return http.HandlerFunc(fn)
}
