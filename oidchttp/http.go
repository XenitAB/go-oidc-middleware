package oidchttp

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/xenitab/go-oidc-middleware/internal/oidc"
)

// Options takes an oidc.Options struct.
type Options oidc.Options

// ContextKey is the type for they key value used to pass claims using request context.
type ContextKey string

const (
	// ClaimsContextKey is the key (`claims`) that will be used to pass claims using request context.
	ClaimsContextKey ContextKey = "claims"
)

// New returns an OpenID Connect (OIDC) discovery handler (middleware)
// to be used with `net/http` and `mux`.
func New(h http.Handler, opts *Options) http.Handler {
	oidcOpts := oidc.Options(*opts)

	oidcHandler, err := oidc.NewHandler(&oidcOpts)
	if err != nil {
		panic(fmt.Sprintf("oidc discovery: %v", err))
	}

	return toHttpHandler(h, oidcHandler.ParseToken)
}

func toHttpHandler(h http.Handler, parseToken oidc.ParseTokenFunc) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		tokenString, err := getTokenStringFromRequest(r)
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

func getTokenStringFromRequest(r *http.Request) (string, error) {
	authz := r.Header.Get("Authorization")
	if authz == "" {
		return "", fmt.Errorf("authorization header empty")
	}

	comp := strings.Split(authz, " ")
	if len(comp) != 2 {
		return "", fmt.Errorf("authorization header components not 2 but: %d", len(comp))
	}

	if comp[0] != "Bearer" {
		return "", fmt.Errorf("authorization headers first component not Bearer")
	}

	return comp[1], nil
}
