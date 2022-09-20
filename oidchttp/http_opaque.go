package oidchttp

import (
	"context"
	"fmt"
	"net/http"

	"github.com/xenitab/go-oidc-middleware/internal/oidc"
	"github.com/xenitab/go-oidc-middleware/options"
)

func NewOpaque[T any](h http.Handler, setters ...options.OpaqueOption[T]) http.Handler {
	oidcHandler, err := oidc.NewOpaqueHandler(setters...)
	if err != nil {
		panic(fmt.Sprintf("oidc discovery: %v", err))
	}

	return toOpaqueHttpHandler(h, oidcHandler.ParseToken, setters...)
}

func toOpaqueHttpHandler[T any](h http.Handler, parseToken oidc.ParseOpaqueTokenFunc[T], setters ...options.OpaqueOption[T]) http.Handler {
	opts := options.NewOpaque(setters...)

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
