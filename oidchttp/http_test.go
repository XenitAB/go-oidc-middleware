package oidchttp

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/xenitab/go-oidc-middleware/internal/oidc"
	"github.com/xenitab/go-oidc-middleware/internal/oidctesting"
	"github.com/xenitab/go-oidc-middleware/options"
)

const testName = "oidchttp"

func TestOidchttp(t *testing.T) {
	handler := testGetHttpHandler(t)
	newHandlerFn := func(opts ...options.Option) http.Handler {
		return New(handler, opts...)
	}
	toHandlerFn := func(parseToken oidc.ParseTokenFunc) http.Handler {
		return toHttpHandler(handler, parseToken)
	}

	oidctesting.RunTests(t, testName, newHandlerFn, toHandlerFn)
}

func BenchmarkOidchttp(b *testing.B) {
	handler := testGetHttpHandler(b)
	newHandlerFn := func(opts ...options.Option) http.Handler {
		return New(handler, opts...)
	}

	oidctesting.RunBenchmarks(b, testName, newHandlerFn)
}

func testGetHttpHandler(tb testing.TB) http.Handler {
	tb.Helper()

	fn := func(w http.ResponseWriter, r *http.Request) {
		claims, ok := r.Context().Value(ClaimsContextKey).(map[string]interface{})
		if !ok {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		err := json.NewEncoder(w).Encode(claims)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	}

	return http.HandlerFunc(fn)
}
