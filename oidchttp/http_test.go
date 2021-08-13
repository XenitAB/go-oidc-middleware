package oidchttp

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/xenitab/go-oidc-middleware/internal/oidc"
	"github.com/xenitab/go-oidc-middleware/internal/oidctesting"
	"github.com/xenitab/go-oidc-middleware/options"
)

const testName = "OidcHttp"

func TestSuite(t *testing.T) {
	oidctesting.RunTests(t, testName, testNewHandlerFn(t), testToHandlerFn(t))
}

func BenchmarkSuite(b *testing.B) {
	oidctesting.RunBenchmarks(b, testName, testNewHandlerFn(b))
}

func testNewHandlerFn(tb testing.TB) func(opts ...options.Option) http.Handler {
	tb.Helper()

	return func(opts ...options.Option) http.Handler {
		handler := testGetHttpHandler(tb)
		return New(handler, opts...)
	}
}

func testToHandlerFn(tb testing.TB) func(parseToken oidc.ParseTokenFunc) http.Handler {
	tb.Helper()

	return func(parseToken oidc.ParseTokenFunc) http.Handler {
		handler := testGetHttpHandler(tb)
		return toHttpHandler(handler, parseToken)
	}
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
