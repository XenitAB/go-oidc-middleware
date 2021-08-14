package oidchttp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/mux"
	"github.com/xenitab/go-oidc-middleware/internal/oidc"
	"github.com/xenitab/go-oidc-middleware/internal/oidctesting"
	"github.com/xenitab/go-oidc-middleware/options"
)

const testName = "OidcHttp"

func TestSuite(t *testing.T) {
	oidctesting.RunTests(t, testName, testNewHandlerFn(t), testToHandlerFn(t))
	oidctesting.RunTests(t, fmt.Sprintf("%sMux", testName), testNewMuxHandlerFn(t), testToMuxHandlerFn(t))
	oidctesting.RunTests(t, fmt.Sprintf("%sChi", testName), testNewChiHandlerFn(t), testToChiHandlerFn(t))
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

func testNewMuxHandlerFn(tb testing.TB) func(opts ...options.Option) http.Handler {
	tb.Helper()

	return func(opts ...options.Option) http.Handler {
		router := testGetMuxRouter(tb)
		return New(router, opts...)
	}
}

func testNewChiHandlerFn(tb testing.TB) func(opts ...options.Option) http.Handler {
	tb.Helper()

	return func(opts ...options.Option) http.Handler {
		router := testGetChiRouter(tb)
		return New(router, opts...)
	}
}

func testToHandlerFn(tb testing.TB) func(parseToken oidc.ParseTokenFunc) http.Handler {
	tb.Helper()

	return func(parseToken oidc.ParseTokenFunc) http.Handler {
		handler := testGetHttpHandler(tb)
		return toHttpHandler(handler, parseToken)
	}
}

func testToMuxHandlerFn(tb testing.TB) func(parseToken oidc.ParseTokenFunc) http.Handler {
	tb.Helper()

	return func(parseToken oidc.ParseTokenFunc) http.Handler {
		router := testGetMuxRouter(tb)
		return toHttpHandler(router, parseToken)
	}
}

func testToChiHandlerFn(tb testing.TB) func(parseToken oidc.ParseTokenFunc) http.Handler {
	tb.Helper()

	return func(parseToken oidc.ParseTokenFunc) http.Handler {
		router := testGetMuxRouter(tb)
		return toHttpHandler(router, parseToken)
	}
}

func testGetHttpHandler(tb testing.TB) http.Handler {
	tb.Helper()

	return http.HandlerFunc(testNewClaimsHandler(tb))
}

func testGetMuxRouter(tb testing.TB) http.Handler {
	tb.Helper()

	router := mux.NewRouter()
	router.HandleFunc("/", testNewClaimsHandler(tb)).Methods(http.MethodGet).Path("/")

	return router
}

func testGetChiRouter(tb testing.TB) http.Handler {
	tb.Helper()

	router := chi.NewRouter()
	router.Get("/", testNewClaimsHandler(tb))

	return router
}

func testNewClaimsHandler(tb testing.TB) func(w http.ResponseWriter, r *http.Request) {
	tb.Helper()

	return func(w http.ResponseWriter, r *http.Request) {
		claims, ok := r.Context().Value(options.ClaimsContextKeyName("claims")).(map[string]interface{})
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
}
