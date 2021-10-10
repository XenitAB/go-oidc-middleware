package oidchttp

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/xenitab/go-oidc-middleware/internal/oidc"
	"github.com/xenitab/go-oidc-middleware/internal/oidctesting"
	"github.com/xenitab/go-oidc-middleware/options"
)

func TestSuiteChi(t *testing.T) {
	oidctesting.RunTests(t, fmt.Sprintf("%sChi", testName), newTestChiHandler(t))
}

func BenchmarkSuiteChi(b *testing.B) {
	oidctesting.RunBenchmarks(b, fmt.Sprintf("%sChi", testName), newTestChiHandler(b))
}

func testGetChiRouter(tb testing.TB) http.Handler {
	tb.Helper()

	router := chi.NewRouter()
	router.Get("/", testNewClaimsHandler(tb))

	return router
}

type testChiHandler struct {
	tb testing.TB
}

func newTestChiHandler(tb testing.TB) *testChiHandler {
	tb.Helper()

	return &testChiHandler{
		tb: tb,
	}
}

func (h *testChiHandler) NewHandlerFn(opts ...options.Option) http.Handler {
	h.tb.Helper()

	router := testGetChiRouter(h.tb)
	return New(router, opts...)
}

func (h *testChiHandler) ToHandlerFn(parseToken oidc.ParseTokenFunc, opts ...options.Option) http.Handler {
	h.tb.Helper()

	router := testGetChiRouter(h.tb)
	return toHttpHandler(router, parseToken, opts...)
}

func (h *testChiHandler) NewTestServer(opts ...options.Option) oidctesting.ServerTester {
	h.tb.Helper()

	router := testGetChiRouter(h.tb)
	return newTestServer(h.tb, New(router, opts...))
}
