package oidchttp

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/gorilla/mux"
	"github.com/xenitab/go-oidc-middleware/internal/oidc"
	"github.com/xenitab/go-oidc-middleware/internal/oidctesting"
	"github.com/xenitab/go-oidc-middleware/options"
)

func TestSuiteMux(t *testing.T) {
	oidctesting.RunTests(t, fmt.Sprintf("%sMux", testName), newTestMuxHandler(t))
}

func BenchmarkSuiteMux(b *testing.B) {
	oidctesting.RunBenchmarks(b, fmt.Sprintf("%sMux", testName), newTestMuxHandler(b))
}

func testGetMuxRouter(tb testing.TB) http.Handler {
	tb.Helper()

	router := mux.NewRouter()
	router.HandleFunc("/", testNewClaimsHandler(tb)).Methods(http.MethodGet).Path("/")

	return router
}

type testMuxHandler struct {
	tb testing.TB
}

func newTestMuxHandler(tb testing.TB) *testMuxHandler {
	tb.Helper()

	return &testMuxHandler{
		tb: tb,
	}
}

func (h *testMuxHandler) NewHandlerFn(opts ...options.Option) http.Handler {
	h.tb.Helper()

	router := testGetMuxRouter(h.tb)
	return New(router, opts...)
}

func (h *testMuxHandler) ToHandlerFn(parseToken oidc.ParseTokenFunc, opts ...options.Option) http.Handler {
	h.tb.Helper()

	router := testGetMuxRouter(h.tb)
	return toHttpHandler(router, parseToken, opts...)
}

func (h *testMuxHandler) NewTestServer(opts ...options.Option) oidctesting.ServerTester {
	h.tb.Helper()

	router := testGetMuxRouter(h.tb)
	return newTestServer(h.tb, New(router, opts...))
}
