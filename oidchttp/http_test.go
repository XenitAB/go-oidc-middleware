package oidchttp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/xenitab/go-oidc-middleware/internal/oidc"
	"github.com/xenitab/go-oidc-middleware/internal/oidctesting"
	"github.com/xenitab/go-oidc-middleware/options"
)

const testName = "OidcHttp"

func TestSuite(t *testing.T) {
	oidctesting.RunTests(t, testName, newTestHttpHandler(t))
}

func BenchmarkSuite(b *testing.B) {
	oidctesting.RunBenchmarks(b, testName, newTestHttpHandler(b))
}

func testGetHttpHandler(tb testing.TB) http.Handler {
	tb.Helper()

	return http.HandlerFunc(testNewClaimsHandler(tb))
}

func testNewClaimsHandler(tb testing.TB) func(w http.ResponseWriter, r *http.Request) {
	tb.Helper()

	return func(w http.ResponseWriter, r *http.Request) {
		claims, ok := r.Context().Value(options.DefaultClaimsContextKeyName).(*oidctesting.TestClaims)
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

type testServer struct {
	tb     testing.TB
	server *httptest.Server
}

func newTestServer(tb testing.TB, handler http.Handler) *testServer {
	tb.Helper()

	server := httptest.NewServer(handler)

	return &testServer{
		tb:     tb,
		server: server,
	}
}

func (srv *testServer) Close() {
	srv.tb.Helper()

	srv.server.Close()
}

func (srv *testServer) URL() string {
	srv.tb.Helper()

	return srv.server.URL
}

type testHttpHandler struct {
	tb testing.TB
}

func newTestHttpHandler(tb testing.TB) *testHttpHandler {
	tb.Helper()

	return &testHttpHandler{
		tb: tb,
	}
}

func (h *testHttpHandler) NewHandlerFn(opts ...options.Option) http.Handler {
	h.tb.Helper()

	handler := testGetHttpHandler(h.tb)
	return New[*oidctesting.TestClaims](handler, opts...)
}

func (h *testHttpHandler) ToHandlerFn(parseToken oidc.ParseTokenFunc[*oidctesting.TestClaims], opts ...options.Option) http.Handler {
	h.tb.Helper()

	handler := testGetHttpHandler(h.tb)
	return toHttpHandler(handler, parseToken, opts...)
}

func (h *testHttpHandler) NewTestServer(opts ...options.Option) oidctesting.ServerTester {
	h.tb.Helper()

	handler := testGetHttpHandler(h.tb)
	return newTestServer(h.tb, New[*oidctesting.TestClaims](handler, opts...))
}
