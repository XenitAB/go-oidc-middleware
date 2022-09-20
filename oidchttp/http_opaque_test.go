package oidchttp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/xenitab/go-oidc-middleware/internal/oidc"
	"github.com/xenitab/go-oidc-middleware/internal/oidctesting"
	"github.com/xenitab/go-oidc-middleware/optest"
	"github.com/xenitab/go-oidc-middleware/options"
)

const testNameOpaque = "OidcOpaqueHttp"

func TestOpaqueSuite(t *testing.T) {
	oidctesting.RunOpaqueTests(t, testNameOpaque, newTestOpaqueHttpHandler(t))
}

// func BenchmarkOpaqueSuite(b *testing.B) {
// 	oidctesting.RunOpaqueBenchmarks(b, testNameOpaque, newTestOpaqueHttpHandler(b))
// }

func testGetOpaqueHttpHandler(tb testing.TB) http.Handler {
	tb.Helper()

	return http.HandlerFunc(testNewOpaqueClaimsHandler(tb))
}

func testNewOpaqueClaimsHandler(tb testing.TB) func(w http.ResponseWriter, r *http.Request) {
	tb.Helper()

	return func(w http.ResponseWriter, r *http.Request) {
		claims, ok := r.Context().Value(options.DefaultClaimsContextKeyName).(map[string]interface{})
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

type opaqueTestServer struct {
	tb     testing.TB
	server *httptest.Server
}

func newOpaqueTestServer(tb testing.TB, handler http.Handler) *opaqueTestServer {
	tb.Helper()

	server := httptest.NewServer(handler)

	return &opaqueTestServer{
		tb:     tb,
		server: server,
	}
}

func (srv *opaqueTestServer) Close() {
	srv.tb.Helper()

	srv.server.Close()
}

func (srv *opaqueTestServer) URL() string {
	srv.tb.Helper()

	return srv.server.URL
}

type testOpaqueHttpHandler struct {
	tb testing.TB
}

func newTestOpaqueHttpHandler(tb testing.TB) *testOpaqueHttpHandler {
	tb.Helper()

	return &testOpaqueHttpHandler{
		tb: tb,
	}
}

func (h *testOpaqueHttpHandler) NewHandlerFn(opts ...options.OpaqueOption[optest.TestUser]) http.Handler {
	h.tb.Helper()

	handler := testGetOpaqueHttpHandler(h.tb)
	return NewOpaque(handler, opts...)
}

func (h *testOpaqueHttpHandler) ToHandlerFn(parseToken oidc.ParseOpaqueTokenFunc[optest.TestUser], opts ...options.OpaqueOption[optest.TestUser]) http.Handler {
	h.tb.Helper()

	handler := testGetOpaqueHttpHandler(h.tb)
	return toOpaqueHttpHandler(handler, parseToken, opts...)
}

func (h *testOpaqueHttpHandler) NewTestServer(opts ...options.OpaqueOption[optest.TestUser]) oidctesting.ServerTester {
	h.tb.Helper()

	handler := testGetOpaqueHttpHandler(h.tb)
	return newOpaqueTestServer(h.tb, NewOpaque(handler, opts...))
}
