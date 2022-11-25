package oidctoken

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/xenitab/go-oidc-middleware/internal/oidc"
	"github.com/xenitab/go-oidc-middleware/internal/oidctesting"
	"github.com/xenitab/go-oidc-middleware/optest"
	"github.com/xenitab/go-oidc-middleware/options"
)

const testName = "OidcToken"

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
	return testNew(h.tb, handler, opts...)
}

func (h *testHttpHandler) ToHandlerFn(parseToken oidc.ParseTokenFunc, opts ...options.Option) http.Handler {
	h.tb.Helper()

	handler := testGetHttpHandler(h.tb)
	return testToHttpHandler(h.tb, handler, parseToken, opts...)
}

func (h *testHttpHandler) NewTestServer(opts ...options.Option) oidctesting.ServerTester {
	h.tb.Helper()

	handler := testGetHttpHandler(h.tb)
	return newTestServer(h.tb, testNew(h.tb, handler, opts...))
}

func testOnError(tb testing.TB, w http.ResponseWriter, errorHandler options.ErrorHandler, statusCode int, description options.ErrorDescription, err error) {
	tb.Helper()

	if errorHandler != nil {
		errorHandler(description, err)
	}

	w.WriteHeader(statusCode)
}

func testNew(tb testing.TB, h http.Handler, setters ...options.Option) http.Handler {
	tb.Helper()

	tokenHandler, err := New[*optest.TestUser](setters...)
	if err != nil {
		panic(fmt.Sprintf("oidc discovery: %v", err))
	}

	return testToHttpHandler(tb, h, tokenHandler.ParseToken, setters...)
}

func testToHttpHandler(tb testing.TB, h http.Handler, parseToken oidc.ParseTokenFunc, setters ...options.Option) http.Handler {
	tb.Helper()

	opts := options.New(setters...)

	fn := func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		tokenString, err := GetTokenString(r.Header.Get, opts.TokenString)
		if err != nil {
			testOnError(tb, w, opts.ErrorHandler, http.StatusBadRequest, options.GetTokenErrorDescription, err)
			return
		}

		token, err := parseToken(ctx, tokenString)
		if err != nil {
			testOnError(tb, w, opts.ErrorHandler, http.StatusUnauthorized, options.ParseTokenErrorDescription, err)
			return
		}

		tokenClaims, err := token.AsMap(ctx)
		if err != nil {
			testOnError(tb, w, opts.ErrorHandler, http.StatusUnauthorized, options.ConvertTokenErrorDescription, err)
			return
		}

		ctxWithClaims := context.WithValue(ctx, opts.ClaimsContextKeyName, tokenClaims)
		reqWithClaims := r.WithContext(ctxWithClaims)

		h.ServeHTTP(w, reqWithClaims)
	}

	return http.HandlerFunc(fn)
}
