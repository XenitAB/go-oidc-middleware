package oidcgin

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/xenitab/go-oidc-middleware/internal/oidc"
	"github.com/xenitab/go-oidc-middleware/internal/oidctesting"
	"github.com/xenitab/go-oidc-middleware/options"

	"github.com/gin-gonic/gin"
)

const testName = "OidcGin"

func TestSuite(t *testing.T) {
	oidctesting.RunTests(t, testName, newTestHandler(t))
}

func BenchmarkSuite(b *testing.B) {
	oidctesting.RunBenchmarks(b, testName, newTestHandler(b))
}

func testGetGinRouter(tb testing.TB, middleware gin.HandlerFunc) *gin.Engine {
	tb.Helper()

	// remove debug output from tests
	gin.SetMode(gin.ReleaseMode)
	gin.DefaultWriter = io.Discard
	gin.DefaultErrorWriter = io.Discard

	r := gin.Default()

	r.Use(middleware)

	r.GET("/", func(c *gin.Context) {
		claimsValue, found := c.Get("claims")
		if !found {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		claims, ok := claimsValue.(oidctesting.TestClaims)
		if !ok {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		c.JSON(http.StatusOK, claims)
	})

	return r
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

type testHandler struct {
	tb testing.TB
}

func newTestHandler(tb testing.TB) *testHandler {
	tb.Helper()

	return &testHandler{
		tb: tb,
	}
}

func (h *testHandler) NewHandlerFn(opts ...options.Option) http.Handler {
	h.tb.Helper()

	middleware := New[oidctesting.TestClaims](nil, opts...)
	return testGetGinRouter(h.tb, middleware)
}

func (h *testHandler) ToHandlerFn(parseToken oidc.ParseTokenFunc[oidctesting.TestClaims], opts ...options.Option) http.Handler {
	h.tb.Helper()

	middleware := toGinHandler(parseToken, opts...)
	return testGetGinRouter(h.tb, middleware)
}

func (h *testHandler) NewTestServer(opts ...options.Option) oidctesting.ServerTester {
	h.tb.Helper()

	middleware := New[oidctesting.TestClaims](nil, opts...)
	return newTestServer(h.tb, testGetGinRouter(h.tb, middleware))
}
