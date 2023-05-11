package oidcgin

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/xenitab/go-oidc-middleware/internal/oidc"
	"github.com/xenitab/go-oidc-middleware/internal/oidctesting"
	"github.com/xenitab/go-oidc-middleware/optest"
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

func testGetGinRouter(tb testing.TB, middlewares []gin.HandlerFunc) *gin.Engine {
	tb.Helper()

	// remove debug output from tests
	gin.SetMode(gin.ReleaseMode)
	gin.DefaultWriter = io.Discard
	gin.DefaultErrorWriter = io.Discard

	r := gin.Default()

	for _, m := range middlewares {
		r.Use(m)
	}

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

func (h *testHandler) NewHandlerFn(claimsValidationFn options.ClaimsValidationFn[oidctesting.TestClaims], opts ...options.Option) http.Handler {
	h.tb.Helper()

	middleware := New(claimsValidationFn, opts...)
	return testGetGinRouter(h.tb, []gin.HandlerFunc{middleware})
}

func (h *testHandler) ToHandlerFn(parseToken oidc.ParseTokenFunc[oidctesting.TestClaims], opts ...options.Option) http.Handler {
	h.tb.Helper()

	middleware := toGinHandler(parseToken, opts...)
	return testGetGinRouter(h.tb, []gin.HandlerFunc{middleware})
}

func (h *testHandler) NewTestServer(opts ...options.Option) oidctesting.ServerTester {
	h.tb.Helper()

	middleware := New[oidctesting.TestClaims](nil, opts...)
	return newTestServer(h.tb, testGetGinRouter(h.tb, []gin.HandlerFunc{middleware}))
}

func TestAbortion(t *testing.T) {
	op := optest.NewTesting(t)
	defer op.Close(t)

	errorHandler := func(ctx context.Context, oidcErr *options.OidcError) *options.Response {
		return &options.Response{
			StatusCode: 418,
			Headers:    map[string]string{},
			Body:       []byte("badness"),
		}
	}
	opts := []options.Option{
		options.WithIssuer(op.GetURL(t)),
		options.WithRequiredAudience("test-client"),
		options.WithRequiredTokenType("JWT+AT"),
		options.WithErrorHandler(errorHandler),
	}
	nextCalled := false
	next := func(c *gin.Context) {
		nextCalled = true
	}

	middleware := New[oidctesting.TestClaims](nil, opts...)
	r := testGetGinRouter(t, []gin.HandlerFunc{middleware, next})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	r.ServeHTTP(httptest.NewRecorder(), req)
	require.Equal(t, false, nextCalled)
}
