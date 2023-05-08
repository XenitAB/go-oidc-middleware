package oidcecho

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/xenitab/go-oidc-middleware/internal/oidc"
	"github.com/xenitab/go-oidc-middleware/internal/oidctesting"
	"github.com/xenitab/go-oidc-middleware/options"

	"github.com/labstack/echo/v4"
	"github.com/phayes/freeport"
	"github.com/stretchr/testify/require"
)

const testName = "OidcEchoJwt"

func TestSuite(t *testing.T) {
	oidctesting.RunTests(t, testName, newTestHandler(t))
}

func BenchmarkSuite(b *testing.B) {
	oidctesting.RunBenchmarks(b, testName, newTestHandler(b))
}

func testGetEchoRouter(tb testing.TB, oidcMiddleware echo.MiddlewareFunc) *echo.Echo {
	tb.Helper()

	e := echo.New()
	e.HidePort = true
	e.HideBanner = true

	e.Use(oidcMiddleware)

	e.GET("/", func(c echo.Context) error {
		claims, ok := c.Get("claims").(oidctesting.TestClaims)
		if !ok {
			return echo.NewHTTPError(http.StatusUnauthorized, "invalid token")
		}

		return c.JSON(http.StatusOK, claims)
	})

	return e
}

type testServer struct {
	tb   testing.TB
	e    *echo.Echo
	port int
}

func newTestServer(tb testing.TB, e *echo.Echo) *testServer {
	tb.Helper()

	port, err := freeport.GetFreePort()
	require.NoError(tb, err)

	go func() {
		err := e.Start(fmt.Sprintf("127.0.0.1:%d", port))
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			require.NoError(tb, err)
		}
	}()

	return &testServer{
		tb:   tb,
		e:    e,
		port: port,
	}
}

func (srv *testServer) Close() {
	srv.tb.Helper()

	context, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := srv.e.Shutdown(context)
	require.NoError(srv.tb, err)
}

func (srv *testServer) URL() string {
	srv.tb.Helper()

	return fmt.Sprintf("http://127.0.0.1:%d", srv.port)
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

	echoParseToken := New(claimsValidationFn, opts...)
	return testGetEchoRouter(h.tb, echoParseToken)
}

func (h *testHandler) ToHandlerFn(parseToken oidc.ParseTokenFunc[oidctesting.TestClaims], opts ...options.Option) http.Handler {
	h.tb.Helper()

	oidcMiddleware := toEchoMiddleware(parseToken, opts...)
	return testGetEchoRouter(h.tb, oidcMiddleware)
}

func (h *testHandler) NewTestServer(opts ...options.Option) oidctesting.ServerTester {
	h.tb.Helper()

	oidcMiddleware := New[oidctesting.TestClaims](nil, opts...)
	return newTestServer(h.tb, testGetEchoRouter(h.tb, oidcMiddleware))
}
