package oidcfiber

import (
	"fmt"
	"io"
	"net/http"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/phayes/freeport"
	"github.com/stretchr/testify/require"
	"github.com/xenitab/go-oidc-middleware/internal/oidc"
	"github.com/xenitab/go-oidc-middleware/internal/oidctesting"
	"github.com/xenitab/go-oidc-middleware/options"
)

const testName = "OidcFiber"

func TestSuite(t *testing.T) {
	oidctesting.RunTests(t, testName, newTestHandler(t))
}

func BenchmarkSuite(b *testing.B) {
	oidctesting.RunBenchmarks(b, testName, newTestHandler(b))
}

func testGetFiberRouter(tb testing.TB, middleware fiber.Handler) *fiber.App {
	tb.Helper()

	app := fiber.New(fiber.Config{
		DisableStartupMessage: true,
	})
	app.Use(middleware)

	app.Get("/", func(c *fiber.Ctx) error {
		claims, ok := c.Locals("claims").(map[string]interface{})
		if !ok {
			return c.SendStatus(fiber.StatusUnauthorized)
		}

		return c.JSON(claims)
	})

	return app
}

type testServer struct {
	tb   testing.TB
	app  *fiber.App
	port int
}

func newTestServer(tb testing.TB, app *fiber.App) *testServer {
	tb.Helper()

	port, err := freeport.GetFreePort()
	require.NoError(tb, err)

	go func() {
		err := app.Listen(fmt.Sprintf("127.0.0.1:%d", port))
		require.NoError(tb, err)
	}()

	return &testServer{
		tb:   tb,
		app:  app,
		port: port,
	}
}

func (srv *testServer) Close() {
	srv.tb.Helper()

	err := srv.app.Shutdown()
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

func (h *testHandler) NewHandlerFn(opts ...options.Option) http.Handler {
	h.tb.Helper()

	middleware := New(opts...)
	app := testGetFiberRouter(h.tb, middleware)

	return newTestFiberHandler(h.tb, app)
}

func (h *testHandler) ToHandlerFn(parseToken oidc.ParseTokenFunc) http.Handler {
	h.tb.Helper()

	middleware := toFiberHandler(parseToken)
	app := testGetFiberRouter(h.tb, middleware)

	return newTestFiberHandler(h.tb, app)
}

func (h *testHandler) NewTestServer(opts ...options.Option) oidctesting.ServerTester {
	h.tb.Helper()

	middleware := New(opts...)
	app := testGetFiberRouter(h.tb, middleware)

	return newTestServer(h.tb, app)
}

type testFiberHandler struct {
	app *fiber.App
	tb  testing.TB
}

func newTestFiberHandler(tb testing.TB, app *fiber.App) http.Handler {
	tb.Helper()

	fiberHandler := &testFiberHandler{
		app: app,
		tb:  tb,
	}

	return fiberHandler
}

func (f *testFiberHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	res, err := f.app.Test(r)
	require.NoError(f.tb, err)

	for name, values := range res.Header {
		w.Header()[name] = values
	}

	w.WriteHeader(res.StatusCode)

	_, err = io.Copy(w, res.Body)
	require.NoError(f.tb, err)

	err = res.Body.Close()
	require.NoError(f.tb, err)
}
