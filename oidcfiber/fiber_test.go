package oidcfiber

import (
	"io"
	"net/http"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/require"
	"github.com/xenitab/go-oidc-middleware/internal/oidc"
	"github.com/xenitab/go-oidc-middleware/internal/oidctesting"
	"github.com/xenitab/go-oidc-middleware/options"
)

const testName = "OidcFiber"

func TestSuite(t *testing.T) {
	oidctesting.RunTests(t, testName, testNewHandlerFn(t), testToHandlerFn(t))
}

func BenchmarkSuite(b *testing.B) {
	oidctesting.RunBenchmarks(b, testName, testNewHandlerFn(b))
}

func testNewHandlerFn(tb testing.TB) func(opts ...options.Option) http.Handler {
	tb.Helper()

	return func(opts ...options.Option) http.Handler {
		middleware := New(opts...)
		return testGetFiberRouter(tb, middleware)
	}
}

func testToHandlerFn(tb testing.TB) func(parseToken oidc.ParseTokenFunc) http.Handler {
	tb.Helper()

	return func(parseToken oidc.ParseTokenFunc) http.Handler {
		middleware := toFiberHandler(parseToken)
		return testGetFiberRouter(tb, middleware)
	}
}

func testGetFiberRouter(tb testing.TB, middleware fiber.Handler) http.Handler {
	tb.Helper()

	app := fiber.New()
	app.Use(middleware)

	app.Get("/", func(c *fiber.Ctx) error {
		claims, ok := c.Locals("claims").(map[string]interface{})
		if !ok {
			return c.SendStatus(fiber.StatusUnauthorized)
		}

		return c.JSON(claims)
	})

	fiberHttp := &testFiberHttpHandler{
		app: app,
		tb:  tb,
	}

	return fiberHttp
}

type testFiberHttpHandler struct {
	app *fiber.App
	tb  testing.TB
}

func (f *testFiberHttpHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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
