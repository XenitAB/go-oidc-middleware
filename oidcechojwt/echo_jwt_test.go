package oidcechojwt

import (
	"net/http"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/xenitab/go-oidc-middleware/internal/oidc"
	"github.com/xenitab/go-oidc-middleware/internal/oidctesting"
	"github.com/xenitab/go-oidc-middleware/options"
)

const testName = "OidcEchoJwt"

func TestSuite(t *testing.T) {
	oidctesting.RunTests(t, testName, testNewHandlerFn(t), testToHandlerFn(t))
}

func BenchmarkSuite(b *testing.B) {
	oidctesting.RunBenchmarks(b, testName, testNewHandlerFn(b))
}

func testNewHandlerFn(tb testing.TB) func(opts ...options.Option) http.Handler {
	tb.Helper()

	return func(opts ...options.Option) http.Handler {
		echoParseToken := New(opts...)
		return testGetEchoRouter(tb, echoParseToken)
	}
}

func testToHandlerFn(tb testing.TB) func(parseToken oidc.ParseTokenFunc) http.Handler {
	tb.Helper()

	return func(parseToken oidc.ParseTokenFunc) http.Handler {
		echoParseToken := toEchoJWTParseTokenFunc(parseToken)
		return testGetEchoRouter(tb, echoParseToken)
	}
}

func testGetEchoRouter(tb testing.TB, parseToken echoJWTParseTokenFunc) *echo.Echo {
	tb.Helper()

	e := echo.New()
	e.HidePort = true
	e.HideBanner = true

	e.Use(middleware.JWTWithConfig(middleware.JWTConfig{
		ParseTokenFunc: parseToken,
	}))

	e.GET("/", func(c echo.Context) error {
		token, ok := c.Get("user").(jwt.Token)
		if !ok {
			return echo.NewHTTPError(http.StatusUnauthorized, "invalid token")
		}

		claims, err := token.AsMap(c.Request().Context())
		if err != nil {
			return echo.NewHTTPError(http.StatusUnauthorized, "invalid token")
		}

		return c.JSON(http.StatusOK, claims)
	})

	return e
}
