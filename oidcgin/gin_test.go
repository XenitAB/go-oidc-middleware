package oidcgin

import (
	"io"
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/xenitab/go-oidc-middleware/internal/oidc"
	"github.com/xenitab/go-oidc-middleware/internal/oidctesting"
	"github.com/xenitab/go-oidc-middleware/options"
)

const testName = "OidcGin"

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
		return testGetGinRouter(tb, middleware)
	}
}

func testToHandlerFn(tb testing.TB) func(parseToken oidc.ParseTokenFunc) http.Handler {
	tb.Helper()

	return func(parseToken oidc.ParseTokenFunc) http.Handler {
		middleware := toGinHandler(parseToken)
		return testGetGinRouter(tb, middleware)
	}
}

func testGetGinRouter(tb testing.TB, middleware gin.HandlerFunc) *gin.Engine {
	tb.Helper()

	opts := options.New()

	// remove debug output from tests
	gin.SetMode(gin.ReleaseMode)
	gin.DefaultWriter = io.Discard
	gin.DefaultErrorWriter = io.Discard

	r := gin.Default()

	r.Use(middleware)

	r.GET("/", func(c *gin.Context) {
		claimsValue, found := c.Get(string(opts.ClaimsContextKeyName))
		if !found {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		claims, ok := claimsValue.(map[string]interface{})
		if !ok {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		c.JSON(http.StatusOK, claims)
	})

	return r
}
