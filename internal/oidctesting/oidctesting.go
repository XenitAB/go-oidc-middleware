package oidctesting

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/xenitab/dispans/server"
	"github.com/xenitab/go-oidc-middleware/internal/oidc"
	"github.com/xenitab/go-oidc-middleware/options"
	"golang.org/x/oauth2"
)

type newHandlerFn func(opts ...options.Option) http.Handler
type toHandlerFn func(parseToken oidc.ParseTokenFunc) http.Handler

func RunBenchmarks(b *testing.B, testName string, newHandlerFn newHandlerFn) {
	b.Helper()

	benchmarkHandler(b, testName, newHandlerFn)
	benchmarkRequirements(b, testName, newHandlerFn)
	benchmarkHttp(b, testName, newHandlerFn)
}

func benchmarkHandler(b *testing.B, testName string, newHandlerFn newHandlerFn) {
	b.Helper()

	b.Run(fmt.Sprintf("handler_%s", testName), func(b *testing.B) {
		op := server.NewTesting(b)
		defer op.Close(b)

		handler := newHandlerFn(
			options.WithIssuer(op.GetURL(b)),
		)

		fn := func(token *oauth2.Token) {
			testHttpWithAuthentication(b, token, handler)
		}

		BenchmarkConcurrent(b, op.GetToken, fn)
	})
}

func benchmarkRequirements(b *testing.B, testName string, newHandlerFn newHandlerFn) {
	b.Helper()

	b.Run(fmt.Sprintf("requirements_%s", testName), func(b *testing.B) {
		op := server.NewTesting(b)
		defer op.Close(b)

		handler := newHandlerFn(
			options.WithIssuer(op.GetURL(b)),
			options.WithRequiredTokenType("JWT+AT"),
			options.WithRequiredAudience("test-client"),
			options.WithRequiredClaims(map[string]interface{}{
				"sub": "test",
			}),
		)

		fn := func(token *oauth2.Token) {
			testHttpWithAuthentication(b, token, handler)
		}

		BenchmarkConcurrent(b, op.GetToken, fn)
	})
}

func benchmarkHttp(b *testing.B, testName string, newHandlerFn newHandlerFn) {
	b.Helper()

	b.Run(fmt.Sprintf("http_%s", testName), func(b *testing.B) {
		op := server.NewTesting(b)
		defer op.Close(b)

		handler := newHandlerFn(
			options.WithIssuer(op.GetURL(b)),
		)

		testServer := httptest.NewServer(handler)
		defer testServer.Close()

		fn := func(token *oauth2.Token) {
			TestHttpRequest(b, testServer.URL, token)
		}

		BenchmarkConcurrent(b, op.GetToken, fn)
	})
}

func BenchmarkConcurrent(b *testing.B, getToken func(t testing.TB) *oauth2.Token, fn func(token *oauth2.Token)) {
	b.Helper()

	concurrencyLevels := []int{5, 10, 20, 50}
	for _, clients := range concurrencyLevels {
		numClients := clients
		b.Run(fmt.Sprintf("%d_clients", numClients), func(b *testing.B) {
			var tokens []*oauth2.Token
			for i := 0; i < b.N; i++ {
				tokens = append(tokens, getToken(b))
			}

			b.ResetTimer()

			var wg sync.WaitGroup
			ch := make(chan int, numClients)
			for i := 0; i < b.N; i++ {
				token := tokens[i]
				wg.Add(1)
				ch <- 1
				go func() {
					defer wg.Done()
					fn(token)
					<-ch
				}()
			}
			wg.Wait()
		})
	}
}

func RunTests(t *testing.T, testName string, newHandlerFn newHandlerFn, toHandlerFn toHandlerFn) {
	t.Helper()

	testNew(t, testName, newHandlerFn)
	testHandler(t, testName, newHandlerFn)
	testLazyLoad(t, testName, toHandlerFn)
	testRequirements(t, testName, newHandlerFn)
}

func TestHttpRequest(tb testing.TB, urlString string, token *oauth2.Token) {
	tb.Helper()

	req, err := http.NewRequest(http.MethodGet, urlString, nil)
	require.NoError(tb, err)
	token.SetAuthHeader(req)
	res, err := http.DefaultClient.Do(req)
	require.NoError(tb, err)

	defer require.NoError(tb, res.Body.Close())

	require.Equal(tb, http.StatusOK, res.StatusCode)
}

func testNew(t *testing.T, testName string, newHandlerFn newHandlerFn) {
	t.Helper()

	t.Run(fmt.Sprintf("new_%s", testName), func(t *testing.T) {
		op := server.NewTesting(t)
		defer op.Close(t)

		cases := []struct {
			testDescription string
			config          []options.Option
			expectPanic     bool
		}{
			{
				testDescription: "valid issuer doesn't panic",
				config: []options.Option{
					options.WithIssuer(op.GetURL(t)),
				},
				expectPanic: false,
			},
			{
				testDescription: "valid issuer, invalid DiscoveryUri panics",
				config: []options.Option{
					options.WithIssuer(op.GetURL(t)),
					options.WithDiscoveryUri("http://foo.bar/baz"),
				},
				expectPanic: true,
			},
			{
				testDescription: "valid issuer, invalid JwksUri panics",
				config: []options.Option{
					options.WithIssuer(op.GetURL(t)),
					options.WithJwksUri("http://foo.bar/baz"),
				},
				expectPanic: true,
			},
			{
				testDescription: "empty config panics",
				config:          []options.Option{},
				expectPanic:     true,
			},
			{
				testDescription: "fake issuer panics",
				config: []options.Option{
					options.WithIssuer("http://foo.bar/baz"),
				},
				expectPanic: true,
			},
			{
				testDescription: "fake issuer with lazy load doesn't panic",
				config: []options.Option{
					options.WithIssuer("http://foo.bar/baz"),
					options.WithLazyLoadJwks(true),
				},
				expectPanic: false,
			},
			{
				testDescription: "valid signature algorithm doesn't panic",
				config: []options.Option{
					options.WithIssuer(op.GetURL(t)),
					options.WithFallbackSignatureAlgorithm("RS256"),
				},
				expectPanic: false,
			},
			{
				testDescription: "invalid signature algorithm panics",
				config: []options.Option{
					options.WithIssuer(op.GetURL(t)),
					options.WithFallbackSignatureAlgorithm("foobar"),
				},
				expectPanic: true,
			},
		}

		for i, c := range cases {
			t.Logf("Test iteration %d: %s", i, c.testDescription)
			if c.expectPanic {
				require.Panics(t, func() { newHandlerFn(c.config...) })
			} else {
				require.NotPanics(t, func() { newHandlerFn(c.config...) })
			}
		}
	})
}

func testHandler(t *testing.T, testName string, newHandlerFn newHandlerFn) {
	t.Helper()

	t.Run(fmt.Sprintf("handler_%s", testName), func(t *testing.T) {
		op := server.NewTesting(t)
		defer op.Close(t)

		handler := newHandlerFn(
			options.WithIssuer(op.GetURL(t)),
			options.WithRequiredAudience("test-client"),
			options.WithRequiredTokenType("JWT+AT"),
		)

		// Test without authentication
		reqNoAuth := httptest.NewRequest(http.MethodGet, "/", nil)
		recNoAuth := httptest.NewRecorder()
		handler.ServeHTTP(recNoAuth, reqNoAuth)

		require.Equal(t, http.StatusBadRequest, recNoAuth.Result().StatusCode)

		// Test with authentication
		token := op.GetToken(t)
		testHttpWithAuthentication(t, token, handler)
		testHttpWithIDTokenFailure(t, token, handler)

		// Test with rotated key
		op.RotateKeys(t)
		tokenWithRotatedKey := op.GetToken(t)
		testHttpWithAuthentication(t, tokenWithRotatedKey, handler)
	})
}

func testLazyLoad(t *testing.T, testName string, toHandlerFn toHandlerFn) {
	t.Helper()

	t.Run(fmt.Sprintf("lazy_load_%s", testName), func(t *testing.T) {
		op := server.NewTesting(t)
		defer op.Close(t)

		oidcHandler, err := oidc.NewHandler(
			options.WithIssuer("http://foo.bar/baz"),
			options.WithRequiredAudience("test-client"),
			options.WithRequiredTokenType("JWT+AT"),
			options.WithLazyLoadJwks(true),
		)
		require.NoError(t, err)

		handler := toHandlerFn(oidcHandler.ParseToken)

		// Test without authentication
		reqNoAuth := httptest.NewRequest(http.MethodGet, "/", nil)
		recNoAuth := httptest.NewRecorder()
		handler.ServeHTTP(recNoAuth, reqNoAuth)

		require.Equal(t, http.StatusBadRequest, recNoAuth.Result().StatusCode)

		// Test with authentication
		token := op.GetToken(t)
		testHttpWithAuthenticationFailure(t, token, handler)

		oidcHandler.SetIssuer(op.GetURL(t))
		oidcHandler.SetDiscoveryUri(oidc.GetDiscoveryUriFromIssuer(op.GetURL(t)))

		testHttpWithAuthentication(t, token, handler)
	})
}

func testRequirements(t *testing.T, testName string, newHandlerFn newHandlerFn) {
	t.Helper()

	t.Run(fmt.Sprintf("requirements_%s", testName), func(t *testing.T) {
		op := server.NewTesting(t)
		defer op.Close(t)

		cases := []struct {
			testDescription string
			options         []options.Option
			succeeds        bool
		}{
			{
				testDescription: "no requirements",
				options: []options.Option{
					options.WithIssuer(op.GetURL(t)),
				},
				succeeds: true,
			},
			{
				testDescription: "required token type matches",
				options: []options.Option{
					options.WithIssuer(op.GetURL(t)),
					options.WithRequiredTokenType("JWT+AT"),
				},
				succeeds: true,
			},
			{
				testDescription: "required token type doesn't match",
				options: []options.Option{
					options.WithIssuer(op.GetURL(t)),
					options.WithRequiredTokenType("FOO"),
				},
				succeeds: false,
			},
			{
				testDescription: "required audience matches",
				options: []options.Option{
					options.WithIssuer(op.GetURL(t)),
					options.WithRequiredAudience("test-client"),
				},
				succeeds: true,
			},
			{
				testDescription: "required audience doesn't match",
				options: []options.Option{
					options.WithIssuer(op.GetURL(t)),
					options.WithRequiredAudience("foo"),
				},
				succeeds: false,
			},
			{
				testDescription: "required sub matches",
				options: []options.Option{
					options.WithIssuer(op.GetURL(t)),
					options.WithRequiredClaims(map[string]interface{}{
						"sub": "test",
					}),
				},
				succeeds: true,
			},
			{
				testDescription: "required sub doesn't match",
				options: []options.Option{
					options.WithIssuer(op.GetURL(t)),
					options.WithRequiredClaims(map[string]interface{}{
						"sub": "foo",
					}),
				},
				succeeds: false,
			},
		}

		for i, c := range cases {
			t.Logf("Test iteration %d: %s", i, c.testDescription)

			handler := newHandlerFn(c.options...)
			token := op.GetToken(t)

			if c.succeeds {
				testHttpWithAuthentication(t, token, handler)
			} else {
				testHttpWithAuthenticationFailure(t, token, handler)
			}
		}
	})
}

func testHttpWithAuthentication(tb testing.TB, token *oauth2.Token, handler http.Handler) {
	tb.Helper()

	req := httptest.NewRequest(http.MethodGet, "/", nil)

	token.Valid()
	token.SetAuthHeader(req)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	res := rec.Result()

	require.Equal(tb, http.StatusOK, res.StatusCode)
}

func testHttpWithIDTokenFailure(tb testing.TB, token *oauth2.Token, handler http.Handler) {
	tb.Helper()

	req := httptest.NewRequest(http.MethodGet, "/", nil)

	idToken, ok := token.Extra("id_token").(string)
	require.True(tb, ok)

	token.AccessToken = idToken

	token.SetAuthHeader(req)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	res := rec.Result()

	require.Equal(tb, http.StatusUnauthorized, res.StatusCode)
}

func testHttpWithAuthenticationFailure(tb testing.TB, token *oauth2.Token, handler http.Handler) {
	tb.Helper()

	req := httptest.NewRequest(http.MethodGet, "/", nil)

	token.Valid()
	token.SetAuthHeader(req)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	res := rec.Result()

	require.Equal(tb, http.StatusUnauthorized, res.StatusCode)
}
