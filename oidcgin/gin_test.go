package oidcgin

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"github.com/xenitab/dispans/server"
	"github.com/xenitab/go-oidc-middleware/internal/oidc"
	"github.com/xenitab/go-oidc-middleware/internal/oidctesting"
	"golang.org/x/oauth2"
)

func TestNewGinMiddleware(t *testing.T) {
	op := server.NewTesting(t)
	defer op.Close(t)

	cases := []struct {
		testDescription string
		config          Options
		expectPanic     bool
	}{
		{
			testDescription: "valid issuer doesn't panic",
			config: Options{
				Issuer: op.GetURL(t),
			},
			expectPanic: false,
		},
		{
			testDescription: "valid issuer, invalid DiscoveryUri panics",
			config: Options{
				Issuer:       op.GetURL(t),
				DiscoveryUri: "http://foo.bar/baz",
			},
			expectPanic: true,
		},
		{
			testDescription: "valid issuer, invalid JwksUri panics",
			config: Options{
				Issuer:  op.GetURL(t),
				JwksUri: "http://foo.bar/baz",
			},
			expectPanic: true,
		},
		{
			testDescription: "empty config panics",
			config:          Options{},
			expectPanic:     true,
		},
		{
			testDescription: "fake issuer panics",
			config: Options{
				Issuer: "http://foo.bar/baz",
			},
			expectPanic: true,
		},
		{
			testDescription: "fake issuer with lazy load doesn't panic",
			config: Options{
				Issuer:       "http://foo.bar/baz",
				LazyLoadJwks: true,
			},
			expectPanic: false,
		},
		{
			testDescription: "valid signature algorithm doesn't panic",
			config: Options{
				Issuer:                     op.GetURL(t),
				FallbackSignatureAlgorithm: "RS256",
			},
			expectPanic: false,
		},
		{
			testDescription: "invalid signature algorithm panics",
			config: Options{
				Issuer:                     op.GetURL(t),
				FallbackSignatureAlgorithm: "foobar",
			},
			expectPanic: true,
		},
	}

	for i, c := range cases {
		t.Logf("Test iteration %d: %s", i, c.testDescription)
		if c.expectPanic {
			require.Panics(t, func() { New(&c.config) })
		} else {
			require.NotPanics(t, func() { New(&c.config) })
		}
	}
}

func TestGin(t *testing.T) {
	op := server.NewTesting(t)
	defer op.Close(t)

	middleware := New(&Options{
		Issuer:            op.GetURL(t),
		RequiredAudience:  "test-client",
		RequiredTokenType: "JWT+AT",
	})

	router := testGetGinRouter(t, middleware)

	// Test without authentication
	reqNoAuth := httptest.NewRequest(http.MethodGet, "/", nil)
	recNoAuth := httptest.NewRecorder()
	router.ServeHTTP(recNoAuth, reqNoAuth)

	require.Equal(t, http.StatusBadRequest, recNoAuth.Result().StatusCode)

	// Test with authentication
	token := op.GetToken(t)
	testHttpWithAuthentication(t, token, router)
	testHttpWithIDTokenFailure(t, token, router)

	// Test with rotated key
	op.RotateKeys(t)
	tokenWithRotatedKey := op.GetToken(t)
	testHttpWithAuthentication(t, tokenWithRotatedKey, router)
}

func TestGinLazyLoad(t *testing.T) {
	op := server.NewTesting(t)
	defer op.Close(t)

	oidcHandler, err := oidc.NewHandler(&oidc.Options{
		Issuer:            "http://foo.bar/baz",
		RequiredAudience:  "test-client",
		RequiredTokenType: "JWT+AT",
		LazyLoadJwks:      true,
	})
	require.NoError(t, err)

	middleware := toGinHandler(oidcHandler.ParseToken)
	router := testGetGinRouter(t, middleware)

	// Test without authentication
	reqNoAuth := httptest.NewRequest(http.MethodGet, "/", nil)
	recNoAuth := httptest.NewRecorder()
	router.ServeHTTP(recNoAuth, reqNoAuth)

	require.Equal(t, http.StatusBadRequest, recNoAuth.Result().StatusCode)

	// Test with authentication
	token := op.GetToken(t)
	testHttpWithAuthenticationFailure(t, token, router)

	oidcHandler.SetIssuer(op.GetURL(t))
	oidcHandler.SetDiscoveryUri(oidc.GetDiscoveryUriFromIssuer(op.GetURL(t)))

	testHttpWithAuthentication(t, token, router)
}

func TestGinRequirements(t *testing.T) {
	op := server.NewTesting(t)
	defer op.Close(t)

	cases := []struct {
		testDescription string
		options         Options
		succeeds        bool
	}{
		{
			testDescription: "no requirements",
			options: Options{
				Issuer: op.GetURL(t),
			},
			succeeds: true,
		},
		{
			testDescription: "required token type matches",
			options: Options{
				Issuer:            op.GetURL(t),
				RequiredTokenType: "JWT+AT",
			},
			succeeds: true,
		},
		{
			testDescription: "required token type doesn't match",
			options: Options{
				Issuer:            op.GetURL(t),
				RequiredTokenType: "FOO",
			},
			succeeds: false,
		},
		{
			testDescription: "required audience matches",
			options: Options{
				Issuer:           op.GetURL(t),
				RequiredAudience: "test-client",
			},
			succeeds: true,
		},
		{
			testDescription: "required audience doesn't match",
			options: Options{
				Issuer:           op.GetURL(t),
				RequiredAudience: "foo",
			},
			succeeds: false,
		},
		{
			testDescription: "required sub matches",
			options: Options{
				Issuer: op.GetURL(t),
				RequiredClaims: map[string]interface{}{
					"sub": "test",
				},
			},
			succeeds: true,
		},
		{
			testDescription: "required sub doesn't match",
			options: Options{
				Issuer: op.GetURL(t),
				RequiredClaims: map[string]interface{}{
					"sub": "foo",
				},
			},
			succeeds: false,
		},
	}

	for i, c := range cases {
		t.Logf("Test iteration %d: %s", i, c.testDescription)

		middleware := New(&c.options)

		router := testGetGinRouter(t, middleware)

		token := op.GetToken(t)

		if c.succeeds {
			testHttpWithAuthentication(t, token, router)
		} else {
			testHttpWithAuthenticationFailure(t, token, router)
		}
	}
}

func BenchmarkGin(b *testing.B) {
	op := server.NewTesting(b)
	defer op.Close(b)

	middleware := New(&Options{
		Issuer: op.GetURL(b),
	})

	router := testGetGinRouter(b, middleware)

	fn := func(token *oauth2.Token) {
		testHttpWithAuthentication(b, token, router)
	}

	oidctesting.BenchmarkConcurrent(b, op.GetToken, fn)
}

func BenchmarkGinRequirements(b *testing.B) {
	op := server.NewTesting(b)
	defer op.Close(b)

	middleware := New(&Options{
		Issuer:            op.GetURL(b),
		RequiredTokenType: "JWT+AT",
		RequiredAudience:  "test-client",
		RequiredClaims: map[string]interface{}{
			"sub": "test",
		},
	})

	router := testGetGinRouter(b, middleware)

	fn := func(token *oauth2.Token) {
		testHttpWithAuthentication(b, token, router)
	}

	oidctesting.BenchmarkConcurrent(b, op.GetToken, fn)
}

func BenchmarkGinHttp(b *testing.B) {
	op := server.NewTesting(b)
	defer op.Close(b)

	middleware := New(&Options{
		Issuer: op.GetURL(b),
	})

	router := testGetGinRouter(b, middleware)

	testServer := httptest.NewServer(router)
	defer testServer.Close()

	fn := func(token *oauth2.Token) {
		oidctesting.TestHttpRequest(b, testServer.URL, token)
	}

	oidctesting.BenchmarkConcurrent(b, op.GetToken, fn)
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

		claims, ok := claimsValue.(map[string]interface{})
		if !ok {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		c.JSON(http.StatusOK, claims)
	})

	return r
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
