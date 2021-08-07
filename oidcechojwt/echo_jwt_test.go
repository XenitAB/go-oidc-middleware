package oidcechojwt

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/phayes/freeport"
	"github.com/stretchr/testify/require"
	"github.com/xenitab/dispans/server"
	"github.com/xenitab/go-oidc-middleware/internal/oidc"
	"github.com/xenitab/go-oidc-middleware/internal/oidctesting"
	"golang.org/x/oauth2"
)

func TestNew(t *testing.T) {
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

func TestEchoJWT(t *testing.T) {
	op := server.NewTesting(t)
	defer op.Close(t)

	handler := testGetEchoHandler(t)

	e := echo.New()
	h := middleware.JWTWithConfig(middleware.JWTConfig{
		ParseTokenFunc: New(&Options{
			Issuer:            op.GetURL(t),
			RequiredAudience:  "test-client",
			RequiredTokenType: "JWT+AT",
		}),
	})(handler)

	// Test without authentication
	reqNoAuth := httptest.NewRequest(http.MethodGet, "/", nil)
	recNoAuth := httptest.NewRecorder()
	cNoAuth := e.NewContext(reqNoAuth, recNoAuth)

	err := h(cNoAuth)
	require.Error(t, err)

	// Test with authentication
	token := op.GetToken(t)
	testEchoJWTWithAuthentication(t, token, h, e)
	testEchoJWTWithIDTokenFailure(t, token, h, e)

	// Test with rotated key
	op.RotateKeys(t)
	tokenWithRotatedKey := op.GetToken(t)
	testEchoJWTWithAuthentication(t, tokenWithRotatedKey, h, e)
}

func TestEchoJWTLazyLoad(t *testing.T) {
	op := server.NewTesting(t)
	defer op.Close(t)

	handler := testGetEchoHandler(t)

	oidcHandler, err := oidc.NewHandler(&oidc.Options{
		Issuer:            "http://foo.bar/baz",
		RequiredAudience:  "test-client",
		RequiredTokenType: "JWT+AT",
		LazyLoadJwks:      true,
	})
	require.NoError(t, err)

	e := echo.New()
	h := middleware.JWTWithConfig(middleware.JWTConfig{
		ParseTokenFunc: toEchoJWTParseTokenFunc(oidcHandler.ParseToken),
	})(handler)

	// Test without authentication
	reqNoAuth := httptest.NewRequest(http.MethodGet, "/", nil)
	recNoAuth := httptest.NewRecorder()
	cNoAuth := e.NewContext(reqNoAuth, recNoAuth)

	err = h(cNoAuth)
	require.Error(t, err)

	// Test with authentication
	token := op.GetToken(t)
	testEchoJWTWithAuthenticationFailure(t, token, h, e)

	oidcHandler.SetIssuer(op.GetURL(t))
	oidcHandler.SetDiscoveryUri(oidc.GetDiscoveryUriFromIssuer(op.GetURL(t)))

	testEchoJWTWithAuthentication(t, token, h, e)
}

func TestEchoJWTRequirements(t *testing.T) {
	op := server.NewTesting(t)
	defer op.Close(t)

	handler := testGetEchoHandler(t)

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

		e := echo.New()
		h := middleware.JWTWithConfig(middleware.JWTConfig{
			ParseTokenFunc: New(&c.options),
		})(handler)

		token := op.GetToken(t)

		if c.succeeds {
			testEchoJWTWithAuthentication(t, token, h, e)
		} else {
			testEchoJWTWithAuthenticationFailure(t, token, h, e)
		}
	}
}

func BenchmarkEchoJWT(b *testing.B) {
	op := server.NewTesting(b)
	defer op.Close(b)

	handler := testGetEchoHandler(b)

	e := echo.New()
	h := middleware.JWTWithConfig(middleware.JWTConfig{
		ParseTokenFunc: New(&Options{
			Issuer: op.GetURL(b),
		}),
	})(handler)

	fn := func(token *oauth2.Token) {
		testEchoJWTWithAuthentication(b, token, h, e)
	}

	oidctesting.BenchmarkConcurrent(b, op.GetToken, fn)
}

func BenchmarkEchoJWTRequirements(b *testing.B) {
	op := server.NewTesting(b)
	defer op.Close(b)

	handler := testGetEchoHandler(b)

	e := echo.New()
	h := middleware.JWTWithConfig(middleware.JWTConfig{
		ParseTokenFunc: New(&Options{
			Issuer:            op.GetURL(b),
			RequiredTokenType: "JWT+AT",
			RequiredAudience:  "test-client",
			RequiredClaims: map[string]interface{}{
				"sub": "test",
			},
		}),
	})(handler)

	fn := func(token *oauth2.Token) {
		testEchoJWTWithAuthentication(b, token, h, e)
	}

	oidctesting.BenchmarkConcurrent(b, op.GetToken, fn)
}

func BenchmarkEchoJWTHttp(b *testing.B) {
	op := server.NewTesting(b)
	defer op.Close(b)

	handler := testGetEchoHandler(b)

	e := echo.New()
	e.HideBanner = true
	e.HidePort = true
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		err := e.Shutdown(ctx)
		require.NoError(b, err)
	}()

	e.Use(middleware.JWTWithConfig(middleware.JWTConfig{
		ParseTokenFunc: New(&Options{
			Issuer: op.GetURL(b),
		}),
	}))

	e.GET("/", handler)

	port, err := freeport.GetFreePort()
	require.NoError(b, err)

	addr := net.JoinHostPort("127.0.0.1", fmt.Sprintf("%d", port))
	urlString := fmt.Sprintf("http://%s/", addr)

	go func() {
		err := e.Start(addr)
		require.ErrorIs(b, err, http.ErrServerClosed)
	}()

	fn := func(token *oauth2.Token) {
		oidctesting.TestHttpRequest(b, urlString, token)
	}

	oidctesting.BenchmarkConcurrent(b, op.GetToken, fn)
}

func testGetEchoHandler(tb testing.TB) func(c echo.Context) error {
	tb.Helper()

	return func(c echo.Context) error {
		token, ok := c.Get("user").(jwt.Token)
		if !ok {
			return echo.NewHTTPError(http.StatusUnauthorized, "invalid token")
		}

		claims, err := token.AsMap(c.Request().Context())
		if err != nil {
			return echo.NewHTTPError(http.StatusUnauthorized, "invalid token")
		}

		return c.JSON(http.StatusOK, claims)
	}
}

func testEchoJWTWithAuthentication(tb testing.TB, token *oauth2.Token, restrictedHandler echo.HandlerFunc, e *echo.Echo) {
	tb.Helper()

	req := httptest.NewRequest(http.MethodGet, "/", nil)

	token.Valid()
	token.SetAuthHeader(req)

	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err := restrictedHandler(c)
	require.NoError(tb, err)

	res := rec.Result()

	require.Equal(tb, http.StatusOK, res.StatusCode)
}

func testEchoJWTWithAuthenticationFailure(tb testing.TB, token *oauth2.Token, restrictedHandler echo.HandlerFunc, e *echo.Echo) {
	tb.Helper()

	req := httptest.NewRequest(http.MethodGet, "/", nil)

	token.Valid()
	token.SetAuthHeader(req)

	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err := restrictedHandler(c)
	require.Error(tb, err)
}

func testEchoJWTWithIDTokenFailure(tb testing.TB, token *oauth2.Token, restrictedHandler echo.HandlerFunc, e *echo.Echo) {
	tb.Helper()

	req := httptest.NewRequest(http.MethodGet, "/", nil)

	idToken, ok := token.Extra("id_token").(string)
	require.True(tb, ok)

	token.AccessToken = idToken

	token.SetAuthHeader(req)

	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err := restrictedHandler(c)
	require.Error(tb, err)
	require.Contains(tb, err.Error(), "type \"JWT+AT\" required")
}
