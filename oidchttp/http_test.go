package oidchttp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/xenitab/dispans/server"
	"github.com/xenitab/go-oidc-middleware/internal/oidc"
	"github.com/xenitab/go-oidc-middleware/internal/oidctesting"
	"github.com/xenitab/go-oidc-middleware/options"
	"golang.org/x/oauth2"
)

func TestNewHttpMiddleware(t *testing.T) {
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

	h := testGetHttpHandler(t)

	for i, c := range cases {
		t.Logf("Test iteration %d: %s", i, c.testDescription)
		if c.expectPanic {
			require.Panics(t, func() { New(h, c.config...) })
		} else {
			require.NotPanics(t, func() { New(h, c.config...) })
		}
	}
}

func TestHttp(t *testing.T) {
	op := server.NewTesting(t)
	defer op.Close(t)

	h := testGetHttpHandler(t)

	handler := New(h,
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
}

func TestHttpLazyLoad(t *testing.T) {
	op := server.NewTesting(t)
	defer op.Close(t)

	oidcHandler, err := oidc.NewHandler(
		options.WithIssuer("http://foo.bar/baz"),
		options.WithRequiredAudience("test-client"),
		options.WithRequiredTokenType("JWT+AT"),
		options.WithLazyLoadJwks(true),
	)
	require.NoError(t, err)

	h := testGetHttpHandler(t)

	handler := toHttpHandler(h, oidcHandler.ParseToken)

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
}

func TestHttpRequirements(t *testing.T) {
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

		h := testGetHttpHandler(t)
		handler := New(h, c.options...)
		token := op.GetToken(t)

		if c.succeeds {
			testHttpWithAuthentication(t, token, handler)
		} else {
			testHttpWithAuthenticationFailure(t, token, handler)
		}
	}
}

func BenchmarkHttp(b *testing.B) {
	op := server.NewTesting(b)
	defer op.Close(b)

	h := testGetHttpHandler(b)
	handler := New(h,
		options.WithIssuer(op.GetURL(b)),
	)

	fn := func(token *oauth2.Token) {
		testHttpWithAuthentication(b, token, handler)
	}

	oidctesting.BenchmarkConcurrent(b, op.GetToken, fn)
}

func BenchmarkHttpRequirements(b *testing.B) {
	op := server.NewTesting(b)
	defer op.Close(b)

	h := testGetHttpHandler(b)
	handler := New(h,
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

	oidctesting.BenchmarkConcurrent(b, op.GetToken, fn)
}

func BenchmarkHttpHttp(b *testing.B) {
	op := server.NewTesting(b)
	defer op.Close(b)

	h := testGetHttpHandler(b)
	handler := New(h,
		options.WithIssuer(op.GetURL(b)),
	)

	testServer := httptest.NewServer(handler)
	defer testServer.Close()

	fn := func(token *oauth2.Token) {
		oidctesting.TestHttpRequest(b, testServer.URL, token)
	}

	oidctesting.BenchmarkConcurrent(b, op.GetToken, fn)
}

func testGetHttpHandler(tb testing.TB) http.Handler {
	tb.Helper()

	fn := func(w http.ResponseWriter, r *http.Request) {
		claims, ok := r.Context().Value(ClaimsContextKey).(map[string]interface{})
		if !ok {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		err := json.NewEncoder(w).Encode(claims)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	}

	return http.HandlerFunc(fn)
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
