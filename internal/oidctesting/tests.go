package oidctesting

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/xenitab/go-oidc-middleware/internal/oidc"
	"github.com/xenitab/go-oidc-middleware/optest"
	"github.com/xenitab/go-oidc-middleware/options"
)

type TestClaims map[string]interface{}

func testClaimsValueEq(claims *TestClaims, key string, expectedValue string) error {
	rawValue, ok := (*claims)[key]
	if !ok {
		return fmt.Errorf("key %s not found", key)
	}

	value, ok := rawValue.(string)
	if !ok {
		return fmt.Errorf("key %s not expected type %T, received: %v", key, expectedValue, rawValue)
	}

	if expectedValue != value {
		return fmt.Errorf("key %s %v != %v", key, expectedValue, value)
	}

	return nil
}

type ServerTester interface {
	Close()
	URL() string
}

type tester interface {
	NewHandlerFn(claimsValidationFn options.ClaimsValidationFn[TestClaims], opts ...options.Option) http.Handler
	ToHandlerFn(parseToken oidc.ParseTokenFunc[TestClaims], opts ...options.Option) http.Handler
	NewTestServer(opts ...options.Option) ServerTester
}

func RunTests(t *testing.T, testName string, tester tester) {
	t.Helper()

	runTestNew(t, testName, tester)
	runTestHandler(t, testName, tester)
	runTestLazyLoad(t, testName, tester)
	runTestRequirements(t, testName, tester)
	runTestErrorHandler(t, testName, tester)
}

func runTestNew(t *testing.T, testName string, tester tester) {
	t.Helper()

	t.Run(fmt.Sprintf("%s_new", testName), func(t *testing.T) {
		op := optest.NewTesting(t)
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

		for i := range cases {
			c := cases[i]
			t.Logf("Test iteration %d: %s", i, c.testDescription)
			if c.expectPanic {
				require.Panics(t, func() { tester.NewHandlerFn(nil, c.config...) })
			} else {
				require.NotPanics(t, func() { tester.NewHandlerFn(nil, c.config...) })
			}
		}
	})
}

func runTestHandler(t *testing.T, testName string, tester tester) {
	t.Helper()

	t.Run(fmt.Sprintf("%s_handler", testName), func(t *testing.T) {
		op := optest.NewTesting(t)
		defer op.Close(t)

		handler := tester.NewHandlerFn(
			nil,
			options.WithIssuer(op.GetURL(t)),
			options.WithRequiredAudience("test-client"),
			options.WithRequiredTokenType("JWT+AT"),
			options.WithTokenString(
				options.WithTokenStringHeaderName("Authorization"),
				options.WithTokenStringTokenPrefix("Bearer "),
			),
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

func runTestLazyLoad(t *testing.T, testName string, tester tester) {
	t.Helper()

	t.Run(fmt.Sprintf("%s_lazy_load", testName), func(t *testing.T) {
		op := optest.NewTesting(t)
		defer op.Close(t)

		oidcHandler, err := oidc.NewHandler[TestClaims](
			nil,
			options.WithIssuer("http://foo.bar/baz"),
			options.WithRequiredAudience("test-client"),
			options.WithRequiredTokenType("JWT+AT"),
			options.WithLazyLoadJwks(true),
		)
		require.NoError(t, err)

		handler := tester.ToHandlerFn(oidcHandler.ParseToken)

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

func runTestRequirements(t *testing.T, testName string, tester tester) {
	t.Helper()

	t.Run(fmt.Sprintf("%s_requirements", testName), func(t *testing.T) {
		op := optest.NewTesting(t)
		defer op.Close(t)

		cases := []struct {
			testDescription    string
			options            []options.Option
			claimsValidationFn options.ClaimsValidationFn[TestClaims]
			succeeds           bool
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
					// options.WithRequiredClaims(map[string]interface{}{
					// 	"sub": "test",
					// }),
				},
				claimsValidationFn: func(claims *TestClaims) error {
					return testClaimsValueEq(claims, "sub", "test")
				},
				succeeds: true,
			},
			{
				testDescription: "required sub doesn't match",
				options: []options.Option{
					options.WithIssuer(op.GetURL(t)),
				},
				claimsValidationFn: func(claims *TestClaims) error {
					return testClaimsValueEq(claims, "sub", "foo")
				},
				succeeds: false,
			},
		}

		for i := range cases {
			c := cases[i]
			t.Logf("Test iteration %d: %s", i, c.testDescription)

			handler := tester.NewHandlerFn(c.claimsValidationFn, c.options...)
			token := op.GetToken(t)

			if c.succeeds {
				testHttpWithAuthentication(t, token, handler)
			} else {
				testHttpWithAuthenticationFailure(t, token, handler)
			}
		}
	})
}

func runTestErrorHandler(t *testing.T, testName string, tester tester) {
	t.Helper()

	t.Run(fmt.Sprintf("%s_error_handler", testName), func(t *testing.T) {
		op := optest.NewTesting(t)
		defer op.Close(t)

		var info struct {
			sync.RWMutex
			description options.ErrorDescription
			err         error
		}

		setInfo := func(description options.ErrorDescription, err error) {
			info.Lock()
			info.description = description
			info.err = err
			info.Unlock()
		}

		getInfo := func() (description options.ErrorDescription, err error) {
			info.RLock()
			defer info.RUnlock()
			return info.description, info.err
		}

		errorHandler := func(description options.ErrorDescription, err error) {
			t.Logf("Description: %s\tError: %v", description, err)
			setInfo(description, err)
		}

		opts := []options.Option{
			options.WithIssuer(op.GetURL(t)),
			options.WithRequiredAudience("test-client"),
			options.WithRequiredTokenType("JWT+AT"),
			options.WithErrorHandler(errorHandler),
		}

		oidcHandler, err := oidc.NewHandler[TestClaims](nil, opts...)
		require.NoError(t, err)

		handler := tester.ToHandlerFn(oidcHandler.ParseToken, opts...)

		// Test without token
		reqNoAuth := httptest.NewRequest(http.MethodGet, "/", nil)
		recNoAuth := httptest.NewRecorder()
		handler.ServeHTTP(recNoAuth, reqNoAuth)

		require.Equal(t, http.StatusBadRequest, recNoAuth.Result().StatusCode)

		d, e := getInfo()

		if !strings.Contains(t.Name(), "OidcEchoJwt") {
			require.Equal(t, options.GetTokenErrorDescription, d)
			require.EqualError(t, e, "unable to extract token: Authorization header empty")
		}

		// Test with fake token
		token := op.GetToken(t)
		token.AccessToken = "foobar"
		testHttpWithAuthenticationFailure(t, token, handler)

		d, e = getInfo()

		require.Equal(t, options.ParseTokenErrorDescription, d)
		require.EqualError(t, e, "token type \"JWT+AT\" required")
	})
}

func testHttpWithAuthentication(tb testing.TB, token *optest.TokenResponse, handler http.Handler) {
	tb.Helper()

	req := httptest.NewRequest(http.MethodGet, "/", nil)

	token.Valid()
	token.SetAuthHeader(req)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	res := rec.Result()

	require.Equal(tb, http.StatusOK, res.StatusCode)
}

func testHttpWithIDTokenFailure(tb testing.TB, token *optest.TokenResponse, handler http.Handler) {
	tb.Helper()

	req := httptest.NewRequest(http.MethodGet, "/", nil)

	token.AccessToken = token.IdToken

	token.SetAuthHeader(req)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	res := rec.Result()

	require.Equal(tb, http.StatusUnauthorized, res.StatusCode)
}

func testHttpWithAuthenticationFailure(tb testing.TB, token *optest.TokenResponse, handler http.Handler) {
	tb.Helper()

	req := httptest.NewRequest(http.MethodGet, "/", nil)

	token.Valid()
	token.SetAuthHeader(req)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	res := rec.Result()

	require.Equal(tb, http.StatusUnauthorized, res.StatusCode)
}
