package oidc

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/xenitab/go-oidc-middleware/options"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/stretchr/testify/require"
	"github.com/xenitab/dispans/server"
)

type testClaims map[string]interface{}

func TestGetHeadersFromTokenString(t *testing.T) {
	key, _ := testNewKey(t)

	// Test with KeyID and Type
	token1 := jwt.New()
	err := token1.Set("foo", "bar")
	require.NoError(t, err)

	headers1 := jws.NewHeaders()
	err = headers1.Set(jws.TypeKey, "JWT")
	require.NoError(t, err)

	signedTokenBytes1, err := jwt.Sign(token1, jwa.ES384, key, jwt.WithHeaders(headers1))
	require.NoError(t, err)

	signedToken1 := string(signedTokenBytes1)
	parsedHeaders1, err := getHeadersFromTokenString(signedToken1)
	require.NoError(t, err)

	require.Equal(t, key.KeyID(), parsedHeaders1.KeyID())
	require.Equal(t, headers1.Type(), parsedHeaders1.Type())

	// Test with empty headers
	payload1 := `{"foo":"bar"}`

	headers2 := jws.NewHeaders()

	signedTokenBytes2, err := jws.Sign([]byte(payload1), jwa.ES384, key, jws.WithHeaders(headers2))
	require.NoError(t, err)

	signedToken2 := string(signedTokenBytes2)
	parsedHeaders2, err := getHeadersFromTokenString(signedToken2)
	require.NoError(t, err)

	require.Empty(t, parsedHeaders2.Type())

	// Test with multiple signatures
	payload2 := `{"foo":"bar"}`

	signer1, err := jws.NewSigner(jwa.ES384)
	require.NoError(t, err)
	signer2, err := jws.NewSigner(jwa.ES384)
	require.NoError(t, err)

	signedTokenBytes3, err := jws.SignMulti([]byte(payload2), jws.WithSigner(signer1, key, nil, nil), jws.WithSigner(signer2, key, nil, nil))
	require.NoError(t, err)

	signedToken3 := string(signedTokenBytes3)

	_, err = getHeadersFromTokenString(signedToken3)
	require.ErrorContains(t, err, "more than one signature in token: 2")

	// Test with non-token string
	_, err = getHeadersFromTokenString("foo")
	require.ErrorContains(t, err, "unable to parse token signature: invalid compact serialization format: invalid number of segments")
}

func TestGetKeyIDFromTokenString(t *testing.T) {
	key, _ := testNewKey(t)

	// Test with KeyID
	token1 := jwt.New()
	err := token1.Set("foo", "bar")
	require.NoError(t, err)

	headers1 := jws.NewHeaders()

	signedTokenBytes1, err := jwt.Sign(token1, jwa.ES384, key, jwt.WithHeaders(headers1))
	require.NoError(t, err)

	signedToken1 := string(signedTokenBytes1)

	parsedHeaders1, err := getHeadersFromTokenString(signedToken1)
	require.NoError(t, err)

	keyID, err := getKeyIDFromTokenHeader(parsedHeaders1)
	require.NoError(t, err)

	require.Equal(t, key.KeyID(), keyID)

	// Test without KeyID
	keyWithoutKeyID := key
	err = keyWithoutKeyID.Remove(jwk.KeyIDKey)
	require.NoError(t, err)

	token2 := jwt.New()
	err = token2.Set("foo", "bar")
	require.NoError(t, err)

	headers2 := jws.NewHeaders()

	signedTokenBytes2, err := jwt.Sign(token2, jwa.ES384, keyWithoutKeyID, jwt.WithHeaders(headers2))
	require.NoError(t, err)

	signedToken2 := string(signedTokenBytes2)

	parsedHeaders2, err := getHeadersFromTokenString(signedToken2)
	require.NoError(t, err)

	_, err = getKeyIDFromTokenHeader(parsedHeaders2)
	require.ErrorContains(t, err, "token header does not contain key id (kid)")

	// Test with non-token string
	_, err = getHeadersFromTokenString("foo")
	require.ErrorContains(t, err, "unable to parse token signature: invalid compact serialization format: invalid number of segments")
}

func TestGetTokenTypeFromTokenString(t *testing.T) {
	key, _ := testNewKey(t)

	// Test with Type
	token1 := jwt.New()
	err := token1.Set("foo", "bar")
	require.NoError(t, err)

	headers1 := jws.NewHeaders()
	err = headers1.Set(jws.TypeKey, "foo")
	require.NoError(t, err)

	signedTokenBytes1, err := jwt.Sign(token1, jwa.ES384, key, jwt.WithHeaders(headers1))
	require.NoError(t, err)

	signedToken1 := string(signedTokenBytes1)

	parsedHeaders1, err := getHeadersFromTokenString(signedToken1)
	require.NoError(t, err)

	tokenType, err := getTokenTypeFromTokenHeader(parsedHeaders1)
	require.NoError(t, err)

	require.Equal(t, headers1.Type(), tokenType)

	// Test without KeyID
	payload1 := `{"foo":"bar"}`

	signer1, err := jws.NewSigner(jwa.ES384)
	require.NoError(t, err)

	signedTokenBytes2, err := jws.SignMulti([]byte(payload1), jws.WithSigner(signer1, key, nil, nil))
	require.NoError(t, err)

	signedToken2 := string(signedTokenBytes2)

	parsedHeaders2, err := getHeadersFromTokenString(signedToken2)
	require.NoError(t, err)

	_, err = getTokenTypeFromTokenHeader(parsedHeaders2)
	require.Error(t, err)
	require.Equal(t, "token header does not contain type (typ)", err.Error())

	// Test with non-token string
	_, err = getHeadersFromTokenString("foo")
	require.ErrorContains(t, err, "unable to parse token signature: invalid compact serialization format: invalid number of segments")
}

func TestIsTokenAudienceValid(t *testing.T) {
	cases := []struct {
		testDescription  string
		requiredAudience string
		tokenAudiences   []string
		expectedResult   bool
	}{
		{
			testDescription:  "empty requiredAudience, empty tokenAudiences",
			requiredAudience: "",
			tokenAudiences:   []string{},
			expectedResult:   true,
		},
		{
			testDescription:  "empty requiredAudience, one tokenAudiences",
			requiredAudience: "",
			tokenAudiences:   []string{"foo"},
			expectedResult:   true,
		},
		{
			testDescription:  "empty requiredAudience, two tokenAudiences",
			requiredAudience: "",
			tokenAudiences:   []string{"foo", "bar"},
			expectedResult:   true,
		},
		{
			testDescription:  "empty requiredAudience, three tokenAudiences",
			requiredAudience: "",
			tokenAudiences:   []string{"foo", "bar", "baz"},
			expectedResult:   true,
		},
		{
			testDescription:  "one tokenAudiences, same as requiredAudience",
			requiredAudience: "foo",
			tokenAudiences:   []string{"foo"},
			expectedResult:   true,
		},
		{
			testDescription:  "two tokenAudiences, first same as requiredAudience",
			requiredAudience: "foo",
			tokenAudiences:   []string{"foo", "bar"},
			expectedResult:   true,
		},
		{
			testDescription:  "two tokenAudiences, second same as requiredAudience",
			requiredAudience: "bar",
			tokenAudiences:   []string{"foo", "bar"},
			expectedResult:   true,
		},
		{
			testDescription:  "three tokenAudiences, third same as requiredAudience",
			requiredAudience: "baz",
			tokenAudiences:   []string{"foo", "bar", "baz"},
			expectedResult:   true,
		},
		{
			testDescription:  "set requiredAudience, empty tokenAudiences",
			requiredAudience: "foo",
			tokenAudiences:   []string{},
			expectedResult:   false,
		},
		{
			testDescription:  "one tokenAudience, not same as requiredAudience",
			requiredAudience: "foo",
			tokenAudiences:   []string{"bar"},
			expectedResult:   false,
		},
		{
			testDescription:  "two tokenAudience, none same as requiredAudience",
			requiredAudience: "foo",
			tokenAudiences:   []string{"bar", "baz"},
			expectedResult:   false,
		},
		{
			testDescription:  "three tokenAudience, none same as requiredAudience",
			requiredAudience: "foo",
			tokenAudiences:   []string{"bar", "baz", "foobar"},
			expectedResult:   false,
		},
	}

	for i, c := range cases {
		t.Logf("Test iteration %d: %s", i, c.testDescription)
		result := isTokenAudienceValid(c.requiredAudience, c.tokenAudiences)
		require.Equal(t, c.expectedResult, result)
	}
}

func TestTokenExpirationValid(t *testing.T) {
	cases := []struct {
		testDescription string
		expiration      time.Time
		allowedDrift    time.Duration
		expectedResult  bool
	}{
		{
			testDescription: "expires now, 50 millisecond drift allowed",
			expiration:      time.Now(),
			allowedDrift:    50 * time.Millisecond,
			expectedResult:  true,
		},
		{
			testDescription: "expires now, 10 second drift allowed",
			expiration:      time.Now(),
			allowedDrift:    10 * time.Second,
			expectedResult:  true,
		},
		{
			testDescription: "expires in one hour, 10 second drift allowed",
			expiration:      time.Now().Add(1 * time.Hour),
			allowedDrift:    10 * time.Second,
			expectedResult:  true,
		},
		{
			testDescription: "expired 5 seconds ago, 10 second drift allowed",
			expiration:      time.Now().Add(-5 * time.Second),
			allowedDrift:    10 * time.Second,
			expectedResult:  true,
		},
		{
			testDescription: "expired 11 seconds ago, 10 second drift allowed",
			expiration:      time.Now().Add(-11 * time.Second),
			allowedDrift:    10 * time.Second,
			expectedResult:  false,
		},
		{
			testDescription: "expires now, no drift",
			expiration:      time.Now(),
			allowedDrift:    0,
			expectedResult:  false,
		},
		{
			testDescription: "expired an hour ago, no drift",
			expiration:      time.Now().Add(-1 * time.Hour),
			allowedDrift:    0,
			expectedResult:  false,
		},
		{
			testDescription: "expired an hour ago, 10 second drift",
			expiration:      time.Now().Add(-1 * time.Hour),
			allowedDrift:    10 * time.Second,
			expectedResult:  false,
		},
	}

	for i, c := range cases {
		t.Logf("Test iteration %d: %s", i, c.testDescription)
		result := isTokenExpirationValid(c.expiration, c.allowedDrift)
		require.Equal(t, c.expectedResult, result)
	}
}

func TestIsTokenIssuerValid(t *testing.T) {
	cases := []struct {
		testDescription string
		requiredIssuer  string
		tokenIssuer     string
		expectedResult  bool
	}{
		{
			testDescription: "both requiredIssuer and tokenIssuer are the same",
			requiredIssuer:  "foo",
			tokenIssuer:     "foo",
			expectedResult:  true,
		},
		{
			testDescription: "requiredIssuer and tokenIssuer are not the same",
			requiredIssuer:  "foo",
			tokenIssuer:     "bar",
			expectedResult:  false,
		},
		{
			testDescription: "both requiredIssuer and tokenIssuer are empty",
			requiredIssuer:  "",
			tokenIssuer:     "",
			expectedResult:  false,
		},
		{
			testDescription: "requiredIssuer is empty and tokenIssuer is set",
			requiredIssuer:  "",
			tokenIssuer:     "foo",
			expectedResult:  false,
		},
		{
			testDescription: "requiredIssuer is set and tokenIssuer is empty",
			requiredIssuer:  "foo",
			tokenIssuer:     "",
			expectedResult:  false,
		},
	}

	for i, c := range cases {
		t.Logf("Test iteration %d: %s", i, c.testDescription)
		result := isTokenIssuerValid(c.requiredIssuer, c.tokenIssuer)
		require.Equal(t, c.expectedResult, result)
	}
}

func TestIsTokenTypeValid(t *testing.T) {
	cases := []struct {
		testDescription   string
		requiredTokenType string
		tokenType         string
		expectedResult    bool
	}{
		{
			testDescription:   "both requiredTokenType and tokenType are empty",
			requiredTokenType: "",
			tokenType:         "",
			expectedResult:    true,
		},
		{
			testDescription:   "requiredTokenType is empty and tokenType is set",
			requiredTokenType: "",
			tokenType:         "foo",
			expectedResult:    true,
		},
		{
			testDescription:   "both requiredTokenType and tokenType are set to the same",
			requiredTokenType: "foo",
			tokenType:         "foo",
			expectedResult:    true,
		},
		{
			testDescription:   "requiredTokenType and tokenType are set to different",
			requiredTokenType: "foo",
			tokenType:         "bar",
			expectedResult:    false,
		},
		{
			testDescription:   "requiredTokenType and tokenType are set to different but tokenType contains requiredTokenType",
			requiredTokenType: "foo",
			tokenType:         "foobar",
			expectedResult:    false,
		},
	}

	for i, c := range cases {
		t.Logf("Test iteration %d: %s", i, c.testDescription)

		key, _ := testNewKey(t)
		payload := `{"foo":"bar"}`

		signer, err := jws.NewSigner(jwa.ES384)
		require.NoError(t, err)

		var signedTokenBytes []byte
		if c.tokenType == "" {
			signedTokenBytes, err = jws.SignMulti([]byte(payload), jws.WithSigner(signer, key, nil, nil))
			require.NoError(t, err)
		} else {
			headers := jws.NewHeaders()
			err = headers.Set(jws.TypeKey, c.tokenType)
			require.NoError(t, err)

			signedTokenBytes, err = jws.SignMulti([]byte(payload), jws.WithSigner(signer, key, nil, headers))
			require.NoError(t, err)
		}

		token := string(signedTokenBytes)

		parsedHeader, err := getHeadersFromTokenString(token)
		require.NoError(t, err)

		result := isTokenTypeValid(c.requiredTokenType, parsedHeader)
		require.Equal(t, c.expectedResult, result)
	}
}

func TestGetAndValidateTokenFromString(t *testing.T) {
	op := server.NewTesting(t)
	defer op.Close(t)

	issuer := op.GetURL(t)
	discoveryUri := GetDiscoveryUriFromIssuer(issuer)
	jwksUri, err := getJwksUriFromDiscoveryUri(http.DefaultClient, discoveryUri, 10*time.Millisecond)
	require.NoError(t, err)

	keyHandler, err := newKeyHandler(http.DefaultClient, jwksUri, 50*time.Millisecond, 100, false)
	require.NoError(t, err)

	validKey, ok := keyHandler.getKeySet().Get(0)
	require.True(t, ok)

	validAccessToken := op.GetToken(t).AccessToken
	require.NotEmpty(t, validAccessToken)

	validIDToken, ok := op.GetToken(t).Extra("id_token").(string)
	require.True(t, ok)
	require.NotEmpty(t, validIDToken)

	invalidKey, invalidPubKey := testNewKey(t)

	invalidToken := jwt.New()
	err = invalidToken.Set("foo", "bar")
	require.NoError(t, err)

	invalidHeaders := jws.NewHeaders()
	err = invalidHeaders.Set(jws.TypeKey, "JWT")
	require.NoError(t, err)

	invalidTokenBytes, err := jwt.Sign(invalidToken, jwa.ES384, invalidKey, jwt.WithHeaders(invalidHeaders))
	require.NoError(t, err)

	invalidSignedToken := string(invalidTokenBytes)

	cases := []struct {
		testDescription string
		tokenString     string
		key             jwk.Key
		expectedError   bool
	}{
		{
			testDescription: "valid access token, valid key",
			tokenString:     validAccessToken,
			key:             validKey,
			expectedError:   false,
		},
		{
			testDescription: "valid id token, valid key",
			tokenString:     validIDToken,
			key:             validKey,
			expectedError:   false,
		},
		{
			testDescription: "empty string, valid key",
			tokenString:     "",
			key:             validKey,
			expectedError:   true,
		},
		{
			testDescription: "random string, valid key",
			tokenString:     "foobar",
			key:             validKey,
			expectedError:   true,
		},
		{
			testDescription: "invalid token, valid key",
			tokenString:     invalidSignedToken,
			key:             validKey,
			expectedError:   true,
		},
		{
			testDescription: "invalid token, invalid key",
			tokenString:     invalidSignedToken,
			key:             invalidPubKey,
			expectedError:   false,
		},
	}

	for i, c := range cases {
		t.Logf("Test iteration %d: %s", i, c.testDescription)

		alg, err := getSignatureAlgorithm(c.key.KeyType(), c.key.Algorithm(), jwa.ES384)
		require.NoError(t, err)

		token, err := getAndValidateTokenFromString(c.tokenString, c.key, alg)
		if c.expectedError {
			require.Error(t, err)
		} else {
			require.NoError(t, err)
			require.NotEmpty(t, token)
		}
	}
}

func TestParseToken(t *testing.T) {
	keySets := testNewTestKeySet(t)
	testServer := testNewJwksServer(t, keySets)
	defer testServer.Close()

	cases := []struct {
		testDescription         string
		options                 []options.Option
		numKeys                 int
		customIssuer            string
		customExpirationMinutes int
		customClaims            map[string]string
		expectedErrorContains   string
	}{
		{
			testDescription: "successful parse with keyID, one key",
			options: []options.Option{
				options.WithIssuer("http://foo.bar"),
				options.WithDiscoveryUri("http://foo.bar"),
				options.WithJwksUri(testServer.URL),
				options.WithDisableKeyID(false),
				options.WithJwksRateLimit(100),
			},
			numKeys:               1,
			expectedErrorContains: "",
		},
		{
			testDescription: "successful parse without keyID, one key",
			options: []options.Option{
				options.WithIssuer("http://foo.bar"),
				options.WithDiscoveryUri("http://foo.bar"),
				options.WithJwksUri(testServer.URL),
				options.WithDisableKeyID(true),
				options.WithJwksRateLimit(100),
			},
			numKeys:               1,
			expectedErrorContains: "",
		},
		{
			testDescription: "successful parse with keyID, two keys",
			options: []options.Option{
				options.WithIssuer("http://foo.bar"),
				options.WithDiscoveryUri("http://foo.bar"),
				options.WithJwksUri(testServer.URL),
				options.WithDisableKeyID(false),
				options.WithJwksRateLimit(100),
			},
			numKeys:               2,
			expectedErrorContains: "",
		},
		{
			// without lazyLoad, New() panics
			testDescription: "unsuccessful parse without keyID, two keys with lazyLoad",
			options: []options.Option{
				options.WithIssuer("http://foo.bar"),
				options.WithDiscoveryUri("http://foo.bar"),
				options.WithJwksUri(testServer.URL),
				options.WithDisableKeyID(true),
				options.WithJwksRateLimit(100),
				options.WithLazyLoadJwks(true),
			},
			numKeys:               2,
			expectedErrorContains: "keyID is disabled, but received a keySet with more than one key",
		},
		{
			testDescription: "wrong issuer, with keyID",
			options: []options.Option{
				options.WithIssuer("http://foo.bar"),
				options.WithDiscoveryUri("http://foo.bar"),
				options.WithJwksUri(testServer.URL),
				options.WithDisableKeyID(false),
			},
			numKeys:               1,
			customIssuer:          "http://wrong.issuer",
			expectedErrorContains: "required issuer \"http://foo.bar\" was not found",
		},
		{
			testDescription: "wrong issuer, without keyID",
			options: []options.Option{
				options.WithIssuer("http://foo.bar"),
				options.WithDiscoveryUri("http://foo.bar"),
				options.WithJwksUri(testServer.URL),
				options.WithDisableKeyID(true),
			},
			numKeys:               1,
			customIssuer:          "http://wrong.issuer",
			expectedErrorContains: "required issuer \"http://foo.bar\" was not found",
		},
		{
			testDescription: "expired token, with keyID",
			options: []options.Option{
				options.WithIssuer("http://foo.bar"),
				options.WithDiscoveryUri("http://foo.bar"),
				options.WithJwksUri(testServer.URL),
				options.WithDisableKeyID(false),
			},
			numKeys:                 1,
			customExpirationMinutes: -1,
			expectedErrorContains:   "token has expired",
		},
		{
			testDescription: "expired token, without keyID",
			options: []options.Option{
				options.WithIssuer("http://foo.bar"),
				options.WithDiscoveryUri("http://foo.bar"),
				options.WithJwksUri(testServer.URL),
				options.WithDisableKeyID(true),
			},
			numKeys:                 1,
			customExpirationMinutes: -1,
			expectedErrorContains:   "token has expired",
		},
	}

	for i, c := range cases {
		t.Logf("Test iteration %d: %s", i, c.testDescription)

		opts := &options.Options{}

		for _, setter := range c.options {
			setter(opts)
		}

		keySets.setKeys(testNewKeySet(t, c.numKeys, opts.DisableKeyID))

		h, err := NewHandler[testClaims](nil, c.options...)
		require.NoError(t, err)

		parseTokenFunc := h.ParseToken

		issuer := opts.Issuer
		if c.customIssuer != "" {
			issuer = c.customIssuer
		}

		expirationMinutes := 1
		if c.customExpirationMinutes != 0 {
			expirationMinutes = c.customExpirationMinutes
		}

		customClaims := make(map[string]string)
		customClaims["foo"] = "bar"
		if c.customClaims != nil {
			customClaims = c.customClaims
		}

		token := testNewCustomTokenString(t, keySets.privateKeySet, issuer, expirationMinutes, customClaims)

		ctx := context.Background()

		_, err = parseTokenFunc(ctx, token)

		if c.expectedErrorContains == "" {
			require.NoError(t, err)
		} else {
			require.Contains(t, err.Error(), c.expectedErrorContains)
		}
	}
}

func TestParseTokenWithKeyID(t *testing.T) {
	disableKeyID := false
	keySets := testNewTestKeySet(t)
	testServer := testNewJwksServer(t, keySets)
	defer testServer.Close()

	keySets.setKeys(testNewKeySet(t, 1, disableKeyID))

	opts := []options.Option{
		options.WithIssuer("http://foo.bar"),
		options.WithDiscoveryUri("http://foo.bar"),
		options.WithJwksUri(testServer.URL),
		options.WithDisableKeyID(disableKeyID),
		options.WithJwksRateLimit(100),
	}

	h, err := NewHandler[testClaims](nil, opts...)
	require.NoError(t, err)

	parseTokenFunc := h.ParseToken

	// first token should succeed
	token1 := testNewTokenString(t, keySets.privateKeySet)

	ctx := context.Background()

	_, err = parseTokenFunc(ctx, token1)
	require.NoError(t, err)

	// second token should succeed, rotation successful
	keySets.setKeys(testNewKeySet(t, 1, disableKeyID))

	token2 := testNewTokenString(t, keySets.privateKeySet)

	_, err = parseTokenFunc(ctx, token2)
	require.NoError(t, err)

	// after rotation, first token should fail
	_, err = parseTokenFunc(ctx, token1)
	require.Error(t, err)

	// third token should succeed with two keys
	keySets.setKeys(testNewKeySet(t, 2, disableKeyID))

	token3 := testNewTokenString(t, keySets.privateKeySet)

	_, err = parseTokenFunc(ctx, token3)
	require.NoError(t, err)

	// fourth token should fail since they token doesn't contain keyID
	keySets.setKeys(testNewKeySet(t, 1, true))

	token4 := testNewTokenString(t, keySets.privateKeySet)

	_, err = parseTokenFunc(ctx, token4)
	require.Error(t, err)

	// fifth token should fail since it's the wrong key but correct keyID
	keySets.setKeys(testNewKeySet(t, 1, disableKeyID))
	currentPrivateKey, found := keySets.privateKeySet.Get(0)
	require.True(t, found)

	currentKeyID := currentPrivateKey.KeyID()
	invalidPrivKey, _ := testNewKey(t)

	err = invalidPrivKey.Set(jwk.KeyIDKey, currentKeyID)
	require.NoError(t, err)

	invalidKeySet := jwk.NewSet()
	invalidKeySet.Add(invalidPrivKey)

	token5 := testNewTokenString(t, invalidKeySet)

	_, err = parseTokenFunc(ctx, token5)
	require.ErrorIs(t, err, errSignatureVerification)

	// sixth token should fail since the jwks can't be refreshed
	keySets.setKeys(testNewKeySet(t, 1, disableKeyID))

	token6 := testNewTokenString(t, keySets.privateKeySet)

	testServer.Close()

	_, err = parseTokenFunc(ctx, token6)
	require.Error(t, err)
}

func TestParseTokenWithoutKeyID(t *testing.T) {
	disableKeyID := true
	keySets := testNewTestKeySet(t)
	testServer := testNewJwksServer(t, keySets)
	defer testServer.Close()

	keySets.setKeys(testNewKeySet(t, 1, disableKeyID))

	opts := []options.Option{
		options.WithIssuer("http://foo.bar"),
		options.WithDiscoveryUri("http://foo.bar"),
		options.WithJwksUri(testServer.URL),
		options.WithDisableKeyID(disableKeyID),
		options.WithJwksRateLimit(100),
	}

	h, err := NewHandler[testClaims](nil, opts...)
	require.NoError(t, err)

	parseTokenFunc := h.ParseToken

	// first token should succeed
	token1 := testNewTokenString(t, keySets.privateKeySet)

	ctx := context.Background()

	_, err = parseTokenFunc(ctx, token1)
	require.NoError(t, err)

	// second token should succeed, with key rotation
	keySets.setKeys(testNewKeySet(t, 1, disableKeyID))

	token2 := testNewTokenString(t, keySets.privateKeySet)

	_, err = parseTokenFunc(ctx, token2)
	require.NoError(t, err)

	// after rotation, first token should fail
	_, err = parseTokenFunc(ctx, token1)
	require.Error(t, err)

	// third token should fail since there are two keys present
	keySets.setKeys(testNewKeySet(t, 2, disableKeyID))

	token3 := testNewTokenString(t, keySets.privateKeySet)

	_, err = parseTokenFunc(ctx, token3)
	require.Error(t, err)

	// fourth token should fail since the jwks can't be refreshed
	keySets.setKeys(testNewKeySet(t, 1, disableKeyID))

	token4 := testNewTokenString(t, keySets.privateKeySet)

	testServer.Close()

	_, err = parseTokenFunc(ctx, token4)
	require.Error(t, err)
}

func TestGetAndValidateTokenFromStringWithKeyID(t *testing.T) {
	disableKeyID := false
	keySets := testNewTestKeySet(t)
	testServer := testNewJwksServer(t, keySets)
	defer testServer.Close()

	keySets.setKeys(testNewKeySet(t, 1, disableKeyID))

	keyHandler, err := newKeyHandler(http.DefaultClient, testServer.URL, 10*time.Millisecond, 100, disableKeyID)
	require.NoError(t, err)

	token1 := testNewTokenString(t, keySets.privateKeySet)

	parsedHeaders1, err := getHeadersFromTokenString(token1)
	require.NoError(t, err)

	keyID, err := getKeyIDFromTokenHeader(parsedHeaders1)
	require.NoError(t, err)

	tokenAlgorithm, err := getTokenAlgorithmFromTokenHeader(parsedHeaders1)
	require.NoError(t, err)

	pubKey, err := keyHandler.getKey(context.Background(), keyID, tokenAlgorithm)
	require.NoError(t, err)

	alg, err := getSignatureAlgorithm(pubKey.KeyType(), pubKey.Algorithm(), jwa.ES384)
	require.NoError(t, err)

	_, err = getAndValidateTokenFromString(token1, pubKey, alg)
	require.NoError(t, err)

	keySets.setKeys(testNewKeySet(t, 1, disableKeyID))

	token2 := testNewTokenString(t, keySets.privateKeySet)

	_, err = getAndValidateTokenFromString(token2, pubKey, alg)
	require.Error(t, err)
}

func TestGetAndValidateTokenFromStringWithoutKeyID(t *testing.T) {
	disableKeyID := true
	keySets := testNewTestKeySet(t)
	testServer := testNewJwksServer(t, keySets)

	keySets.setKeys(testNewKeySet(t, 1, disableKeyID))

	keyHandler, err := newKeyHandler(http.DefaultClient, testServer.URL, 10*time.Millisecond, 100, disableKeyID)
	require.NoError(t, err)

	token1 := testNewTokenString(t, keySets.privateKeySet)

	parsedHeaders1, err := getHeadersFromTokenString(token1)
	require.NoError(t, err)

	tokenAlgorithm, err := getTokenAlgorithmFromTokenHeader(parsedHeaders1)
	require.NoError(t, err)

	pubKey, err := keyHandler.getKey(context.Background(), "", tokenAlgorithm)
	require.NoError(t, err)

	alg, err := getSignatureAlgorithm(pubKey.KeyType(), pubKey.Algorithm(), jwa.ES384)
	require.NoError(t, err)

	_, err = getAndValidateTokenFromString(token1, pubKey, alg)
	require.NoError(t, err)

	keySets.setKeys(testNewKeySet(t, 1, disableKeyID))

	token2 := testNewTokenString(t, keySets.privateKeySet)

	_, err = getAndValidateTokenFromString(token2, pubKey, alg)
	require.ErrorIs(t, err, errSignatureVerification)
}

func TestGetSignatureAlgorithm(t *testing.T) {
	cases := []struct {
		inputKty         jwa.KeyType
		inputAlg         string
		inputFallbackAlg jwa.SignatureAlgorithm
		expectedResult   jwa.SignatureAlgorithm
		expectedError    bool
	}{
		{
			inputKty:         jwa.RSA,
			inputAlg:         "RS256",
			inputFallbackAlg: "",
			expectedResult:   jwa.RS256,
			expectedError:    false,
		},
		{
			inputKty:         jwa.EC,
			inputAlg:         "ES256",
			inputFallbackAlg: "",
			expectedResult:   jwa.ES256,
			expectedError:    false,
		},
		{
			inputKty:         jwa.RSA,
			inputAlg:         "",
			inputFallbackAlg: "",
			expectedResult:   jwa.RS256,
			expectedError:    false,
		},
		{
			inputKty:         jwa.EC,
			inputAlg:         "",
			inputFallbackAlg: "",
			expectedResult:   jwa.ES256,
			expectedError:    false,
		},
		{
			inputKty:         "",
			inputAlg:         "",
			inputFallbackAlg: "",
			expectedResult:   "",
			expectedError:    true,
		},
		{
			inputKty:         "",
			inputAlg:         "foobar",
			inputFallbackAlg: "",
			expectedResult:   "",
			expectedError:    true,
		},
		{
			inputKty:         "",
			inputAlg:         "",
			inputFallbackAlg: jwa.ES384,
			expectedResult:   jwa.ES384,
			expectedError:    false,
		},
		{
			inputKty:         jwa.RSA,
			inputAlg:         "",
			inputFallbackAlg: jwa.ES384,
			expectedResult:   jwa.ES384,
			expectedError:    false,
		},
	}

	for i, c := range cases {
		t.Logf("Test iteration %d: inputKty=%s, inputAlg=%s, inputFallbackAlg=%s", i, c.inputKty, c.inputAlg, c.inputFallbackAlg)

		result, err := getSignatureAlgorithm(c.inputKty, c.inputAlg, c.inputFallbackAlg)
		require.Equal(t, c.expectedResult, result)

		if !c.expectedError {
			require.NoError(t, err)
		} else {
			require.Error(t, err)
		}
	}
}

func testNewKey(tb testing.TB) (jwk.Key, jwk.Key) {
	tb.Helper()

	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(tb, err)

	key, err := jwk.New(ecdsaKey)
	require.NoError(tb, err)

	_, ok := key.(jwk.ECDSAPrivateKey)
	require.True(tb, ok)

	thumbprint, err := key.Thumbprint(crypto.SHA256)
	require.NoError(tb, err)

	keyID := fmt.Sprintf("%x", thumbprint)
	err = key.Set(jwk.KeyIDKey, keyID)
	require.NoError(tb, err)

	pubKey, err := jwk.New(ecdsaKey.PublicKey)
	require.NoError(tb, err)

	_, ok = pubKey.(jwk.ECDSAPublicKey)
	require.True(tb, ok)

	err = pubKey.Set(jwk.KeyIDKey, keyID)
	require.NoError(tb, err)

	err = pubKey.Set(jwk.AlgorithmKey, jwa.ES384)
	require.NoError(tb, err)

	return key, pubKey
}

func testDuplicateKey(tb testing.TB) (jwk.Key, jwk.Key, jwk.Key) {
	tb.Helper()

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(tb, err)

	key, err := jwk.New(rsaKey)
	require.NoError(tb, err)

	thumbprint, err := key.Thumbprint(crypto.SHA256)
	require.NoError(tb, err)

	keyID := fmt.Sprintf("%x", thumbprint)
	err = key.Set(jwk.KeyIDKey, keyID)
	require.NoError(tb, err)

	pubKey256, err := jwk.New(rsaKey.PublicKey)
	require.NoError(tb, err)

	err = pubKey256.Set(jwk.KeyIDKey, keyID)
	require.NoError(tb, err)

	err = pubKey256.Set(jwk.AlgorithmKey, jwa.RS256)
	require.NoError(tb, err)

	pubKey512, err := jwk.New(rsaKey.PublicKey)
	require.NoError(tb, err)

	err = pubKey512.Set(jwk.KeyIDKey, keyID)
	require.NoError(tb, err)

	err = pubKey512.Set(jwk.AlgorithmKey, jwa.RS512)
	require.NoError(tb, err)

	return key, pubKey256, pubKey512
}

func testNewTokenString(t *testing.T, privKeySet jwk.Set) string {
	t.Helper()

	jwtToken := jwt.New()
	err := jwtToken.Set(jwt.IssuerKey, "http://foo.bar")
	require.NoError(t, err)

	err = jwtToken.Set(jwt.ExpirationKey, time.Now().Add(1*time.Minute).Unix())
	require.NoError(t, err)

	err = jwtToken.Set("foo", "bar")
	require.NoError(t, err)

	headers := jws.NewHeaders()
	err = headers.Set(jws.TypeKey, "JWT")
	require.NoError(t, err)

	privKey, found := privKeySet.Get(0)
	require.True(t, found)

	tokenBytes, err := jwt.Sign(jwtToken, jwa.ES384, privKey, jwt.WithHeaders(headers))
	require.NoError(t, err)

	return string(tokenBytes)
}

func testNewCustomTokenString(t *testing.T, privKeySet jwk.Set, issuer string, expirationMinutes int, customClaims map[string]string) string {
	t.Helper()

	jwtToken := jwt.New()
	err := jwtToken.Set(jwt.IssuerKey, issuer)
	require.NoError(t, err)

	err = jwtToken.Set(jwt.ExpirationKey, time.Now().Add(time.Duration(expirationMinutes)*time.Minute).Unix())
	require.NoError(t, err)

	for k, v := range customClaims {
		err := jwtToken.Set(k, v)
		require.NoError(t, err)
	}

	headers := jws.NewHeaders()

	err = headers.Set(jws.TypeKey, "JWT")
	require.NoError(t, err)

	privKey, found := privKeySet.Get(0)
	require.True(t, found)

	tokenBytes, err := jwt.Sign(jwtToken, jwa.ES384, privKey, jwt.WithHeaders(headers))
	require.NoError(t, err)

	return string(tokenBytes)
}
