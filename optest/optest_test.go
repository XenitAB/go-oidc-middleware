package optest

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/stretchr/testify/require"
)

type testData struct {
	baseURL      string
	redirectUrl  string
	clientID     string
	codeVerifier string
	code         string
	metadata     Metadata
	publicKey    jwk.Set
	httpClient   *http.Client
}

var (
	testDefaultUser   = "test"
	testSecondaryUser = "foo"
	testUsers         = map[string]TestUser{
		testDefaultUser: {
			Audience:           "test-client",
			Subject:            "test",
			Name:               "Test Testersson",
			GivenName:          "Test",
			FamilyName:         "Testersson",
			Locale:             "en-US",
			Email:              "test@testersson.com",
			AccessTokenKeyType: "JWT+AT",
			IdTokenKeyType:     "JWT",
		},
		testSecondaryUser: {
			Audience:           "foo-client",
			Subject:            "foo",
			Name:               "Foo Bar",
			GivenName:          "Foo",
			FamilyName:         "Bar",
			Locale:             "en-US",
			Email:              "foo@bar.com",
			AccessTokenKeyType: "JWT+AT",
			IdTokenKeyType:     "JWT",
		},
	}
)

func TestE2E(t *testing.T) {
	op, err := New(WithTestUsers(testUsers), WithDefaultTestUser(testDefaultUser))
	require.NoError(t, err)
	defer op.Close()

	httpClient := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	td1 := &testData{
		baseURL:     op.GetURL(),
		redirectUrl: "http://foobar.baz/callback",
		clientID:    "test-client",
		httpClient:  httpClient,
	}

	td2 := &testData{
		baseURL:     op.GetURL(),
		redirectUrl: "http://foobar.baz/callback",
		clientID:    "test-client",
		httpClient:  httpClient,
	}

	td3 := &testData{
		baseURL:     op.GetURL(),
		redirectUrl: "http://foobar.baz/callback",
		clientID:    "test-client",
		httpClient:  httpClient,
	}

	td1.testMetadata(t)
	td1.testAuthorization(t, "")
	td1.testJwks(t)
	tr1 := td1.testToken(t, "")
	td1.testValidateOpaqueTokenResponse(t, tr1, testUsers[testDefaultUser])

	td2.testMetadata(t)
	td2.testAuthorization(t, "")
	td2.testJwks(t)
	tr2 := td2.testToken(t, testDefaultUser)
	td2.testValidateOpaqueTokenResponse(t, tr2, testUsers[testDefaultUser])

	td3.testMetadata(t)
	td3.testAuthorization(t, "")
	td3.testJwks(t)
	tr3 := td3.testToken(t, testSecondaryUser)
	td3.testValidateOpaqueTokenResponse(t, tr3, testUsers[testSecondaryUser])
}

func TestE2EOpaque(t *testing.T) {
	op, err := New(WithTestUsers(testUsers), WithDefaultTestUser(testDefaultUser), WithOpaqueAccessTokens())
	require.NoError(t, err)
	defer op.Close()

	httpClient := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	td1 := &testData{
		baseURL:     op.GetURL(),
		redirectUrl: "http://foobar.baz/callback",
		clientID:    "test-client",
		httpClient:  httpClient,
	}

	td2 := &testData{
		baseURL:     op.GetURL(),
		redirectUrl: "http://foobar.baz/callback",
		clientID:    "test-client",
		httpClient:  httpClient,
	}

	td3 := &testData{
		baseURL:     op.GetURL(),
		redirectUrl: "http://foobar.baz/callback",
		clientID:    "test-client",
		httpClient:  httpClient,
	}

	td1.testMetadata(t)
	td1.testAuthorization(t, "")
	td1.testJwks(t)
	tr1 := td1.testToken(t, "")
	td1.testValidateOpaqueTokenResponse(t, tr1, testUsers[testDefaultUser])

	td2.testMetadata(t)
	td2.testAuthorization(t, "")
	td2.testJwks(t)
	tr2 := td2.testToken(t, testDefaultUser)
	td2.testValidateOpaqueTokenResponse(t, tr2, testUsers[testDefaultUser])

	td3.testMetadata(t)
	td3.testAuthorization(t, "")
	td3.testJwks(t)
	tr3 := td3.testToken(t, testSecondaryUser)
	td3.testValidateOpaqueTokenResponse(t, tr3, testUsers[testSecondaryUser])
}

func TestE2EOtherUser(t *testing.T) {
	op, err := New(WithTestUsers(testUsers), WithDefaultTestUser(testDefaultUser))
	require.NoError(t, err)
	defer op.Close()

	httpClient := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	td := &testData{
		baseURL:     op.GetURL(),
		redirectUrl: "http://foobar.baz/callback",
		clientID:    "test-client",
		httpClient:  httpClient,
	}

	td.testMetadata(t)
	td.testAuthorization(t, testSecondaryUser)
	td.testJwks(t)
	tr := td.testToken(t, testSecondaryUser)
	td.testValidateTokenResponse(t, tr, testUsers[testSecondaryUser])
}

func (td *testData) testAuthorization(t *testing.T, loginHint string) {
	t.Helper()

	remoteUrl, err := url.Parse(td.metadata.AuthorizationEndpoint)
	require.NoError(t, err)

	codeVerifier, codeChallenge := testGenerateCodeChallengeS256(t)
	td.codeVerifier = codeVerifier

	state := testGenerateState(t)

	query := url.Values{}
	query.Add("client_id", td.clientID)
	query.Add("code_challenge", codeChallenge)
	query.Add("code_challenge_method", "S256")
	query.Add("redirect_uri", td.redirectUrl)
	query.Add("response_type", "code")
	query.Add("scope", "all")
	query.Add("state", state)

	if loginHint != "" {
		query.Add("login_hint", loginHint)
	}

	remoteUrl.RawQuery = query.Encode()

	req, err := http.NewRequest("GET", remoteUrl.String(), nil)
	require.NoError(t, err)

	res, err := td.httpClient.Do(req)
	require.NoError(t, err)

	require.Equal(t, http.StatusFound, res.StatusCode)
	resLocation := res.Header.Get("location")
	require.Contains(t, resLocation, td.redirectUrl)
	resUrl, err := url.Parse(resLocation)
	require.NoError(t, err)
	require.Equal(t, state, resUrl.Query().Get("state"))

	code := resUrl.Query().Get("code")
	require.NotEmpty(t, code)

	td.code = code
}

func (td *testData) testMetadata(t *testing.T) {
	t.Helper()

	metadataURL := fmt.Sprintf("%s/.well-known/openid-configuration", td.baseURL)
	req, err := http.NewRequest("GET", metadataURL, nil)
	require.NoError(t, err)

	res, err := td.httpClient.Do(req)
	require.NoError(t, err)

	bodyBytes, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	defer res.Body.Close()

	var metadata Metadata
	err = json.Unmarshal(bodyBytes, &metadata)
	require.NoError(t, err)

	td.metadata = metadata
}

func (td *testData) testToken(t *testing.T, user string) *TokenResponse {
	t.Helper()

	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("client_id", td.clientID)
	data.Set("code_verifier", td.codeVerifier)
	data.Set("code", td.code)
	data.Set("redirect_uri", td.redirectUrl)

	tokenEndpoint := td.metadata.TokenEndpoint
	if user != "" {
		tokenEndpoint = fmt.Sprintf("%s?test_user=%s", tokenEndpoint, user)
	}

	req, err := http.NewRequest("POST", tokenEndpoint, strings.NewReader(data.Encode()))
	require.NoError(t, err)

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	res, err := td.httpClient.Do(req)
	require.NoError(t, err)

	bodyBytes, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	defer res.Body.Close()

	var tokenResponse TokenResponse
	err = json.Unmarshal(bodyBytes, &tokenResponse)
	require.NoError(t, err)

	require.NotEmpty(t, tokenResponse.AccessToken)
	require.NotEmpty(t, tokenResponse.TokenType)
	require.NotEmpty(t, tokenResponse.ExpiresIn)
	require.NotEmpty(t, tokenResponse.IdToken)

	return &tokenResponse
}

func (td *testData) testJwks(t *testing.T) {
	t.Helper()

	req, err := http.NewRequest("GET", td.metadata.JwksUri, nil)
	require.NoError(t, err)

	res, err := td.httpClient.Do(req)
	require.NoError(t, err)

	require.Equal(t, http.StatusOK, res.StatusCode)

	bodyBytes, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	defer res.Body.Close()

	publicKey, err := jwk.Parse(bodyBytes)
	require.NoError(t, err)
	require.GreaterOrEqual(t, 1, publicKey.Len())

	td.publicKey = publicKey
}

func (td *testData) testValidateTokenResponse(t *testing.T, tr *TokenResponse, user TestUser) {
	t.Helper()

	accessToken, err := jwt.Parse([]byte(tr.AccessToken), jwt.WithKeySet(td.publicKey))
	require.NoError(t, err)

	require.Equal(t, td.baseURL, accessToken.Issuer())
	require.Equal(t, user.Audience, accessToken.Audience()[0])
	require.Equal(t, user.Subject, accessToken.Subject())
	require.WithinDuration(t, time.Now(), accessToken.NotBefore(), 5*time.Second)
	require.WithinDuration(t, time.Now().Add(3600*time.Second), accessToken.Expiration(), 5*time.Second)

	idToken, err := jwt.Parse([]byte(tr.IdToken), jwt.WithKeySet(td.publicKey))
	require.NoError(t, err)

	require.Equal(t, td.baseURL, idToken.Issuer())
	require.Equal(t, user.Audience, idToken.Audience()[0])
	require.Equal(t, user.Subject, idToken.Subject())
	require.WithinDuration(t, time.Now(), idToken.NotBefore(), 5*time.Second)
	require.WithinDuration(t, time.Now().Add(3600*time.Second), idToken.Expiration(), 5*time.Second)
}

func (td *testData) testValidateOpaqueTokenResponse(t *testing.T, tr *TokenResponse, user TestUser) {
	t.Helper()

	req, err := http.NewRequest(http.MethodGet, td.metadata.UserinfoEndpoint, http.NoBody)
	require.NoError(t, err)

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", tr.AccessToken))

	res, err := td.httpClient.Do(req)
	require.NoError(t, err)

	bodyBytes, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	defer res.Body.Close()

	var userInfoResponse TestUser
	err = json.Unmarshal(bodyBytes, &userInfoResponse)
	require.NoError(t, err)

	require.Equal(t, user.Audience, userInfoResponse.Audience)
	require.Equal(t, user.Subject, userInfoResponse.Subject)

	idToken, err := jwt.Parse([]byte(tr.IdToken), jwt.WithKeySet(td.publicKey))
	require.NoError(t, err)

	require.Equal(t, td.baseURL, idToken.Issuer())
	require.Equal(t, user.Audience, idToken.Audience()[0])
	require.Equal(t, user.Subject, idToken.Subject())
	require.WithinDuration(t, time.Now(), idToken.NotBefore(), 5*time.Second)
	require.WithinDuration(t, time.Now().Add(3600*time.Second), idToken.Expiration(), 5*time.Second)
}

func testGenerateCodeChallengeS256(t *testing.T) (string, string) {
	t.Helper()

	codeVerifier, err := generateRandomString(43)
	require.NoError(t, err)

	hasher := sha256.New()
	hasher.Write([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(hasher.Sum(nil))

	return codeVerifier, codeChallenge
}

func testGenerateState(t *testing.T) string {
	t.Helper()

	stateString, err := generateRandomString(32)
	require.NoError(t, err)

	hasher := sha256.New()
	hasher.Write([]byte(stateString))
	state := base64.RawURLEncoding.EncodeToString(hasher.Sum(nil))

	return state
}

func TestNew(t *testing.T) {
	testUsers := map[string]TestUser{
		"foo": {
			Audience:           "foo-client",
			Subject:            "foo",
			Name:               "Foo Bar",
			GivenName:          "Foo",
			FamilyName:         "Bar",
			Locale:             "en-US",
			Email:              "foo@bar.com",
			AccessTokenKeyType: "JWT+AT",
			IdTokenKeyType:     "JWT",
		},
	}

	_, err := New()
	require.NoError(t, err)

	_, err = New(WithTestUsers(nil))
	require.ErrorContains(t, err, "at least one test user is required")

	emptyTestUsers := make(map[string]TestUser)
	_, err = New(WithTestUsers(emptyTestUsers))
	require.ErrorContains(t, err, "at least one test user is required")

	_, err = New(WithTestUsers(testUsers))
	require.ErrorContains(t, err, "the DefaultTestUser \"test\" could not be found in TestUsers")

	_, err = New(WithTestUsers(testUsers), WithDefaultTestUser("foo"))
	require.NoError(t, err)
}
