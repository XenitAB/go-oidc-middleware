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
	baseURL       string
	redirectUrl   string
	clientID      string
	codeVerifier  string
	code          string
	metadata      Metadata
	tokenResponse TokenResponse
	publicKey     jwk.Set
	httpClient    *http.Client
}

func TestE2E(t *testing.T) {
	op, err := New()
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
	td.testAuthorization(t)
	td.testToken(t)
	td.testJwks(t)
	td.testValidateTokenResponse(t)
}

func (td *testData) testAuthorization(t *testing.T) {
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

func (td *testData) testToken(t *testing.T) {
	t.Helper()

	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("client_id", td.clientID)
	data.Set("code_verifier", td.codeVerifier)
	data.Set("code", td.code)
	data.Set("redirect_uri", td.redirectUrl)

	req, err := http.NewRequest("POST", td.metadata.TokenEndpoint, strings.NewReader(data.Encode()))
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

	td.tokenResponse = tokenResponse
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

func (td *testData) testValidateTokenResponse(t *testing.T) {
	t.Helper()

	accessToken, err := jwt.Parse([]byte(td.tokenResponse.AccessToken), jwt.WithKeySet(td.publicKey))
	require.NoError(t, err)

	require.Equal(t, td.baseURL, accessToken.Issuer())
	require.Equal(t, td.clientID, accessToken.Audience()[0])
	require.Equal(t, "test", accessToken.Subject())
	require.WithinDuration(t, time.Now(), accessToken.NotBefore(), 1*time.Second)
	require.WithinDuration(t, time.Now().Add(3600*time.Second), accessToken.Expiration(), 1*time.Second)

	idToken, err := jwt.Parse([]byte(td.tokenResponse.IdToken), jwt.WithKeySet(td.publicKey))
	require.NoError(t, err)

	require.Equal(t, td.baseURL, idToken.Issuer())
	require.Equal(t, td.clientID, idToken.Audience()[0])
	require.Equal(t, "test", idToken.Subject())
	require.WithinDuration(t, time.Now(), idToken.NotBefore(), 1*time.Second)
	require.WithinDuration(t, time.Now().Add(3600*time.Second), idToken.Expiration(), 1*time.Second)
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
