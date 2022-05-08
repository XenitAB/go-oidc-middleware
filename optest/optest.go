package optest

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"time"
)

// OPTest is the struct used for the test OpenID Provider.
type OPTest struct {
	server  *httptest.Server
	router  *http.ServeMux
	options Options
	jwks    *jwksHandler
}

// New sets up a new test OpenID Provider.
func New(setters ...Option) (*OPTest, error) {
	jwks, err := newJwksHandler()
	if err != nil {
		return nil, err
	}

	op := &OPTest{
		jwks: jwks,
	}

	router := op.routeHandler()
	op.router = router

	srv := httptest.NewUnstartedServer(router)
	op.server = srv

	opts := &Options{
		Issuer:          srv.URL,
		DefaultTestUser: "test",
		TestUsers: map[string]TestUser{
			"test": {
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
		},
		TokenExpiration: time.Hour,
		AutoStart:       true,
	}

	for _, setter := range setters {
		setter(opts)
	}

	if len(opts.TestUsers) == 0 {
		return nil, fmt.Errorf("at least one test user is required")
	}

	_, ok := opts.TestUsers[opts.DefaultTestUser]
	if !ok {
		return nil, fmt.Errorf("the DefaultTestUser %q could not be find in TestUsers: %v", opts.DefaultTestUser, opts.TestUsers)
	}

	if opts.AutoStart {
		srv.Start()
		if opts.Issuer == "" {
			opts.Issuer = srv.URL
		}
	}

	op.options = *opts

	return op, nil
}

// Start starts the http server if AutoStart was disabled.
func (op *OPTest) Start() {
	if !op.options.AutoStart {
		op.server.Start()
		if op.options.Issuer == "" {
			op.options.Issuer = op.server.URL
		}
	}
}

// Close shuts down the http server.
func (op *OPTest) Close() {
	op.server.Close()
}

// GetURL returns the current URL of the http server.
func (op *OPTest) GetURL() string {
	return op.server.URL
}

// GetRouter returns the router to be used by a http server.
func (op *OPTest) GetRouter() *http.ServeMux {
	return op.router
}

// RotateKeys rotates the jwks keys.
func (op *OPTest) RotateKeys() error {
	err := op.jwks.addNewKey()
	if err != nil {
		return err
	}

	err = op.jwks.removeOldestKey()
	return err
}

// GetToken returns a TokenResponse with an id_token and an access_token.
func (op *OPTest) GetToken() (*TokenResponse, error) {
	return op.GetTokenByUser(op.options.DefaultTestUser)
}

// GetToken returns a TokenResponse with an id_token and an access_token.
func (op *OPTest) GetTokenByUser(userString string) (*TokenResponse, error) {
	testUser, ok := op.options.TestUsers[userString]
	if !ok {
		return nil, fmt.Errorf("unable to find test user: %s", userString)
	}

	accessToken, err := op.newAccessToken(testUser)
	if err != nil {
		return nil, err
	}

	idToken, err := op.newIdToken(testUser)
	if err != nil {
		return nil, err
	}

	tokenResponse := TokenResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   int(op.options.TokenExpiration.Seconds()),
		IdToken:     idToken,
		Expiry:      time.Now().Add(op.options.TokenExpiration),
	}

	return &tokenResponse, nil
}

// Metadata contains the information exposed through `/.well-known/openid-configuration`.
type Metadata struct {
	Issuer                 string   `json:"issuer"`
	AuthorizationEndpoint  string   `json:"authorization_endpoint"`
	TokenEndpoint          string   `json:"token_endpoint"`
	JwksUri                string   `json:"jwks_uri"`
	ResponseTypesSupported []string `json:"response_types_supported"`
}

// TokenResponse contains the token endpoint response data.
type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	IdToken     string `json:"id_token"`
	Expiry      time.Time
}

// SetAuthHeader adds the access_token to the `Authorization` header of the request.
func (t *TokenResponse) SetAuthHeader(r *http.Request) {
	r.Header.Set("Authorization", fmt.Sprintf("%s %s", t.TokenType, t.AccessToken))
}

// Valid returns true if the token exists and isn't expired.
func (t *TokenResponse) Valid() bool {
	return t != nil && t.AccessToken != "" && !t.expired()
}

func (t *TokenResponse) expired() bool {
	if t.Expiry.IsZero() {
		return false
	}
	return t.Expiry.Round(0).Add(-10 * time.Second).Before(time.Now())
}

func (op *OPTest) routeHandler() *http.ServeMux {
	router := http.NewServeMux()

	router.HandleFunc("/.well-known/openid-configuration", op.metadataHandler)
	router.HandleFunc("/authorization", op.authorizationHandler)
	router.HandleFunc("/token", op.tokenHandler)
	router.HandleFunc("/jwks", op.jwksHandler)

	return router
}

func (op *OPTest) metadataHandler(w http.ResponseWriter, r *http.Request) {
	issuer := op.options.Issuer
	data := Metadata{
		Issuer:                 issuer,
		AuthorizationEndpoint:  fmt.Sprintf("%s/authorization", issuer),
		TokenEndpoint:          fmt.Sprintf("%s/token", issuer),
		JwksUri:                fmt.Sprintf("%s/jwks", issuer),
		ResponseTypesSupported: []string{"code"},
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	//nolint: errcheck // false positive
	json.NewEncoder(w).Encode(data)
}

func (op *OPTest) authorizationHandler(w http.ResponseWriter, r *http.Request) {
	redirectUrl, err := url.Parse(r.URL.Query().Get("redirect_uri"))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	code, err := generateRandomString(32)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	state := r.URL.Query().Get("state")
	query := url.Values{}
	query.Set("code", code)
	query.Set("state", state)

	redirectUrl.RawQuery = query.Encode()

	w.Header().Set("Location", redirectUrl.String())
	w.WriteHeader(http.StatusFound)
}

func (op *OPTest) tokenHandler(w http.ResponseWriter, r *http.Request) {
	userString := r.URL.Query().Get("test_user")
	if userString == "" {
		userString = op.options.DefaultTestUser
	}

	tokenResponse, err := op.GetTokenByUser(userString)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json;charset=UTF-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusOK)

	//nolint: errcheck // false positive
	json.NewEncoder(w).Encode(tokenResponse)
}

func (op *OPTest) jwksHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	pubKey := op.jwks.getPublicKeySet()

	e := json.NewEncoder(w)
	e.SetIndent("", "  ")

	//nolint: errcheck // false positive
	e.Encode(pubKey)
}

func generateRandomString(n int) (string, error) {
	const letters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-"
	ret := make([]byte, n)
	for i := 0; i < n; i++ {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		if err != nil {
			return "", err
		}
		ret[i] = letters[num.Int64()]
	}

	return string(ret), nil
}
