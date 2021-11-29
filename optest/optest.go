package optest

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
)

type Options struct {
	Issuer string
}

type Option func(*Options)

func WithIssuer(issuer string) Option {
	return func(opts *Options) {
		opts.Issuer = issuer
	}
}

type OPTest struct {
	server  *httptest.Server
	options Options
	jwks    *jwksHandler
}

func New(setters ...Option) (*OPTest, error) {
	jwks, err := newJwksHandler()
	if err != nil {
		return nil, err
	}

	op := &OPTest{
		jwks: jwks,
	}

	router := op.routeHandler()
	srv := httptest.NewServer(router)
	op.server = srv

	opts := &Options{
		Issuer: srv.URL,
	}

	for _, setter := range setters {
		setter(opts)
	}

	op.options = *opts

	return op, nil
}

func (op *OPTest) Close() {
	op.server.Close()
}

func (op *OPTest) GetURL() string {
	return op.server.URL
}

func (op *OPTest) RotateKeys() error {
	err := op.jwks.addNewKey()
	if err != nil {
		return err
	}

	err = op.jwks.removeOldestKey()
	if err != nil {
		return err
	}

	return nil
}

func (op *OPTest) GetToken() (*TokenResponse, error) {
	accessToken, err := newAccessToken(op.options.Issuer, op.jwks.getPrivateKey())
	if err != nil {
		return nil, err
	}

	idToken, err := newIdToken(op.options.Issuer, op.jwks.getPrivateKey())
	if err != nil {
		return nil, err
	}

	tokenResponse := TokenResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   3600,
		IdToken:     idToken,
	}

	return &tokenResponse, nil
}

type Metadata struct {
	Issuer                 string   `json:"issuer"`
	AuthorizationEndpoint  string   `json:"authorization_endpoint"`
	TokenEndpoint          string   `json:"token_endpoint"`
	JwksUri                string   `json:"jwks_uri"`
	ResponseTypesSupported []string `json:"response_types_supported"`
}

type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	IdToken     string `json:"id_token"`
}

func (t *TokenResponse) SetAuthHeader(r *http.Request) {
	r.Header.Set("Authorization", fmt.Sprintf("%s %s", t.TokenType, t.AccessToken))
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
	accessToken, err := newAccessToken(op.options.Issuer, op.jwks.getPrivateKey())
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	idToken, err := newIdToken(op.options.Issuer, op.jwks.getPrivateKey())
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	tokenResponse := TokenResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   3600,
		IdToken:     idToken,
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
