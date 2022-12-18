package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/xenitab/go-oidc-middleware/options"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/lestrrat-go/jwx/jwt"
)

var (
	errSignatureVerification = fmt.Errorf("failed to verify signature")
)

type handler[T any] struct {
	issuer                     string
	discoveryUri               string
	discoveryFetchTimeout      time.Duration
	jwksUri                    string
	jwksFetchTimeout           time.Duration
	jwksRateLimit              uint
	fallbackSignatureAlgorithm jwa.SignatureAlgorithm
	allowedTokenDrift          time.Duration
	requiredAudience           string
	requiredTokenType          string
	disableKeyID               bool
	httpClient                 *http.Client
	keyHandler                 *keyHandler
	claimsValidationFn         options.ClaimsValidationFn[T]
}

func NewHandler[T any](claimsValidationFn options.ClaimsValidationFn[T], setters ...options.Option) (*handler[T], error) {
	opts := options.New(setters...)

	h := &handler[T]{
		issuer:                opts.Issuer,
		discoveryUri:          opts.DiscoveryUri,
		discoveryFetchTimeout: opts.DiscoveryFetchTimeout,
		jwksUri:               opts.JwksUri,
		jwksFetchTimeout:      opts.JwksFetchTimeout,
		jwksRateLimit:         opts.JwksRateLimit,
		allowedTokenDrift:     opts.AllowedTokenDrift,
		requiredTokenType:     opts.RequiredTokenType,
		requiredAudience:      opts.RequiredAudience,
		disableKeyID:          opts.DisableKeyID,
		httpClient:            opts.HttpClient,
		claimsValidationFn:    claimsValidationFn,
	}

	if h.issuer == "" {
		return nil, fmt.Errorf("issuer is empty")
	}
	if h.discoveryUri == "" {
		h.discoveryUri = GetDiscoveryUriFromIssuer(h.issuer)
	}
	if opts.FallbackSignatureAlgorithm != "" {
		alg, err := getSignatureAlgorithmFromString(opts.FallbackSignatureAlgorithm)
		if err != nil {
			return nil, fmt.Errorf("FallbackSignatureAlgorithm not accepted: %w", err)
		}

		h.fallbackSignatureAlgorithm = alg
	}
	if !opts.LazyLoadJwks {
		err := h.loadJwks()
		if err != nil {
			return nil, fmt.Errorf("unable to load jwks: %w", err)
		}
	}

	return h, nil
}

func (h *handler[T]) loadJwks() error {
	if h.jwksUri == "" {
		jwksUri, err := getJwksUriFromDiscoveryUri(h.httpClient, h.discoveryUri, h.discoveryFetchTimeout)
		if err != nil {
			return fmt.Errorf("unable to fetch jwksUri from discoveryUri (%s): %w", h.discoveryUri, err)
		}
		h.jwksUri = jwksUri
	}

	keyHandler, err := newKeyHandler(h.httpClient, h.jwksUri, h.jwksFetchTimeout, h.jwksRateLimit, h.disableKeyID)
	if err != nil {
		return fmt.Errorf("unable to initialize keyHandler: %w", err)
	}

	h.keyHandler = keyHandler

	return nil
}

func (h *handler[T]) SetIssuer(issuer string) {
	h.issuer = issuer
}

func (h *handler[T]) SetDiscoveryUri(discoveryUri string) {
	h.discoveryUri = discoveryUri
}

type ParseTokenFunc[T any] func(ctx context.Context, tokenString string) (T, error)

func (h *handler[T]) ParseToken(ctx context.Context, tokenString string) (T, error) {
	if h.keyHandler == nil {
		err := h.loadJwks()
		if err != nil {
			return *new(T), fmt.Errorf("unable to load jwks: %w", err)
		}
	}

	tokenHeaders, err := getHeadersFromTokenString(tokenString)
	if err != nil {
		return *new(T), err
	}

	tokenTypeValid := isTokenTypeValid(h.requiredTokenType, tokenHeaders)
	if !tokenTypeValid {
		return *new(T), fmt.Errorf("token type %q required", h.requiredTokenType)
	}

	keyID := ""
	if !h.disableKeyID {
		var err error
		keyID, err = getKeyIDFromTokenHeader(tokenHeaders)
		if err != nil {
			return *new(T), err
		}
	}

	tokenAlgorithm, err := getTokenAlgorithmFromTokenHeader(tokenHeaders)
	if err != nil {
		return *new(T), fmt.Errorf("tokenAlgorithm required: %w", err)
	}

	key, err := h.keyHandler.getKey(ctx, keyID, tokenAlgorithm)
	if err != nil {
		return *new(T), fmt.Errorf("unable to get public key: %w", err)
	}

	alg, err := getSignatureAlgorithm(key.KeyType(), key.Algorithm(), h.fallbackSignatureAlgorithm)
	if err != nil {
		return *new(T), err
	}

	token, err := getAndValidateTokenFromString(tokenString, key, alg)
	if err != nil {
		if h.disableKeyID && errors.Is(err, errSignatureVerification) {
			updatedKey, err := h.keyHandler.waitForUpdateKeySetAndGetKey(ctx)
			if err != nil {
				return *new(T), err
			}

			alg, err := getSignatureAlgorithm(key.KeyType(), key.Algorithm(), h.fallbackSignatureAlgorithm)
			if err != nil {
				return *new(T), err
			}

			token, err = getAndValidateTokenFromString(tokenString, updatedKey, alg)
			if err != nil {
				return *new(T), err
			}
		} else {
			return *new(T), err
		}
	}

	validExpiration := isTokenExpirationValid(token.Expiration(), h.allowedTokenDrift)
	if !validExpiration {
		return *new(T), fmt.Errorf("token has expired: %s", token.Expiration())
	}

	validIssuer := isTokenIssuerValid(h.issuer, token.Issuer())
	if !validIssuer {
		return *new(T), fmt.Errorf("required issuer %q was not found, received: %s", h.issuer, token.Issuer())
	}

	validAudience := isTokenAudienceValid(h.requiredAudience, token.Audience())
	if !validAudience {
		return *new(T), fmt.Errorf("required audience %q was not found, received: %v", h.requiredAudience, token.Audience())
	}

	claims, err := h.jwtTokenToClaims(ctx, token)
	if err != nil {
		return *new(T), fmt.Errorf("unable to convert jwt.Token to claims: %w", err)
	}

	err = h.validateClaims(&claims)
	if err != nil {
		return *new(T), fmt.Errorf("claims validation returned an error: %w", err)
	}

	return claims, nil
}

func (h *handler[T]) validateClaims(claims *T) error {
	if h.claimsValidationFn == nil {
		return nil
	}

	return h.claimsValidationFn(claims)
}

func (h *handler[T]) jwtTokenToClaims(ctx context.Context, token jwt.Token) (T, error) {
	rawClaims, err := token.AsMap(ctx)
	if err != nil {
		return *new(T), fmt.Errorf("unable to convert token to claims: %w", err)
	}

	claimsBytes, err := json.Marshal(rawClaims)
	if err != nil {
		return *new(T), fmt.Errorf("unable to marshal raw claims to json: %w", err)
	}

	claims := *new(T)
	err = json.Unmarshal(claimsBytes, &claims)
	if err != nil {
		return *new(T), fmt.Errorf("unable to unmarshal claims from json: %w", err)
	}

	return claims, nil
}

func GetDiscoveryUriFromIssuer(issuer string) string {
	return fmt.Sprintf("%s/.well-known/openid-configuration", strings.TrimSuffix(issuer, "/"))
}

func getJwksUriFromDiscoveryUri(httpClient *http.Client, discoveryUri string, fetchTimeout time.Duration) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), fetchTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryUri, nil)
	if err != nil {
		return "", err
	}

	req.Header.Set("Accept", "application/json")

	res, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}

	bodyBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return "", err
	}

	err = res.Body.Close()
	if err != nil {
		return "", err
	}

	var discoveryData struct {
		JwksUri string `json:"jwks_uri"`
	}

	err = json.Unmarshal(bodyBytes, &discoveryData)
	if err != nil {
		return "", err
	}

	if discoveryData.JwksUri == "" {
		return "", fmt.Errorf("JwksUri is empty")
	}

	return discoveryData.JwksUri, nil
}

func getKeyIDFromTokenHeader(headers jws.Headers) (string, error) {
	keyID := headers.KeyID()
	if keyID == "" {
		return "", fmt.Errorf("token header does not contain key id (kid)")
	}

	return keyID, nil
}

func getTokenAlgorithmFromTokenHeader(headers jws.Headers) (jwa.SignatureAlgorithm, error) {
	// algorithm is a required field for a jwt see: https://www.rfc-editor.org/rfc/rfc7515#section-4.1.1
	algorithm := headers.Algorithm()
	if algorithm == "" {
		return "", fmt.Errorf("token header does not contain algorithm (alg)")
	}

	return algorithm, nil
}

func getTokenTypeFromTokenHeader(headers jws.Headers) (string, error) {
	tokenType := headers.Type()
	if tokenType == "" {
		return "", fmt.Errorf("token header does not contain type (typ)")
	}

	return tokenType, nil
}

func getHeadersFromTokenString(tokenString string) (jws.Headers, error) {
	msg, err := jws.ParseString(tokenString)
	if err != nil {
		return nil, fmt.Errorf("unable to parse tokenString: %w", err)
	}

	signatures := msg.Signatures()
	if len(signatures) != 1 {
		return nil, fmt.Errorf("more than one signature in token")
	}

	headers := signatures[0].ProtectedHeaders()

	return headers, nil
}

func isTokenAudienceValid(requiredAudience string, audiences []string) bool {
	if requiredAudience == "" {
		return true
	}

	for _, audience := range audiences {
		if audience == requiredAudience {
			return true
		}
	}

	return false
}

func isTokenExpirationValid(expiration time.Time, allowedDrift time.Duration) bool {
	expirationWithAllowedDrift := expiration.Round(0).Add(allowedDrift)

	return expirationWithAllowedDrift.After(time.Now())
}

func isTokenIssuerValid(requiredIssuer string, tokenIssuer string) bool {
	if requiredIssuer == "" {
		return false
	}

	return tokenIssuer == requiredIssuer
}

func isTokenTypeValid(requiredTokenType string, tokenHeaders jws.Headers) bool {
	if requiredTokenType == "" {
		return true
	}

	tokenType, err := getTokenTypeFromTokenHeader(tokenHeaders)
	if err != nil {
		return false
	}

	if tokenType != requiredTokenType {
		return false
	}

	return true
}

func getAndValidateTokenFromString(tokenString string, key jwk.Key, alg jwa.SignatureAlgorithm) (jwt.Token, error) {
	token, err := jwt.ParseString(tokenString, jwt.WithVerify(alg, key))
	if err != nil {
		if strings.Contains(err.Error(), errSignatureVerification.Error()) {
			return nil, errSignatureVerification
		}

		return nil, err
	}

	return token, nil
}

func getSignatureAlgorithm(kty jwa.KeyType, keyAlg string, fallbackAlg jwa.SignatureAlgorithm) (jwa.SignatureAlgorithm, error) {
	if keyAlg != "" {
		return getSignatureAlgorithmFromString(keyAlg)
	}

	if fallbackAlg != "" {
		return fallbackAlg, nil
	}

	switch kty {
	case jwa.RSA:
		return jwa.RS256, nil
	case jwa.EC:
		return jwa.ES256, nil
	default:
		return "", fmt.Errorf("unable to get signature algorithm with kty=%s, alg=%s, fallbackAlg=%s", kty, keyAlg, fallbackAlg)
	}
}

func getSignatureAlgorithmFromString(s string) (jwa.SignatureAlgorithm, error) {
	var alg jwa.SignatureAlgorithm
	err := alg.Accept(s)
	if err != nil {
		return "", err
	}

	return alg, nil
}
