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

type jwtHandler[T any] struct {
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
	disableIssuerValidation    bool
	httpClient                 *http.Client
	keyHandler                 *keyHandler
	claimsValidationFn         options.ClaimsValidationFn[T]
}

type Handler[T any] interface {
	ParseToken(ctx context.Context, tokenString string) (T, error)
	SetIssuer(issuer string)
	SetDiscoveryUri(discoveryUri string)
}

func NewHandler[T any](claimsValidationFn options.ClaimsValidationFn[T], setters ...options.Option) (Handler[T], error) {
	opts := options.New(setters...)
	if opts.OpaqueTokensEnabled {
		return newOpaqueHandler(claimsValidationFn, setters...)
	}

	return newjwtHandler(claimsValidationFn, setters...)
}

func newjwtHandler[T any](claimsValidationFn options.ClaimsValidationFn[T], setters ...options.Option) (*jwtHandler[T], error) {
	opts := options.New(setters...)
	h := &jwtHandler[T]{
		issuer:                  opts.Issuer,
		discoveryUri:            opts.DiscoveryUri,
		discoveryFetchTimeout:   opts.DiscoveryFetchTimeout,
		jwksUri:                 opts.JwksUri,
		jwksFetchTimeout:        opts.JwksFetchTimeout,
		jwksRateLimit:           opts.JwksRateLimit,
		allowedTokenDrift:       opts.AllowedTokenDrift,
		requiredTokenType:       opts.RequiredTokenType,
		requiredAudience:        opts.RequiredAudience,
		disableKeyID:            opts.DisableKeyID,
		disableIssuerValidation: opts.DisableIssuerValidation,
		httpClient:              opts.HttpClient,
		claimsValidationFn:      claimsValidationFn,
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
	if !opts.LazyLoadMetadata {
		err := h.loadJwks()
		if err != nil {
			return nil, fmt.Errorf("unable to load jwks: %w", err)
		}
	}

	return h, nil
}

func (h *jwtHandler[T]) loadJwks() error {
	if h.jwksUri == "" {
		metadata, err := getOidcMetadataFromDiscoveryUri(h.httpClient, h.discoveryUri, h.discoveryFetchTimeout)
		if err != nil {
			return fmt.Errorf("unable to fetch jwksUri from discoveryUri (%s): %w", h.discoveryUri, err)
		}
		if metadata.JwksUri == "" {
			return fmt.Errorf("JwksUri is empty")
		}
		h.jwksUri = metadata.JwksUri
	}

	keyHandler, err := newKeyHandler(h.httpClient, h.jwksUri, h.jwksFetchTimeout, h.jwksRateLimit, h.disableKeyID)
	if err != nil {
		return fmt.Errorf("unable to initialize keyHandler: %w", err)
	}

	h.keyHandler = keyHandler

	return nil
}

func (h *jwtHandler[T]) SetIssuer(issuer string) {
	h.issuer = issuer
}

func (h *jwtHandler[T]) SetDiscoveryUri(discoveryUri string) {
	h.discoveryUri = discoveryUri
}

type ParseTokenFunc[T any] func(ctx context.Context, tokenString string) (T, error)

func (h *jwtHandler[T]) ParseToken(ctx context.Context, tokenString string) (T, error) {
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

	tokenKeyID := ""
	if !h.disableKeyID {
		var err error
		tokenKeyID, err = getKeyIDFromTokenHeader(tokenHeaders)
		if err != nil {
			return *new(T), err
		}
	}

	tokenAlgorithm, err := getTokenAlgorithmFromTokenHeader(tokenHeaders)
	if err != nil {
		return *new(T), fmt.Errorf("token algorithm required: %w", err)
	}

	key, err := h.keyHandler.getKey(ctx, tokenKeyID, tokenAlgorithm)
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

	validIssuer := isTokenIssuerValid(h.disableIssuerValidation, h.issuer, token.Issuer())
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

func (h *jwtHandler[T]) validateClaims(claims *T) error {
	if h.claimsValidationFn == nil {
		return nil
	}

	return h.claimsValidationFn(claims)
}

func (h *jwtHandler[T]) jwtTokenToClaims(ctx context.Context, token jwt.Token) (T, error) {
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

type oidcMetadata struct {
	JwksUri          string `json:"jwks_uri"`
	UserinfoEndpoint string `json:"userinfo_endpoint"`
}

func getOidcMetadataFromDiscoveryUri(httpClient *http.Client, discoveryUri string, fetchTimeout time.Duration) (oidcMetadata, error) {
	ctx, cancel := context.WithTimeout(context.Background(), fetchTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryUri, nil)
	if err != nil {
		return oidcMetadata{}, err
	}

	req.Header.Set("Accept", "application/json")

	res, err := httpClient.Do(req)
	if err != nil {
		return oidcMetadata{}, err
	}

	bodyBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return oidcMetadata{}, err
	}

	err = res.Body.Close()
	if err != nil {
		return oidcMetadata{}, err
	}

	metadata := oidcMetadata{}
	err = json.Unmarshal(bodyBytes, &metadata)
	if err != nil {
		return oidcMetadata{}, err
	}

	return metadata, nil
}

func getKeyIDFromTokenHeader(tokenHeaders jws.Headers) (string, error) {
	tokenKeyID := tokenHeaders.KeyID()
	if tokenKeyID == "" {
		return "", fmt.Errorf("token header does not contain key id (kid)")
	}

	return tokenKeyID, nil
}

func getTokenAlgorithmFromTokenHeader(tokenHeaders jws.Headers) (jwa.SignatureAlgorithm, error) {
	// algorithm is a required field for a jwt see: https://www.rfc-editor.org/rfc/rfc7515#section-4.1.1
	tokenAlgorithm := tokenHeaders.Algorithm()
	if tokenAlgorithm == "" {
		return "", fmt.Errorf("token header does not contain algorithm (alg)")
	}

	return tokenAlgorithm, nil
}

func getTokenTypeFromTokenHeader(tokenHeaders jws.Headers) (string, error) {
	tokenType := tokenHeaders.Type()
	if tokenType == "" {
		return "", fmt.Errorf("token header does not contain type (typ)")
	}

	return tokenType, nil
}

func getHeadersFromTokenString(tokenString string) (jws.Headers, error) {
	msg, err := jws.ParseString(tokenString)
	if err != nil {
		return nil, fmt.Errorf("unable to parse token signature: %w", err)
	}

	signatures := msg.Signatures()
	if len(signatures) != 1 {
		return nil, fmt.Errorf("more than one signature in token: %d", len(signatures))
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

func isTokenIssuerValid(disableIssuerValidation bool, requiredIssuer string, tokenIssuer string) bool {
	if disableIssuerValidation {
		return true
	}

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
