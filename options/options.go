package options

import (
	"net/http"
	"time"
)

// ClaimsValidationFn is a generic function to validate calims.
// If an error is returned, the claims failed the validation.
// If `nil` is provided instead of a function when configuration the handler,
// no additional validation of the claims will be done.
type ClaimsValidationFn[T any] func(*T) error

// ClaimsContextKeyName is the type for they key value used to pass claims using request context.
// Using separate type because of the following: https://staticcheck.io/docs/checks#SA1029
type ClaimsContextKeyName string

// DefaultClaimsContextKeyName is of type ClaimsContextKeyName and defaults to "claims"
const DefaultClaimsContextKeyName ClaimsContextKeyName = "claims"

// ErrorHandler is called by the middleware if not nil
type ErrorHandler func(description ErrorDescription, err error)

// ErrorDescription is used to pass the description of the error to ErrorHandler
type ErrorDescription string

const (
	// GetTokenErrorDescription is returned to ErrorHandler if the middleware is unable to get a token from the request
	GetTokenErrorDescription ErrorDescription = "unable to get token string"
	// ParseTokenErrorDescription is returned to ErrorHandler if the middleware is unable to parse the token extracted from the request
	ParseTokenErrorDescription ErrorDescription = "unable to parse token string"
	// ConvertTokenErrorDescription is returned to ErrorHandler if the middleware is unable to convert the token to a map
	ConvertTokenErrorDescription ErrorDescription = "unable to convert token to map"
)

// Options defines the options for OIDC Middleware.
type Options struct {
	Issuer                     string
	DiscoveryUri               string
	DiscoveryFetchTimeout      time.Duration
	JwksUri                    string
	JwksFetchTimeout           time.Duration
	JwksRateLimit              uint
	FallbackSignatureAlgorithm string
	AllowedTokenDrift          time.Duration
	LazyLoadMetadata           bool
	RequiredTokenType          string
	RequiredAudience           string
	DisableKeyID               bool
	DisableIssuerValidation    bool
	HttpClient                 *http.Client
	TokenString                [][]TokenStringOption
	ClaimsContextKeyName       ClaimsContextKeyName
	ErrorHandler               ErrorHandler
	OpaqueTokensEnabled        bool
	OpaqueOptions              []OpaqueOption
}

// New takes Option setters and returns an Options pointer.
// Mainly used by the internal functions and most likely not
// needed by any external application using this library.
func New(setters ...Option) *Options {
	opts := &Options{
		DiscoveryFetchTimeout: 5 * time.Second,
		JwksFetchTimeout:      5 * time.Second,
		JwksRateLimit:         1,
		AllowedTokenDrift:     10 * time.Second,
		HttpClient:            http.DefaultClient,
		ClaimsContextKeyName:  DefaultClaimsContextKeyName,
	}

	for _, setter := range setters {
		setter(opts)
	}

	return opts
}

// Option returns a function that modifies an Options pointer.
type Option func(*Options)

// WithIssuer sets the Issuer parameter for Options.
// Issuer is the authority that issues the tokens
func WithIssuer(opt string) Option {
	return func(opts *Options) {
		opts.Issuer = opt
	}
}

// WithDiscoveryUri sets the Issuer parameter for an Options pointer.
// DiscoveryUri is where the `jwks_uri` will be grabbed
// Defaults to `fmt.Sprintf("%s/.well-known/openid-configuration", strings.TrimSuffix(issuer, "/"))`
func WithDiscoveryUri(opt string) Option {
	return func(opts *Options) {
		opts.DiscoveryUri = opt
	}
}

// WithDiscoveryFetchTimeout sets the DiscoveryFetchTimeout parameter for an Options pointer.
// DiscoveryFetchTimeout sets the context timeout when downloading the discovery metadata
// Defaults to 5 seconds
func WithDiscoveryFetchTimeout(opt time.Duration) Option {
	return func(opts *Options) {
		opts.DiscoveryFetchTimeout = opt
	}
}

// WithJwksUri sets the JwksUri parameter for an Options pointer.
// JwksUri is used to download the public key(s)
// Defaults to the `jwks_uri` from the response of DiscoveryUri
func WithJwksUri(opt string) Option {
	return func(opts *Options) {
		opts.JwksUri = opt
	}
}

// WithJwksFetchTimeout sets the JwksFetchTimeout parameter for an Options pointer.
// JwksFetchTimeout sets the context timeout when downloading the jwks
// Defaults to 5 seconds
func WithJwksFetchTimeout(opt time.Duration) Option {
	return func(opts *Options) {
		opts.JwksFetchTimeout = opt
	}
}

// WithJwksRateLimit sets the JwksFetchTimeout parameter for an Options pointer.
// JwksRateLimit takes an uint and makes sure that the jwks will at a maximum
// be requested these many times per second.
// Defaults to 1 (Request Per Second)
// Please observe: Requests that force update of jwks (like wrong keyID) will be rate limited
func WithJwksRateLimit(opt uint) Option {
	return func(opts *Options) {
		opts.JwksRateLimit = opt
	}
}

// WithFallbackSignatureAlgorithm sets the FallbackSignatureAlgorithm parameter for an Options pointer.
// FallbackSignatureAlgorithm needs to be used when the jwks doesn't contain the alg key.
// If not specified and jwks doesn't contain alg key, will default to:
// - RS256 for key type (kty) RSA
// - ES256 for key type (kty) EC
//
// When specified and jwks contains alg key, alg key from jwks will be used.
//
// Example values (one of them): RS256 RS384 RS512 ES256 ES384 ES512
func WithFallbackSignatureAlgorithm(opt string) Option {
	return func(opts *Options) {
		opts.FallbackSignatureAlgorithm = opt
	}
}

// WithAllowedTokenDrift sets the AllowedTokenDrift parameter for an Options pointer.
// AllowedTokenDrift adds the duration to the token expiration to allow
// for time drift between parties.
// Defaults to 10 seconds
func WithAllowedTokenDrift(opt time.Duration) Option {
	return func(opts *Options) {
		opts.AllowedTokenDrift = opt
	}
}

// WithLazyLoadMetadata sets the LazyLoadMetadata parameter for an Options pointer.
// LazyLoadMetadata makes it possible to use OIDC Discovery without being
// able to load the metadata at startup.
// Default setting is disabled.
// Please observe: If enabled, it will always load even though settings
// may be wrong / not working.
func WithLazyLoadMetadata(opt bool) Option {
	return func(opts *Options) {
		opts.LazyLoadMetadata = opt
	}
}

// WithRequiredTokenType sets the RequiredTokenType parameter for an Options pointer.
// RequiredTokenType is used if only specific tokens should be allowed.
// Default is empty string `""` and means all token types are allowed.
// Use case could be to configure this if the TokenType (set in the header of the JWT)
// should be `JWT` or maybe even `JWT+AT` to differentiate between access tokens and
// id tokens. Not all providers support or use this.
func WithRequiredTokenType(opt string) Option {
	return func(opts *Options) {
		opts.RequiredTokenType = opt
	}
}

// WithRequiredAudience sets the RequiredAudience parameter for an Options pointer.
// RequiredAudience is used to require a specific Audience `aud` in the claims.
// Defaults to empty string `""` and means all audiences are allowed.
func WithRequiredAudience(opt string) Option {
	return func(opts *Options) {
		opts.RequiredAudience = opt
	}
}

// WithDisableKeyID sets the DisableKeyID parameter for an Options pointer.
// DisableKeyID adjusts if a KeyID needs to be extracted from the token or not
// Defaults to false and means KeyID is required to be present in both the jwks and token
// The OIDC specification doesn't require KeyID if there's only one key in the jwks:
// https://openid.net/specs/openid-connect-core-1_0.html#Signing
//
// This also means that if enabled, refresh of the jwks will be done if the token can't be
// validated due to invalid key. The JWKS fetch will fail if there's more than one key present.
func WithDisableKeyID(opt bool) Option {
	return func(opts *Options) {
		opts.DisableKeyID = opt
	}
}

// WithHttpClient sets the HttpClient parameter for an Options pointer.
// HttpClient takes a *http.Client for external calls
// Defaults to http.DefaultClient
func WithHttpClient(opt *http.Client) Option {
	return func(opts *Options) {
		opts.HttpClient = opt
	}
}

// WithTokenString sets the TokenString parameter for an Options pointer.
// TokenString makes it possible to configure how the JWT token should be extracted from
// an http header. Not supported by Echo JWT and will be ignored if used by it.
// Defaults to: 'Authorization: Bearer JWT'
func WithTokenString(setters ...TokenStringOption) Option {
	var tokenString []TokenStringOption
	tokenString = append(tokenString, setters...)

	return func(opts *Options) {
		opts.TokenString = append(opts.TokenString, tokenString)
	}
}

// WithClaimsContextKeyName sets the ClaimsContextKeyName parameter for an Options pointer.
// ClaimsContextKeyName is the name of key that will be used to pass claims using request context.
// Not supported by Echo JWT and will be ignored if used by it.
//
// Important note: If you change this using `options.WithClaimsContextKeyName("foo")`, then
// you also need to use it like this:
// `claims, ok := r.Context().Value(options.ClaimsContextKeyName("foo")).(map[string]interface{})`
//
// Default: `options.DefaultClaimsContextKeyName`
// Used like this: “claims, ok := r.Context().Value(options.DefaultClaimsContextKeyName).(map[string]interface{})“
//
// When used with gin, it is converted to normal string - by default:
// `claimsValue, found := c.Get("claims")`
func WithClaimsContextKeyName(opt string) Option {
	return func(opts *Options) {
		opts.ClaimsContextKeyName = ClaimsContextKeyName(opt)
	}
}

// WithErrorHandler sets the ErrorHandler parameter for an Options pointer.
// You can pass a function to run custom logic on errors, logging as an example.
// Defaults to nil
func WithErrorHandler(opt ErrorHandler) Option {
	return func(opts *Options) {
		opts.ErrorHandler = opt
	}
}

// WithDisableIssuerValidation will disable the Issuer validation.
// Use with care, make sure to do some kind of validation inside of the ClaimsValidationFn.
// Default to false
func WithDisableIssuerValidation() Option {
	return func(opts *Options) {
		opts.DisableIssuerValidation = true
	}
}

// WithOpaqueToken enable the middleware to use opaque tokens instead of JWTs.
// Defaults to false
func WithOpaqueTokensEnabled(opt ...OpaqueOption) Option {
	return func(opts *Options) {
		opts.OpaqueOptions = opt
		opts.OpaqueTokensEnabled = true
	}
}
