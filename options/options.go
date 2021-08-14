package options

import (
	"net/http"
	"time"
)

// ClaimsContextKeyName is the type for they key value used to pass claims using request context.
// Using separate type because of the following: https://staticcheck.io/docs/checks#SA1029
type ClaimsContextKeyName string

// Options defines the options for OIDC Middleware.
type Options struct {
	// Issuer is the authority that issues the tokens
	Issuer string

	// DiscoveryUri is where the `jwks_uri` will be grabbed
	// Defaults to `fmt.Sprintf("%s/.well-known/openid-configuration", strings.TrimSuffix(issuer, "/"))`
	DiscoveryUri string

	// JwksUri is used to download the public key(s)
	// Defaults to the `jwks_uri` from the response of DiscoveryUri
	JwksUri string

	// JwksFetchTimeout sets the context timeout when downloading the jwks
	// Defaults to 5 seconds
	JwksFetchTimeout time.Duration

	// JwksRateLimit takes an uint and makes sure that the jwks will at a maximum
	// be requested these many times per second.
	// Defaults to 1 (Request Per Second)
	// Please observe: Requests that force update of jwks (like wrong keyID) will be rate limited
	JwksRateLimit uint

	// FallbackSignatureAlgorithm needs to be used when the jwks doesn't contain the alg key.
	// If not specified and jwks doesn't contain alg key, will default to:
	// - RS256 for key type (kty) RSA
	// - ES256 for key type (kty) EC
	//
	// When specified and jwks contains alg key, alg key from jwks will be used.
	//
	// Example values (one of them): RS256 RS384 RS512 ES256 ES384 ES512
	FallbackSignatureAlgorithm string

	// AllowedTokenDrift adds the duration to the token expiration to allow
	// for time drift between parties.
	// Defaults to 10 seconds
	AllowedTokenDrift time.Duration

	// LazyLoadJwks makes it possible to use OIDC Discovery without being
	// able to load the keys at startup.
	// Default setting is disabled.
	// Please observe: If enabled, it will always load even though settings
	// may be wrong / not working.
	LazyLoadJwks bool

	// RequiredTokenType is used if only specific tokens should be allowed.
	// Default is empty string `""` and means all token types are allowed.
	// Use case could be to configure this if the TokenType (set in the header of the JWT)
	// should be `JWT` or maybe even `JWT+AT` to differentiate between access tokens and
	// id tokens. Not all providers support or use this.
	RequiredTokenType string

	// RequiredAudience is used to require a specific Audience `aud` in the claims.
	// Defaults to empty string `""` and means all audiences are allowed.
	RequiredAudience string

	// RequiredClaims is used to require specific claims in the token
	// Defaults to empty map (nil) and won't check for anything else
	// Works with primitive types, slices and maps.
	// Please observe: slices and strings checks that the token contains it, but more is allowed.
	// Required claim []string{"bar"} matches token []string{"foo", "bar", "baz"}
	// Required claim map[string]string{{"foo": "bar"}} matches token map[string]string{{"a": "b"},{"foo": "bar"},{"c": "d"}}
	//
	// Example:
	//
	// ```go
	// map[string]interface{}{
	// 	"foo": "bar",
	// 	"bar": 1337,
	// 	"baz": []string{"bar"},
	// 	"oof": []map[string]string{
	// 		{"bar": "baz"},
	// 	},
	// },
	// ```
	RequiredClaims map[string]interface{}

	// DisableKeyID adjusts if a KeyID needs to be extracted from the token or not
	// Defaults to false and means KeyID is required to be present in both the jwks and token
	// The OIDC specification doesn't require KeyID if there's only one key in the jwks:
	// https://openid.net/specs/openid-connect-core-1_0.html#Signing
	//
	// This also means that if enabled, refresh of the jwks will be done if the token can't be
	// validated due to invalid key. The JWKS fetch will fail if there's more than one key present.
	DisableKeyID bool

	// HttpClient takes a *http.Client for external calls
	// Defaults to http.DefaultClient
	HttpClient *http.Client

	// TokenString makes it possible to configure how the JWT token should be extracted from
	// an http header. Not supported by Echo JWT and will be ignored if used by it.
	// Defaults to: 'Authorization: Bearer JWT'
	TokenString []TokenStringOption

	// ClaimsContextKey is the name of key that will be used to pass claims using request context.
	// Not supported by Echo JWT and will be ignored if used by it.
	// Default: claims
	ClaimsContextKeyName ClaimsContextKeyName
}

func New(setters ...Option) *Options {
	opts := &Options{
		JwksFetchTimeout:     5 * time.Second,
		JwksRateLimit:        1,
		AllowedTokenDrift:    10 * time.Second,
		HttpClient:           http.DefaultClient,
		ClaimsContextKeyName: "claims",
	}

	for _, setter := range setters {
		setter(opts)
	}

	return opts
}

// Option returns a function that modifies an Options pointer.
type Option func(*Options)

// WithIssuer sets the Issuer parameter for Options.
func WithIssuer(opt string) Option {
	return func(opts *Options) {
		opts.Issuer = opt
	}
}

// WithDiscoveryUri sets the Issuer parameter for an Options pointer.
func WithDiscoveryUri(opt string) Option {
	return func(opts *Options) {
		opts.DiscoveryUri = opt
	}
}

// WithJwksUri sets the JwksUri parameter for an Options pointer.
func WithJwksUri(opt string) Option {
	return func(opts *Options) {
		opts.JwksUri = opt
	}
}

// WithJwksFetchTimeout sets the JwksFetchTimeout parameter for an Options pointer.
func WithJwksFetchTimeout(opt time.Duration) Option {
	return func(opts *Options) {
		opts.JwksFetchTimeout = opt
	}
}

// WithJwksRateLimit sets the JwksFetchTimeout parameter for an Options pointer.
func WithJwksRateLimit(opt uint) Option {
	return func(opts *Options) {
		opts.JwksRateLimit = opt
	}
}

// WithFallbackSignatureAlgorithm sets the FallbackSignatureAlgorithm parameter for an Options pointer.
func WithFallbackSignatureAlgorithm(opt string) Option {
	return func(opts *Options) {
		opts.FallbackSignatureAlgorithm = opt
	}
}

// WithAllowedTokenDrift sets the AllowedTokenDrift parameter for an Options pointer.
func WithAllowedTokenDrift(opt time.Duration) Option {
	return func(opts *Options) {
		opts.AllowedTokenDrift = opt
	}
}

// WithLazyLoadJwks sets the LazyLoadJwks parameter for an Options pointer.
func WithLazyLoadJwks(opt bool) Option {
	return func(opts *Options) {
		opts.LazyLoadJwks = opt
	}
}

// WithRequiredTokenType sets the RequiredTokenType parameter for an Options pointer.
func WithRequiredTokenType(opt string) Option {
	return func(opts *Options) {
		opts.RequiredTokenType = opt
	}
}

// WithRequiredAudience sets the RequiredAudience parameter for an Options pointer.
func WithRequiredAudience(opt string) Option {
	return func(opts *Options) {
		opts.RequiredAudience = opt
	}
}

// WithRequiredClaims sets the RequiredClaims parameter for an Options pointer.
func WithRequiredClaims(opt map[string]interface{}) Option {
	return func(opts *Options) {
		opts.RequiredClaims = opt
	}
}

// WithDisableKeyID sets the DisableKeyID parameter for an Options pointer.
func WithDisableKeyID(opt bool) Option {
	return func(opts *Options) {
		opts.DisableKeyID = opt
	}
}

// WithHttpClient sets the HttpClient parameter for an Options pointer.
func WithHttpClient(opt *http.Client) Option {
	return func(opts *Options) {
		opts.HttpClient = opt
	}
}

// WithTokenString sets the TokenString parameter for an Options pointer.
func WithTokenString(setters ...TokenStringOption) Option {
	return func(opts *Options) {
		opts.TokenString = append(opts.TokenString, setters...)
	}
}

// WithClaimsContextKeyName sets the ClaimsContextKeyName parameter for an Options pointer.
func WithClaimsContextKeyName(opt string) Option {
	return func(opts *Options) {
		opts.ClaimsContextKeyName = ClaimsContextKeyName(opt)
	}
}
