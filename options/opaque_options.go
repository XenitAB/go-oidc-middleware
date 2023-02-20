package options

import (
	"net/http"
	"time"
)

// OpaqueOptions defines the options for OIDC Middleware.
type OpaqueOptions struct {
	Issuer                    string
	DiscoveryUri              string
	DiscoveryFetchTimeout     time.Duration
	IntrospectionUri          string
	IntrospectionFetchTimeout time.Duration
	TokenCacheTimeToLive      time.Duration
	HttpClient                *http.Client
	TokenString               [][]TokenStringOption
	ClaimsContextKeyName      ClaimsContextKeyName
	ErrorHandler              ErrorHandler
}

// NewOpaque takes Option setters and returns an OpaqueOptions pointer.
// Mainly used by the internal functions and most likely not
// needed by any external application using this library.
func NewOpaque(setters ...OpaqueOption) *OpaqueOptions {
	opts := &OpaqueOptions{
		DiscoveryFetchTimeout:     5 * time.Second,
		IntrospectionFetchTimeout: 5 * time.Second,
		HttpClient:                http.DefaultClient,
		ClaimsContextKeyName:      DefaultClaimsContextKeyName,
	}

	for _, setter := range setters {
		setter(opts)
	}

	return opts
}

// OpaqueOption returns a function that modifies an OpaqueOptions pointer.
type OpaqueOption func(*OpaqueOptions)

// WithOpaqueIssuer sets the Issuer parameter for Options.
// Issuer is the authority that issues the tokens
func WithOpaqueIssuer(opt string) OpaqueOption {
	return func(opts *OpaqueOptions) {
		opts.Issuer = opt
	}
}

// WithOpaqueDiscoveryUri sets the Issuer parameter for an OpaqueOptions pointer.
// DiscoveryUri is where the `userinfo_endpoint` will be grabbed
// Defaults to `fmt.Sprintf("%s/.well-known/openid-configuration", strings.TrimSuffix(issuer, "/"))`
func WithOpaqueDiscoveryUri(opt string) OpaqueOption {
	return func(opts *OpaqueOptions) {
		opts.DiscoveryUri = opt
	}
}

// WithOpaqueDiscoveryFetchTimeout sets the DiscoveryFetchTimeout parameter for an OpaqueOptions pointer.
// DiscoveryFetchTimeout sets the context timeout when downloading the discovery metadata
// Defaults to 5 seconds
func WithOpaqueDiscoveryFetchTimeout(opt time.Duration) OpaqueOption {
	return func(opts *OpaqueOptions) {
		opts.DiscoveryFetchTimeout = opt
	}
}

// WithOpaqueIntrospectionUri sets the Issuer parameter for an OpaqueOptions pointer.
// IntrospectionUri is where the `userinfo_endpoint` from the discovery metadata is pointing.
// Defaults to what's fetched from the discovery metadata, but if defined here will be overwritten.
func WithOpaqueIntrospectionUri(opt string) OpaqueOption {
	return func(opts *OpaqueOptions) {
		opts.IntrospectionUri = opt
	}
}

// WithOpaqueIntrospectionFetchTimeout sets the IntrospectionFetchTimeout parameter for an OpaqueOptions pointer.
// IntrospectionFetchTimeout sets the context timeout when sending the introspection request
// Defaults to 5 seconds
func WithOpaqueIntrospectionFetchTimeout(opt time.Duration) OpaqueOption {
	return func(opts *OpaqueOptions) {
		opts.IntrospectionFetchTimeout = opt
	}
}

// WithOpaqueTokenCacheTimeToLive sets the TokenCacheTimeToLive parameter for an OpaqueOptions pointer.
// TokenCacheTimeToLive sets the token cache ttl (time to live)
// Defaults to disabled (0s)
func WithOpaqueTokenCacheTimeToLive(opt time.Duration) OpaqueOption {
	return func(opts *OpaqueOptions) {
		opts.IntrospectionFetchTimeout = opt
	}
}

// WithOpaqueHttpClient sets the HttpClient parameter for an OpaqueOptions pointer.
// HttpClient takes a *http.Client for external calls
// Defaults to http.DefaultClient
func WithOpaqueHttpClient(opt *http.Client) OpaqueOption {
	return func(opts *OpaqueOptions) {
		opts.HttpClient = opt
	}
}

// WithOpaqueTokenString sets the TokenString parameter for an OpaqueOptions pointer.
// TokenString makes it possible to configure how the JWT token should be extracted from
// an http header. Not supported by Echo JWT and will be ignored if used by it.
// Defaults to: 'Authorization: Bearer JWT'
func WithOpaqueTokenString(setters ...TokenStringOption) OpaqueOption {
	var tokenString []TokenStringOption
	tokenString = append(tokenString, setters...)

	return func(opts *OpaqueOptions) {
		opts.TokenString = append(opts.TokenString, tokenString)
	}
}

// WithOpaqueClaimsContextKeyName sets the ClaimsContextKeyName parameter for an OpaqueOptions pointer.
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
func WithOpaqueClaimsContextKeyName(opt string) OpaqueOption {
	return func(opts *OpaqueOptions) {
		opts.ClaimsContextKeyName = ClaimsContextKeyName(opt)
	}
}

// WithOpaqueErrorHandler sets the ErrorHandler parameter for an OpaqueOptions pointer.
// You can pass a function to run custom logic on errors, logging as an example.
// Defaults to nil
func WithOpaqueErrorHandler(opt ErrorHandler) OpaqueOption {
	return func(opts *OpaqueOptions) {
		opts.ErrorHandler = opt
	}
}
