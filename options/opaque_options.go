package options

import (
	"net/http"
	"time"
)

// OpaqueOptions defines the options for OIDC Middleware.
type OpaqueOptions struct {
	Issuer                string
	DiscoveryUri          string
	DiscoveryFetchTimeout time.Duration
	HttpClient            *http.Client
	TokenString           [][]TokenStringOption
	ClaimsContextKeyName  ClaimsContextKeyName
	ErrorHandler          ErrorHandler
}

// New takes Option setters and returns an Options pointer.
// Mainly used by the internal functions and most likely not
// needed by any external application using this library.
func NewOpaque(setters ...OpaqueOption) *OpaqueOptions {
	opts := &OpaqueOptions{
		DiscoveryFetchTimeout: 5 * time.Second,
		HttpClient:            http.DefaultClient,
		ClaimsContextKeyName:  DefaultClaimsContextKeyName,
	}

	for _, setter := range setters {
		setter(opts)
	}

	return opts
}

// Option returns a function that modifies an Options pointer.
type OpaqueOption func(*OpaqueOptions)

// WithOpaqueIssuer sets the Issuer parameter for Options.
// Issuer is the authority that issues the tokens
func WithOpaqueIssuer(opt string) OpaqueOption {
	return func(opts *OpaqueOptions) {
		opts.Issuer = opt
	}
}

// WithOpaqueDiscoveryUri sets the Issuer parameter for an Options pointer.
// DiscoveryUri is where the `jwks_uri` will be grabbed
// Defaults to `fmt.Sprintf("%s/.well-known/openid-configuration", strings.TrimSuffix(issuer, "/"))`
func WithOpaqueDiscoveryUri(opt string) OpaqueOption {
	return func(opts *OpaqueOptions) {
		opts.DiscoveryUri = opt
	}
}

// WithOpaqueDiscoveryFetchTimeout sets the DiscoveryFetchTimeout parameter for an Options pointer.
// DiscoveryFetchTimeout sets the context timeout when downloading the discovery metadata
// Defaults to 5 seconds
func WithOpaqueDiscoveryFetchTimeout(opt time.Duration) OpaqueOption {
	return func(opts *OpaqueOptions) {
		opts.DiscoveryFetchTimeout = opt
	}
}

// WithOpaqueHttpClient sets the HttpClient parameter for an Options pointer.
// HttpClient takes a *http.Client for external calls
// Defaults to http.DefaultClient
func WithOpaqueHttpClient(opt *http.Client) OpaqueOption {
	return func(opts *OpaqueOptions) {
		opts.HttpClient = opt
	}
}

// WithOpaqueTokenString sets the TokenString parameter for an Options pointer.
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

// WithOpaqueClaimsContextKeyName sets the ClaimsContextKeyName parameter for an Options pointer.
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

// WithOpaqueErrorHandler sets the ErrorHandler parameter for an Options pointer.
// You can pass a function to run custom logic on errors, logging as an example.
// Defaults to nil
func WithOpaqueErrorHandler(opt ErrorHandler) OpaqueOption {
	return func(opts *OpaqueOptions) {
		opts.ErrorHandler = opt
	}
}
