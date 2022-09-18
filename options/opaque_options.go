package options

import (
	"net/http"
	"time"
)

type OpaqueOptions struct {
	Issuer                string
	DiscoveryUri          string
	DiscoveryFetchTimeout time.Duration
	UserinfoUri           string
	UserinfoFetchTimeout  time.Duration
	TokenTTL              time.Duration
	RequiredClaims        map[string]interface{}
	HttpClient            *http.Client
	ClaimsContextKeyName  ClaimsContextKeyName
	ErrorHandler          ErrorHandler
}

func NewOpaque(setters ...OpaqueOption) *OpaqueOptions {
	opts := &OpaqueOptions{
		DiscoveryFetchTimeout: 5 * time.Second,
		UserinfoFetchTimeout:  5 * time.Second,
		TokenTTL:              10 * time.Second,
		HttpClient:            http.DefaultClient,
		ClaimsContextKeyName:  DefaultClaimsContextKeyName,
	}

	for _, setter := range setters {
		setter(opts)
	}

	return opts
}

type OpaqueOption func(*OpaqueOptions)

// WithOpaqueIssuer sets the Issuer parameter for OpaqueOptions.
// Issuer is the authority that issues the tokens
func WithOpaqueIssuer(opt string) OpaqueOption {
	return func(opts *OpaqueOptions) {
		opts.Issuer = opt
	}
}

// WithOpaqueDiscoveryUri sets the DiscoveryUri parameter for an OpaqueOptions pointer.
// DiscoveryUri is where the `userinfo_endpoint` will be grabbed
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

// WithOpaqueUserinfoUri sets the Issuer parameter for an Options pointer.
// UserinfoUri is where the opaque access token will be sent to extract the user claims
// Defaults to empty string
func WithOpaqueUserinfoUri(opt string) OpaqueOption {
	return func(opts *OpaqueOptions) {
		opts.UserinfoUri = opt
	}
}

// WithOpaqueUserinfoFetchTimeout sets the UserinfoFetchTimeout parameter for an OpaqueOptions pointer.
// UserinfoFetchTimeout sets the context timeout when extracting the user claims
// Defaults to 5 seconds
func WithOpaqueUserinfoFetchTimeout(opt time.Duration) OpaqueOption {
	return func(opts *OpaqueOptions) {
		opts.UserinfoFetchTimeout = opt
	}
}

// WithOpaqueTokenTTL sets the TokenTTL parameter for an OpaqueOptions pointer.
// TokenTTL sets how long a token should be cached in the middleware until it verifies it again
// Defaults to 10 seconds
func WithOpaqueTokenTTL(opt time.Duration) OpaqueOption {
	return func(opts *OpaqueOptions) {
		opts.TokenTTL = opt
	}
}

// WithOpaqueRequiredClaims sets the RequiredClaims parameter for an OpaqueOptions pointer.
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
//
//	map[string]interface{}{
//		"foo": "bar",
//		"bar": 1337,
//		"baz": []string{"bar"},
//		"oof": []map[string]string{
//			{"bar": "baz"},
//		},
//	},
//
// ```
func WithOpaqueRequiredClaims(opt map[string]interface{}) OpaqueOption {
	return func(opts *OpaqueOptions) {
		opts.RequiredClaims = opt
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

// WithClaimsContextKeyName sets the ClaimsContextKeyName parameter for an OpaqueOptions pointer.
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

// WithErrorHandler sets the ErrorHandler parameter for an OpaqueOptions pointer.
// You can pass a function to run custom logic on errors, logging as an example.
// Defaults to nil
func WithOpaqueErrorHandler(opt ErrorHandler) OpaqueOption {
	return func(opts *OpaqueOptions) {
		opts.ErrorHandler = opt
	}
}
