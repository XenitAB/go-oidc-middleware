package options

import (
	"context"
	"net/http"
	"time"
)

// ClaimsValidator called by the middleware if not nil
type ClaimsValidator[T any] func(ctx context.Context, claims T) error

// OpaqueOptions defines the options for handling opaque tokens for OIDC Middleware
type OpaqueOptions[T any] struct {
	Issuer                string
	DiscoveryUri          string
	DiscoveryFetchTimeout time.Duration
	UserinfoUri           string
	UserinfoFetchTimeout  time.Duration
	TokenTTL              time.Duration
	HttpClient            *http.Client
	TokenString           [][]TokenStringOption
	ClaimsContextKeyName  ClaimsContextKeyName
	ErrorHandler          ErrorHandler
	ClaimsValidator       ClaimsValidator[T]
}

func NewOpaque[T any](setters ...OpaqueOption[T]) *OpaqueOptions[T] {
	opts := &OpaqueOptions[T]{
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

type OpaqueOption[T any] func(*OpaqueOptions[T])

// WithOpaqueIssuer sets the Issuer parameter for OpaqueOptions.
// Issuer is the authority that issues the tokens
func WithOpaqueIssuer[T any](opt string) OpaqueOption[T] {
	return func(opts *OpaqueOptions[T]) {
		opts.Issuer = opt
	}
}

// WithOpaqueDiscoveryUri sets the DiscoveryUri parameter for an OpaqueOptions pointer.
// DiscoveryUri is where the `userinfo_endpoint` will be grabbed
// Defaults to `fmt.Sprintf("%s/.well-known/openid-configuration", strings.TrimSuffix(issuer, "/"))`
func WithOpaqueDiscoveryUri[T any](opt string) OpaqueOption[T] {
	return func(opts *OpaqueOptions[T]) {
		opts.DiscoveryUri = opt
	}
}

// WithOpaqueDiscoveryFetchTimeout sets the DiscoveryFetchTimeout parameter for an Options pointer.
// DiscoveryFetchTimeout sets the context timeout when downloading the discovery metadata
// Defaults to 5 seconds
func WithOpaqueDiscoveryFetchTimeout[T any](opt time.Duration) OpaqueOption[T] {
	return func(opts *OpaqueOptions[T]) {
		opts.DiscoveryFetchTimeout = opt
	}
}

// WithOpaqueUserinfoUri sets the Issuer parameter for an Options pointer.
// UserinfoUri is where the opaque access token will be sent to extract the user claims
// Defaults to empty string
func WithOpaqueUserinfoUri[T any](opt string) OpaqueOption[T] {
	return func(opts *OpaqueOptions[T]) {
		opts.UserinfoUri = opt
	}
}

// WithOpaqueUserinfoFetchTimeout sets the UserinfoFetchTimeout parameter for an OpaqueOptions pointer.
// UserinfoFetchTimeout sets the context timeout when extracting the user claims
// Defaults to 5 seconds
func WithOpaqueUserinfoFetchTimeout[T any](opt time.Duration) OpaqueOption[T] {
	return func(opts *OpaqueOptions[T]) {
		opts.UserinfoFetchTimeout = opt
	}
}

// WithOpaqueTokenTTL sets the TokenTTL parameter for an OpaqueOptions pointer.
// TokenTTL sets how long a token should be cached in the middleware until it verifies it again
// Defaults to 10 seconds
func WithOpaqueTokenTTL[T any](opt time.Duration) OpaqueOption[T] {
	return func(opts *OpaqueOptions[T]) {
		opts.TokenTTL = opt
	}
}

// WithOpaqueHttpClient sets the HttpClient parameter for an OpaqueOptions pointer.
// HttpClient takes a *http.Client for external calls
// Defaults to http.DefaultClient
func WithOpaqueHttpClient[T any](opt *http.Client) OpaqueOption[T] {
	return func(opts *OpaqueOptions[T]) {
		opts.HttpClient = opt
	}
}

// WithOpaqueTokenString sets the TokenString parameter for an Options pointer.
// TokenString makes it possible to configure how the opaque token should be extracted from
// an http header.
// Defaults to: 'Authorization: Bearer token'
func WithOpaqueTokenString[T any](setters ...TokenStringOption) OpaqueOption[T] {
	var tokenString []TokenStringOption
	tokenString = append(tokenString, setters...)

	return func(opts *OpaqueOptions[T]) {
		opts.TokenString = append(opts.TokenString, tokenString)
	}
}

// WithClaimsContextKeyName sets the ClaimsContextKeyName parameter for an OpaqueOptions pointer.
// ClaimsContextKeyName is the name of key that will be used to pass claims using request context.
//
// Important note: If you change this using `options.WithClaimsContextKeyName("foo")`, then
// you also need to use it like this:
// `claims, ok := r.Context().Value[T any](options.ClaimsContextKeyName("foo")).(map[string]interface{})`
//
// Default: `options.DefaultClaimsContextKeyName`
// Used like this: “claims, ok := r.Context().Value[T any](options.DefaultClaimsContextKeyName).(map[string]interface{})“
//
// When used with gin, it is converted to normal string - by default:
// `claimsValue, found := c.Get("claims")`
func WithOpaqueClaimsContextKeyName[T any](opt string) OpaqueOption[T] {
	return func(opts *OpaqueOptions[T]) {
		opts.ClaimsContextKeyName = ClaimsContextKeyName(opt)
	}
}

// WithErrorHandler sets the ErrorHandler parameter for an OpaqueOptions pointer.
// You can pass a function to run custom logic on errors, logging as an example.
// Defaults to nil
func WithOpaqueErrorHandler[T any](opt ErrorHandler) OpaqueOption[T] {
	return func(opts *OpaqueOptions[T]) {
		opts.ErrorHandler = opt
	}
}

// WithOpaqueClaimsValidator sets the ClaimsValidator parameter for an OpaqueOptions pointer.
// You pass this function to validate if the claims are valid or not.
// Defaults to nil
func WithOpaqueClaimsValidator[T any](opt ClaimsValidator[T]) OpaqueOption[T] {
	return func(opts *OpaqueOptions[T]) {
		opts.ClaimsValidator = opt
	}
}
