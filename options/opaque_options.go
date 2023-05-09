package options

import (
	"time"
)

// OpaqueOptions defines the options for OIDC Middleware.
type OpaqueOptions struct {
	IntrospectionUri          string
	IntrospectionFetchTimeout time.Duration
	TokenCacheTimeToLive      time.Duration
}

// NewOpaque takes Option setters and returns an OpaqueOptions pointer.
// Mainly used by the internal functions and most likely not
// needed by any external application using this library.
func NewOpaque(setters ...OpaqueOption) *OpaqueOptions {
	opts := &OpaqueOptions{
		IntrospectionFetchTimeout: 5 * time.Second,
	}

	for _, setter := range setters {
		setter(opts)
	}

	return opts
}

// OpaqueOption returns a function that modifies an OpaqueOptions pointer.
type OpaqueOption func(*OpaqueOptions)

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
