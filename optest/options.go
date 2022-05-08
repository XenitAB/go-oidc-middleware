package optest

import "time"

// Options is the configuration object for OPTest.
type Options struct {
	Issuer          string
	DefaultTestUser string
	TestUsers       map[string]TestUser
	TokenExpiration time.Duration
	AutoStart       bool
}

// Option is used to configure functional options for OPTest.
type Option func(*Options)

// WithIssuer configures the issuer claim for tokens and addresses in metadata.
// Defaults to the addr of the http server.
func WithIssuer(opt string) Option {
	return func(opts *Options) {
		opts.Issuer = opt
	}
}

// WithDefaultTestUser configures the default test user, needs to match one of the users provided in `WithTestUsers()`.
// Defaults to the addr of the http server.
func WithDefaultTestUser(opt string) Option {
	return func(opts *Options) {
		opts.DefaultTestUser = opt
	}
}

// WithTestUsers configures the users that can be used to issue tokens.
// Defaults to a single test user named `test`.
func WithTestUsers(opt map[string]TestUser) Option {
	return func(opts *Options) {
		opts.TestUsers = opt
	}
}

// WithTokenExpiration configures the expiration for tokens.
// Default: 1 hour (3600 seconds).
func WithTokenExpiration(opt time.Duration) Option {
	return func(opts *Options) {
		opts.TokenExpiration = opt
	}
}

// WithoutAutoStart disables the autostart of the http server.
// Default is AutoStart enabled.
func WithoutAutoStart() Option {
	return func(opts *Options) {
		opts.AutoStart = false
	}
}
