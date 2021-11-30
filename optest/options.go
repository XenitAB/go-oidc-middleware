package optest

import "time"

// Options is the configuration object for OPTest.
type Options struct {
	Issuer                 string
	Audience               string
	Subject                string
	Name                   string
	GivenName              string
	FamilyName             string
	Locale                 string
	Email                  string
	AccessTokenKeyType     string
	IdTokenKeyType         string
	TokenExpiration        time.Duration
	ExtraAccessTokenClaims map[string]interface{}
	ExtraIdTokenClaims     map[string]interface{}
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

// WithAudience sets the audience claim for issued tokens.
// Default: "test-client"
func WithAudience(opt string) Option {
	return func(opts *Options) {
		opts.Audience = opt
	}
}

// WithSubject configures the subject for tokens.
// Default: "test"
func WithSubject(opt string) Option {
	return func(opts *Options) {
		opts.Subject = opt
	}
}

// WithName configures the name claim in id_tokens.
// Default: Test Testersson
func WithName(opt string) Option {
	return func(opts *Options) {
		opts.Name = opt
	}
}

// WithGivenName configures the given_name claim in id_tokens.
// Default: Test
func WithGivenName(opt string) Option {
	return func(opts *Options) {
		opts.GivenName = opt
	}
}

// WithFamilyName configures the family_name claim in id_tokens.
// Default: Testersson
func WithFamilyName(opt string) Option {
	return func(opts *Options) {
		opts.FamilyName = opt
	}
}

// WithLocale configures the locale claim in id_tokens.
// Default: en-US
func WithLocale(opt string) Option {
	return func(opts *Options) {
		opts.Locale = opt
	}
}

// WithEmail configures the email claim in id_tokens.
// Default: test@testersson.com
func WithEmail(opt string) Option {
	return func(opts *Options) {
		opts.Email = opt
	}
}

// WithAccessTokenKeyType configures the access_token key type (header).
// Default: JWT+AT
func WithAccessTokenKeyType(opt string) Option {
	return func(opts *Options) {
		opts.AccessTokenKeyType = opt
	}
}

// WithIdTokenKeyType configures the id_token key type (header).
// Default: JWT
func WithIdTokenKeyType(opt string) Option {
	return func(opts *Options) {
		opts.IdTokenKeyType = opt
	}
}

// WithTokenExpiration configures the expiration for tokens.
// Default: 1 hour (3600 seconds)
func WithTokenExpiration(opt time.Duration) Option {
	return func(opts *Options) {
		opts.TokenExpiration = opt
	}
}

// WithExtraAccessTokenClaims configures extra claims for the access_token.
// Default: empty map[string]interface{}{}
func WithExtraAccessTokenClaims(opt map[string]interface{}) Option {
	return func(opts *Options) {
		opts.ExtraAccessTokenClaims = opt
	}
}

// WithExtraIdTokenClaims configures extra claims for the id_token.
// Default: empty map[string]interface{}{}
func WithExtraIdTokenClaims(opt map[string]interface{}) Option {
	return func(opts *Options) {
		opts.ExtraIdTokenClaims = opt
	}
}
