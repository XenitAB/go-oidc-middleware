package options

// TokenStringOptions handles the settings for how to extract the token from a request.
type TokenStringOptions struct {
	// HeaderName is the name of the header.
	// Default: "Authorization"
	HeaderName string

	// TokenPrefix defines the prefix that should be trimmed from the header value
	// to extract the token.
	// Default: "Bearer "
	TokenPrefix string

	// ListSeparator defines if the value of the header is a list or not.
	// The value will be split (up to 20 slices) by the ListSeparator.
	// Default disabled: ""
	ListSeparator string
}

func NewTokenString(setters ...TokenStringOption) *TokenStringOptions {
	opts := &TokenStringOptions{
		HeaderName:    "Authorization",
		TokenPrefix:   "Bearer ",
		ListSeparator: "",
	}

	for _, setter := range setters {
		setter(opts)
	}

	return opts
}

// TokenStringOption returns a function that modifies a TokenStringOptions pointer.
type TokenStringOption func(*TokenStringOptions)

// WithTokenStringHeaderName sets the HeaderName parameter for a TokenStringOptions pointer.
func WithTokenStringHeaderName(opt string) TokenStringOption {
	return func(opts *TokenStringOptions) {
		opts.HeaderName = opt
	}
}

// WithTokenStringTokenPrefix sets the TokenPrefix parameter for a TokenStringOptions pointer.
func WithTokenStringTokenPrefix(opt string) TokenStringOption {
	return func(opts *TokenStringOptions) {
		opts.TokenPrefix = opt
	}
}

// WithTokenStringListSeparator sets the ListSeparator parameter for a TokenStringOptions pointer.
func WithTokenStringListSeparator(opt string) TokenStringOption {
	return func(opts *TokenStringOptions) {
		opts.ListSeparator = opt
	}
}
