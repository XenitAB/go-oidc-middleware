package options

// TokenStringOptions handles the settings for how to extract the token from a request.
type TokenStringOptions struct {
	HeaderName       string
	TokenPrefix      string
	ListSeparator    string
	PostExtractionFn func(string) (string, error)
}

// NewTokenString takes TokenStringOption setters and returns
// a TokenStringOptions pointer.
// Mainly used by the internal functions and most likely not
// needed by any external application using this library.
func NewTokenString(setters ...TokenStringOption) *TokenStringOptions {
	opts := &TokenStringOptions{
		HeaderName:       "Authorization",
		TokenPrefix:      "Bearer ",
		ListSeparator:    "",
		PostExtractionFn: nil,
	}

	for _, setter := range setters {
		setter(opts)
	}

	return opts
}

// TokenStringOption returns a function that modifies a TokenStringOptions pointer.
type TokenStringOption func(*TokenStringOptions)

// WithTokenStringHeaderName sets the HeaderName parameter for a TokenStringOptions pointer.
// HeaderName is the name of the header.
// Default: "Authorization"
func WithTokenStringHeaderName(opt string) TokenStringOption {
	return func(opts *TokenStringOptions) {
		opts.HeaderName = opt
	}
}

// WithTokenStringTokenPrefix sets the TokenPrefix parameter for a TokenStringOptions pointer.
// TokenPrefix defines the prefix that should be trimmed from the header value
// to extract the token.
// Default: "Bearer "
func WithTokenStringTokenPrefix(opt string) TokenStringOption {
	return func(opts *TokenStringOptions) {
		opts.TokenPrefix = opt
	}
}

// WithTokenStringListSeparator sets the ListSeparator parameter for a TokenStringOptions pointer.
// ListSeparator defines if the value of the header is a list or not.
// The value will be split (up to 20 slices) by the ListSeparator.
// Default disabled: ""
func WithTokenStringListSeparator(opt string) TokenStringOption {
	return func(opts *TokenStringOptions) {
		opts.ListSeparator = opt
	}
}

// WithTokenStringPostExtractionFn sets the PostExtractionFn parameter for a TokenStringOptions pointer.
// PostExtractionFn will be run if not nil after a token has been successfully extracted.
// Default: nil
func WithTokenStringPostExtractionFn(opt func(string) (string, error)) TokenStringOption {
	return func(opts *TokenStringOptions) {
		opts.PostExtractionFn = opt
	}
}
