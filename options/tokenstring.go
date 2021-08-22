package options

// TokenStringOptions handles the settings for how to extract the token from a request.
type TokenStringOptions struct {
	// HeaderName is the name of the header.
	// Default: "Authorization"
	HeaderName string

	// HeaderValueSeparator defines if the header value is separated into an array and if so what the separator is
	// Default: ""
	// Example could be: `HeaderName = foo,Bearer token,bar` and in that case HeaderValueSeparator should be set to "," (comma)
	HeaderValueSeparator string

	// Delimiter is the delimiter between the token type and the token.
	// Default: " " (single space)
	Delimiter string

	// TokenType is the type of token that is sent.
	// Default: "Bearer"
	TokenType string
}

func NewTokenString(setters ...TokenStringOption) *TokenStringOptions {
	opts := &TokenStringOptions{
		HeaderName:           "Authorization",
		HeaderValueSeparator: "",
		Delimiter:            " ",
		TokenType:            "Bearer",
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

// WithHeaderValueSeparator sets the HeaderValueSeparator parameter for a TokenStringOptions pointer.
func WithHeaderValueSeparator(opt string) TokenStringOption {
	return func(opts *TokenStringOptions) {
		opts.HeaderValueSeparator = opt
	}
}

// WithTokenStringDelimiter sets the Delimiter parameter for a TokenStringOptions pointer.
func WithTokenStringDelimiter(opt string) TokenStringOption {
	return func(opts *TokenStringOptions) {
		opts.Delimiter = opt
	}
}

// WithTokenStringTokenType sets the TokenType for a TokenStringOptions pointer.
func WithTokenStringTokenType(opt string) TokenStringOption {
	return func(opts *TokenStringOptions) {
		opts.TokenType = opt
	}
}
