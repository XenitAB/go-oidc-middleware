package oidc

import (
	"fmt"
	"strings"

	"github.com/xenitab/go-oidc-middleware/options"
)

type GetHeaderFn func(key string) string

const maxListSeparatorSlices = 20

// GetTokenString extracts a token string
func GetTokenString(getHeaderFn GetHeaderFn, tokenStringOpts [][]options.TokenStringOption) (string, error) {
	opts := tokenStringOpts
	if len(opts) == 0 {
		opts = append(opts, []options.TokenStringOption{})
	}

	var err error
	for _, setters := range opts {
		var tokenString string
		tokenString, err = getTokenString(getHeaderFn, setters...)
		if err == nil && tokenString != "" {
			return tokenString, nil
		}
	}

	return "", fmt.Errorf("unable to extract token: %w", err)
}

func getTokenString(getHeaderFn GetHeaderFn, setters ...options.TokenStringOption) (string, error) {
	opts := options.NewTokenString(setters...)

	headerValue := getHeaderFn(opts.HeaderName)
	if headerValue == "" {
		return "", fmt.Errorf("%s header empty", opts.HeaderName)
	}

	if opts.ListSeparator != "" && strings.Contains(headerValue, opts.ListSeparator) {
		headerValueList := strings.SplitN(headerValue, opts.ListSeparator, maxListSeparatorSlices)
		return getTokenFromList(headerValueList, setters...)
	}

	return getTokenFromString(headerValue, setters...)
}

func getTokenFromList(headerValueList []string, setters ...options.TokenStringOption) (string, error) {
	for _, headerValue := range headerValueList {
		tokenString, err := getTokenFromString(headerValue, setters...)
		if err == nil && tokenString != "" {
			return tokenString, nil
		}
	}

	return "", fmt.Errorf("no token found in list")
}

func getTokenFromString(headerValue string, setters ...options.TokenStringOption) (string, error) {
	opts := options.NewTokenString(setters...)

	if headerValue == "" {
		return "", fmt.Errorf("%s header empty", opts.HeaderName)
	}

	if !strings.HasPrefix(headerValue, opts.TokenPrefix) {
		return "", fmt.Errorf("%s header does not begin with: %s", opts.HeaderName, opts.TokenPrefix)
	}

	token := strings.TrimPrefix(headerValue, opts.TokenPrefix)

	if token == "" {
		return "", fmt.Errorf("%s header empty after prefix is trimmed", opts.HeaderName)
	}

	return token, nil
}
