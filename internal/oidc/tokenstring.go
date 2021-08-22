package oidc

import (
	"fmt"
	"strings"

	"github.com/xenitab/go-oidc-middleware/options"
)

type GetHeaderFn func(key string) string

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

	authz := getHeaderFn(opts.HeaderName)
	if authz == "" {
		return "", fmt.Errorf("%s header empty", opts.HeaderName)
	}

	if opts.HeaderValueSeparator != "" {
		comp := strings.Split(authz, opts.HeaderValueSeparator)
		for _, v := range comp {
			tokenString, err := getTokenStringFromString(v, setters...)
			if err == nil && tokenString != "" {
				return tokenString, nil
			}
		}
	}

	return getTokenStringFromString(authz, setters...)
}

func getTokenStringFromString(authz string, setters ...options.TokenStringOption) (string, error) {
	opts := options.NewTokenString(setters...)

	if authz == "" {
		return "", fmt.Errorf("%s header empty", opts.HeaderName)
	}

	comp := strings.Split(authz, opts.Delimiter)
	if len(comp) != 2 {
		return "", fmt.Errorf("%s header components not 2 but: %d", opts.HeaderName, len(comp))
	}

	if comp[0] != opts.TokenType {
		return "", fmt.Errorf("%s headers first component not %s", opts.HeaderName, opts.TokenType)
	}

	return comp[1], nil
}
