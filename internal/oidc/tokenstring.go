package oidc

import (
	"fmt"
	"strings"

	"github.com/xenitab/go-oidc-middleware/options"
)

type GetHeaderFn func(key string) string

const maxListSeparatorSlices = 20

// GetTokenString extracts a token string.
func GetTokenString(getHeaderFn GetHeaderFn, tokenStringOpts [][]options.TokenStringOption) (string, error) {
	optsList := tokenStringOpts
	if len(optsList) == 0 {
		optsList = append(optsList, []options.TokenStringOption{})
	}

	var err error
	for _, setters := range optsList {
		opts := options.NewTokenString(setters...)

		var tokenString string
		tokenString, err = getTokenString(getHeaderFn, opts)
		if err == nil && tokenString != "" {
			// if a PostExtractionFn is defined, pass the token to it
			if opts.PostExtractionFn != nil {
				tokenString, err = opts.PostExtractionFn(tokenString)
				if err != nil {
					// if the PostExtractionFn returns an error, continue the loop
					continue
				}

				if tokenString == "" {
					// if the PostExtractionFn returns an empty string, continue the loop
					err = fmt.Errorf("post extraction function returned an empty token string")
					continue
				}

				return tokenString, nil
			}

			return tokenString, nil
		}
	}

	return "", fmt.Errorf("unable to extract token: %w", err)
}

func getTokenString(getHeaderFn GetHeaderFn, opts *options.TokenStringOptions) (string, error) {
	headerValue := getHeaderFn(opts.HeaderName)
	if headerValue == "" {
		return "", fmt.Errorf("%s header empty", opts.HeaderName)
	}

	if opts.ListSeparator != "" && strings.Contains(headerValue, opts.ListSeparator) {
		headerValueList := strings.SplitN(headerValue, opts.ListSeparator, maxListSeparatorSlices)
		return getTokenFromList(headerValueList, opts)
	}

	return getTokenFromString(headerValue, opts)
}

func getTokenFromList(headerValueList []string, opts *options.TokenStringOptions) (string, error) {
	for _, headerValue := range headerValueList {
		tokenString, err := getTokenFromString(headerValue, opts)
		if err == nil && tokenString != "" {
			return tokenString, nil
		}
	}

	return "", fmt.Errorf("no token found in list")
}

func getTokenFromString(headerValue string, opts *options.TokenStringOptions) (string, error) {
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
