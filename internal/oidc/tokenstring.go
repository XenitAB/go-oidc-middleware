package oidc

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/xenitab/go-oidc-middleware/options"
)

// GetTokenStringFromRequest extracts a token string from an http request.
func GetTokenStringFromRequest(r *http.Request, setters ...options.TokenStringOption) (string, error) {
	opts := options.NewTokenString(setters...)

	authz := r.Header.Get(opts.HeaderName)
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
