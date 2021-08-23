package options

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestOptions(t *testing.T) {
	expectedResult := &Options{
		Issuer:                     "foo",
		DiscoveryUri:               "foo",
		JwksUri:                    "foo",
		JwksFetchTimeout:           1234 * time.Second,
		JwksRateLimit:              1234,
		FallbackSignatureAlgorithm: "foo",
		AllowedTokenDrift:          1234 * time.Second,
		LazyLoadJwks:               true,
		RequiredTokenType:          "foo",
		RequiredAudience:           "foo",
		RequiredClaims: map[string]interface{}{
			"foo": "bar",
		},
		DisableKeyID: true,
		HttpClient: &http.Client{
			Timeout: 1234 * time.Second,
		},
		TokenString:          nil,
		ClaimsContextKeyName: ClaimsContextKeyName("foo"),
	}

	expectedTokenString := &TokenStringOptions{
		HeaderName:    "foo",
		TokenPrefix:   "bar_",
		ListSeparator: ",",
	}

	setters := []Option{
		WithIssuer("foo"),
		WithDiscoveryUri("foo"),
		WithJwksUri("foo"),
		WithJwksFetchTimeout(1234 * time.Second),
		WithJwksRateLimit(1234),
		WithFallbackSignatureAlgorithm("foo"),
		WithAllowedTokenDrift(1234 * time.Second),
		WithLazyLoadJwks(true),
		WithRequiredTokenType("foo"),
		WithRequiredAudience("foo"),
		WithRequiredClaims(map[string]interface{}{
			"foo": "bar",
		}),
		WithDisableKeyID(true),
		WithHttpClient(&http.Client{
			Timeout: 1234 * time.Second,
		}),
		WithTokenString(
			WithTokenStringHeaderName("foo"),
			WithTokenStringTokenPrefix("bar_"),
			WithTokenStringListSeparator(","),
		),
		WithClaimsContextKeyName("foo"),
	}

	result := &Options{}

	for _, setter := range setters {
		setter(result)
	}

	resultTokenString := &TokenStringOptions{}

	for _, setter := range result.TokenString[0] {
		setter(resultTokenString)
	}

	// Needed or else expectedResult can't be compared to result
	result.TokenString = nil

	require.Equal(t, expectedResult, result)
	require.Equal(t, expectedTokenString, resultTokenString)
}
