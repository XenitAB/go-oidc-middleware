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
		DiscoveryFetchTimeout:      1234 * time.Second,
		JwksUri:                    "foo",
		JwksFetchTimeout:           1234 * time.Second,
		JwksRateLimit:              1234,
		FallbackSignatureAlgorithm: "foo",
		AllowedTokenDrift:          1234 * time.Second,
		LazyLoadMetadata:           true,
		RequiredTokenType:          "foo",
		RequiredAudience:           "foo",
		DisableKeyID:               true,
		HttpClient: &http.Client{
			Timeout: 1234 * time.Second,
		},
		TokenString:          nil,
		ClaimsContextKeyName: ClaimsContextKeyName("foo"),
		ErrorHandler:         nil,
	}

	expectedFirstTokenString := &TokenStringOptions{
		HeaderName:    "foo",
		TokenPrefix:   "bar_",
		ListSeparator: ",",
	}

	expectedSecondTokenString := &TokenStringOptions{
		HeaderName:    "too",
		TokenPrefix:   "lar_",
		ListSeparator: "",
	}

	setters := []Option{
		WithIssuer("foo"),
		WithDiscoveryUri("foo"),
		WithDiscoveryFetchTimeout(1234 * time.Second),
		WithJwksUri("foo"),
		WithJwksFetchTimeout(1234 * time.Second),
		WithJwksRateLimit(1234),
		WithFallbackSignatureAlgorithm("foo"),
		WithAllowedTokenDrift(1234 * time.Second),
		WithLazyLoadMetadata(true),
		WithRequiredTokenType("foo"),
		WithRequiredAudience("foo"),
		WithDisableKeyID(true),
		WithHttpClient(&http.Client{
			Timeout: 1234 * time.Second,
		}),
		WithTokenString(
			WithTokenStringHeaderName("foo"),
			WithTokenStringTokenPrefix("bar_"),
			WithTokenStringListSeparator(","),
		),
		WithTokenString(
			WithTokenStringHeaderName("too"),
			WithTokenStringTokenPrefix("lar_"),
		),
		WithClaimsContextKeyName("foo"),
		WithErrorHandler(nil),
	}

	result := &Options{}

	for _, setter := range setters {
		setter(result)
	}

	resultFirstTokenString := &TokenStringOptions{}
	resultSecondTokenString := &TokenStringOptions{}

	for _, setter := range result.TokenString[0] {
		setter(resultFirstTokenString)
	}

	for _, setter := range result.TokenString[1] {
		setter(resultSecondTokenString)
	}

	// Needed or else expectedResult can't be compared to result
	result.TokenString = nil

	require.Equal(t, expectedResult, result)
	require.Equal(t, expectedFirstTokenString, resultFirstTokenString)
	require.Equal(t, expectedSecondTokenString, resultSecondTokenString)
}
