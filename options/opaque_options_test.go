package options

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestOpaqueOptions(t *testing.T) {
	expectedResult := &OpaqueOptions{
		Issuer:                "foo",
		DiscoveryUri:          "foo",
		DiscoveryFetchTimeout: 1234 * time.Second,
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

	setters := []OpaqueOption{
		WithOpaqueIssuer("foo"),
		WithOpaqueDiscoveryUri("foo"),
		WithOpaqueDiscoveryFetchTimeout(1234 * time.Second),
		WithOpaqueHttpClient(&http.Client{
			Timeout: 1234 * time.Second,
		}),
		WithOpaqueTokenString(
			WithTokenStringHeaderName("foo"),
			WithTokenStringTokenPrefix("bar_"),
			WithTokenStringListSeparator(","),
		),
		WithOpaqueTokenString(
			WithTokenStringHeaderName("too"),
			WithTokenStringTokenPrefix("lar_"),
		),
		WithOpaqueClaimsContextKeyName("foo"),
		WithOpaqueErrorHandler(nil),
	}

	result := &OpaqueOptions{}

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
