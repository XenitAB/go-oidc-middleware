package oidc

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/xenitab/go-oidc-middleware/options"
)

func TestGetTokenStringFromRequest(t *testing.T) {
	cases := []struct {
		testDescription       string
		headers               http.Header
		options               [][]options.TokenStringOption
		expectedToken         string
		expectedErrorContains string
	}{
		{
			testDescription:       "empty headers",
			headers:               make(http.Header),
			expectedToken:         "",
			expectedErrorContains: "Authorization header empty",
		},
		{
			testDescription: "Authorization header empty",
			headers: http.Header{
				"Authorization": {},
			},
			expectedToken:         "",
			expectedErrorContains: "Authorization header empty",
		},
		{
			testDescription: "Authorization header empty string",
			headers: http.Header{
				"Authorization": {""},
			},
			expectedToken:         "",
			expectedErrorContains: "Authorization header empty",
		},
		{
			testDescription: "Authorization header first empty string",
			headers: http.Header{
				"Authorization": {"", "Bearer foobar"},
			},
			expectedToken:         "",
			expectedErrorContains: "Authorization header empty",
		},
		{
			testDescription: "Authorization header single component",
			headers: http.Header{
				"Authorization": {"foo"},
			},
			expectedToken:         "",
			expectedErrorContains: "Authorization header components not 2 but: 1",
		},
		{
			testDescription: "Authorization header three component",
			headers: http.Header{
				"Authorization": {"foo bar baz"},
			},
			expectedToken:         "",
			expectedErrorContains: "Authorization header components not 2 but: 3",
		},
		{
			testDescription: "Authorization header two components",
			headers: http.Header{
				"Authorization": {"foo bar"},
			},
			expectedToken:         "",
			expectedErrorContains: "Authorization headers first component not Bearer",
		},
		{
			testDescription: "Authorization header two components",
			headers: http.Header{
				"Authorization": {"Bearer foobar"},
			},
			expectedToken:         "foobar",
			expectedErrorContains: "",
		},
		{
			testDescription: "test options",
			headers: http.Header{
				"Foo": {"Bar_baz"},
			},
			options: [][]options.TokenStringOption{
				{
					options.WithTokenStringHeaderName("Foo"),
					options.WithTokenStringDelimiter("_"),
					options.WithTokenStringTokenType("Bar"),
				},
			},
			expectedToken:         "baz",
			expectedErrorContains: "",
		},
		{
			testDescription: "test multiple options second header",
			headers: http.Header{
				"Too": {"Lar_kaz"},
				"Foo": {"Bar_baz"},
			},
			options: [][]options.TokenStringOption{
				{
					options.WithTokenStringHeaderName("Foo"),
					options.WithTokenStringDelimiter("_"),
					options.WithTokenStringTokenType("Bar"),
				},
				{
					options.WithTokenStringHeaderName("Too"),
					options.WithTokenStringDelimiter("_"),
					options.WithTokenStringTokenType("Lar"),
				},
			},
			expectedToken:         "baz",
			expectedErrorContains: "",
		},
		{
			testDescription: "test multiple options first header",
			headers: http.Header{
				"Too": {"Lar_kaz"},
				"Foo": {"Bar_baz"},
			},
			options: [][]options.TokenStringOption{
				{
					options.WithTokenStringHeaderName("Too"),
					options.WithTokenStringDelimiter("_"),
					options.WithTokenStringTokenType("Lar"),
				},
				{
					options.WithTokenStringHeaderName("Foo"),
					options.WithTokenStringDelimiter("_"),
					options.WithTokenStringTokenType("Bar"),
				},
			},
			expectedToken:         "kaz",
			expectedErrorContains: "",
		},
		{
			testDescription: "websockets",
			headers: http.Header{
				"Sec-WebSocket-Protocol": {"Foo.bar,Too.lar,Koo.nar"},
			},
			options: [][]options.TokenStringOption{
				{
					options.WithTokenStringHeaderName("Sec-WebSocket-Protocol"),
					options.WithTokenStringDelimiter("."),
					options.WithTokenStringTokenType("Too"),
					options.WithHeaderValueSeparator(","),
				},
			},
			expectedToken:         "lar",
			expectedErrorContains: "",
		},
	}

	for i, c := range cases {
		t.Logf("Test iteration %d: %s", i, c.testDescription)

		req := httptest.NewRequest(http.MethodGet, "/", nil)

		for k, v := range c.headers {
			req.Header[k] = v
		}

		token, err := GetTokenString(req.Header.Get, c.options)
		require.Equal(t, c.expectedToken, token)

		if c.expectedErrorContains == "" {
			require.NoError(t, err)
		} else {
			require.Error(t, err)
			require.Contains(t, err.Error(), c.expectedErrorContains)
		}
	}
}
