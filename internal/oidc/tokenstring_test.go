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
		headers               map[string][]string
		options               [][]options.TokenStringOption
		expectedToken         string
		expectedErrorContains string
	}{
		{
			testDescription:       "empty headers",
			headers:               make(map[string][]string),
			expectedToken:         "",
			expectedErrorContains: "Authorization header empty",
		},
		{
			testDescription: "Authorization header empty",
			headers: map[string][]string{
				"Authorization": {},
			},
			expectedToken:         "",
			expectedErrorContains: "Authorization header empty",
		},
		{
			testDescription: "Authorization header empty string",
			headers: map[string][]string{
				"Authorization": {""},
			},
			expectedToken:         "",
			expectedErrorContains: "Authorization header empty",
		},
		{
			testDescription: "Authorization header first empty string",
			headers: map[string][]string{
				"Authorization": {"", "Bearer foobar"},
			},
			expectedToken:         "",
			expectedErrorContains: "Authorization header empty",
		},
		{
			testDescription: "Authorization header single component",
			headers: map[string][]string{
				"Authorization": {"foo"},
			},
			expectedToken:         "",
			expectedErrorContains: "Authorization header does not begin with: Bearer ",
		},
		{
			testDescription: "Authorization header three component",
			headers: map[string][]string{
				"Authorization": {"foo bar baz"},
			},
			expectedToken:         "",
			expectedErrorContains: "Authorization header does not begin with: Bearer ",
		},
		{
			testDescription: "Authorization header two components",
			headers: map[string][]string{
				"Authorization": {"foo bar"},
			},
			expectedToken:         "",
			expectedErrorContains: "Authorization header does not begin with: Bearer ",
		},
		{
			testDescription: "Authorization header two components",
			headers: map[string][]string{
				"Authorization": {"Bearer foobar"},
			},
			expectedToken:         "foobar",
			expectedErrorContains: "",
		},
		{
			testDescription: "test options",
			headers: map[string][]string{
				"Foo": {"Bar_baz"},
			},
			options: [][]options.TokenStringOption{
				{
					options.WithTokenStringHeaderName("Foo"),
					options.WithTokenStringTokenPrefix("Bar_"),
				},
			},
			expectedToken:         "baz",
			expectedErrorContains: "",
		},
		{
			testDescription: "test multiple options second header",
			headers: map[string][]string{
				"Too": {"Lar_kaz"},
				"Foo": {"Bar_baz"},
			},
			options: [][]options.TokenStringOption{
				{
					options.WithTokenStringHeaderName("Foo"),
					options.WithTokenStringTokenPrefix("Bar_"),
				},
				{
					options.WithTokenStringHeaderName("Too"),
					options.WithTokenStringTokenPrefix("Lar_"),
				},
			},
			expectedToken:         "baz",
			expectedErrorContains: "",
		},
		{
			testDescription: "test multiple options first header",
			headers: map[string][]string{
				"Too": {"Lar_kaz"},
				"Foo": {"Bar_baz"},
			},
			options: [][]options.TokenStringOption{
				{
					options.WithTokenStringHeaderName("Too"),
					options.WithTokenStringTokenPrefix("Lar_"),
				},
				{
					options.WithTokenStringHeaderName("Foo"),
					options.WithTokenStringTokenPrefix("Bar_"),
				},
			},
			expectedToken:         "kaz",
			expectedErrorContains: "",
		},
		{
			testDescription: "websockets",
			headers: map[string][]string{
				"Sec-WebSocket-Protocol": {"Foo.bar,Too.lar,Koo.nar"},
			},
			options: [][]options.TokenStringOption{
				{
					options.WithTokenStringHeaderName("Sec-WebSocket-Protocol"),
					options.WithTokenStringTokenPrefix("Too."),
					options.WithTokenStringListSeparator(","),
				},
			},
			expectedToken:         "lar",
			expectedErrorContains: "",
		},
		{
			testDescription: "authorization first and and then websockets",
			headers: map[string][]string{
				"Authorization":          {"Bearer foobar"},
				"Sec-WebSocket-Protocol": {"Foo.bar,Too.lar,Koo.nar"},
			},
			options: [][]options.TokenStringOption{
				{
					options.WithTokenStringHeaderName("Authorization"),
					options.WithTokenStringTokenPrefix("Bearer "),
				},
				{
					options.WithTokenStringHeaderName("Sec-WebSocket-Protocol"),
					options.WithTokenStringTokenPrefix("Too."),
					options.WithTokenStringListSeparator(","),
				},
			},
			expectedToken:         "foobar",
			expectedErrorContains: "",
		},
		{
			testDescription: "websockets first and then authorization",
			headers: map[string][]string{
				"Authorization":          {"Bearer foobar"},
				"Sec-WebSocket-Protocol": {"Foo.bar,Too.lar,Koo.nar"},
			},
			options: [][]options.TokenStringOption{
				{
					options.WithTokenStringHeaderName("Sec-WebSocket-Protocol"),
					options.WithTokenStringTokenPrefix("Too."),
					options.WithTokenStringListSeparator(","),
				},
				{
					options.WithTokenStringHeaderName("Authorization"),
					options.WithTokenStringTokenPrefix("Bearer "),
				},
			},
			expectedToken:         "lar",
			expectedErrorContains: "",
		},
		{
			testDescription: "websockets first and then authorization, but without a token in websockets",
			headers: map[string][]string{
				"Authorization":          {"Bearer foobar"},
				"Sec-WebSocket-Protocol": {"Foo.bar"},
			},
			options: [][]options.TokenStringOption{
				{
					options.WithTokenStringHeaderName("Sec-WebSocket-Protocol"),
					options.WithTokenStringTokenPrefix("Too."),
					options.WithTokenStringListSeparator(","),
				},
				{
					options.WithTokenStringHeaderName("Authorization"),
					options.WithTokenStringTokenPrefix("Bearer "),
				},
			},
			expectedToken:         "foobar",
			expectedErrorContains: "",
		},
	}

	for i, c := range cases {
		t.Logf("Test iteration %d: %s", i, c.testDescription)

		req := httptest.NewRequest(http.MethodGet, "/", nil)

		for k, values := range c.headers {
			for _, v := range values {
				req.Header.Add(k, v)
			}
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
