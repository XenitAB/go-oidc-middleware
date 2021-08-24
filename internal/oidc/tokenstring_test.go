package oidc

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/xenitab/go-oidc-middleware/options"
)

func TestGetTokenString(t *testing.T) {
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
			testDescription: "websockets",
			headers: map[string][]string{
				"Sec-WebSocket-Protocol": {"Foo.bar,Too.lar,Koo.nar"},
			},
			options: [][]options.TokenStringOption{
				{
					options.WithTokenStringHeaderName("Sec-WebSocket-Protocol"),
					options.WithTokenStringTokenPrefix("Baz."),
					options.WithTokenStringListSeparator(","),
				},
			},
			expectedToken:         "",
			expectedErrorContains: "no token found in list",
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
		{
			testDescription: "one header with PostExtractionFn",
			headers: map[string][]string{
				"Authorization": {"Bearer Zm9vYmFy"},
			},
			options: [][]options.TokenStringOption{
				{
					options.WithTokenStringHeaderName("Authorization"),
					options.WithTokenStringTokenPrefix("Bearer "),
					options.WithTokenStringPostExtractionFn(func(s string) (string, error) {
						bytes, err := base64.StdEncoding.DecodeString(s)
						if err != nil {
							return "", err
						}

						return string(bytes), nil
					}),
				},
			},
			expectedToken:         "foobar",
			expectedErrorContains: "",
		},
		{
			testDescription: "two headers with PostExtractionFn error",
			headers: map[string][]string{
				"Foo":           {"Bar_baz"},
				"Authorization": {"Bearer foobar"},
			},
			options: [][]options.TokenStringOption{
				{
					options.WithTokenStringHeaderName("Authorization"),
					options.WithTokenStringTokenPrefix("Bearer "),
					options.WithTokenStringPostExtractionFn(func(s string) (string, error) {
						return "", fmt.Errorf("fake error")
					}),
				},
				{
					options.WithTokenStringHeaderName("Foo"),
					options.WithTokenStringTokenPrefix("Bar_"),
				},
			},
			expectedToken:         "baz",
			expectedErrorContains: "",
		},
		{
			testDescription: "one header with PostExtractionFn error",
			headers: map[string][]string{
				"Authorization": {"Bearer foobar"},
			},
			options: [][]options.TokenStringOption{
				{
					options.WithTokenStringHeaderName("Authorization"),
					options.WithTokenStringTokenPrefix("Bearer "),
					options.WithTokenStringPostExtractionFn(func(s string) (string, error) {
						return "", fmt.Errorf("fake error")
					}),
				},
			},
			expectedToken:         "",
			expectedErrorContains: "fake error",
		},
		{
			testDescription: "one header with PostExtractionFn returns empty string",
			headers: map[string][]string{
				"Authorization": {"Bearer foobar"},
			},
			options: [][]options.TokenStringOption{
				{
					options.WithTokenStringHeaderName("Authorization"),
					options.WithTokenStringTokenPrefix("Bearer "),
					options.WithTokenStringPostExtractionFn(func(s string) (string, error) {
						return "", nil
					}),
				},
			},
			expectedToken:         "",
			expectedErrorContains: "post extraction function returned an empty token string",
		},
		{
			testDescription: "kubernetes websocket test",
			headers: map[string][]string{
				"Sec-WebSocket-Protocol": {"foo,bar,base64url.bearer.authorization.k8s.io.Rm9vQmFyQmF6,baz,test"},
			},
			options: [][]options.TokenStringOption{
				{
					options.WithTokenStringHeaderName("Authorization"),
					options.WithTokenStringTokenPrefix("Bearer "),
				},
				{
					options.WithTokenStringHeaderName("Sec-WebSocket-Protocol"),
					options.WithTokenStringTokenPrefix("base64url.bearer.authorization.k8s.io."),
					options.WithTokenStringListSeparator(","),
					options.WithTokenStringPostExtractionFn(func(s string) (string, error) {
						bytes, err := base64.RawStdEncoding.DecodeString(s)
						if err != nil {
							return "", err
						}

						return string(bytes), nil
					}),
				},
			},
			expectedToken:         "FooBarBaz",
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

func TestGetTokenFromString(t *testing.T) {
	cases := []struct {
		testDescription       string
		options               []options.TokenStringOption
		headerValue           string
		expectedToken         string
		expectedErrorContains string
	}{
		{
			testDescription:       "default working",
			headerValue:           "Bearer foobar",
			expectedToken:         "foobar",
			expectedErrorContains: "",
		},
		{
			testDescription:       "empty header",
			headerValue:           "",
			expectedToken:         "",
			expectedErrorContains: "header empty",
		},
		{
			testDescription:       "header doesn't begin with 'Bearer '",
			headerValue:           "Foo_bar",
			expectedToken:         "",
			expectedErrorContains: "header does not begin with",
		},
		{
			testDescription:       "header contains 'Bearer ' but nothing else",
			headerValue:           "Bearer ",
			expectedToken:         "",
			expectedErrorContains: "header empty after prefix is trimmed",
		},
	}

	for i, c := range cases {
		t.Logf("Test iteration %d: %s", i, c.testDescription)

		opts := options.NewTokenString(c.options...)

		token, err := getTokenFromString(c.headerValue, opts)
		require.Equal(t, c.expectedToken, token)

		if c.expectedErrorContains == "" {
			require.NoError(t, err)
		} else {
			require.Error(t, err)
			require.Contains(t, err.Error(), c.expectedErrorContains)
		}
	}
}
