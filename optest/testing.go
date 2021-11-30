package optest

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// OPTesting is a wrapper for the OPTest to be used in tests.
type OPTesting struct {
	op *OPTest
}

// NewTesting sets up a new test OpenID Provider.
func NewTesting(tb testing.TB, setters ...Option) *OPTesting {
	tb.Helper()

	op, err := New(setters...)
	require.NoError(tb, err)

	return &OPTesting{
		op,
	}
}

// Close shuts down the http server.
func (o *OPTesting) Close(tb testing.TB) {
	tb.Helper()

	o.op.Close()
}

// GetURL returns the current URL of the http server.
func (o *OPTesting) GetURL(tb testing.TB) string {
	tb.Helper()

	return o.op.GetURL()
}

// RotateKeys rotates the jwks keys.
func (o *OPTesting) RotateKeys(tb testing.TB) {
	tb.Helper()

	err := o.op.RotateKeys()
	require.NoError(tb, err)
}

// GetToken returns a TokenResponse with an id_token and an access_token.
func (o *OPTesting) GetToken(tb testing.TB) *TokenResponse {
	tb.Helper()

	tokenResponse, err := o.op.GetToken()
	require.NoError(tb, err)

	return tokenResponse
}
