package optest

import (
	"net/http"
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

// Start starts the http server if AutoStart was disabled.
func (o *OPTesting) Start(tb testing.TB) {
	tb.Helper()

	o.op.Start()
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

// GetRouter returns the router to be used by a http server.
func (o *OPTesting) GetRouter(tb testing.TB) *http.ServeMux {
	tb.Helper()

	return o.op.GetRouter()
}

// RotateKeys rotates the jwks keys.
func (o *OPTesting) RotateKeys(tb testing.TB) {
	tb.Helper()

	err := o.op.RotateKeys()
	require.NoError(tb, err)
}

// GetToken returns a TokenResponse with an id_token and an access_token for the default test user.
func (o *OPTesting) GetToken(tb testing.TB) *TokenResponse {
	tb.Helper()

	tokenResponse, err := o.op.GetToken()
	require.NoError(tb, err)

	return tokenResponse
}

// GetTokenByUser returns a TokenResponse with an id_token and an access_token for the specified user.
func (o *OPTesting) GetTokenByUser(tb testing.TB, userString string) *TokenResponse {
	tb.Helper()

	tokenResponse, err := o.op.GetTokenByUser(userString)
	require.NoError(tb, err)

	return tokenResponse
}
