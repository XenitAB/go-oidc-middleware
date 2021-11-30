package optest

import (
	"testing"

	"github.com/stretchr/testify/require"
)

type OPTesting struct {
	op *OPTest
}

func NewTesting(tb testing.TB, setters ...Option) *OPTesting {
	tb.Helper()

	op, err := New(setters...)
	require.NoError(tb, err)

	return &OPTesting{
		op,
	}
}

func (o *OPTesting) Close(tb testing.TB) {
	tb.Helper()

	o.op.Close()
}

func (o *OPTesting) GetURL(tb testing.TB) string {
	tb.Helper()

	return o.op.GetURL()
}

func (o *OPTesting) RotateKeys(tb testing.TB) {
	tb.Helper()

	err := o.op.RotateKeys()
	require.NoError(tb, err)
}

func (o *OPTesting) GetToken(tb testing.TB) *TokenResponse {
	tb.Helper()

	tokenResponse, err := o.op.GetToken()
	require.NoError(tb, err)

	return tokenResponse
}
