package oidctoken

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/xenitab/go-oidc-middleware/optest"
	"github.com/xenitab/go-oidc-middleware/options"
)

type MyToken struct {
	result bool
}

func TestTokenSuccessfulValidation(t *testing.T) {
	op := optest.NewTesting(t)
	defer op.Close(t)

	th, err := New(
		func(token *MyToken) error {
			token.result = true
			return nil
		},
		options.WithIssuer(op.GetURL(t)),
	)
	require.NoError(t, err)
	ctx := context.Background()
	token := op.GetToken(t).AccessToken
	claims, err := th.ParseToken(ctx, token)
	require.NoError(t, err)
	require.True(t, claims.result)
}

func TestFailedInstantiation(t *testing.T) {
	_, err := New(
		func(token *MyToken) error {
			token.result = true
			return nil
		},
	)
	require.ErrorContains(t, err, "issuer is empty")
}

func TestTokenFailedParse(t *testing.T) {
	op := optest.NewTesting(t)
	defer op.Close(t)

	th, err := New(
		func(token *MyToken) error {
			token.result = true
			return nil
		},
		options.WithIssuer(op.GetURL(t)),
	)
	require.NoError(t, err)
	ctx := context.Background()
	_, err = th.ParseToken(ctx, "bork!")
	require.ErrorContains(t, err, "invalid")
}

func TestValidationFails(t *testing.T) {
	op := optest.NewTesting(t)
	defer op.Close(t)

	th, err := New(
		func(token *MyToken) error {
			return errors.New("boom!")
		},
		options.WithIssuer(op.GetURL(t)),
	)
	require.NoError(t, err)
	ctx := context.Background()
	token := op.GetToken(t).AccessToken
	_, err = th.ParseToken(ctx, token)
	require.ErrorContains(t, err, "boom!")
}
