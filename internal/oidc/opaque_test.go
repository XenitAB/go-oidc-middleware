package oidc

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/xenitab/go-oidc-middleware/optest"
	"github.com/xenitab/go-oidc-middleware/options"
)

func TestOpaqueHandler(t *testing.T) {
	op := optest.NewTesting(t,
		optest.WithOpaqueAccessTokens(),
	)
	defer op.Close(t)

	issuer := op.GetURL(t)
	h, err := NewOpaqueHandler[testClaims](nil,
		options.WithOpaqueIssuer(issuer),
	)

	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	token := op.GetToken(t)
	claims, err := h.ParseToken(ctx, token.AccessToken)
	require.NoError(t, err)

	sub, ok := claims["sub"]
	require.True(t, ok)
	require.Equal(t, "test", sub)
}
