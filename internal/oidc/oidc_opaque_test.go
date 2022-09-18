package oidc

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/xenitab/go-oidc-middleware/optest"
	"github.com/xenitab/go-oidc-middleware/options"
)

func TestNewOpaqueHandler(t *testing.T) {
	op := optest.NewTesting(t, optest.WithOpaqueAccessTokens())
	defer op.Close(t)

	handler, err := NewOpaqueHandler[optest.TestUser](
		options.WithOpaqueIssuer(op.GetURL(t)),
	)
	require.NoError(t, err)

	opaqueToken := op.GetToken(t)
	claims, err := handler.ParseToken(context.Background(), opaqueToken.AccessToken)
	require.NoError(t, err)
	subject := claims.Subject
	require.Equal(t, "test", subject)
}

func TestNewOpaqueHandlerWithRequiredClaims(t *testing.T) {
	op := optest.NewTesting(t, optest.WithOpaqueAccessTokens())
	defer op.Close(t)

	{
		handler, err := NewOpaqueHandler[optest.TestUser](
			options.WithOpaqueIssuer(op.GetURL(t)),
			options.WithOpaqueRequiredClaims(map[string]interface{}{
				"locale": "en-US",
			}),
		)
		require.NoError(t, err)

		opaqueToken := op.GetToken(t)
		claims, err := handler.ParseToken(context.Background(), opaqueToken.AccessToken)
		require.NoError(t, err)
		subject := claims.Subject
		require.Equal(t, "test", subject)
	}

	{
		handler, err := NewOpaqueHandler[optest.TestUser](
			options.WithOpaqueIssuer(op.GetURL(t)),
			options.WithOpaqueRequiredClaims(map[string]interface{}{
				"locale": "sv-SE",
			}),
		)
		require.NoError(t, err)

		opaqueToken := op.GetToken(t)
		_, err = handler.ParseToken(context.Background(), opaqueToken.AccessToken)
		require.ErrorContains(t, err, "unable to validate required claims: claim \"locale\"")
	}
}
