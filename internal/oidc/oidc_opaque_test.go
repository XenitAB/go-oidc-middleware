package oidc

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/xenitab/go-oidc-middleware/optest"
	"github.com/xenitab/go-oidc-middleware/options"
)

func TestNewOpaqueHandler(t *testing.T) {
	op := optest.NewTesting(t, optest.WithOpaqueAccessTokens())
	defer op.Close(t)

	handler, err := NewOpaqueHandler[optest.TestUser](
		options.WithOpaqueIssuer[optest.TestUser](op.GetURL(t)),
	)
	require.NoError(t, err)

	opaqueToken := op.GetToken(t)
	claims, err := handler.ParseToken(context.Background(), opaqueToken.AccessToken)
	require.NoError(t, err)
	subject := claims.Subject
	require.Equal(t, "test", subject)
}

func TestNewOpaqueHandlerWithClaimsValidator(t *testing.T) {
	op := optest.NewTesting(t, optest.WithOpaqueAccessTokens())
	defer op.Close(t)

	t.Run("claims validator passing", func(t *testing.T) {
		claimsValidator := func(ctx context.Context, claims optest.TestUser) error {
			if claims.Locale != "en-US" {
				return fmt.Errorf("expected 'en-US' for locale")
			}

			return nil
		}

		handler, err := NewOpaqueHandler(
			options.WithOpaqueIssuer[optest.TestUser](op.GetURL(t)),
			options.WithOpaqueClaimsValidator(claimsValidator),
		)
		require.NoError(t, err)

		opaqueToken := op.GetToken(t)
		claims, err := handler.ParseToken(context.Background(), opaqueToken.AccessToken)
		require.NoError(t, err)
		subject := claims.Subject
		require.Equal(t, "test", subject)
	})

	t.Run("claims validator failing", func(t *testing.T) {
		claimsValidator := func(ctx context.Context, claims optest.TestUser) error {
			if claims.Locale != "sv-SE" {
				return fmt.Errorf("expected 'sv-SE' for locale")
			}

			return nil
		}

		handler, err := NewOpaqueHandler(
			options.WithOpaqueIssuer[optest.TestUser](op.GetURL(t)),
			options.WithOpaqueClaimsValidator(claimsValidator),
		)
		require.NoError(t, err)

		opaqueToken := op.GetToken(t)
		_, err = handler.ParseToken(context.Background(), opaqueToken.AccessToken)
		require.ErrorContains(t, err, "expected 'sv-SE' for locale")
	})
}
