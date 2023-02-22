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
	h, err := newOpaqueHandler[testClaims](nil,
		options.WithIssuer(issuer),
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

func TestOpaqueTokenCache(t *testing.T) {
	ttl := 50 * time.Millisecond
	cache := &opaqueTokenCache[string]{
		timeToLive: ttl,
		tokens:     map[string]opaqueToken[string]{},
	}

	cases := []struct {
		sleep   time.Duration
		expired bool
	}{
		{
			sleep:   ttl / 5,
			expired: false,
		},
		{
			sleep:   ttl / 5,
			expired: false,
		},
		{
			sleep:   ttl,
			expired: true,
		},
	}
	cache.set("foo", "bar")

	for _, c := range cases {
		time.Sleep(c.sleep)
		value, ok := cache.get("foo")
		if !c.expired {
			require.True(t, ok)
			require.Equal(t, "bar", value)
		} else {
			require.False(t, ok)
			require.Empty(t, value)
		}
	}
}
