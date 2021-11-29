package optest

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewJwksHandler(t *testing.T) {
	jwks, err := newJwksHandler()
	require.NoError(t, err)

	require.Equal(t, 1, len(jwks.privateKeys))
	require.Equal(t, 1, len(jwks.publicKeys))
}

func TestAddNewKey(t *testing.T) {
	jwks, err := newJwksHandler()
	require.NoError(t, err)

	err = jwks.addNewKey()
	require.NoError(t, err)

	require.Equal(t, 2, len(jwks.privateKeys))
	require.Equal(t, 2, len(jwks.publicKeys))
}

func TestRemoveOldestKey(t *testing.T) {
	jwks, err := newJwksHandler()
	require.NoError(t, err)

	err = jwks.removeOldestKey()
	require.Error(t, err)

	err = jwks.addNewKey()
	require.NoError(t, err)

	require.Equal(t, 2, len(jwks.privateKeys))
	require.Equal(t, 2, len(jwks.publicKeys))

	secondPrivKey := jwks.privateKeys[1]
	secondPubKey := jwks.publicKeys[1]

	err = jwks.removeOldestKey()
	require.NoError(t, err)

	require.Equal(t, secondPrivKey, jwks.privateKeys[0])
	require.Equal(t, secondPubKey, jwks.publicKeys[0])
}

func TestGetPrivateKey(t *testing.T) {
	jwks, err := newJwksHandler()
	require.NoError(t, err)

	require.Equal(t, jwks.privateKeys[0], jwks.getPrivateKey())

	err = jwks.addNewKey()
	require.NoError(t, err)

	require.Equal(t, jwks.privateKeys[1], jwks.getPrivateKey())

	err = jwks.removeOldestKey()
	require.NoError(t, err)

	require.Equal(t, jwks.privateKeys[0], jwks.getPrivateKey())
}

func TestGetPublicKey(t *testing.T) {
	jwks, err := newJwksHandler()
	require.NoError(t, err)

	require.Equal(t, jwks.publicKeys[0], jwks.getPublicKey())

	err = jwks.addNewKey()
	require.NoError(t, err)

	require.Equal(t, jwks.publicKeys[1], jwks.getPublicKey())

	err = jwks.removeOldestKey()
	require.NoError(t, err)

	require.Equal(t, jwks.publicKeys[0], jwks.getPublicKey())
}

func TestGetPublicKeySet(t *testing.T) {
	jwks, err := newJwksHandler()
	require.NoError(t, err)

	keySet := jwks.getPublicKeySet()
	key, ok := keySet.Get(0)
	require.True(t, ok)

	require.Equal(t, jwks.publicKeys[0], key)

	err = jwks.addNewKey()
	require.NoError(t, err)

	keySet = jwks.getPublicKeySet()
	firstKey, ok := keySet.Get(0)
	require.True(t, ok)

	secondKey, ok := keySet.Get(1)
	require.True(t, ok)

	require.Equal(t, jwks.publicKeys[0], firstKey)
	require.Equal(t, jwks.publicKeys[1], secondKey)

	err = jwks.removeOldestKey()
	require.NoError(t, err)

	keySet = jwks.getPublicKeySet()
	key, ok = keySet.Get(0)
	require.True(t, ok)

	require.Equal(t, jwks.publicKeys[0], key)

	_, ok = keySet.Get(1)
	require.False(t, ok)
}
