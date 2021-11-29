package optest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"sync"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
)

type jwksHandler struct {
	sync.RWMutex
	privateKeys []jwk.Key
	publicKeys  []jwk.Key
}

func newJwksHandler() (*jwksHandler, error) {
	h := &jwksHandler{
		privateKeys: []jwk.Key{},
		publicKeys:  []jwk.Key{},
	}

	err := h.addNewKey()
	if err != nil {
		return nil, err
	}

	return h, nil
}

func (h *jwksHandler) addNewKey() error {
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		fmt.Printf("failed to generate new ECDSA privatre key: %s\n", err)
		return err
	}

	key, err := jwk.New(ecdsaKey)
	if err != nil {
		return err
	}

	if _, ok := key.(jwk.ECDSAPrivateKey); !ok {
		return fmt.Errorf("expected jwk.ECDSAPrivateKey, got %T", key)
	}

	thumbprint, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		return err
	}

	keyID := fmt.Sprintf("%x", thumbprint)
	err = key.Set(jwk.KeyIDKey, keyID)
	if err != nil {
		return err
	}

	pubKey, err := jwk.New(ecdsaKey.PublicKey)
	if err != nil {
		return err
	}

	if _, ok := pubKey.(jwk.ECDSAPublicKey); !ok {
		return fmt.Errorf("expected jwk.ECDSAPublicKey, got %T", key)
	}

	err = pubKey.Set(jwk.KeyIDKey, keyID)
	if err != nil {
		return err
	}

	err = pubKey.Set(jwk.AlgorithmKey, jwa.ES384)
	if err != nil {
		return err
	}

	h.Lock()

	h.privateKeys = append(h.privateKeys, key)
	h.publicKeys = append(h.publicKeys, pubKey)

	h.Unlock()

	return nil
}

func (h *jwksHandler) removeOldestKey() error {
	h.RLock()
	privKeysLen := len(h.privateKeys)
	pubKeysLen := len(h.publicKeys)
	h.RUnlock()

	if privKeysLen != pubKeysLen {
		return fmt.Errorf("private keys length (%d) isn't equal private keys length (%d)", privKeysLen, pubKeysLen)
	}

	if privKeysLen <= 1 {
		return fmt.Errorf("keys length smaller or equal 1: %d", privKeysLen)
	}

	h.Lock()
	h.privateKeys = h.privateKeys[1:]
	h.publicKeys = h.publicKeys[1:]
	h.Unlock()

	return nil
}

func (h *jwksHandler) getPrivateKey() jwk.Key {
	h.RLock()

	lastKeyIndex := len(h.privateKeys) - 1
	privKey := h.privateKeys[lastKeyIndex]

	h.RUnlock()

	return privKey
}

func (h *jwksHandler) getPublicKey() jwk.Key {
	h.RLock()

	lastKeyIndex := len(h.publicKeys) - 1
	pubKey := h.publicKeys[lastKeyIndex]

	h.RUnlock()

	return pubKey
}

func (h *jwksHandler) getPublicKeySet() jwk.Set {
	keySet := jwk.NewSet()

	h.RLock()

	for _, pubKey := range h.publicKeys {
		keySet.Add(pubKey)
	}

	h.RUnlock()

	return keySet
}
