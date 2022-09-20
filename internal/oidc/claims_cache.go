package oidc

import (
	"sync"
	"time"
)

type cachedClaims[T any] struct {
	claims    T
	err       error
	expiresAt time.Time
}

type claimsCache[T any] struct {
	mu    sync.RWMutex
	cache map[string]cachedClaims[T]
	ttl   time.Duration
}

func newClaimsCache[T any](ttl time.Duration) *claimsCache[T] {
	cache := make(map[string]cachedClaims[T])
	return &claimsCache[T]{
		cache: cache,
		ttl:   ttl,
	}
}

func (c *claimsCache[T]) get(name string) (T, error, bool) {
	c.mu.RLock()
	token, ok := c.cache[name]
	c.mu.RUnlock()
	if !ok {
		return *new(T), nil, false
	}

	if time.Now().After(token.expiresAt) {
		c.mu.Lock()
		delete(c.cache, name)
		c.mu.Unlock()
		return *new(T), nil, false
	}

	return token.claims, token.err, true
}

func (c *claimsCache[T]) set(name string, claims T, err error) {
	c.mu.Lock()
	c.cache[name] = cachedClaims[T]{
		claims:    claims,
		err:       err,
		expiresAt: time.Now().Add(c.ttl),
	}
	c.mu.Unlock()
}
