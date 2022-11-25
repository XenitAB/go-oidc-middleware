package optest

import (
	"sync"
	"time"
)

type authorizationCache struct {
	code      string
	loginHint string
	nonce     string
	expires   time.Time
}

type authorizationCacheContainer struct {
	values map[string]authorizationCache
	mu     sync.RWMutex
	ttl    time.Duration
}

func newAuthorizationCacheContainer() *authorizationCacheContainer {
	return &authorizationCacheContainer{
		values: make(map[string]authorizationCache),
		ttl:    10 * time.Second,
	}
}

func (c *authorizationCacheContainer) set(code string, loginHint string, nonce string) {
	c.mu.Lock()
	expires := time.Now().Add(c.ttl)
	c.values[code] = authorizationCache{
		code,
		loginHint,
		nonce,
		expires,
	}
	for k := range c.values {
		if c.values[k].expires.Before(time.Now()) {
			delete(c.values, k)
		}
	}
	c.mu.Unlock()
}

func (c *authorizationCacheContainer) get(code string) (string, string, bool) {
	c.mu.Lock()
	for k := range c.values {
		if c.values[k].expires.Before(time.Now()) {
			delete(c.values, k)
		}
	}
	v, ok := c.values[code]
	if ok {
		delete(c.values, code)
	}
	c.mu.Unlock()
	return v.loginHint, v.nonce, ok
}
