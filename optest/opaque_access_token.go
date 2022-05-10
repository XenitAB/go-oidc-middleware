package optest

import (
	"sync"
	"time"
)

type opaqueAccesToken struct {
	jwtAccessToken string
	expires        time.Time
}

type opaqueAccessTokenContainer struct {
	values map[string]opaqueAccesToken
	mu     sync.RWMutex
}

func newOpaqueAccessTokenContainer() *opaqueAccessTokenContainer {
	return &opaqueAccessTokenContainer{
		values: make(map[string]opaqueAccesToken),
	}
}

func (c *opaqueAccessTokenContainer) set(opaqueToken string, jwtAccessToken string, expires time.Time) {
	c.mu.Lock()
	c.values[opaqueToken] = opaqueAccesToken{
		jwtAccessToken,
		expires,
	}
	for k := range c.values {
		if c.values[k].expires.Before(time.Now()) {
			delete(c.values, k)
		}
	}
	c.mu.Unlock()
}

func (c *opaqueAccessTokenContainer) get(opaqueToken string) (string, bool) {
	c.mu.Lock()
	for k := range c.values {
		if c.values[k].expires.Before(time.Now()) {
			delete(c.values, k)
		}
	}
	v, ok := c.values[opaqueToken]
	c.mu.Unlock()
	return v.jwtAccessToken, ok
}
