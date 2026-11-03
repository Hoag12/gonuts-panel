package web

import (
	"sync"
	"time"
)

// cachedPage is the raw panel page for one installation build.
type cachedPage struct {
	body    string
	expires time.Time
}

// cachedAsset is a decoded binary panel asset (icon, logo, font).
type cachedAsset struct {
	body        []byte
	contentType string
	expires     time.Time
}

// panelCache is a bounded in-memory cache for relayed panel responses. Task 7
// adds the request-path helpers that fill it.
type panelCache struct {
	mu     sync.Mutex
	pages  map[string]cachedPage
	assets map[string]cachedAsset
	bytes  int64
	max    int64
}

func newPanelCache(max int64) *panelCache {
	if max <= 0 {
		max = 16 << 20
	}
	return &panelCache{
		pages:  map[string]cachedPage{},
		assets: map[string]cachedAsset{},
		max:    max,
	}
}

// page returns a cached page body while it is fresh.
func (c *panelCache) page(key string) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	p, ok := c.pages[key]
	if !ok || time.Now().After(p.expires) {
		if ok {
			delete(c.pages, key)
		}
		return "", false
	}
	return p.body, true
}

// putPage stores a page body for ttl.
func (c *panelCache) putPage(key, body string, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pages[key] = cachedPage{body: body, expires: time.Now().Add(ttl)}
}
