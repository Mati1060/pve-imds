package secrets

import (
	"context"
	"maps"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

// Cache wraps a Source with a per-(pool, set) TTL cache. Concurrent misses
// for the same key share one upstream request. Errors are never cached, so a
// failed fetch is retried on the next request.
type Cache struct {
	src Source
	ttl time.Duration
	now func() time.Time

	group singleflight.Group

	mu      sync.Mutex
	entries map[cacheKey]cacheEntry
}

type cacheKey struct{ pool, set string }

type cacheEntry struct {
	values  map[string]string
	expires time.Time
}

// NewCache returns a Cache in front of src. A ttl of zero or less disables
// caching (but still coalesces concurrent requests).
func NewCache(src Source, ttl time.Duration) *Cache {
	return &Cache{
		src:     src,
		ttl:     ttl,
		now:     time.Now,
		entries: make(map[cacheKey]cacheEntry),
	}
}

// Get implements [Source]. The returned map is a copy and may be modified.
func (c *Cache) Get(ctx context.Context, pool, set string) (map[string]string, error) {
	key := cacheKey{pool, set}

	c.mu.Lock()
	e, ok := c.entries[key]
	if ok && c.now().Before(e.expires) {
		c.mu.Unlock()
		return maps.Clone(e.values), nil
	}
	delete(c.entries, key)
	c.mu.Unlock()

	v, err, _ := c.group.Do(pool+"\x00"+set, func() (any, error) {
		values, err := c.src.Get(ctx, pool, set)
		if err != nil {
			return nil, err
		}
		if c.ttl > 0 {
			c.mu.Lock()
			c.entries[key] = cacheEntry{values: values, expires: c.now().Add(c.ttl)}
			c.mu.Unlock()
		}
		return values, nil
	})
	if err != nil {
		return nil, err
	}
	return maps.Clone(v.(map[string]string)), nil
}
