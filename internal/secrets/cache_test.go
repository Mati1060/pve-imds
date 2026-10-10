package secrets

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// countingSource returns a value that embeds the call count, or err if set.
type countingSource struct {
	mu    sync.Mutex
	calls map[string]int
	err   error
}

func (s *countingSource) Get(_ context.Context, pool, set string) (map[string]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.calls == nil {
		s.calls = map[string]int{}
	}
	s.calls[pool+"/"+set]++
	if s.err != nil {
		return nil, s.err
	}
	return map[string]string{"pool": pool, "n": string(rune('0' + s.calls[pool+"/"+set]))}, nil
}

func (s *countingSource) count(key string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls[key]
}

func newTestCache(src Source, ttl time.Duration) (*Cache, *time.Time) {
	now := time.Unix(1_000_000, 0)
	c := NewCache(src, ttl)
	c.now = func() time.Time { return now }
	return c, &now
}

func TestCacheHitWithinTTL(t *testing.T) {
	src := &countingSource{}
	c, now := newTestCache(src, time.Minute)

	v1, err := c.Get(context.Background(), "p", "s")
	require.NoError(t, err)
	*now = now.Add(59 * time.Second)
	v2, err := c.Get(context.Background(), "p", "s")
	require.NoError(t, err)

	assert.Equal(t, v1, v2)
	assert.Equal(t, 1, src.count("p/s"))
}

func TestCacheExpiry(t *testing.T) {
	src := &countingSource{}
	c, now := newTestCache(src, time.Minute)

	_, err := c.Get(context.Background(), "p", "s")
	require.NoError(t, err)
	*now = now.Add(time.Minute)
	v, err := c.Get(context.Background(), "p", "s")
	require.NoError(t, err)

	assert.Equal(t, "2", v["n"])
	assert.Equal(t, 2, src.count("p/s"))
}

func TestCacheKeyedByPoolAndSet(t *testing.T) {
	src := &countingSource{}
	c, _ := newTestCache(src, time.Minute)

	a, err := c.Get(context.Background(), "pool-a", "s")
	require.NoError(t, err)
	b, err := c.Get(context.Background(), "pool-b", "s")
	require.NoError(t, err)

	// A VM that moved to another pool gets that pool's set, not a cached
	// copy of its old pool's set.
	assert.Equal(t, "pool-a", a["pool"])
	assert.Equal(t, "pool-b", b["pool"])
	assert.Equal(t, 1, src.count("pool-a/s"))
	assert.Equal(t, 1, src.count("pool-b/s"))
}

func TestCacheErrorsNotCached(t *testing.T) {
	src := &countingSource{err: errors.New("unreachable")}
	c, _ := newTestCache(src, time.Minute)

	_, err := c.Get(context.Background(), "p", "s")
	require.Error(t, err)

	src.mu.Lock()
	src.err = nil
	src.mu.Unlock()

	_, err = c.Get(context.Background(), "p", "s")
	require.NoError(t, err)
	assert.Equal(t, 2, src.count("p/s"))
}

func TestCacheZeroTTLDisablesCaching(t *testing.T) {
	src := &countingSource{}
	c, _ := newTestCache(src, 0)

	for range 3 {
		_, err := c.Get(context.Background(), "p", "s")
		require.NoError(t, err)
	}
	assert.Equal(t, 3, src.count("p/s"))
}

func TestCacheReturnsCopy(t *testing.T) {
	src := &countingSource{}
	c, _ := newTestCache(src, time.Minute)

	v, err := c.Get(context.Background(), "p", "s")
	require.NoError(t, err)
	v["pool"] = "mutated"

	v2, err := c.Get(context.Background(), "p", "s")
	require.NoError(t, err)
	assert.Equal(t, "p", v2["pool"])
}
