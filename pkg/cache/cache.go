// Package cache provides a generic TTL cache safe for concurrent use.
package cache

import (
	"sync"
	"time"
)

type entry[V any] struct {
	value     V
	expiresAt time.Time
}

// TTL is a thread-safe in-memory cache with per-key expiration.
type TTL[K comparable, V any] struct {
	mu      sync.RWMutex
	items   map[K]entry[V]
	ttl     time.Duration
}

// New creates a TTL cache with the given item lifetime.
// A background goroutine evicts expired entries every ttl/2 (minimum 30s).
func New[K comparable, V any](ttl time.Duration) *TTL[K, V] {
	c := &TTL[K, V]{
		items: make(map[K]entry[V]),
		ttl:   ttl,
	}
	interval := ttl / 2
	if interval < 30*time.Second {
		interval = 30 * time.Second
	}
	go c.evictLoop(interval)
	return c
}

// Set stores value under key with the cache's TTL.
func (c *TTL[K, V]) Set(key K, value V) {
	c.mu.Lock()
	c.items[key] = entry[V]{value: value, expiresAt: time.Now().Add(c.ttl)}
	c.mu.Unlock()
}

// Get returns the value and true if the key exists and hasn't expired.
func (c *TTL[K, V]) Get(key K) (V, bool) {
	c.mu.RLock()
	e, ok := c.items[key]
	c.mu.RUnlock()
	if !ok || time.Now().After(e.expiresAt) {
		var zero V
		return zero, false
	}
	return e.value, true
}

// Delete removes a key immediately.
func (c *TTL[K, V]) Delete(key K) {
	c.mu.Lock()
	delete(c.items, key)
	c.mu.Unlock()
}

// Len returns the number of items, including expired ones not yet evicted.
func (c *TTL[K, V]) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.items)
}

func (c *TTL[K, V]) evictLoop(interval time.Duration) {
	for range time.Tick(interval) {
		c.evict()
	}
}

func (c *TTL[K, V]) evict() {
	now := time.Now()
	c.mu.Lock()
	for k, e := range c.items {
		if now.After(e.expiresAt) {
			delete(c.items, k)
		}
	}
	c.mu.Unlock()
}
