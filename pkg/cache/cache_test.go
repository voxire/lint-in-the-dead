package cache_test

import (
	"testing"
	"time"

	"github.com/voxire/lint-in-the-dead/pkg/cache"
)

func TestCache_SetAndGet(t *testing.T) {
	c := cache.New[string, int](time.Minute)
	c.Set("key", 42)

	v, ok := c.Get("key")
	if !ok {
		t.Fatal("Get returned false for existing key")
	}
	if v != 42 {
		t.Errorf("Get: got %d, want 42", v)
	}
}

func TestCache_MissOnUnknownKey(t *testing.T) {
	c := cache.New[string, int](time.Minute)
	_, ok := c.Get("missing")
	if ok {
		t.Error("Get returned true for missing key")
	}
}

func TestCache_Expiry(t *testing.T) {
	c := cache.New[string, string](50 * time.Millisecond)
	c.Set("k", "v")

	if _, ok := c.Get("k"); !ok {
		t.Fatal("key should exist immediately after Set")
	}

	time.Sleep(100 * time.Millisecond)

	if _, ok := c.Get("k"); ok {
		t.Error("key should have expired")
	}
}

func TestCache_Delete(t *testing.T) {
	c := cache.New[string, int](time.Minute)
	c.Set("x", 1)
	c.Delete("x")

	if _, ok := c.Get("x"); ok {
		t.Error("key should be gone after Delete")
	}
}

func TestCache_Overwrite(t *testing.T) {
	c := cache.New[string, int](time.Minute)
	c.Set("n", 1)
	c.Set("n", 99)

	v, ok := c.Get("n")
	if !ok || v != 99 {
		t.Errorf("expected 99, got %d (ok=%v)", v, ok)
	}
}

func TestCache_Len(t *testing.T) {
	c := cache.New[int, int](time.Minute)
	if c.Len() != 0 {
		t.Errorf("expected Len 0, got %d", c.Len())
	}
	c.Set(1, 10)
	c.Set(2, 20)
	if c.Len() != 2 {
		t.Errorf("expected Len 2, got %d", c.Len())
	}
}

func TestCache_ConcurrentAccess(t *testing.T) {
	c := cache.New[int, int](time.Minute)
	done := make(chan struct{})

	for i := range 50 {
		go func(n int) {
			c.Set(n, n*n)
			c.Get(n)
			done <- struct{}{}
		}(i)
	}
	for range 50 {
		<-done
	}
}
