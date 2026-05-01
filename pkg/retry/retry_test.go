package retry_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/voxire/lint-in-the-dead/pkg/retry"
)

func TestDo_SucceedsOnFirstAttempt(t *testing.T) {
	calls := 0
	err := retry.Do(context.Background(), retry.Config{MaxAttempts: 3, BaseDelay: time.Millisecond}, func() (bool, error) {
		calls++
		return true, nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if calls != 1 {
		t.Errorf("expected 1 call, got %d", calls)
	}
}

func TestDo_RetriesAndSucceeds(t *testing.T) {
	var calls int32
	err := retry.Do(context.Background(), retry.Config{MaxAttempts: 4, BaseDelay: time.Millisecond}, func() (bool, error) {
		n := atomic.AddInt32(&calls, 1)
		if n < 3 {
			return false, errors.New("transient")
		}
		return true, nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if calls != 3 {
		t.Errorf("expected 3 calls, got %d", calls)
	}
}

func TestDo_ExhaustsAttempts(t *testing.T) {
	calls := 0
	cfg := retry.Config{MaxAttempts: 3, BaseDelay: time.Millisecond}
	err := retry.Do(context.Background(), cfg, func() (bool, error) {
		calls++
		return false, errors.New("always fails")
	})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if calls != 3 {
		t.Errorf("expected 3 calls, got %d", calls)
	}
}

func TestDo_PermanentErrorStopsImmediately(t *testing.T) {
	calls := 0
	sentinel := errors.New("fatal")
	err := retry.Do(context.Background(), retry.Config{MaxAttempts: 5, BaseDelay: time.Millisecond}, func() (bool, error) {
		calls++
		return false, retry.Permanent(sentinel)
	})
	if !errors.Is(err, sentinel) {
		t.Errorf("expected sentinel error, got %v", err)
	}
	if calls != 1 {
		t.Errorf("expected 1 call (permanent), got %d", calls)
	}
}

func TestDo_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	go func() {
		time.Sleep(5 * time.Millisecond)
		cancel()
	}()
	err := retry.Do(ctx, retry.Config{MaxAttempts: 10, BaseDelay: 20 * time.Millisecond}, func() (bool, error) {
		calls++
		return false, errors.New("nope")
	})
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got %v", err)
	}
	if calls > 2 {
		t.Errorf("too many calls before cancel: %d", calls)
	}
}

func TestDoHTTP_RetriesOn503(t *testing.T) {
	var count int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := atomic.AddInt32(&count, 1)
		if n < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := retry.Config{MaxAttempts: 4, BaseDelay: time.Millisecond, Multiplier: 2}
	resp, err := retry.DoHTTP(context.Background(), cfg, func() (*http.Response, error) {
		return http.Get(srv.URL)
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	if count != 3 {
		t.Errorf("expected 3 requests, got %d", count)
	}
}
