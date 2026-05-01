// Package retry provides exponential backoff retry logic for HTTP calls and
// arbitrary operations between services.
package retry

import (
	"context"
	"errors"
	"math/rand/v2"
	"net/http"
	"time"
)

// Config controls backoff behaviour.
type Config struct {
	MaxAttempts int
	BaseDelay   time.Duration
	MaxDelay    time.Duration
	Multiplier  float64
	Jitter      float64 // fraction of delay to randomise, e.g. 0.2 = ±20%
}

var Default = Config{
	MaxAttempts: 4,
	BaseDelay:   500 * time.Millisecond,
	MaxDelay:    16 * time.Second,
	Multiplier:  2.0,
	Jitter:      0.2,
}

// ErrMaxAttempts is returned when all attempts are exhausted.
var ErrMaxAttempts = errors.New("retry: max attempts reached")

// Do calls fn up to cfg.MaxAttempts times, backing off between failures.
// fn should return (true, nil) on success, (false, err) to retry, or
// (false, err) with a permanent error wrapped in Permanent() to stop early.
func Do(ctx context.Context, cfg Config, fn func() (bool, error)) error {
	delay := cfg.BaseDelay
	var lastErr error

	for attempt := range cfg.MaxAttempts {
		ok, err := fn()
		if ok {
			return nil
		}
		lastErr = err

		var perm *permanentError
		if errors.As(err, &perm) {
			return perm.Unwrap()
		}

		if attempt == cfg.MaxAttempts-1 {
			break
		}

		sleep := addJitter(delay, cfg.Jitter)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(sleep):
		}

		delay = time.Duration(float64(delay) * cfg.Multiplier)
		if delay > cfg.MaxDelay {
			delay = cfg.MaxDelay
		}
	}

	if lastErr != nil {
		return lastErr
	}
	return ErrMaxAttempts
}

// DoHTTP wraps an HTTP request function, retrying on 429, 502, 503, 504.
func DoHTTP(ctx context.Context, cfg Config, fn func() (*http.Response, error)) (*http.Response, error) {
	var resp *http.Response
	err := Do(ctx, cfg, func() (bool, error) {
		var err error
		resp, err = fn()
		if err != nil {
			return false, err
		}
		switch resp.StatusCode {
		case http.StatusTooManyRequests,
			http.StatusBadGateway,
			http.StatusServiceUnavailable,
			http.StatusGatewayTimeout:
			resp.Body.Close()
			return false, errors.New(resp.Status)
		}
		return true, nil
	})
	return resp, err
}

// Permanent wraps an error to signal that it should not be retried.
func Permanent(err error) error { return &permanentError{err} }

type permanentError struct{ err error }

func (e *permanentError) Error() string { return e.err.Error() }
func (e *permanentError) Unwrap() error { return e.err }

func addJitter(d time.Duration, jitter float64) time.Duration {
	if jitter <= 0 {
		return d
	}
	delta := float64(d) * jitter
	return d + time.Duration((rand.Float64()*2-1)*delta)
}
