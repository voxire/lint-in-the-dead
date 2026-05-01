package middleware

import (
	"net/http"
	"time"

	"github.com/voxire/lint-in-the-dead/pkg/metrics"
)

// Metrics instruments every request with Prometheus-compatible counters and
// a latency histogram stored in the provided registry.
func Metrics(reg *metrics.Registry) func(http.Handler) http.Handler {
	requests := reg.Counter("http_requests_total")
	errors   := reg.Counter("http_errors_total")
	latency  := reg.Histogram("http_request_duration_ms")
	inflight := reg.Gauge("http_inflight_requests")

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			inflight.Inc()
			defer inflight.Dec()

			start := time.Now()
			rw := &responseWriter{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(rw, r)

			requests.Inc()
			latency.Observe(float64(time.Since(start).Milliseconds()))
			if rw.status >= 500 {
				errors.Inc()
			}
		})
	}
}
