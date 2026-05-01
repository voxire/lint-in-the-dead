// Package metrics provides shared Prometheus metric definitions and an HTTP
// handler that each service mounts at GET /metrics.
package metrics

import (
	"fmt"
	"net/http"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

// Counter is a monotonically increasing uint64.
type Counter struct{ v uint64 }

func (c *Counter) Inc()            { atomic.AddUint64(&c.v, 1) }
func (c *Counter) Add(n uint64)   { atomic.AddUint64(&c.v, n) }
func (c *Counter) Value() uint64  { return atomic.LoadUint64(&c.v) }

// Gauge is a signed int64 that can go up or down.
type Gauge struct{ v int64 }

func (g *Gauge) Set(n int64)     { atomic.StoreInt64(&g.v, n) }
func (g *Gauge) Inc()            { atomic.AddInt64(&g.v, 1) }
func (g *Gauge) Dec()            { atomic.AddInt64(&g.v, -1) }
func (g *Gauge) Value() int64    { return atomic.LoadInt64(&g.v) }

// Histogram approximates latency distribution with fixed buckets (ms).
type Histogram struct {
	mu      sync.Mutex
	buckets []float64
	counts  []uint64
	sum     float64
	total   uint64
}

var defaultBuckets = []float64{5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000}

func NewHistogram(buckets ...float64) *Histogram {
	if len(buckets) == 0 {
		buckets = defaultBuckets
	}
	return &Histogram{buckets: buckets, counts: make([]uint64, len(buckets)+1)}
}

func (h *Histogram) Observe(ms float64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.sum += ms
	h.total++
	for i, b := range h.buckets {
		if ms <= b {
			h.counts[i]++
			return
		}
	}
	h.counts[len(h.buckets)]++ // +Inf bucket
}

func (h *Histogram) snapshot() (buckets []float64, counts []uint64, sum float64, total uint64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	c := make([]uint64, len(h.counts))
	copy(c, h.counts)
	return h.buckets, c, h.sum, h.total
}

// Registry holds all named metrics for a service.
type Registry struct {
	name     string
	mu       sync.RWMutex
	counters   map[string]*Counter
	gauges     map[string]*Gauge
	histograms map[string]*Histogram
	startTime  time.Time
}

func NewRegistry(serviceName string) *Registry {
	return &Registry{
		name:       serviceName,
		counters:   make(map[string]*Counter),
		gauges:     make(map[string]*Gauge),
		histograms: make(map[string]*Histogram),
		startTime:  time.Now(),
	}
}

func (r *Registry) Counter(name string) *Counter {
	r.mu.Lock()
	defer r.mu.Unlock()
	if c, ok := r.counters[name]; ok {
		return c
	}
	c := &Counter{}
	r.counters[name] = c
	return c
}

func (r *Registry) Gauge(name string) *Gauge {
	r.mu.Lock()
	defer r.mu.Unlock()
	if g, ok := r.gauges[name]; ok {
		return g
	}
	g := &Gauge{}
	r.gauges[name] = g
	return g
}

func (r *Registry) Histogram(name string) *Histogram {
	r.mu.Lock()
	defer r.mu.Unlock()
	if h, ok := r.histograms[name]; ok {
		return h
	}
	h := NewHistogram()
	r.histograms[name] = h
	return h
}

// Handler returns an http.HandlerFunc that serves Prometheus text format.
func (r *Registry) Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")

		prefix := r.name + "_"

		r.mu.RLock()
		defer r.mu.RUnlock()

		// Process metrics.
		var ms runtime.MemStats
		runtime.ReadMemStats(&ms)

		fmt.Fprintf(w, "# HELP %sgoroutines Number of goroutines\n", prefix)
		fmt.Fprintf(w, "# TYPE %sgoroutines gauge\n", prefix)
		fmt.Fprintf(w, "%sgoroutines %d\n", prefix, runtime.NumGoroutine())

		fmt.Fprintf(w, "# HELP %suptime_seconds Seconds since service start\n", prefix)
		fmt.Fprintf(w, "# TYPE %suptime_seconds gauge\n", prefix)
		fmt.Fprintf(w, "%suptime_seconds %.2f\n", prefix, time.Since(r.startTime).Seconds())

		fmt.Fprintf(w, "# HELP %sheap_alloc_bytes Heap bytes allocated\n", prefix)
		fmt.Fprintf(w, "# TYPE %sheap_alloc_bytes gauge\n", prefix)
		fmt.Fprintf(w, "%sheap_alloc_bytes %d\n", prefix, ms.HeapAlloc)

		// Counters.
		for name, c := range r.counters {
			fmt.Fprintf(w, "# TYPE %s%s counter\n", prefix, name)
			fmt.Fprintf(w, "%s%s %d\n", prefix, name, c.Value())
		}

		// Gauges.
		for name, g := range r.gauges {
			fmt.Fprintf(w, "# TYPE %s%s gauge\n", prefix, name)
			fmt.Fprintf(w, "%s%s %d\n", prefix, name, g.Value())
		}

		// Histograms.
		for name, h := range r.histograms {
			buckets, counts, sum, total := h.snapshot()
			fmt.Fprintf(w, "# TYPE %s%s histogram\n", prefix, name)
			cumulative := uint64(0)
			for i, b := range buckets {
				cumulative += counts[i]
				fmt.Fprintf(w, "%s%s_bucket{le=\"%.0f\"} %d\n", prefix, name, b, cumulative)
			}
			cumulative += counts[len(buckets)]
			fmt.Fprintf(w, "%s%s_bucket{le=\"+Inf\"} %d\n", prefix, name, cumulative)
			fmt.Fprintf(w, "%s%s_sum %.3f\n", prefix, name, sum)
			fmt.Fprintf(w, "%s%s_count %d\n", prefix, name, total)
		}
	}
}
