package server

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/voxire/lint-in-the-dead/pkg/models"
)

// SSEBroker manages Server-Sent Events subscriptions keyed by job ID.
type SSEBroker struct {
	mu          sync.RWMutex
	subscribers map[string][]chan models.JobEvent
}

func NewSSEBroker() *SSEBroker {
	return &SSEBroker{
		subscribers: make(map[string][]chan models.JobEvent),
	}
}

// Publish sends an event to all subscribers for the given job ID.
func (b *SSEBroker) Publish(jobID string, event models.JobEvent) {
	b.mu.RLock()
	chans := b.subscribers[jobID]
	b.mu.RUnlock()
	for _, ch := range chans {
		select {
		case ch <- event:
		default: // slow consumer — drop rather than block
		}
	}
}

// PublishAll broadcasts an event to every subscriber (e.g. job list updates).
func (b *SSEBroker) PublishAll(event models.JobEvent) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	for _, chans := range b.subscribers {
		for _, ch := range chans {
			select {
			case ch <- event:
			default:
			}
		}
	}
}

func (b *SSEBroker) subscribe(jobID string) chan models.JobEvent {
	ch := make(chan models.JobEvent, 64)
	b.mu.Lock()
	b.subscribers[jobID] = append(b.subscribers[jobID], ch)
	b.mu.Unlock()
	return ch
}

func (b *SSEBroker) unsubscribe(jobID string, ch chan models.JobEvent) {
	b.mu.Lock()
	defer b.mu.Unlock()
	list := b.subscribers[jobID]
	for i, c := range list {
		if c == ch {
			b.subscribers[jobID] = append(list[:i], list[i+1:]...)
			break
		}
	}
	if len(b.subscribers[jobID]) == 0 {
		delete(b.subscribers, jobID)
	}
}

// ServeSSE returns an http.HandlerFunc that streams job events as SSE.
// GET /api/v1/jobs/{id}/stream
func (b *SSEBroker) ServeSSE(w http.ResponseWriter, r *http.Request) {
	jobID := r.PathValue("id")
	if jobID == "" {
		http.Error(w, "job id required", http.StatusBadRequest)
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no") // disable nginx buffering

	// Send an initial keep-alive comment so the client knows we're connected.
	fmt.Fprintf(w, ": connected job=%s\n\n", jobID)
	flusher.Flush()

	ch := b.subscribe(jobID)
	defer b.unsubscribe(jobID, ch)

	ticker := time.NewTicker(25 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case event, ok := <-ch:
			if !ok {
				return
			}
			if err := writeSSEEvent(w, event); err != nil {
				log.Printf("sse write error: %v", err)
				return
			}
			flusher.Flush()

			if event.Type == "done" || event.Type == "failed" {
				return
			}

		case <-ticker.C:
			// heartbeat keeps proxies from closing idle connections
			fmt.Fprintf(w, ": heartbeat\n\n")
			flusher.Flush()

		case <-r.Context().Done():
			return
		}
	}
}

func writeSSEEvent(w http.ResponseWriter, event models.JobEvent) error {
	data, err := json.Marshal(event)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event.Type, data)
	return err
}
