package queue

import (
	"context"
	"sync"

	"github.com/voxire/lint-in-the-dead/pkg/models"
)

// Queue is a generic job queue interface.
type Queue interface {
	Enqueue(ctx context.Context, job models.Job) error
	Dequeue(ctx context.Context) (models.Job, error)
	Len() int
}

// InMemory is a thread-safe, buffered in-memory queue for local dev.
type InMemory struct {
	mu  sync.Mutex
	ch  chan models.Job
}

func NewInMemory(capacity int) *InMemory {
	return &InMemory{ch: make(chan models.Job, capacity)}
}

func (q *InMemory) Enqueue(_ context.Context, job models.Job) error {
	q.ch <- job
	return nil
}

func (q *InMemory) Dequeue(ctx context.Context) (models.Job, error) {
	select {
	case job := <-q.ch:
		return job, nil
	case <-ctx.Done():
		return models.Job{}, ctx.Err()
	}
}

func (q *InMemory) Len() int {
	return len(q.ch)
}
