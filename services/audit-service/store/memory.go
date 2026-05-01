package store

import (
	"context"
	"sync"

	"github.com/voxire/lint-in-the-dead/pkg/models"
	"github.com/voxire/lint-in-the-dead/pkg/signing"
)

// Memory is a thread-safe in-memory store for testing / dev without Postgres.
type Memory struct {
	mu      sync.RWMutex
	entries []models.AuditEntry
	secret  string
}

func NewMemory(secret string) *Memory {
	return &Memory{secret: secret}
}

func (m *Memory) Insert(_ context.Context, e models.AuditEntry) error {
	if e.Signature == "" {
		e.Signature = signing.Sign(m.secret, e.Payload)
	}
	m.mu.Lock()
	m.entries = append(m.entries, e)
	m.mu.Unlock()
	return nil
}

func (m *Memory) Query(_ context.Context, q models.AuditQuery) ([]models.AuditEntry, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var out []models.AuditEntry
	for _, e := range m.entries {
		if q.JobID != "" && e.JobID != q.JobID {
			continue
		}
		if q.EventType != "" && e.EventType != q.EventType {
			continue
		}
		if q.Actor != "" && e.Actor != q.Actor {
			continue
		}
		if !q.Since.IsZero() && e.CreatedAt.Before(q.Since) {
			continue
		}
		if !q.Until.IsZero() && e.CreatedAt.After(q.Until) {
			continue
		}
		out = append(out, e)
	}
	limit := q.Limit
	if limit <= 0 || limit > len(out) {
		limit = len(out)
	}
	offset := q.Offset
	if offset >= len(out) {
		return nil, nil
	}
	return out[offset : offset+limit], nil
}

func (m *Memory) Verify(_ context.Context, id string) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, e := range m.entries {
		if e.ID == id {
			return signing.Verify(m.secret, e.Payload, e.Signature), nil
		}
	}
	return false, nil
}
