package store

import (
	"context"

	"github.com/voxire/lint-in-the-dead/pkg/models"
)

// Store is the interface for persisting and querying audit entries.
type Store interface {
	Insert(ctx context.Context, entry models.AuditEntry) error
	Query(ctx context.Context, q models.AuditQuery) ([]models.AuditEntry, error)
	Verify(ctx context.Context, id string) (bool, error)
}
