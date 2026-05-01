package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	_ "github.com/lib/pq"
	"github.com/voxire/lint-in-the-dead/pkg/models"
	"github.com/voxire/lint-in-the-dead/pkg/signing"
)

const schema = `
CREATE TABLE IF NOT EXISTS audit_entries (
	id          TEXT PRIMARY KEY,
	job_id      TEXT NOT NULL,
	event_type  TEXT NOT NULL,
	actor       TEXT NOT NULL,
	payload     TEXT NOT NULL,
	signature   TEXT NOT NULL,
	created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_audit_job_id     ON audit_entries(job_id);
CREATE INDEX IF NOT EXISTS idx_audit_event_type ON audit_entries(event_type);
CREATE INDEX IF NOT EXISTS idx_audit_created_at ON audit_entries(created_at);
`

// Postgres implements Store using PostgreSQL.
type Postgres struct {
	db     *sql.DB
	secret string
}

func NewPostgres(dsn, secret string) (*Postgres, error) {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("ping db: %w", err)
	}
	if _, err := db.ExecContext(ctx, schema); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return &Postgres{db: db, secret: secret}, nil
}

func (p *Postgres) Insert(ctx context.Context, entry models.AuditEntry) error {
	// Ensure signature is set before insert.
	if entry.Signature == "" {
		entry.Signature = signing.Sign(p.secret, entry.Payload)
	}
	_, err := p.db.ExecContext(ctx, `
		INSERT INTO audit_entries (id, job_id, event_type, actor, payload, signature, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		entry.ID, entry.JobID, entry.EventType, entry.Actor,
		entry.Payload, entry.Signature, entry.CreatedAt,
	)
	return err
}

func (p *Postgres) Query(ctx context.Context, q models.AuditQuery) ([]models.AuditEntry, error) {
	query := `SELECT id, job_id, event_type, actor, payload, signature, created_at
	          FROM audit_entries WHERE 1=1`
	args := []interface{}{}
	n := 1

	if q.JobID != "" {
		query += fmt.Sprintf(" AND job_id = $%d", n)
		args = append(args, q.JobID)
		n++
	}
	if q.EventType != "" {
		query += fmt.Sprintf(" AND event_type = $%d", n)
		args = append(args, q.EventType)
		n++
	}
	if q.Actor != "" {
		query += fmt.Sprintf(" AND actor = $%d", n)
		args = append(args, q.Actor)
		n++
	}
	if !q.Since.IsZero() {
		query += fmt.Sprintf(" AND created_at >= $%d", n)
		args = append(args, q.Since)
		n++
	}
	if !q.Until.IsZero() {
		query += fmt.Sprintf(" AND created_at <= $%d", n)
		args = append(args, q.Until)
		n++
	}
	query += " ORDER BY created_at DESC"
	if q.Limit > 0 {
		query += fmt.Sprintf(" LIMIT $%d", n)
		args = append(args, q.Limit)
		n++
	}
	if q.Offset > 0 {
		query += fmt.Sprintf(" OFFSET $%d", n)
		args = append(args, q.Offset)
	}

	rows, err := p.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []models.AuditEntry
	for rows.Next() {
		var e models.AuditEntry
		if err := rows.Scan(&e.ID, &e.JobID, &e.EventType, &e.Actor,
			&e.Payload, &e.Signature, &e.CreatedAt); err != nil {
			return nil, err
		}
		entries = append(entries, e)
	}
	return entries, rows.Err()
}

// Verify re-computes the HMAC and checks it matches the stored signature.
func (p *Postgres) Verify(ctx context.Context, id string) (bool, error) {
	var payload, storedSig string
	err := p.db.QueryRowContext(ctx,
		`SELECT payload, signature FROM audit_entries WHERE id = $1`, id,
	).Scan(&payload, &storedSig)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return signing.Verify(p.secret, payload, storedSig), nil
}
