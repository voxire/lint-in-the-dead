package models

import "time"

// AuditEntry is a single immutable, HMAC-signed record.
type AuditEntry struct {
	ID        string    `json:"id"`
	JobID     string    `json:"job_id"`
	EventType string    `json:"event_type"`
	Actor     string    `json:"actor"`
	Payload   string    `json:"payload"` // JSON-encoded
	Signature string    `json:"signature"`
	CreatedAt time.Time `json:"created_at"`
}

// AuditQuery filters for listing audit entries.
type AuditQuery struct {
	JobID     string
	EventType string
	Actor     string
	Since     time.Time
	Until     time.Time
	Limit     int
	Offset    int
}
