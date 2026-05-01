package models

import "time"

type JobStatus string

const (
	JobStatusQueued     JobStatus = "queued"
	JobStatusRunning    JobStatus = "running"
	JobStatusCompleted  JobStatus = "completed"
	JobStatusFailed     JobStatus = "failed"
	JobStatusCancelled  JobStatus = "cancelled"
)

type JobSource string

const (
	JobSourceGitHub    JobSource = "github"
	JobSourceGitLab    JobSource = "gitlab"
	JobSourceAzureDevOps JobSource = "azure_devops"
	JobSourceManual    JobSource = "manual"
)

// Job represents a single analysis request (PR, push, manual scan).
type Job struct {
	ID          string            `json:"id"`
	Source      JobSource         `json:"source"`
	RepoURL     string            `json:"repo_url"`
	RepoOwner   string            `json:"repo_owner"`
	RepoName    string            `json:"repo_name"`
	CommitSHA   string            `json:"commit_sha"`
	Branch      string            `json:"branch"`
	PRNumber    int               `json:"pr_number,omitempty"`
	Status      JobStatus         `json:"status"`
	CreatedAt   time.Time         `json:"created_at"`
	StartedAt   *time.Time        `json:"started_at,omitempty"`
	CompletedAt *time.Time        `json:"completed_at,omitempty"`
	Meta        map[string]string `json:"meta,omitempty"`
}

// JobEvent is emitted over WebSocket and SSE to report progress.
type JobEvent struct {
	JobID   string      `json:"job_id"`
	Type    string      `json:"type"` // "status_change" | "finding" | "done"
	Payload interface{} `json:"payload"`
	At      time.Time   `json:"at"`
}
