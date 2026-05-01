package models

// NotificationRequest is sent to the notification service.
type NotificationRequest struct {
	JobID   string         `json:"job_id"`
	Result  AnalysisResult `json:"result"`
	Policy  PolicyResult   `json:"policy"`
	Targets []string       `json:"targets"` // "slack", "email"
}
