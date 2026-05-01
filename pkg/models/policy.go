package models

// PolicyResult is returned by the policy engine for a given job.
type PolicyResult struct {
	JobID    string        `json:"job_id"`
	Allowed  bool          `json:"allowed"`
	Blocked  bool          `json:"blocked"`
	Warnings []string      `json:"warnings,omitempty"`
	Errors   []string      `json:"errors,omitempty"`
	Rules    []RuleMatch   `json:"rules"`
}

// RuleMatch records which rule matched and how.
type RuleMatch struct {
	RuleID  string `json:"rule_id"`
	Matched bool   `json:"matched"`
	Reason  string `json:"reason,omitempty"`
}
