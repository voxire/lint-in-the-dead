package models

import "time"

type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

type FindingCategory string

const (
	CategorySecurity   FindingCategory = "security"
	CategoryQuality    FindingCategory = "quality"
	CategoryLicense    FindingCategory = "license"
	CategoryCompliance FindingCategory = "compliance"
	CategoryStyle      FindingCategory = "style"
)

// Finding is a single linting / security / compliance issue.
type Finding struct {
	RuleID    string          `json:"rule_id"`
	RuleName  string          `json:"rule_name"`
	Category  FindingCategory `json:"category"`
	Severity  Severity        `json:"severity"`
	File      string          `json:"file"`
	Line      int             `json:"line"`
	Column    int             `json:"column"`
	Message   string          `json:"message"`
	Snippet   string          `json:"snippet,omitempty"`
	FixSuggestion string      `json:"fix_suggestion,omitempty"`
}

// AnalysisResult is the aggregated output of a completed job.
type AnalysisResult struct {
	JobID       string    `json:"job_id"`
	RepoOwner   string    `json:"repo_owner"`
	RepoName    string    `json:"repo_name"`
	CommitSHA   string    `json:"commit_sha"`
	Language    string    `json:"language"`
	Findings    []Finding `json:"findings"`
	Summary     Summary   `json:"summary"`
	CompletedAt time.Time `json:"completed_at"`
	DurationMS  int64     `json:"duration_ms"`
}

// Summary contains aggregated counts for the dashboard.
type Summary struct {
	TotalFindings int            `json:"total_findings"`
	BySeverity    map[string]int `json:"by_severity"`
	ByCategory    map[string]int `json:"by_category"`
	Score         float64        `json:"score"` // 0–100, higher is better
	Passed        bool           `json:"passed"`
}

func NewSummary(findings []Finding) Summary {
	s := Summary{
		TotalFindings: len(findings),
		BySeverity:    make(map[string]int),
		ByCategory:    make(map[string]int),
	}
	for _, f := range findings {
		s.BySeverity[string(f.Severity)]++
		s.ByCategory[string(f.Category)]++
	}
	// Simple weighted score: start at 100, deduct per finding.
	deductions := float64(s.BySeverity["critical"])*20 +
		float64(s.BySeverity["high"])*10 +
		float64(s.BySeverity["medium"])*4 +
		float64(s.BySeverity["low"])*1
	s.Score = max(0, 100-deductions)
	s.Passed = s.BySeverity["critical"] == 0 && s.BySeverity["high"] == 0
	return s
}

func max(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}
