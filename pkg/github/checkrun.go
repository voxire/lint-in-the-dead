// Package github provides a minimal GitHub API client for posting Check Runs.
// It uses only the stdlib — no octokit dependency.
package github

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/voxire/lint-in-the-dead/pkg/models"
)

const apiBase = "https://api.github.com"

// Client is a thin GitHub REST API client scoped to one installation token.
type Client struct {
	token      string
	httpClient *http.Client
}

func NewClient(token string) *Client {
	return &Client{
		token:      token,
		httpClient: &http.Client{Timeout: 15 * time.Second},
	}
}

// checkRunPayload is the GitHub Check Run creation body.
type checkRunPayload struct {
	Name       string          `json:"name"`
	HeadSHA    string          `json:"head_sha"`
	Status     string          `json:"status"`
	Conclusion string          `json:"conclusion,omitempty"`
	StartedAt  string          `json:"started_at,omitempty"`
	CompletedAt string         `json:"completed_at,omitempty"`
	Output     checkRunOutput  `json:"output"`
}

type checkRunOutput struct {
	Title   string            `json:"title"`
	Summary string            `json:"summary"`
	Text    string            `json:"text,omitempty"`
	Annotations []annotation  `json:"annotations,omitempty"`
}

type annotation struct {
	Path            string `json:"path"`
	StartLine       int    `json:"start_line"`
	EndLine         int    `json:"end_line"`
	AnnotationLevel string `json:"annotation_level"` // "notice" | "warning" | "failure"
	Message         string `json:"message"`
	Title           string `json:"title,omitempty"`
}

// PostCheckRun creates or updates a GitHub Check Run for the given result.
// owner/repo are the GitHub repository owner and name.
func (c *Client) PostCheckRun(ctx context.Context, owner, repo string, result models.AnalysisResult) error {
	conclusion := "success"
	if !result.Summary.Passed {
		conclusion = "failure"
	}

	annotations := buildAnnotations(result.Findings)
	// GitHub caps annotations at 50 per request.
	if len(annotations) > 50 {
		annotations = annotations[:50]
	}

	summary := fmt.Sprintf(
		"**Score:** %.0f / 100\n\n"+
			"| Severity | Count |\n|----------|-------|\n"+
			"| 🔴 Critical | %d |\n"+
			"| 🟠 High     | %d |\n"+
			"| 🟡 Medium   | %d |\n"+
			"| 🔵 Low      | %d |\n"+
			"| ℹ️  Info    | %d |\n\n"+
			"Analysis completed in %dms.",
		result.Summary.Score,
		result.Summary.BySeverity["critical"],
		result.Summary.BySeverity["high"],
		result.Summary.BySeverity["medium"],
		result.Summary.BySeverity["low"],
		result.Summary.BySeverity["info"],
		result.DurationMS,
	)

	payload := checkRunPayload{
		Name:        "lint-in-the-dead",
		HeadSHA:     result.CommitSHA,
		Status:      "completed",
		Conclusion:  conclusion,
		CompletedAt: result.CompletedAt.UTC().Format(time.RFC3339),
		Output: checkRunOutput{
			Title:       titleFor(result),
			Summary:     summary,
			Annotations: annotations,
		},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("%s/repos/%s/%s/check-runs", apiBase, owner, repo)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("post check run: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		var errBody map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&errBody)
		return fmt.Errorf("github API %d: %v", resp.StatusCode, errBody)
	}
	return nil
}

func buildAnnotations(findings []models.Finding) []annotation {
	out := make([]annotation, 0, len(findings))
	for _, f := range findings {
		level := severityToLevel(f.Severity)
		out = append(out, annotation{
			Path:            f.File,
			StartLine:       max(1, f.Line),
			EndLine:         max(1, f.Line),
			AnnotationLevel: level,
			Title:           fmt.Sprintf("[%s] %s", f.RuleID, f.RuleName),
			Message:         f.Message,
		})
	}
	return out
}

func severityToLevel(s models.Severity) string {
	switch s {
	case models.SeverityCritical, models.SeverityHigh:
		return "failure"
	case models.SeverityMedium:
		return "warning"
	default:
		return "notice"
	}
}

func titleFor(r models.AnalysisResult) string {
	if r.Summary.Passed {
		return fmt.Sprintf("✅ Passed — score %.0f/100, %d findings", r.Summary.Score, r.Summary.TotalFindings)
	}
	return fmt.Sprintf("❌ Failed — score %.0f/100, %d critical/high findings",
		r.Summary.Score,
		r.Summary.BySeverity["critical"]+r.Summary.BySeverity["high"])
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// PRComment posts a markdown summary as a pull-request comment.
func (c *Client) PRComment(ctx context.Context, owner, repo string, prNumber int, result models.AnalysisResult) error {
	body := buildCommentBody(result)
	payload, _ := json.Marshal(map[string]string{"body": body})

	url := fmt.Sprintf("%s/repos/%s/%s/issues/%d/comments", apiBase, owner, repo, prNumber)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("post pr comment: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("github API %d", resp.StatusCode)
	}
	return nil
}

func buildCommentBody(r models.AnalysisResult) string {
	icon := "✅"
	if !r.Summary.Passed {
		icon = "❌"
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "## %s lint-in-the-dead Analysis\n\n", icon)
	fmt.Fprintf(&sb, "**Score:** `%.0f / 100` | **Commit:** `%s`\n\n", r.Summary.Score, r.CommitSHA[:8])
	fmt.Fprintf(&sb, "| Severity | Count |\n|:---------|------:|\n")
	for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
		if n := r.Summary.BySeverity[sev]; n > 0 {
			fmt.Fprintf(&sb, "| %s | %d |\n", sev, n)
		}
	}

	if len(r.Findings) > 0 {
		fmt.Fprintf(&sb, "\n<details><summary>Top findings</summary>\n\n")
		limit := 10
		if len(r.Findings) < limit {
			limit = len(r.Findings)
		}
		for _, f := range r.Findings[:limit] {
			fmt.Fprintf(&sb, "- **[%s]** `%s:%d` — %s\n", f.RuleID, f.File, f.Line, f.Message)
		}
		if len(r.Findings) > 10 {
			fmt.Fprintf(&sb, "\n_…and %d more findings._\n", len(r.Findings)-10)
		}
		fmt.Fprintf(&sb, "\n</details>\n")
	}

	fmt.Fprintf(&sb, "\n_Analysis took %dms._\n", r.DurationMS)
	return sb.String()
}
