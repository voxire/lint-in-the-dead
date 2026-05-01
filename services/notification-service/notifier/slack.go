package notifier

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/voxire/lint-in-the-dead/pkg/models"
)

type Slack struct {
	webhookURL string
}

func NewSlack(webhookURL string) *Slack {
	return &Slack{webhookURL: webhookURL}
}

func (s *Slack) Enabled() bool { return s.webhookURL != "" }

func (s *Slack) Send(ctx context.Context, req models.NotificationRequest) error {
	if !s.Enabled() {
		return nil
	}

	result := req.Result
	icon := ":white_check_mark:"
	color := "#36a64f"
	if !result.Summary.Passed {
		icon = ":x:"
		color = "#ff0000"
	}

	text := fmt.Sprintf("%s *%s/%s* — analysis %s\n"+
		"Score: %.0f/100 | Findings: %d (critical: %d, high: %d, medium: %d)",
		icon,
		result.RepoOwner, result.RepoName,
		statusLabel(result.Summary.Passed),
		result.Summary.Score,
		result.Summary.TotalFindings,
		result.Summary.BySeverity["critical"],
		result.Summary.BySeverity["high"],
		result.Summary.BySeverity["medium"],
	)

	payload := map[string]interface{}{
		"attachments": []map[string]interface{}{
			{
				"color":     color,
				"text":      text,
				"footer":    "lint-in-the-dead",
				"ts":        result.CompletedAt.Unix(),
				"mrkdwn_in": []string{"text"},
			},
		},
	}

	body, _ := json.Marshal(payload)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, s.webhookURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("slack post: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("slack returned %d", resp.StatusCode)
	}
	return nil
}

func statusLabel(passed bool) string {
	if passed {
		return "passed"
	}
	return "FAILED"
}
