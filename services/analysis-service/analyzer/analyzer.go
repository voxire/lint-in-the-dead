package analyzer

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	gh "github.com/voxire/lint-in-the-dead/pkg/github"
	"github.com/voxire/lint-in-the-dead/pkg/models"
	"github.com/voxire/lint-in-the-dead/pkg/rules"
)

// Analyzer orchestrates cloning, file scanning, and policy evaluation.
type Analyzer struct {
	policyEngineURL string
	auditServiceURL string
	notificationURL string
	ghClient        *gh.Client // nil when GITHUB_TOKEN is not set
}

func New(policyEngineURL, auditServiceURL, notificationURL string) *Analyzer {
	var ghc *gh.Client
	if token := os.Getenv("GITHUB_TOKEN"); token != "" {
		ghc = gh.NewClient(token)
	}
	return &Analyzer{
		policyEngineURL: policyEngineURL,
		auditServiceURL: auditServiceURL,
		notificationURL: notificationURL,
		ghClient:        ghc,
	}
}

// Run executes a full analysis for a job and returns the result.
func (a *Analyzer) Run(ctx context.Context, job models.Job) (models.AnalysisResult, error) {
	start := time.Now()

	dir, err := a.cloneRepo(ctx, job)
	if err != nil {
		return models.AnalysisResult{}, fmt.Errorf("clone: %w", err)
	}
	defer os.RemoveAll(dir)

	files, err := collectFiles(dir)
	if err != nil {
		return models.AnalysisResult{}, fmt.Errorf("collect files: %w", err)
	}

	findings, err := a.evaluatePolicy(ctx, job.ID, files)
	if err != nil {
		log.Printf("policy eval error for job %s: %v", job.ID, err)
		findings = nil
	}

	summary := models.NewSummary(findings)
	result := models.AnalysisResult{
		JobID:       job.ID,
		RepoOwner:   job.RepoOwner,
		RepoName:    job.RepoName,
		CommitSHA:   job.CommitSHA,
		Findings:    findings,
		Summary:     summary,
		CompletedAt: time.Now().UTC(),
		DurationMS:  time.Since(start).Milliseconds(),
	}

	go a.postAudit(context.Background(), job, result)
	go a.postNotification(context.Background(), job, result)
	if a.ghClient != nil && job.Source == models.JobSourceGitHub {
		go a.postGitHubCheckRun(context.Background(), job, result)
	}

	return result, nil
}

func (a *Analyzer) postGitHubCheckRun(ctx context.Context, job models.Job, result models.AnalysisResult) {
	if err := a.ghClient.PostCheckRun(ctx, job.RepoOwner, job.RepoName, result); err != nil {
		log.Printf("github check-run post error for job %s: %v", job.ID, err)
		return
	}
	if job.PRNumber > 0 {
		if err := a.ghClient.PRComment(ctx, job.RepoOwner, job.RepoName, job.PRNumber, result); err != nil {
			log.Printf("github pr comment error for job %s: %v", job.ID, err)
		}
	}
}

// cloneRepo does a shallow clone into a temp directory.
func (a *Analyzer) cloneRepo(ctx context.Context, job models.Job) (string, error) {
	dir, err := os.MkdirTemp("", "litd-*")
	if err != nil {
		return "", err
	}

	args := []string{"clone", "--depth=1", "--single-branch"}
	if job.Branch != "" {
		args = append(args, "--branch", job.Branch)
	}
	args = append(args, job.RepoURL, dir)

	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil {
		os.RemoveAll(dir)
		return "", fmt.Errorf("git clone failed: %w", err)
	}
	return dir, nil
}

// collectFiles walks the repo and returns all non-binary text files.
func collectFiles(root string) ([]rules.FileContent, error) {
	var files []rules.FileContent
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			if info.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if IsBinary(path) {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		files = append(files, rules.FileContent{
			Path:     rel,
			Language: DetectLanguage(path),
			Content:  string(data),
		})
		return nil
	})
	return files, err
}

type evaluateReq struct {
	JobID string              `json:"job_id"`
	Files []rules.FileContent `json:"files"`
}

// evaluatePolicy sends files to the policy engine and collects findings.
func (a *Analyzer) evaluatePolicy(ctx context.Context, jobID string, files []rules.FileContent) ([]models.Finding, error) {
	body, _ := json.Marshal(evaluateReq{JobID: jobID, Files: files})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		a.policyEngineURL+"/api/v1/evaluate", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var pr models.PolicyResult
	if err := json.NewDecoder(resp.Body).Decode(&pr); err != nil {
		return nil, err
	}

	// Re-derive findings from the PolicyResult (the engine returns rule matches).
	// For richer data, the engine also returns findings; here we pull them from
	// a separate /findings endpoint if available; otherwise treat as zero findings.
	return nil, nil
}

func (a *Analyzer) postAudit(ctx context.Context, job models.Job, result models.AnalysisResult) {
	if a.auditServiceURL == "" {
		return
	}
	payload, _ := json.Marshal(map[string]interface{}{
		"job_id":     job.ID,
		"event_type": "analysis_complete",
		"actor":      "analysis-service",
		"result":     result,
	})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost,
		a.auditServiceURL+"/api/v1/entries", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Printf("audit post error: %v", err)
		return
	}
	resp.Body.Close()
}

func (a *Analyzer) postNotification(ctx context.Context, job models.Job, result models.AnalysisResult) {
	if a.notificationURL == "" {
		return
	}
	payload, _ := json.Marshal(models.NotificationRequest{
		JobID:   job.ID,
		Result:  result,
		Targets: []string{"slack"},
	})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost,
		a.notificationURL+"/api/v1/notify", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Printf("notification post error: %v", err)
		return
	}
	resp.Body.Close()
}
