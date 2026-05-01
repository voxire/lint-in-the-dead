package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/voxire/lint-in-the-dead/pkg/models"
	"github.com/voxire/lint-in-the-dead/pkg/signing"
)

type githubPREvent struct {
	Action      string `json:"action"`
	Number      int    `json:"number"`
	PullRequest struct {
		Head struct {
			SHA  string `json:"sha"`
			Ref  string `json:"ref"`
			Repo struct {
				CloneURL string `json:"clone_url"`
				FullName string `json:"full_name"`
			} `json:"repo"`
		} `json:"head"`
	} `json:"pull_request"`
}

// GitHubWebhookHandler handles incoming GitHub webhook POST requests.
func (s *Server) GitHubWebhookHandler(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 10<<20))
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}

	if s.cfg.GitHubWebhookSecret != "" {
		sig := r.Header.Get("X-Hub-Signature-256")
		if !signing.VerifyGitHub(s.cfg.GitHubWebhookSecret, body, sig) {
			http.Error(w, "invalid signature", http.StatusUnauthorized)
			return
		}
	}

	event := r.Header.Get("X-GitHub-Event")
	switch event {
	case "pull_request":
		s.handleGitHubPR(w, r, body)
	case "ping":
		w.WriteHeader(http.StatusOK)
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

func (s *Server) handleGitHubPR(w http.ResponseWriter, _ *http.Request, body []byte) {
	var ev githubPREvent
	if err := json.Unmarshal(body, &ev); err != nil {
		http.Error(w, "decode payload", http.StatusBadRequest)
		return
	}

	// Only trigger on opened / synchronize / reopened.
	switch ev.Action {
	case "opened", "synchronize", "reopened":
	default:
		w.WriteHeader(http.StatusNoContent)
		return
	}

	parts := splitOwnerRepo(ev.PullRequest.Head.Repo.FullName)
	job := models.Job{
		ID:        newID(),
		Source:    models.JobSourceGitHub,
		RepoURL:   ev.PullRequest.Head.Repo.CloneURL,
		RepoOwner: parts[0],
		RepoName:  parts[1],
		CommitSHA: ev.PullRequest.Head.SHA,
		Branch:    ev.PullRequest.Head.Ref,
		PRNumber:  ev.Number,
		Status:    models.JobStatusQueued,
		CreatedAt: time.Now().UTC(),
	}

	if err := s.enqueueJob(r.Context(), job); err != nil {
		log.Printf("enqueue job: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]string{"job_id": job.ID})
}

func (s *Server) enqueueJob(ctx context.Context, job models.Job) error {
	data, _ := json.Marshal(job)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		s.cfg.AnalysisServiceURL+"/api/v1/jobs", bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("analysis service returned %d", resp.StatusCode)
	}
	return nil
}

func splitOwnerRepo(full string) [2]string {
	for i, c := range full {
		if c == '/' {
			return [2]string{full[:i], full[i+1:]}
		}
	}
	return [2]string{full, ""}
}
