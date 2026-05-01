package server

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/voxire/lint-in-the-dead/pkg/models"
)

// ListJobsHandler proxies job listing from the analysis service.
func (s *Server) ListJobsHandler(w http.ResponseWriter, r *http.Request) {
	resp, err := http.Get(s.cfg.AnalysisServiceURL + "/api/v1/jobs")
	if err != nil {
		http.Error(w, "analysis service unavailable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	json.NewDecoder(resp.Body).Decode(new(interface{})) // drain
}

// SubmitJobHandler accepts a manual job submission.
func (s *Server) SubmitJobHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RepoURL   string `json:"repo_url"`
		CommitSHA string `json:"commit_sha"`
		Branch    string `json:"branch"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	if req.RepoURL == "" || req.CommitSHA == "" {
		http.Error(w, "repo_url and commit_sha required", http.StatusBadRequest)
		return
	}

	job := models.Job{
		ID:        newID(),
		Source:    models.JobSourceManual,
		RepoURL:   req.RepoURL,
		CommitSHA: req.CommitSHA,
		Branch:    req.Branch,
		Status:    models.JobStatusQueued,
		CreatedAt: time.Now().UTC(),
	}

	if err := s.enqueueJob(r.Context(), job); err != nil {
		http.Error(w, "failed to enqueue", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(job)
}

// HealthHandler returns a simple health-check response.
func HealthHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}
