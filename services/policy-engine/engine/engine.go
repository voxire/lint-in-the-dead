package engine

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/voxire/lint-in-the-dead/pkg/metrics"
	"github.com/voxire/lint-in-the-dead/pkg/models"
	"github.com/voxire/lint-in-the-dead/pkg/rules"
)

// Engine holds compiled rules and serves evaluation requests.
type Engine struct {
	rules      []rules.Rule
	evaluator  *rules.Evaluator
	mux        *http.ServeMux
	listenAddr string
	reg        *metrics.Registry
}

func New(listenAddr, rulesDir string) (*Engine, error) {
	loaded, err := LoadRules(rulesDir)
	if err != nil {
		// Non-fatal: start with zero rules if dir is missing in dev.
		log.Printf("policy-engine: rules load warning: %v", err)
		loaded = nil
	}

	eval, err := rules.NewEvaluator(loaded)
	if err != nil {
		return nil, fmt.Errorf("compile rules: %w", err)
	}

	reg := metrics.NewRegistry("policy_engine")
	reg.Gauge("rules_loaded").Set(int64(len(loaded)))

	e := &Engine{
		rules:      loaded,
		evaluator:  eval,
		mux:        http.NewServeMux(),
		listenAddr: listenAddr,
		reg:        reg,
	}
	e.routes()
	return e, nil
}

func (e *Engine) routes() {
	e.mux.HandleFunc("GET /healthz", healthHandler)
	e.mux.HandleFunc("GET /metrics", e.reg.Handler())
	e.mux.HandleFunc("POST /api/v1/evaluate", e.evaluateHandler)
	e.mux.HandleFunc("GET /api/v1/rules", e.listRulesHandler)
}

func (e *Engine) Start() error {
	log.Printf("policy-engine listening on %s (%d rules loaded)", e.listenAddr, len(e.rules))
	return http.ListenAndServe(e.listenAddr, e.mux)
}

// EvaluateRequest is the body sent to POST /api/v1/evaluate.
type EvaluateRequest struct {
	JobID string             `json:"job_id"`
	Files []rules.FileContent `json:"files"`
}

func (e *Engine) evaluateHandler(w http.ResponseWriter, r *http.Request) {
	e.reg.Counter("evaluations_total").Inc()
	start := timeNow()

	var req EvaluateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}

	findings := e.evaluator.Evaluate(req.Files)
	e.reg.Histogram("evaluation_duration_ms").Observe(float64(timeNow() - start))
	result := models.PolicyResult{
		JobID:   req.JobID,
		Allowed: true,
		Rules:   make([]models.RuleMatch, 0, len(e.rules)),
	}

	for _, f := range findings {
		if f.Severity == models.SeverityCritical || f.Severity == models.SeverityHigh {
			result.Blocked = true
			result.Allowed = false
			result.Errors = append(result.Errors, fmt.Sprintf("[%s] %s at %s:%d", f.RuleID, f.Message, f.File, f.Line))
		} else {
			result.Warnings = append(result.Warnings, fmt.Sprintf("[%s] %s at %s:%d", f.RuleID, f.Message, f.File, f.Line))
		}
		result.Rules = append(result.Rules, models.RuleMatch{
			RuleID:  f.RuleID,
			Matched: true,
			Reason:  f.Message,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func (e *Engine) listRulesHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(e.rules)
}

func timeNow() int64 {
	return time.Now().UnixMilli()
}

func healthHandler(w http.ResponseWriter, _ *http.Request) {
	hostname, _ := os.Hostname()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok", "host": hostname})
}
