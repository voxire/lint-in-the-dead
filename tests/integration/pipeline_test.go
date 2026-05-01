// Package integration wires together the pkg layer and verifies the full
// analysis pipeline: rule evaluation → entropy scanning → dep scanning →
// summary scoring.  No real network or Docker required.
package integration_test

import (
	"testing"
	"time"

	"github.com/voxire/lint-in-the-dead/pkg/cache"
	"github.com/voxire/lint-in-the-dead/pkg/deps"
	"github.com/voxire/lint-in-the-dead/pkg/entropy"
	"github.com/voxire/lint-in-the-dead/pkg/models"
	"github.com/voxire/lint-in-the-dead/pkg/rules"
	"github.com/voxire/lint-in-the-dead/pkg/signing"
)

// ── helpers ──────────────────────────────────────────────────────────────────

func mustEvaluator(t *testing.T, rs []rules.Rule) *rules.Evaluator {
	t.Helper()
	e, err := rules.NewEvaluator(rs)
	if err != nil {
		t.Fatalf("NewEvaluator: %v", err)
	}
	return e
}

func runPipeline(t *testing.T, files []rules.FileContent) models.AnalysisResult {
	t.Helper()

	// 1. Rule evaluation
	loaded := securityAndQualityRules()
	evaluator := mustEvaluator(t, loaded)
	findings := evaluator.Evaluate(files)

	// 2. Entropy scan
	for _, f := range files {
		ef := entropy.Scan(f.Path, f.Content, entropy.DefaultThreshold)
		findings = append(findings, entropy.ToModelFindings(ef)...)
	}

	// 3. Dependency scan
	for _, f := range files {
		m, _ := deps.ScanFile(f.Path, f.Content)
		if m == nil {
			continue
		}
		for _, d := range m.Deps {
			if d.Version == "" {
				findings = append(findings, models.Finding{
					RuleID:   "DEP-001",
					Category: models.CategoryCompliance,
					Severity: models.SeverityMedium,
					File:     f.Path,
					Line:     1,
					Message:  "Unpinned dependency: " + d.Name,
				})
			}
		}
	}

	summary := models.NewSummary(findings)
	return models.AnalysisResult{
		JobID:     "test-job-001",
		RepoOwner: "testorg",
		RepoName:  "testrepo",
		CommitSHA: "deadbeef",
		Findings:  findings,
		Summary:   summary,
	}
}

// securityAndQualityRules returns a minimal inline rule set for testing.
func securityAndQualityRules() []rules.Rule {
	return []rules.Rule{
		{
			ID: "SEC-TEST-001", Name: "Hardcoded password", Enabled: true,
			Category: "security", Severity: "critical",
			Languages: []string{"*"},
			Pattern:   rules.Pattern{Type: "regex", Match: `(?i)password\s*=\s*["'][^"']{4,}["']`},
			Message:   "Hardcoded password",
		},
		{
			ID: "QUAL-TEST-001", Name: "Debug print", Enabled: true,
			Category: "quality", Severity: "low",
			Languages: []string{"go"},
			Pattern:   rules.Pattern{Type: "regex", Match: `fmt\.Println\(`},
			Message:   "Debug print left in code",
		},
		{
			ID: "SEC-TEST-002", Name: "eval() usage", Enabled: true,
			Category: "security", Severity: "high",
			Languages: []string{"javascript"},
			Pattern:   rules.Pattern{Type: "regex", Match: `\beval\s*\(`},
			Message:   "eval() is dangerous",
		},
	}
}

// ── tests ─────────────────────────────────────────────────────────────────────

func TestPipeline_CleanCode_Passes(t *testing.T) {
	files := []rules.FileContent{
		{Path: "main.go", Language: "go", Content: `package main

func main() {
	// nothing suspicious here
}
`},
	}
	result := runPipeline(t, files)
	if !result.Summary.Passed {
		t.Errorf("expected clean code to pass, got score=%.0f findings=%d",
			result.Summary.Score, result.Summary.TotalFindings)
	}
	if result.Summary.Score < 90 {
		t.Errorf("expected high score for clean code, got %.0f", result.Summary.Score)
	}
}

func TestPipeline_HardcodedPassword_Fails(t *testing.T) {
	files := []rules.FileContent{
		{Path: "config.go", Language: "go", Content: `package main

const password = "supersecret123"
var dbPassword = "hunter2_production"
`},
	}
	result := runPipeline(t, files)
	if result.Summary.Passed {
		t.Error("expected hardcoded password to fail the scan")
	}
	if result.Summary.BySeverity["critical"] == 0 {
		t.Error("expected at least one critical finding")
	}
}

func TestPipeline_JSEval_MarkedHigh(t *testing.T) {
	files := []rules.FileContent{
		{Path: "app.js", Language: "javascript", Content: "eval(userInput);\n"},
	}
	result := runPipeline(t, files)
	if result.Summary.BySeverity["high"] == 0 {
		t.Error("expected high-severity finding for eval()")
	}
}

func TestPipeline_DebugPrint_DoesNotFail(t *testing.T) {
	// Low-severity findings should not cause Passed=false.
	files := []rules.FileContent{
		{Path: "debug.go", Language: "go", Content: `package main
import "fmt"
func foo() { fmt.Println("debug") }
`},
	}
	result := runPipeline(t, files)
	if !result.Summary.Passed {
		t.Error("low-severity debug print should not fail the build")
	}
	if result.Summary.BySeverity["low"] == 0 {
		t.Error("expected a low-severity finding for debug print")
	}
}

func TestPipeline_MultipleFiles_AggregatesCorrectly(t *testing.T) {
	files := []rules.FileContent{
		{Path: "a.go", Language: "go", Content: `package a
import "fmt"
func a() { fmt.Println("a") }
`},
		{Path: "b.go", Language: "go", Content: `package b
import "fmt"
func b() { fmt.Println("b") }
`},
		{Path: "c.js", Language: "javascript", Content: "eval(x);\n"},
	}
	result := runPipeline(t, files)
	if result.Summary.TotalFindings < 3 {
		t.Errorf("expected at least 3 findings across files, got %d", result.Summary.TotalFindings)
	}
}

func TestPipeline_UnpinnedDep_MediumFinding(t *testing.T) {
	files := []rules.FileContent{
		{Path: "requirements.txt", Language: "unknown", Content: "flask\nrequests==2.28.0\n"},
	}
	result := runPipeline(t, files)
	if result.Summary.BySeverity["medium"] == 0 {
		t.Error("expected medium finding for unpinned flask dependency")
	}
}

func TestPipeline_ScoreDecay(t *testing.T) {
	// 1 critical = -20, 1 high = -10 → score = 70
	files := []rules.FileContent{
		{Path: "bad.go", Language: "go", Content: `const password = "hunter2_production"` + "\n"},
		{Path: "app.js", Language: "javascript", Content: "eval(x);\n"},
	}
	result := runPipeline(t, files)
	if result.Summary.Score >= 100 {
		t.Error("score should be reduced for findings")
	}
}

// ── signing integration ───────────────────────────────────────────────────────

func TestSigningRoundTrip(t *testing.T) {
	payload := `{"job_id":"abc","event_type":"analysis_complete"}`
	sig := signing.Sign("integration-secret", payload)
	if !signing.Verify("integration-secret", payload, sig) {
		t.Error("signing round-trip failed")
	}
	if signing.Verify("wrong-secret", payload, sig) {
		t.Error("signature verified with wrong secret")
	}
}

// ── cache integration ─────────────────────────────────────────────────────────

func TestCacheIntegration_StoreAndRetrieveResult(t *testing.T) {
	c := cache.New[string, models.AnalysisResult](5 * time.Minute)

	files := []rules.FileContent{
		{Path: "main.go", Language: "go", Content: "package main\n"},
	}
	result := runPipeline(t, files)

	key := "testorg/testrepo@deadbeef"
	c.Set(key, result)

	got, ok := c.Get(key)
	if !ok {
		t.Fatal("expected cached result, got miss")
	}
	if got.JobID != result.JobID {
		t.Errorf("cached JobID mismatch: %q vs %q", got.JobID, result.JobID)
	}
}
