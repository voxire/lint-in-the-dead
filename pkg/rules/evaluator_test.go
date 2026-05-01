package rules_test

import (
	"testing"

	"github.com/voxire/lint-in-the-dead/pkg/models"
	"github.com/voxire/lint-in-the-dead/pkg/rules"
)

func makeEvaluator(t *testing.T, rs []rules.Rule) *rules.Evaluator {
	t.Helper()
	e, err := rules.NewEvaluator(rs)
	if err != nil {
		t.Fatalf("NewEvaluator: %v", err)
	}
	return e
}

func TestEvaluator_RegexMatch(t *testing.T) {
	r := rules.Rule{
		ID:        "TEST-001",
		Name:      "No eval",
		Category:  "security",
		Severity:  "high",
		Languages: []string{"javascript"},
		Enabled:   true,
		Pattern:   rules.Pattern{Type: "regex", Match: `\beval\s*\(`},
		Message:   "eval detected",
	}

	e := makeEvaluator(t, []rules.Rule{r})
	files := []rules.FileContent{
		{Path: "app.js", Language: "javascript", Content: "eval(userInput);\n"},
	}

	findings := e.Evaluate(files)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.RuleID != "TEST-001" {
		t.Errorf("rule ID: got %q, want TEST-001", f.RuleID)
	}
	if f.Line != 1 {
		t.Errorf("line: got %d, want 1", f.Line)
	}
	if f.Severity != models.SeverityHigh {
		t.Errorf("severity: got %q, want high", f.Severity)
	}
}

func TestEvaluator_NoMatchWhenDisabled(t *testing.T) {
	r := rules.Rule{
		ID:        "TEST-002",
		Name:      "Disabled rule",
		Languages: []string{"*"},
		Enabled:   false,
		Pattern:   rules.Pattern{Type: "regex", Match: `password`},
		Message:   "should not fire",
	}
	e := makeEvaluator(t, []rules.Rule{r})
	files := []rules.FileContent{
		{Path: "config.go", Language: "go", Content: "password = \"secret\"\n"},
	}
	if got := e.Evaluate(files); len(got) != 0 {
		t.Errorf("expected 0 findings for disabled rule, got %d", len(got))
	}
}

func TestEvaluator_LanguageFilter(t *testing.T) {
	r := rules.Rule{
		ID:        "TEST-003",
		Name:      "Go-only rule",
		Languages: []string{"go"},
		Enabled:   true,
		Pattern:   rules.Pattern{Type: "regex", Match: `panic\(`},
		Message:   "panic detected",
	}
	e := makeEvaluator(t, []rules.Rule{r})

	files := []rules.FileContent{
		{Path: "main.go", Language: "go", Content: "panic(\"oh no\")\n"},
		{Path: "app.js", Language: "javascript", Content: "panic(\"oh no\")\n"},
	}
	findings := e.Evaluate(files)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding (go only), got %d", len(findings))
	}
	if findings[0].File != "main.go" {
		t.Errorf("expected finding in main.go, got %q", findings[0].File)
	}
}

func TestEvaluator_WildcardLanguage(t *testing.T) {
	r := rules.Rule{
		ID:        "TEST-004",
		Name:      "Universal rule",
		Languages: []string{"*"},
		Enabled:   true,
		Pattern:   rules.Pattern{Type: "regex", Match: `TODO.*security`},
		Message:   "security TODO",
	}
	e := makeEvaluator(t, []rules.Rule{r})

	files := []rules.FileContent{
		{Path: "a.go", Language: "go", Content: "// TODO security fix\n"},
		{Path: "b.py", Language: "python", Content: "# TODO security fix\n"},
		{Path: "c.rs", Language: "rust", Content: "// TODO security fix\n"},
	}
	findings := e.Evaluate(files)
	if len(findings) != 3 {
		t.Errorf("expected 3 findings (wildcard), got %d", len(findings))
	}
}

func TestEvaluator_NegatePattern(t *testing.T) {
	r := rules.Rule{
		ID:        "TEST-005",
		Name:      "Must have license",
		Languages: []string{"go"},
		Enabled:   true,
		Pattern:   rules.Pattern{Type: "regex", Match: `SPDX-License-Identifier`, Negate: true},
		Message:   "missing license header",
	}
	e := makeEvaluator(t, []rules.Rule{r})

	// This file has the identifier — negate means no finding.
	withLicense := rules.FileContent{
		Path: "good.go", Language: "go",
		Content: "// SPDX-License-Identifier: MIT\npackage main\n",
	}
	// This file lacks it — negate means finding.
	withoutLicense := rules.FileContent{
		Path: "bad.go", Language: "go",
		Content: "package main\n",
	}

	withFindings := e.Evaluate([]rules.FileContent{withLicense})
	if len(withFindings) != 0 {
		t.Errorf("expected 0 findings for file with license, got %d", len(withFindings))
	}

	withoutFindings := e.Evaluate([]rules.FileContent{withoutLicense})
	if len(withoutFindings) != 1 {
		t.Errorf("expected 1 finding for file without license, got %d", len(withoutFindings))
	}
}

func TestEvaluator_MultipleFindings(t *testing.T) {
	r := rules.Rule{
		ID:        "TEST-006",
		Languages: []string{"*"},
		Enabled:   true,
		Pattern:   rules.Pattern{Type: "regex", Match: `secret\s*=`},
		Message:   "hardcoded secret",
		Severity:  "critical",
		Category:  "security",
	}
	e := makeEvaluator(t, []rules.Rule{r})

	content := "secret = \"abc\"\nfoo = 1\nsecret = \"xyz\"\n"
	files := []rules.FileContent{{Path: "cfg.go", Language: "go", Content: content}}

	findings := e.Evaluate(files)
	if len(findings) != 2 {
		t.Errorf("expected 2 findings, got %d", len(findings))
	}
	if findings[0].Line != 1 || findings[1].Line != 3 {
		t.Errorf("unexpected lines: %d, %d", findings[0].Line, findings[1].Line)
	}
}

func TestEvaluator_InvalidRegexReturnsError(t *testing.T) {
	r := rules.Rule{
		ID:      "BAD-001",
		Enabled: true,
		Pattern: rules.Pattern{Type: "regex", Match: `[invalid`},
	}
	_, err := rules.NewEvaluator([]rules.Rule{r})
	if err == nil {
		t.Error("expected error for invalid regex, got nil")
	}
}
