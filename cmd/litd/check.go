package main

// cmdCheck runs the full analysis pipeline entirely in-process — no running
// services required. Useful for CI, local pre-commit hooks, and self-analysis.

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/voxire/lint-in-the-dead/pkg/deps"
	"github.com/voxire/lint-in-the-dead/pkg/entropy"
	"github.com/voxire/lint-in-the-dead/pkg/models"
	"github.com/voxire/lint-in-the-dead/pkg/rules"
)

func cmdCheck(args []string) {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	rulesDir  := fs.String("rules", defaultRulesDir(), "Directory containing YAML rule files")
	format    := fs.String("format", "text", `Output format: "text" | "gh" (GitHub Actions annotations) | "json"`)
	threshold := fs.Float64("entropy-threshold", entropy.DefaultThreshold, "Shannon entropy threshold for secret detection")
	maxFinds  := fs.Int("max-findings", 0, "Limit output to N findings (0 = all)")
	noEntropy := fs.Bool("no-entropy", false, "Disable entropy-based secret scanning")
	noDeps    := fs.Bool("no-deps", false, "Disable dependency lockfile scanning")
	failOn    := fs.String("fail-on", "high", `Minimum severity that causes non-zero exit: "critical" | "high" | "medium" | "low" | "never"`)
	fs.Parse(args)

	dir := "."
	if fs.NArg() > 0 {
		dir = fs.Arg(0)
	}

	// ── 1. Load rules ───────────────────────────────────────────────────────
	loaded, err := rules.LoadDir(*rulesDir)
	if err != nil {
		// Non-fatal: warn and continue with zero rules (entropy + deps still run).
		fmt.Fprintf(os.Stderr, "warn: could not load rules from %q: %v\n", *rulesDir, err)
		loaded = nil
	}
	evaluator, err := rules.NewEvaluator(loaded)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: compile rules: %v\n", err)
		os.Exit(2)
	}

	// ── 2. Walk files ────────────────────────────────────────────────────────
	files, err := walkFiles(dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: walk %q: %v\n", dir, err)
		os.Exit(2)
	}

	// ── 3. Run analysers ─────────────────────────────────────────────────────
	var findings []models.Finding

	findings = append(findings, evaluator.Evaluate(files)...)

	if !*noEntropy {
		for _, f := range files {
			ef := entropy.Scan(f.Path, f.Content, *threshold)
			findings = append(findings, entropy.ToModelFindings(ef)...)
		}
	}

	if !*noDeps {
		for _, f := range files {
			m, _ := deps.ScanFile(f.Path, f.Content)
			if m == nil {
				continue
			}
			for _, d := range m.Deps {
				if d.Version == "" {
					findings = append(findings, models.Finding{
						RuleID:        "DEP-001",
						RuleName:      "Unpinned dependency",
						Category:      models.CategoryCompliance,
						Severity:      models.SeverityMedium,
						File:          f.Path,
						Line:          1,
						Column:        1,
						Message:       "Unpinned dependency: " + d.Name,
						FixSuggestion: "Pin to an exact version for reproducible builds.",
					})
				}
			}
		}
	}

	// ── 4. Apply limit ───────────────────────────────────────────────────────
	if *maxFinds > 0 && len(findings) > *maxFinds {
		findings = findings[:*maxFinds]
	}

	summary := models.NewSummary(findings)

	// ── 5. Output ────────────────────────────────────────────────────────────
	switch *format {
	case "gh":
		printGHAnnotations(findings)
	case "json":
		printJSON(models.AnalysisResult{Findings: findings, Summary: summary})
	default:
		printTextReport(findings, summary, dir)
	}

	// ── 6. Exit code ─────────────────────────────────────────────────────────
	os.Exit(exitCode(summary, *failOn))
}

// ── output formatters ────────────────────────────────────────────────────────

func printGHAnnotations(findings []models.Finding) {
	for _, f := range findings {
		level := "warning"
		if f.Severity == models.SeverityCritical || f.Severity == models.SeverityHigh {
			level = "error"
		} else if f.Severity == models.SeverityInfo {
			level = "notice"
		}
		// GitHub Actions workflow command syntax.
		fmt.Printf("::%s file=%s,line=%d,col=%d,title=[%s] %s::%s\n",
			level, f.File, f.Line, f.Column, f.RuleID, f.RuleName, f.Message)
	}
}

func printJSON(result models.AnalysisResult) {
	printJSON_inner(result)
}

func printJSON_inner(v interface{}) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(v) //nolint:errcheck
}

func printTextReport(findings []models.Finding, summary models.Summary, dir string) {
	statusIcon := "✅ PASSED"
	if !summary.Passed {
		statusIcon = "❌ FAILED"
	}

	fmt.Printf("lint-in-the-dead — %s\n", statusIcon)
	fmt.Printf("Directory:  %s\n", dir)
	fmt.Printf("Score:      %.0f / 100\n", summary.Score)
	fmt.Printf("Findings:   %d total\n\n", summary.TotalFindings)

	for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
		if n := summary.BySeverity[sev]; n > 0 {
			fmt.Printf("  %-10s %d\n", sev+":", n)
		}
	}

	if len(findings) == 0 {
		fmt.Println("\nNo findings. 🎉")
		return
	}

	fmt.Println("\nFindings:")
	fmt.Println(strings.Repeat("─", 80))
	for _, f := range findings {
		sevLabel := fmt.Sprintf("[%s]", strings.ToUpper(string(f.Severity)))
		fmt.Printf("%-10s %s:%d  [%s] %s\n", sevLabel, f.File, f.Line, f.RuleID, f.Message)
		if f.Snippet != "" {
			fmt.Printf("           %s\n", f.Snippet)
		}
	}
}

// ── helpers ──────────────────────────────────────────────────────────────────

func walkFiles(root string) ([]rules.FileContent, error) {
	var files []rules.FileContent
	skipDirs := map[string]bool{
		".git": true, "node_modules": true, "vendor": true,
		".cache": true, "dist": true, "bin": true,
	}
	binaryExts := map[string]bool{
		".png": true, ".jpg": true, ".jpeg": true, ".gif": true,
		".pdf": true, ".zip": true, ".tar": true, ".gz": true,
		".exe": true, ".bin": true, ".so": true, ".dll": true,
		".wasm": true, ".class": true, ".jar": true,
	}

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			if skipDirs[info.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if binaryExts[ext] {
			return nil
		}
		if info.Size() > 1<<20 { // skip files > 1 MiB
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		files = append(files, rules.FileContent{
			Path:     rel,
			Language: detectLang(ext),
			Content:  string(data),
		})
		return nil
	})
	return files, err
}

var extToLang = map[string]string{
	".go": "go", ".ts": "typescript", ".tsx": "typescript",
	".js": "javascript", ".jsx": "javascript", ".mjs": "javascript",
	".py": "python", ".rs": "rust", ".java": "java",
	".kt": "kotlin", ".cs": "csharp", ".cpp": "cpp",
	".c": "c", ".rb": "ruby", ".php": "php",
	".swift": "swift", ".sh": "bash", ".bash": "bash",
	".yaml": "yaml", ".yml": "yaml", ".json": "json",
	".tf": "terraform", ".hcl": "hcl", ".sql": "sql",
}

func detectLang(ext string) string {
	if l, ok := extToLang[ext]; ok {
		return l
	}
	return "unknown"
}

func defaultRulesDir() string {
	// Walk upwards from the binary looking for configs/rules.
	cwd, _ := os.Getwd()
	for _, candidate := range []string{
		filepath.Join(cwd, "configs", "rules"),
		filepath.Join(cwd, "..", "configs", "rules"),
		filepath.Join(cwd, "..", "..", "configs", "rules"),
	} {
		if fi, err := os.Stat(candidate); err == nil && fi.IsDir() {
			return candidate
		}
	}
	return "configs/rules"
}

func exitCode(s models.Summary, failOn string) int {
	switch failOn {
	case "never":
		return 0
	case "critical":
		if s.BySeverity["critical"] > 0 {
			return 1
		}
	case "high", "":
		if s.BySeverity["critical"]+s.BySeverity["high"] > 0 {
			return 1
		}
	case "medium":
		if s.BySeverity["critical"]+s.BySeverity["high"]+s.BySeverity["medium"] > 0 {
			return 1
		}
	case "low":
		if s.TotalFindings > 0 {
			return 1
		}
	}
	return 0
}
