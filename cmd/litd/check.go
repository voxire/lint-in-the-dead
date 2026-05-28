package main

// cmdCheck runs the full analysis pipeline entirely in-process — no running
// services required. Useful for CI, local pre-commit hooks, and self-analysis.

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/voxire/lint-in-the-dead/pkg/deps"
	"github.com/voxire/lint-in-the-dead/pkg/entropy"
	"github.com/voxire/lint-in-the-dead/pkg/models"
	"github.com/voxire/lint-in-the-dead/pkg/rules"
	"gopkg.in/yaml.v3"
)

// litdConfig is the schema for .litd.yaml project configuration.
// CLI flags always override values set here.
type litdConfig struct {
	RulesDir         string   `yaml:"rules_dir"`
	Format           string   `yaml:"format"`
	FailOn           string   `yaml:"fail_on"`
	EntropyThreshold float64  `yaml:"entropy_threshold"`
	NoEntropy        bool     `yaml:"no_entropy"`
	NoDeps           bool     `yaml:"no_deps"`
	Exclude          []string `yaml:"exclude"`
}

func loadProjectConfig(dir string) litdConfig {
	data, err := os.ReadFile(filepath.Join(dir, ".litd.yaml"))
	if err != nil {
		return litdConfig{}
	}
	var cfg litdConfig
	yaml.Unmarshal(data, &cfg) //nolint:errcheck
	return cfg
}

func cmdCheck(args []string) {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	rulesDir := fs.String("rules", "", "Directory containing YAML rule files (default: configs/rules or .litd.yaml)")
	format := fs.String("format", "", `Output format: "text" | "gh" | "json" | "sarif"`)
	threshold := fs.Float64("entropy-threshold", 0, "Shannon entropy threshold (0 = use config or default 4.5)")
	maxFinds := fs.Int("max-findings", 0, "Limit output to N findings (0 = all)")
	noEntropy := fs.Bool("no-entropy", false, "Disable entropy-based secret scanning")
	noDeps := fs.Bool("no-deps", false, "Disable dependency lockfile scanning")
	failOn := fs.String("fail-on", "", `Minimum severity for non-zero exit: "critical"|"high"|"medium"|"low"|"never"`)
	exclude := fs.String("exclude", "", "Comma-separated path prefixes to skip")
	changed := fs.Bool("changed", false, "Only scan files changed since last commit (requires git)")
	fs.Parse(args)

	dir := "."
	if fs.NArg() > 0 {
		dir = fs.Arg(0)
	}

	// ── 0. Merge .litd.yaml config (CLI flags win) ───────────────────────────
	cfg := loadProjectConfig(dir)
	if *rulesDir == "" {
		if cfg.RulesDir != "" {
			*rulesDir = cfg.RulesDir
		} else {
			*rulesDir = defaultRulesDir()
		}
	}
	if *format == "" {
		if cfg.Format != "" {
			*format = cfg.Format
		} else {
			*format = "text"
		}
	}
	if *failOn == "" {
		if cfg.FailOn != "" {
			*failOn = cfg.FailOn
		} else {
			*failOn = "high"
		}
	}
	if *threshold == 0 {
		if cfg.EntropyThreshold != 0 {
			*threshold = cfg.EntropyThreshold
		} else {
			*threshold = entropy.DefaultThreshold
		}
	}
	if cfg.NoEntropy {
		*noEntropy = true
	}
	if cfg.NoDeps {
		*noDeps = true
	}
	// Merge exclude lists
	excludePrefixes := cfg.Exclude
	if *exclude != "" {
		for _, p := range strings.Split(*exclude, ",") {
			excludePrefixes = append(excludePrefixes, strings.TrimSpace(p))
		}
	}

	// ── 1. Load rules ────────────────────────────────────────────────────────
	loaded, err := rules.LoadDir(*rulesDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warn: could not load rules from %q: %v\n", *rulesDir, err)
		loaded = nil
	}
	evaluator, err := rules.NewEvaluator(loaded)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: compile rules: %v\n", err)
		os.Exit(2)
	}

	// ── 2. Collect files ─────────────────────────────────────────────────────
	var files []rules.FileContent
	if *changed {
		files, err = changedFiles(dir)
	} else {
		files, err = walkFiles(dir)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: collect files: %v\n", err)
		os.Exit(2)
	}

	// Apply exclude prefixes
	if len(excludePrefixes) > 0 {
		var kept []rules.FileContent
		for _, f := range files {
			skip := false
			for _, p := range excludePrefixes {
				if p != "" && strings.HasPrefix(f.Path, p) {
					skip = true
					break
				}
			}
			if !skip {
				kept = append(kept, f)
			}
		}
		files = kept
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
	case "sarif":
		printSARIF(findings, loaded)
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
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(result) //nolint:errcheck
}

// printSARIF emits SARIF 2.1.0 — consumable by GitHub Advanced Security
// (upload-sarif action) and any SARIF-aware viewer.
func printSARIF(findings []models.Finding, loaded []rules.Rule) {
	type sarifMessage struct {
		Text string `json:"text"`
	}
	type sarifLocation struct {
		PhysicalLocation struct {
			ArtifactLocation struct {
				URI string `json:"uri"`
			} `json:"artifactLocation"`
			Region struct {
				StartLine   int `json:"startLine"`
				StartColumn int `json:"startColumn"`
			} `json:"region"`
		} `json:"physicalLocation"`
	}
	type sarifResult struct {
		RuleID    string          `json:"ruleId"`
		Level     string          `json:"level"`
		Message   sarifMessage    `json:"message"`
		Locations []sarifLocation `json:"locations"`
	}
	type sarifRule struct {
		ID               string       `json:"id"`
		Name             string       `json:"name"`
		ShortDescription sarifMessage `json:"shortDescription"`
	}
	type sarifDriver struct {
		Name           string      `json:"name"`
		Version        string      `json:"version"`
		InformationURI string      `json:"informationUri"`
		Rules          []sarifRule `json:"rules"`
	}
	type sarifTool struct {
		Driver sarifDriver `json:"driver"`
	}
	type sarifRun struct {
		Tool    sarifTool     `json:"tool"`
		Results []sarifResult `json:"results"`
	}
	type sarifRoot struct {
		Schema  string     `json:"$schema"`
		Version string     `json:"version"`
		Runs    []sarifRun `json:"runs"`
	}

	severityToLevel := map[models.Severity]string{
		models.SeverityCritical: "error",
		models.SeverityHigh:     "error",
		models.SeverityMedium:   "warning",
		models.SeverityLow:      "note",
		models.SeverityInfo:     "note",
	}

	var sarifRules []sarifRule
	for _, r := range loaded {
		sarifRules = append(sarifRules, sarifRule{
			ID:               r.ID,
			Name:             r.Name,
			ShortDescription: sarifMessage{Text: r.Message},
		})
	}

	var results []sarifResult
	for _, f := range findings {
		var loc sarifLocation
		loc.PhysicalLocation.ArtifactLocation.URI = f.File
		loc.PhysicalLocation.Region.StartLine = f.Line
		loc.PhysicalLocation.Region.StartColumn = f.Column

		level := severityToLevel[f.Severity]
		if level == "" {
			level = "warning"
		}
		results = append(results, sarifResult{
			RuleID:    f.RuleID,
			Level:     level,
			Message:   sarifMessage{Text: f.Message},
			Locations: []sarifLocation{loc},
		})
	}

	run := sarifRun{Results: results}
	run.Tool.Driver = sarifDriver{
		Name:           "litd",
		Version:        "0.1.0",
		InformationURI: "https://github.com/voxire/lint-in-the-dead",
		Rules:          sarifRules,
	}

	out := sarifRoot{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs:    []sarifRun{run},
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(out) //nolint:errcheck
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

// changedFiles returns only files that differ from the last commit.
func changedFiles(root string) ([]rules.FileContent, error) {
	out, err := exec.Command("git", "-C", root, "diff", "--name-only", "HEAD").Output()
	if err != nil {
		// Fall back to all files if git isn't available.
		return walkFiles(root)
	}
	// Also include staged files.
	staged, _ := exec.Command("git", "-C", root, "diff", "--name-only", "--cached").Output()
	pathSet := make(map[string]bool)
	for _, line := range strings.Split(strings.TrimSpace(string(out))+"\n"+strings.TrimSpace(string(staged)), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			pathSet[line] = true
		}
	}

	var files []rules.FileContent
	for rel := range pathSet {
		abs := filepath.Join(root, rel)
		data, err := os.ReadFile(abs)
		if err != nil {
			continue
		}
		ext := strings.ToLower(filepath.Ext(rel))
		files = append(files, rules.FileContent{
			Path:     rel,
			Language: detectLang(ext),
			Content:  string(data),
		})
	}
	return files, nil
}

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
