package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/voxire/lint-in-the-dead/pkg/models"
)

const defaultGateway = "http://localhost:8080"

func main() {
	gateway := envOr("LITD_GATEWAY", defaultGateway)

	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "check":
		cmdCheck(os.Args[2:])
	case "scan":
		cmdScan(gateway, os.Args[2:])
	case "jobs":
		cmdJobs(gateway, os.Args[2:])
	case "job":
		cmdJob(gateway, os.Args[2:])
	case "audit":
		cmdAudit(gateway, os.Args[2:])
	case "rules":
		cmdRules(gateway, os.Args[2:])
	case "health":
		cmdHealth(gateway)
	case "version":
		fmt.Println("litd v0.1.0")
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(1)
	}
}

// ── scan ──────────────────────────────────────────────────────────────────────

func cmdScan(gateway string, args []string) {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	repoURL := fs.String("repo", "", "Git repository URL to scan (required)")
	sha := fs.String("sha", "", "Commit SHA (required)")
	branch := fs.String("branch", "main", "Branch name")
	wait := fs.Bool("wait", false, "Poll until job completes and print result")
	fs.Parse(args)

	if *repoURL == "" || *sha == "" {
		fmt.Fprintln(os.Stderr, "scan: --repo and --sha are required")
		fs.Usage()
		os.Exit(1)
	}

	body, _ := json.Marshal(map[string]string{
		"repo_url":   *repoURL,
		"commit_sha": *sha,
		"branch":     *branch,
	})

	resp, err := http.Post(gateway+"/api/v1/jobs", "application/json", bytes.NewReader(body))
	must(err, "submit job")
	defer resp.Body.Close()

	var job models.Job
	must(json.NewDecoder(resp.Body).Decode(&job), "decode response")
	fmt.Printf("job submitted: %s\n", job.ID)

	if !*wait {
		return
	}

	fmt.Print("waiting")
	analysisURL := envOr("LITD_ANALYSIS_URL", "http://localhost:8082")
	for range 60 {
		time.Sleep(3 * time.Second)
		fmt.Print(".")
		r, err := http.Get(analysisURL + "/api/v1/jobs/" + job.ID)
		if err != nil || r.StatusCode == http.StatusNotFound {
			continue
		}
		defer r.Body.Close()
		var result models.AnalysisResult
		if err := json.NewDecoder(r.Body).Decode(&result); err == nil && result.JobID != "" {
			fmt.Println()
			printResult(result)
			return
		}
	}
	fmt.Fprintln(os.Stderr, "\ntimed out waiting for result")
	os.Exit(1)
}

// ── jobs ──────────────────────────────────────────────────────────────────────

func cmdJobs(gateway string, _ []string) {
	analysisURL := envOr("LITD_ANALYSIS_URL", "http://localhost:8082")
	resp, err := http.Get(analysisURL + "/api/v1/jobs")
	must(err, "list jobs")
	defer resp.Body.Close()

	var results []models.AnalysisResult
	must(json.NewDecoder(resp.Body).Decode(&results), "decode")

	if len(results) == 0 {
		fmt.Println("no jobs found")
		return
	}

	fmt.Printf("%-36s  %-20s  %6s  %s\n", "JOB ID", "REPO", "SCORE", "PASSED")
	fmt.Println(strings.Repeat("-", 80))
	for _, r := range results {
		passed := "✅"
		if !r.Summary.Passed {
			passed = "❌"
		}
		repo := r.RepoOwner + "/" + r.RepoName
		fmt.Printf("%-36s  %-20s  %6.0f  %s\n", r.JobID, repo, r.Summary.Score, passed)
	}
}

// ── job ───────────────────────────────────────────────────────────────────────

func cmdJob(gateway string, args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "job: requires a job ID")
		os.Exit(1)
	}
	analysisURL := envOr("LITD_ANALYSIS_URL", "http://localhost:8082")
	resp, err := http.Get(analysisURL + "/api/v1/jobs/" + args[0])
	must(err, "get job")
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		fmt.Fprintf(os.Stderr, "job %s not found\n", args[0])
		os.Exit(1)
	}

	var result models.AnalysisResult
	must(json.NewDecoder(resp.Body).Decode(&result), "decode")
	printResult(result)
}

// ── audit ─────────────────────────────────────────────────────────────────────

func cmdAudit(_ string, args []string) {
	fs := flag.NewFlagSet("audit", flag.ExitOnError)
	jobID := fs.String("job", "", "Filter by job ID")
	limit := fs.Int("limit", 20, "Max entries")
	fs.Parse(args)

	auditURL := envOr("LITD_AUDIT_URL", "http://localhost:8083")
	url := fmt.Sprintf("%s/api/v1/entries?limit=%d", auditURL, *limit)
	if *jobID != "" {
		url += "&job_id=" + *jobID
	}

	resp, err := http.Get(url)
	must(err, "query audit log")
	defer resp.Body.Close()

	var entries []models.AuditEntry
	must(json.NewDecoder(resp.Body).Decode(&entries), "decode")

	if len(entries) == 0 {
		fmt.Println("no audit entries found")
		return
	}

	fmt.Printf("%-32s  %-24s  %-20s  %s\n", "ID", "JOB ID", "EVENT", "ACTOR")
	fmt.Println(strings.Repeat("-", 90))
	for _, e := range entries {
		fmt.Printf("%-32s  %-24s  %-20s  %s\n",
			truncate(e.ID, 32), truncate(e.JobID, 24), e.EventType, e.Actor)
	}
}

// ── rules ─────────────────────────────────────────────────────────────────────

func cmdRules(_ string, _ []string) {
	policyURL := envOr("LITD_POLICY_URL", "http://localhost:8081")
	resp, err := http.Get(policyURL + "/api/v1/rules")
	must(err, "list rules")
	defer resp.Body.Close()

	var rules []map[string]interface{}
	must(json.NewDecoder(resp.Body).Decode(&rules), "decode")

	fmt.Printf("%-12s  %-10s  %-8s  %s\n", "ID", "SEVERITY", "CATEGORY", "NAME")
	fmt.Println(strings.Repeat("-", 70))
	for _, r := range rules {
		fmt.Printf("%-12v  %-10v  %-8v  %v\n",
			r["id"], r["severity"], r["category"], r["name"])
	}
}

// ── health ────────────────────────────────────────────────────────────────────

func cmdHealth(gateway string) {
	services := map[string]string{
		"api-gateway":          gateway + "/healthz",
		"policy-engine":        envOr("LITD_POLICY_URL", "http://localhost:8081") + "/healthz",
		"analysis-service":     envOr("LITD_ANALYSIS_URL", "http://localhost:8082") + "/healthz",
		"audit-service":        envOr("LITD_AUDIT_URL", "http://localhost:8083") + "/healthz",
		"notification-service": envOr("LITD_NOTIF_URL", "http://localhost:8084") + "/healthz",
	}

	for name, url := range services {
		start := time.Now()
		resp, err := http.Get(url)
		latency := time.Since(start).Milliseconds()
		if err != nil {
			fmt.Printf("%-24s  ❌  unreachable (%v)\n", name, err)
			continue
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		icon := "✅"
		if resp.StatusCode >= 300 {
			icon = "❌"
		}
		fmt.Printf("%-24s  %s  %dms  HTTP %d\n", name, icon, latency, resp.StatusCode)
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

func printResult(r models.AnalysisResult) {
	status := "PASSED ✅"
	if !r.Summary.Passed {
		status = "FAILED ❌"
	}
	fmt.Printf("Job:      %s\n", r.JobID)
	fmt.Printf("Repo:     %s/%s @ %s\n", r.RepoOwner, r.RepoName, r.CommitSHA)
	fmt.Printf("Status:   %s\n", status)
	fmt.Printf("Score:    %.0f / 100\n", r.Summary.Score)
	fmt.Printf("Findings: %d total\n", r.Summary.TotalFindings)
	for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
		if n := r.Summary.BySeverity[sev]; n > 0 {
			fmt.Printf("  %-10s %d\n", sev+":", n)
		}
	}
	fmt.Printf("Duration: %dms\n", r.DurationMS)

	if len(r.Findings) > 0 {
		fmt.Println("\nTop findings:")
		limit := 15
		if len(r.Findings) < limit {
			limit = len(r.Findings)
		}
		for _, f := range r.Findings[:limit] {
			fmt.Printf("  [%s] %s:%d  %s\n", f.RuleID, f.File, f.Line, f.Message)
		}
		if len(r.Findings) > 15 {
			fmt.Printf("  … and %d more\n", len(r.Findings)-15)
		}
	}
}

func must(err error, context string) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "error %s: %v\n", context, err)
		os.Exit(1)
	}
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

func usage() {
	fmt.Fprintf(os.Stderr, `litd — Distributed Code Quality & Compliance CLI

Usage:
  litd <command> [flags]

Commands:
  scan    Submit a repository for analysis
  jobs    List all completed analysis results
  job     Show detailed result for a single job ID
  audit   Query the immutable audit log
  rules   List all loaded policy rules
  health  Check health of all services
  version Print version

Environment:
  LITD_GATEWAY      API gateway URL    (default: http://localhost:8080)
  LITD_ANALYSIS_URL Analysis svc URL   (default: http://localhost:8082)
  LITD_POLICY_URL   Policy engine URL  (default: http://localhost:8081)
  LITD_AUDIT_URL    Audit service URL  (default: http://localhost:8083)
  LITD_NOTIF_URL    Notif service URL  (default: http://localhost:8084)

Examples:
  litd check ./                                  # scan current directory
  litd check --rules ./configs/rules --format gh # GitHub Actions annotations
  litd scan --repo https://github.com/org/repo --sha abc123 --wait
  litd jobs
  litd job <job-id>
  litd audit --job <job-id>
  litd rules
  litd health
`)
}
