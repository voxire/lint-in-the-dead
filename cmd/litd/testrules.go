package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/voxire/lint-in-the-dead/pkg/rules"
)

func cmdTestRules(args []string) {
	fs := flag.NewFlagSet("test-rules", flag.ExitOnError)
	rulesDir := fs.String("rules", defaultRulesDir(), "Directory containing YAML rule files")
	fs.Parse(args)

	loaded, err := rules.LoadDir(*rulesDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: load rules: %v\n", err)
		os.Exit(2)
	}

	evaluator, err := rules.NewEvaluator(loaded)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: compile rules: %v\n", err)
		os.Exit(2)
	}

	total, passed, failed := 0, 0, 0
	for _, r := range loaded {
		if len(r.Tests.Pass)+len(r.Tests.Fail) == 0 {
			continue
		}
		for i, snippet := range r.Tests.Pass {
			total++
			fc := rules.FileContent{Path: fmt.Sprintf("%s/pass-%d", r.ID, i), Language: primaryLang(r.Languages), Content: snippet}
			findings := evaluator.EvaluateOne(r, fc)
			if len(findings) == 0 {
				passed++
			} else {
				failed++
				fmt.Printf("FAIL  %s  pass[%d]: rule fired unexpectedly\n       snippet: %q\n", r.ID, i, snippet)
			}
		}
		for i, snippet := range r.Tests.Fail {
			total++
			fc := rules.FileContent{Path: fmt.Sprintf("%s/fail-%d", r.ID, i), Language: primaryLang(r.Languages), Content: snippet}
			findings := evaluator.EvaluateOne(r, fc)
			if len(findings) > 0 {
				passed++
			} else {
				failed++
				fmt.Printf("FAIL  %s  fail[%d]: rule did not fire\n       snippet: %q\n", r.ID, i, snippet)
			}
		}
	}

	if total == 0 {
		fmt.Println("no rule tests defined (add tests.pass/tests.fail to your YAML rules)")
		os.Exit(0)
	}

	fmt.Printf("\n%d tests: %d passed, %d failed\n", total, passed, failed)
	if failed > 0 {
		os.Exit(1)
	}
}

// primaryLang returns the first concrete language from the list, or "unknown".
func primaryLang(langs []string) string {
	for _, l := range langs {
		if l != "*" {
			return l
		}
	}
	return "unknown"
}
