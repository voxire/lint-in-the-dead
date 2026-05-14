package rules

import (
	"bufio"
	"regexp"
	"strings"

	"github.com/voxire/lint-in-the-dead/pkg/models"
)

// FileContent holds a single file's text for evaluation.
type FileContent struct {
	Path     string
	Language string
	Content  string
}

// Evaluator runs a set of Rules against a collection of files.
type Evaluator struct {
	rules    []Rule
	compiled map[string]*regexp.Regexp
}

func NewEvaluator(rules []Rule) (*Evaluator, error) {
	e := &Evaluator{
		rules:    rules,
		compiled: make(map[string]*regexp.Regexp),
	}
	for _, r := range rules {
		if r.Pattern.Type == "regex" && r.Pattern.Match != "" {
			re, err := regexp.Compile(r.Pattern.Match)
			if err != nil {
				return nil, err
			}
			e.compiled[r.ID] = re
		}
	}
	return e, nil
}

// Evaluate returns all findings across all files, respecting litd:ignore directives.
func (e *Evaluator) Evaluate(files []FileContent) []models.Finding {
	var findings []models.Finding
	for _, f := range files {
		if fileIgnored(f.Content) {
			continue
		}
		for _, r := range e.rules {
			if !r.Enabled {
				continue
			}
			if !languageMatches(r.Languages, f.Language) {
				continue
			}
			found := e.evalRule(r, f)
			findings = append(findings, found...)
		}
	}
	return findings
}

// EvaluateOne runs a single rule against a single file. Used by litd test-rules.
func (e *Evaluator) EvaluateOne(r Rule, f FileContent) []models.Finding {
	return e.evalRule(r, f)
}

func (e *Evaluator) evalRule(r Rule, f FileContent) []models.Finding {
	switch r.Pattern.Type {
	case "regex":
		return e.evalRegex(r, f)
	default:
		return nil
	}
}

func (e *Evaluator) evalRegex(r Rule, f FileContent) []models.Finding {
	re, ok := e.compiled[r.ID]
	if !ok {
		return nil
	}

	// Negate = file-level check: flag the whole file if the pattern is absent.
	if r.Pattern.Negate {
		if !re.MatchString(f.Content) {
			return []models.Finding{{
				RuleID:        r.ID,
				RuleName:      r.Name,
				Category:      models.FindingCategory(r.Category),
				Severity:      models.Severity(r.Severity),
				File:          f.Path,
				Line:          1,
				Column:        1,
				Message:       r.Message,
				FixSuggestion: r.Fix,
			}}
		}
		return nil
	}

	var findings []models.Finding
	scanner := bufio.NewScanner(strings.NewReader(f.Content))
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		if lineIgnored(line, r.ID) {
			continue
		}
		if re.MatchString(line) {
			col := 1
			if loc := re.FindStringIndex(line); loc != nil {
				col = loc[0] + 1
			}
			findings = append(findings, models.Finding{
				RuleID:        r.ID,
				RuleName:      r.Name,
				Category:      models.FindingCategory(r.Category),
				Severity:      models.Severity(r.Severity),
				File:          f.Path,
				Line:          lineNum,
				Column:        col,
				Message:       r.Message,
				Snippet:       strings.TrimSpace(line),
				FixSuggestion: r.Fix,
			})
		}
	}
	return findings
}

// fileIgnored returns true when the file contains a litd:ignore-file directive.
func fileIgnored(content string) bool {
	scanner := bufio.NewScanner(strings.NewReader(content))
	for i := 0; i < 10 && scanner.Scan(); i++ {
		if strings.Contains(scanner.Text(), "litd:ignore-file") {
			return true
		}
	}
	return false
}

// lineIgnored returns true when the line carries a litd:ignore directive that
// covers ruleID. Formats:
//
//	litd:ignore           — suppress all rules on this line
//	litd:ignore SEC-001   — suppress a specific rule
//	litd:ignore SEC-001,SEC-002 — suppress multiple rules
func lineIgnored(line, ruleID string) bool {
	idx := strings.Index(line, "litd:ignore")
	if idx == -1 {
		return false
	}
	rest := strings.TrimSpace(line[idx+len("litd:ignore"):])
	if rest == "" || strings.HasPrefix(rest, "\n") {
		return true // bare litd:ignore — suppress all
	}
	for _, id := range strings.Split(rest, ",") {
		if strings.TrimSpace(id) == ruleID {
			return true
		}
	}
	return false
}

func languageMatches(langs []string, target string) bool {
	for _, l := range langs {
		if l == "*" || strings.EqualFold(l, target) {
			return true
		}
	}
	return false
}
