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

// Evaluate returns all findings across all files.
func (e *Evaluator) Evaluate(files []FileContent) []models.Finding {
	var findings []models.Finding
	for _, f := range files {
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
				RuleID:   r.ID,
				RuleName: r.Name,
				Category: models.FindingCategory(r.Category),
				Severity: models.Severity(r.Severity),
				File:     f.Path,
				Line:     1,
				Column:   1,
				Message:  r.Message,
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

func languageMatches(langs []string, target string) bool {
	for _, l := range langs {
		if l == "*" || strings.EqualFold(l, target) {
			return true
		}
	}
	return false
}
