// Package entropy implements Shannon entropy analysis for detecting high-entropy
// strings that are likely hardcoded secrets (API keys, tokens, passwords).
package entropy

import (
	"bufio"
	"math"
	"regexp"
	"strings"

	"github.com/voxire/lint-in-the-dead/pkg/models"
)

const (
	// DefaultThreshold is the minimum Shannon entropy to flag a string.
	// Most English text falls below 4.0; random tokens/keys exceed 4.5.
	DefaultThreshold = 4.5

	// MinLength ignores strings shorter than this to reduce noise.
	MinLength = 12
)

// alphabets used to identify candidate tokens
var (
	base64Alphabet = regexp.MustCompile(`^[A-Za-z0-9+/=_\-]{12,}$`)
	hexAlphabet    = regexp.MustCompile(`^[0-9a-fA-F]{16,}$`)
	// Matches assignment patterns like: key = "value", KEY: 'value', key="value"
	assignmentRe   = regexp.MustCompile(`(?i)[\w_-]+\s*[:=]\s*["']([^"'\s]{12,})["']`)
)

// Shannon returns the Shannon entropy of s over its unique byte values.
func Shannon(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := make(map[rune]float64)
	total := float64(len([]rune(s)))
	for _, c := range s {
		freq[c]++
	}
	var h float64
	for _, f := range freq {
		p := f / total
		h -= p * math.Log2(p)
	}
	return h
}

// Finding records a high-entropy string found in a file.
type Finding struct {
	File    string
	Line    int
	Value   string
	Entropy float64
	Context string // the full line for reference
}

// Scan checks every line of content for high-entropy string candidates.
// It returns findings whose entropy exceeds threshold.
func Scan(path, content string, threshold float64) []Finding {
	if threshold <= 0 {
		threshold = DefaultThreshold
	}

	var findings []Finding
	scanner := bufio.NewScanner(strings.NewReader(content))
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		// Skip comment lines.
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") ||
			strings.HasPrefix(trimmed, "#") ||
			strings.HasPrefix(trimmed, "*") {
			continue
		}

		// Extract candidate strings from assignment expressions.
		for _, match := range assignmentRe.FindAllStringSubmatch(line, -1) {
			if len(match) < 2 {
				continue
			}
			candidate := match[1]
			if !isEntropyCandidate(candidate) {
				continue
			}
			e := Shannon(candidate)
			if e >= threshold {
				findings = append(findings, Finding{
					File:    path,
					Line:    lineNum,
					Value:   redact(candidate),
					Entropy: e,
					Context: strings.TrimSpace(line),
				})
			}
		}
	}
	return findings
}

// ToModelFindings converts entropy findings to the shared models.Finding type.
func ToModelFindings(ef []Finding) []models.Finding {
	out := make([]models.Finding, 0, len(ef))
	for _, f := range ef {
		out = append(out, models.Finding{
			RuleID:   "ENT-001",
			RuleName: "High-entropy string (possible secret)",
			Category: models.CategorySecurity,
			Severity: models.SeverityHigh,
			File:     f.File,
			Line:     f.Line,
			Column:   1,
			Message: strings.Join([]string{
				"High-entropy string detected (entropy=",
				formatEntropy(f.Entropy),
				"). Possible hardcoded secret: ",
				f.Value,
			}, ""),
			Snippet:       f.Context,
			FixSuggestion: "Move to an environment variable or secrets manager.",
		})
	}
	return out
}

func isEntropyCandidate(s string) bool {
	return len(s) >= MinLength && (base64Alphabet.MatchString(s) || hexAlphabet.MatchString(s))
}

// redact replaces the middle of a secret with *** to avoid leaking it in logs.
func redact(s string) string {
	if len(s) <= 8 {
		return "***"
	}
	return s[:4] + "***" + s[len(s)-4:]
}

func formatEntropy(e float64) string {
	// manual float formatting to avoid importing fmt in a hot path
	i := int(e * 100)
	whole := i / 100
	frac := i % 100
	return strings.Join([]string{itoa(whole), ".", pad2(frac)}, "")
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	buf := make([]byte, 0, 10)
	for n > 0 {
		buf = append([]byte{byte('0' + n%10)}, buf...)
		n /= 10
	}
	return string(buf)
}

func pad2(n int) string {
	if n < 10 {
		return "0" + itoa(n)
	}
	return itoa(n)
}
