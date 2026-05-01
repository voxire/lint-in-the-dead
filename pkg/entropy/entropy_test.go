package entropy_test

import (
	"math"
	"testing"

	"github.com/voxire/lint-in-the-dead/pkg/entropy"
)

func TestShannon_Uniform(t *testing.T) {
	// "abcd" — 4 unique chars, each with p=0.25 → entropy = 2.0
	h := entropy.Shannon("abcd")
	if math.Abs(h-2.0) > 0.001 {
		t.Errorf("expected ~2.0, got %f", h)
	}
}

func TestShannon_SingleChar(t *testing.T) {
	h := entropy.Shannon("aaaa")
	if h != 0 {
		t.Errorf("expected 0 for single-char string, got %f", h)
	}
}

func TestShannon_Empty(t *testing.T) {
	if h := entropy.Shannon(""); h != 0 {
		t.Errorf("expected 0 for empty string, got %f", h)
	}
}

func TestShannon_HighEntropyToken(t *testing.T) {
	// A realistic API key — should be well above 4.5
	token := "xK9pL2mN5qR8sT1uV4wX7yZ0aB3cD6eF"
	h := entropy.Shannon(token)
	if h < 4.0 {
		t.Errorf("expected high entropy for API key, got %f", h)
	}
}

func TestShannon_LowEntropyWord(t *testing.T) {
	// Normal English word — should be below threshold
	h := entropy.Shannon("password")
	if h > 4.5 {
		t.Errorf("expected low entropy for 'password', got %f", h)
	}
}

func TestScan_DetectsHighEntropySecret(t *testing.T) {
	content := `package main

const apiKey = "xK9pL2mN5qR8sT1uV4wX7yZ0aB3cD6eFyZ0123456789"
`
	findings := entropy.Scan("config.go", content, 4.5)
	if len(findings) == 0 {
		t.Error("expected a finding for high-entropy API key, got none")
	}
}

func TestScan_IgnoresLowEntropyValue(t *testing.T) {
	content := `const env = "production"`
	findings := entropy.Scan("config.go", content, 4.5)
	if len(findings) != 0 {
		t.Errorf("expected no findings for low-entropy value, got %d", len(findings))
	}
}

func TestScan_IgnoresCommentLines(t *testing.T) {
	content := `// apiKey = "xK9pL2mN5qR8sT1uV4wX7yZ0aB3cD6eFyZ0123456789"` + "\n"
	findings := entropy.Scan("foo.go", content, 4.5)
	if len(findings) != 0 {
		t.Errorf("comment lines should be ignored, got %d findings", len(findings))
	}
}

func TestScan_MultipleSecretsOnDifferentLines(t *testing.T) {
	content := "token1 = \"aB3dE6gH9jK2mN5pQ8rS1tU4vW7xY0zA\"\n" +
		"normal = \"hello\"\n" +
		"token2 = \"zY0xW7vU4tS1rQ8pN5mK2jH9gE6dB3aZ\"\n"
	findings := entropy.Scan("secrets.env", content, 4.5)
	if len(findings) < 2 {
		t.Errorf("expected at least 2 findings, got %d", len(findings))
	}
}

func TestScan_RedactsValueInMessage(t *testing.T) {
	content := "secret_key = \"aB3dE6gH9jK2mN5pQ8rS1tU4vW7xY0zA\"\n"
	findings := entropy.Scan("cfg.go", content, 4.5)
	if len(findings) == 0 {
		t.Skip("no findings to check redaction")
	}
	val := findings[0].Value
	if len(val) > 12 && !contains(val, "***") {
		t.Errorf("expected redacted value, got %q", val)
	}
}

func TestToModelFindings(t *testing.T) {
	ef := []entropy.Finding{
		{File: "a.go", Line: 3, Value: "xK9p***6eFg", Entropy: 5.1, Context: "key = \"...\""},
	}
	mf := entropy.ToModelFindings(ef)
	if len(mf) != 1 {
		t.Fatalf("expected 1 model finding, got %d", len(mf))
	}
	if mf[0].RuleID != "ENT-001" {
		t.Errorf("expected ENT-001, got %q", mf[0].RuleID)
	}
	if mf[0].Line != 3 {
		t.Errorf("expected line 3, got %d", mf[0].Line)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && containsStr(s, sub))
}

func containsStr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
