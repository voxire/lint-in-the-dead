package rules

// Rule is the in-memory representation of a YAML rule definition.
type Rule struct {
	ID          string      `yaml:"id"`
	Name        string      `yaml:"name"`
	Description string      `yaml:"description"`
	Category    string      `yaml:"category"`
	Severity    string      `yaml:"severity"`
	Languages   []string    `yaml:"languages"` // ["*"] means all
	Pattern     Pattern     `yaml:"pattern"`
	Message     string      `yaml:"message"`
	Fix         string      `yaml:"fix,omitempty"`
	Enabled     bool        `yaml:"enabled"`
}

// Pattern describes how to detect a violation.
type Pattern struct {
	Type       string `yaml:"type"`  // "regex" | "ast" | "semgrep" | "complexity"
	Match      string `yaml:"match"` // regex or semgrep pattern
	MaxValue   int    `yaml:"max,omitempty"`
	Negate     bool   `yaml:"negate,omitempty"` // flag if pattern NOT found
}

// RuleSet is the top-level YAML document.
type RuleSet struct {
	Version string `yaml:"version"`
	Rules   []Rule `yaml:"rules"`
}
