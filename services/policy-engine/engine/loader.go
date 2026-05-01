package engine

import (
	"fmt"
	"os"

	"github.com/voxire/lint-in-the-dead/pkg/rules"
)

// LoadRules reads all YAML rule files from dir and compiles them.
func LoadRules(dir string) ([]rules.Rule, error) {
	if dir == "" {
		return nil, fmt.Errorf("RULES_DIR not set")
	}
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return nil, fmt.Errorf("rules dir %q does not exist", dir)
	}
	return rules.LoadDir(dir)
}
