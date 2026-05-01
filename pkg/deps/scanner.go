// Package deps scans common dependency lockfiles and manifests to surface
// outdated, deprecated, or unlicensed packages.
package deps

import (
	"bufio"
	"path/filepath"
	"regexp"
	"strings"
)

// Dep represents a single parsed dependency.
type Dep struct {
	Name     string
	Version  string
	Source   string // "go.mod" | "package.json" | "requirements.txt" | "Cargo.toml" | "pom.xml"
	Indirect bool
}

// Manifest holds all dependencies parsed from a single lockfile.
type Manifest struct {
	File string
	Deps []Dep
}

// ScanFile parses a lockfile/manifest by filename and returns its dependencies.
// Returns nil, nil for unrecognised files (not an error).
func ScanFile(path, content string) (*Manifest, error) {
	base := strings.ToLower(filepath.Base(path))
	var deps []Dep
	var err error

	switch {
	case base == "go.mod":
		deps, err = parseGoMod(content)
	case base == "package.json":
		deps, err = parsePackageJSON(content)
	case base == "requirements.txt":
		deps = parseRequirementsTxt(content)
	case base == "cargo.toml":
		deps, err = parseCargoToml(content)
	case base == "pom.xml":
		deps = parsePomXML(content)
	default:
		return nil, nil
	}

	if err != nil {
		return nil, err
	}
	return &Manifest{File: path, Deps: deps}, nil
}

// ── go.mod ────────────────────────────────────────────────────────────────────

var (
	goRequireLine    = regexp.MustCompile(`^\s*([\w./\-]+)\s+(v[\w.\-+]+)(\s*//\s*indirect)?`)
	goRequireBlock   = regexp.MustCompile(`^require\s*\(`)
	goRequireSingle  = regexp.MustCompile(`^require\s+([\w./\-]+)\s+(v[\w.\-+]+)`)
)

func parseGoMod(content string) ([]Dep, error) {
	var deps []Dep
	inBlock := false

	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		if goRequireBlock.MatchString(trimmed) {
			inBlock = true
			continue
		}
		if inBlock && trimmed == ")" {
			inBlock = false
			continue
		}

		if inBlock {
			if m := goRequireLine.FindStringSubmatch(trimmed); m != nil {
				deps = append(deps, Dep{
					Name:     m[1],
					Version:  m[2],
					Source:   "go.mod",
					Indirect: m[3] != "",
				})
			}
		} else if m := goRequireSingle.FindStringSubmatch(trimmed); m != nil {
			deps = append(deps, Dep{Name: m[1], Version: m[2], Source: "go.mod"})
		}
	}
	return deps, nil
}

// ── package.json ──────────────────────────────────────────────────────────────

var pkgJSONDepLine = regexp.MustCompile(`^\s+"([^"]+)":\s+"([^"]+)"`)

func parsePackageJSON(content string) ([]Dep, error) {
	var deps []Dep
	inDeps := false

	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		if strings.Contains(trimmed, `"dependencies"`) ||
			strings.Contains(trimmed, `"devDependencies"`) ||
			strings.Contains(trimmed, `"peerDependencies"`) {
			inDeps = true
			continue
		}
		if inDeps && trimmed == "}" {
			inDeps = false
			continue
		}
		if inDeps {
			if m := pkgJSONDepLine.FindStringSubmatch(line); m != nil {
				deps = append(deps, Dep{Name: m[1], Version: m[2], Source: "package.json"})
			}
		}
	}
	return deps, nil
}

// ── requirements.txt ─────────────────────────────────────────────────────────

var reqLine = regexp.MustCompile(`^([A-Za-z0-9_\-\.]+)\s*([><=!~^]+)\s*([\w.\-]+)`)

func parseRequirementsTxt(content string) []Dep {
	var deps []Dep
	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}
		if m := reqLine.FindStringSubmatch(line); m != nil {
			deps = append(deps, Dep{Name: m[1], Version: m[2] + m[3], Source: "requirements.txt"})
		} else {
			// bare package name without version pin
			if name := strings.Fields(line); len(name) > 0 {
				deps = append(deps, Dep{Name: name[0], Source: "requirements.txt"})
			}
		}
	}
	return deps
}

// ── Cargo.toml ───────────────────────────────────────────────────────────────

var (
	cargoDepsSection = regexp.MustCompile(`^\[(dependencies|dev-dependencies|build-dependencies)\]`)
	cargoDepSimple   = regexp.MustCompile(`^([A-Za-z0-9_\-]+)\s*=\s*"([^"]+)"`)
	cargoDepTable    = regexp.MustCompile(`^([A-Za-z0-9_\-]+)\s*=\s*\{`)
	cargoVersionKey  = regexp.MustCompile(`version\s*=\s*"([^"]+)"`)
)

func parseCargoToml(content string) ([]Dep, error) {
	var deps []Dep
	inDeps := false

	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		if cargoDepsSection.MatchString(trimmed) {
			inDeps = true
			continue
		}
		if strings.HasPrefix(trimmed, "[") && !cargoDepsSection.MatchString(trimmed) {
			inDeps = false
			continue
		}
		if !inDeps {
			continue
		}

		if m := cargoDepSimple.FindStringSubmatch(trimmed); m != nil {
			deps = append(deps, Dep{Name: m[1], Version: m[2], Source: "Cargo.toml"})
		} else if m := cargoDepTable.FindStringSubmatch(trimmed); m != nil {
			ver := ""
			if mv := cargoVersionKey.FindStringSubmatch(trimmed); mv != nil {
				ver = mv[1]
			}
			deps = append(deps, Dep{Name: m[1], Version: ver, Source: "Cargo.toml"})
		}
	}
	return deps, nil
}

// ── pom.xml ───────────────────────────────────────────────────────────────────

var (
	pomGroupID    = regexp.MustCompile(`<groupId>([^<]+)</groupId>`)
	pomArtifactID = regexp.MustCompile(`<artifactId>([^<]+)</artifactId>`)
	pomVersion    = regexp.MustCompile(`<version>([^<]+)</version>`)
)

func parsePomXML(content string) []Dep {
	var deps []Dep
	inDep := false
	var group, artifact, version string

	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if strings.Contains(line, "<dependency>") {
			inDep = true
			group, artifact, version = "", "", ""
			continue
		}
		if strings.Contains(line, "</dependency>") {
			if artifact != "" {
				name := artifact
				if group != "" {
					name = group + ":" + artifact
				}
				deps = append(deps, Dep{Name: name, Version: version, Source: "pom.xml"})
			}
			inDep = false
			continue
		}
		if !inDep {
			continue
		}
		if m := pomGroupID.FindStringSubmatch(line); m != nil {
			group = m[1]
		} else if m := pomArtifactID.FindStringSubmatch(line); m != nil {
			artifact = m[1]
		} else if m := pomVersion.FindStringSubmatch(line); m != nil {
			version = m[1]
		}
	}
	return deps
}
