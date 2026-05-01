package deps_test

import (
	"testing"

	"github.com/voxire/lint-in-the-dead/pkg/deps"
)

func TestParseGoMod(t *testing.T) {
	content := `module example.com/app

go 1.24

require (
	github.com/gorilla/websocket v1.5.3
	github.com/lib/pq v1.10.9 // indirect
)

require golang.org/x/net v0.17.0
`
	m, err := deps.ScanFile("go.mod", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if m == nil {
		t.Fatal("expected manifest, got nil")
	}
	if len(m.Deps) != 3 {
		t.Fatalf("expected 3 deps, got %d: %+v", len(m.Deps), m.Deps)
	}
	if m.Deps[0].Name != "github.com/gorilla/websocket" {
		t.Errorf("unexpected first dep: %+v", m.Deps[0])
	}
	if !m.Deps[1].Indirect {
		t.Error("lib/pq should be indirect")
	}
	if m.Deps[2].Name != "golang.org/x/net" {
		t.Errorf("unexpected third dep: %+v", m.Deps[2])
	}
}

func TestParsePackageJSON(t *testing.T) {
	content := `{
  "name": "my-app",
  "dependencies": {
    "express": "^4.18.2",
    "lodash": "4.17.21"
  },
  "devDependencies": {
    "jest": "^29.0.0"
  }
}`
	m, err := deps.ScanFile("package.json", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(m.Deps) != 3 {
		t.Fatalf("expected 3 deps, got %d", len(m.Deps))
	}
	names := map[string]bool{}
	for _, d := range m.Deps {
		names[d.Name] = true
	}
	for _, want := range []string{"express", "lodash", "jest"} {
		if !names[want] {
			t.Errorf("missing dep %q", want)
		}
	}
}

func TestParseRequirementsTxt(t *testing.T) {
	content := `# web framework
flask==2.3.0
requests>=2.28.0
numpy
`
	m, err := deps.ScanFile("requirements.txt", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(m.Deps) != 3 {
		t.Fatalf("expected 3 deps, got %d: %+v", len(m.Deps), m.Deps)
	}
	if m.Deps[0].Name != "flask" {
		t.Errorf("expected flask, got %q", m.Deps[0].Name)
	}
}

func TestParseCargoToml(t *testing.T) {
	content := `[package]
name = "myapp"
version = "0.1.0"

[dependencies]
serde = "1.0"
tokio = { version = "1.35", features = ["full"] }

[dev-dependencies]
mockall = "0.12"
`
	m, err := deps.ScanFile("Cargo.toml", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(m.Deps) != 3 {
		t.Fatalf("expected 3 deps, got %d: %+v", len(m.Deps), m.Deps)
	}
	if m.Deps[0].Name != "serde" || m.Deps[0].Version != "1.0" {
		t.Errorf("unexpected first dep: %+v", m.Deps[0])
	}
}

func TestParsePomXML(t *testing.T) {
	content := `<project>
  <dependencies>
    <dependency>
      <groupId>org.springframework</groupId>
      <artifactId>spring-core</artifactId>
      <version>6.1.0</version>
    </dependency>
    <dependency>
      <groupId>junit</groupId>
      <artifactId>junit</artifactId>
      <version>4.13.2</version>
    </dependency>
  </dependencies>
</project>`
	m, err := deps.ScanFile("pom.xml", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(m.Deps) != 2 {
		t.Fatalf("expected 2 deps, got %d", len(m.Deps))
	}
	if m.Deps[0].Name != "org.springframework:spring-core" {
		t.Errorf("unexpected dep: %+v", m.Deps[0])
	}
}

func TestUnknownFile_ReturnsNil(t *testing.T) {
	m, err := deps.ScanFile("README.md", "# hello")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if m != nil {
		t.Error("expected nil manifest for unknown file type")
	}
}
