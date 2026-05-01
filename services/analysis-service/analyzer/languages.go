package analyzer

import (
	"path/filepath"
	"strings"
)

var extLang = map[string]string{
	".go":    "go",
	".ts":    "typescript",
	".tsx":   "typescript",
	".js":    "javascript",
	".jsx":   "javascript",
	".mjs":   "javascript",
	".cjs":   "javascript",
	".py":    "python",
	".rs":    "rust",
	".java":  "java",
	".kt":    "kotlin",
	".kts":   "kotlin",
	".cs":    "csharp",
	".cpp":   "cpp",
	".cc":    "cpp",
	".cxx":   "cpp",
	".c":     "c",
	".h":     "c",
	".hpp":   "cpp",
	".rb":    "ruby",
	".php":   "php",
	".swift": "swift",
	".sh":    "bash",
	".bash":  "bash",
	".yaml":  "yaml",
	".yml":   "yaml",
	".json":  "json",
	".tf":    "terraform",
	".hcl":   "hcl",
	".sql":   "sql",
	".proto": "protobuf",
}

// DetectLanguage returns the language name for a file path.
func DetectLanguage(path string) string {
	ext := strings.ToLower(filepath.Ext(path))
	if lang, ok := extLang[ext]; ok {
		return lang
	}
	return "unknown"
}

// IsBinary returns true for file extensions that should not be text-scanned.
func IsBinary(path string) bool {
	binary := map[string]bool{
		".png": true, ".jpg": true, ".jpeg": true, ".gif": true,
		".pdf": true, ".zip": true, ".tar": true, ".gz": true,
		".exe": true, ".bin": true, ".so":  true, ".dll": true,
		".wasm": true, ".class": true, ".jar": true,
	}
	ext := strings.ToLower(filepath.Ext(path))
	return binary[ext]
}
