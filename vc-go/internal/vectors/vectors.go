// Package vectors locates and loads the shared test vectors at the repository root.
package vectors

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// Dir returns the absolute path of the repository's vectors directory,
// found by walking up from the working directory.
func Dir(t testing.TB) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		candidate := filepath.Join(dir, "vectors")
		if _, err := os.Stat(filepath.Join(candidate, "codes.json")); err == nil {
			return candidate
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("vectors directory not found")
		}
		dir = parent
	}
}

// Load decodes the JSON file at rel, relative to the vectors directory, into v.
func Load(t testing.TB, rel string, v any) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(Dir(t), rel))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, v); err != nil {
		t.Fatalf("%s: %v", rel, err)
	}
}
