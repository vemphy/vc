package directory

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/vemphy/vc/vc-go/internal/vectors"
)

// expectedFile is the shape of the "directories" section of expected.json:
// one of three result words per vector, alongside a note explaining why.
type expectedFile struct {
	Now         time.Time `json:"now"`
	Directories map[string]struct {
		Result string `json:"result"`
		Note   string `json:"note"`
	} `json:"directories"`
}

// TestDirectoryVectors proves the Go implementation agrees with the signed
// directories TypeScript generated: for every vector in vectors/directory,
// directory.Verify must reach the outcome expected.json records for it.
//
// Deps.DocumentLoader is left nil throughout, which is what makes this
// possible offline: a directory's own term vocabulary — did, slug, status,
// legalName, the two types — is carried inline in its @context, so nothing
// beyond the bundled W3C credentials context is ever needed to canonicalise
// it, and no network access or cache is required to check any of these
// vectors.
func TestDirectoryVectors(t *testing.T) {
	var expected expectedFile
	vectors.Load(t, "expected.json", &expected)

	dir := vectors.Dir(t)
	apexRaw, err := os.ReadFile(filepath.Join(dir, "keys", "apex.did.json"))
	if err != nil {
		t.Fatal(err)
	}
	deps := Deps{
		Now:         expected.Now,
		ResolveApex: func(context.Context) ([]byte, error) { return apexRaw, nil },
	}

	// Fail if a vector was added to vectors/directory but never listed in
	// expected.json, or vice versa: either way it would never be exercised.
	files, _ := filepath.Glob(filepath.Join(dir, "directory", "*.json"))
	var onDisk, listed []string
	for _, f := range files {
		onDisk = append(onDisk, strings.TrimSuffix(filepath.Base(f), ".json"))
	}
	for name := range expected.Directories {
		listed = append(listed, name)
	}
	sort.Strings(onDisk)
	sort.Strings(listed)
	if strings.Join(onDisk, " ") != strings.Join(listed, " ") {
		t.Fatalf("expected.json lists %v, vectors/directory has %v", listed, onDisk)
	}

	for name, want := range expected.Directories {
		t.Run(name, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join(dir, "directory", name+".json"))
			if err != nil {
				t.Fatal(err)
			}
			got, err := Verify(context.Background(), raw, deps)

			switch want.Result {
			case "valid":
				if err != nil {
					t.Fatalf("got error %v, want valid (%s)", err, want.Note)
				}
				if len(got.Entries) == 0 {
					t.Error("a valid directory should have entries")
				}
				if _, ok := got.Issuer("gcb"); !ok {
					t.Error("Issuer(\"gcb\") should be found in a valid directory")
				}
				if !got.ValidUntil.After(expected.Now) {
					t.Errorf("ValidUntil %v should be after now %v", got.ValidUntil, expected.Now)
				}
			case "expired":
				if !errors.Is(err, ErrStale) {
					t.Errorf("got %v, want errors.Is(err, ErrStale) (%s)", err, want.Note)
				}
			case "not-trustworthy":
				// Getting this the wrong way round would make a directory
				// that was altered after signing indistinguishable from one
				// that has merely gone stale, which defeats the reason
				// ErrStale is a sentinel at all.
				if err == nil {
					t.Fatalf("got no error, want a refusal (%s)", want.Note)
				}
				if errors.Is(err, ErrStale) {
					t.Errorf("got ErrStale, want a refusal that is not ErrStale (%s)", want.Note)
				}
			default:
				t.Fatalf("unknown result word %q in expected.json", want.Result)
			}
		})
	}
}
