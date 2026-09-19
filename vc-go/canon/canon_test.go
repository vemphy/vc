package canon

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/vemphy/vc/vc-go/internal/vectors"
	"github.com/vemphy/vc/vc-go/vcctx"
)

func minimal(t *testing.T) map[string]any {
	var doc map[string]any
	vectors.Load(t, "canon/minimal.json", &doc)
	return doc
}

func TestReproducesCommittedNQuads(t *testing.T) {
	want, err := os.ReadFile(filepath.Join(vectors.Dir(t), "canon", "minimal.nq"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := Canonicalize(minimal(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got != string(want) {
		t.Errorf("N-Quads differ from the TypeScript output\n--- got\n%s--- want\n%s", got, want)
	}
}

func TestRejectsUndefinedProperty(t *testing.T) {
	doc := minimal(t)
	doc["credentialSubject"].(map[string]any)["balance"] = "1000"
	if _, err := Canonicalize(doc, nil); err == nil {
		t.Error("expected an error for a property no context defines")
	}
}

func TestRejectsUnknownContext(t *testing.T) {
	doc := minimal(t)
	doc["@context"] = append(doc["@context"].([]any), "https://example.com/ctx")
	_, err := Canonicalize(doc, nil)
	if !errors.Is(err, vcctx.ErrUnknownContext) {
		t.Errorf("got %v, want ErrUnknownContext", err)
	}
}

func TestRejectsUndefinedType(t *testing.T) {
	doc := minimal(t)
	doc["type"] = []any{"VerifiableCredential", "NotDefinedAnywhere"}
	if _, err := Canonicalize(doc, nil); err == nil {
		t.Error("expected an error for a type no context defines")
	}
}

func TestRejectsRelativeID(t *testing.T) {
	doc := minimal(t)
	doc["id"] = "not-an-iri"
	if _, err := Canonicalize(doc, nil); err == nil {
		t.Error("expected an error for a relative id")
	}
}
