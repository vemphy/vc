package canon_test

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vemphy/vc/vc-go/canon"
	"github.com/vemphy/vc/vc-go/internal/vectors"
	"github.com/vemphy/vc/vc-go/schema"
)

func staffIDCard(t *testing.T) (*schema.Schema, schema.Ref) {
	t.Helper()
	var file struct{ Schema json.RawMessage }
	vectors.Load(t, "schemas/valid/gcb.StaffIdCard.v1.json", &file)
	s, err := schema.Parse(file.Schema)
	if err != nil {
		t.Fatal(err)
	}
	return s, schema.Ref{Issuer: "gcb", Name: "StaffIdCard", Version: 1}
}

func TestNoCoreOrVectorContextDropsATerm(t *testing.T) {
	for _, c := range schema.Core() {
		if err := canon.AssertNoDroppedTerms(c.Schema, schema.GenerateContext(c.Schema, c.Ref.Namespace()), c.Ref.Namespace()); err != nil {
			t.Errorf("%s: %v", c.Ref.Name, err)
		}
	}
	files, _ := filepath.Glob(filepath.Join(vectors.Dir(t), "schemas", "valid", "*.json"))
	for _, f := range files {
		var file struct {
			Ref struct {
				Issuer, Name string
				Version      int
			}
			Schema json.RawMessage
		}
		vectors.Load(t, "schemas/valid/"+filepath.Base(f), &file)
		s, err := schema.Parse(file.Schema)
		if err != nil {
			t.Fatal(err)
		}
		ref := schema.Ref{Issuer: file.Ref.Issuer, Name: file.Ref.Name, Version: file.Ref.Version}
		if err := canon.AssertNoDroppedTerms(s, schema.GenerateContext(s, ref.Namespace()), ref.Namespace()); err != nil {
			t.Errorf("%s: %v", f, err)
		}
	}
}

func TestADroppedTermIsNoticed(t *testing.T) {
	s, ref := staffIDCard(t)
	context := schema.GenerateContext(s, ref.Namespace())

	// Leave one property out of the context.
	missing := bytes.Replace(context, []byte(`"issuedOn":`), []byte(`"issuedOnX":`), 1)
	if err := canon.AssertNoDroppedTerms(s, missing, ref.Namespace()); err == nil || !strings.Contains(err.Error(), "drops issuedOn") {
		t.Errorf("got %v", err)
	}

	// Map everything somewhere else.
	elsewhere := schema.GenerateContext(s, "https://example.com/other#")
	if err := canon.AssertNoDroppedTerms(s, elsewhere, ref.Namespace()); err == nil {
		t.Error("a context under another namespace was accepted")
	}
}
