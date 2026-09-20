package schema_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/vemphy/vc/vc-go/internal/vectors"
	"github.com/vemphy/vc/vc-go/schema"
	"github.com/vemphy/vc/vc-go/vcctx"
)

type published struct {
	ref    schema.Ref
	schema *schema.Schema
}

func names(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(vectors.Dir(t), dir))
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		out = append(out, strings.TrimSuffix(e.Name(), ".json"))
	}
	return out
}

func customTypes(t *testing.T) []published {
	t.Helper()
	var out []published
	for _, name := range names(t, "schemas/valid") {
		var file struct {
			Ref struct {
				Issuer  string `json:"issuer"`
				Name    string `json:"name"`
				Version int    `json:"version"`
			} `json:"ref"`
			Schema json.RawMessage `json:"schema"`
		}
		vectors.Load(t, "schemas/valid/"+name+".json", &file)
		s, err := schema.Parse(file.Schema)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		out = append(out, published{schema.Ref{Issuer: file.Ref.Issuer, Name: file.Ref.Name, Version: file.Ref.Version}, s})
	}
	return out
}

func everyType(t *testing.T) []published {
	out := customTypes(t)
	for _, c := range schema.Core() {
		out = append(out, published{c.Ref, c.Schema})
	}
	return out
}

func TestCoreTypes(t *testing.T) {
	var got []string
	for _, c := range schema.Core() {
		got = append(got, c.Ref.Name)
	}
	want := []string{"Attestation", "BankBalanceLetter", "BankReferenceLetter", "DegreeCertificate", "EmploymentLetter", "InsuranceCertificate", "SalaryConfirmation"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("core types are %v", got)
	}
}

func TestReservedTermsAreThoseOfTheCredentialsContext(t *testing.T) {
	raw, _ := vcctx.Document(vcctx.CredentialsV2)
	var ctx struct {
		Context map[string]any `json:"@context"`
	}
	if err := json.Unmarshal(raw, &ctx); err != nil {
		t.Fatal(err)
	}
	var want []string
	for term := range ctx.Context {
		if !strings.HasPrefix(term, "@") {
			want = append(want, term)
		}
	}
	sort.Strings(want)

	metaRaw, err := os.ReadFile("meta/vemphy-claim-schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var meta struct {
		Defs struct {
			Reserved struct {
				Enum []string `json:"enum"`
			} `json:"reserved"`
		} `json:"$defs"`
	}
	if err := json.Unmarshal(metaRaw, &meta); err != nil {
		t.Fatal(err)
	}
	if strings.Join(meta.Defs.Reserved.Enum, ",") != strings.Join(want, ",") {
		t.Fatalf("reserved terms have drifted from the credentials context")
	}
}

func TestInvalidSchemasAreRefused(t *testing.T) {
	for _, name := range names(t, "schemas/invalid") {
		var file struct {
			Rule   string          `json:"rule"`
			Schema json.RawMessage `json:"schema"`
		}
		vectors.Load(t, "schemas/invalid/"+name+".json", &file)
		if problems := schema.Validate(file.Schema); len(problems) == 0 {
			t.Errorf("%s was accepted; it breaks the rule: %s", name, file.Rule)
		}
	}
	for _, raw := range []string{`null`, `42`, `"text"`, `[]`, `{`} {
		if len(schema.Validate([]byte(raw))) == 0 {
			t.Errorf("%s was accepted", raw)
		}
	}
}

func TestPatterns(t *testing.T) {
	var file struct{ Allowed, Refused []string }
	vectors.Load(t, "patterns.json", &file)
	for _, p := range file.Allowed {
		if problem := schema.PatternProblem(p); problem != "" {
			t.Errorf("%q refused: %s", p, problem)
		}
		// Whatever is allowed must also compile here.
		if _, err := regexp.Compile(p); err != nil {
			t.Errorf("%q does not compile: %v", p, err)
		}
	}
	for _, p := range file.Refused {
		if schema.PatternProblem(p) == "" {
			t.Errorf("%q was allowed", p)
		}
	}
}

func TestSubjects(t *testing.T) {
	type fixtureCase struct {
		Note  string
		Set   map[string]json.RawMessage
		Unset []string
	}
	for _, name := range names(t, "schemas/subjects") {
		var fixture struct {
			Schema string
			Base   map[string]json.RawMessage
			Accept []fixtureCase
			Reject []fixtureCase
		}
		vectors.Load(t, "schemas/subjects/"+name+".json", &fixture)

		raw, err := os.ReadFile(filepath.Join(filepath.Join(vectors.Dir(t), ".."), fixture.Schema))
		if err != nil {
			t.Fatal(err)
		}
		var wrapped struct{ Schema json.RawMessage }
		if json.Unmarshal(raw, &wrapped) == nil && wrapped.Schema != nil {
			raw = wrapped.Schema
		}
		s, err := schema.Parse(raw)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}

		build := func(c fixtureCase) []byte {
			subject := map[string]json.RawMessage{}
			for k, v := range fixture.Base {
				subject[k] = v
			}
			for k, v := range c.Set {
				subject[k] = v
			}
			for _, k := range c.Unset {
				delete(subject, k)
			}
			out, _ := json.Marshal(subject)
			return out
		}
		for _, c := range fixture.Accept {
			if problems := s.ValidateSubject(build(c)); len(problems) > 0 {
				t.Errorf("%s should accept %s: %v", name, c.Note, problems)
			}
		}
		for _, c := range fixture.Reject {
			if problems := s.ValidateSubject(build(c)); len(problems) == 0 {
				t.Errorf("%s should reject %s", name, c.Note)
			}
		}
	}
}

func TestProblemsNameEveryField(t *testing.T) {
	var card *schema.Schema
	for _, p := range customTypes(t) {
		if p.ref.Name == "StaffIdCard" && p.ref.Version == 1 {
			card = p.schema
		}
	}
	problems := card.ValidateSubject([]byte(`{"holderName":" Ama","grade":"principal","issuedOn":"2026-02-30","extra":1}`))
	var fields []string
	for _, p := range problems {
		fields = append(fields, p.Field)
	}
	sort.Strings(fields)
	if strings.Join(fields, ",") != ",grade,holderName,issuedOn,staffNumber" {
		t.Fatalf("problems name %q", fields)
	}
}

// The TypeScript generator wrote vectors/cache. These bytes must match it.
func TestContextsAndDocumentsMatchTypeScript(t *testing.T) {
	for _, p := range everyType(t) {
		want, err := os.ReadFile(filepath.Join(vectors.Dir(t), "cache", vcctx.CacheFileName(p.ref.ContextURL())))
		if err != nil {
			t.Fatal(err)
		}
		if got := schema.GenerateContext(p.schema, p.ref.Namespace()); string(got) != string(want) {
			t.Errorf("%s context differs:\n%s\n%s", p.ref.ContextURL(), got, want)
		}

		want, err = os.ReadFile(filepath.Join(vectors.Dir(t), "cache", vcctx.CacheFileName(p.ref.SchemaURL())))
		if err != nil {
			t.Fatal(err)
		}
		got, err := schema.Document(p.schema, p.ref.SchemaURL())
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != string(want) {
			t.Errorf("%s document differs:\n%s\n%s", p.ref.SchemaURL(), got, want)
		}

		inner, ok := schema.SubjectSchemaFrom(got)
		if !ok {
			t.Fatalf("%s: no schema inside its document", p.ref.SchemaURL())
		}
		again, err := schema.Parse(inner)
		if err != nil || again.Name != p.schema.Name || len(again.Fields) != len(p.schema.Fields) {
			t.Errorf("%s does not unwrap to its schema: %v", p.ref.SchemaURL(), err)
		}
	}
}

func TestCanonicalJSONMatchesJavaScript(t *testing.T) {
	doc, err := schema.Decode([]byte(`{"b":1.0,"a":1e3,"😀":"x","￿":"y","s":"<&> \u0001\"\\\n"}`))
	if err != nil {
		t.Fatal(err)
	}
	got, err := schema.CanonicalJSON(doc)
	if err != nil {
		t.Fatal(err)
	}
	// Keys sort by UTF-16 code unit: the surrogate pair (d83d) comes before ffff.
	want := "{\"a\":1000,\"b\":1,\"s\":\"<&> \\u0001\\\"\\\\\\n\",\"\U0001F600\":\"x\",\"￿\":\"y\"}"
	if string(got) != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}

func TestURLs(t *testing.T) {
	ref := schema.Ref{Issuer: "gcb", Name: "StaffIdCard", Version: 2}
	if got, ok := schema.ParseContextURL(ref.ContextURL()); !ok || got != ref {
		t.Errorf("context URL does not round-trip: %v", got)
	}
	if got, ok := schema.ParseSchemaURL(ref.SchemaURL()); !ok || got != ref {
		t.Errorf("schema URL does not round-trip: %v", got)
	}
	for _, url := range []string{schema.LegacyContext, "https://vemphy.com/ns/core/attestation/v1", "https://vemphy.com/ns/i/GCB/X1/v1", "https://vemphy.com/ns/core/Attestation/v0"} {
		if _, ok := schema.ParseContextURL(url); ok {
			t.Errorf("%s was read as a type context", url)
		}
	}
}

func TestLabels(t *testing.T) {
	var v2, all *schema.Schema
	for _, p := range customTypes(t) {
		switch {
		case p.ref.Name == "StaffIdCard" && p.ref.Version == 2:
			v2 = p.schema
		case p.ref.Name == "AllKinds":
			all = p.schema
		}
	}
	check := func(got, want string) {
		t.Helper()
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	}
	label := func(s *schema.Schema, key string, wanted ...string) string {
		l, _ := s.Label(key, wanted...)
		return l
	}
	check(label(v2, "holderName"), "Card holder")
	check(label(v2, "holderName", "fr-CA"), "Titulaire")
	check(label(v2, "holderName", "de", "fr"), "Titulaire")
	check(label(v2, "holderName", "de"), "Card holder")
	check(label(all, "text", "pt-br"), "Texto")
	check(label(all, "text", "pt"), "Text")
	check(all.DisplayName.Pick("fr"), "Tous les types de champ")
	if _, ok := v2.Label("nothing"); ok {
		t.Error("found a label for a field that does not exist")
	}
	choice, _ := all.Field("choice")
	check(choice.ValueLabel("a", "fr"), "Choix A")
	check(choice.ValueLabel("b"), "b")

	var kinds []string
	for _, f := range all.Fields {
		kinds = append(kinds, string(f.Kind))
	}
	check(strings.Join(kinds, " "), "text text multiline decimal integer integer boolean date datetime email uri choice")
}
