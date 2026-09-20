package schema

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/vemphy/vc/vc-go/internal/vectors"
	"github.com/vemphy/vc/vc-go/vcctx"
)

const bank = `{"accountHolderName":"Ama Serwaa Mensah","accountType":"current","accountNumberLast4":"0042",
"accountOpenedOn":"2019-03-04","branch":"Accra High Street","standing":"satisfactory","referenceDate":"2026-05-04"}`

func patch(t *testing.T, base string, changes map[string]any) json.RawMessage {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(base), &m); err != nil {
		t.Fatal(err)
	}
	for k, v := range changes {
		if v == nil {
			delete(m, k)
		} else {
			m[k] = v
		}
	}
	out, _ := json.Marshal(m)
	return out
}

func TestValidateSubject(t *testing.T) {
	if err := ValidateSubject("BankReferenceLetter", json.RawMessage(bank)); err != nil {
		t.Fatalf("well-formed subject refused: %v", err)
	}
	refused := map[string]map[string]any{
		"unknown field":            {"balance": "1000"},
		"value outside the enum":   {"accountType": "offshore"},
		"date that does not exist": {"referenceDate": "2026-02-30"},
		"date with a time":         {"referenceDate": "2026-01-10T00:00:00Z"},
		"five digits":              {"accountNumberLast4": "00421"},
		"padded text":              {"branch": " Accra "},
		"empty text":               {"branch": ""},
		"number for text":          {"branch": 7},
		"missing required field":   {"standing": nil},
	}
	for name, changes := range refused {
		if err := ValidateSubject("BankReferenceLetter", patch(t, bank, changes)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := ValidateSubject("Passport", json.RawMessage(bank)); err == nil {
		t.Error("unknown claim type accepted")
	}
	for _, raw := range []string{`null`, `[]`, `"text"`, ``} {
		if err := ValidateSubject("BankReferenceLetter", json.RawMessage(raw)); err == nil {
			t.Errorf("%q accepted", raw)
		}
	}
}

func TestEmploymentDateRules(t *testing.T) {
	const base = `{"employeeName":"Efua Asante","jobTitle":"Senior Accountant","employmentType":"permanent","startDate":"2021-02-01","currentlyEmployed":true}`
	cases := []struct {
		name    string
		changes map[string]any
		ok      bool
	}{
		{"current employee", nil, true},
		{"former employee with end date", map[string]any{"currentlyEmployed": false, "endDate": "2025-06-30"}, true},
		{"current employee with end date", map[string]any{"endDate": "2025-06-30"}, false},
		{"end before start", map[string]any{"currentlyEmployed": false, "endDate": "2020-01-01"}, false},
		{"text for a boolean", map[string]any{"currentlyEmployed": "yes"}, false},
	}
	for _, c := range cases {
		err := ValidateSubject("EmploymentLetter", patch(t, base, c.changes))
		if (err == nil) != c.ok {
			t.Errorf("%s: err = %v", c.name, err)
		}
	}
}

// Every field and every disclosed field must be a term in the claims context,
// or it would be dropped from what gets signed.
func TestFieldsAreContextTerms(t *testing.T) {
	raw, ok := vcctx.Document(vcctx.ClaimsV1)
	if !ok {
		t.Fatal("claims context not bundled")
	}
	var doc struct {
		Context map[string]any `json:"@context"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if got := ClaimTypes(); !slices.Equal(got, []string{"BankReferenceLetter", "DegreeCertificate", "EmploymentLetter"}) {
		t.Errorf("ClaimTypes = %v", got)
	}
	for _, claimType := range ClaimTypes() {
		if _, ok := doc.Context[claimType]; !ok {
			t.Errorf("%s is not a context term", claimType)
		}
		for _, f := range Fields(claimType) {
			if _, ok := doc.Context[f]; !ok {
				t.Errorf("%s.%s is not a context term", claimType, f)
			}
		}
		if len(DefaultDisclosure(claimType)) == 0 {
			t.Errorf("%s discloses nothing", claimType)
		}
		for _, f := range DefaultDisclosure(claimType) {
			if !slices.Contains(Fields(claimType), f) {
				t.Errorf("%s discloses %s, which it does not define", claimType, f)
			}
		}
	}
}

// The subjects in the shared vectors are the ones the TypeScript schemas accepted.
func TestAcceptsVectorSubjects(t *testing.T) {
	files, _ := filepath.Glob(filepath.Join(vectors.Dir(t), "claims", "*-001.json"))
	if len(files) != 3 {
		t.Fatalf("expected three -001 vectors, found %d", len(files))
	}
	for _, f := range files {
		raw, _ := os.ReadFile(f)
		var c struct {
			Type              []string        `json:"type"`
			CredentialSubject json.RawMessage `json:"credentialSubject"`
		}
		if err := json.Unmarshal(raw, &c); err != nil {
			t.Fatal(err)
		}
		if err := ValidateSubject(c.Type[1], c.CredentialSubject); err != nil {
			t.Errorf("%s: %v", filepath.Base(f), err)
		}
	}
}

// vectors/schema.json is written from the TypeScript schemas.
func TestMatchesTypeScriptSchemas(t *testing.T) {
	var want map[string]struct {
		Fields            []string `json:"fields"`
		DefaultDisclosure []string `json:"defaultDisclosure"`
	}
	vectors.Load(t, "schema.json", &want)
	if len(want) != len(ClaimTypes()) {
		t.Fatalf("TypeScript defines %d claim types, Go %d", len(want), len(ClaimTypes()))
	}
	for claimType, w := range want {
		if got := Fields(claimType); !slices.Equal(got, w.Fields) {
			t.Errorf("%s fields: %v, want %v", claimType, got, w.Fields)
		}
		if got := DefaultDisclosure(claimType); !slices.Equal(got, w.DefaultDisclosure) {
			t.Errorf("%s disclosure: %v, want %v", claimType, got, w.DefaultDisclosure)
		}
	}
}
