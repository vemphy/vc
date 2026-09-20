package schema

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Ref names one published version of a claim type. Issuer is the lowercase
// issuer slug, and empty for a core type.
type Ref struct {
	Issuer  string
	Name    string
	Version int
}

const (
	nsBase      = "https://vemphy.com/ns/"
	schemasBase = "https://vemphy.com/schemas/"

	// LegacyContext is the shared context of 0.1.0. Claims issued under it
	// carry one of LegacyTypes and no credentialSchema. It is never edited.
	LegacyContext = "https://vemphy.com/ns/claims/v1"
)

// LegacyTypes are the three types of 0.1.0.
var LegacyTypes = []string{"BankReferenceLetter", "DegreeCertificate", "EmploymentLetter"}

var refPath = regexp.MustCompile(`^(?:core|i/([a-z]{2,4}))/([A-Z][a-zA-Z0-9]{1,39})/v([1-9]\d{0,5})$`)

func (r Ref) path() string {
	if r.Issuer == "" {
		return fmt.Sprintf("core/%s/v%d", r.Name, r.Version)
	}
	return fmt.Sprintf("i/%s/%s/v%d", r.Issuer, r.Name, r.Version)
}

// IsCore reports whether the type is curated by Vemphy and open to every issuer.
func (r Ref) IsCore() bool { return r.Issuer == "" }

// ContextURL is where the JSON-LD context of the type version lives. It never changes.
func (r Ref) ContextURL() string { return nsBase + r.path() }

// SchemaURL is where the JSON Schema document of the type version lives. It never changes.
func (r Ref) SchemaURL() string { return schemasBase + r.path() + ".json" }

// Namespace is what the fields of the type version are defined under: its context URL and "#".
func (r Ref) Namespace() string { return r.ContextURL() + "#" }

func parseRef(url, prefix, suffix string) (Ref, bool) {
	if !strings.HasPrefix(url, prefix) || !strings.HasSuffix(url, suffix) {
		return Ref{}, false
	}
	m := refPath.FindStringSubmatch(url[len(prefix) : len(url)-len(suffix)])
	if m == nil {
		return Ref{}, false
	}
	version, _ := strconv.Atoi(m[3])
	return Ref{Issuer: m[1], Name: m[2], Version: version}, true
}

// ParseContextURL reads a type version out of its context URL.
func ParseContextURL(url string) (Ref, bool) { return parseRef(url, nsBase, "") }

// ParseSchemaURL reads a type version out of its schema URL.
func ParseSchemaURL(url string) (Ref, bool) { return parseRef(url, schemasBase, ".json") }
