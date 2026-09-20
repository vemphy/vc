// Package schema is what a Vemphy claim type may look like and how it is
// checked. A claim type is a document: a restricted JSON Schema (2020-12)
// describing credentialSubject, from which the type's JSON-LD context is
// generated. packages/vc/src/schema is the same thing in TypeScript, and
// vectors/schemas holds the cases both must agree on.
package schema

import (
	"bytes"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/santhosh-tekuri/jsonschema/v6/kind"
	"golang.org/x/text/language"
	"golang.org/x/text/message"
)

//go:embed core/*.json meta/*.json envelope/*.json
var files embed.FS

const (
	metaURL     = "https://vemphy.com/schemas/meta/claim-schema/v1.json"
	envelopeURL = "https://vemphy.com/schemas/envelope/v1.json"
	draft       = "https://json-schema.org/draft/2020-12/schema"
)

// Problem is one reason a schema or a subject was refused.
type Problem struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

func (p Problem) String() string { return strings.TrimSpace(p.Field + " " + p.Message) }

// Labels is text in one or more languages, keyed by language tag. "en" is always present.
type Labels map[string]string

// Kind is how a value should be shown. It is derived from the schema so that
// nothing downstream needs schema logic.
type Kind string

const (
	KindText      Kind = "text"
	KindMultiline Kind = "multiline"
	KindDecimal   Kind = "decimal"
	KindInteger   Kind = "integer"
	KindBoolean   Kind = "boolean"
	KindDate      Kind = "date"
	KindDateTime  Kind = "datetime"
	KindEmail     Kind = "email"
	KindURI       Kind = "uri"
	KindChoice    Kind = "choice"
)

// Field is one property of a claim schema.
type Field struct {
	Key  string
	Kind Kind
	// Label is what a person sees next to the value.
	Label Labels
	// Disclosable says whether the issuer may choose to show this field to someone verifying a claim.
	Disclosable bool
	PII         bool
	Order       int
	Required    bool
	EnumLabels  map[string]Labels

	sample any
}

// Schema is a checked claim schema, ready to validate subjects.
type Schema struct {
	Name        string
	DisplayName Labels
	// Fields are in the order the schema gives them.
	Fields []Field

	raw       []byte
	doc       map[string]any
	validator *jsonschema.Schema
}

// JSON returns the schema document as it was given.
func (s *Schema) JSON() []byte { return append([]byte(nil), s.raw...) }

// Field returns a field by key.
func (s *Schema) Field(key string) (Field, bool) {
	for _, f := range s.Fields {
		if f.Key == key {
			return f, true
		}
	}
	return Field{}, false
}

func newCompiler() *jsonschema.Compiler {
	c := jsonschema.NewCompiler()
	c.DefaultDraft(jsonschema.Draft2020)
	c.AssertFormat()
	for name, check := range map[string]func(string) bool{"date": IsDate, "date-time": IsDateTime, "email": IsEmail, "uri": IsURI} {
		c.RegisterFormat(&jsonschema.Format{Name: name, Validate: func(v any) error {
			if s, ok := v.(string); ok && !check(s) {
				return fmt.Errorf("is not a valid %s", name)
			}
			return nil
		}})
	}
	return c
}

var shared = sync.OnceValue(func() *jsonschema.Compiler {
	c := newCompiler()
	for url, path := range map[string]string{metaURL: "meta/vemphy-claim-schema.json", envelopeURL: "envelope/envelope.json"} {
		raw, err := files.ReadFile(path)
		if err != nil {
			panic(err)
		}
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
		if err != nil {
			panic(err)
		}
		if err := c.AddResource(url, doc); err != nil {
			panic(err)
		}
	}
	return c
})

var meta = sync.OnceValue(func() *jsonschema.Schema { return shared().MustCompile(metaURL) })

var (
	envelopeMu    sync.Mutex
	envelopeCache = map[string]*jsonschema.Schema{}
)

// ValidateEnvelope checks a decoded document (see Decode) against one of the
// definitions in envelope/envelope.json: credential, unsignedCredential,
// statusListCredential or didDocument.
func ValidateEnvelope(definition string, doc any) error {
	envelopeMu.Lock()
	v, ok := envelopeCache[definition]
	if !ok {
		v = shared().MustCompile(envelopeURL + "#/$defs/" + definition)
		envelopeCache[definition] = v
	}
	envelopeMu.Unlock()
	return v.Validate(doc)
}

// Decode reads JSON the way the validator needs it: numbers keep their text.
func Decode(raw []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	if dec.More() {
		return nil, errors.New("trailing data")
	}
	return v, nil
}

// Validate checks that a document is a legitimate Vemphy claim schema: the
// meta-schema, then the rules JSON Schema cannot express. It returns every
// problem found; none means the schema may be published.
func Validate(raw []byte) []Problem {
	_, problems := parse(raw)
	return problems
}

// Parse checks a claim schema and compiles it. Nothing outside the restricted
// subset is ever compiled.
func Parse(raw []byte) (*Schema, error) {
	s, problems := parse(raw)
	if len(problems) > 0 {
		return nil, fmt.Errorf("not a Vemphy claim schema: %s", problems[0])
	}
	return s, nil
}

func parse(raw []byte) (*Schema, []Problem) {
	decoded, err := Decode(raw)
	if err != nil {
		return nil, []Problem{{Message: "is not JSON: " + err.Error()}}
	}
	doc, ok := decoded.(map[string]any)
	if !ok {
		return nil, []Problem{{Message: "must be an object"}}
	}
	if err := meta().Validate(doc); err != nil {
		return nil, toProblems(err)
	}

	root := doc["x-vemphy"].(map[string]any)
	s := &Schema{Name: root["name"].(string), DisplayName: toLabels(root["displayName"]), raw: append([]byte(nil), raw...), doc: doc}

	var problems []Problem
	at := func(key, format string, args ...any) {
		problems = append(problems, Problem{Field: "properties." + key, Message: fmt.Sprintf(format, args...)})
	}

	properties := doc["properties"].(map[string]any)
	required := map[string]bool{}
	if list, ok := doc["required"].([]any); ok {
		for _, item := range list {
			name := item.(string)
			required[name] = true
			if _, ok := properties[name]; !ok {
				problems = append(problems, Problem{Field: "required", Message: name + " is not a property"})
			}
		}
	}

	orders := map[int]string{}
	for key, value := range properties {
		p := value.(map[string]any)
		x := p["x-vemphy"].(map[string]any)
		f := Field{
			Key:         key,
			Label:       toLabels(x["label"]),
			Disclosable: x["disclosable"].(bool),
			PII:         x["pii"].(bool),
			Order:       int(wholeNumber(x["order"])),
			Required:    required[key],
		}
		if other, ok := orders[f.Order]; ok {
			// Name the two in a fixed order so the message does not depend on map iteration.
			a, b := key, other
			if b < a {
				a, b = b, a
			}
			at(b, "has the same order as %s", a)
		}
		orders[f.Order] = key

		switch {
		case p["type"] == "integer":
			f.Kind, f.sample = KindInteger, p["minimum"]
			if wholeNumber(p["minimum"]) > wholeNumber(p["maximum"]) {
				at(key, "minimum is greater than maximum")
			}
		case p["type"] == "boolean":
			f.Kind, f.sample = KindBoolean, true
		case p["enum"] != nil:
			values := p["enum"].([]any)
			f.Kind, f.sample = KindChoice, values[0]
			if labels, ok := x["enumLabels"].(map[string]any); ok {
				f.EnumLabels = map[string]Labels{}
				for value, l := range labels {
					f.EnumLabels[value] = toLabels(l)
					if !contains(values, value) {
						at(key, "enumLabels names %s, which is not in enum", value)
					}
				}
			}
		case p["format"] != nil:
			switch p["format"] {
			case "date":
				f.Kind, f.sample = KindDate, "2026-01-01"
			case "date-time":
				f.Kind, f.sample = KindDateTime, "2026-01-01T00:00:00Z"
			case "email":
				f.Kind, f.sample = KindEmail, "a@example.com"
			default:
				f.Kind, f.sample = KindURI, "https://example.com/"
			}
		default:
			f.Kind, f.sample = KindText, "x"
			if k, ok := x["kind"].(string); ok {
				f.Kind = Kind(k)
			}
			if pattern, ok := p["pattern"].(string); ok {
				if problem := PatternProblem(pattern); problem != "" {
					at(key, "pattern: %s", problem)
				}
			}
			if p["minLength"] != nil && wholeNumber(p["minLength"]) > wholeNumber(p["maxLength"]) {
				at(key, "minLength is greater than maxLength")
			}
		}
		s.Fields = append(s.Fields, f)
	}
	if len(problems) > 0 {
		sort.Slice(problems, func(i, j int) bool { return problems[i].String() < problems[j].String() })
		return nil, problems
	}
	sort.Slice(s.Fields, func(i, j int) bool { return s.Fields[i].Order < s.Fields[j].Order })

	// Its own compiler: these schemas are not ours to keep.
	c := newCompiler()
	if err := c.AddResource("claim-schema.json", doc); err != nil {
		return nil, []Problem{{Message: err.Error()}}
	}
	validator, err := c.Compile("claim-schema.json")
	if err != nil {
		return nil, []Problem{{Message: err.Error()}}
	}
	s.validator = validator
	return s, nil
}

// ValidateSubject validates a claim's credentialSubject, given as JSON.
func (s *Schema) ValidateSubject(subject []byte) []Problem {
	doc, err := Decode(subject)
	if err != nil {
		return []Problem{{Message: "is not JSON: " + err.Error()}}
	}
	if err := s.validator.Validate(doc); err != nil {
		return toProblems(err)
	}
	return nil
}

func wholeNumber(v any) int64 {
	n, _ := v.(json.Number)
	if i, err := n.Int64(); err == nil {
		return i
	}
	f, _ := n.Float64()
	return int64(f)
}

func toLabels(v any) Labels {
	labels := Labels{}
	for lang, text := range v.(map[string]any) {
		labels[lang] = text.(string)
	}
	return labels
}

func contains(values []any, s string) bool {
	for _, v := range values {
		if v == s {
			return true
		}
	}
	return false
}

var english = message.NewPrinter(language.English)

// toProblems flattens a validation error into one problem per failing place.
func toProblems(err error) []Problem {
	var ve *jsonschema.ValidationError
	if !errors.As(err, &ve) {
		return []Problem{{Message: err.Error()}}
	}
	var problems []Problem
	var walk func(e *jsonschema.ValidationError)
	walk = func(e *jsonschema.ValidationError) {
		if len(e.Causes) > 0 {
			for _, cause := range e.Causes {
				walk(cause)
			}
			return
		}
		field := strings.Join(e.InstanceLocation, ".")
		join := func(name string) string {
			if field == "" {
				return name
			}
			return field + "." + name
		}
		switch k := e.ErrorKind.(type) {
		case *kind.Required:
			for _, missing := range k.Missing {
				problems = append(problems, Problem{Field: join(missing), Message: "is required"})
			}
		case *kind.AdditionalProperties:
			for _, extra := range k.Properties {
				problems = append(problems, Problem{Field: field, Message: "must not have the property " + extra})
			}
		default:
			problems = append(problems, Problem{Field: field, Message: e.ErrorKind.LocalizedString(english)})
		}
	}
	walk(ve)
	return problems
}
