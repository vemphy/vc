package schema

const xsd = "http://www.w3.org/2001/XMLSchema#"

var datatypes = map[Kind]string{
	KindInteger:  xsd + "integer",
	KindBoolean:  xsd + "boolean",
	KindDate:     xsd + "date",
	KindDateTime: xsd + "dateTime",
}

// GenerateContext builds the JSON-LD context for one version of a claim type,
// as canonical JSON. namespace is the context's own URL followed by "#" (see
// Ref.Namespace).
//
// Every property is defined, by name, with an identifier under the namespace.
// JSON-LD drops a term that no context defines, and a dropped field is a field
// the signature does not cover.
//
// contextFromSchema in the TypeScript package produces the same bytes.
func GenerateContext(s *Schema, namespace string) []byte {
	terms := map[string]any{"@protected": true, s.Name: namespace + s.Name}
	for _, f := range s.Fields {
		if datatype, ok := datatypes[f.Kind]; ok {
			terms[f.Key] = map[string]any{"@id": namespace + f.Key, "@type": datatype}
		} else {
			terms[f.Key] = namespace + f.Key
		}
	}
	out, err := CanonicalJSON(map[string]any{"@context": terms})
	if err != nil {
		panic(err) // Only strings and a boolean went in.
	}
	return out
}

// Sample is a subject with every property of the schema present, for checking
// what a context covers.
func (s *Schema) Sample() map[string]any {
	subject := make(map[string]any, len(s.Fields))
	for _, f := range s.Fields {
		subject[f.Key] = f.sample
	}
	return subject
}

// Document is what is served at a schema URL, as canonical JSON. A
// credentialSchema of type JsonSchema validates the whole credential (W3C,
// "Verifiable Credentials JSON Schema"), so the claim schema sits under
// credentialSubject.
func Document(s *Schema, url string) ([]byte, error) {
	subject := make(map[string]any, len(s.doc))
	for k, v := range s.doc {
		if k != "$schema" {
			subject[k] = v
		}
	}
	return CanonicalJSON(map[string]any{
		"$schema":    draft,
		"$id":        url,
		"title":      s.DisplayName["en"],
		"type":       "object",
		"required":   []string{"credentialSubject"},
		"properties": map[string]any{"credentialSubject": subject},
	})
}

// SubjectSchemaFrom returns the claim schema inside a schema document. It is
// not yet checked: give it to Parse.
func SubjectSchemaFrom(document []byte) ([]byte, bool) {
	decoded, err := Decode(document)
	if err != nil {
		return nil, false
	}
	doc, _ := decoded.(map[string]any)
	properties, _ := doc["properties"].(map[string]any)
	subject, ok := properties["credentialSubject"].(map[string]any)
	if !ok {
		return nil, false
	}
	out := map[string]any{"$schema": draft}
	for k, v := range subject {
		out[k] = v
	}
	raw, err := CanonicalJSON(out)
	return raw, err == nil
}
