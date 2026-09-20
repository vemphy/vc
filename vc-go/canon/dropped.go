package canon

import (
	"fmt"

	"github.com/piprate/json-gold/ld"

	"github.com/vemphy/vc/vc-go/schema"
	"github.com/vemphy/vc/vc-go/vcctx"
)

const (
	sampleContext     = "https://vemphy.com/ns/sample"
	credentialSubject = "https://www.w3.org/2018/credentials#credentialSubject"
)

// AssertNoDroppedTerms builds a claim with every property of the schema
// present, expands it under the context, and fails unless the type and every
// property come out the other side under namespace. A term that expansion
// drops is a field that would be issued unsigned.
//
// It deliberately does not run in safe mode: it must see what an ordinary
// JSON-LD processor would do with this context, not be told by ours.
func AssertNoDroppedTerms(s *schema.Schema, context []byte, namespace string) error {
	claim := map[string]any{
		"@context":          []any{vcctx.CredentialsV2, sampleContext},
		"type":              []any{"VerifiableCredential", s.Name},
		"credentialSubject": s.Sample(),
	}
	opts := ld.NewJsonLdOptions("")
	opts.ProcessingMode = ld.JsonLd_1_1
	opts.DocumentLoader = vcctx.Loader(map[string][]byte{sampleContext: context})
	expanded, err := ld.NewJsonLdProcessor().Expand(claim, opts)
	if err != nil {
		return fmt.Errorf("the context cannot be used: %w", err)
	}
	node, _ := first(expanded).(map[string]any)

	found := false
	types, _ := node["@type"].([]any)
	for _, t := range types {
		found = found || t == namespace+s.Name
	}
	if !found {
		return fmt.Errorf("the context drops the type %s", s.Name)
	}

	subject, _ := first(node[credentialSubject]).(map[string]any)
	for _, f := range s.Fields {
		if _, ok := subject[namespace+f.Key]; !ok {
			return fmt.Errorf("the context drops %s", f.Key)
		}
	}
	return nil
}

func first(v any) any {
	if list, ok := v.([]any); ok && len(list) > 0 {
		return list[0]
	}
	return nil
}
