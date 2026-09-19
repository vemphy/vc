// Package canon produces RDFC-1.0 canonical N-Quads for JSON-LD documents.
package canon

import (
	"fmt"
	"strings"

	"github.com/piprate/json-gold/ld"

	"github.com/vemphy/vc/vc-go/vcctx"
)

var defaultLoader = vcctx.Loader(nil)

// Canonicalize returns the canonical N-Quads for doc. A nil loader means the
// bundled contexts only.
//
// It runs in safe mode: a property or type that no context defines is an
// error rather than being dropped, because a dropped property would not be
// signed.
func Canonicalize(doc map[string]any, loader ld.DocumentLoader) (string, error) {
	if loader == nil {
		loader = defaultLoader
	}
	opts := ld.NewJsonLdOptions("")
	opts.ProcessingMode = ld.JsonLd_1_1
	opts.Algorithm = ld.AlgorithmURDNA2015
	opts.Format = "application/n-quads"
	opts.DocumentLoader = loader
	opts.SafeMode = true

	// The two stages are run separately. JsonLdProcessor.Normalize (json-gold
	// v0.8.0) builds fresh options for its internal ToRDF call and leaves
	// SafeMode behind, so undefined properties would be dropped without an error.
	//
	// json-gold's safe mode covers properties only. A type or id that no
	// context resolves stays a relative reference and would be left out of the
	// dataset, so the expanded form is checked for those before going further.
	toRDF := *opts
	toRDF.Format = ""
	expanded, err := ld.NewJsonLdProcessor().Expand(doc, &toRDF)
	if err != nil {
		return "", fmt.Errorf("canonicalize: %w", err)
	}
	if err := requireAbsolute(expanded); err != nil {
		return "", fmt.Errorf("canonicalize: %w", err)
	}
	dataset, err := ld.NewJsonLdProcessor().ToRDF(expanded, &toRDF)
	if err != nil {
		return "", fmt.Errorf("canonicalize: %w", err)
	}
	out, err := ld.NewJsonLdApi().Normalize(dataset.(*ld.RDFDataset), opts)
	if err != nil {
		return "", fmt.Errorf("canonicalize: %w", err)
	}
	nquads, ok := out.(string)
	if !ok {
		return "", fmt.Errorf("canonicalize: unexpected result type %T", out)
	}
	return nquads, nil
}

// requireAbsolute walks an expanded document and fails on any @type or @id
// that is not an absolute IRI or a blank node label.
func requireAbsolute(node any) error {
	switch v := node.(type) {
	case []any:
		for _, item := range v {
			if err := requireAbsolute(item); err != nil {
				return err
			}
		}
	case map[string]any:
		_, isValue := v["@value"]
		for key, value := range v {
			// In a value object @type is a datatype; it is still an IRI.
			if key == "@id" || key == "@type" {
				if err := requireAbsoluteRefs(key, value); err != nil {
					return err
				}
				continue
			}
			if isValue {
				continue
			}
			if err := requireAbsolute(value); err != nil {
				return err
			}
		}
	}
	return nil
}

func requireAbsoluteRefs(key string, value any) error {
	refs, ok := value.([]any)
	if !ok {
		refs = []any{value}
	}
	for _, ref := range refs {
		s, ok := ref.(string)
		if !ok || !strings.Contains(s, ":") {
			return fmt.Errorf("%s %v does not resolve to an absolute IRI", key, ref)
		}
	}
	return nil
}
