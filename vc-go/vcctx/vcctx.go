// Package vcctx bundles the JSON-LD contexts a Vemphy claim may use and a
// document loader that serves them and nothing else.
package vcctx

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/piprate/json-gold/ld"
)

const (
	CredentialsV2 = "https://www.w3.org/ns/credentials/v2"
	ClaimsV1      = "https://vemphy.com/ns/claims/v1"
)

// credentials-v2.json is the W3C file, byte for byte. Its SHA-256 is published in the
// Verifiable Credentials Data Model 2.0 specification:
// 59955ced6697d61e03f2b2556febe5308ab16842846f5b586d7f1f7adec92734
//
//go:embed credentials-v2.json
var credentialsV2 []byte

//go:embed claims-v1.json
var claimsV1 []byte

// ErrUnknownContext is returned for any URL that is not a bundled context.
var ErrUnknownContext = errors.New("unknown context")

type loader struct{ documents map[string][]byte }

// Loader returns a document loader that serves the bundled contexts and
// nothing else. It never touches the network, so what a signature covers
// cannot be changed by whoever serves a context URL, and verification works
// offline.
//
// extra adds documents by URL. It exists for tests that use third-party
// fixtures; it cannot replace a bundled context.
func Loader(extra map[string][]byte) ld.DocumentLoader {
	documents := make(map[string][]byte, len(extra)+2)
	for u, d := range extra {
		documents[u] = d
	}
	documents[CredentialsV2] = credentialsV2
	documents[ClaimsV1] = claimsV1
	return &loader{documents}
}

func (l *loader) LoadDocument(u string) (*ld.RemoteDocument, error) {
	raw, ok := l.documents[u]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrUnknownContext, u)
	}
	// Decoded per call: the processor is free to modify what it is given.
	var doc any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("context %s: %w", u, err)
	}
	return &ld.RemoteDocument{DocumentURL: u, Document: doc}, nil
}
