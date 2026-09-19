// Package did resolves Vemphy issuer DIDs (did:web:vemphy.com:i:<slug>) to
// their document URL and reads signing keys out of DID documents.
package did

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/vemphy/vc/vc-go/multibase"
)

var (
	didPattern       = regexp.MustCompile(`^did:web:vemphy\.com:i:([a-z]{2,4})$`)
	multibasePattern = regexp.MustCompile(`^z[1-9A-HJ-NP-Za-km-z]+$`)
)

// SlugOf returns the issuer slug in a Vemphy DID, lowercase.
func SlugOf(did string) (string, error) {
	m := didPattern.FindStringSubmatch(did)
	if m == nil {
		return "", fmt.Errorf("not a Vemphy issuer DID: %s", did)
	}
	return m[1], nil
}

// URL maps did:web:vemphy.com:i:gcb to https://vemphy.com/i/gcb/did.json.
func URL(did string) (string, error) {
	slug, err := SlugOf(did)
	if err != nil {
		return "", err
	}
	return "https://vemphy.com/i/" + slug + "/did.json", nil
}

type VerificationMethod struct {
	ID                 string     `json:"id"`
	Type               string     `json:"type"`
	Controller         string     `json:"controller"`
	PublicKeyMultibase string     `json:"publicKeyMultibase"`
	Revoked            *time.Time `json:"revoked,omitempty"`
	Expires            *time.Time `json:"expires,omitempty"`
}

// Document is the part of a DID document that verification uses. DID
// documents are read, never signed over, so unknown members are allowed.
type Document struct {
	ID                 string               `json:"id"`
	VerificationMethod []VerificationMethod `json:"verificationMethod"`
	AssertionMethod    []string             `json:"assertionMethod"`
}

// Parse validates a DID document and checks that it describes did.
func Parse(raw []byte, did string) (*Document, error) {
	// Decoded through pointers so that a missing member is told apart from an empty one.
	var wire struct {
		ID                 string                `json:"id"`
		VerificationMethod *[]VerificationMethod `json:"verificationMethod"`
		AssertionMethod    *[]string             `json:"assertionMethod"`
	}
	if err := json.Unmarshal(raw, &wire); err != nil {
		return nil, fmt.Errorf("did document: %w", err)
	}
	if !didPattern.MatchString(wire.ID) {
		return nil, fmt.Errorf("did document: id %q is not a Vemphy issuer DID", wire.ID)
	}
	if wire.ID != did {
		return nil, fmt.Errorf("did document is for %s, not %s", wire.ID, did)
	}
	if wire.VerificationMethod == nil || wire.AssertionMethod == nil {
		return nil, fmt.Errorf("did document: verificationMethod and assertionMethod are required")
	}
	for _, m := range *wire.VerificationMethod {
		if m.ID == "" || m.Controller == "" || m.Type != "Multikey" || !multibasePattern.MatchString(m.PublicKeyMultibase) {
			return nil, fmt.Errorf("did document: verification method %q is not a well-formed Multikey", m.ID)
		}
	}
	return &Document{ID: wire.ID, VerificationMethod: *wire.VerificationMethod, AssertionMethod: *wire.AssertionMethod}, nil
}

// Key is a signing key found in an issuer's DID document.
type Key struct {
	PublicKey ed25519.PublicKey
	// Revoked, when set, is the instant from which signatures are not accepted.
	Revoked *time.Time
	Expires *time.Time
	// InAssertionMethod reports whether the key may sign new claims.
	// Retired and revoked keys may not.
	InAssertionMethod bool
}

// FindKey finds a key in the issuer's own DID document. A key controlled by
// anyone else is ignored. It returns nil, nil when there is no such key.
func FindKey(doc *Document, verificationMethod string) (*Key, error) {
	if !strings.HasPrefix(verificationMethod, doc.ID+"#") {
		return nil, nil
	}
	for _, m := range doc.VerificationMethod {
		if m.ID != verificationMethod || m.Controller != doc.ID {
			continue
		}
		pub, err := multibase.DecodeMultikey(m.PublicKeyMultibase)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", m.ID, err)
		}
		return &Key{
			PublicKey:         pub,
			Revoked:           m.Revoked,
			Expires:           m.Expires,
			InAssertionMethod: slices.Contains(doc.AssertionMethod, verificationMethod),
		}, nil
	}
	return nil, nil
}
