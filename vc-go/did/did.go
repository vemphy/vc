// Package did resolves Vemphy issuer DIDs (did:web:vemphy.com:i:<slug>) to
// their document URL and reads signing keys out of DID documents. It also
// resolves Vemphy's own apex DID (did:web:vemphy.com), which signs the
// published issuer directory rather than any claim; see Apex and ParseApex,
// and package directory for checking the directory itself.
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

// Apex is Vemphy's own DID, at the apex of vemphy.com. Its key signs the
// published issuer directory (see the directory package) and nothing else:
// Vemphy is not an issuer of claims, so this constant is never accepted where
// an issuer DID is expected. See Parse and ParseApex.
const Apex = "did:web:vemphy.com"

// ApexURL is the address that the did:web method resolves Apex to: a DID with
// no path component resolves to /.well-known/did.json on its domain.
func ApexURL() string { return "https://vemphy.com/.well-known/did.json" }

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

// wireDocument is the shape shared by every DID document this module reads,
// whoever it belongs to: an issuer's, or Vemphy's own apex document.
type wireDocument struct {
	ID string `json:"id"`
	// Decoded through pointers so that a missing member is told apart from an empty one.
	VerificationMethod *[]VerificationMethod `json:"verificationMethod"`
	AssertionMethod    *[]string             `json:"assertionMethod"`
}

// parseDocument decodes raw and checks the parts of a DID document that do
// not depend on whose document it is. The caller checks the id.
func parseDocument(raw []byte) (*wireDocument, error) {
	var wire wireDocument
	if err := json.Unmarshal(raw, &wire); err != nil {
		return nil, fmt.Errorf("did document: %w", err)
	}
	if wire.VerificationMethod == nil || wire.AssertionMethod == nil {
		return nil, fmt.Errorf("did document: verificationMethod and assertionMethod are required")
	}
	for _, m := range *wire.VerificationMethod {
		if m.ID == "" || m.Controller == "" || m.Type != "Multikey" || !multibasePattern.MatchString(m.PublicKeyMultibase) {
			return nil, fmt.Errorf("did document: verification method %q is not a well-formed Multikey", m.ID)
		}
	}
	return &wire, nil
}

// Parse validates a DID document and checks that it describes did. did must
// be a Vemphy issuer DID: Vemphy's own apex DID is never accepted here, even
// when it is the very document the caller means to read, because this is the
// function verify.Credential uses to resolve a claim's issuer, and Vemphy is
// not an issuer of claims. Use ParseApex to read Vemphy's own DID document.
func Parse(raw []byte, did string) (*Document, error) {
	wire, err := parseDocument(raw)
	if err != nil {
		return nil, err
	}
	if !didPattern.MatchString(wire.ID) {
		return nil, fmt.Errorf("did document: id %q is not a Vemphy issuer DID", wire.ID)
	}
	if wire.ID != did {
		return nil, fmt.Errorf("did document is for %s, not %s", wire.ID, did)
	}
	return &Document{ID: wire.ID, VerificationMethod: *wire.VerificationMethod, AssertionMethod: *wire.AssertionMethod}, nil
}

// ParseApex reads Vemphy's own DID document: the one Apex resolves to, at
// ApexURL. It is kept separate from Parse, on purpose, rather than letting
// Parse also accept Apex: the two functions answer different questions, and
// conflating them would let a document meant only to authorise the issuer
// directory be read as though it authorised an ordinary claim.
func ParseApex(raw []byte) (*Document, error) {
	wire, err := parseDocument(raw)
	if err != nil {
		return nil, err
	}
	if wire.ID != Apex {
		return nil, fmt.Errorf("did document: id %q is not %s", wire.ID, Apex)
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

// UsableAt reports whether k could sign at the given instant: it must not
// have been revoked, and must not have expired, by then.
//
// Both halves are exclusive of the instant itself — a proof dated exactly
// when a key was revoked is refused. That is deliberate and is why this rule
// lives in one place: a DID document publishes a retired key's `expires` as
// the start of the second *after* it stopped signing, so that a proof made
// during that second is still covered, while `revoked` is published truncated
// down to its own second, so that a proof made during it is not. The two
// round opposite ways, and a second copy of the comparison would eventually
// disagree with the first about whether a signature holds.
func (k *Key) UsableAt(at time.Time) bool {
	if k.Revoked != nil && !at.Before(*k.Revoked) {
		return false
	}
	if k.Expires != nil && !at.Before(*k.Expires) {
		return false
	}
	return true
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
