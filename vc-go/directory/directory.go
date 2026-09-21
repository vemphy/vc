// Package directory checks the issuer directory Vemphy publishes: a
// Verifiable Credential, issued by Vemphy's own apex DID (did.Apex), that
// lists the issuers Vemphy recognises. A receiver who holds this directory
// can pin trust to Vemphy rather than to DNS alone, provided the directory
// itself checks out.
//
// Verify follows the same pipeline as verify.Credential, in the same order —
// shape, then key, then key window, then signature — because a directory is
// read the same careful way a claim is. It differs after that: a directory
// either holds or it does not, so Verify returns a plain error rather than
// verify's four-answer Outcome, and it ends with one check a claim has no
// equivalent of, validUntil, because a directory going stale is the normal
// failure a receiver meets, not an attack.
package directory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/piprate/json-gold/ld"

	"github.com/vemphy/vc/vc-go/did"
	"github.com/vemphy/vc/vc-go/proof"
	"github.com/vemphy/vc/vc-go/schema"
	"github.com/vemphy/vc/vc-go/vcctx"
)

// credentialType is the type every published directory carries, alongside
// "VerifiableCredential".
const credentialType = "VemphyIssuerDirectoryCredential"

// ErrStale means the directory's signature and shape are trustworthy, but
// deps.Now is at or after its validUntil. A caller can tell this apart from
// every other refusal with errors.Is, because a stale directory is not wrong,
// it is merely due for a refresh, and the two deserve different handling.
var ErrStale = errors.New("directory: validUntil has passed")

// Entry is one issuer as the directory describes it.
type Entry struct {
	Slug      string `json:"slug"`
	LegalName string `json:"legalName"`
	DID       string `json:"did"`
	Status    string `json:"status"`
}

// Directory is what a verified issuer directory says.
type Directory struct {
	Entries    []Entry   `json:"entries"`
	ValidUntil time.Time `json:"validUntil"`
}

// Issuer finds an entry by slug, case-insensitively: slugs are lowercase by
// convention, but a receiver's own input need not be.
func (d *Directory) Issuer(slug string) (Entry, bool) {
	for _, e := range d.Entries {
		if strings.EqualFold(e.Slug, slug) {
			return e, true
		}
	}
	return Entry{}, false
}

// Deps is everything Verify needs from outside. Verify reads no clock and
// does no I/O of its own.
type Deps struct {
	Now time.Time
	// ResolveApex returns the document at did.ApexURL().
	ResolveApex func(ctx context.Context) ([]byte, error)
	// DocumentLoader loads JSON-LD contexts. Nil means the bundled ones,
	// offline: the W3C context and every core type. The directory's own
	// vocabulary is carried inline in its @context, so nothing beyond the W3C
	// context need ever be fetched to canonicalise it.
	DocumentLoader ld.DocumentLoader
}

var bundledContexts = vcctx.New(vcctx.Options{Allowlist: []string{}})

// wireProof is the part of a proof Verify reads. The full shape a proof must
// have is checked by proof.Verify itself, over the document as a whole; this
// is only what is needed to find and window-check the key beforehand.
type wireProof struct {
	VerificationMethod string `json:"verificationMethod"`
	Created            string `json:"created"`
}

type wireDirectory struct {
	Type              []string `json:"type"`
	Issuer            string   `json:"issuer"`
	ValidUntil        string   `json:"validUntil"`
	CredentialSubject struct {
		Issuers []Entry `json:"issuers"`
	} `json:"credentialSubject"`
	Proof *wireProof `json:"proof"`
}

func parseInstant(s string) (time.Time, error) {
	if !schema.IsDateTime(s) {
		return time.Time{}, fmt.Errorf("directory: %q is not an instant with an offset", s)
	}
	return time.Parse(time.RFC3339Nano, s)
}

// Verify checks a signed issuer directory and returns what it says.
func Verify(ctx context.Context, raw []byte, deps Deps) (*Directory, error) {
	loader := deps.DocumentLoader
	if loader == nil {
		loader = bundledContexts
	}

	// 1. Shape. A document claiming to be Vemphy's directory must say so in
	// its type, and it must be issued by Vemphy's apex DID and nothing else:
	// an issuer DID, however genuinely theirs, must never be read as the
	// directory Vemphy itself vouches for, because that would let any one
	// issuer publish a document a receiver could mistake for the list of
	// every issuer.
	var w wireDirectory
	if err := json.Unmarshal(raw, &w); err != nil {
		return nil, fmt.Errorf("directory: %w", err)
	}
	var document map[string]any
	if err := json.Unmarshal(raw, &document); err != nil {
		return nil, fmt.Errorf("directory: %w", err)
	}
	if !slices.Contains(w.Type, "VerifiableCredential") || !slices.Contains(w.Type, credentialType) {
		return nil, fmt.Errorf("directory: type does not include %s", credentialType)
	}
	if w.Issuer != did.Apex {
		return nil, fmt.Errorf("directory: issuer %q is not %s", w.Issuer, did.Apex)
	}
	if w.Proof == nil || w.Proof.VerificationMethod == "" {
		return nil, errors.New("directory: proof.verificationMethod is required")
	}
	created, err := parseInstant(w.Proof.Created)
	if err != nil {
		return nil, err
	}
	validUntil, err := parseInstant(w.ValidUntil)
	if err != nil {
		return nil, err
	}

	// 2. Key, resolved from Vemphy's own apex document, never an issuer's.
	if deps.ResolveApex == nil {
		return nil, errors.New("directory: deps.ResolveApex is required")
	}
	apexRaw, err := deps.ResolveApex(ctx)
	if err != nil {
		return nil, fmt.Errorf("directory: resolving the apex document: %w", err)
	}
	apex, err := did.ParseApex(apexRaw)
	if err != nil {
		return nil, fmt.Errorf("directory: %w", err)
	}
	key, err := did.FindKey(apex, w.Proof.VerificationMethod)
	if err != nil {
		return nil, fmt.Errorf("directory: %w", err)
	}
	if key == nil {
		return nil, fmt.Errorf("directory: no key %s in Vemphy's apex document", w.Proof.VerificationMethod)
	}

	// 3. The key must not have been revoked or expired when the proof was made.
	if !key.UsableAt(created) {
		return nil, fmt.Errorf("directory: key %s was not usable when the proof was made", w.Proof.VerificationMethod)
	}

	// 4. Signature, over the document exactly as published: the inline
	// vocabulary in @context is what makes every field of an entry, including
	// legalName and status, part of what is signed.
	ok, err := proof.Verify(document, key.PublicKey, loader)
	if err != nil {
		return nil, fmt.Errorf("directory: %w", err)
	}
	if !ok {
		return nil, errors.New("directory: signature does not match")
	}

	// 5. validUntil. Checked last, and given its own sentinel error, because a
	// directory that is merely old is the failure a receiver meets day to
	// day, not an attack, and deserves an answer they can tell apart from
	// every other refusal.
	if !deps.Now.Before(validUntil) {
		return nil, ErrStale
	}

	return &Directory{Entries: w.CredentialSubject.Issuers, ValidUntil: validUntil}, nil
}
