package verify

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/vemphy/vc/vc-go/schema"
	"github.com/vemphy/vc/vc-go/status"
)

// The structure of everything outside credentialSubject is described by
// schema/envelope/envelope.json, shared with the TypeScript package. The rules
// below span more than one field, which JSON Schema cannot say. A document
// either side refuses, the other refuses too.

type proofShape struct {
	Type               string `json:"type"`
	Cryptosuite        string `json:"cryptosuite"`
	Created            string `json:"created"`
	VerificationMethod string `json:"verificationMethod"`
	ProofPurpose       string `json:"proofPurpose"`
	ProofValue         string `json:"proofValue"`
}

type statusEntry struct {
	ID                   string `json:"id"`
	Type                 string `json:"type"`
	StatusPurpose        string `json:"statusPurpose"`
	StatusListIndex      string `json:"statusListIndex"`
	StatusListCredential string `json:"statusListCredential"`
}

type credential struct {
	Context          []string `json:"@context"`
	ID               string   `json:"id"`
	Type             []string `json:"type"`
	Issuer           string   `json:"issuer"`
	ValidFrom        string   `json:"validFrom"`
	ValidUntil       *string  `json:"validUntil"`
	CredentialSchema *struct {
		ID   string `json:"id"`
		Type string `json:"type"`
	} `json:"credentialSchema"`
	CredentialSubject json.RawMessage `json:"credentialSubject"`
	CredentialStatus  *statusEntry    `json:"credentialStatus"`
	Proof             *proofShape     `json:"proof"`

	// ref is the type version the claim is issued under; legacy is set for a claims/v1 claim.
	ref    schema.Ref
	legacy bool

	index      int
	validFrom  time.Time
	validUntil *time.Time
	created    time.Time
}

type statusListCredential struct {
	Context           []string `json:"@context"`
	ID                string   `json:"id"`
	Type              []string `json:"type"`
	Issuer            string   `json:"issuer"`
	ValidFrom         string   `json:"validFrom"`
	ValidUntil        string   `json:"validUntil"`
	CredentialSubject *struct {
		ID            string `json:"id"`
		Type          string `json:"type"`
		StatusPurpose string `json:"statusPurpose"`
		EncodedList   string `json:"encodedList"`
	} `json:"credentialSubject"`
	Proof *proofShape `json:"proof"`

	validFrom, validUntil, created time.Time
}

// decode checks raw against an envelope definition and then reads it into v.
// The schema has already refused unknown and misspelt members, so the
// case-insensitive matching of encoding/json cannot let anything through.
func decode(raw []byte, definition string, v any) error {
	doc, err := schema.Decode(raw)
	if err != nil {
		return err
	}
	if err := schema.ValidateEnvelope(definition, doc); err != nil {
		return err
	}
	return json.Unmarshal(raw, v)
}

func parseInstant(s string) (time.Time, error) {
	if !schema.IsDateTime(s) {
		return time.Time{}, fmt.Errorf("%q is not an instant with an offset", s)
	}
	return time.Parse(time.RFC3339Nano, s)
}

func slugOfDID(did string) string { return did[strings.LastIndexByte(did, ':')+1:] }

func (p *proofShape) check(issuer string) (time.Time, error) {
	if !strings.HasPrefix(p.VerificationMethod, issuer+"#") {
		return time.Time{}, errors.New("key does not belong to the issuer")
	}
	return parseInstant(p.Created)
}

func parseCredential(raw []byte) (*credential, error) {
	var c credential
	if err := decode(raw, "credential", &c); err != nil {
		return nil, err
	}

	// Everything in a claim has to name the same issuer: the slug in the code,
	// the issuer DID, the status list URL, the key that signed it, and the
	// vocabulary it uses when that belongs to an issuer.
	issuerSlug := slugOfDID(c.Issuer)
	if !strings.HasPrefix(c.ID, "urn:vemphy:claim:"+strings.ToUpper(issuerSlug)+"-") {
		return nil, errors.New("code does not belong to the issuer")
	}

	var err error
	if c.validFrom, err = parseInstant(c.ValidFrom); err != nil {
		return nil, err
	}
	if c.ValidUntil != nil {
		until, err := parseInstant(*c.ValidUntil)
		if err != nil {
			return nil, err
		}
		if !until.After(c.validFrom) {
			return nil, errors.New("validUntil must be after validFrom")
		}
		c.validUntil = &until
	}

	s := c.CredentialStatus
	if c.index, err = strconv.Atoi(s.StatusListIndex); err != nil || c.index >= status.ListBits {
		return nil, errors.New("status index is past the end of the list")
	}
	if s.ID != s.StatusListCredential+"#"+s.StatusListIndex {
		return nil, errors.New("credentialStatus.id must be the list URL followed by # and the index")
	}
	if !strings.HasPrefix(s.StatusListCredential, "https://vemphy.com/i/"+issuerSlug+"/status/") {
		return nil, errors.New("status list does not belong to the issuer")
	}
	if c.created, err = c.Proof.check(c.Issuer); err != nil {
		return nil, err
	}

	claimType := c.Type[1]
	if c.Context[1] == schema.LegacyContext {
		if !slices.Contains(schema.LegacyTypes, claimType) {
			return nil, errors.New("type is not defined by claims/v1")
		}
		if c.CredentialSchema != nil {
			return nil, errors.New("a claims/v1 claim has no credentialSchema")
		}
		c.legacy, c.ref = true, schema.Ref{Name: claimType, Version: 1}
		return &c, nil
	}
	ref, ok := schema.ParseContextURL(c.Context[1])
	switch {
	case !ok:
		return nil, errors.New("context is not a Vemphy type context")
	case ref.Name != claimType:
		return nil, errors.New("type does not match its context")
	case ref.Issuer != "" && ref.Issuer != issuerSlug:
		return nil, errors.New("context belongs to another issuer")
	case c.CredentialSchema == nil || c.CredentialSchema.ID != ref.SchemaURL():
		return nil, errors.New("credentialSchema does not match the context")
	}
	c.ref = ref
	return &c, nil
}

func parseStatusList(raw []byte) (*statusListCredential, error) {
	var l statusListCredential
	if err := decode(raw, "statusListCredential", &l); err != nil {
		return nil, err
	}
	if !strings.HasPrefix(l.ID, "https://vemphy.com/i/"+slugOfDID(l.Issuer)+"/status/") {
		return nil, errors.New("status list does not belong to the issuer")
	}
	if l.CredentialSubject.ID != l.ID+"#list" {
		return nil, errors.New("credentialSubject.id must be the list URL followed by #list")
	}
	var err error
	if l.validFrom, err = parseInstant(l.ValidFrom); err != nil {
		return nil, err
	}
	if l.validUntil, err = parseInstant(l.ValidUntil); err != nil {
		return nil, err
	}
	if l.created, err = l.Proof.check(l.Issuer); err != nil {
		return nil, err
	}
	return &l, nil
}
