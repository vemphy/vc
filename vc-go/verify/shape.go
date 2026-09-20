package verify

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/vemphy/vc/vc-go/status"
	"github.com/vemphy/vc/vc-go/vcctx"
)

// The shape rules here are the same ones the TypeScript package expresses as
// zod schemas in packages/vc/src/schema. A document either side refuses, the
// other refuses too.

const slug = `[a-z]{2,4}`

var (
	issuerPattern     = regexp.MustCompile(`^did:web:vemphy\.com:i:` + slug + `$`)
	claimIDPattern    = regexp.MustCompile(`^urn:vemphy:claim:[A-Z]{2,4}-[0-9A-Z]{4}-[0-9A-Z]{3}[0-9A-Z*~$=]$`)
	keyPattern        = regexp.MustCompile(`^did:web:vemphy\.com:i:` + slug + `#key-[1-9]\d*$`)
	proofValuePattern = regexp.MustCompile(`^z[1-9A-HJ-NP-Za-km-z]+$`)
	listURLPattern    = regexp.MustCompile(`^https://vemphy\.com/i/` + slug + `/status/[1-9]\d*$`)
	indexPattern      = regexp.MustCompile(`^(0|[1-9]\d*)$`)
	encodedPattern    = regexp.MustCompile(`^u[A-Za-z0-9_-]+$`)
	datePattern       = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
	instantPattern    = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$`)
	last4Pattern      = regexp.MustCompile(`^\d{4}$`)
)

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
	Context           []string        `json:"@context"`
	ID                string          `json:"id"`
	Type              []string        `json:"type"`
	Issuer            string          `json:"issuer"`
	ValidFrom         string          `json:"validFrom"`
	ValidUntil        *string         `json:"validUntil"`
	CredentialSubject json.RawMessage `json:"credentialSubject"`
	CredentialStatus  *statusEntry    `json:"credentialStatus"`
	Proof             *proofShape     `json:"proof"`

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

func strictDecode(raw []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("trailing data")
	}
	return nil
}

// encoding/json matches member names to struct fields without regard to case.
// The schemas do not, so the exact spelling is checked separately.
func exactKeys(raw []byte, allowed map[string][]string) error {
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(raw, &doc); err != nil {
		return err
	}
	check := func(where string, obj map[string]json.RawMessage) error {
		for name := range obj {
			found := false
			for _, a := range allowed[where] {
				if name == a {
					found = true
				}
			}
			if !found {
				return fmt.Errorf("unknown member %q", name)
			}
		}
		return nil
	}
	if err := check("", doc); err != nil {
		return err
	}
	for name := range allowed {
		if name == "" || doc[name] == nil {
			continue
		}
		var nested map[string]json.RawMessage
		if err := json.Unmarshal(doc[name], &nested); err != nil {
			return fmt.Errorf("%s must be an object", name)
		}
		if err := check(name, nested); err != nil {
			return err
		}
	}
	return nil
}

var (
	proofKeys      = []string{"type", "cryptosuite", "created", "verificationMethod", "proofPurpose", "proofValue"}
	credentialKeys = map[string][]string{
		"":                 {"@context", "id", "type", "issuer", "validFrom", "validUntil", "credentialSubject", "credentialStatus", "proof"},
		"credentialStatus": {"id", "type", "statusPurpose", "statusListIndex", "statusListCredential"},
		"proof":            proofKeys,
	}
	statusListKeys = map[string][]string{
		"":                  {"@context", "id", "type", "issuer", "validFrom", "validUntil", "credentialSubject", "proof"},
		"credentialSubject": {"id", "type", "statusPurpose", "encodedList"},
		"proof":             proofKeys,
	}
)

func parseInstant(s string) (time.Time, error) {
	if !instantPattern.MatchString(s) {
		return time.Time{}, fmt.Errorf("%q is not an instant with an offset", s)
	}
	return time.Parse(time.RFC3339Nano, s)
}

func equal(a []string, b ...string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func slugOfDID(did string) string { return did[strings.LastIndexByte(did, ':')+1:] }

func (p *proofShape) check(issuer string) (time.Time, error) {
	if p == nil {
		return time.Time{}, errors.New("proof is required")
	}
	if p.Type != "DataIntegrityProof" || p.Cryptosuite != "eddsa-rdfc-2022" || p.ProofPurpose != "assertionMethod" {
		return time.Time{}, errors.New("proof is not an eddsa-rdfc-2022 assertion")
	}
	if !keyPattern.MatchString(p.VerificationMethod) || !strings.HasPrefix(p.VerificationMethod, issuer+"#") {
		return time.Time{}, errors.New("key does not belong to the issuer")
	}
	if !proofValuePattern.MatchString(p.ProofValue) {
		return time.Time{}, errors.New("proofValue is not base58btc")
	}
	return parseInstant(p.Created)
}

func parseCredential(raw []byte) (*credential, error) {
	var c credential
	if err := strictDecode(raw, &c); err != nil {
		return nil, err
	}
	if err := exactKeys(raw, credentialKeys); err != nil {
		return nil, err
	}
	if !equal(c.Context, vcctx.CredentialsV2, vcctx.ClaimsV1) {
		return nil, errors.New("@context must be exactly the credentials and claims contexts")
	}
	if len(c.Type) != 2 || c.Type[0] != "VerifiableCredential" {
		return nil, errors.New("type must be VerifiableCredential and one claim type")
	}
	fields, known := claimTypes[c.Type[1]]
	if !known {
		return nil, fmt.Errorf("unknown claim type %q", c.Type[1])
	}
	if !issuerPattern.MatchString(c.Issuer) || !claimIDPattern.MatchString(c.ID) {
		return nil, errors.New("issuer or id is malformed")
	}
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
	if s == nil || s.Type != "BitstringStatusListEntry" || s.StatusPurpose != "revocation" {
		return nil, errors.New("credentialStatus must be a revocation BitstringStatusListEntry")
	}
	if !listURLPattern.MatchString(s.StatusListCredential) || !indexPattern.MatchString(s.StatusListIndex) {
		return nil, errors.New("credentialStatus is malformed")
	}
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
	if err := checkSubject(c.Type[1], fields, c.CredentialSubject); err != nil {
		return nil, fmt.Errorf("credentialSubject: %w", err)
	}
	return &c, nil
}

func parseStatusList(raw []byte) (*statusListCredential, error) {
	var l statusListCredential
	if err := strictDecode(raw, &l); err != nil {
		return nil, err
	}
	if err := exactKeys(raw, statusListKeys); err != nil {
		return nil, err
	}
	if !equal(l.Context, vcctx.CredentialsV2) || !equal(l.Type, "VerifiableCredential", "BitstringStatusListCredential") {
		return nil, errors.New("not a BitstringStatusListCredential")
	}
	if !issuerPattern.MatchString(l.Issuer) || !listURLPattern.MatchString(l.ID) {
		return nil, errors.New("issuer or id is malformed")
	}
	if !strings.HasPrefix(l.ID, "https://vemphy.com/i/"+slugOfDID(l.Issuer)+"/status/") {
		return nil, errors.New("status list does not belong to the issuer")
	}
	s := l.CredentialSubject
	if s == nil || s.ID != l.ID+"#list" || s.Type != "BitstringStatusList" || s.StatusPurpose != "revocation" ||
		!encodedPattern.MatchString(s.EncodedList) {
		return nil, errors.New("credentialSubject is not a revocation BitstringStatusList")
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

// ---- claim subjects ---------------------------------------------------------

type kind int

const (
	text kind = iota
	date
	last4
	boolean
	enum
)

type field struct {
	kind     kind
	optional bool
	values   []string
}

var claimTypes = map[string]map[string]field{
	"BankReferenceLetter": {
		"accountHolderName":  {kind: text},
		"accountType":        {kind: enum, values: []string{"current", "savings", "business"}},
		"accountNumberLast4": {kind: last4},
		"accountOpenedOn":    {kind: date},
		"branch":             {kind: text},
		"standing":           {kind: enum, values: []string{"satisfactory", "unsatisfactory"}},
		"addressedTo":        {kind: text, optional: true},
		"referenceDate":      {kind: date},
	},
	"DegreeCertificate": {
		"graduateName":   {kind: text},
		"studentNumber":  {kind: text},
		"qualification":  {kind: text},
		"programme":      {kind: text},
		"classification": {kind: text, optional: true},
		"conferredOn":    {kind: date},
	},
	"EmploymentLetter": {
		"employeeName":      {kind: text},
		"staffNumber":       {kind: text, optional: true},
		"jobTitle":          {kind: text},
		"employmentType":    {kind: enum, values: []string{"permanent", "contract", "temporary", "internship"}},
		"startDate":         {kind: date},
		"endDate":           {kind: date, optional: true},
		"currentlyEmployed": {kind: boolean},
	},
}

func checkSubject(claimType string, fields map[string]field, raw json.RawMessage) error {
	var subject map[string]any
	if err := json.Unmarshal(raw, &subject); err != nil || subject == nil {
		return errors.New("must be an object")
	}
	for name := range subject {
		if _, ok := fields[name]; !ok {
			return fmt.Errorf("unknown field %q", name)
		}
	}
	for name, f := range fields {
		value, present := subject[name]
		if !present {
			if f.optional {
				continue
			}
			return fmt.Errorf("%s is required", name)
		}
		if err := f.check(value); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	if claimType == "EmploymentLetter" {
		if end, ok := subject["endDate"].(string); ok {
			if subject["currentlyEmployed"] == true {
				return errors.New("a current employee has no end date")
			}
			// ISO dates compare correctly as strings.
			if end < subject["startDate"].(string) {
				return errors.New("endDate must not be before startDate")
			}
		}
	}
	return nil
}

func (f field) check(value any) error {
	if f.kind == boolean {
		if _, ok := value.(bool); !ok {
			return errors.New("must be true or false")
		}
		return nil
	}
	s, ok := value.(string)
	if !ok {
		return errors.New("must be text")
	}
	switch f.kind {
	case text:
		// Length is counted the way JavaScript counts it, in UTF-16 units.
		if n := len(utf16.Encode([]rune(s))); n < 1 || n > 200 {
			return errors.New("must be 1-200 characters")
		}
		runes := []rune(s)
		if isJSSpace(runes[0]) || isJSSpace(runes[len(runes)-1]) {
			return errors.New("must not start or end with a space")
		}
	case date:
		if !datePattern.MatchString(s) {
			return errors.New("must be YYYY-MM-DD")
		}
		if _, err := time.Parse("2006-01-02", s); err != nil {
			return errors.New("is not a calendar date")
		}
	case last4:
		if !last4Pattern.MatchString(s) {
			return errors.New("must be four digits")
		}
	case enum:
		for _, v := range f.values {
			if s == v {
				return nil
			}
		}
		return fmt.Errorf("must be one of %s", strings.Join(f.values, ", "))
	}
	return nil
}

// The characters String.prototype.trim removes.
func isJSSpace(r rune) bool {
	switch {
	case r >= '\t' && r <= '\r', r == ' ', r == 0xA0, r == 0x1680, r >= 0x2000 && r <= 0x200A,
		r == 0x2028, r == 0x2029, r == 0x202F, r == 0x205F, r == 0x3000, r == 0xFEFF:
		return true
	}
	return false
}
