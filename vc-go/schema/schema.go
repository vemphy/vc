// Package schema holds the rules for the subject of each Vemphy claim type.
package schema

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf16"
)

var (
	datePattern  = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
	last4Pattern = regexp.MustCompile(`^\d{4}$`)
)

// ClaimTypes lists the claim types defined by the claims v1 context, sorted.
func ClaimTypes() []string {
	out := make([]string, 0, len(claimTypes))
	for name := range claimTypes {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// IsClaimType reports whether name is a known claim type.
func IsClaimType(name string) bool {
	_, ok := claimTypes[name]
	return ok
}

// Fields lists the subject fields a claim type defines, sorted.
func Fields(claimType string) []string {
	out := make([]string, 0, len(claimTypes[claimType]))
	for name := range claimTypes[claimType] {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// DefaultDisclosure returns the subject fields shown to anyone who verifies a
// claim of this type, unless the issuer's policy says otherwise.
func DefaultDisclosure(claimType string) []string {
	return append([]string(nil), defaultDisclosure[claimType]...)
}

var defaultDisclosure = map[string][]string{
	"BankReferenceLetter": {"accountHolderName", "accountType", "standing", "referenceDate"},
	"DegreeCertificate":   {"graduateName", "qualification", "programme", "classification", "conferredOn"},
	"EmploymentLetter":    {"employeeName", "jobTitle", "startDate", "currentlyEmployed"},
}

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

// ValidateSubject checks a credentialSubject against the rules for its claim
// type: known fields only, required fields present, each value well formed.
// These are the rules the TypeScript package expresses as zod schemas in
// packages/vc/src/schema; a subject either side refuses, the other refuses too.
func ValidateSubject(claimType string, raw json.RawMessage) error {
	fields, known := claimTypes[claimType]
	if !known {
		return fmt.Errorf("unknown claim type %q", claimType)
	}
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
