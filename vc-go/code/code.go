// Package code parses and formats Vemphy claim codes: <SLUG>-<XXXX>-<XXXX>.
//
// SLUG is 2-4 letters. The eight characters that follow are seven Crockford
// base32 characters and one Crockford mod-37 check character. The check
// character covers the slug as well as the body, so a mistyped slug is caught
// the same way a mistyped body character is.
package code

import (
	"fmt"
	"math/big"
	"net/url"
	"regexp"
	"strings"
)

const (
	Alphabet      = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	CheckAlphabet = Alphabet + "*~$=U"

	letters    = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	bodyLength = 7
	// 2^35 mod 37. The body is 35 bits, so the slug is weighted by this.
	slugWeight = 19
)

var (
	slugPattern = regexp.MustCompile(`^[A-Z]{2,4}$`)
	linkPattern = regexp.MustCompile(`(?i)^(?:https?://)?(?:www\.)?vemphy\.com/v/([^/?#]+)`)
	separators  = regexp.MustCompile(`[\s-]+`)
)

// Code is a parsed, normalised claim code.
type Code struct{ Slug, Body, Check string }

func (c Code) String() string {
	return c.Slug + "-" + c.Body[:4] + "-" + c.Body[4:] + c.Check
}

type ErrorKind string

const (
	ErrFormat ErrorKind = "format"
	ErrCheck  ErrorKind = "check"
)

// Candidate is a position where replacing Typed with Repair would make the
// check character agree. Position is 1-based with separators removed.
type Candidate struct {
	Position int
	Typed    byte
	Repair   byte
}

// ParseError reports why a code was rejected. Position is set for a format
// error caused by one invalid character. Suspects is set for a check error.
type ParseError struct {
	Kind     ErrorKind
	Position int
	Suspects []int
}

func (e *ParseError) Error() string {
	if e.Kind == ErrCheck {
		return "code: check character does not match"
	}
	if e.Position > 0 {
		return fmt.Sprintf("code: invalid character at position %d", e.Position)
	}
	return "code: not a claim code"
}

// CheckChar returns the Crockford mod-37 check symbol for a non-negative integer.
func CheckChar(n *big.Int) byte {
	return CheckAlphabet[new(big.Int).Mod(n, big.NewInt(37)).Int64()]
}

// CheckCharFor returns the check character for a normalised slug and body.
func CheckCharFor(slug, body string) byte {
	return CheckAlphabet[checkValue(slug, body)]
}

func checkValue(slug, body string) int {
	s := 0
	for i := 0; i < len(slug); i++ {
		s = (s*26 + strings.IndexByte(letters, slug[i])) % 37
	}
	n := 0
	for i := 0; i < len(body); i++ {
		n = (n*32 + strings.IndexByte(Alphabet, body[i])) % 37
	}
	return (slugWeight*s + n) % 37
}

func fold(c byte) byte {
	switch c {
	case 'O':
		return '0'
	case 'I', 'L':
		return '1'
	}
	return c
}

func foldAll(s string) string {
	b := []byte(s)
	for i := range b {
		b[i] = fold(b[i])
	}
	return string(b)
}

// Format builds the display form of a code, computing its check character.
func Format(slug, body string) string {
	s := strings.ToUpper(slug)
	b := foldAll(strings.ToUpper(body))
	return Code{Slug: s, Body: b, Check: string(CheckCharFor(s, b))}.String()
}

// IsIssuable is false when the check character is a symbol that chat
// applications treat as formatting.
func IsIssuable(c Code) bool {
	return strings.Contains(Alphabet, c.Check)
}

// Parse accepts a bare code in any case, with or without separators, or a
// vemphy.com/v/<code> link.
func Parse(input string) (Code, error) {
	text := strings.TrimSpace(input)
	if m := linkPattern.FindStringSubmatch(text); m != nil {
		decoded, err := url.PathUnescape(m[1])
		if err != nil {
			return Code{}, &ParseError{Kind: ErrFormat}
		}
		text = decoded
	}
	text = strings.ToUpper(text)

	slug, rest, ok := splitSlug(text)
	if !ok || len(rest) != bodyLength+1 {
		return Code{}, &ParseError{Kind: ErrFormat}
	}
	if !slugPattern.MatchString(slug) {
		if len(slug) <= 4 {
			for i := 0; i < len(slug); i++ {
				if strings.IndexByte(letters, slug[i]) < 0 {
					return Code{}, &ParseError{Kind: ErrFormat, Position: i + 1}
				}
			}
		}
		return Code{}, &ParseError{Kind: ErrFormat}
	}

	folded := foldAll(rest)
	for i := 0; i < len(folded); i++ {
		allowed := CheckAlphabet
		if i < bodyLength {
			allowed = Alphabet
		}
		if strings.IndexByte(allowed, folded[i]) < 0 {
			return Code{}, &ParseError{Kind: ErrFormat, Position: len(slug) + i + 1}
		}
	}
	body, check := folded[:bodyLength], folded[bodyLength]

	if CheckCharFor(slug, body) != check {
		return Code{}, &ParseError{Kind: ErrCheck, Suspects: RankSuspects(repairs(slug, body, check))}
	}
	return Code{Slug: slug, Body: body, Check: string(check)}, nil
}

// With separators the slug is whatever precedes the first one. Without them
// it is whatever is left after the last eight characters.
func splitSlug(text string) (slug, rest string, ok bool) {
	var parts []string
	for _, p := range separators.Split(text, -1) {
		if p != "" {
			parts = append(parts, p)
		}
	}
	switch len(parts) {
	case 0:
		return "", "", false
	case 1:
		only := parts[0]
		if len(only) <= bodyLength+1 {
			return "", "", false
		}
		cut := len(only) - (bodyLength + 1)
		return only[:cut], only[cut:], true
	}
	return parts[0], strings.Join(parts[1:], ""), true
}

// A mod-37 check detects a wrong character but cannot say which one it is.
// For each position this finds the single replacement, if any, that would make
// the check character agree.
func repairs(slug, body string, check byte) []Candidate {
	var out []Candidate
	target := strings.IndexByte(CheckAlphabet, check)

	for i := 0; i < len(slug); i++ {
		for j := 0; j < len(letters); j++ {
			c := letters[j]
			if c != slug[i] && checkValue(slug[:i]+string(c)+slug[i+1:], body) == target {
				out = append(out, Candidate{Position: i + 1, Typed: slug[i], Repair: c})
			}
		}
	}
	for i := 0; i < len(body); i++ {
		for j := 0; j < len(Alphabet); j++ {
			c := Alphabet[j]
			if c != body[i] && checkValue(slug, body[:i]+string(c)+body[i+1:]) == target {
				out = append(out, Candidate{Position: len(slug) + i + 1, Typed: body[i], Repair: c})
			}
		}
	}
	return append(out, Candidate{Position: len(slug) + len(body) + 1, Typed: check, Repair: CheckCharFor(slug, body)})
}

// RankSuspects orders the positions a person should re-check, most likely
// first. It must return the same order as rankSuspects in packages/vc/src/code.ts.
func RankSuspects(candidates []Candidate) []int {
	out := make([]int, len(candidates))
	for i, c := range candidates {
		out[i] = c.Position
	}
	return out
}
