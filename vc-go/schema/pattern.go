package schema

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// JSON Schema says a "pattern" is an ECMA-262 regular expression. Go uses RE2.
// The two disagree about lookarounds and backreferences, and more quietly
// about \s, \w, \b and the dot. A Vemphy claim schema may only use syntax that
// means the same in both, which this file checks.
// packages/vc/src/schema/pattern.ts is the same code in TypeScript.

const (
	escapes   = `\./()[]{}*+?|^$`
	control   = "tnr"
	maxRepeat = 1000
)

var repeatPattern = regexp.MustCompile(`^(\d{1,4})(,(\d{0,4}))?$`)

// PatternProblem returns why a pattern is not allowed, or "" when it is.
func PatternProblem(pattern string) string {
	chars := []rune(pattern)
	if len(chars) == 0 || len(chars) > 200 {
		return "must be 1-200 characters"
	}
	i, depth := 0, 0
	// Whether the previous token is something a quantifier can repeat.
	atom := false

	for i < len(chars) {
		c := chars[i]
		switch {
		case c == '\\':
			if i+1 >= len(chars) {
				return "ends with a backslash"
			}
			next := chars[i+1]
			if next != 'd' && !strings.ContainsRune(escapes, next) && !strings.ContainsRune(control, next) {
				return fmt.Sprintf(`\%c is not allowed`, next)
			}
			i += 2
			atom = true
		case c == '[':
			end, problem := classEnd(chars, i)
			if problem != "" {
				return problem
			}
			i = end
			atom = true
		case c == '(':
			if i+1 < len(chars) && chars[i+1] == '?' {
				if i+2 >= len(chars) || chars[i+2] != ':' {
					return "only (?:...) groups are allowed"
				}
				i += 3
			} else {
				i++
			}
			depth++
			if depth > 10 {
				return "groups are nested too deeply"
			}
			atom = false
		case c == ')':
			if depth == 0 {
				return "unmatched )"
			}
			depth--
			i++
			atom = true
		case c == '*' || c == '+' || c == '?' || c == '{':
			if !atom {
				return fmt.Sprintf("nothing for %c to repeat", c)
			}
			if c == '{' {
				end, problem := repeatEnd(chars, i)
				if problem != "" {
					return problem
				}
				i = end
			} else {
				i++
			}
			// A second quantifier would be lazy (+?), possessive (++) or an error.
			atom = false
		case c == '^' || c == '$' || c == '|':
			i++
			atom = false
		case c == '.':
			return ". is not allowed; use a character class"
		case c == ']' || c == '}':
			return fmt.Sprintf("%c must be escaped", c)
		default:
			i++
			atom = true
		}
	}
	if depth != 0 {
		return "unmatched ("
	}
	return ""
}

// classEnd returns the index after the closing bracket, or a problem.
func classEnd(chars []rune, start int) (int, string) {
	i := start + 1
	if i < len(chars) && chars[i] == '^' {
		i++
	}
	members := 0
	// The previous member when it could start a range; -1 otherwise.
	low := rune(-1)
	for i < len(chars) {
		c := chars[i]
		switch c {
		case ']':
			if members == 0 {
				return 0, "empty character class"
			}
			return i + 1, ""
		case '[':
			return 0, "[ must be escaped inside a character class"
		case '^':
			return 0, "^ must be escaped inside a character class"
		case '-':
			if low < 0 || i+1 >= len(chars) || chars[i+1] == ']' {
				return 0, "- must be escaped unless it forms a range"
			}
			next, high, problem := classMember(chars, i+1)
			if problem != "" {
				return 0, problem
			}
			if high < 0 {
				return 0, `\d cannot end a range`
			}
			if high < low {
				return 0, "range is out of order"
			}
			i = next
			low = -1
			continue
		}
		next, point, problem := classMember(chars, i)
		if problem != "" {
			return 0, problem
		}
		i = next
		low = point
		members++
	}
	return 0, "unmatched ["
}

// classMember returns the index after one member and its code point, or -1 for \d.
func classMember(chars []rune, i int) (int, rune, string) {
	c := chars[i]
	if c != '\\' {
		return i + 1, c, ""
	}
	if i+1 >= len(chars) {
		return 0, 0, "ends with a backslash"
	}
	next := chars[i+1]
	switch {
	case next == 'd':
		return i + 2, -1, ""
	case next == '-' || strings.ContainsRune(escapes, next):
		return i + 2, next, ""
	case next == 't':
		return i + 2, 9, ""
	case next == 'n':
		return i + 2, 10, ""
	case next == 'r':
		return i + 2, 13, ""
	}
	return 0, 0, fmt.Sprintf(`\%c is not allowed`, next)
}

// repeatEnd returns the index after the closing brace, or a problem.
func repeatEnd(chars []rune, start int) (int, string) {
	end := -1
	for j := start; j < len(chars); j++ {
		if chars[j] == '}' {
			end = j
			break
		}
	}
	if end < 0 {
		return 0, "{ must be escaped"
	}
	m := repeatPattern.FindStringSubmatch(string(chars[start+1 : end]))
	if m == nil {
		return 0, "a repeat must be {n}, {n,} or {n,m}"
	}
	lo, _ := strconv.Atoi(m[1])
	hi := lo
	if m[3] != "" {
		hi, _ = strconv.Atoi(m[3])
	}
	if lo > maxRepeat || hi > maxRepeat {
		return 0, fmt.Sprintf("a repeat may be at most %d", maxRepeat)
	}
	if hi < lo {
		return 0, "repeat is out of order"
	}
	return end + 1, ""
}
