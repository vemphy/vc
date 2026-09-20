package schema

import (
	"regexp"
	"strconv"
	"strings"
)

// JSON Schema leaves "format" loosely defined, and validator libraries differ.
// Vemphy defines its four formats here. packages/vc/src/schema/formats.ts is
// the same code in TypeScript, and vectors/schemas/subjects holds the cases
// both must agree on.

var (
	datePattern     = regexp.MustCompile(`^(\d{4})-(\d{2})-(\d{2})$`)
	dateTimePattern = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2})T(\d{2}):(\d{2}):(\d{2})(\.\d{1,9})?(Z|[+-](\d{2}):(\d{2}))$`)
	emailLocal      = regexp.MustCompile(`^[A-Za-z0-9._%+-]{1,64}$`)
	emailLabel      = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)
	uriPattern      = regexp.MustCompile(`^https?://[!-~]+$`)
)

var daysIn = [...]int{31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31}

func atoi(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}

// IsDate reports whether s is YYYY-MM-DD, a real calendar date, year 0001-9999.
func IsDate(s string) bool {
	m := datePattern.FindStringSubmatch(s)
	if m == nil {
		return false
	}
	year, month, day := atoi(m[1]), atoi(m[2]), atoi(m[3])
	if year < 1 || month < 1 || month > 12 || day < 1 {
		return false
	}
	limit := daysIn[month-1]
	if month == 2 && year%4 == 0 && (year%100 != 0 || year%400 == 0) {
		limit = 29
	}
	return day <= limit
}

// IsDateTime reports whether s is YYYY-MM-DDThh:mm:ss, an optional fraction of
// 1-9 digits, then Z or ±hh:mm. No leap seconds.
func IsDateTime(s string) bool {
	m := dateTimePattern.FindStringSubmatch(s)
	if m == nil || !IsDate(m[1]) {
		return false
	}
	if atoi(m[2]) > 23 || atoi(m[3]) > 59 || atoi(m[4]) > 59 {
		return false
	}
	return m[6] == "Z" || (atoi(m[7]) <= 23 && atoi(m[8]) <= 59)
}

// IsEmail accepts a conservative ASCII address: local@domain, at most 254
// characters, a domain of two or more labels.
func IsEmail(s string) bool {
	if len(s) > 254 {
		return false
	}
	at := strings.LastIndexByte(s, '@')
	if at < 1 {
		return false
	}
	local := s[:at]
	if !emailLocal.MatchString(local) || strings.HasPrefix(local, ".") || strings.HasSuffix(local, ".") || strings.Contains(local, "..") {
		return false
	}
	labels := strings.Split(s[at+1:], ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if !emailLabel.MatchString(label) {
			return false
		}
	}
	return true
}

// IsURI accepts an http or https link in printable ASCII, at most 2000 characters.
func IsURI(s string) bool {
	return len(s) <= 2000 && uriPattern.MatchString(s)
}
