package schema

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/big"
	"sort"
	"unicode/utf16"
)

// CanonicalJSON writes a decoded JSON value with object keys sorted and no
// whitespace, exactly as canonicalJson does in the TypeScript package, so the
// two can be compared byte for byte. Numbers must be json.Number or Go
// integers, and must be whole.
func CanonicalJSON(value any) ([]byte, error) {
	var b bytes.Buffer
	if err := writeCanonical(&b, value); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func writeCanonical(b *bytes.Buffer, value any) error {
	switch v := value.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		if v {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case string:
		writeString(b, v)
	case int:
		fmt.Fprintf(b, "%d", v)
	case int64:
		fmt.Fprintf(b, "%d", v)
	case json.Number:
		// 1e3 and 1.0 are whole numbers; JavaScript prints them as 1000 and 1.
		r, ok := new(big.Rat).SetString(v.String())
		if !ok || !r.IsInt() {
			return fmt.Errorf("%s is not a whole number", v)
		}
		b.WriteString(r.Num().String())
	case []any:
		b.WriteByte('[')
		for i, item := range v {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := writeCanonical(b, item); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case []string:
		items := make([]any, len(v))
		for i, s := range v {
			items[i] = s
		}
		return writeCanonical(b, items)
	case map[string]any:
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		// JavaScript compares strings by UTF-16 code unit, which differs from
		// byte order for characters outside the Basic Multilingual Plane.
		sort.Slice(keys, func(i, j int) bool { return lessUTF16(keys[i], keys[j]) })
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			writeString(b, k)
			b.WriteByte(':')
			if err := writeCanonical(b, v[k]); err != nil {
				return err
			}
		}
		b.WriteByte('}')
	default:
		return fmt.Errorf("cannot write %T as canonical JSON", value)
	}
	return nil
}

func lessUTF16(a, b string) bool {
	x, y := utf16.Encode([]rune(a)), utf16.Encode([]rune(b))
	for i := 0; i < len(x) && i < len(y); i++ {
		if x[i] != y[i] {
			return x[i] < y[i]
		}
	}
	return len(x) < len(y)
}

// writeString escapes as JSON.stringify does: quote, backslash and control
// characters only. encoding/json also escapes <, >, &, U+2028 and U+2029.
func writeString(b *bytes.Buffer, s string) {
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(b, `\u%04x`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
}
