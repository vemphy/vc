package schema

import "strings"

// Pick chooses the language to show. wanted is a list of language tags, most
// preferred first (the order of an Accept-Language header). An exact match
// wins, then a match on the primary language (fr-CA → fr), then en.
func (l Labels) Pick(wanted ...string) string {
	for _, tag := range wanted {
		lower := strings.ToLower(tag)
		for key, text := range l {
			if strings.ToLower(key) == lower {
				return text
			}
		}
		primary, _, _ := strings.Cut(lower, "-")
		for key, text := range l {
			if strings.ToLower(key) == primary {
				return text
			}
		}
	}
	return l["en"]
}

// Label is the label of a field, and whether the schema has such a field.
func (s *Schema) Label(key string, wanted ...string) (string, bool) {
	f, ok := s.Field(key)
	if !ok {
		return "", false
	}
	return f.Label.Pick(wanted...), true
}

// ValueLabel is the label of an enum value, falling back to the value itself.
func (f Field) ValueLabel(value string, wanted ...string) string {
	if labels, ok := f.EnumLabels[value]; ok {
		return labels.Pick(wanted...)
	}
	return value
}
