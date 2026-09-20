package schema

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// CoreType is one version of a type curated by Vemphy and open to every issuer.
type CoreType struct {
	Ref    Ref
	Schema *Schema
}

// Core returns every version of every core type this release knows, by name
// and then version. The schemas are embedded copies of
// packages/vc/schemas/core; CI fails if they differ.
var Core = sync.OnceValue(func() []CoreType {
	entries, err := files.ReadDir("core")
	if err != nil {
		panic(err)
	}
	var types []CoreType
	for _, entry := range entries {
		// BankReferenceLetter.v1.json
		name, rest, _ := strings.Cut(entry.Name(), ".v")
		version, err := strconv.Atoi(strings.TrimSuffix(rest, ".json"))
		if err != nil {
			panic(fmt.Sprintf("core schema %s is not named <Type>.v<n>.json", entry.Name()))
		}
		raw, err := files.ReadFile("core/" + entry.Name())
		if err != nil {
			panic(err)
		}
		s, err := Parse(raw)
		if err != nil {
			panic(fmt.Sprintf("core schema %s: %v", entry.Name(), err))
		}
		if s.Name != name {
			panic(fmt.Sprintf("core schema %s names itself %s", entry.Name(), s.Name))
		}
		types = append(types, CoreType{Ref: Ref{Name: name, Version: version}, Schema: s})
	}
	sort.Slice(types, func(i, j int) bool {
		if types[i].Ref.Name != types[j].Ref.Name {
			return types[i].Ref.Name < types[j].Ref.Name
		}
		return types[i].Ref.Version < types[j].Ref.Version
	})
	return types
})

// CoreSchema returns one version of a core type.
func CoreSchema(name string, version int) (*Schema, bool) {
	for _, t := range Core() {
		if t.Ref.Name == name && t.Ref.Version == version {
			return t.Schema, true
		}
	}
	return nil, false
}
