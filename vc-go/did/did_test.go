package did

import (
	"testing"
	"time"
)

const (
	gcb = "did:web:vemphy.com:i:gcb"
	key = "z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2"
)

const document = `{
  "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1"],
  "id": "` + gcb + `",
  "verificationMethod": [
    {"id": "` + gcb + `#key-1", "type": "Multikey", "controller": "` + gcb + `", "publicKeyMultibase": "` + key + `", "revoked": "2026-03-01T00:00:00Z"},
    {"id": "` + gcb + `#key-2", "type": "Multikey", "controller": "` + gcb + `", "publicKeyMultibase": "` + key + `"},
    {"id": "` + gcb + `#key-3", "type": "Multikey", "controller": "did:web:vemphy.com:i:ug", "publicKeyMultibase": "` + key + `"}
  ],
  "assertionMethod": ["` + gcb + `#key-2"]
}`

func TestURL(t *testing.T) {
	got, err := URL(gcb)
	if err != nil || got != "https://vemphy.com/i/gcb/did.json" {
		t.Errorf("URL = %q, %v", got, err)
	}
	for _, bad := range []string{
		"did:web:example.com:i:gcb",
		"did:web:vemphy.com",
		"did:web:vemphy.com:i:GCB",
		"did:web:vemphy.com:i:gcb:extra",
		"did:web:vemphy.com%3A8443:i:gcb",
		"did:web:vemphy.com:i:g%63b",
		"did:key:" + key,
	} {
		if _, err := URL(bad); err == nil {
			t.Errorf("URL(%q) succeeded", bad)
		}
	}
}

func TestParseRefuses(t *testing.T) {
	if _, err := Parse([]byte(document), "did:web:vemphy.com:i:ug"); err == nil {
		t.Error("accepted a document for another DID")
	}
	if _, err := Parse([]byte(`{"id":"`+gcb+`"}`), gcb); err == nil {
		t.Error("accepted a document with no keys")
	}
	if _, err := Parse([]byte(`not json`), gcb); err == nil {
		t.Error("accepted invalid JSON")
	}
}

func TestFindKey(t *testing.T) {
	doc, err := Parse([]byte(document), gcb)
	if err != nil {
		t.Fatal(err)
	}

	active, err := FindKey(doc, gcb+"#key-2")
	if err != nil || active == nil {
		t.Fatalf("key-2: %v, %v", active, err)
	}
	if len(active.PublicKey) != 32 || !active.InAssertionMethod || active.Revoked != nil {
		t.Errorf("key-2: %+v", active)
	}

	revoked, _ := FindKey(doc, gcb+"#key-1")
	want := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	if revoked == nil || revoked.Revoked == nil || !revoked.Revoked.Equal(want) || revoked.InAssertionMethod {
		t.Errorf("key-1: %+v", revoked)
	}

	for _, vm := range []string{gcb + "#key-3", gcb + "#key-9", "did:web:vemphy.com:i:ug#key-1"} {
		if k, err := FindKey(doc, vm); k != nil || err != nil {
			t.Errorf("FindKey(%s) = %v, %v; want nil, nil", vm, k, err)
		}
	}
}
