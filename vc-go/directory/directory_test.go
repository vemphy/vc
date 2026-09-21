package directory

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/vemphy/vc/vc-go/did"
	"github.com/vemphy/vc/vc-go/multibase"
	"github.com/vemphy/vc/vc-go/proof"
)

// inlineContext is the term vocabulary the reference directory carries in its
// own @context, so nothing has to be fetched to canonicalise it. Every field
// an entry has, and the two types, are declared here: that is what puts them
// under the signature.
var inlineContext = map[string]any{
	"did":                             "vemphy:did",
	"slug":                            "vemphy:slug",
	"status":                          "vemphy:status",
	"vemphy":                          "https://vemphy.com/ns/directory#",
	"issuers":                         map[string]any{"@id": "vemphy:issuers", "@container": "@set"},
	"legalName":                       "vemphy:legalName",
	"@protected":                      true,
	"VemphyIssuerDirectory":           "vemphy:VemphyIssuerDirectory",
	"VemphyIssuerDirectoryCredential": "vemphy:VemphyIssuerDirectoryCredential",
}

func newSigner(t *testing.T, seedByte byte, vm string) (*proof.MemorySigner, string) {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = seedByte
	}
	signer, err := proof.NewMemorySigner(seed, vm)
	if err != nil {
		t.Fatal(err)
	}
	pk, err := multibase.EncodeMultikey(signer.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	return signer, pk
}

type apexKey struct {
	id      string
	pk      string
	revoked string
	expires string
}

func apexDocument(keys ...apexKey) []byte {
	var methods, assertion []string
	for _, k := range keys {
		m := `{"id":"` + k.id + `","type":"Multikey","controller":"` + did.Apex + `","publicKeyMultibase":"` + k.pk + `"`
		if k.revoked != "" {
			m += `,"revoked":"` + k.revoked + `"`
		}
		if k.expires != "" {
			m += `,"expires":"` + k.expires + `"`
		}
		m += "}"
		methods = append(methods, m)
		assertion = append(assertion, `"`+k.id+`"`)
	}
	return []byte(`{"id":"` + did.Apex + `","verificationMethod":[` + strings.Join(methods, ",") + `],"assertionMethod":[` + strings.Join(assertion, ",") + `]}`)
}

func unsignedDirectory(issuer, validUntil string, entries []map[string]any) map[string]any {
	return map[string]any{
		"id":         "https://vemphy.com/.well-known/vemphy-issuers.json",
		"type":       []any{"VerifiableCredential", "VemphyIssuerDirectoryCredential"},
		"issuer":     issuer,
		"@context":   []any{"https://www.w3.org/ns/credentials/v2", inlineContext},
		"validFrom":  "2026-09-21T10:00:00Z",
		"validUntil": validUntil,
		"credentialSubject": map[string]any{
			"id":      "https://vemphy.com/.well-known/vemphy-issuers.json#issuers",
			"type":    "VemphyIssuerDirectory",
			"issuers": entries,
		},
	}
}

// sign builds the document exactly as it would arrive over JSON before
// signing it: a JSON-LD processor expects encoding/json's generic types
// ([]interface{}, map[string]interface{}, ...), and a map built by hand in Go
// can hold a more specific type that it does not know how to walk.
func sign(t *testing.T, unsigned map[string]any, signer proof.Signer, created time.Time) []byte {
	t.Helper()
	roundTripped, err := json.Marshal(unsigned)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(roundTripped, &document); err != nil {
		t.Fatal(err)
	}
	signed, err := proof.Create(context.Background(), document, signer, created, nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

var entries = []map[string]any{
	{"slug": "gcb", "legalName": "Green Coast Bank", "did": "did:web:vemphy.com:i:gcb", "status": "active"},
}

// A valid directory, signed by Vemphy's apex key, verifies and reports its entries.
func TestVerifyAccepts(t *testing.T) {
	signer, pk := newSigner(t, 1, did.Apex+"#key-1")
	apex := apexDocument(apexKey{id: did.Apex + "#key-1", pk: pk})
	created := time.Date(2026, 9, 21, 10, 0, 0, 0, time.UTC)
	raw := sign(t, unsignedDirectory(did.Apex, "2026-09-21T11:00:00Z", entries), signer, created)

	got, err := Verify(context.Background(), raw, Deps{
		Now:         created.Add(30 * time.Minute),
		ResolveApex: func(context.Context) ([]byte, error) { return apex, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Entries) != 1 || got.Entries[0].DID != "did:web:vemphy.com:i:gcb" {
		t.Errorf("entries: %+v", got.Entries)
	}
	want := time.Date(2026, 9, 21, 11, 0, 0, 0, time.UTC)
	if !got.ValidUntil.Equal(want) {
		t.Errorf("ValidUntil = %v", got.ValidUntil)
	}

	if e, ok := got.Issuer("GCB"); !ok || e.LegalName != "Green Coast Bank" {
		t.Errorf("Issuer(GCB) = %+v, %v", e, ok)
	}
	if _, ok := got.Issuer("ug"); ok {
		t.Error("Issuer found a slug that is not in the directory")
	}
}

// An issuer's own DID, however genuine, must never be read as Vemphy's
// directory: only did.Apex may be. Otherwise any one issuer could publish a
// document a receiver would mistake for the list of every issuer.
func TestVerifyRefusesAnIssuerAsPublisher(t *testing.T) {
	issuer := "did:web:vemphy.com:i:gcb"
	signer, _ := newSigner(t, 2, issuer+"#key-1")
	created := time.Date(2026, 9, 21, 10, 0, 0, 0, time.UTC)
	raw := sign(t, unsignedDirectory(issuer, "2026-09-21T11:00:00Z", entries), signer, created)

	_, err := Verify(context.Background(), raw, Deps{
		Now: created.Add(time.Minute),
		ResolveApex: func(context.Context) ([]byte, error) {
			t.Fatal("Verify resolved the apex document for a directory that does not claim to be Vemphy's")
			return nil, nil
		},
	})
	if err == nil {
		t.Error("accepted a directory issued by an ordinary issuer DID")
	}
}

func TestVerifyRefusesWrongType(t *testing.T) {
	signer, pk := newSigner(t, 1, did.Apex+"#key-1")
	apex := apexDocument(apexKey{id: did.Apex + "#key-1", pk: pk})
	created := time.Date(2026, 9, 21, 10, 0, 0, 0, time.UTC)
	unsigned := unsignedDirectory(did.Apex, "2026-09-21T11:00:00Z", entries)
	unsigned["type"] = []any{"VerifiableCredential"}
	raw := sign(t, unsigned, signer, created)

	_, err := Verify(context.Background(), raw, Deps{
		Now:         created.Add(time.Minute),
		ResolveApex: func(context.Context) ([]byte, error) { return apex, nil },
	})
	if err == nil {
		t.Error("accepted a document that does not carry the directory type")
	}
}

func TestVerifyRefusesUnknownKey(t *testing.T) {
	signer, pk := newSigner(t, 1, did.Apex+"#key-9")
	apex := apexDocument(apexKey{id: did.Apex + "#key-1", pk: pk})
	created := time.Date(2026, 9, 21, 10, 0, 0, 0, time.UTC)
	raw := sign(t, unsignedDirectory(did.Apex, "2026-09-21T11:00:00Z", entries), signer, created)

	_, err := Verify(context.Background(), raw, Deps{
		Now:         created.Add(time.Minute),
		ResolveApex: func(context.Context) ([]byte, error) { return apex, nil },
	})
	if err == nil {
		t.Error("accepted a proof made with a key not in the apex document")
	}
}

// A key that was already revoked when the proof was made must not vouch for
// it, the same rule verify.Credential applies to an issuer's key.
func TestVerifyRefusesKeyWindow(t *testing.T) {
	signer, pk := newSigner(t, 1, did.Apex+"#key-1")
	apex := apexDocument(apexKey{id: did.Apex + "#key-1", pk: pk, revoked: "2026-09-21T09:00:00Z"})
	created := time.Date(2026, 9, 21, 10, 0, 0, 0, time.UTC) // after the key was revoked
	raw := sign(t, unsignedDirectory(did.Apex, "2026-09-21T11:00:00Z", entries), signer, created)

	_, err := Verify(context.Background(), raw, Deps{
		Now:         created.Add(time.Minute),
		ResolveApex: func(context.Context) ([]byte, error) { return apex, nil },
	})
	if err == nil {
		t.Error("accepted a proof made after its key was revoked")
	}
}

// The inline vocabulary is what puts every field of an entry under the
// signature. Changing status or legalName after signing must be caught,
// which is only true if the context actually declares those terms.
func TestVerifyRefusesAlteredStatus(t *testing.T) {
	raw := validSignedDirectory(t)
	altered := strings.Replace(string(raw), `"status":"active"`, `"status":"suspended"`, 1)
	if altered == string(raw) {
		t.Fatal("test fixture does not contain the expected status field")
	}
	assertSignatureRefused(t, []byte(altered))
}

func TestVerifyRefusesAlteredLegalName(t *testing.T) {
	raw := validSignedDirectory(t)
	altered := strings.Replace(string(raw), `"Green Coast Bank"`, `"Not Green Coast Bank"`, 1)
	if altered == string(raw) {
		t.Fatal("test fixture does not contain the expected legalName field")
	}
	assertSignatureRefused(t, []byte(altered))
}

func validSignedDirectory(t *testing.T) []byte {
	t.Helper()
	signer, _ := newSigner(t, 1, did.Apex+"#key-1")
	created := time.Date(2026, 9, 21, 10, 0, 0, 0, time.UTC)
	return sign(t, unsignedDirectory(did.Apex, "2026-09-21T11:00:00Z", entries), signer, created)
}

func assertSignatureRefused(t *testing.T, raw []byte) {
	t.Helper()
	_, pk := newSigner(t, 1, did.Apex+"#key-1")
	apex := apexDocument(apexKey{id: did.Apex + "#key-1", pk: pk})
	created := time.Date(2026, 9, 21, 10, 0, 0, 0, time.UTC)
	_, err := Verify(context.Background(), raw, Deps{
		Now:         created.Add(time.Minute),
		ResolveApex: func(context.Context) ([]byte, error) { return apex, nil },
	})
	if err == nil {
		t.Error("accepted a directory altered after signing")
	}
	if errors.Is(err, ErrStale) {
		t.Error("an altered document was reported stale rather than not trustworthy")
	}
}

// A directory that is merely old, not altered, gets a distinguishable error:
// this is the failure a receiver meets in the ordinary course of things, and
// they need to be able to tell it apart from every other refusal.
func TestVerifyRefusesStale(t *testing.T) {
	signer, pk := newSigner(t, 1, did.Apex+"#key-1")
	apex := apexDocument(apexKey{id: did.Apex + "#key-1", pk: pk})
	created := time.Date(2026, 9, 21, 10, 0, 0, 0, time.UTC)
	raw := sign(t, unsignedDirectory(did.Apex, "2026-09-21T11:00:00Z", entries), signer, created)

	_, err := Verify(context.Background(), raw, Deps{
		Now:         time.Date(2026, 9, 21, 11, 0, 0, 0, time.UTC), // at validUntil, not after
		ResolveApex: func(context.Context) ([]byte, error) { return apex, nil },
	})
	if !errors.Is(err, ErrStale) {
		t.Errorf("got %v, want ErrStale", err)
	}
}
