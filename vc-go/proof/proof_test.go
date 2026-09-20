package proof

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/piprate/json-gold/ld"

	"github.com/vemphy/vc/vc-go/canon"
	"github.com/vemphy/vc/vc-go/internal/vectors"
	"github.com/vemphy/vc/vc-go/multibase"
	"github.com/vemphy/vc/vc-go/vcctx"
)

// The test vector published in the W3C Data Integrity EdDSA Cryptosuites specification.
type w3cVector struct {
	PublicKeyMultibase    string         `json:"publicKeyMultibase"`
	SecretKeyMultibase    string         `json:"secretKeyMultibase"`
	Unsigned              map[string]any `json:"unsigned"`
	CanonicalDocument     string         `json:"canonicalDocument"`
	ProofOptions          map[string]any `json:"proofOptions"`
	CanonicalProofOptions string         `json:"canonicalProofOptions"`
	CombinedHashHex       string         `json:"combinedHashHex"`
	Signed                map[string]any `json:"signed"`
}

func load(t *testing.T) (w3cVector, ld.DocumentLoader) {
	t.Helper()
	var v w3cVector
	vectors.Load(t, "w3c/eddsa-rdfc-2022.json", &v)
	examples, err := os.ReadFile(filepath.Join(vectors.Dir(t), "w3c", "examples-v2.json"))
	if err != nil {
		t.Fatal(err)
	}
	return v, vcctx.Loader(map[string][]byte{"https://www.w3.org/ns/credentials/examples/v2": examples})
}

func signer(t *testing.T, v w3cVector) *MemorySigner {
	t.Helper()
	// secretKeyMultibase is a two-byte multicodec prefix followed by the 32-byte seed.
	secret, err := multibase.DecodeBase58btc(v.SecretKeyMultibase)
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewMemorySigner(secret[2:], v.ProofOptions["verificationMethod"].(string))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestW3CCanonicalForms(t *testing.T) {
	v, loader := load(t)
	if got, err := canon.Canonicalize(v.Unsigned, loader); err != nil || got != v.CanonicalDocument {
		t.Errorf("document: %v\n%s", err, got)
	}
	if got, err := canon.Canonicalize(v.ProofOptions, loader); err != nil || got != v.CanonicalProofOptions {
		t.Errorf("proof options: %v\n%s", err, got)
	}
}

func TestW3CHash(t *testing.T) {
	v, loader := load(t)
	options := map[string]any{}
	for k, val := range v.ProofOptions {
		if k != "@context" {
			options[k] = val
		}
	}
	hash, err := Hash(v.Unsigned, options, loader)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(hash); got != v.CombinedHashHex {
		t.Errorf("hash %s, want %s", got, v.CombinedHashHex)
	}
}

func TestW3CPublicKey(t *testing.T) {
	v, _ := load(t)
	want, _ := multibase.DecodeMultikey(v.PublicKeyMultibase)
	if got := signer(t, v).PublicKey(); !got.Equal(want) {
		t.Errorf("public key %x, want %x", got, want)
	}
}

func TestW3CProofValue(t *testing.T) {
	v, loader := load(t)
	created, _ := time.Parse(time.RFC3339, v.ProofOptions["created"].(string))
	signed, err := Create(context.Background(), v.Unsigned, signer(t, v), created, loader)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(signed, v.Signed) {
		got, _ := json.MarshalIndent(signed["proof"], "", "  ")
		t.Errorf("signed credential differs from the published one; proof:\n%s", got)
	}
}

func TestW3CVerify(t *testing.T) {
	v, loader := load(t)
	key, _ := multibase.DecodeMultikey(v.PublicKeyMultibase)
	if ok, err := Verify(v.Signed, key, loader); err != nil || !ok {
		t.Errorf("Verify = %v, %v", ok, err)
	}
}

func clone(t *testing.T, doc map[string]any) map[string]any {
	t.Helper()
	raw, _ := json.Marshal(doc)
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestVerifyIsFalseAfterAnyChange(t *testing.T) {
	v, loader := load(t)
	key, _ := multibase.DecodeMultikey(v.PublicKeyMultibase)
	proofOf := func(c map[string]any) map[string]any { return c["proof"].(map[string]any) }

	cases := map[string]func(c map[string]any){
		"changed subject value": func(c map[string]any) {
			c["credentialSubject"].(map[string]any)["alumniOf"] = "The School of Exampless"
		},
		"changed issuer":              func(c map[string]any) { c["issuer"] = "https://vc.example/issuers/5679" },
		"changed proof date":          func(c map[string]any) { proofOf(c)["created"] = "2023-02-24T23:36:39Z" },
		"changed verification method": func(c map[string]any) { proofOf(c)["verificationMethod"] = "did:example:other#key-1" },
		"removed member":              func(c map[string]any) { delete(c, "description") },
		"no proof":                    func(c map[string]any) { delete(c, "proof") },
		"list of proofs":              func(c map[string]any) { c["proof"] = []any{c["proof"]} },
		"proofValue in another base":  func(c map[string]any) { proofOf(c)["proofValue"] = "u" + proofOf(c)["proofValue"].(string)[1:] },
		"truncated proofValue":        func(c map[string]any) { proofOf(c)["proofValue"] = proofOf(c)["proofValue"].(string)[:40] },
		"proofValue that is not text": func(c map[string]any) { proofOf(c)["proofValue"] = 42 },
	}
	for name, mutate := range cases {
		c := clone(t, v.Signed)
		mutate(c)
		if ok, err := Verify(c, key, loader); ok || err != nil {
			t.Errorf("%s: Verify = %v, %v; want false, nil", name, ok, err)
		}
	}

	other, _ := NewMemorySigner(make([]byte, 32), "did:example:other#key-1")
	if ok, _ := Verify(v.Signed, other.PublicKey(), loader); ok {
		t.Error("verified under another key")
	}
}

func TestCreateRefusesSignedDocument(t *testing.T) {
	v, loader := load(t)
	if _, err := Create(context.Background(), v.Signed, signer(t, v), time.Now(), loader); err == nil {
		t.Error("signed a document that already has a proof")
	}
}
