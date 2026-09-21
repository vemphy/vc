package verify

import (
	"context"
	"testing"
	"time"

	"github.com/vemphy/vc/vc-go/did"
)

// A credential naming Vemphy's own apex DID as its issuer must never verify
// as an ordinary claim. Vemphy is not an issuer: its apex key signs the
// published issuer directory (package directory) and nothing else. This is
// deliberate defence in depth. The envelope schema's issuer pattern already
// refuses did:web:vemphy.com, since it requires the :i:<slug> issuer form, so
// this document is rejected at the shape check before anything is resolved.
// Independently, did.Parse itself refuses to resolve Apex as an issuer DID
// (see did.TestParseRejectsApex): were the envelope pattern ever loosened,
// Credential would still stop at the "did" check rather than verify the
// claim.
func TestCredentialRefusesApexAsIssuer(t *testing.T) {
	claim := `{
  "@context": ["https://www.w3.org/ns/credentials/v2", "https://vemphy.com/ns/claims/v1"],
  "id": "urn:vemphy:claim:VMPY-0001-0010",
  "type": ["VerifiableCredential", "EmploymentLetter"],
  "issuer": "` + did.Apex + `",
  "validFrom": "2026-01-01T00:00:00Z",
  "credentialSubject": {},
  "credentialStatus": {
    "id": "https://vemphy.com/i/vmpy/status/1#0",
    "type": "BitstringStatusListEntry",
    "statusPurpose": "revocation",
    "statusListIndex": "0",
    "statusListCredential": "https://vemphy.com/i/vmpy/status/1"
  },
  "proof": {
    "type": "DataIntegrityProof",
    "cryptosuite": "eddsa-rdfc-2022",
    "created": "2026-01-01T00:00:00Z",
    "verificationMethod": "` + did.Apex + `#key-1",
    "proofPurpose": "assertionMethod",
    "proofValue": "z1111111111111111111111111111111111111111111111111111111111111111111111111111111111"
  }
}`

	got := Credential(context.Background(), []byte(claim), Deps{
		Now: time.Now(),
		ResolveDID: func(context.Context, string) ([]byte, error) {
			t.Fatal("Credential resolved a DID for a claim naming Apex as issuer; the shape check should have stopped it first")
			return nil, nil
		},
	})
	if got.Result != Unknown || got.Reason != Malformed {
		t.Errorf("got %s %q, want unknown malformed", got.Result, got.Reason)
	}
}
