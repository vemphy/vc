// Package proof creates and verifies Data Integrity proofs with the
// eddsa-rdfc-2022 cryptosuite.
package proof

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"github.com/piprate/json-gold/ld"

	"github.com/vemphy/vc/vc-go/canon"
	"github.com/vemphy/vc/vc-go/multibase"
)

// Signer signs on behalf of one verification method.
//
// It is given the 64-byte Data Integrity hash, never the document and never a
// key, so an implementation can sit in front of a KMS or an HSM.
type Signer interface {
	VerificationMethod() string
	Sign(ctx context.Context, hash []byte) ([]byte, error)
}

// MemorySigner holds an Ed25519 key in memory. It is for tests, and for
// issuers who keep their own keys.
type MemorySigner struct {
	verificationMethod string
	key                ed25519.PrivateKey
}

// NewMemorySigner builds a signer from a 32-byte Ed25519 seed.
func NewMemorySigner(seed []byte, verificationMethod string) (*MemorySigner, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, errors.New("an Ed25519 seed is 32 bytes")
	}
	return &MemorySigner{verificationMethod, ed25519.NewKeyFromSeed(seed)}, nil
}

func (s *MemorySigner) VerificationMethod() string { return s.verificationMethod }

func (s *MemorySigner) PublicKey() ed25519.PublicKey { return s.key.Public().(ed25519.PublicKey) }

func (s *MemorySigner) Sign(_ context.Context, hash []byte) ([]byte, error) {
	return ed25519.Sign(s.key, hash), nil
}

// Hash returns the bytes that are signed: SHA-256 of the canonical proof
// options followed by SHA-256 of the canonical document. The proof options
// are the proof without its value, read in the document's own context.
func Hash(unsigned, proofOptions map[string]any, loader ld.DocumentLoader) ([]byte, error) {
	options := make(map[string]any, len(proofOptions)+1)
	for k, v := range proofOptions {
		options[k] = v
	}
	options["@context"] = unsigned["@context"]

	optionsNQuads, err := canon.Canonicalize(options, loader)
	if err != nil {
		return nil, fmt.Errorf("proof options: %w", err)
	}
	documentNQuads, err := canon.Canonicalize(unsigned, loader)
	if err != nil {
		return nil, fmt.Errorf("document: %w", err)
	}
	optionsHash := sha256.Sum256([]byte(optionsNQuads))
	documentHash := sha256.Sum256([]byte(documentNQuads))
	return append(optionsHash[:], documentHash[:]...), nil
}

// Create signs a document and returns a copy with the proof attached. The
// proof date comes from the caller; this package never reads a clock.
func Create(ctx context.Context, unsigned map[string]any, s Signer, created time.Time, loader ld.DocumentLoader) (map[string]any, error) {
	if _, signed := unsigned["proof"]; signed {
		return nil, errors.New("document already has a proof")
	}
	options := map[string]any{
		"type":               "DataIntegrityProof",
		"cryptosuite":        "eddsa-rdfc-2022",
		"created":            created.UTC().Format("2006-01-02T15:04:05Z"),
		"verificationMethod": s.VerificationMethod(),
		"proofPurpose":       "assertionMethod",
	}
	hash, err := Hash(unsigned, options, loader)
	if err != nil {
		return nil, err
	}
	signature, err := s.Sign(ctx, hash)
	if err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}
	if len(signature) != ed25519.SignatureSize {
		return nil, errors.New("an Ed25519 signature is 64 bytes")
	}
	options["proofValue"] = multibase.EncodeBase58btc(signature)

	out := make(map[string]any, len(unsigned)+1)
	for k, v := range unsigned {
		out[k] = v
	}
	out["proof"] = options
	return out, nil
}

// Verify checks a document's signature against a public key. It returns false
// for a signature that does not match, and an error only when the document
// cannot be canonicalized.
func Verify(signed map[string]any, publicKey ed25519.PublicKey, loader ld.DocumentLoader) (bool, error) {
	proof, ok := signed["proof"].(map[string]any)
	if !ok {
		return false, nil
	}
	proofValue, ok := proof["proofValue"].(string)
	if !ok {
		return false, nil
	}
	signature, err := multibase.DecodeBase58btc(proofValue)
	if err != nil || len(signature) != ed25519.SignatureSize || len(publicKey) != ed25519.PublicKeySize {
		return false, nil
	}

	unsigned := make(map[string]any, len(signed))
	for k, v := range signed {
		if k != "proof" {
			unsigned[k] = v
		}
	}
	options := make(map[string]any, len(proof))
	for k, v := range proof {
		if k != "proofValue" {
			options[k] = v
		}
	}
	hash, err := Hash(unsigned, options, loader)
	if err != nil {
		return false, err
	}
	return ed25519.Verify(publicKey, hash, signature), nil
}
