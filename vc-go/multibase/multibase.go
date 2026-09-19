// Package multibase encodes and decodes the two multiformat values Vemphy
// uses: base58btc strings and Ed25519 Multikey public keys.
package multibase

import (
	"crypto/ed25519"
	"errors"
	"strings"

	"github.com/mr-tron/base58"
)

// Multicodec prefix for an Ed25519 public key (0xed), varint-encoded.
var ed25519Pub = []byte{0xed, 0x01}

var (
	ErrNotBase58btc = errors.New("not multibase base58btc")
	ErrNotEd25519   = errors.New("not an Ed25519 Multikey")
	ErrKeyLength    = errors.New("an Ed25519 public key is 32 bytes")
)

// EncodeBase58btc returns the letter z followed by the base58 text.
func EncodeBase58btc(b []byte) string {
	return "z" + base58.Encode(b)
}

func DecodeBase58btc(s string) ([]byte, error) {
	rest, ok := strings.CutPrefix(s, "z")
	if !ok {
		return nil, ErrNotBase58btc
	}
	b, err := base58.Decode(rest)
	if err != nil {
		return nil, ErrNotBase58btc
	}
	return b, nil
}

// EncodeMultikey returns a public key as a publicKeyMultibase value (z6Mk...).
func EncodeMultikey(key ed25519.PublicKey) (string, error) {
	if len(key) != ed25519.PublicKeySize {
		return "", ErrKeyLength
	}
	return EncodeBase58btc(append(append([]byte{}, ed25519Pub...), key...)), nil
}

func DecodeMultikey(s string) (ed25519.PublicKey, error) {
	b, err := DecodeBase58btc(s)
	if err != nil {
		return nil, err
	}
	if len(b) < 2 || b[0] != ed25519Pub[0] || b[1] != ed25519Pub[1] {
		return nil, ErrNotEd25519
	}
	if len(b) != len(ed25519Pub)+ed25519.PublicKeySize {
		return nil, ErrKeyLength
	}
	return ed25519.PublicKey(b[2:]), nil
}
