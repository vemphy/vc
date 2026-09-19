package multibase

import (
	"bytes"
	"testing"
)

// The public key used by the W3C eddsa-rdfc-2022 test vectors.
const w3cKey = "z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2"

func TestMultikeyRoundTrip(t *testing.T) {
	key, err := DecodeMultikey(w3cKey)
	if err != nil {
		t.Fatal(err)
	}
	if len(key) != 32 {
		t.Fatalf("key length %d", len(key))
	}
	if got, _ := EncodeMultikey(key); got != w3cKey {
		t.Errorf("re-encoded as %s", got)
	}
}

func TestMultikeyRejects(t *testing.T) {
	secp := EncodeBase58btc(append([]byte{0xe7, 0x01}, make([]byte, 32)...))
	short := EncodeBase58btc([]byte{0xed, 0x01, 1, 2, 3})
	for _, in := range []string{secp, short, "u" + w3cKey[1:], "z0OIl", ""} {
		if _, err := DecodeMultikey(in); err == nil {
			t.Errorf("DecodeMultikey(%q) succeeded", in)
		}
	}
	if _, err := EncodeMultikey(make([]byte, 31)); err == nil {
		t.Error("EncodeMultikey accepted a 31-byte key")
	}
}

func TestBase58KeepsLeadingZeros(t *testing.T) {
	in := []byte{0, 0, 7}
	out, err := DecodeBase58btc(EncodeBase58btc(in))
	if err != nil || !bytes.Equal(in, out) {
		t.Errorf("got %v, %v", out, err)
	}
}
