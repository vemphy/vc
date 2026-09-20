package status

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/vemphy/vc/vc-go/internal/vectors"
)

func gz(t *testing.T, b []byte) string {
	t.Helper()
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	w.Write(b)
	w.Close()
	return "u" + base64.RawURLEncoding.EncodeToString(buf.Bytes())
}

func TestBitOrder(t *testing.T) {
	bits := make([]byte, listBytes)
	for _, i := range []int{0, 9, ListBits - 1} {
		if err := Set(bits, i); err != nil {
			t.Fatal(err)
		}
	}
	if bits[0] != 0x80 || bits[1] != 0x40 || bits[listBytes-1] != 0x01 {
		t.Errorf("bytes %x %x %x", bits[0], bits[1], bits[listBytes-1])
	}
	if on, _ := Get(bits, 1); on {
		t.Error("bit 1 should be clear")
	}
	for _, i := range []int{-1, ListBits} {
		if _, err := Get(bits, i); err == nil {
			t.Errorf("Get(%d) succeeded", i)
		}
		if err := Set(bits, i); err == nil {
			t.Errorf("Set(%d) succeeded", i)
		}
	}
}

func TestRoundTrip(t *testing.T) {
	bits := make([]byte, listBytes)
	Set(bits, 94_567)
	a, err := Encode(bits)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := Encode(bits)
	if a != b {
		t.Error("encoding is not deterministic")
	}
	back, err := Decode(a)
	if err != nil || !bytes.Equal(back, bits) {
		t.Errorf("round trip failed: %v", err)
	}
}

func TestDecodesTypeScriptEncoding(t *testing.T) {
	var fixture struct {
		Set         []int  `json:"set"`
		EncodedList string `json:"encodedList"`
	}
	vectors.Load(t, "status/encoding.json", &fixture)
	bits, err := Decode(fixture.EncodedList)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < ListBits; i++ {
		on, _ := Get(bits, i)
		if on != slices.Contains(fixture.Set, i) {
			t.Fatalf("bit %d = %v", i, on)
		}
	}
}

func TestDecodeRefuses(t *testing.T) {
	cases := map[string]string{
		"short list":        gz(t, make([]byte, 100)),
		"oversized list":    gz(t, make([]byte, 10*1024*1024)),
		"another multibase": "zabc",
		"not gzip":          "u" + base64.RawURLEncoding.EncodeToString(make([]byte, 64)),
		"not base64url":     "u!!!",
		"empty":             "",
	}
	for name, in := range cases {
		if _, err := Decode(in); err == nil {
			t.Errorf("%s: Decode succeeded", name)
		}
	}
	if _, err := Encode(make([]byte, 100)); err == nil {
		t.Error("Encode accepted a short list")
	}
}

// vectors/status/encoding-go.json is a list encoded by this package, which the
// TypeScript tests decode. Run with UPDATE_VECTORS=1 to rewrite it.
//
// The compressed bytes are not compared: compress/flate is free to produce
// different output from one Go release to the next, and it has. What has to
// hold is that the committed text and a fresh encoding both decode to the
// same bits.
func TestGoEncodingFixture(t *testing.T) {
	set := []int{0, 9, 94_567, ListBits - 1}
	bits := make([]byte, listBytes)
	for _, i := range set {
		Set(bits, i)
	}
	encoded, err := Encode(bits)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(vectors.Dir(t), "status", "encoding-go.json")
	if os.Getenv("UPDATE_VECTORS") == "1" {
		out, _ := json.MarshalIndent(map[string]any{"set": set, "encodedList": encoded}, "", "  ")
		if err := os.WriteFile(path, append(out, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	var fixture struct {
		EncodedList string `json:"encodedList"`
	}
	vectors.Load(t, "status/encoding-go.json", &fixture)
	for name, text := range map[string]string{"committed": fixture.EncodedList, "fresh": encoded} {
		got, err := Decode(text)
		if err != nil || !bytes.Equal(got, bits) {
			t.Errorf("%s encoding does not decode to the expected bits: %v", name, err)
		}
	}
}
