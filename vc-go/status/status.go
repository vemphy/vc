// Package status decodes and encodes Bitstring Status List 1.0 lists.
package status

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
)

const (
	// ListBits is the number of bits in a Vemphy status list.
	ListBits  = 131_072
	listBytes = ListBits / 8
)

var (
	ErrEncoding   = errors.New("status list is not multibase base64url around gzip")
	ErrSize       = fmt.Errorf("status list must be %d bytes", listBytes)
	ErrOutOfRange = errors.New("status index is outside the list")
)

// Decode reads an encodedList: multibase base64url (the letter u) around
// gzip. Decompression stops as soon as the output passes the expected size,
// so a small input cannot be used to exhaust memory.
func Decode(encodedList string) ([]byte, error) {
	rest, ok := strings.CutPrefix(encodedList, "u")
	if !ok {
		return nil, ErrEncoding
	}
	compressed, err := base64.RawURLEncoding.DecodeString(rest)
	if err != nil {
		return nil, ErrEncoding
	}
	reader, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, ErrEncoding
	}
	bits, err := io.ReadAll(io.LimitReader(reader, listBytes+1))
	if err != nil {
		return nil, ErrEncoding
	}
	if len(bits) != listBytes {
		return nil, ErrSize
	}
	return bits, nil
}

// Encode is deterministic: the gzip header carries no timestamp or file name.
func Encode(bits []byte) (string, error) {
	if len(bits) != listBytes {
		return "", ErrSize
	}
	var buf bytes.Buffer
	w, _ := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if _, err := w.Write(bits); err != nil {
		return "", err
	}
	if err := w.Close(); err != nil {
		return "", err
	}
	return "u" + base64.RawURLEncoding.EncodeToString(buf.Bytes()), nil
}

// Get reports whether a bit is set. Bit 0 is the most significant bit of the first byte.
func Get(bits []byte, index int) (bool, error) {
	if index < 0 || index >= len(bits)*8 {
		return false, ErrOutOfRange
	}
	return bits[index>>3]&(0x80>>(index&7)) != 0, nil
}

func Set(bits []byte, index int) error {
	if index < 0 || index >= len(bits)*8 {
		return ErrOutOfRange
	}
	bits[index>>3] |= 0x80 >> (index & 7)
	return nil
}
