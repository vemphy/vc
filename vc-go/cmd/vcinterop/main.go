// Command vcinterop signs, verifies and canonicalizes documents from the
// command line. The interop workflow uses it to check this module against the
// TypeScript package with keys neither side has seen before.
//
//	vcinterop canon                                   < doc.json    > doc.nq
//	vcinterop sign --seed <hex> --vm <id> --created <iso> < unsigned.json > signed.json
//	vcinterop verify --key <publicKeyMultibase>       < signed.json   (exit 0 or 1)
package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/vemphy/vc/vc-go/canon"
	"github.com/vemphy/vc/vc-go/multibase"
	"github.com/vemphy/vc/vc-go/proof"
)

func main() {
	if len(os.Args) < 2 {
		fail(2, "usage: vcinterop canon|sign|verify [flags] < document.json")
	}
	flags := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	seed := flags.String("seed", "", "Ed25519 seed, 64 hex characters (sign)")
	vm := flags.String("vm", "", "verification method id (sign)")
	created := flags.String("created", "", "proof date, RFC 3339 (sign)")
	key := flags.String("key", "", "publicKeyMultibase (verify)")
	flags.Parse(os.Args[2:])

	raw, err := io.ReadAll(os.Stdin)
	if err != nil {
		fail(2, err.Error())
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		fail(2, "stdin is not a JSON object: "+err.Error())
	}

	switch os.Args[1] {
	case "canon":
		nquads, err := canon.Canonicalize(doc, nil)
		if err != nil {
			fail(1, err.Error())
		}
		fmt.Print(nquads)

	case "sign":
		seedBytes, err := hex.DecodeString(*seed)
		if err != nil {
			fail(2, "--seed: "+err.Error())
		}
		at, err := time.Parse(time.RFC3339, *created)
		if err != nil {
			fail(2, "--created: "+err.Error())
		}
		signer, err := proof.NewMemorySigner(seedBytes, *vm)
		if err != nil {
			fail(2, err.Error())
		}
		signed, err := proof.Create(context.Background(), doc, signer, at, nil)
		if err != nil {
			fail(1, err.Error())
		}
		out, _ := json.MarshalIndent(signed, "", "  ")
		fmt.Println(string(out))

	case "verify":
		publicKey, err := multibase.DecodeMultikey(*key)
		if err != nil {
			fail(2, "--key: "+err.Error())
		}
		ok, err := proof.Verify(doc, publicKey, nil)
		if err != nil {
			fail(1, err.Error())
		}
		if !ok {
			fail(1, "signature does not match")
		}
		fmt.Println("ok")

	default:
		fail(2, "unknown command "+os.Args[1])
	}
}

func fail(code int, message string) {
	fmt.Fprintln(os.Stderr, message)
	os.Exit(code)
}
