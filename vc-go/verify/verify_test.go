package verify

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/vemphy/vc/vc-go/canon"
	"github.com/vemphy/vc/vc-go/did"
	"github.com/vemphy/vc/vc-go/internal/vectors"
)

type expectedFile struct {
	Now     time.Time `json:"now"`
	Vectors map[string]struct {
		Result Result `json:"result"`
		Reason Reason `json:"reason"`
	} `json:"vectors"`
}

var listURL = regexp.MustCompile(`^https://vemphy\.com/i/([a-z]+)/status/(\d+)$`)

// Resolvers backed by the vectors directory. Nothing here touches the network.
func fileDeps(t *testing.T, now time.Time) Deps {
	dir := vectors.Dir(t)
	return Deps{
		Now: now,
		ResolveDID: func(_ context.Context, id string) ([]byte, error) {
			slug, err := did.SlugOf(id)
			if err != nil {
				return nil, err
			}
			return os.ReadFile(filepath.Join(dir, "keys", slug+".did.json"))
		},
		FetchStatusList: func(_ context.Context, url string) ([]byte, error) {
			m := listURL.FindStringSubmatch(url)
			if m == nil {
				return nil, fmt.Errorf("unexpected status list URL %s", url)
			}
			return os.ReadFile(filepath.Join(dir, "status", m[1]+"-"+m[2]+".json"))
		},
	}
}

func readClaim(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(vectors.Dir(t), "claims", name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestVectors(t *testing.T) {
	var expected expectedFile
	vectors.Load(t, "expected.json", &expected)

	files, _ := filepath.Glob(filepath.Join(vectors.Dir(t), "claims", "*.json"))
	var onDisk, listed []string
	for _, f := range files {
		onDisk = append(onDisk, strings.TrimSuffix(filepath.Base(f), ".json"))
	}
	for name := range expected.Vectors {
		listed = append(listed, name)
	}
	sort.Strings(listed)
	if strings.Join(onDisk, " ") != strings.Join(listed, " ") {
		t.Fatalf("expected.json lists %v, vectors/claims has %v", listed, onDisk)
	}

	for name, want := range expected.Vectors {
		t.Run(name, func(t *testing.T) {
			got := Credential(context.Background(), readClaim(t, name), fileDeps(t, expected.Now))
			if got.Result != want.Result || got.Reason != want.Reason {
				t.Errorf("got %s %q, want %s %q (checks %v)", got.Result, got.Reason, want.Result, want.Reason, got.Checks)
			}
		})
	}
}

// Every claim must canonicalize to exactly the bytes the TypeScript side produced.
func TestCanonicalFormsMatchTypeScript(t *testing.T) {
	files, _ := filepath.Glob(filepath.Join(vectors.Dir(t), "canon", "gcb-*.nq"))
	more, _ := filepath.Glob(filepath.Join(vectors.Dir(t), "canon", "*-001.nq"))
	seen := map[string]bool{}
	for _, nq := range append(files, more...) {
		name := strings.TrimSuffix(filepath.Base(nq), ".nq")
		// gcb-002 and gcb-009 were altered after signing, so the file on disk is not what was canonicalized.
		if seen[name] || name == "gcb-002" || name == "gcb-009" {
			continue
		}
		seen[name] = true
		var doc map[string]any
		vectors.Load(t, "claims/"+name+".json", &doc)
		delete(doc, "proof")
		want, _ := os.ReadFile(nq)
		got, err := canon.Canonicalize(doc, nil)
		if err != nil || got != string(want) {
			t.Errorf("%s: canonical form differs (%v)", name, err)
		}
	}
	if len(seen) < 10 {
		t.Errorf("only %d canonical forms compared", len(seen))
	}
}

func TestChecksAreReportedInOrder(t *testing.T) {
	var expected expectedFile
	vectors.Load(t, "expected.json", &expected)

	got := Credential(context.Background(), readClaim(t, "gcb-001"), fileDeps(t, expected.Now))
	var names []string
	for _, c := range got.Checks {
		if !c.OK {
			t.Errorf("check %s did not hold", c.Name)
		}
		names = append(names, c.Name)
	}
	want := "shape did key key_window signature status_list not_revoked validity_period"
	if strings.Join(names, " ") != want {
		t.Errorf("checks %v", names)
	}

	altered := Credential(context.Background(), readClaim(t, "gcb-002"), fileDeps(t, expected.Now))
	if last := altered.Checks[len(altered.Checks)-1]; last.Name != "signature" || last.OK {
		t.Errorf("an altered claim should stop at the signature, got %v", altered.Checks)
	}
}

func TestNeverPanicsOnMalformedInput(t *testing.T) {
	for _, in := range []string{``, `null`, `42`, `"text"`, `[]`, `{}`, `{"@context":1}`, `{"proof":[]}`} {
		got := Credential(context.Background(), []byte(in), fileDeps(t, time.Now()))
		if got.Result != Unknown || got.Reason != Malformed {
			t.Errorf("%q: got %s %q", in, got.Result, got.Reason)
		}
	}
}

func TestDependencyFailures(t *testing.T) {
	var expected expectedFile
	vectors.Load(t, "expected.json", &expected)
	offline := errors.New("offline")
	claim := readClaim(t, "gcb-001")

	deps := fileDeps(t, expected.Now)
	deps.ResolveDID = func(context.Context, string) ([]byte, error) { return nil, offline }
	if got := Credential(context.Background(), claim, deps); got.Reason != DIDUnresolvable {
		t.Errorf("unresolvable DID: %s %q", got.Result, got.Reason)
	}

	deps = fileDeps(t, expected.Now)
	deps.ResolveDID = func(context.Context, string) ([]byte, error) {
		return os.ReadFile(filepath.Join(vectors.Dir(t), "keys", "ug.did.json"))
	}
	if got := Credential(context.Background(), claim, deps); got.Reason != DIDUnresolvable {
		t.Errorf("someone else's DID document: %s %q", got.Result, got.Reason)
	}

	deps = fileDeps(t, expected.Now)
	deps.FetchStatusList = func(context.Context, string) ([]byte, error) { return nil, offline }
	if got := Credential(context.Background(), claim, deps); got.Reason != StatusListUnverifiable {
		t.Errorf("unreachable status list: %s %q", got.Result, got.Reason)
	}

	deps = fileDeps(t, expected.Now)
	deps.FetchStatusList = func(context.Context, string) ([]byte, error) {
		return os.ReadFile(filepath.Join(vectors.Dir(t), "status", "ug-1.json"))
	}
	if got := Credential(context.Background(), claim, deps); got.Reason != StatusListUnverifiable {
		t.Errorf("another issuer's status list: %s %q", got.Result, got.Reason)
	}
}

func TestMemberNamesAreCaseSensitive(t *testing.T) {
	var expected expectedFile
	vectors.Load(t, "expected.json", &expected)
	claim := string(readClaim(t, "gcb-001"))
	for _, swap := range [][2]string{{`"issuer"`, `"Issuer"`}, {`"proofValue"`, `"ProofValue"`}, {`"statusPurpose"`, `"StatusPurpose"`}} {
		altered := strings.Replace(claim, swap[0], swap[1], 1)
		got := Credential(context.Background(), []byte(altered), fileDeps(t, expected.Now))
		if got.Reason != Malformed {
			t.Errorf("%s: got %s %q, want unknown malformed", swap[1], got.Result, got.Reason)
		}
	}
}
