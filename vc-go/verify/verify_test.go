package verify

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
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
	"github.com/vemphy/vc/vc-go/vcctx"
)

type expectedFile struct {
	Now     time.Time `json:"now"`
	Vectors map[string]struct {
		Result      Result `json:"result"`
		Reason      Reason `json:"reason"`
		SchemaValid *bool  `json:"schemaValid"`
	} `json:"vectors"`
}

var listURL = regexp.MustCompile(`^https://vemphy\.com/i/([a-z]+)/status/(\d+)$`)

// vectors/cache is what a verifier's cache holds once it has met the issuers' own types.
func cache(t *testing.T) vcctx.Cache { return vcctx.DirCache(filepath.Join(vectors.Dir(t), "cache")) }

// Resolvers backed by the vectors directory. Nothing here touches the network:
// neither resolver is given an HTTP client.
func fileDeps(t *testing.T, now time.Time) Deps {
	dir := vectors.Dir(t)
	return Deps{
		Now:            now,
		DocumentLoader: vcctx.New(vcctx.Options{Cache: cache(t)}),
		FetchSchema:    vcctx.NewSchemas(vcctx.Options{Cache: cache(t)}).Get,
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
			if (got.SchemaValid == nil) != (want.SchemaValid == nil) || (got.SchemaValid != nil && *got.SchemaValid != *want.SchemaValid) {
				t.Errorf("schemaValid differs from expected.json")
			}
		})
	}
}

// Every claim must canonicalize to exactly the bytes the TypeScript side produced.
func TestCanonicalFormsMatchTypeScript(t *testing.T) {
	files, _ := filepath.Glob(filepath.Join(vectors.Dir(t), "canon", "*.nq"))
	loader := vcctx.New(vcctx.Options{Cache: cache(t)})
	seen := map[string]bool{}
	for _, nq := range files {
		name := strings.TrimSuffix(filepath.Base(nq), ".nq")
		// gcb-002 and gcb-009 were altered after signing, so the file on disk is not what was canonicalized.
		if seen[name] || name == "gcb-002" || name == "gcb-009" {
			continue
		}
		// canon/ also holds forms that belong to no claim.
		if _, err := os.Stat(filepath.Join(vectors.Dir(t), "claims", name+".json")); err != nil {
			continue
		}
		seen[name] = true
		var doc map[string]any
		vectors.Load(t, "claims/"+name+".json", &doc)
		delete(doc, "proof")
		want, _ := os.ReadFile(nq)
		got, err := canon.Canonicalize(doc, loader)
		if err != nil || got != string(want) {
			t.Errorf("%s: canonical form differs (%v)", name, err)
		}
	}
	if len(seen) < 18 {
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
	want := "shape context did key key_window signature status_list not_revoked validity_period"
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

func TestAnIssuersOwnTypeNeedsItsContext(t *testing.T) {
	var expected expectedFile
	vectors.Load(t, "expected.json", &expected)
	claim := readClaim(t, "gcb-012")

	// Offline with nothing cached: a clear answer, not a signature failure.
	deps := fileDeps(t, expected.Now)
	deps.DocumentLoader = nil
	if got := Credential(context.Background(), claim, deps); got.Result != Unknown || got.Reason != ContextUnavailable {
		t.Errorf("got %s %q", got.Result, got.Reason)
	}

	// Online: fetched once from vemphy.com, then kept.
	var requested []string
	client := &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
		requested = append(requested, r.URL.String())
		raw, ok := cache(t).Get(r.Context(), r.URL.String())
		if !ok {
			return &http.Response{StatusCode: 404, Body: io.NopCloser(strings.NewReader(""))}, nil
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(raw))}, nil
	})}
	deps.DocumentLoader = vcctx.New(vcctx.Options{Cache: &vcctx.MemoryCache{}, Client: client})
	for i := 0; i < 2; i++ {
		if got := Credential(context.Background(), claim, deps); got.Result != Valid {
			t.Fatalf("got %s %q", got.Result, got.Reason)
		}
	}
	if len(requested) != 1 || requested[0] != "https://vemphy.com/ns/i/gcb/StaffIdCard/v1" {
		t.Errorf("requested %v", requested)
	}
}

func TestSchemaValidityNeverChangesTheAnswer(t *testing.T) {
	var expected expectedFile
	vectors.Load(t, "expected.json", &expected)
	deps := fileDeps(t, expected.Now)

	got := Credential(context.Background(), readClaim(t, "gcb-016"), deps)
	if got.Result != Valid || got.SchemaValid == nil || *got.SchemaValid {
		t.Errorf("a subject that breaks its schema: got %s, schemaValid %v", got.Result, got.SchemaValid)
	}

	deps.FetchSchema = func(context.Context, string) ([]byte, error) { return nil, errors.New("offline") }
	got = Credential(context.Background(), readClaim(t, "gcb-012"), deps)
	if got.Result != Valid || got.SchemaValid != nil {
		t.Errorf("without the schema: got %s, schemaValid %v", got.Result, got.SchemaValid)
	}

	// A schema document that breaks the rules is never compiled.
	document, _ := cache(t).Get(context.Background(), "https://vemphy.com/schemas/i/gcb/StaffIdCard/v1.json")
	hostile := bytes.Replace(document, []byte(`"maxLength":200`), []byte(`"maxLength":200,"$ref":"https://example.com/x"`), 1)
	deps.FetchSchema = func(context.Context, string) ([]byte, error) { return hostile, nil }
	got = Credential(context.Background(), readClaim(t, "gcb-012"), deps)
	if got.Result != Valid || got.SchemaValid == nil || *got.SchemaValid {
		t.Errorf("with a hostile schema: got %s, schemaValid %v", got.Result, got.SchemaValid)
	}
}

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
