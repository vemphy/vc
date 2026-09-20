// Package vcctx loads the JSON-LD contexts a Vemphy claim may use. What a
// signature covers depends on the contexts, so where they may come from is
// not left open: bundled documents first, then a cache, then the network, and
// the network only for a URL on an allowlist.
package vcctx

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/piprate/json-gold/ld"

	"github.com/vemphy/vc/vc-go/schema"
)

const (
	CredentialsV2 = "https://www.w3.org/ns/credentials/v2"
	ClaimsV1      = schema.LegacyContext
)

// credentials-v2.json is the W3C file, byte for byte. Its SHA-256 is published in the
// Verifiable Credentials Data Model 2.0 specification:
// 59955ced6697d61e03f2b2556febe5308ab16842846f5b586d7f1f7adec92734
//
//go:embed credentials-v2.json
var credentialsV2 []byte

//go:embed claims-v1.json
var claimsV1 []byte

var (
	// ErrUnknownContext means the URL is not on the allowlist. Nothing was requested.
	ErrUnknownContext = errors.New("not an allowed origin")
	// ErrUnavailable means the URL is allowed, but the document is not bundled
	// or cached and could not be fetched.
	ErrUnavailable = errors.New("document unavailable")
)

// ContextAllowlist is where a context may be fetched from. An entry is an
// exact URL, or a prefix ending in "*".
var ContextAllowlist = []string{CredentialsV2, "https://w3id.org/security/*", "https://vemphy.com/ns/*"}

// SchemaAllowlist is where a schema document may be fetched from.
var SchemaAllowlist = []string{"https://vemphy.com/schemas/*"}

var bundledContexts = sync.OnceValue(func() map[string][]byte {
	documents := map[string][]byte{CredentialsV2: credentialsV2, ClaimsV1: claimsV1}
	for _, t := range schema.Core() {
		documents[t.Ref.ContextURL()] = schema.GenerateContext(t.Schema, t.Ref.Namespace())
	}
	return documents
})

var bundledSchemas = sync.OnceValue(func() map[string][]byte {
	documents := map[string][]byte{}
	for _, t := range schema.Core() {
		doc, err := schema.Document(t.Schema, t.Ref.SchemaURL())
		if err != nil {
			panic(err)
		}
		documents[t.Ref.SchemaURL()] = doc
	}
	return documents
})

// Document returns the bundled context served at url, byte for byte, and
// whether there is one: the W3C context, claims/v1, and every core type
// context. A service that hosts a context should serve these bytes.
func Document(url string) ([]byte, bool) {
	raw, ok := bundledContexts()[url]
	return append([]byte(nil), raw...), ok
}

// SchemaDocument returns the bundled schema document of a core type.
func SchemaDocument(url string) ([]byte, bool) {
	raw, ok := bundledSchemas()[url]
	return append([]byte(nil), raw...), ok
}

// Cache keeps fetched documents. Published contexts and schemas never change,
// so nothing expires.
type Cache interface {
	Get(ctx context.Context, url string) ([]byte, bool)
	Set(ctx context.Context, url string, document []byte)
}

// Options configure a Resolver. The zero value serves the bundled contexts
// and nothing else, offline.
type Options struct {
	// Allowlist defaults to ContextAllowlist.
	Allowlist []string
	Cache     Cache
	// Bundled are documents that need no lookup. Defaults to the bundled contexts.
	Bundled map[string][]byte
	// Client fetches what is neither bundled nor cached. Leave it nil to stay offline.
	Client *http.Client
	// Accept decides whether a fetched document is kept. Defaults to requiring an @context.
	Accept func(document []byte) bool
}

// Resolver finds documents by URL. It is a json-gold document loader.
type Resolver struct{ o Options }

// New returns a resolver for JSON-LD contexts.
func New(o Options) *Resolver {
	if o.Allowlist == nil {
		o.Allowlist = ContextAllowlist
	}
	if o.Bundled == nil {
		o.Bundled = bundledContexts()
	}
	if o.Accept == nil {
		o.Accept = hasMember("@context")
	}
	return &Resolver{o}
}

// NewSchemas returns a resolver for schema documents: the bundled core
// schemas, then the cache, then https://vemphy.com/schemas/.
func NewSchemas(o Options) *Resolver {
	if o.Allowlist == nil {
		o.Allowlist = SchemaAllowlist
	}
	if o.Bundled == nil {
		o.Bundled = bundledSchemas()
	}
	if o.Accept == nil {
		o.Accept = hasMember("properties")
	}
	return &Resolver{o}
}

// Loader returns a document loader that serves the bundled contexts and
// nothing else, offline. extra adds documents by URL, for tests that use
// third-party fixtures; it cannot replace a bundled context.
func Loader(extra map[string][]byte) ld.DocumentLoader {
	documents := make(map[string][]byte, len(extra))
	for u, d := range extra {
		documents[u] = d
	}
	for u, d := range bundledContexts() {
		documents[u] = d
	}
	return New(Options{Allowlist: []string{}, Bundled: documents})
}

func hasMember(name string) func([]byte) bool {
	return func(document []byte) bool {
		var doc map[string]json.RawMessage
		return json.Unmarshal(document, &doc) == nil && doc[name] != nil
	}
}

func allowed(url string, allowlist []string) bool {
	for _, entry := range allowlist {
		if prefix, ok := strings.CutSuffix(entry, "*"); ok {
			if strings.HasPrefix(url, prefix) {
				return true
			}
		} else if url == entry {
			return true
		}
	}
	return false
}

const maxBytes = 64 * 1024

// Get returns the document at url.
func (r *Resolver) Get(ctx context.Context, url string) ([]byte, error) {
	if raw, ok := r.o.Bundled[url]; ok {
		return raw, nil
	}
	if !allowed(url, r.o.Allowlist) {
		return nil, fmt.Errorf("refused to load %s: %w", url, ErrUnknownContext)
	}
	if r.o.Cache != nil {
		if raw, ok := r.o.Cache.Get(ctx, url); ok {
			return raw, nil
		}
	}
	if r.o.Client == nil {
		return nil, fmt.Errorf("%w: %s is not bundled or cached, and this loader is offline", ErrUnavailable, url)
	}
	raw, err := r.fetch(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrUnavailable, url, err)
	}
	if !r.o.Accept(raw) {
		return nil, fmt.Errorf("%w: %s is not the kind of document expected", ErrUnavailable, url)
	}
	if r.o.Cache != nil {
		r.o.Cache.Set(ctx, url, raw)
	}
	return raw, nil
}

func (r *Resolver) fetch(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/ld+json, application/json")
	res, err := r.o.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", res.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(res.Body, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxBytes {
		return nil, errors.New("the document is too large")
	}
	return raw, nil
}

// LoadDocument implements ld.DocumentLoader.
func (r *Resolver) LoadDocument(u string) (*ld.RemoteDocument, error) {
	raw, err := r.Get(context.Background(), u)
	if err != nil {
		return nil, err
	}
	// Decoded per call: the processor is free to modify what it is given.
	var doc any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("context %s: %w", u, err)
	}
	return &ld.RemoteDocument{DocumentURL: u, Document: doc}, nil
}

var unsafeInFileName = regexp.MustCompile(`[^A-Za-z0-9.-]`)

// CacheFileName is the name a document has in a cache directory:
// https://vemphy.com/ns/i/gcb/StaffIdCard/v1 -> vemphy.com_ns_i_gcb_StaffIdCard_v1.json.
// The vemphy-vc command line uses the same names.
func CacheFileName(url string) string {
	return unsafeInFileName.ReplaceAllString(strings.TrimPrefix(url, "https://"), "_") + ".json"
}

// DirCache is a cache that is a directory of JSON files.
type DirCache string

func (d DirCache) Get(_ context.Context, url string) ([]byte, bool) {
	raw, err := os.ReadFile(filepath.Join(string(d), CacheFileName(url)))
	return raw, err == nil
}

func (d DirCache) Set(_ context.Context, url string, document []byte) {
	if os.MkdirAll(string(d), 0o755) == nil {
		_ = os.WriteFile(filepath.Join(string(d), CacheFileName(url)), document, 0o644)
	}
}

// MemoryCache is a cache for the life of the process.
type MemoryCache struct{ m sync.Map }

func (c *MemoryCache) Get(_ context.Context, url string) ([]byte, bool) {
	v, ok := c.m.Load(url)
	if !ok {
		return nil, false
	}
	return v.([]byte), true
}

func (c *MemoryCache) Set(_ context.Context, url string, document []byte) { c.m.Store(url, document) }
