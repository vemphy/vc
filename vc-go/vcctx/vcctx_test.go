package vcctx_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/vemphy/vc/vc-go/vcctx"
)

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func respond(status int, body string, calls *int) *http.Client {
	return &http.Client{Transport: roundTrip(func(*http.Request) (*http.Response, error) {
		*calls++
		return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body))}, nil
	})}
}

const custom = "https://vemphy.com/ns/i/gcb/StaffIdCard/v1"

func TestBundledDocumentsNeedNothing(t *testing.T) {
	r := vcctx.New(vcctx.Options{})
	for _, url := range []string{vcctx.CredentialsV2, vcctx.ClaimsV1, "https://vemphy.com/ns/core/Attestation/v1"} {
		if _, err := r.Get(context.Background(), url); err != nil {
			t.Errorf("%s: %v", url, err)
		}
	}
	if _, err := vcctx.NewSchemas(vcctx.Options{}).Get(context.Background(), "https://vemphy.com/schemas/core/Attestation/v1.json"); err != nil {
		t.Error(err)
	}
}

func TestOtherOriginsAreRefusedBeforeAnyRequest(t *testing.T) {
	calls := 0
	cache := &vcctx.MemoryCache{}
	cache.Set(context.Background(), "https://example.com/ns/v1", []byte(`{"@context":{}}`))
	r := vcctx.New(vcctx.Options{Cache: cache, Client: respond(200, `{"@context":{}}`, &calls)})
	for _, url := range []string{
		"https://example.com/ns/v1",
		"http://vemphy.com/ns/i/gcb/StaffIdCard/v1",
		"https://vemphy.com.example.com/ns/x",
		"https://vemphy.com/other",
		"https://www.w3.org/ns/credentials/v2/extra",
	} {
		if _, err := r.Get(context.Background(), url); !errors.Is(err, vcctx.ErrUnknownContext) {
			t.Errorf("%s: %v", url, err)
		}
	}
	if calls != 0 {
		t.Errorf("%d requests were made", calls)
	}
}

func TestFetchedOnceThenCached(t *testing.T) {
	calls := 0
	r := vcctx.New(vcctx.Options{Cache: &vcctx.MemoryCache{}, Client: respond(200, `{"@context":{}}`, &calls)})
	for i := 0; i < 2; i++ {
		if _, err := r.Get(context.Background(), custom); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 1 {
		t.Errorf("%d requests were made", calls)
	}
}

func TestOfflineWithoutAClient(t *testing.T) {
	_, err := vcctx.New(vcctx.Options{}).Get(context.Background(), custom)
	if !errors.Is(err, vcctx.ErrUnavailable) || !strings.Contains(err.Error(), "offline") {
		t.Errorf("got %v", err)
	}
}

func TestWhatIsNotAContextIsNotKept(t *testing.T) {
	for name, client := range map[string]func(*int) *http.Client{
		"an error status":       func(c *int) *http.Client { return respond(404, "no", c) },
		"not JSON":              func(c *int) *http.Client { return respond(200, "<html>", c) },
		"JSON with no @context": func(c *int) *http.Client { return respond(200, `{"hello":"world"}`, c) },
		"a document over 64 KB": func(c *int) *http.Client {
			return respond(200, `{"@context":{},"p":"`+strings.Repeat("x", 70_000)+`"}`, c)
		},
	} {
		calls := 0
		cache := &vcctx.MemoryCache{}
		_, err := vcctx.New(vcctx.Options{Cache: cache, Client: client(&calls)}).Get(context.Background(), custom)
		if !errors.Is(err, vcctx.ErrUnavailable) {
			t.Errorf("%s: %v", name, err)
		}
		if _, ok := cache.Get(context.Background(), custom); ok {
			t.Errorf("%s was kept", name)
		}
	}
}

func TestTheCacheCannotReplaceABundledContext(t *testing.T) {
	cache := &vcctx.MemoryCache{}
	cache.Set(context.Background(), vcctx.CredentialsV2, []byte(`{"@context":{}}`))
	got, _ := vcctx.New(vcctx.Options{Cache: cache}).Get(context.Background(), vcctx.CredentialsV2)
	want, _ := vcctx.Document(vcctx.CredentialsV2)
	if string(got) != string(want) {
		t.Error("the cache replaced a bundled context")
	}
}

func TestCacheFileName(t *testing.T) {
	if got := vcctx.CacheFileName("https://vemphy.com/schemas/i/gcb/StaffIdCard/v1.json"); got != "vemphy.com_schemas_i_gcb_StaffIdCard_v1.json.json" {
		t.Error(got)
	}
}
