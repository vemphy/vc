package did

import (
	"testing"
	"time"
)

func at(s string) *time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return &t
}

// The boundary is the whole point of this rule, and it is asymmetric on
// purpose: a DID document publishes a retired key's `expires` as the start of
// the second after it stopped signing, so a proof made during that second is
// still covered, while `revoked` is published truncated down to its own
// second, so a proof made during it is not. Both comparisons are therefore
// exclusive of the instant itself, and this test is what stops somebody
// "tidying" one of them into `!After`.
func TestUsableAtIsExclusiveOfTheInstantItself(t *testing.T) {
	moment := at("2026-06-01T12:00:00Z")
	for name, c := range map[string]struct {
		key  Key
		when string
		want bool
	}{
		"a key with no limits":           {Key{}, "2026-06-01T12:00:00Z", true},
		"a second before it was revoked": {Key{Revoked: moment}, "2026-06-01T11:59:59Z", true},
		"exactly when it was revoked":    {Key{Revoked: moment}, "2026-06-01T12:00:00Z", false},
		"a second after it was revoked":  {Key{Revoked: moment}, "2026-06-01T12:00:01Z", false},
		"a second before it expired":     {Key{Expires: moment}, "2026-06-01T11:59:59Z", true},
		"exactly when it expired":        {Key{Expires: moment}, "2026-06-01T12:00:00Z", false},
		"a second after it expired":      {Key{Expires: moment}, "2026-06-01T12:00:01Z", false},
		"revoked before it would expire": {Key{Revoked: at("2026-01-01T00:00:00Z"), Expires: moment}, "2026-03-01T00:00:00Z", false},
	} {
		when, err := time.Parse(time.RFC3339, c.when)
		if err != nil {
			t.Fatal(err)
		}
		key := c.key
		if got := key.UsableAt(when); got != c.want {
			t.Errorf("%s: UsableAt = %v, want %v", name, got, c.want)
		}
	}
}
