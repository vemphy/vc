package code

import (
	"errors"
	"math/big"
	"reflect"
	"testing"

	"github.com/vemphy/vc/vc-go/internal/vectors"
)

func TestCheckChar(t *testing.T) {
	cases := map[int64]byte{0: '0', 31: 'Z', 32: '*', 33: '~', 34: '$', 35: '=', 36: 'U', 37: '0', 1234: 'D'}
	for n, want := range cases {
		if got := CheckChar(big.NewInt(n)); got != want {
			t.Errorf("CheckChar(%d) = %q, want %q", n, got, want)
		}
	}
}

func TestCheckCharFor(t *testing.T) {
	cases := []struct {
		slug, body string
		want       byte
	}{{"GCB", "0000000", '1'}, {"UG", "0000000", '4'}, {"GCB", "7K2M9QX", 'D'}}
	for _, c := range cases {
		if got := CheckCharFor(c.slug, c.body); got != c.want {
			t.Errorf("CheckCharFor(%s, %s) = %q, want %q", c.slug, c.body, got, c.want)
		}
	}
}

func TestFormat(t *testing.T) {
	if got := Format("gcb", "7k2m9qx"); got != "GCB-7K2M-9QXD" {
		t.Errorf("Format = %s", got)
	}
}

type vectorCase struct {
	Input  string `json:"input"`
	Result struct {
		OK       bool   `json:"ok"`
		Code     string `json:"code"`
		Slug     string `json:"slug"`
		Body     string `json:"body"`
		Check    string `json:"check"`
		Error    string `json:"error"`
		Position int    `json:"position"`
		Suspects []int  `json:"suspects"`
	} `json:"result"`
	Issuable *bool `json:"issuable"`
}

func TestVectors(t *testing.T) {
	var cases []vectorCase
	vectors.Load(t, "codes.json", &cases)
	if len(cases) == 0 {
		t.Fatal("no cases")
	}
	for _, c := range cases {
		got, err := Parse(c.Input)
		want := c.Result
		if want.OK {
			if err != nil {
				t.Errorf("%q: unexpected error %v", c.Input, err)
				continue
			}
			if got.String() != want.Code || got.Slug != want.Slug || got.Body != want.Body || got.Check != want.Check {
				t.Errorf("%q: got %+v, want %+v", c.Input, got, want)
			}
			if c.Issuable != nil && IsIssuable(got) != *c.Issuable {
				t.Errorf("%q: IsIssuable = %v", c.Input, IsIssuable(got))
			}
			continue
		}
		var perr *ParseError
		if !errors.As(err, &perr) {
			t.Errorf("%q: got %v, want ParseError", c.Input, err)
			continue
		}
		if string(perr.Kind) != want.Error || perr.Position != want.Position {
			t.Errorf("%q: got %s at %d, want %s at %d", c.Input, perr.Kind, perr.Position, want.Error, want.Position)
		}
		if want.Error == "check" && !reflect.DeepEqual(perr.Suspects, want.Suspects) {
			t.Errorf("%q: suspects %v, want %v", c.Input, perr.Suspects, want.Suspects)
		}
	}
}
