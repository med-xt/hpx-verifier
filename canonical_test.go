package verify

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"os"
	"strings"
	"testing"
)

const omitSentinel = "<<omit>>"

type canonicalVectors struct {
	OmitSentinel string `json:"omitSentinel"`
	OmitMeaning  string `json:"omitMeaning"`
	Cases        []struct {
		Name     string          `json:"name"`
		Input    json.RawMessage `json:"input"`
		Expected string          `json:"expected"`
		Digest   string          `json:"digest"`
	} `json:"cases"`
}

// A value equal to the sentinel means the key is absent, not null. JSON cannot
// express "this key is not present", and the distinction changes the digest, so
// the vector file states the protocol rather than leaving it to be inferred.
func hydrate(v any) any {
	switch t := v.(type) {
	case []any:
		out := make([]any, 0, len(t))
		for _, e := range t {
			out = append(out, hydrate(e))
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, e := range t {
			if s, isStr := e.(string); isStr && s == omitSentinel {
				continue
			}
			out[k] = hydrate(e)
		}
		return out
	default:
		return v
	}
}

func load(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("conformance/" + name)
	if err != nil {
		t.Fatalf("cannot read conformance/%s: %v", name, err)
	}
	return b
}

func TestCanonicalVectors(t *testing.T) {
	var cv canonicalVectors
	if err := json.Unmarshal(load(t, "canonical.json"), &cv); err != nil {
		t.Fatalf("cannot parse canonical.json: %v", err)
	}
	if cv.OmitSentinel != omitSentinel {
		t.Fatalf("vector file uses sentinel %q, this implementation expects %q", cv.OmitSentinel, omitSentinel)
	}
	if len(cv.Cases) == 0 {
		t.Fatal("no cases in canonical.json")
	}

	for _, c := range cv.Cases {
		t.Run(c.Name, func(t *testing.T) {
			raw, err := Decode(c.Input)
			if err != nil {
				t.Fatalf("cannot decode input: %v", err)
			}
			got, err := Canonicalize(hydrate(raw))
			if err != nil {
				t.Fatalf("canonicalize: %v", err)
			}
			if got != c.Expected {
				t.Errorf("\n  expected %s\n  got      %s", c.Expected, got)
				return
			}
			sum := sha256.Sum256([]byte(got))
			if d := "sha256:" + hex.EncodeToString(sum[:]); d != c.Digest {
				t.Errorf("digest mismatch\n  expected %s\n  got      %s", c.Digest, d)
			}
		})
	}
	t.Logf("%d canonical vectors reproduced", len(cv.Cases))
}

// Absence and null must not collide. If they did, a record could drop a field
// and keep its digest, which is the property the whole format rests on.
func TestAbsentIsNotNull(t *testing.T) {
	withNull, err := Canonicalize(map[string]any{"a": json.Number("1"), "b": nil})
	if err != nil {
		t.Fatal(err)
	}
	withAbsent, err := Canonicalize(map[string]any{"a": json.Number("1")})
	if err != nil {
		t.Fatal(err)
	}
	if withNull == withAbsent {
		t.Fatalf("absent and null encode identically as %s", withNull)
	}
}

// Go's native string ordering is byte-wise over UTF-8, which agrees with UTF-16
// code unit ordering inside the Basic Multilingual Plane and disagrees above it.
// This pins the behaviour so a future refactor to sort.Strings is caught here
// rather than by a partner organisation that cannot verify our records.
func TestKeyOrderIsUTF16(t *testing.T) {
	// U+FF3A fullwidth Z is one UTF-16 unit. U+1D419 mathematical bold capital Z
	// is a surrogate pair starting D835, so it sorts first in UTF-16 and second
	// in code point order.
	got, err := Canonicalize(map[string]any{"Ｚ": json.Number("1"), "\U0001D419": json.Number("2")})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(got, "{\"\U0001D419\"") {
		t.Errorf("surrogate pair key should sort first under UTF-16 ordering, got %s", got)
	}
}

func TestNumberFormatting(t *testing.T) {
	cases := []struct {
		in   float64
		want string
	}{
		{0, "0"},
		{-0, "0"},
		{1, "1"},
		{1.0, "1"},
		{-42, "-42"},
		{1.5, "1.5"},
		{0.1, "0.1"},
		{1.0 / 3.0, "0.3333333333333333"},
		// The band where Go and ECMAScript disagree. Go's %g would render the
		// first of these as 1e+20.
		{1e20, "100000000000000000000"},
		{1e21, "1e+21"},
		{1e-6, "0.000001"},
		{1e-7, "1e-7"},
		{9007199254740991, "9007199254740991"},
	}
	for _, c := range cases {
		got, err := jsNumber(c.in)
		if err != nil {
			t.Errorf("%v: %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("%v: expected %s, got %s", c.in, c.want, got)
		}
	}
}

// Untyped constants are evaluated at arbitrary precision, so 1e308*10 is a
// compile error rather than an infinity. math.Inf is the only way to get one.
func TestNonFiniteIsRefused(t *testing.T) {
	for _, f := range []float64{math.Inf(1), math.Inf(-1), math.NaN()} {
		if _, err := jsNumber(f); err == nil {
			t.Errorf("expected a refusal for %v", f)
		}
	}
}
