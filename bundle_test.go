package verify

import (
	"encoding/json"
	"strings"
	"testing"
)

type merkleVectors struct {
	EmptyTreeRoot string `json:"emptyTreeRoot"`
	Trees         []struct {
		Size   int    `json:"size"`
		Root   string `json:"root"`
		Proofs []struct {
			Index int            `json:"index"`
			Leaf  string         `json:"leaf"`
			Proof InclusionProof `json:"proof"`
		} `json:"proofs"`
	} `json:"trees"`
	MustFail []struct {
		About string         `json:"about"`
		Root  string         `json:"root"`
		Leaf  string         `json:"leaf"`
		Proof InclusionProof `json:"proof"`
	} `json:"mustFail"`
}

func leafFor(i int) string {
	s := ""
	n := []byte(itoa(i))
	for j := 0; j < 64-len(n); j++ {
		s += "0"
	}
	return "sha256:" + s + string(n)
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}

func TestMerkleVectors(t *testing.T) {
	var mv merkleVectors
	if err := json.Unmarshal(load(t, "merkle.json"), &mv); err != nil {
		t.Fatalf("cannot parse merkle.json: %v", err)
	}

	if got := Root(nil); got != mv.EmptyTreeRoot {
		t.Errorf("empty tree root\n  expected %s\n  got      %s", mv.EmptyTreeRoot, got)
	}

	proofs := 0
	for _, tree := range mv.Trees {
		digests := make([]string, tree.Size)
		for i := range digests {
			digests[i] = leafFor(i)
		}
		if got := Root(digests); got != tree.Root {
			t.Errorf("size %d root\n  expected %s\n  got      %s", tree.Size, tree.Root, got)
		}
		for _, p := range tree.Proofs {
			proofs++
			ok, err := VerifyInclusion(p.Leaf, p.Proof, tree.Root)
			if err != nil {
				t.Errorf("size %d index %d: %v", tree.Size, p.Index, err)
			} else if !ok {
				t.Errorf("size %d index %d: proof does not verify", tree.Size, p.Index)
			}
		}
	}
	t.Logf("%d tree roots and %d inclusion proofs reproduced", len(mv.Trees), proofs)

	// A valid path presented with a different leaf. A verifier that checks only
	// that the path is internally consistent accepts this, which is why the
	// record digest is an input rather than something read out of the proof.
	for _, f := range mv.MustFail {
		ok, err := VerifyInclusion(f.Leaf, f.Proof, f.Root)
		if err != nil {
			t.Errorf("%s: unexpected error %v", f.About, err)
		} else if ok {
			t.Errorf("%s: accepted, must be rejected", f.About)
		}
	}
}

// Floating point log2 lands a hair under the integer for some large powers of
// two, which splits the tree in the wrong place for exactly one size and
// produces a root that disagrees with every other implementation.
func TestSplitPointIsExact(t *testing.T) {
	cases := map[int]int{2: 1, 3: 2, 4: 2, 5: 4, 7: 4, 8: 4, 9: 8, 1024: 512, 1025: 1024, 100000: 65536}
	for n, want := range cases {
		if got := splitPoint(n); got != want {
			t.Errorf("splitPoint(%d) = %d, want %d", n, got, want)
		}
	}
}

func TestLeafAndNodeDomainsDiffer(t *testing.T) {
	d := "sha256:" + "ab"
	l := LeafHash(d)
	// The same bytes hashed as an interior node must not collide with the leaf.
	n := NodeHash([]byte(d), nil)
	if string(l) == string(n) {
		t.Fatal("leaf and interior node hash identically; domain separation is missing")
	}
}

// ---------------------------------------------------------------- the bundle

func TestBundleStructurally(t *testing.T) {
	reg, err := LoadRegistry(load(t, "keys.json"))
	if err != nil {
		t.Fatalf("keys.json: %v", err)
	}
	var b Bundle
	if err := json.Unmarshal(load(t, "bundle-valid.json"), &b); err != nil {
		t.Fatalf("cannot parse bundle-valid.json: %v", err)
	}

	// Signature verification is deliberately absent here. Everything else must
	// pass with the standard library alone: digests, the chain and the log.
	res := VerifyBundle(&b, reg, nil)
	if !res.OK {
		for _, p := range res.Problems {
			t.Errorf("  %s", p)
		}
		t.Fatal("the valid bundle did not verify structurally")
	}
	if res.Records != 6 {
		t.Errorf("expected 6 records, got %d", res.Records)
	}
	t.Logf("%d records verified structurally against an independent implementation", res.Records)
}

func TestBundleFailures(t *testing.T) {
	reg, err := LoadRegistry(load(t, "keys.json"))
	if err != nil {
		t.Fatal(err)
	}
	raw := load(t, "bundle-valid.json")

	fresh := func(t *testing.T) *Bundle {
		t.Helper()
		var b Bundle
		if err := json.Unmarshal(raw, &b); err != nil {
			t.Fatal(err)
		}
		return &b
	}

	// Each case is built from the valid bundle so the only difference between
	// pass and fail is the defect itself.
	cases := []struct {
		name   string
		code   string
		mutate func(*testing.T, *Bundle)
	}{
		{"a field altered in a record", CodeDigestMismatch, func(t *testing.T, b *Bundle) {
			setPayload(t, b.Records[0], func(p map[string]any) {
				assertion(t, p)["nights"] = json.Number("2")
			})
		}},
		{"two records transposed", CodePrevMismatch, func(t *testing.T, b *Bundle) {
			b.Records[1], b.Records[2] = b.Records[2], b.Records[1]
		}},
		{"a record removed from the middle", CodeSeqMismatch, func(t *testing.T, b *Bundle) {
			b.Records = append(b.Records[:2], b.Records[3:]...)
		}},
		{"a record inserted into the chain", CodeSeqMismatch, func(t *testing.T, b *Bundle) {
			dup := *b.Records[1]
			b.Records = append(b.Records[:3], append([]*Envelope{&dup}, b.Records[3:]...)...)
		}},
		{"a key not in the registry", CodeKeyUnknown, func(t *testing.T, b *Bundle) {
			b.Records[0].Signature.KeyID = "k-unknown-999"
			setPayload(t, b.Records[0], func(p map[string]any) {
				keyRef(t, p)["id"] = "k-unknown-999"
			})
		}},
		{"the envelope key reference swapped", CodeKeyMismatch, func(t *testing.T, b *Bundle) {
			b.Records[2].Signature.KeyID = "k-hosp-001"
		}},
		{"an unknown spec version", CodeSpecUnknown, func(t *testing.T, b *Bundle) {
			setPayload(t, b.Records[0], func(p map[string]any) { p["spec"] = "hpx/9" })
		}},
		{"a forged digest against a valid proof", CodeInclusionFailed, func(t *testing.T, b *Bundle) {
			b.Records[0].Digest = "sha256:" + strings.Repeat("0", 64)
		}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b := fresh(t)
			c.mutate(t, b)
			res := VerifyBundle(b, reg, nil)
			if res.OK {
				t.Fatal("accepted, must be rejected")
			}
			found := false
			for _, p := range res.Problems {
				if p.Code == c.code {
					found = true
				}
			}
			if !found {
				var codes []string
				for _, p := range res.Problems {
					codes = append(codes, p.Code)
				}
				t.Errorf("expected code %s, got %v", c.code, codes)
			}
		})
	}
}

// Mutating the payload as text is how the first version of this test quietly
// did nothing: the committed bundle is pretty printed, so a search for
// `"nights":3` matched a string that does not appear in the file. A mutation
// that silently fails turns a negative test into one that proves nothing.
//
// Decoding, mutating and re-encoding has no whitespace dependency at all. The
// digest is computed over the canonical form, so re-encoding is free.
func setPayload(t *testing.T, e *Envelope, fn func(map[string]any)) {
	t.Helper()
	v, err := Decode(e.Payload)
	if err != nil {
		t.Fatalf("payload will not decode: %v", err)
	}
	m, ok := v.(map[string]any)
	if !ok {
		t.Fatalf("payload is %T, expected an object", v)
	}
	fn(m)
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("payload will not re-encode: %v", err)
	}
	e.Payload = b
}

func assertion(t *testing.T, p map[string]any) map[string]any {
	t.Helper()
	a, ok := p["assertion"].(map[string]any)
	if !ok {
		t.Fatalf("payload has no assertion object, got %T", p["assertion"])
	}
	return a
}

func keyRef(t *testing.T, p map[string]any) map[string]any {
	t.Helper()
	k, ok := p["key"].(map[string]any)
	if !ok {
		t.Fatalf("payload has no key object, got %T", p["key"])
	}
	return k
}

// Proves the mutation helper actually mutates. Without this, every negative
// case above could silently pass on an unmodified bundle.
func TestMutationHelperActuallyMutates(t *testing.T) {
	var b Bundle
	if err := json.Unmarshal(load(t, "bundle-valid.json"), &b); err != nil {
		t.Fatal(err)
	}
	before := b.Records[0].Digest
	computedBefore, err := b.Records[0].CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	if Digest(computedBefore) != before {
		t.Fatal("the unmodified record does not match its own digest")
	}
	setPayload(t, b.Records[0], func(p map[string]any) {
		assertion(t, p)["nights"] = json.Number("2")
	})
	computedAfter, err := b.Records[0].CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	if Digest(computedAfter) == before {
		t.Fatal("mutation did not change the payload digest")
	}
}
