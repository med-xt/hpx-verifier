package mldsa

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/med-xt/hpx-verifier"
)

func load(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("../conformance/" + name)
	if err != nil {
		t.Fatalf("cannot read conformance/%s: %v", name, err)
	}
	return b
}

// The whole point of this file. Signatures produced by the reference
// implementation in JavaScript, verified by an independent implementation in Go
// against a different post-quantum library.
//
// If this passes, two implementations that share no code agree on canonical
// encoding, on what bytes get signed, and on the signature itself. That is what
// freezing the format actually rests on.
func TestSignedBundleVerifiesEndToEnd(t *testing.T) {
	reg, err := verify.LoadRegistry(load(t, "keys.json"))
	if err != nil {
		t.Fatalf("keys.json: %v", err)
	}
	var b verify.Bundle
	if err := json.Unmarshal(load(t, "bundle-valid.json"), &b); err != nil {
		t.Fatalf("bundle-valid.json: %v", err)
	}

	res := verify.VerifyBundle(&b, reg, New())
	if !res.OK {
		for _, p := range res.Problems {
			t.Errorf("  %s", p)
		}
		t.Fatal("the valid bundle did not verify with signature checking enabled")
	}
	t.Logf("%d records verified, signatures included, across two independent implementations", res.Records)
}

func TestSizesMatchTheSpecification(t *testing.T) {
	if got := SignatureSize(); got != 3309 {
		t.Errorf("ML-DSA-65 signature is %d bytes, specification says 3309", got)
	}
	if got := PublicKeySize(); got != 1952 {
		t.Errorf("ML-DSA-65 public key is %d bytes, specification says 1952", got)
	}
}

// An altered payload must fail the signature, not merely the digest. The digest
// check would catch this on its own, so this proves the signature is actually
// bound to the bytes rather than being carried along beside them.
func TestAlteredPayloadFailsTheSignature(t *testing.T) {
	reg, err := verify.LoadRegistry(load(t, "keys.json"))
	if err != nil {
		t.Fatal(err)
	}
	var b verify.Bundle
	if err := json.Unmarshal(load(t, "bundle-valid.json"), &b); err != nil {
		t.Fatal(err)
	}

	e := b.Records[0]
	v, err := verify.Decode(e.Payload)
	if err != nil {
		t.Fatal(err)
	}
	m := v.(map[string]any)
	m["assertion"].(map[string]any)["nights"] = json.Number("2")
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	e.Payload = raw
	// Recompute the digest so the digest check passes and only the signature
	// is left to catch it.
	bytes, err := e.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	e.Digest = verify.Digest(bytes)

	problems := verify.VerifyRecord(e, reg, New())
	found := false
	for _, p := range problems {
		if p.Code == verify.CodeSigInvalid {
			found = true
		}
	}
	if !found {
		var codes []string
		for _, p := range problems {
			codes = append(codes, p.Code)
		}
		t.Errorf("expected %s, got %v", verify.CodeSigInvalid, codes)
	}
}

func TestMalformedInputIsRefusedNotPanicked(t *testing.T) {
	v := New()
	cases := []struct {
		name string
		alg  string
		sig  string
		key  []byte
	}{
		{"wrong algorithm", "Ed25519", "AAAA", make([]byte, PublicKeySize())},
		{"signature is not base64", Alg, "not base64 !!", make([]byte, PublicKeySize())},
		{"signature is the wrong length", Alg, "AAAA", make([]byte, PublicKeySize())},
		{"public key is the wrong length", Alg, "", make([]byte, 10)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ok, err := v.Verify(c.alg, c.sig, []byte("message"), c.key)
			if ok {
				t.Error("accepted, must be refused")
			}
			if err == nil {
				t.Error("expected an error explaining the refusal")
			}
		})
	}
}
