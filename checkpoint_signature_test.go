// This file is the one place the two implementations are tied together
// cryptographically on the checkpoint.
//
// Everything else about a checkpoint is structural and runs on the standard
// library. Here a document signed by the reference implementation in
// JavaScript, with ML-DSA-65 keys generated there, is verified in Go by a
// different library. If this passes, a checkpoint produced by the log can be
// checked by somebody who shares no code with it, which is the only form of
// verification worth the name.
//
// It lives in the external test package so the verify package's own dependency
// graph stays standard library only.
package verify_test

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/med-xt/hpx-verifier"
	"github.com/med-xt/hpx-verifier/mldsa"
)

type signedCheckpoint struct {
	Keys   []*verify.Key `json:"keys"`
	Fields struct {
		Origin string `json:"origin"`
		Size   int    `json:"size"`
		Root   string `json:"root"`
		Time   string `json:"time"`
	} `json:"fields"`
	LogOnly   string `json:"logOnly"`
	Witnessed string `json:"witnessed"`
	MustFail  []struct {
		About    string `json:"about"`
		Document string `json:"document"`
	} `json:"mustFail"`
}

func loadSigned(t *testing.T) (*signedCheckpoint, *verify.Registry) {
	t.Helper()
	b, err := os.ReadFile("conformance/checkpoint-signed.json")
	if err != nil {
		t.Fatalf("cannot read conformance/checkpoint-signed.json: %v", err)
	}
	var sc signedCheckpoint
	if err := json.Unmarshal(b, &sc); err != nil {
		t.Fatalf("cannot parse checkpoint-signed.json: %v", err)
	}
	keyList, err := json.Marshal(sc.Keys)
	if err != nil {
		t.Fatalf("cannot re-encode the key list: %v", err)
	}
	reg, err := verify.LoadRegistry(keyList)
	if err != nil {
		t.Fatalf("cannot load the key registry: %v", err)
	}
	return &sc, reg
}

func TestSignedCheckpointVerifiesAcrossImplementations(t *testing.T) {
	sc, reg := loadSigned(t)
	sv := mldsa.New()

	res := verify.VerifyCheckpoint(sc.LogOnly, reg, sv)
	if !res.OK {
		t.Fatalf("the log signed checkpoint should verify: %v", res.Problems)
	}
	if len(res.Problems) != 0 {
		t.Errorf("unexpected problems: %v", res.Problems)
	}
	if res.Checkpoint.Size != sc.Fields.Size || res.Checkpoint.Root != sc.Fields.Root {
		t.Errorf("parsed fields disagree with the vector")
	}
	if len(res.SignedBy) != 1 || res.SignedBy[0].KeyID != "k-log-001" {
		t.Errorf("expected one signature from the log, got %+v", res.SignedBy)
	}

	// A co-signature must not disturb the one already there. If it did,
	// witnessing would require re-signing, and a witness cannot sign for the
	// log.
	wit := verify.VerifyCheckpoint(sc.Witnessed, reg, sv)
	if !wit.OK || len(wit.SignedBy) != 2 {
		t.Fatalf("the witnessed checkpoint should carry two valid signatures: %v %+v", wit.Problems, wit.SignedBy)
	}
	logParsed, err := verify.ParseCheckpoint(sc.LogOnly)
	if err != nil {
		t.Fatal(err)
	}
	if wit.Checkpoint.Body != logParsed.Body {
		t.Error("co-signing changed the body, which would invalidate the log's own signature")
	}

	if ok, reason := verify.MeetsQuorum(wit, "k-log-001", 1); !ok {
		t.Errorf("the witnessed checkpoint should meet a one witness quorum: %s", reason)
	}
	if ok, _ := verify.MeetsQuorum(res, "k-log-001", 1); ok {
		t.Error("the log signed checkpoint alone should not meet a one witness quorum")
	}
}

// A checkpoint inside a bundle has to be tied to the root the inclusion proofs
// are built on. A valid checkpoint for a different tree verifies as a document
// and proves nothing about these records, and accepting it as though it did
// would be worse than carrying none at all.
func TestBundleCheckpointIsTiedToTheLogRoot(t *testing.T) {
	sc, reg := loadSigned(t)
	sv := mldsa.New()

	cp, err := verify.ParseCheckpoint(sc.Witnessed)
	if err != nil {
		t.Fatal(err)
	}

	matching := &verify.Bundle{LogRoot: cp.Root, Checkpoint: sc.Witnessed}
	out, problems := verify.VerifyBundleCheckpoint(matching, reg, sv)
	if len(problems) != 0 {
		t.Errorf("a checkpoint over the bundle's own root should raise nothing: %v", problems)
	}
	if !out.Present || !out.Verified || !out.MatchesLogRoot {
		t.Errorf("expected a verified checkpoint, got %+v", out)
	}
	if out.Size != sc.Fields.Size || out.Origin != sc.Fields.Origin {
		t.Errorf("the outcome should carry the checkpoint's own fields, got %+v", out)
	}
	if len(out.SignedBy) != 2 {
		t.Errorf("expected two signers, got %+v", out.SignedBy)
	}

	elsewhere := &verify.Bundle{LogRoot: "sha256:" + strings.Repeat("c", 64), Checkpoint: sc.Witnessed}
	out, problems = verify.VerifyBundleCheckpoint(elsewhere, reg, sv)
	if len(problems) == 0 {
		t.Fatal("a checkpoint for another root must be refused")
	}
	if problems[0].Code != verify.CodeCheckpointMismatch {
		t.Errorf("expected %s, got %s", verify.CodeCheckpointMismatch, problems[0].Code)
	}
	if out.Verified || out.MatchesLogRoot {
		t.Errorf("it must not be reported as verified, got %+v", out)
	}

	// No checkpoint is not a failure. The records are genuine and the log's
	// history is simply not independently established, and the outcome has to
	// distinguish those two states rather than collapse them.
	none := &verify.Bundle{LogRoot: cp.Root}
	out, problems = verify.VerifyBundleCheckpoint(none, reg, sv)
	if len(problems) != 0 || out.Present || out.Verified {
		t.Errorf("an absent checkpoint is not a failure, got %+v %v", out, problems)
	}
}

func TestSignedCheckpointTamperCases(t *testing.T) {
	sc, reg := loadSigned(t)
	sv := mldsa.New()

	for _, f := range sc.MustFail {
		res := verify.VerifyCheckpoint(f.Document, reg, sv)
		if res.OK {
			t.Errorf("should have failed: %s", f.About)
		}
	}

	// A key the registry does not hold is reported and does not pass. This is
	// the case a reviewer hits when handed a checkpoint co-signed by a witness
	// whose key they were never given.
	empty := verify.NewRegistry()
	res := verify.VerifyCheckpoint(sc.LogOnly, empty, sv)
	if res.OK {
		t.Error("a checkpoint whose key is unknown must not verify")
	}
	if len(res.Problems) == 0 || !strings.Contains(res.Problems[0], "not in the registry") {
		t.Errorf("the problem should name the missing key, got %v", res.Problems)
	}
}
