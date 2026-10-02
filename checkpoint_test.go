package verify

import (
	"encoding/json"
	"strings"
	"testing"
)

type checkpointVectors struct {
	Spec  string `json:"spec"`
	Cases []struct {
		Fields struct {
			Origin string `json:"origin"`
			Size   int    `json:"size"`
			Root   string `json:"root"`
			Time   string `json:"time"`
		} `json:"fields"`
		Body string `json:"body"`
	} `json:"cases"`
	MustReject []struct {
		About string `json:"about"`
		Body  string `json:"body"`
	} `json:"mustReject"`
}

// The body is the signed bytes. A parser that accepts a body it would not
// reproduce, or reproduces one it was not given, breaks every signature over it
// in a way that is indistinguishable from tampering.
func TestCheckpointVectors(t *testing.T) {
	var kv checkpointVectors
	if err := json.Unmarshal(load(t, "checkpoint.json"), &kv); err != nil {
		t.Fatalf("cannot parse checkpoint.json: %v", err)
	}
	if kv.Spec != CheckpointSpec {
		t.Fatalf("vector file is for spec %q, this implementation is %s", kv.Spec, CheckpointSpec)
	}
	if len(kv.Cases) == 0 {
		t.Fatal("no cases in checkpoint.json")
	}

	for _, c := range kv.Cases {
		// Parsing requires a signature block, so one is attached. The fields
		// and the body are what this case is about.
		cp, err := ParseCheckpoint(c.Body + "\nsig k-log-001 1 ML-DSA-65 AA==\n")
		if err != nil {
			t.Errorf("size %d: %v", c.Fields.Size, err)
			continue
		}
		if cp.Origin != c.Fields.Origin || cp.Size != c.Fields.Size || cp.Root != c.Fields.Root || cp.Time != c.Fields.Time {
			t.Errorf("size %d: parsed fields disagree with the vector", c.Fields.Size)
		}
		// The body must come back byte for byte, including the trailing newline.
		if cp.Body != c.Body {
			t.Errorf("size %d: body is not preserved\n  expected %q\n  got      %q", c.Fields.Size, c.Body, cp.Body)
		}
	}
	t.Logf("%d checkpoint bodies parsed and preserved", len(kv.Cases))

	for _, r := range kv.MustReject {
		if _, err := ParseCheckpoint(r.Body); err == nil {
			t.Errorf("should have been rejected: %s", r.About)
		}
	}
}

func TestCheckpointParserRefusals(t *testing.T) {
	good := CheckpointSpec + "\nmedxt-evidence/us-east-1\n8\nsha256:" + strings.Repeat("1", 64) + "\n2026-10-01T12:00:00.000Z\n\nsig k-log-001 1 ML-DSA-65 AA==\n"
	if _, err := ParseCheckpoint(good); err != nil {
		t.Fatalf("the baseline document should parse: %v", err)
	}

	cases := []struct {
		name     string
		document string
	}{
		{"no signature block", strings.Split(good, "\n\n")[0] + "\n"},
		{"an empty signature block", strings.Split(good, "\n\n")[0] + "\n\n"},
		{"a carriage return", strings.ReplaceAll(good, "\n", "\r\n")},
		{"a leading zero in the size", strings.Replace(good, "\n8\n", "\n08\n", 1)},
		{"a negative size", strings.Replace(good, "\n8\n", "\n-8\n", 1)},
		{"an unknown spec", strings.Replace(good, CheckpointSpec, "hpx/checkpoint/2", 1)},
		{"an origin with a space", strings.Replace(good, "medxt-evidence/us-east-1", "medxt evidence", 1)},
		{"a root with the wrong algorithm", strings.Replace(good, "sha256:", "md5:", 1)},
		{"a time without milliseconds", strings.Replace(good, "2026-10-01T12:00:00.000Z", "2026-10-01T12:00:00Z", 1)},
		{"a time that is not a date", strings.Replace(good, "2026-10-01T12:00:00.000Z", "2026-02-30T12:00:00.000Z", 1)},
		{"a signature line with a missing field", strings.Replace(good, "sig k-log-001 1 ML-DSA-65 AA==", "sig k-log-001 1 AA==", 1)},
		{"a signature value that is not base64", strings.Replace(good, "AA==", "not base64!", 1)},
		{"a second blank line", strings.Replace(good, "\n\nsig", "\n\n\nsig", 1)},
		// Two signatures from one key would let a quorum count look larger than
		// it is, which is the only way to defeat a quorum rule without a key.
		{"the same key twice", good + "sig k-log-001 1 ML-DSA-65 AA==\n"},
	}
	for _, c := range cases {
		if _, err := ParseCheckpoint(c.document); err == nil {
			t.Errorf("should have been refused: %s", c.name)
		}
	}
}

// A checkpoint signed only by the log proves nothing against the log. The
// log's signature is necessary and never sufficient, and that is the single
// most important thing this file asserts.
func TestQuorum(t *testing.T) {
	logOnly := CheckpointResult{OK: true, SignedBy: []CheckpointSigner{{KeyID: "k-log-001", Version: 1}}}
	if ok, reason := MeetsQuorum(logOnly, "k-log-001", 1); ok {
		t.Error("the log alone must not meet a quorum of one witness")
	} else if !strings.Contains(reason, "0 independent") {
		t.Errorf("reason should count the independent signatures, got %q", reason)
	}

	witnessed := CheckpointResult{OK: true, SignedBy: []CheckpointSigner{
		{KeyID: "k-log-001", Version: 1},
		{KeyID: "k-wit-001", Version: 1, Owner: "Independent witness"},
	}}
	if ok, reason := MeetsQuorum(witnessed, "k-log-001", 1); !ok {
		t.Errorf("one witness should meet a quorum of one: %s", reason)
	}
	if ok, _ := MeetsQuorum(witnessed, "k-log-001", 2); ok {
		t.Error("one witness must not meet a quorum of two")
	}

	// Witnesses without the log is not the log speaking.
	noLog := CheckpointResult{OK: true, SignedBy: []CheckpointSigner{{KeyID: "k-wit-001", Version: 1}}}
	if ok, reason := MeetsQuorum(noLog, "k-log-001", 1); ok {
		t.Error("a checkpoint the log did not sign must not meet a quorum")
	} else if !strings.Contains(reason, "did not sign") {
		t.Errorf("reason should say the log did not sign, got %q", reason)
	}

	if ok, _ := MeetsQuorum(CheckpointResult{OK: false}, "k-log-001", 0); ok {
		t.Error("an invalid checkpoint must not meet any quorum")
	}
}

// Without a verifier the parser still works and no signature is treated as
// valid. A structural pass that silently counted as a cryptographic one would
// be the worst defect this tool could have.
func TestCheckpointWithoutAVerifier(t *testing.T) {
	good := CheckpointSpec + "\na-log\n8\nsha256:" + strings.Repeat("1", 64) + "\n2026-10-01T12:00:00.000Z\n\nsig k-log-001 1 ML-DSA-65 AA==\n"
	res := VerifyCheckpoint(good, NewRegistry(), nil)
	if res.OK {
		t.Error("no verifier must not produce a valid result")
	}
	if len(res.SignedBy) != 0 {
		t.Error("no signature can be reported as valid without a verifier")
	}
	if res.Checkpoint == nil || res.Checkpoint.Size != 8 {
		t.Error("the checkpoint should still be parsed and reported")
	}
}
