package verify

import (
	"encoding/json"
	"strings"
	"testing"
)

type consistencyVectors struct {
	Cases []struct {
		OldSize int      `json:"oldSize"`
		NewSize int      `json:"newSize"`
		OldRoot string   `json:"oldRoot"`
		NewRoot string   `json:"newRoot"`
		Proof   []string `json:"proof"`
	} `json:"cases"`
	MustFail []struct {
		About   string   `json:"about"`
		OldSize int      `json:"oldSize"`
		NewSize int      `json:"newSize"`
		OldRoot string   `json:"oldRoot"`
		NewRoot string   `json:"newRoot"`
		Proof   []string `json:"proof"`
	} `json:"mustFail"`
}

// The job this file does.
//
// Two implementations that agree on inclusion can still disagree on
// consistency, because consistency has branches inclusion does not: the power
// of two case where the old root is omitted from the proof, and the loop that
// walks two sizes at once. Those are the branches where a second implementation
// written from the same document goes wrong, and this is where it has to fail.
func TestConsistencyVectors(t *testing.T) {
	var cv consistencyVectors
	if err := json.Unmarshal(load(t, "consistency.json"), &cv); err != nil {
		t.Fatalf("cannot parse consistency.json: %v", err)
	}
	if len(cv.Cases) == 0 {
		t.Fatal("no cases in consistency.json")
	}

	for _, c := range cv.Cases {
		res := VerifyConsistency(c.OldRoot, c.OldSize, c.NewRoot, c.NewSize, c.Proof)
		if !res.OK {
			t.Errorf("%d to %d should verify: %s", c.OldSize, c.NewSize, res.Reason)
		}
	}
	t.Logf("%d consistency cases verified", len(cv.Cases))

	// A power of two old size is the case an implementation fails first, and it
	// is worth asserting the vector file still contains one rather than
	// discovering later that the coverage was removed.
	hasPowerOfTwo := false
	for _, c := range cv.Cases {
		if isPowerOfTwo(c.OldSize) && c.NewSize > c.OldSize {
			hasPowerOfTwo = true
		}
	}
	if !hasPowerOfTwo {
		t.Error("no power of two old size among the cases; the omitted old root branch is untested")
	}

	for _, f := range cv.MustFail {
		res := VerifyConsistency(f.OldRoot, f.OldSize, f.NewRoot, f.NewSize, f.Proof)
		if res.OK {
			t.Errorf("should have been refused: %s", f.About)
		}
		if res.Reason == "" {
			t.Errorf("refusal with no reason: %s", f.About)
		}
	}
}

// A rewritten log is the attack the proof exists for, and the reason given has
// to distinguish it from a malformed proof. Whoever reads the alert needs to
// know whether they have a bug or an incident.
func TestConsistencyReasonsAreSpecific(t *testing.T) {
	digests := make([]string, 40)
	for i := range digests {
		digests[i] = leafFor(i)
	}
	honest := Root(digests)
	prefix := Root(digests[:20])

	cases := []struct {
		name    string
		oldRoot string
		oldSize int
		newRoot string
		newSize int
		proof   []string
		expect  string
	}{
		{"a shrinking log is named", honest, 40, prefix, 20, nil, "shrank"},
		{"two roots at one size is named", honest, 40, prefix, 40, nil, "two different roots"},
		{"growth with no proof is named", prefix, 21, honest, 40, nil, "empty but the tree grew"},
		{"a non hex step is named", prefix, 21, honest, 40, []string{"nonsense"}, "not a sha256 value"},
		{"an unreadable root is named", "md5:abc", 21, honest, 40, []string{strings.Repeat("a", 64)}, "does not name its hash"},
	}
	for _, c := range cases {
		res := VerifyConsistency(c.oldRoot, c.oldSize, c.newRoot, c.newSize, c.proof)
		if res.OK {
			t.Errorf("%s: should have been refused", c.name)
			continue
		}
		if !strings.Contains(res.Reason, c.expect) {
			t.Errorf("%s: reason %q does not contain %q", c.name, res.Reason, c.expect)
		}
	}
}

// Every pair of sizes up to a bound, computed here rather than read from a
// file, so this implementation is checked against itself as well as against the
// vectors. A proof this package generates is not available, so the check is
// that the vectors cover the shape and these edges behave.
func TestConsistencyEdges(t *testing.T) {
	digests := make([]string, 16)
	for i := range digests {
		digests[i] = leafFor(i)
	}
	full := Root(digests)

	if res := VerifyConsistency(full, 16, full, 16, nil); !res.OK {
		t.Errorf("a tree is consistent with itself: %s", res.Reason)
	}
	// Everything is consistent with an empty tree and there is nothing to prove.
	if res := VerifyConsistency(Root(nil), 0, full, 16, nil); !res.OK {
		t.Errorf("growth from empty should verify: %s", res.Reason)
	}
	if res := VerifyConsistency(Root(nil), 0, full, 16, []string{strings.Repeat("a", 64)}); res.OK {
		t.Error("a proof from an empty tree must be empty")
	}
	if res := VerifyConsistency(full, -1, full, 16, nil); res.OK {
		t.Error("a negative size must be refused")
	}
}
