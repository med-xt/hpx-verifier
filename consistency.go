package verify

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// RFC 6962 section 2.1.2, consistency proofs.
//
// An inclusion proof says a record is in a tree. A consistency proof says the
// tree being shown today is the same tree that was shown last week with records
// added, and not a second tree built afterwards with an inconvenient record left
// out. That distinction is the only thing standing between an evidence log and
// the operator of an evidence log.
//
// Written from docs/spec/record-format.md and RFC 6962 rather than from the
// JavaScript, which is the point of this package existing. If the two
// implementations disagree the vectors fail, and they fail here rather than
// between two organisations that cannot check each other's records.

// ConsistencyResult separates a malformed proof from two roots that describe
// different trees, because the first is a bug and the second is an incident.
type ConsistencyResult struct {
	OK     bool
	Reason string
}

func inconsistent(format string, args ...any) ConsistencyResult {
	return ConsistencyResult{OK: false, Reason: fmt.Sprintf(format, args...)}
}

func isPowerOfTwo(n int) bool { return n > 0 && n&(n-1) == 0 }

func rootHex(root string) ([]byte, error) {
	if !strings.HasPrefix(root, "sha256:") {
		return nil, fmt.Errorf("root %q does not name its hash", root)
	}
	b, err := hex.DecodeString(strings.TrimPrefix(root, "sha256:"))
	if err != nil || len(b) != 32 {
		return nil, fmt.Errorf("root %q is not a sha256 value", root)
	}
	return b, nil
}

func asRoot(b []byte) string { return "sha256:" + hex.EncodeToString(b) }

// VerifyConsistency checks that the tree of newSize leaves contains the tree of
// oldSize leaves as an unchanged prefix.
func VerifyConsistency(oldRoot string, oldSize int, newRoot string, newSize int, path []string) ConsistencyResult {
	if oldSize < 0 || newSize < 0 {
		return inconsistent("sizes must not be negative")
	}
	// A log cannot shrink. This is the headline failure and it is named
	// separately so whoever reads the alert knows which kind of problem it is.
	if oldSize > newSize {
		return inconsistent("the log shrank from %d to %d", oldSize, newSize)
	}

	steps := make([][]byte, 0, len(path)+1)
	for i, h := range path {
		b, err := hex.DecodeString(h)
		if err != nil || len(b) != 32 {
			return inconsistent("proof step %d is not a sha256 value", i)
		}
		steps = append(steps, b)
	}

	if oldSize == newSize {
		if len(steps) != 0 {
			return inconsistent("a proof of no change must be empty")
		}
		if oldRoot != newRoot {
			return inconsistent("the same size reports two different roots")
		}
		return ConsistencyResult{OK: true}
	}
	// Everything is consistent with an empty tree and there is nothing to prove.
	if oldSize == 0 {
		if len(steps) != 0 {
			return inconsistent("a proof from an empty tree must be empty")
		}
		return ConsistencyResult{OK: true}
	}

	expectedOld, err := rootHex(oldRoot)
	if err != nil {
		return inconsistent("%s", err.Error())
	}
	expectedNew, err := rootHex(newRoot)
	if err != nil {
		return inconsistent("%s", err.Error())
	}

	// When the old size is a power of two, the old root is itself a node of the
	// new tree, so the proof omits it and the verifier supplies it. An
	// implementation that misses this fails every power of two case and passes
	// all the others, which is exactly the kind of defect a tidy test set hides.
	if isPowerOfTwo(oldSize) {
		steps = append([][]byte{expectedOld}, steps...)
	}
	if len(steps) == 0 {
		return inconsistent("proof is empty but the tree grew")
	}

	fn, sn := oldSize-1, newSize-1
	for fn&1 == 1 {
		fn >>= 1
		sn >>= 1
	}

	fr, sr := steps[0], steps[0]
	i := 1
	for sn > 0 {
		if i >= len(steps) {
			return inconsistent("proof ended before the tree was reconstructed")
		}
		if fn&1 == 1 || fn == sn {
			fr = NodeHash(steps[i], fr)
			sr = NodeHash(steps[i], sr)
			for fn != 0 && fn&1 == 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			sr = NodeHash(sr, steps[i])
		}
		i++
		fn >>= 1
		sn >>= 1
	}

	if i != len(steps) {
		return inconsistent("proof carries more steps than the tree needs")
	}
	if asRoot(fr) != asRoot(expectedOld) {
		return inconsistent("the proof does not reconstruct the earlier root")
	}
	if asRoot(sr) != asRoot(expectedNew) {
		return inconsistent("the proof does not reconstruct the current root")
	}
	return ConsistencyResult{OK: true}
}
