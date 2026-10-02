package verify

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// RFC 6962 domain separation. Leaves carry 0x00 and interior nodes carry 0x01.
//
// These two bytes are the whole reason a tree cannot be forged. Without them a
// leaf hash and an interior node hash are computed over the same bytes, so a
// leaf can be presented as an interior node and an attacker can construct a
// proof for a record that was never logged. Any implementation of this pattern
// lacking the prefixes is broken rather than a variant.
const (
	leafPrefix = 0x00
	nodePrefix = 0x01
)

// Digest renders a SHA-256 over bytes in the form the format uses everywhere.
func Digest(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// LeafHash is computed over the ASCII digest string, not over the raw hash
// bytes it encodes. That is a format decision rather than an accident: the
// digest string is what travels in the envelope, so it is what gets committed.
func LeafHash(recordDigest string) []byte {
	h := sha256.New()
	h.Write([]byte{leafPrefix})
	h.Write([]byte(recordDigest))
	return h.Sum(nil)
}

func NodeHash(left, right []byte) []byte {
	h := sha256.New()
	h.Write([]byte{nodePrefix})
	h.Write(left)
	h.Write(right)
	return h.Sum(nil)
}

// splitPoint is 2^ceil(log2(n) - 1), computed in integers.
//
// That expression is the largest power of two strictly less than n. Doing it in
// floating point works until it does not: log2 of a large power of two can land
// a hair under the integer and ceil then returns the wrong bucket, which splits
// the tree in the wrong place and produces a root that disagrees with every
// other implementation for one specific size.
func splitPoint(n int) int {
	k := 1
	for k<<1 < n {
		k <<= 1
	}
	return k
}

// Root computes the tree root over an ordered list of record digests.
func Root(recordDigests []string) string {
	leaves := make([][]byte, len(recordDigests))
	for i, d := range recordDigests {
		leaves[i] = LeafHash(d)
	}
	return "sha256:" + hex.EncodeToString(rootOf(leaves))
}

func rootOf(leaves [][]byte) []byte {
	if len(leaves) == 0 {
		// The empty tree is SHA-256 of the empty string, not a zero hash.
		sum := sha256.Sum256(nil)
		return sum[:]
	}
	if len(leaves) == 1 {
		return leaves[0]
	}
	s := splitPoint(len(leaves))
	return NodeHash(rootOf(leaves[:s]), rootOf(leaves[s:]))
}

// InclusionStep is one sibling on the path from a leaf to the root. Side names
// the position of the sibling, not of the node being computed.
type InclusionStep struct {
	Side string `json:"side"`
	Hash string `json:"hash"`
}

type InclusionProof struct {
	Index int             `json:"index"`
	Size  int             `json:"size"`
	Path  []InclusionStep `json:"path"`
}

// VerifyInclusion recomputes the root from a leaf and its path.
//
// Note that the record digest is an input rather than something read out of the
// proof. A verifier that checks only that the path is internally consistent will
// accept a valid proof presented with a different record, which is failure case
// eight in the specification.
func VerifyInclusion(recordDigest string, p InclusionProof, expectedRoot string) (bool, error) {
	acc := LeafHash(recordDigest)
	for i, step := range p.Path {
		sib, err := hex.DecodeString(step.Hash)
		if err != nil {
			return false, fmt.Errorf("path step %d is not hex: %w", i, err)
		}
		switch step.Side {
		case "right":
			acc = NodeHash(acc, sib)
		case "left":
			acc = NodeHash(sib, acc)
		default:
			return false, fmt.Errorf("path step %d has side %q, expected left or right", i, step.Side)
		}
	}
	return strings.EqualFold("sha256:"+hex.EncodeToString(acc), expectedRoot), nil
}
