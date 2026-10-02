package verify

import (
	"encoding/json"
	"fmt"
)

// Problem is a named failure. A verifier that returns only a boolean is not
// useful to a reviewer: the question is never just whether the chain is valid,
// it is which record failed and why.
type Problem struct {
	Record int    `json:"record"`
	Type   string `json:"type"`
	Code   string `json:"code"`
	Detail string `json:"detail"`
}

func (p Problem) String() string {
	if p.Record < 0 {
		return fmt.Sprintf("%s: %s", p.Code, p.Detail)
	}
	return fmt.Sprintf("record %d (%s): %s: %s", p.Record, p.Type, p.Code, p.Detail)
}

type Result struct {
	OK       bool      `json:"ok"`
	Records  int       `json:"records"`
	Problems []Problem `json:"problems"`
}

// Stable codes. Downstream systems match on these, so they are part of the
// interface rather than log text.
const (
	CodeSpecUnknown     = "SPEC_UNKNOWN"
	CodeTypeUnknown     = "TYPE_UNKNOWN"
	CodeDigestMismatch  = "DIGEST_MISMATCH"
	CodeKeyMismatch     = "KEY_MISMATCH"
	CodeKeyUnknown      = "KEY_UNKNOWN"
	CodeKeyExpired      = "KEY_EXPIRED"
	CodeSigInvalid      = "SIG_INVALID"
	CodeSeqMismatch     = "SEQ_MISMATCH"
	CodePrevMismatch    = "PREV_MISMATCH"
	CodePrevUnexpected  = "PREV_UNEXPECTED"
	CodeInclusionFailed = "INCLUSION_FAILED"
	CodePHIDetected     = "PHI_DETECTED"

	// Checkpoint level. These are about the log's own history rather than about
	// any record, which is why they carry no record position.
	CodeCheckpointInvalid  = "CHECKPOINT_INVALID"
	CodeCheckpointMismatch = "CHECKPOINT_ROOT_MISMATCH"
	CodeLogInconsistent    = "LOG_INCONSISTENT"
)

// VerifyRecord checks everything about one envelope that does not depend on its
// neighbours. Signature checking is delegated, so this package compiles and
// runs the structural checks without a post-quantum library present.
func VerifyRecord(e *Envelope, reg *Registry, sig SignatureVerifier) []Problem {
	var out []Problem
	add := func(code, detail string) {
		out = append(out, Problem{Record: -1, Code: code, Detail: detail})
	}

	p, err := e.ParsePayload()
	if err != nil {
		add(CodeDigestMismatch, err.Error())
		return out
	}
	if p.Spec != SupportedSpec {
		add(CodeSpecUnknown, fmt.Sprintf("spec is %q, this verifier implements %q", p.Spec, SupportedSpec))
		return out
	}
	if !RecordTypes[p.Type] {
		add(CodeTypeUnknown, fmt.Sprintf("record type %q is not in the frozen set", p.Type))
	}

	bytes, err := e.CanonicalBytes()
	if err != nil {
		add(CodeDigestMismatch, err.Error())
		return out
	}
	if got := Digest(bytes); got != e.Digest {
		add(CodeDigestMismatch, fmt.Sprintf("envelope says %s, payload hashes to %s", e.Digest, got))
	}

	// The envelope's key reference is outside the signed bytes. The payload's is
	// inside them. Checking they agree is what stops an attacker swapping the
	// envelope reference to point at a key that happens to verify.
	if p.Key.ID != e.Signature.KeyID || p.Key.Version != e.Signature.Version || p.Key.Alg != e.Signature.Alg {
		add(CodeKeyMismatch, fmt.Sprintf("payload names %s#%d/%s, envelope names %s#%d/%s",
			p.Key.ID, p.Key.Version, p.Key.Alg, e.Signature.KeyID, e.Signature.Version, e.Signature.Alg))
		return out
	}

	key := reg.Resolve(e.Signature.KeyID, e.Signature.Version)
	if key == nil {
		add(CodeKeyUnknown, fmt.Sprintf("signing key %s#%d is not in the registry", e.Signature.KeyID, e.Signature.Version))
		return out
	}
	// A retired key still verifies what it signed while it was in service, and
	// must be refused for anything claiming a later time. That is what contains
	// a key stolen after retirement.
	if key.Status == "retired" && key.NotAfter != "" && p.Time > key.NotAfter {
		add(CodeKeyExpired, fmt.Sprintf("key retired at %s but the record claims %s", key.NotAfter, p.Time))
	}

	if sig == nil {
		// Structural verification only. Saying so is better than returning a
		// verdict that reads like a pass.
		return out
	}
	ok, err := sig.Verify(e.Signature.Alg, e.Signature.Value, bytes, key.PublicKey)
	if err != nil {
		add(CodeSigInvalid, err.Error())
	} else if !ok {
		add(CodeSigInvalid, "signature does not verify over the canonical payload")
	}
	return out
}

// VerifyChain adds the checks that only make sense across a sequence.
func VerifyChain(records []*Envelope, reg *Registry, sig SignatureVerifier) Result {
	res := Result{Records: len(records)}
	for i, e := range records {
		p, err := e.ParsePayload()
		typ := ""
		if err == nil {
			typ = p.Type
		}
		for _, pr := range VerifyRecord(e, reg, sig) {
			pr.Record = i
			pr.Type = typ
			res.Problems = append(res.Problems, pr)
		}
		if err != nil {
			continue
		}

		if p.Seq != i {
			res.Problems = append(res.Problems, Problem{i, typ, CodeSeqMismatch,
				fmt.Sprintf("sequence says %d, position is %d", p.Seq, i)})
		}
		if i == 0 {
			if p.Prev != nil {
				res.Problems = append(res.Problems, Problem{i, typ, CodePrevUnexpected,
					"the first record must not link to a predecessor"})
			}
			continue
		}
		switch {
		case p.Prev == nil:
			res.Problems = append(res.Problems, Problem{i, typ, CodePrevUnexpected,
				"a record after the first must link to its predecessor"})
		case *p.Prev != records[i-1].Digest:
			res.Problems = append(res.Problems, Problem{i, typ, CodePrevMismatch,
				fmt.Sprintf("links to %s, predecessor is %s", *p.Prev, records[i-1].Digest)})
		}
	}
	res.OK = len(res.Problems) == 0
	return res
}

// Bundle is what a reviewer is handed: records, the keys needed to check them,
// and optionally the log root with inclusion proofs. Nothing else, and no
// network.
type Bundle struct {
	Episode         string           `json:"episode"`
	Records         []*Envelope      `json:"records"`
	LogRoot         string           `json:"logRoot"`
	InclusionProofs []InclusionProof `json:"inclusionProofs"`

	// Optional. A signed statement that the root above was published, which is
	// the difference between a bundle whose root the reviewer has to take the
	// operator's word for and one they do not.
	Checkpoint string `json:"checkpoint"`

	// Optional, and the reason a bundle can be described as sufficient on its
	// own. A bundle exported for an audit carries the public keys needed to
	// check it, so a reviewer handed one file is not then asked for a second
	// one they were never given.
	Keys json.RawMessage `json:"keys"`
}

// CheckpointOutcome is reported alongside the result rather than folded into
// it, because a bundle with no checkpoint is still a valid bundle. The records
// are genuine; the log's own history is simply not independently established,
// and collapsing those two states into one boolean loses the distinction that
// matters most.
type CheckpointOutcome struct {
	Present        bool               `json:"present"`
	Verified       bool               `json:"verified"`
	MatchesLogRoot bool               `json:"matchesLogRoot"`
	Origin         string             `json:"origin,omitempty"`
	Size           int                `json:"size,omitempty"`
	Time           string             `json:"time,omitempty"`
	SignedBy       []CheckpointSigner `json:"signedBy,omitempty"`
	Problems       []string           `json:"problems,omitempty"`
}

func VerifyBundle(b *Bundle, reg *Registry, sig SignatureVerifier) Result {
	res := VerifyChain(b.Records, reg, sig)

	if b.LogRoot != "" {
		for i, e := range b.Records {
			if i >= len(b.InclusionProofs) {
				res.Problems = append(res.Problems, Problem{i, "", CodeInclusionFailed, "no inclusion proof supplied"})
				continue
			}
			ok, err := VerifyInclusion(e.Digest, b.InclusionProofs[i], b.LogRoot)
			if err != nil {
				res.Problems = append(res.Problems, Problem{i, "", CodeInclusionFailed, err.Error()})
			} else if !ok {
				res.Problems = append(res.Problems, Problem{i, "", CodeInclusionFailed,
					"record is not included under the published log root"})
			}
		}
	}
	res.OK = len(res.Problems) == 0
	return res
}

// VerifyBundleCheckpoint checks the checkpoint a bundle carries, if any.
//
// Kept as a second call rather than folded into VerifyBundle so the existing
// signature does not change and so the outcome can be reported separately. The
// one failure it adds is a checkpoint over a different root: that is not
// evidence about these records, and letting it pass as though it were is worse
// than carrying no checkpoint at all.
func VerifyBundleCheckpoint(b *Bundle, reg *Registry, sig SignatureVerifier) (CheckpointOutcome, []Problem) {
	if b.Checkpoint == "" {
		return CheckpointOutcome{}, nil
	}
	var problems []Problem
	res := VerifyCheckpoint(b.Checkpoint, reg, sig)
	out := CheckpointOutcome{Present: true, Problems: res.Problems, SignedBy: res.SignedBy}
	if res.Checkpoint != nil {
		out.Origin = res.Checkpoint.Origin
		out.Size = res.Checkpoint.Size
		out.Time = res.Checkpoint.Time
		out.MatchesLogRoot = res.Checkpoint.Root == b.LogRoot
		if !out.MatchesLogRoot {
			problems = append(problems, Problem{-1, "", CodeCheckpointMismatch,
				fmt.Sprintf("checkpoint is for root %s but the inclusion proofs are built on %s", res.Checkpoint.Root, b.LogRoot)})
		}
	}
	for _, p := range res.Problems {
		problems = append(problems, Problem{-1, "", CodeCheckpointInvalid, p})
	}
	out.Verified = res.OK && out.MatchesLogRoot && len(res.Problems) == 0
	return out, problems
}
