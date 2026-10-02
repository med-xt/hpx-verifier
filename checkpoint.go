package verify

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// The signed checkpoint.
//
// A short, signed statement that at one moment the log held exactly this many
// records and its root was this. Handed to parties who keep their own copy, it
// is what stops the operator changing the past quietly.
//
// The format is newline-delimited text rather than canonical JSON, and from the
// position of a second implementation that choice is the whole point.
// Canonicalising JSON identically across two languages took a conformance suite
// and a reimplementation of ECMAScript number formatting. A checkpoint has five
// values and parsing it needs none of that: no key ordering, no number
// formatting, no escaping. This file is shorter than canonical.go by an order of
// magnitude and that is the evidence for the decision.

const CheckpointSpec = "hpx/checkpoint/1"

var (
	originPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._\-]{2,63}(/[a-z0-9][a-z0-9._\-]{0,63})*$`)
	rootPattern   = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	timePattern   = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$`)
	keyIDPattern  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9\-]{1,63}$`)
	algPattern    = regexp.MustCompile(`^[A-Za-z0-9\-]{1,32}$`)
	b64Pattern    = regexp.MustCompile(`^[A-Za-z0-9+/]+={0,2}$`)
	integer       = regexp.MustCompile(`^(0|[1-9][0-9]*)$`)
)

type CheckpointSignature struct {
	KeyID   string
	Version int
	Alg     string
	Value   string
}

type Checkpoint struct {
	Origin string
	Size   int
	Root   string
	Time   string

	// Body is the exact bytes the signatures cover, including the trailing
	// newline. Kept verbatim rather than rebuilt from the fields above: if a
	// verifier reconstructed the body and its formatting differed by one byte,
	// every signature would fail for a reason that looks like tampering.
	Body       string
	Signatures []CheckpointSignature
}

// ParseCheckpoint is strict on purpose. A checkpoint is the one object here
// expected to be stored by people who do not run the log, moved between
// systems, and read years later. Anything it accepts, it accepts forever.
func ParseCheckpoint(document string) (*Checkpoint, error) {
	// Carriage returns are refused rather than stripped. Stripping them means
	// the bytes verified are not the bytes stored.
	if strings.Contains(document, "\r") {
		return nil, fmt.Errorf("a checkpoint contains no carriage returns")
	}
	parts := strings.Split(document, "\n\n")
	if len(parts) != 2 {
		return nil, fmt.Errorf("a checkpoint is a body, a blank line, then signatures")
	}
	lines := strings.Split(parts[0], "\n")
	if len(lines) != 5 {
		return nil, fmt.Errorf("a body has five lines, this has %d", len(lines))
	}
	if lines[0] != CheckpointSpec {
		return nil, fmt.Errorf("unknown checkpoint spec %q", lines[0])
	}
	if !originPattern.MatchString(lines[1]) {
		return nil, fmt.Errorf("origin %q is not a log name", lines[1])
	}
	// One size must have exactly one spelling, or it is two different signed
	// statements.
	if !integer.MatchString(lines[2]) {
		return nil, fmt.Errorf("size %q is not a plain integer", lines[2])
	}
	size, err := strconv.Atoi(lines[2])
	if err != nil {
		return nil, fmt.Errorf("size %q is not a count of records", lines[2])
	}
	if !rootPattern.MatchString(lines[3]) {
		return nil, fmt.Errorf("root %q is not a sha256 root", lines[3])
	}
	if !timePattern.MatchString(lines[4]) {
		return nil, fmt.Errorf("time %q is not an instant with milliseconds in UTC", lines[4])
	}
	// A value that matches the pattern and is not a date, such as 2026-02-30,
	// has to be caught here or it becomes a signed statement about a day that
	// never happened.
	parsed, err := time.Parse("2006-01-02T15:04:05.000Z", lines[4])
	if err != nil || parsed.UTC().Format("2006-01-02T15:04:05.000Z") != lines[4] {
		return nil, fmt.Errorf("time %q is not a real instant", lines[4])
	}

	cp := &Checkpoint{
		Origin: lines[1], Size: size, Root: lines[3], Time: lines[4],
		Body: parts[0] + "\n",
	}

	// The signature block ends with exactly one newline and contains no blank
	// lines. Tolerating a stray blank line would mean two different byte
	// sequences parse to the same checkpoint, and a checkpoint is specifically
	// an object whose stored bytes have to be the bytes that were verified.
	if !strings.HasSuffix(parts[1], "\n") {
		return nil, fmt.Errorf("the signature block must end with a newline")
	}
	for _, line := range strings.Split(strings.TrimSuffix(parts[1], "\n"), "\n") {
		if line == "" {
			return nil, fmt.Errorf("the signature block contains a blank line")
		}
		fields := strings.Split(line, " ")
		if len(fields) != 5 || fields[0] != "sig" {
			return nil, fmt.Errorf("unreadable signature line %q", line)
		}
		if !keyIDPattern.MatchString(fields[1]) {
			return nil, fmt.Errorf("key id %q is not usable", fields[1])
		}
		if !integer.MatchString(fields[2]) {
			return nil, fmt.Errorf("key version %q is not an integer", fields[2])
		}
		version, _ := strconv.Atoi(fields[2])
		if !algPattern.MatchString(fields[3]) {
			return nil, fmt.Errorf("algorithm %q is not usable", fields[3])
		}
		if !b64Pattern.MatchString(fields[4]) {
			return nil, fmt.Errorf("a signature value is not base64")
		}
		// Two signatures from one key is either a bug or an attempt to make a
		// quorum count look larger than it is.
		for _, existing := range cp.Signatures {
			if existing.KeyID == fields[1] && existing.Version == version {
				return nil, fmt.Errorf("%s#%d appears twice", fields[1], version)
			}
		}
		cp.Signatures = append(cp.Signatures, CheckpointSignature{KeyID: fields[1], Version: version, Alg: fields[3], Value: fields[4]})
	}
	if len(cp.Signatures) == 0 {
		return nil, fmt.Errorf("a checkpoint carries at least one signature")
	}
	return cp, nil
}

type CheckpointSigner struct {
	KeyID   string
	Version int
	Owner   string
}

type CheckpointResult struct {
	OK         bool
	Problems   []string
	SignedBy   []CheckpointSigner
	Checkpoint *Checkpoint
}

// VerifyCheckpoint reports which keys validly signed rather than a single
// boolean. Whether that set is enough is a quorum rule belonging to whoever
// relies on the checkpoint, not to this function.
func VerifyCheckpoint(document string, reg *Registry, sv SignatureVerifier) CheckpointResult {
	cp, err := ParseCheckpoint(document)
	if err != nil {
		return CheckpointResult{OK: false, Problems: []string{err.Error()}}
	}
	res := CheckpointResult{Checkpoint: cp}
	if sv == nil {
		res.Problems = append(res.Problems, "no signature verifier was supplied")
		return res
	}
	for _, s := range cp.Signatures {
		k := reg.Resolve(s.KeyID, s.Version)
		if k == nil {
			res.Problems = append(res.Problems, fmt.Sprintf("%s#%d is not in the registry", s.KeyID, s.Version))
			continue
		}
		valid, err := sv.Verify(s.Alg, s.Value, []byte(cp.Body), k.PublicKey)
		if err != nil {
			res.Problems = append(res.Problems, fmt.Sprintf("%s#%d: %v", s.KeyID, s.Version, err))
			continue
		}
		if !valid {
			res.Problems = append(res.Problems, fmt.Sprintf("signature from %s#%d does not verify", s.KeyID, s.Version))
			continue
		}
		// A retired key still verifies what it signed while in service, and a
		// checkpoint carries the time it was made, so this is checkable.
		if k.Status == "retired" && k.NotAfter != "" && cp.Time > k.NotAfter {
			res.Problems = append(res.Problems, fmt.Sprintf("%s#%d was retired at %s but signed a checkpoint at %s", s.KeyID, s.Version, k.NotAfter, cp.Time))
			continue
		}
		res.SignedBy = append(res.SignedBy, CheckpointSigner{KeyID: s.KeyID, Version: s.Version, Owner: k.Owner})
	}
	res.OK = len(res.SignedBy) > 0
	return res
}

// MeetsQuorum applies a relying party's own threshold.
//
// A checkpoint signed only by the log proves nothing against the log, so the
// log's signature is necessary and never sufficient. Independent signatures are
// counted as those from any key other than the log's.
func MeetsQuorum(res CheckpointResult, logKeyID string, witnesses int) (bool, string) {
	if !res.OK {
		return false, "the checkpoint is not validly signed"
	}
	foundLog := false
	cosigners := 0
	for _, s := range res.SignedBy {
		if s.KeyID == logKeyID {
			foundLog = true
		} else {
			cosigners++
		}
	}
	if !foundLog {
		return false, fmt.Sprintf("the log key %s did not sign this checkpoint", logKeyID)
	}
	if cosigners < witnesses {
		return false, fmt.Sprintf("%d independent signatures, %d required", cosigners, witnesses)
	}
	return true, ""
}
