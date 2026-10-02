package verify

import (
	"encoding/json"
	"fmt"
)

// Envelope is the wire shape. The payload is kept as raw bytes because the
// digest and the signature are computed over a canonical encoding of it, and
// round-tripping through a typed struct would silently normalise things the
// format is deliberately strict about.
type Envelope struct {
	Digest    string          `json:"digest"`
	Payload   json.RawMessage `json:"payload"`
	Signature Signature       `json:"signature"`
}

type Signature struct {
	Alg     string `json:"alg"`
	KeyID   string `json:"keyId"`
	Version int    `json:"version"`
	Value   string `json:"value"`
}

// Payload is the subset of fields verification reasons about. Everything else
// in the payload still contributes to the digest; this struct is for the checks
// that need named fields, not a definition of what a payload may contain.
type Payload struct {
	Spec      string          `json:"spec"`
	Type      string          `json:"type"`
	Episode   string          `json:"episode"`
	Seq       int             `json:"seq"`
	Prev      *string         `json:"prev"`
	Subject   Party           `json:"subject"`
	Actor     *Party          `json:"actor"`
	Assertion json.RawMessage `json:"assertion"`
	Evidence  []Fingerprint   `json:"evidence"`
	Time      string          `json:"time"`
	Key       KeyRef          `json:"key"`
}

type Party struct {
	Scheme string `json:"scheme"`
	ID     string `json:"id"`
}

type Fingerprint struct {
	Alg        string `json:"alg"`
	Digest     string `json:"digest"`
	Descriptor string `json:"descriptor"`
}

type KeyRef struct {
	ID      string `json:"id"`
	Version int    `json:"version"`
	Alg     string `json:"alg"`
}

// SupportedSpec is the only version this verifier implements. An unknown version
// is rejected outright rather than parsed on a best effort, because a verifier
// that guesses at a format it does not know will eventually return a confident
// verdict about something it did not understand.
const SupportedSpec = "hpx/1"

// RecordTypes is the frozen set. A seventh type is a new spec version.
var RecordTypes = map[string]bool{
	"discharge.proof": true,
	"consent.proof":   true,
	"order.proof":     true,
	"encounter.proof": true,
	"claim.proof":     true,
	"payment.receipt": true,
}

func (e *Envelope) ParsePayload() (*Payload, error) {
	var p Payload
	if err := json.Unmarshal(e.Payload, &p); err != nil {
		return nil, fmt.Errorf("payload is not readable: %w", err)
	}
	return &p, nil
}

// CanonicalBytes renders the payload in canonical form. This is what the digest
// is over and what the signature is over. Both, over the same bytes.
func (e *Envelope) CanonicalBytes() ([]byte, error) {
	v, err := Decode(e.Payload)
	if err != nil {
		return nil, fmt.Errorf("payload is not valid JSON: %w", err)
	}
	s, err := Canonicalize(v)
	if err != nil {
		return nil, err
	}
	return []byte(s), nil
}
