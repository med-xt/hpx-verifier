// Package mldsa supplies ML-DSA-65 signature verification to the verifier.
//
// It is a separate package on purpose. The verify package itself imports
// nothing outside the standard library, so every structural check, digests, the
// chain walk, the Merkle path, key resolution and retirement windows, runs with
// no dependency at all. That is what lets an auditor run those checks on a
// locked down machine, and it is what makes the cryptographic provider a
// component rather than a dependency of the whole tool.
//
// Swapping to a FIPS 140-3 validated module means replacing this file. Nothing
// else changes, which is the same property the reference implementation has and
// the reason the FIPS answer is a real answer rather than a hope.
package mldsa

import (
	"encoding/base64"
	"fmt"

	"github.com/cloudflare/circl/sign"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

const Alg = "ML-DSA-65"

// Verifier implements verify.SignatureVerifier.
type Verifier struct{}

func New() *Verifier { return &Verifier{} }

// Verify checks a base64 signature over the canonical payload bytes.
//
// It returns false rather than panicking on malformed input. A verification
// path that can panic is one where a recover somewhere up the stack eventually
// gets mistaken for a pass, and a verifier that fails open is worse than no
// verifier at all.
func (v *Verifier) Verify(alg, signatureB64 string, message, publicKey []byte) (bool, error) {
	if alg != Alg {
		return false, fmt.Errorf("unsupported algorithm %q, this verifier implements %s", alg, Alg)
	}
	sig, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil {
		return false, fmt.Errorf("signature is not valid base64: %w", err)
	}

	scheme := mldsa65.Scheme()
	if len(sig) != scheme.SignatureSize() {
		return false, fmt.Errorf("signature is %d bytes, ML-DSA-65 is %d", len(sig), scheme.SignatureSize())
	}
	if len(publicKey) != scheme.PublicKeySize() {
		return false, fmt.Errorf("public key is %d bytes, ML-DSA-65 is %d", len(publicKey), scheme.PublicKeySize())
	}

	pk, err := scheme.UnmarshalBinaryPublicKey(publicKey)
	if err != nil {
		return false, fmt.Errorf("public key will not unmarshal: %w", err)
	}

	// FIPS 204 allows a context string. The reference implementation signs with
	// an empty context, so nil options are correct here. If a future deployment
	// adopts a context it has to be adopted on both sides at once: a context
	// mismatch produces a clean verification failure that looks exactly like
	// tampering, which is the worst possible way to discover a config drift.
	var opts *sign.SignatureOpts
	return scheme.Verify(pk, message, sig, opts), nil
}

// Sizes, exposed so a caller can state them rather than hardcode them.
func SignatureSize() int { return mldsa65.Scheme().SignatureSize() }
func PublicKeySize() int { return mldsa65.Scheme().PublicKeySize() }
