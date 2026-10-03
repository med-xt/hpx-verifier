# Proof Record Format, `hpx/1`

Version 1. Frozen: two independent implementations agree on the published
conformance vectors.

This document is the normative wire format. It is Part V of *A Doctrine of
Verifiable Evidence for United States Healthcare Payment*, https://doi.org/10.5281/zenodo.23107483, which
carries the reasoning behind every requirement here. Where this file and that
document differ, that document governs.

This is the wire format. Two systems that have never communicated must produce
byte-identical output for identical facts, or signatures will not verify across an
organizational boundary. Everything below exists to make that true.

---

## 1. Envelope

```json
{
  "digest": "sha256:<hex>",
  "payload": { },
  "signature": {
    "alg": "ML-DSA-65",
    "keyId": "k-snf-001",
    "version": 1,
    "value": "<base64>"
  }
}
```

`digest` is SHA-256 over the canonical encoding of `payload`, prefixed `sha256:`
and lower-case hex. It lives in the envelope rather than the payload so the
payload never has to contain a hash of itself.

`signature.value` is over the same canonical bytes, not over the digest string.

## 2. Payload

```json
{
  "spec": "hpx/1",
  "type": "consent.proof",
  "episode": "ep_2026_0918_7741",
  "seq": 1,
  "prev": "sha256:<hex>",
  "subject": { "scheme": "mbi-pseudonym", "id": "p_9f2c41a8" },
  "actor":   { "scheme": "npi", "id": "1932847561" },
  "assertion": { },
  "evidence": [
    { "alg": "sha256", "digest": "sha256:<hex>", "descriptor": "consent form" }
  ],
  "time": "2026-09-11T18:05:00.000Z",
  "key": { "id": "k-snf-001", "version": 1, "alg": "ML-DSA-65" }
}
```

| Field | Rule |
|---|---|
| `spec` | Always `hpx/1` for this version. A verifier rejects a spec it does not implement rather than guessing. |
| `type` | One of the six record types in section 3. |
| `episode` | Opaque episode identifier. Carries no meaning and must not encode identity. |
| `seq` | Zero-based position in the chain. Must equal the record's index. |
| `prev` | The `digest` of the preceding record, or `null` at `seq` 0. Any other combination is invalid. |
| `subject` | Who or what the record concerns. |
| `actor` | Who made the assertion. |
| `assertion` | One fact and nothing wider. |
| `evidence` | Fingerprints of source documents. Never the documents. May be empty. |
| `time` | RFC 3339, UTC, always with milliseconds and a `Z` suffix. |
| `key` | Must match `signature.keyId`, `signature.version` and `signature.alg`. |

## 3. Record types

| Type | Asserts |
|---|---|
| `discharge.proof` | A qualifying inpatient stay completed, bound to beneficiary and discharging facility. |
| `consent.proof` | Identity was verified and consent was granted, as an event rather than a setting. |
| `order.proof` | A certifying clinician, eligible on the date of service, signed the order. |
| `encounter.proof` | Services were performed, bound to the actors who performed them. |
| `claim.proof` | A claim was submitted and references the chain beneath it. |
| `payment.receipt` | A payment determination bound to the evidence root that authorized it. |

## 4. Canonical encoding

RFC 8785 in substance. The rules a second implementation must follow exactly:

- Object keys sorted ascending by UTF-16 code unit, not by locale or by Unicode collation.
- Keys whose value is `undefined` are omitted. `null` is a value and is retained.
- No insignificant whitespace anywhere.
- Strings escaped per JSON, with the shortest valid escape.
- Numbers serialized in shortest round-trip form. Non-finite numbers are an error, not a null.
- Arrays keep their order. Order is meaning.

Reference: `packages/core/src/canonical.js`.

## 5. Identity

`scheme` is one of:

| Scheme | Meaning |
|---|---|
| `npi` | National Provider Identifier, validated against enrollment status on the date of service. |
| `mbi-pseudonym` | A keyed pseudonym derived from the beneficiary identifier, per program. |

**A raw MBI must never appear in a record.** The pseudonym is derived with a
program-scoped key so that a copy of the proof store cannot be turned into a
beneficiary index by whoever obtains it. This is a requirement of the format, not
a deployment preference.

## 6. Evidence fingerprints

```json
{ "alg": "sha256", "digest": "sha256:<hex>", "descriptor": "plan of care" }
```

`descriptor` is a short human label for what was fingerprinted. It must not
contain a path, a URL, a record locator, or anything that identifies a person.
It exists so a reviewer knows what to ask the custodian for.

## 7. Merkle log

RFC 6962 structure.

- Leaf hash: `SHA-256(0x00 || record.digest)` over the ASCII digest string.
- Interior node: `SHA-256(0x01 || left || right)`.
- Split point for a list of `n` leaves is the largest power of two strictly less
  than `n`. This is `2^ceil(log2(n) - 1)`, and it must be computed in integers.
  Evaluated in floating point, `log2` can land a fraction either side of the
  true value, `ceil` turns that fraction into a whole power of two, and the tree
  splits in the wrong place for one specific size. The resulting root disagrees
  with every other implementation and the failure looks like tampering.
- Empty tree: `SHA-256` of the empty string.

The domain separation prefixes are not optional. Without them a leaf can be
presented as an interior node and the tree can be forged.

An inclusion proof is `{ index, size, path: [{ side, hash }] }` ordered from the
leaf upward, where `side` names the position of the sibling.

Reference: `packages/core/src/merkle.js`. Tested across every index in trees of
size 1 to 64.

### 7.1 Consistency proofs

An inclusion proof establishes that a record is in a tree. It says nothing about
whether the tree is the same one that was published before. A consistency proof
does: it establishes that the tree of `newSize` leaves contains the tree of
`oldSize` leaves as an unchanged prefix.

RFC 6962 section 2.1.2, with no deviation. A proof is an ordered list of
hex-encoded hashes, and the following rules are the ones an implementation gets
wrong.

- When `oldSize` is a power of two, the earlier root is itself a node of the new
  tree, so it is omitted from the proof and the verifier supplies it. An
  implementation that misses this fails every power of two case and passes all
  the others.
- `oldSize == newSize` requires an empty proof and identical roots. Two
  different roots at one size is the clearest possible evidence of two
  histories and no proof can reconcile them.
- `oldSize == 0` requires an empty proof. Everything is consistent with an empty
  tree.
- `oldSize > newSize` is refused outright. A log cannot shrink.

A verifier must report *why* a proof failed, and must distinguish a malformed
proof from two roots that describe different trees. The first is a bug. The
second is an incident.

Vectors: `conformance/consistency.json`. Reference: `packages/core/src/merkle.js`
and the independent implementation in `consistency.go`.

## 7.2 Checkpoints

A checkpoint is a signed statement that at one moment the log held exactly this
many records and its root was this.

It exists because every signature elsewhere in this format protects a record
against anyone who does not hold a signing key, and none of them protect against
the operator of the log. An operator can rebuild the log without a record and
every remaining signature still verifies. A checkpoint held by somebody else is
what makes that rewrite detectable.

The format is newline-delimited text, not canonical JSON. A checkpoint carries
five values, and text has no key ordering, number formatting or escaping to
disagree about. It also survives being pasted into an email, a ticket or a
commit message, and a person can read it without a tool.

```
hpx/checkpoint/1
<origin>
<size>
<root>
<time>

sig <keyId> <version> <alg> <base64>
sig <keyId> <version> <alg> <base64>
```

- The body is the five lines, each terminated by `\n`. A blank line ends the
  body. Signatures follow, one per line, and the block ends with exactly one
  `\n`.
- **Signatures cover the body bytes exactly**, including the body's trailing
  newline and excluding the blank line. This is what lets a checkpoint gain
  co-signatures without any existing signature being recomputed, and that
  property is what makes witnessing possible at all.
- `origin` names one log and is inside the signed bytes, so a signature over one
  log's checkpoint cannot be replayed as another log's. It matches
  `[a-z0-9][a-z0-9._-]{2,63}` with optional `/`-separated segments.
- `size` is a plain decimal integer with no sign and no leading zeros. One size
  must have exactly one spelling or it is two different signed statements.
- `root` is `sha256:` followed by 64 lowercase hex characters.
- `time` is an instant with milliseconds in UTC, `YYYY-MM-DDTHH:MM:SS.sssZ`, and
  must be a real instant. `2026-02-30T00:00:00.000Z` matches the pattern and is
  not a date.

A parser must refuse, rather than normalise: carriage returns anywhere, a blank
line inside the signature block, a signature block that does not end with a
newline, a duplicate `keyId` and `version` pair, and any unknown `spec`. Two
different byte sequences must never parse to the same checkpoint: a checkpoint
is the one object here whose stored bytes have to be the bytes that were
verified.

A verifier reports *which* keys validly signed rather than a single boolean.
Whether that set is sufficient is a quorum rule belonging to whoever relies on
the checkpoint. The log's own signature is necessary and never sufficient.

Vectors: `conformance/checkpoint.json` for bodies and refusals,
`conformance/checkpoint-signed.json` for signatures. Reference:
`packages/core/src/checkpoint.js` and `checkpoint.go`.

## 7.3 Witnessing

A witness holds one line per log, the size and root it last endorsed, and will
co-sign a new checkpoint only after being shown a consistency proof from that
size to the new one.

- A witness that has not seen a log before cannot validate its history. It may
  co-sign what it observes and must say that it makes no statement about
  anything earlier. A first sighting is not evidence of continuity and must not
  count toward a quorum.
- Growth with no consistency proof is refused. Accepting it on trust is the
  difference between a witness and a rubber stamp.
- A checkpoint the log did not validly sign is refused before anything else is
  considered, or a witness becomes a laundering service for whatever an attacker
  wants published.
- A witness advances its recorded state only after everything has passed. A
  witness that advanced on a refused checkpoint would accept the rewrite on the
  next attempt.
- A refusal is a signal, not an error to retry. It is the single most important
  thing this design can produce.

One witness operated by the log's operator provides nothing. The value is
entirely in independence, which is an organisational property and not something
any amount of code establishes.

Reference: `packages/core/src/witness.js`.

## 8. Keys

- Key identifier and version are inside the signed payload. A signature that does not
  name its own key cannot be checked after rotation.
- Retired keys are retained permanently. Deleting a public key destroys the
  ability to verify everything it ever signed.
- A retired key verifies records whose `time` precedes its `notAfter`, and is
  rejected for records claiming a later time.
- One key per signing organization. **No party ever signs on behalf of another.**
  The moment one organization can sign for another, the evidence stops meaning
  anything, and no convenience justifies it.

## 9. Verification

A verifier is conformant if, given only envelopes, a public key registry and
optionally a log root with inclusion proofs, it checks all of:

1. `spec` is implemented.
2. `digest` equals SHA-256 over the canonical payload.
3. `signature.alg`, `keyId` and `version` match `payload.key`.
4. The signing key resolves in the registry.
5. A retired key was in service at `payload.time`.
6. The signature verifies over the canonical bytes.
7. `seq` equals the record's index.
8. `prev` equals the preceding record's `digest`, or is `null` at index 0.
9. Each record's inclusion proof resolves to the published root, when a log is supplied.
10. When a checkpoint is supplied, it parses under the rules in 7.2, its
    signatures verify, and its `root` is the same root the inclusion proofs are
    built on. A checkpoint over a different root is not evidence about these
    records, and accepting it as though it were is worse than carrying none.

Checkpoint verification is reported separately from the overall result. A bundle
with no checkpoint is still a valid bundle: the records are genuine and the
log's own history is simply not independently established.

It must do all of this with no network access and no dependency on any service.

Reference: `packages/core/src/verify.js`.

## 10. Errors that must be caught

A conformant verifier detects, and names, at minimum:

- Any field altered in any record.
- Two records transposed.
- A record removed from the middle of a chain.
- A record inserted into a chain.
- A record signed by a key not in the registry.
- A record signed by a key retired before the claimed time.
- A leaf presented as an interior node in an inclusion proof.
- A forged digest presented with a valid proof for a different record.
- A log that reports fewer records than a checkpoint it has already signed.
- Two checkpoints at one size carrying different roots.
- A consistency proof that does not reconstruct the earlier signed root, which
  is what a rebuilt log produces.
- A checkpoint whose root is not the root the inclusion proofs are built on.

## 11. Changing this document

Canonicalization, the Merkle construction, the envelope shape and the checkpoint
body format are frozen once a second implementation exists. Changing any of them
invalidates every signature ever made under `hpx/1`, and changing the checkpoint
body invalidates every checkpoint anybody else is holding, which is worse: those
are the copies the operator cannot reissue.

Changes are new spec versions carried in the `spec` field. Records are never
migrated. A store holds `hpx/1` and `hpx/2` records side by side and verifiers
implement both.
