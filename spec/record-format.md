# Proof Record Format, `hpx/1`

Version 1. Draft. Frozen once a second implementation exists.

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
- Split point for a list of `n` leaves is `2^ceil(log2(n) - 1)`.
- Empty tree: `SHA-256` of the empty string.

The domain separation prefixes are not optional. Without them a leaf can be
presented as an interior node and the tree can be forged.

An inclusion proof is `{ index, size, path: [{ side, hash }] }` ordered from the
leaf upward, where `side` names the position of the sibling.

Reference: `packages/core/src/merkle.js`. Tested across every index in trees of
size 1 to 64.

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

## 11. Changing this document

Canonicalization, the Merkle construction and the envelope shape are frozen once a
second implementation exists. Changing any of them invalidates every signature
ever made under `hpx/1`.

Changes are new spec versions carried in the `spec` field. Records are never
migrated. A store holds `hpx/1` and `hpx/2` records side by side and verifiers
implement both.
