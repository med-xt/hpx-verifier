# hpx-verifier

An independent, offline verifier for `hpx/1` evidence records.

It makes no network call, needs no service, no account and no licence check, and
it does not care whether the organisation that produced the records still
exists. Give it a bundle and a public key registry and it answers.

```
go build -o verify ./cmd/verify
./verify --bundle conformance/bundle-valid.json --keys conformance/keys.json
```

```
VERIFIES  6 records, episode ep_conformance_0001
          chain intact, every record links to its predecessor
          every record included under the published log root
          every signature verifies over the canonical payload
```

Now alter one field and run it again.

```
sed 's/"nights": 3/"nights": 2/' conformance/bundle-valid.json > /tmp/tampered.json
./verify --bundle /tmp/tampered.json --keys conformance/keys.json
```

```
DOES NOT VERIFY  6 records, 2 problems

  record 0 (discharge.proof): DIGEST_MISMATCH: envelope says sha256:39bb303c…, payload hashes to sha256:e5fbea85…
  record 0 (discharge.proof): SIG_INVALID: signature does not verify over the canonical payload
```

---

## Why this exists

A specification that has only ever been implemented once has not been tested, it
has been asserted. A verifier that a reviewer cannot run without trusting the
supplier is not a verifier.

This is a second, independent implementation of the `hpx/1` format, written from
[the specification](spec/record-format.md) rather than from the reference
implementation, sharing no code with it and using a different post-quantum
cryptography library. It is validated against the published conformance vectors
in [`conformance/`](conformance/).

If it disagrees with the reference implementation, one of them is wrong, and
that is the point of publishing it.

## What the data in this repository is

**The bundle in `conformance/` is synthetic.** It contains no real beneficiary,
no real provider, no real encounter and no real claim. The subject identifier is
a pseudonym derived from an invented value, the provider identifiers are not
assigned to anybody, and the episode never happened.

It exists so you can run the verifier, watch it succeed, alter a field, and
watch it fail.

## What it checks

Given only envelopes, a public key registry, and optionally a log root with
inclusion proofs:

1. The record declares a spec version this verifier implements.
2. The envelope digest equals SHA-256 over the canonical encoding of the payload.
3. The algorithm, key identifier and version in the envelope match those inside
   the signed payload.
4. The signing key resolves in the registry.
5. A retired key was in service at the time the record claims.
6. The signature verifies over the canonical bytes.
7. Sequence equals the record's position in the chain.
8. Each record links to the digest of its predecessor, or is the first.
9. Each record's inclusion proof resolves to the published log root.

It does all of this with no network access and no dependency on any service.

## What it detects and names

- Any field altered in any record
- Two records transposed
- A record removed from the middle of a chain
- A record inserted into a chain
- A record signed by a key not in the registry
- A record signed by a key retired before the claimed time
- A leaf presented as an interior node in an inclusion proof
- A forged digest presented with a valid proof for a different record

Each problem names the record by position and the check that failed.

## What a valid chain does not establish

A complete, valid chain establishes that a record is authentic, unaltered,
attributable to a verified actor and correctly sequenced.

**It does not establish that the underlying event occurred.** An actor holding
valid credentials can sign a flawless attestation about something that never
happened. No cryptographic construction closes that, and anyone claiming
otherwise is worth distrusting on everything else as well.

What changes is that the false statement becomes attributable, contemporaneous
and permanent.

## Zero dependencies for the structural checks

The root package imports nothing outside the Go standard library. Digests, the
canonical encoding, the chain walk, the Merkle path, key resolution and
retirement windows all run with no dependency at all.

Only signature verification needs a post-quantum library, and it lives in its
own package. That means two things. An auditor can run the structural checks on
a locked down machine with no package manager. And moving to a FIPS 140-3
validated cryptographic module means replacing one file.

```
./verify --bundle BUNDLE --keys KEYS --structural
```

That mode skips signatures and says so in its output, so a structural pass can
never be mistaken for a full one.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | The bundle verifies |
| 1 | The bundle does not verify, and every problem is named |
| 2 | The tool could not run |

Zero and one are about the evidence. Two is about the tool. A verifier that
returns "failed" when it merely could not read a file has told a reviewer the
evidence is bad when the truth is that the tool is broken.

## Running the tests

```
go test ./...
```

That reproduces every published vector: 31 canonical encoding cases, Merkle
trees at sizes 0, 1, 2, 3, 7, 8 and 100,000, and a signed six-record episode
with the eight required failure cases constructed from it.

## The format

[`spec/record-format.md`](spec/record-format.md) is the normative document.
Canonical encoding, the Merkle construction and the envelope shape are frozen.
Changing any of them invalidates every signature ever made under `hpx/1`.

## What is not here

This repository contains a verifier. It does not contain the capture adapters,
the signing path, or anything that produces records. Those are separate and are
not published.

## Licence

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
