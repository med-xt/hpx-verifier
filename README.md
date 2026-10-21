# hpx-verifier

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.23107483.svg)](https://doi.org/10.5281/zenodo.23107483)

An independent, offline verifier for `hpx/1` evidence records.

The format this tool verifies is specified in *A Doctrine of Verifiable Evidence
for United States Healthcare Payment*, https://doi.org/10.5281/zenodo.23107483. Part V of that document is
the normative specification; this repository is one of the two implementations it
describes.

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

## The check that is about the operator, not the record

Everything above establishes that a record cannot be altered by anyone who does
not hold a signing key. It says nothing about the party who runs the log, and
that is the question worth asking. With full database access: stop the service,
remove a record, rebuild the Merkle tree, start again. Every remaining signature
verifies. Every chain links. Every inclusion proof resolves against the new
root. The removed record simply never existed.

A **checkpoint** closes it. Five lines of signed text saying that at one moment
the log held this many records and its root was this.

```
hpx/checkpoint/1
medxt-evidence/us-east-1
20
sha256:5f2c…
2026-10-06T09:00:00.000Z

sig k-log-001 1 ML-DSA-65 …
sig k-wit-001 1 ML-DSA-65 …
```

The second signature is the one that matters. It belongs to a party that is not
the operator, keeps its own copy of what it last endorsed, and will only sign a
new checkpoint after verifying a **consistency proof** that the tree now
contains the tree then as an unchanged prefix. A log that has been rebuilt
cannot produce that proof, and the failure to produce it is the detection.

This verifier implements both, and the asymmetry is the point: a reviewer
holding two checkpoints and a proof needs nothing from the operator at all.

```
go test -run Consistency ./...
go test -run Checkpoint ./...
```

Two honest limits, stated here rather than buried. A checkpoint signed only by
the log proves nothing against the log, so this tool reports which keys signed
and leaves the quorum rule to whoever is relying on it. And a witness operated
by the same party as the log provides nothing whatsoever; the value is entirely
in independence, which is an agreement between organisations and not a property
any code can establish.

## What it detects and names

- Any field altered in any record
- Two records transposed
- A record removed from the middle of a chain
- A record inserted into a chain
- A record signed by a key not in the registry
- A record signed by a key retired before the claimed time
- A leaf presented as an interior node in an inclusion proof
- A forged digest presented with a valid proof for a different record
- A log reporting fewer records than a checkpoint it has already signed
- Two checkpoints at one size carrying different roots
- A consistency proof that does not reconstruct the earlier signed root, which
  is what a rebuilt log produces
- A checkpoint whose root is not the root the inclusion proofs are built on
- A checkpoint altered after signing, including a changed origin, which is how a
  checkpoint from one log would be replayed as another's

Each problem names the record by position and the check that failed. A
consistency failure additionally distinguishes a malformed proof from two roots
that describe different trees, because the first is a bug and the second is an
incident.

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

## A demonstration you can run

`demo/` holds three synthetic post-acute episodes with real cryptography: one
complete, one missing a required document, and one with a field altered after
signing. The first two verify, the third does not, and `demo/README.md` shows the
commands and the expected exit codes.

```
./verify --bundle demo/1-complete.json    # exit 0
./verify --bundle demo/3-altered.json     # exit 1, names the record and the check
```

`demo/INTEGRATION.md` is for anyone building a screen that shows an evidence
status beside another vendor's finding. [`spec/api.md`](spec/api.md) is the
integration contract: the endpoints, every response field, the reason codes and
the fail open semantics a client has to implement.

## The same verifier, in a browser

`web/` holds this verifier compiled to WebAssembly, and it is the same Go code
in this repository, not a reimplementation in JavaScript. A page using it does
real cryptography locally. Nothing is uploaded, there is no server to trust, and
if you save the page to disk it keeps working.

```
GOOS=js GOARCH=wasm go build -o web/verify.wasm ./cmd/wasm
cp "$(go env GOROOT)/lib/wasm/wasm_exec.js" web/
```

Then serve `web/` over HTTP and open it. A `file://` URL will not work, because
browsers refuse to instantiate WebAssembly from one.

The page computes a SHA-256 of the exact bytes of the module it loaded and
displays it, so the binary that ran can be identified rather than assumed. A
running copy is at [medxt.us/verify](https://medxt.us/verify), and
`web/verify.wasm` in this repository is byte-identical to the module that page
serves: hash the file and compare it against what the page shows.

Go builds are not byte-reproducible across toolchain versions, so a module you
build yourself will hash differently from the committed one. That is expected,
and it is why the page reports the hash of what it actually loaded instead of a
figure written into the HTML.

## Running a witness

`witness/` is a witness you can run against an hpx/1 log.

A checkpoint signed only by the log proves nothing about the log. Whoever
operates it holds the key, so they can rebuild history without one record and
sign a checkpoint for the rebuilt version, and anyone holding only that
checkpoint cannot tell. A witness keeps its own record of what it last
endorsed, and co-signs a new checkpoint only after being shown that the new
tree grew from the one it already holds. If it was not, it refuses, and the
refusal is the point.

```
cd witness
npm install
node test-witness.js
```

Forty six checks, running a log and a witness as two separate parties with two
separate keys, including a log rewriting its history and being refused over
HTTP.

It is published for one reason. If you are asked to run a witness and vouch
that somebody else's log cannot be quietly rewritten, you should be able to
read what you are running. A witness nobody can inspect is not independent in
any sense that survives a question from your own counsel.

What it sees is an origin, a count, a hash and a time. There is no patient, no
provider, no diagnosis and no money in anything a witness receives.
[`witness/OPERATING.md`](witness/OPERATING.md) is written for the organisation
operating one rather than for the log operator, and states what running one
actually commits you to, what it refuses to do, and the limits of what a
journal on a single machine can prove.

## A third implementation, in Python

Two implementations written by the same people in the same month can share a
misreading and agree with each other all the way into production. So there is a
third, in `python/`, written from `spec/record-format.md` and from RFC 6962
rather than from the Go.

```
python3 python/check_vectors.py
```

86 checks, standard library only. No `pip install`, no virtualenv, no network,
and CI fails if an import outside the standard library ever appears. A reviewer
with nothing but a Python interpreter can confirm the published vectors are
what they claim to be.

It covers the canonical encoding and the Merkle construction, which is
everything a digest or a proof depends on. It does not verify signatures,
because ML-DSA-65 is not in the Python standard library and a dependency would
cost the property above.

Writing it found two gaps in what was published here, which is the entire
return on the exercise. Section 7 did not say whether an interior node hashes
the raw 32 byte child hashes or the `sha256:`-prefixed hex strings, and the
more natural reading of the text was the wrong one. And `conformance/merkle.json`
never stated that its synthetic leaves use the index in decimal rather than
hex, a difference invisible in every tree it publishes except the largest. Both
are now written down. [`python/README.md`](python/README.md) has the detail.

## Running the tests

```
go test ./...
python3 python/check_vectors.py
```

That reproduces every published vector: 31 canonical encoding cases, Merkle
trees at sizes 0, 1, 2, 3, 7, 8 and 100,000, a signed six-record episode with
the eight required failure cases constructed from it, 21 consistency proofs with
seven cases that must fail, and a signed checkpoint with a witness
co-signature.

The consistency cases include power of two sizes deliberately. When the earlier
size is a power of two the old root is a node of the new tree and is omitted
from the proof, so the verifier has to supply it. An implementation that misses
that fails every power of two case and passes all the others, which is the
defect a tidy test set hides.

## The format

[`spec/record-format.md`](spec/record-format.md) is the normative document.
Canonical encoding, the Merkle construction, the envelope shape and the
checkpoint body format are frozen. Changing any of the first three invalidates
every signature ever made under `hpx/1`. Changing the checkpoint body is worse:
it invalidates every checkpoint anyone else is holding, and those are the copies
the operator cannot reissue.

## What is not here

This repository contains a verifier, as a command line tool and as a
WebAssembly module. It does not contain the capture adapters, the signing path,
the witness implementation, or anything that produces records or checkpoints.
Those are separate and are not published.

That boundary is deliberate and it does not weaken anything here. Verifying a
checkpoint needs no part of the thing that made it, which is the same reason
verifying a record needs no part of the signing path.

## Citing this work

The specification:

> A Doctrine of Verifiable Evidence for United States Healthcare Payment. Version 1.0, October 2026. https://doi.org/10.5281/zenodo.23107483

The verifier: cite this repository and the commit you built, since the published
conformance vectors are versioned with it.

## Licence

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

The licence covers the verifier software in this repository. The specification and
the conformance vectors are published for implementation, and publication grants no
patent or trade mark licence by implication or estoppel.
