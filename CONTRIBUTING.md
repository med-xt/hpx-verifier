# Contributing

The most useful contribution to this repository is a disagreement.

If you implement `hpx/1` and your implementation produces different bytes from
this one on any published vector, that is a finding, and we would rather have it
than not. Open an issue with the vector name, what you produced, and what you
expected.

## Before a pull request is merged

**We need a signed Contributor Licence Agreement.**

This is not a formality and it is not about ownership of your ideas. Without a
CLA, a contributor retains copyright in their contribution, which means this
project can no longer be relicensed, audited cleanly, or acquired without
tracing every line back to its author and asking permission.

Papering it before the first contribution is cheap. Papering it afterward is
expensive and sometimes impossible. Open an issue and we will send the agreement.

Small fixes that are not copyrightable, a typo, a one-word correction, do not
need one.

## What belongs here

- Bug reports against the verifier
- Divergence between this implementation and the specification
- Divergence between this implementation and the published vectors
- Additional conformance vectors covering cases the current set misses
- Ports of the verifier to other languages, which we would link to rather than
  vendor
- Documentation that makes the specification easier to implement correctly

## What does not belong here

- Capture adapters, record production, or anything that creates records. This
  repository is a verifier. The producing side is separate and is not published.
- Changes to canonical encoding, the Merkle construction or the envelope shape.
  Those are frozen. Changing any of them invalidates every signature ever made
  under `hpx/1`. If you believe one of them is wrong, open an issue rather than
  a pull request, because the answer is a new spec version rather than an edit.
- Real patient, provider or claim data in a fixture, under any circumstances.
  The vectors here are synthetic and must stay that way.

## Running the tests

```
go test ./...
```

Every published vector is reproduced: 31 canonical encoding cases, Merkle trees
at seven sizes, and a signed six-record episode with the eight required failure
cases constructed from it.

A change that makes `go test` pass by editing a vector rather than fixing the
code will be refused. The vectors are the contract.
