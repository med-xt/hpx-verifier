# Displaying evidence status alongside a claim intelligence finding

A note for engineers building a screen that shows both a claim intelligence
result and an evidence verification result for the same episode.

It is short because the rules are few, and three of them are not negotiable.

## The data

`summary.json` carries, for each episode: the file, the episode identifier, the
evidence status, the disposition, and the requirement set assessment including
the citation for anything missing.

A display needs nothing else. The bundle files carry the records, keys, inclusion
proofs and checkpoint, and are what a verifier consumes.

## The three statuses

```
complete              every required document is present and every record verifies
incomplete            a required document is absent
integrity failure     a record is not what it claims to be
```

And the dispositions they map to:

```
proceed    review    escalate
```

## Rule one. The evidence row never gates anything

The evidence status is an input to a decision made elsewhere. It must not be
rendered as a gate, a block, or a stop.

Specifically, the evidence row must never display:

```
denied        blocked       rejected      failed
not approved  on hold       stopped       declined
```

If the surrounding product holds a claim, that is the product's decision and
should be attributed to the product. The moment a screen shows the evidence
status as the thing that stopped a claim, this layer has become an adjudication
system in the eyes of whoever is watching, without any of the accountability that
belongs to one.

## Rule two. Keep the rows visually separate

The claim intelligence finding and the evidence status answer different
questions, owned by different parties.

Showing them as one combined status is the most common way this goes wrong. Two
rows, two labels, two owners.

```
  Claim intelligence   diagnosis at risk, unsupported HCC          [vendor]
  Evidence             incomplete, physician certification absent  [evidence layer]
                       42 CFR 424.22
  Disposition          route to review
```

## Rule three. Never say unavailable means a problem with the evidence

If the verification service cannot be reached, the status is `unavailable` and
the verdict is null. That is a statement about the verifier, not about the
records.

A screen that renders an unavailable verifier as a negative finding will, during
the first outage, tell a reviewer that good evidence is bad.

```
  Evidence   could not be verified at this time
             this is not a finding about the records
```

## Showing the hashes

Record digests and the log root are safe to display. They contain no protected
health information: a digest is a hash, and the subject identifier in a record is
a keyed pseudonym rather than a beneficiary identifier.

Truncate for display, show the full value on hover or expand, and make it
copyable. Engineers in the room will copy one, and that is the point.

Do not display the evidence fingerprint descriptors as free text from an
untrusted source. They come from a controlled vocabulary, and anything outside it
should not have been accepted upstream.

## Adding a verify action

The strongest thing a demonstration can do is let the viewer check the screen.

```
verify --bundle <the episode bundle>
```

Exit 0 means it verifies. Exit 1 means it does not, and the output names the
record by position and the check that failed. Exit 2 means the tool could not
run, which is a different thing and must not be shown as a verification failure.

The verifier makes no network call and needs no account, so it can run locally,
in a container, or on the viewer's own laptop.

## What not to claim on screen

An integrity failure means a record is not what it claims to be. It does not mean
fraud has occurred, and labelling it as fraud is a claim the tool cannot support
and that a payer's legal team will object to.

A complete evidence chain does not mean the claim should be paid. It means the
documents the programme requires are present and authentic. Coverage, medical
necessity, coding and pricing are all outside this layer, and the assessment says
so in its own `notAssessed` field. Display that field somewhere.
