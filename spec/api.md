# Integration API, `hpx-contract/1`

The interface a consuming system builds against.

Plain HTTP with JSON bodies. No SDK, no RPC, no client library. If you can make
an HTTPS request and parse JSON, you have everything you need, and nothing in
the integration depends on code from us.

This document is the contract. It is published separately from the record format
specification because a consuming system should never need to understand the
record internals: the canonical encoding, the chain construction, the log, the
key derivation and the identity scheme are all behind this interface and none of
them appear in it.

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be interpreted
as described in RFC 2119 and RFC 8174 when, and only when, they appear in
capitals.

## Status of this document

The contract version is `hpx-contract/1` and is carried in every response.

The reason codes and the separation of verdict from status are frozen. Renaming
a code or collapsing those fields is a breaking change for every consuming
system and would require a new contract version.

The service implementation is in active development. The interface below is
settled and testable today against the published fixtures; a hosted endpoint is
a separate question and is not implied by this document.

---

## 1. The call that matters

For a claim intelligence or adjudication system, the integration is one call.

```http
POST /v1/verify
Content-Type: application/json

<an evidence bundle>
```

### 1.1 Response

```json
{
  "contract": "hpx-contract/1",
  "status": "available",
  "verdict": "incomplete",
  "reasons": [
    { "code": "CHAIN_INCOMPLETE",
      "class": "business",
      "meaning": "A record type the workflow requires is absent from the episode." }
  ],
  "episodeRef": "ep_...",
  "claimRef": null,
  "evidencePresent": ["discharge.proof", "consent.proof", "encounter.proof"],
  "evidenceAbsent": ["order.proof"],
  "identityBasis": "local",
  "earliestRecord": "2026-09-11T15:20:00.000Z",
  "evidencePrecedesClaim": true,
  "proofRef": "...",
  "checkedAt": "2026-10-06T14:02:11.004Z",
  "attestation": null
}
```

### 1.2 Fields

| Field | Meaning |
|---|---|
| `contract` | Contract version. Check it. |
| `status` | Whether the service could answer. Read this first. |
| `verdict` | What the evidence says. Null unless status is `available`. |
| `reasons` | Stable codes with their class and a human readable meaning. |
| `episodeRef` | The episode the evidence belongs to. |
| `claimRef` | The claim the question was asked about, where supplied. |
| `evidencePresent` | Record types found. |
| `evidenceAbsent` | Record types looked for and not found. |
| `identityBasis` | `authoritative`, `local`, or null where identity was not assessed. |
| `earliestRecord` | Timestamp of the earliest record in the chain. |
| `evidencePrecedesClaim` | Whether the evidence existed before the claim was submitted. |
| `proofRef` | A reference a reviewer can follow to pull the chain and check it independently. Not the chain itself. |
| `checkedAt` | When the check ran. |
| `attestation` | The verdict, signed, where the deployment issues one. Lets a consumer prove later what the answer was without trusting its own log of it. |

`evidencePrecedesClaim` is worth attention. Evidence created before the claim is
the property that matters. Evidence assembled afterward is the thing this layer
exists to replace.

---

## 2. Status, and why it is a separate field

```
available     the service performed the check
degraded      the service answered with reduced capability
unavailable   the service could not perform the check
```

**A client MUST read `status` before reading `verdict`.**

When status is not `available`, `verdict` is `null`, `reasons` is empty, and the
response carries an `advisory` instead:

```json
{
  "contract": "hpx-contract/1",
  "status": "unavailable",
  "verdict": null,
  "reasons": [],
  "checkedAt": "2026-10-06T14:02:11.004Z",
  "advisory": "The verifier could not answer. No conclusion about this claim is available, and the absence of a verdict is not a finding. Proceed as though this service were not deployed."
}
```

A client MUST NOT render a null verdict as a negative finding. During the first
outage, a UI that does so will tell a reviewer that good evidence is bad.

---

## 3. Verdict

```
complete        the evidence is present and consistent with the claim
incomplete      the evidence has a gap
unverifiable    the check could not be completed
```

`unverifiable` is not a worse `incomplete`. Incomplete means we checked and
found a gap. Unverifiable means we could not check. A client MUST NOT collapse
them, because only one of the two is a finding about the claim.

---

## 4. Reason codes

Codes are stable identifiers. Downstream systems match on them, so they are part
of the interface rather than log text.

Each carries a `class`, which is what a client should branch on.

### 4.1 `reject`

The input was malformed or outside the format. Raise an incident.

| Code | Meaning |
|---|---|
| `SPEC_UNKNOWN` | The record declares a format version this verifier does not implement. |
| `TYPE_UNKNOWN` | The record declares a type outside the frozen set. |
| `PHI_DETECTED` | A field contains data the format forbids. |

### 4.2 `integrity`

A cryptographic check failed. This is a security event, not a claim finding.

| Code | Meaning |
|---|---|
| `DIGEST_MISMATCH` | The record was altered after signing. |
| `SIG_INVALID` | The signature does not verify over the record. |
| `KEY_MISMATCH` | The key named outside the signature disagrees with the key named inside it. |
| `KEY_EXPIRED` | The signing key was retired before the time the record claims. |
| `SEQ_MISMATCH` | A record is not in the position it claims. Something was moved, removed or inserted. |
| `PREV_MISMATCH` | The chain link is broken between two records. |
| `PREV_UNEXPECTED` | A first record links to a predecessor, or a later record does not. |
| `INCLUSION_FAILED` | A record is not included under the published log root. |

### 4.3 `unverifiable`

An input the verifier needed was missing. This says nothing about the claim.

| Code | Meaning |
|---|---|
| `KEY_UNKNOWN` | The signing key is not in the registry supplied. A missing input, not a bad record. |

### 4.4 `business`

The findings this layer exists to produce. These route to human review.

| Code | Meaning |
|---|---|
| `CHAIN_INCOMPLETE` | A record type the workflow requires is absent from the episode. |
| `CLAIM_DIVERGENT` | The claim states something the evidence chain does not support. |
| `ASSERTION_CONFLICT` | Two records in the episode assert incompatible facts. |
| `IDENTITY_DEGRADED` | An actor resolved to a local identifier rather than an authoritative one. The evidence is weaker, not wrong. |
| `NO_EVIDENCE` | No evidence chain exists for this claim at all. |

A client SHOULD route `integrity` and `reject` to a different queue from
`business`. An integrity failure is rare by construction, and burying it in the
volume of ordinary documentation gaps defeats the purpose of reporting it.

---

## 5. Disposition

The contract answers what a caller should do, never what a caller should
conclude.

| Disposition | When | Meaning |
|---|---|---|
| `proceed` | status not available | The verifier could not answer and its silence is not a finding |
| `proceed` | verdict complete | The evidence is present and consistent with the claim |
| `proceed` | class `unverifiable` | An input was missing, which says nothing about the claim |
| `escalate` | class `reject` or `integrity` | A record failed an integrity check. An incident, not a claim finding |
| `review` | otherwise | The evidence has a gap a reviewer should look at |

**There is no `deny`.**

This layer does not decide claims. A consuming adjudication system may deny on
any basis it chooses, including this input, and that decision and its label
belong to that system.

A client MUST NOT display the evidence status as the cause of a denial, a block
or a hold. See `demo/INTEGRATION.md` for display rules.

---

## 6. Fail open

The verification service fails open, and this is a requirement rather than a
quality of implementation.

An unreadable body, a malformed bundle, an oversized request, an internal
exception or a timeout all produce a response that permits the caller to
proceed.

**An `unavailable` response is returned with HTTP 200.** The request was
answered. The answer is that the check could not be performed. A client MUST NOT
treat the HTTP status as the verdict.

A client SHOULD treat a transport level failure, a connection reset or its own
timeout exactly as it treats `unavailable`: proceed, and record that the check
did not happen.

### 6.1 Limits

| Limit | Value | Behaviour when exceeded |
|---|---|---|
| Request body | 2 MB | `unavailable` |
| Deadline | 250 ms | `unavailable` |

The service returns `unavailable` rather than exceeding its deadline, so a
client can treat the call as having a hard ceiling. A verification step that can
hang is one that gets removed from the critical path by whoever is on call.

---

## 7. Other endpoints

Not required for a first integration.

### 7.1 Capture

```http
POST /v1/events
```

Eight event types, across six standards:

```
hl7v2.adt.discharge     hl7v2.adt.admission     hl7v2.mdm.document
cdshooks.order-sign     x12.837.claim           x12.835.remittance
fhir.careplan           fhir.encounter
```

A CDS Hooks discovery endpoint is served at `GET /cds-services`, with the hook
itself at `POST /cds-services/evidence-capture`. The hook returns an empty card
set, always. It displays nothing to the clinician and never delays a signature.

Responses distinguish permanent from transient failure: a 422 means do not
retry, a 409 means retry. Conflating them either loses messages or produces
infinite retry.

### 7.2 Provider view

```http
GET /v1/episodes                                      a facility's own episodes
GET /v1/gaps?episode=&program=&workflow=              missing documents, with citations
GET /v1/bundle?episode=                               the audit artifact
GET /v1/requirements?set=                             a published requirement set
```

Scope is derived from the authenticated facility, never from a query parameter.
An episode outside the caller's scope and an episode that does not exist return
the same 404, so the endpoint cannot be used to discover which episodes are
real.

### 7.3 Checkpoints, served openly

```http
GET /v1/checkpoints                  the list
GET /v1/checkpoint?size=             one checkpoint, as text
GET /v1/proof?from=&to=              a consistency proof, a bare JSON array of hex
```

These require no authentication. A checkpoint carries an origin, a record count,
a hash and a time, and contains no beneficiary, provider, episode or clinical
content. Its entire function is to be held outside this system, and a log that
shows its checkpoints only to parties it approves of has not published anything.

`GET /v1/checkpoint` returns `text/plain`. The signed bytes are the document, so
re-encoding it as JSON would hand the reader a file whose signature will not
check.

---

## 8. Building against this today

No endpoint from us is required to build and test a client.

```
git clone https://github.com/med-xt/hpx-verifier
cd hpx-verifier && go build -o verify ./cmd/verify
```

`demo/` holds three episodes: one complete, one missing a required document, one
altered after signing. Synthetic data, real cryptography.

```
./verify --bundle demo/1-complete.json    # exit 0
./verify --bundle demo/2-incomplete.json  # exit 0, gap reported separately
./verify --bundle demo/3-altered.json     # exit 1, names the record and the check
```

`demo/summary.json` carries the assessment for each episode in the shape a
display consumes, including the regulatory citation for anything missing.

A client can stub `/v1/verify` against those three bundles and have its side of
the integration finished and tested before a URL exists.

### 8.1 Exit codes, for anyone shelling out to the binary

| Code | Meaning |
|---|---|
| 0 | Verifies |
| 1 | Does not verify, and every problem is named |
| 2 | The tool could not run |

Zero and one are about the evidence. Two is about the tool. A verifier that
returns failure when it merely could not read a file has told a reviewer the
evidence is bad when the truth is that the tool is broken.

---

## 9. What this interface does not provide

Coverage determination, medical necessity, coding, pricing, and any judgement
about whether a claim should be paid.

A `complete` verdict means the documents a programme requires are present and
authentic. It does not mean the claim is payable, and the assessment returned
with it names what was not assessed.

The layer also does not establish that the underlying clinical event occurred.
An actor holding valid credentials can sign a well formed record about something
that never happened. No cryptographic construction closes that, and the format
specification states it directly.

---

## 10. References

The record format, including the normative wire format and the conformance
requirements, is Part V of *A Doctrine of Verifiable Evidence for United States
Healthcare Payment*, https://doi.org/10.5281/zenodo.23107483.

Display rules for showing an evidence status beside another vendor's finding are
in `demo/INTEGRATION.md`.
