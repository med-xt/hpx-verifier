# Demonstration dataset

Three post-acute home health episodes. The data is synthetic and the
cryptography is real.

No real beneficiary, provider, encounter or claim appears here. The episodes
never happened. The digests, the ML-DSA-65 signatures, the Merkle log and the
witnessed checkpoint are genuine, produced by the reference implementation, and
every one of them verifies with the tool in this repository.

That distinction is the point of the directory. A demonstration built on invented
hashes is decoration, and the first person who copies one into a hash calculator
finds out. These can be checked.

## Run it

```
go build -o verify ./cmd/verify
```

**Episode one. Complete, and it verifies.**

```
./verify --bundle demo/1-complete.json
```

```
VERIFIES  5 records, episode ep_demo_complete_0001
          chain intact, every record links to its predecessor
          every record included under the published log root
          every signature verifies over the canonical payload
          log root published at size 15, checkpoint signed by 2 key(s)
```

Exit code 0.

**Episode two. A required document is missing, and it still verifies.**

```
./verify --bundle demo/2-incomplete.json
```

Exit code 0, and that is correct. Every record present is authentic. What is
missing is the physician certification, which is a documentation gap rather than
an integrity problem, and it is reported separately in `summary.json`:

```json
"missingRequired": [
  { "type": "order.proof",
    "what": "physician certification that the services are required, with a face to face encounter",
    "cite": "42 CFR 424.22" }
]
```

The two questions are independent and must stay that way. Verification asks
whether the records are genuine. The requirement set asks whether the documents
a programme requires are present. Collapsing them would mean an incomplete
episode looked like a tampered one.

**Episode three. One field was altered after signing.**

```
./verify --bundle demo/3-altered.json
```

```
DOES NOT VERIFY  5 records, 2 problems

  record 0 (discharge.proof): DIGEST_MISMATCH: envelope says sha256:77f6fc37…,
                              payload hashes to sha256:…
  record 0 (discharge.proof): SIG_INVALID: signature does not verify over the
                              canonical payload
```

Exit code 1. A single edit to one field breaks two independent checks, because
the digest and the signature are both bound to the content.

Note that episode three's requirement assessment still reports complete. Every
document type the programme asks for is present. The problem is not a missing
document, it is a record that is not what it claims to be, and the integrity
failure is what matters here.

## The checkpoint

`checkpoint.txt` is the signed statement that the log held 15 records with the
published root at a given moment, carrying two signatures: the log's own, and an
independent witness that verified continuity before co-signing.

```
hpx/checkpoint/1
medxt-evidence/demo
15
sha256:b14260755766240f824b2c070e535c78d0e56b9b39ac2b82a1ee9d8fdbeaed93
2026-11-07T09:00:00.000Z
```

A checkpoint signed only by the log proves nothing against the log. The second
signature is the one that matters.

```
./verify --checkpoint demo/checkpoint.txt --keys demo/keys.json \
         --log-key k-log-001 --witnesses 1
```

## What the three outcomes are called

The three episodes correspond to the three dispositions the output contract
returns. None of them is a denial, because this layer does not deny claims.

| Episode | Evidence | Disposition | Meaning |
|---|---|---|---|
| 1 | complete | `proceed` | Nothing in the evidence warrants holding the decision |
| 2 | incomplete | `review` | A required document is absent. A person should look before the decision is final |
| 3 | integrity failure | `escalate` | A record is not what it claims to be. This is a security event |

An integrity failure is evidence of alteration. It is not a finding of fraud, and
describing it as one would be a claim this tool cannot support.

## Keys

`keys.json` holds public keys only. It is the object an auditor is given, which
is why it can be published without any further precaution.

The bundles also carry their own copy, so `--keys` is optional when verifying
them. Supply it explicitly if you obtained the registry from somewhere other than
the party under review, which is what a reviewer should do.

## Regenerating

These files are produced by the reference implementation, which is not published.
They are committed here as artifacts so that this repository is self contained.
