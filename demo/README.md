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
          log root published at size 14, checkpoint signed by 2 key(s)
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

  record 0 (discharge.proof): DIGEST_MISMATCH: envelope says sha256:09f5780a139…,
                              payload hashes to sha256:786a9a2c…
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

`checkpoint.txt` is the signed statement that the log held 14 records with the
published root at a given moment, carrying two signatures: the log's own, and an
independent witness that verified continuity before co-signing.

```
hpx/checkpoint/1
medxt-evidence/demo
14
sha256:b14260755766240f824b2c070e535c78d0e56b9b39ac2b82a1ee9d8fdbeaed93
2026-11-07T09:00:00.000Z
```

A checkpoint signed only by the log proves nothing against the log. The second
signature is the one that matters.

```
./verify --checkpoint demo/checkpoint.txt --keys demo/keys.json \
         --log-key k-log-001 --witnesses 1
```

## When the operator is the adversary

Every signature above protects a record against anyone who does not hold a key.
None of them protects against the party running the log, who holds the real key
and can sign anything.

Four more files cover that case. They are three checkpoints over the same log as
it grew, plus a fourth over a log rebuilt without one record and signed with the
same genuine key.

| File | Size | Signatures |
|---|---|---|
| `checkpoint-monday.txt` | 5 | log and witness |
| `checkpoint-tuesday.txt` | 14 | log and witness |
| `checkpoint-rewritten.txt` | 13 | log only |

`proof-monday-to-tuesday.json` is the RFC 6962 consistency proof for the honest
growth, five hashes long. `proof-rewritten.json` is an empty array, because no
proof exists for the rewrite and none can be constructed.

**Honest growth. The log of 14 contains the log of 5, unchanged.**

```
./verify --checkpoint demo/checkpoint-tuesday.txt \
         --against    demo/checkpoint-monday.txt \
         --proof      demo/proof-monday-to-tuesday.json \
         --keys       demo/keys.json
```

**The rewrite. The same key, a valid signature, and no continuity.**

```
./verify --checkpoint demo/checkpoint-rewritten.txt \
         --against    demo/checkpoint-tuesday.txt \
         --proof      demo/proof-rewritten.json \
         --keys       demo/keys.json
```

The second command fails on the size, because a log that shrank from 14 to 13 is
not an append only log whatever it is signed with. Had the operator rebuilt at
the same size or larger, the proof check would have failed instead. Either way
the witness refuses to co-sign, which is why the rewritten checkpoint carries one
signature and the honest ones carry two.

The property worth noticing is that a reviewer holding only these text files
reaches the same conclusion, offline, with no access to the log and no
cooperation from whoever runs it.

No independent witness is in operation today. The witness here is a second key
held by the same generator, which demonstrates the protocol and does not
demonstrate independence. Until a party outside MedXT holds a co-signing key,
the system is not described as independently anchored.

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
