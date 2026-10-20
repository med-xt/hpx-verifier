# A third implementation

```
python3 python/check_vectors.py
```

86 checks. Standard library only, no `pip install`, no virtualenv, no network.
Python 3.8 or later.

## Why

The README at the root of this repository argues that a specification
implemented once has not been tested, it has been asserted, and that if two
implementations disagree one of them is wrong. That argument is weaker with two
implementations than it looks, because two written by the same people in the
same month can share a misreading and agree with each other all the way into
production. A third, in a different language, written from the specification
and the published vectors rather than from either existing implementation, is
how you find out.

`hpx.py` covers the two parts of the format every signature depends on: the
canonical encoding that digests are taken over, and the Merkle construction
that inclusion and consistency proofs are built on. It does no signature
verification, because ML-DSA-65 is not in the Python standard library and
adding a dependency would cost the property that makes this useful, which is
that a reviewer with nothing but a Python interpreter can check the published
vectors are what they claim to be.

It deliberately does not read `canonical.go`, `merkle.go`, `consistency.go` or
the JavaScript reference. Transliterating an implementation reproduces its
mistakes and proves nothing. It is the same error as writing a test fixture
from the code the fixture is meant to test, which is a mistake this project has
already made and written up at length.

## What it found

Two things, both real, and finding them is the entire return on the exercise.

### The specification does not say how interior nodes are hashed

Section 7 of `spec/record-format.md` gives the interior node as:

```
SHA-256(0x01 || left || right)
```

It does not say whether `left` and `right` are the raw 32 byte hashes or the
`sha256:`-prefixed hex strings that every other part of the format uses. Both
readings are defensible from the text alone, and leaf hashing in the line above
it explicitly uses the ASCII digest string, which makes the string reading the
more natural inference of the two.

They produce completely different roots. An implementation that picks the
string reading disagrees with every other implementation on every tree larger
than one leaf, and the disagreement looks exactly like tampering rather than
like a misreading.

The vectors settle it: raw bytes. The specification should say so.

### The vectors do not say how their synthetic leaves are built

`conformance/merkle.json` publishes roots for trees of 0, 1, 2, 3, 7, 8 and
100,000 leaves, but never states what the leaves are. They can be recovered
from the `leaf` field of the inclusion proof entries, and they are

```
"sha256:" + str(i).zfill(64)
```

which is the index in **decimal**, left padded to 64 characters. Not hex.

Every digest elsewhere in this format is hex, so hex is what a reader assumes,
and this implementation assumed it on the first run. It is undetectable in the
small trees: for any index below 10 the decimal and hex encodings are the same
string, so the trees of 1, 2, 3, 7 and 8 all pass either way. Only the tree of
100,000 distinguishes them.

That is worth stating plainly, because the tree of 100,000 exists in the vector
set to exercise depth and the power-of-two split, and it turned out to be the
only case in the file that could catch a wrong leaf encoding at all. A tidier
vector set without it would have let this implementation report ALL PASS while
computing different roots from the other two.

The vector file should state the rule.

## What else it caught

A bug in this implementation's own proof generator, found by the exhaustive
sweep rather than by the published vectors. Recursing into a sibling subtree
with a sentinel target, the sentinel compared less than every real offset, so
the sibling's internal nodes were appended to the proof path. Trees of 1, 2 and
3 still produced correct proofs. A tree of 4 was the first to fail.

That is the same shape as both findings above and as this project's finding
2.12: small cases agree under both the right rule and the wrong one, so a test
set that stops at three or four leaves confirms whatever the implementation
already does.

## What is checked

| Area | Checks |
|---|---|
| Canonical encoding | All 31 published cases, string and digest, byte for byte |
| Merkle roots | Trees of 0, 1, 2, 3, 7, 8 and 100,000 leaves |
| Inclusion | Every published proof, plus the case that must fail |
| Inclusion, exhaustive | Every index in every tree from 1 to 64, 2,080 generated proofs, each verified and each also checked to reject a leaf it was not made for |
| Generator agreement | Generated proofs compared against the published ones, step for step |
| Consistency | All 21 cases including every power-of-two old size, and all 7 that must fail, each with its reason classified |

The number work is the part most likely to differ between languages. RFC 8785
defines number serialisation by reference to ECMAScript, and Python's own
formatting differs in three places that all change the bytes and therefore
every signature:

| Value | Python `repr` | Canonical |
|---|---|---|
| `1.0` | `1.0` | `1` |
| `1e16` | `1e+16` | `10000000000000000` |
| `1e-7` | `1e-07` | `1e-7` |

`_number` implements the ECMAScript algorithm rather than reaching for
`repr`, and uses `repr` only to obtain the shortest round-tripping digit
string, which is the one thing it is right about.
