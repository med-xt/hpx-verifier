"""Run every published conformance vector against the Python implementation.

    python3 python/check_vectors.py

Exits 0 if all of them pass and 1 otherwise, so it can be a CI gate. It prints
what it checked rather than a bare count, because a gate nobody has watched
pass is not a gate, which is finding 2.11 in this project's own security review.

This is the whole point of the third implementation. If it disagrees with the
vectors, either the vectors are wrong, the specification is ambiguous, or this
file is wrong, and all three of those are worth knowing.
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import hpx  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
CONFORMANCE = os.path.join(os.path.dirname(HERE), 'conformance')

failures = []
checks = 0


def ok(label, condition, got=None):
    global checks
    checks += 1
    if condition:
        print('  PASS  %s' % label)
    else:
        print('  FAIL  %s   got: %r' % (label, got))
        failures.append(label)


def load(name):
    with open(os.path.join(CONFORMANCE, name), encoding='utf-8') as fh:
        return json.load(fh)


def section(title):
    print('\n%s\n%s' % (title, '-' * len(title)))


# ------------------------------------------------------- canonical encoding
vectors = load('canonical.json')
section('Canonical encoding, %d cases' % len(vectors['cases']))
sentinel = vectors.get('omitSentinel', '<<omit>>')

for case in vectors['cases']:
    value = hpx.hydrate(case['input'], sentinel)
    try:
        encoded = hpx.canonicalize(value)
    except Exception as exc:                      # noqa: BLE001
        ok(case['name'], False, 'raised %s: %s' % (type(exc).__name__, exc))
        continue
    # Byte for byte, and the digest as well. The digest is the thing signatures
    # are made over, so matching the string but not the digest would mean the
    # hashing or the encoding to UTF-8 was wrong.
    if encoded != case['expected']:
        ok(case['name'], False, encoded)
        continue
    if 'digest' in case and hpx.digest(value) != case['digest']:
        ok('%s (digest)' % case['name'], False, hpx.digest(value))
        continue
    ok(case['name'], True)


# ------------------------------------------------------------------- Merkle
vectors = load('merkle.json')
section('Merkle trees and inclusion proofs')

ok('empty tree root', hpx.merkle_root([]) == vectors['emptyTreeRoot'], hpx.merkle_root([]))

# Leaf i is "sha256:" followed by i written in decimal and left padded with
# zeros to 64 characters.
#
# Decimal, not hex, and the vector file does not say so anywhere. A digest is
# hex everywhere else in this format, so hex is the natural assumption, and it
# is wrong. It is also undetectable in the small trees: for any index below 10
# the two encodings are the same string, so trees of size 1, 2, 3, 7 and 8 all
# pass either way. Only the tree of 100,000 distinguishes them, and this
# implementation got it wrong in exactly that way on the first run.
#
# Noted in python/README.md. The vectors should state the rule rather than
# leaving a third implementation to infer it from the one case that can.
def synthetic(n):
    return ['sha256:' + str(i).zfill(64) for i in range(n)]


for tree in vectors['trees']:
    size = tree['size']
    root = hpx.merkle_root(synthetic(size))
    ok('root over %d leaves' % size, root == tree['root'], root)

    for entry in tree['proofs']:
        got = hpx.verify_inclusion(entry['leaf'], entry['proof'], tree['root'])
        ok('  inclusion of index %d in tree of %d' % (entry['proof']['index'], size), got, got)

for case in vectors['mustFail']:
    got = hpx.verify_inclusion(case['leaf'], case['proof'], case['root'])
    ok('must fail: %s' % case['about'], got is False, got)

# Every index in every tree from 1 to 64. The spec says the reference is tested
# this way, and a proof that works for index 0 and the last index while failing
# somewhere in the middle is the normal shape of this bug.
section('Inclusion at every index, trees of 1 to 64')
bad_sizes = []
total = 0
for size in range(1, 65):
    digests = synthetic(size)
    root = hpx.merkle_root(digests)
    for index in range(size):
        proof = hpx.inclusion_proof(digests, index)
        total += 1
        if not hpx.verify_inclusion(digests[index], proof, root):
            bad_sizes.append((size, index))
        # The same proof against a leaf it was not made for must fail, or the
        # proof is not binding the leaf to the tree at all.
        other = (index + 1) % size
        if size > 1 and hpx.verify_inclusion(digests[other], proof, root):
            bad_sizes.append((size, index, 'wrong leaf accepted'))
ok('every index in every tree from 1 to 64 verifies (%d proofs)' % total,
   not bad_sizes, bad_sizes[:6])

# A leaf that is not in the tree must not verify.
bad = hpx.verify_inclusion('sha256:' + 'ff' * 32, {'index': 0, 'size': 1, 'path': []},
                           hpx.merkle_root(synthetic(1)))
ok('a leaf not in the tree does not verify', bad is False, bad)

# Generated proofs must agree with the published ones, or the generator and the
# vectors disagree about the tree shape.
mismatched = []
for tree in vectors['trees']:
    if tree['size'] == 0 or tree['size'] > 1000:
        continue
    digests = synthetic(tree['size'])
    for entry in tree['proofs']:
        mine = hpx.inclusion_proof(digests, entry['proof']['index'])
        if mine['path'] != entry['proof']['path']:
            mismatched.append((tree['size'], entry['proof']['index']))
ok('generated proofs match the published ones exactly', not mismatched, mismatched)


# ------------------------------------------------------------- consistency
vectors = load('consistency.json')
section('Consistency proofs, %d cases and %d that must fail'
        % (len(vectors['cases']), len(vectors['mustFail'])))

for case in vectors['cases']:
    got, reason = hpx.verify_consistency(
        case['oldSize'], case['newSize'], case['oldRoot'], case['newRoot'], case['proof'])
    power_of_two = case['oldSize'] > 0 and case['oldSize'] & (case['oldSize'] - 1) == 0
    label = '%d to %d%s' % (case['oldSize'], case['newSize'],
                            '  (old size is a power of two)' if power_of_two else '')
    ok(label, got, reason)

for case in vectors['mustFail']:
    got, reason = hpx.verify_consistency(
        case['oldSize'], case['newSize'], case['oldRoot'], case['newRoot'], case['proof'])
    ok('must fail: %s' % case['about'], got is False, reason)
    if not got:
        print('          reported: %s' % reason)


# --------------------------------------------------------------------- done
print('\n%d checks' % checks)
if failures:
    print('%d FAILED\n' % len(failures))
    for f in failures:
        print('  %s' % f)
    print()
    sys.exit(1)
print('ALL PASS\n')
