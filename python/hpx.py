"""A third implementation of the hpx/1 canonical encoding and Merkle log.

Why a third one exists
----------------------

The README of this repository argues that a specification implemented once has
not been tested, it has been asserted, and that two implementations disagreeing
means one of them is wrong. That argument gets stronger with a third
implementation and weaker without one, because two implementations written by
the same people in the same week can share a misreading and agree with each
other all the way to production.

So this is written from `spec/record-format.md` and from RFC 6962 directly. It
does not read `canonical.go`, `merkle.go`, or the JavaScript reference. A
transliteration of an existing implementation would reproduce its mistakes and
prove nothing, which is the same error as writing a test fixture from the code
it is meant to test.

It covers the two parts of the format that every signature depends on: the
canonical encoding that digests are taken over, and the Merkle construction
that inclusion and consistency proofs are built on. It does no signature
verification, because ML-DSA-65 is not in the Python standard library and a
dependency would defeat the point below.

Standard library only. No pip install, no virtualenv, no network. If this file
and a Python interpreter are all a reviewer has, that is enough to check that
the published vectors are what they claim to be.

What writing this found
-----------------------

One genuine ambiguity in the specification, which is the whole reason for the
exercise. Section 7 states the interior node as `SHA-256(0x01 || left ||
right)` without saying whether `left` and `right` are the raw 32 byte hashes or
the `sha256:`-prefixed hex strings that appear everywhere else in the format.
Both readings are defensible from the text alone and they produce different
roots. The vectors settle it: raw bytes. That is now stated in
`python/README.md`, and the specification should say it.

Usage:

    python3 check_vectors.py            # run every published vector
    python3 -c "import hpx; print(hpx.digest({'b':1,'a':2}))"
"""

import hashlib
import math
from decimal import Decimal

__all__ = [
    'OMIT', 'canonicalize', 'digest', 'hydrate',
    'EMPTY_ROOT', 'leaf_hash', 'node_hash', 'split_point', 'merkle_root',
    'verify_inclusion', 'verify_consistency',
]


class _Omit:
    """A key whose value is this is absent, not null.

    The spec is explicit that absence and null produce different digests, so
    they need different representations. JavaScript has `undefined` for this
    and Python has no equivalent, so the format's own sentinel is modelled as a
    singleton object rather than as None, which already means null.
    """
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __repr__(self):
        return '<omit>'


OMIT = _Omit()


# --------------------------------------------------------------------- numbers

def _number(value):
    """A JSON number in shortest round-trip form, per ECMAScript Number::toString.

    RFC 8785 defines number serialisation by reference to ECMAScript, so this
    has to reproduce those rules rather than use Python's own formatting, which
    differs in three places that matter:

      Python repr(1.0) is '1.0'; the canonical form is '1'.
      Python repr(1e16) is '1e+16'; the canonical form is '10000000000000000',
        because ECMAScript only goes exponential at 1e21.
      Python repr(1e-7) is '1e-07'; the canonical form is '1e-7', with no
        zero padding, and a '+' on positive exponents only.

    Every one of those differences changes the bytes, and therefore the digest,
    and therefore every signature over the record.
    """
    # bool is a subclass of int in Python, and True must not serialise as 1.
    if isinstance(value, bool):
        raise TypeError('a boolean is not a number')

    if isinstance(value, int):
        # RFC 8785 is defined on the IEEE 754 double, so an integer is
        # converted rather than printed exactly. This is deliberate: an
        # integer beyond 2^53 loses precision here exactly as it would in the
        # other two implementations, and a record that encoded it exactly in
        # one language and approximately in another would not verify across
        # them.
        try:
            value = float(value)
        except OverflowError:
            raise ValueError('integer is too large to be a JSON number')

    if math.isnan(value) or math.isinf(value):
        # Not null. The spec says non-finite is an error, because silently
        # turning a failed computation into a signed null is worse than
        # refusing it.
        raise ValueError('non-finite numbers cannot be encoded')

    if value == 0:
        # Covers negative zero, which serialises as '0'. Keeping the sign
        # would give two encodings of the same value and two digests.
        return '0'
    if value < 0:
        return '-' + _number(-value)

    # repr gives the shortest decimal string that round-trips, which is the
    # digit sequence ECMAScript calls s, with k digits. Decimal is used only to
    # split that string into digits and an exponent without further parsing.
    sign, digits, exponent = Decimal(repr(value)).as_tuple()

    # k must be minimal, so trailing zeros come off. repr(1.0) is '1.0', whose
    # digits are (1, 0); leaving the zero in place would put k at 2 and send a
    # value that should print as '1' down the fractional branch.
    digits = list(digits)
    while len(digits) > 1 and digits[-1] == 0:
        digits.pop()
        exponent += 1

    s = ''.join(str(d) for d in digits)
    k = len(s)
    n = exponent + k

    if k <= n <= 21:
        # An integer, written out with trailing zeros rather than an exponent.
        return s + '0' * (n - k)
    if 0 < n <= 21:
        # A decimal point inside the digits.
        return s[:n] + '.' + s[n:]
    if -6 < n <= 0:
        # Leading zeros after the point. The boundary is strict: n == -6 goes
        # exponential, which is what makes 1e-7 print as '1e-7'.
        return '0.' + '0' * (-n) + s
    # Exponential. n is never 1 here, so the exponent is never zero and the
    # sign is always written.
    e = n - 1
    mantissa = s if k == 1 else s[0] + '.' + s[1:]
    return mantissa + 'e' + ('+' if e > 0 else '-') + str(abs(e))


# --------------------------------------------------------------------- strings

_SHORT_ESCAPES = {
    '"': '\\"',
    '\\': '\\\\',
    '\b': '\\b',
    '\f': '\\f',
    '\n': '\\n',
    '\r': '\\r',
    '\t': '\\t',
}


def _string(value):
    """A JSON string with the shortest valid escape for each character.

    Two rules here are the ones an implementation gets wrong by being helpful.
    A forward slash is not escaped, even though escaping it is legal JSON, and
    non-ASCII characters are emitted as themselves rather than as \\u escapes.
    Either kind of extra escaping is still valid JSON and still parses to the
    same value, and both change the bytes and break every signature.
    """
    out = ['"']
    for ch in value:
        point = ord(ch)
        if ch in _SHORT_ESCAPES:
            out.append(_SHORT_ESCAPES[ch])
        elif point < 0x20:
            # Control characters with no short form. Lower case hex, fixed
            # width, which is what RFC 8785 requires.
            out.append('\\u%04x' % point)
        elif 0xD800 <= point <= 0xDFFF:
            # Python strings can hold an unpaired surrogate; UTF-8 cannot
            # encode one. Refusing is the only honest option, because any
            # substitution would silently alter the data being signed.
            raise ValueError('string contains an unpaired surrogate')
        else:
            out.append(ch)
    out.append('"')
    return ''.join(out)


def _sort_key(key):
    """Object keys sort ascending by UTF-16 code unit.

    Python sorts strings by code point. For anything in the Basic Multilingual
    Plane the two orders agree, so a test set of Latin and accented keys passes
    either way. They diverge above U+FFFF: a character like U+1F600 is a
    surrogate pair in UTF-16 beginning 0xD83D, which sorts below a BMP
    character such as U+FE0F, while by code point it sorts above. Comparing
    big-endian UTF-16 bytes reproduces code unit order exactly.
    """
    return key.encode('utf-16-be')


# ------------------------------------------------------------------ canonicalise

def canonicalize(value):
    """The canonical encoding of a value, as a string.

    This is what a digest is taken over and what a signature covers, so it is
    the one function in the format where being approximately right is the same
    as being wrong.
    """
    if value is None:
        return 'null'
    if value is OMIT:
        raise ValueError('the omit sentinel is not a value; it marks an absent key')
    if isinstance(value, bool):
        return 'true' if value else 'false'
    if isinstance(value, (int, float)):
        return _number(value)
    if isinstance(value, str):
        return _string(value)
    if isinstance(value, (list, tuple)):
        # Arrays keep their order. Order is meaning, so nothing here sorts.
        return '[' + ','.join(canonicalize(v) for v in value) + ']'
    if isinstance(value, dict):
        parts = []
        for key in sorted(value.keys(), key=_sort_key):
            if not isinstance(key, str):
                raise TypeError('object keys must be strings')
            inner = value[key]
            if inner is OMIT:
                # Absent, so the key does not appear at all. Writing null here
                # instead would be a different document with a different
                # digest, which is the distinction the vectors check.
                continue
            parts.append(_string(key) + ':' + canonicalize(inner))
        return '{' + ','.join(parts) + '}'
    raise TypeError('cannot canonicalize %s' % type(value).__name__)


def digest(value):
    """SHA-256 over the canonical encoding, with the format's prefix."""
    encoded = canonicalize(value).encode('utf-8')
    return 'sha256:' + hashlib.sha256(encoded).hexdigest()


def hydrate(value, sentinel='<<omit>>'):
    """Replace the vector file's omit sentinel with the OMIT object.

    The vectors are JSON, so they cannot express an absent key directly and use
    a sentinel string instead. This turns it back into absence before encoding.
    """
    if isinstance(value, str):
        return OMIT if value == sentinel else value
    if isinstance(value, list):
        return [hydrate(v, sentinel) for v in value]
    if isinstance(value, dict):
        return {k: hydrate(v, sentinel) for k, v in value.items()}
    return value


# ---------------------------------------------------------------------- Merkle

# An empty tree is SHA-256 of the empty string, not a zero hash and not an
# error. A log with nothing in it still has a root that can be signed.
EMPTY_ROOT = 'sha256:' + hashlib.sha256(b'').hexdigest()


def leaf_hash(record_digest):
    """SHA-256(0x00 || the ASCII digest string).

    The input is the whole prefixed string, "sha256:" and all, not the decoded
    bytes of the hex. The 0x00 prefix is domain separation and is not optional:
    without it a leaf can be presented as an interior node and the tree can be
    forged.
    """
    return hashlib.sha256(b'\x00' + record_digest.encode('ascii')).digest()


def node_hash(left, right):
    """SHA-256(0x01 || left || right) over the raw 32 byte hashes.

    Raw bytes, not the prefixed hex strings. The specification does not say
    which, and both readings are defensible from its text; the published
    vectors only reconcile with raw bytes. Encoding the children as hex instead
    produces a completely different root that looks exactly like tampering.
    """
    return hashlib.sha256(b'\x01' + left + right).digest()


def split_point(n):
    """The largest power of two strictly less than n.

    Computed by doubling an integer. The specification gives the closed form as
    2^ceil(log2(n) - 1) and then warns against evaluating it in floating point,
    because log2 can land a fraction either side of the true value for one
    specific size, ceil turns that into a whole power of two, and the tree
    splits in the wrong place. There is no reason to go near a float for this.
    """
    if n < 2:
        raise ValueError('a split point needs at least two leaves')
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def _root_of(hashes):
    if len(hashes) == 1:
        return hashes[0]
    k = split_point(len(hashes))
    return node_hash(_root_of(hashes[:k]), _root_of(hashes[k:]))


def merkle_root(record_digests):
    """The root over a list of record digests, as a prefixed hex string."""
    if not record_digests:
        return EMPTY_ROOT
    return 'sha256:' + _root_of([leaf_hash(d) for d in record_digests]).hex()


def inclusion_proof(record_digests, index):
    """Build an inclusion proof for one index, leaf upward.

    A verifier does not need to generate proofs, so this exists for the test
    sweep rather than for production use. It is worth having: generating a
    proof and then verifying it with the separate code path below exercises
    both directions against each other, and an off-by-one in either one shows
    up as a mismatch instead of passing quietly.
    """
    if not record_digests:
        raise ValueError('an empty tree has no inclusion proofs')
    if not 0 <= index < len(record_digests):
        raise IndexError('index %d is outside a tree of %d' % (index, len(record_digests)))

    hashes = [leaf_hash(d) for d in record_digests]
    path = []

    # The sibling subtree is collapsed with _root_of rather than by recursing
    # through this function. The first version of this recursed into siblings
    # with a sentinel target, and because the sentinel compared less than every
    # real offset it took the on-path branch and appended the sibling's own
    # internal nodes to the proof. Trees of 1, 2 and 3 still produced correct
    # proofs, so it looked right until the sweep reached a tree of 4.
    def walk(items, offset, target):
        if len(items) == 1:
            return items[0]
        k = split_point(len(items))
        if target < offset + k:
            mine = walk(items[:k], offset, target)
            sibling = _root_of(items[k:])
            path.append({'side': 'right', 'hash': sibling.hex()})
            return node_hash(mine, sibling)
        sibling = _root_of(items[:k])
        mine = walk(items[k:], offset + k, target)
        path.append({'side': 'left', 'hash': sibling.hex()})
        return node_hash(sibling, mine)

    # Appending after the deeper call returns puts the step nearest the leaf
    # first, which is the order the format specifies.
    walk(hashes, 0, index)
    return {'index': index, 'size': len(record_digests), 'path': path}


def verify_inclusion(record_digest, proof, expected_root):
    """Whether a record is in the tree with the given root.

    The proof is ordered from the leaf upward and each step names the side the
    sibling is on, so "left" means the sibling is the left child and the hash
    carried up goes on the right.
    """
    if proof.get('index', 0) < 0 or proof.get('size', 0) < 0:
        return False
    if proof.get('index', 0) >= max(proof.get('size', 0), 1) and proof.get('size', 0) != 0:
        return False

    current = leaf_hash(record_digest)
    for step in proof.get('path', []):
        sibling = bytes.fromhex(step['hash'])
        side = step['side']
        if side == 'left':
            current = node_hash(sibling, current)
        elif side == 'right':
            current = node_hash(current, sibling)
        else:
            raise ValueError('a proof step must name side left or right, got %r' % side)
    return 'sha256:' + current.hex() == expected_root


def verify_consistency(old_size, new_size, old_root, new_root, proof):
    """Whether the tree of new_size contains the tree of old_size as a prefix.

    RFC 6962 section 2.1.2. An inclusion proof says a record is in a tree; this
    says the tree is the same one that was published before. It is the check
    that detects a log rebuilt to remove something, which an inclusion proof
    against the rebuilt log cannot.

    Returns (ok, reason). A caller has to be able to tell a malformed proof
    from two roots that describe genuinely different trees: the first is a bug
    and the second is an incident.
    """
    if old_size < 0 or new_size < 0:
        return False, 'MALFORMED: a tree size cannot be negative'
    if old_size > new_size:
        # Not a verification failure to be investigated. A log cannot shrink,
        # so this is the answer already.
        return False, 'SHRANK: the log reports fewer records than it was already signed for'
    if old_size == new_size:
        if proof:
            return False, 'MALFORMED: sizes are equal so the proof must be empty'
        if old_root != new_root:
            return False, 'SPLIT_VIEW: two different roots at one size describe two histories'
        return True, 'identical trees'
    if old_size == 0:
        if proof:
            return False, 'MALFORMED: an empty old tree needs no proof'
        return True, 'everything is consistent with an empty tree'

    try:
        path = [bytes.fromhex(h) for h in proof]
    except ValueError:
        return False, 'MALFORMED: a proof hash is not hex'

    # When old_size is a power of two the old root is itself a node of the new
    # tree, so it is left out of the proof and the verifier supplies it. An
    # implementation that misses this fails every power of two case and passes
    # all the others, which is the shape of bug a tidy test set hides.
    if old_size & (old_size - 1) == 0:
        if not old_root.startswith('sha256:'):
            return False, 'MALFORMED: the old root is not a sha256 digest'
        path = [bytes.fromhex(old_root[len('sha256:'):])] + path

    if not path:
        return False, 'MALFORMED: a proof is required for these sizes'

    # fn and sn walk the old and new sizes down the tree together. While the
    # old size is odd the old tree ends inside a node the new tree also has, so
    # both shift until it does not.
    fn = old_size - 1
    sn = new_size - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1

    old_hash = path[0]
    new_hash = path[0]

    for sibling in path[1:]:
        if sn == 0:
            return False, 'MALFORMED: the proof is longer than the tree is deep'
        if (fn & 1) or fn == sn:
            old_hash = node_hash(sibling, old_hash)
            new_hash = node_hash(sibling, new_hash)
            while fn != 0 and not (fn & 1):
                fn >>= 1
                sn >>= 1
        else:
            new_hash = node_hash(new_hash, sibling)
        fn >>= 1
        sn >>= 1

    if sn != 0:
        return False, 'MALFORMED: the proof is too short for the tree'
    if 'sha256:' + old_hash.hex() != old_root:
        return False, 'DIVERGED: the proof does not reconstruct the root that was signed'
    if 'sha256:' + new_hash.hex() != new_root:
        return False, 'DIVERGED: the proof does not reconstruct the new root'
    return True, 'the new tree extends the old one'
