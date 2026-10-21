import { rawHash, hex } from './hash.js';

// RFC 6962 domain separation. Leaves are prefixed 0x00 and interior nodes 0x01
// so no leaf can ever be presented as an interior node.
const LEAF = 0x00, NODE = 0x01;
const cat = (...arrs) => { const out = new Uint8Array(arrs.reduce((n,a)=>n+a.length,0));
  let o = 0; for (const a of arrs) { out.set(a, o); o += a.length; } return out; };
const te = new TextEncoder();
const leafHash = d => rawHash(cat(Uint8Array.of(LEAF), te.encode(d)));
const nodeHash = (l, r) => rawHash(cat(Uint8Array.of(NODE), l, r));

// The largest power of two strictly less than n, computed in integers.
//
// The obvious form is 2 ** Math.ceil(Math.log2(n) - 1), and it is wrong at
// sizes this log will reach. Math.log2 is a floating point operation: for some
// n it returns a value a fraction above or below the true logarithm, ceil
// amplifies that fraction into a whole power of two, and the tree splits in the
// wrong place. The failure is silent and it looks exactly like tampering,
// because a root computed with a different split does not match.
//
// This is also the one place where the Go verifier had to agree with this file
// bit for bit, so it is written the way an integer implementation would be.
export function splitPoint(n) {
  if (!Number.isInteger(n) || n < 2) throw new Error(`split point is undefined for size ${n}`);
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

const isPowerOfTwo = n => n > 0 && (n & (n - 1)) === 0;
const fromHex = h => Uint8Array.from(Buffer.from(h, 'hex'));
const asRoot = bytes => 'sha256:' + hex(bytes);
const rootBytes = root => {
  if (typeof root !== 'string' || !root.startsWith('sha256:')) throw new Error(`unreadable root ${root}`);
  const h = root.slice(7);
  if (!/^[0-9a-f]{64}$/.test(h)) throw new Error(`unreadable root ${root}`);
  return fromHex(h);
};

// One signature covers the whole tree. Each record gets an inclusion proof of a
// few hundred bytes instead of its own 3.3 kilobyte signature. At national volume
// that is the difference between terabytes of signatures and gigabytes.
export class MerkleLog {
  constructor() { this.leaves = []; }
  add(recordDigest) { this.leaves.push(leafHash(recordDigest)); return this.leaves.length - 1; }

  _root(list) {
    if (list.length === 0) return rawHash(new Uint8Array(0));
    if (list.length === 1) return list[0];
    const split = splitPoint(list.length);
    return nodeHash(this._root(list.slice(0, split)), this._root(list.slice(split)));
  }
  root() { return asRoot(this._root(this.leaves)); }

  // The root the log had at an earlier size. This is what makes a checkpoint
  // auditable after the fact: a reviewer holding an old checkpoint can ask the
  // log to prove the tree it has now grew from the tree it signed then.
  rootAt(size) {
    if (!Number.isInteger(size) || size < 0 || size > this.leaves.length) {
      throw new Error(`no root at size ${size}; the log holds ${this.leaves.length}`);
    }
    return asRoot(this._root(this.leaves.slice(0, size)));
  }

  inclusionProof(index) {
    const path = [];
    const walk = (list, i) => {
      if (list.length <= 1) return;
      const split = splitPoint(list.length);
      if (i < split) { path.push({ side: 'right', hash: hex(this._root(list.slice(split))) }); walk(list.slice(0, split), i); }
      else { path.push({ side: 'left', hash: hex(this._root(list.slice(0, split))) }); walk(list.slice(split), i - split); }
    };
    walk(this.leaves, index);
    return { index, size: this.leaves.length, path: path.reverse() };
  }

  /**
   * RFC 6962 section 2.1.2. A proof that the tree of `newSize` leaves contains
   * the tree of `oldSize` leaves as a prefix, unchanged.
   *
   * This is the proof that makes an external anchor worth publishing. An
   * inclusion proof says a record is in a tree. A consistency proof says the
   * tree the operator is showing you today is the same tree it showed you last
   * week with records added, and not a second tree built after the fact with an
   * inconvenient record left out. Without it, an operator can publish a root,
   * rebuild the log, and publish a new root that is internally perfect and has
   * no relationship to the first.
   */
  consistencyProof(oldSize, newSize = this.leaves.length) {
    if (!Number.isInteger(oldSize) || !Number.isInteger(newSize)) throw new Error('sizes must be integers');
    if (oldSize < 0 || newSize > this.leaves.length) {
      throw new Error(`sizes ${oldSize} and ${newSize} are outside a log of ${this.leaves.length}`);
    }
    // A log cannot shrink. Asked to prove it did, it refuses rather than
    // producing something that will fail verification for an unexplained reason.
    if (oldSize > newSize) throw new Error(`a log cannot shrink: ${newSize} is smaller than ${oldSize}`);
    if (oldSize === 0 || oldSize === newSize) return { oldSize, newSize, path: [] };

    const path = [];
    const sub = (m, list, isOldRoot) => {
      if (m === list.length) {
        // The whole of this subtree is the old tree. Its root is only sent when
        // it is not already known to the verifier, which it is when the old
        // tree is not itself a complete subtree of the new one.
        if (!isOldRoot) path.push(hex(this._root(list)));
        return;
      }
      const k = splitPoint(list.length);
      if (m <= k) {
        sub(m, list.slice(0, k), isOldRoot);
        path.push(hex(this._root(list.slice(k))));
      } else {
        sub(m - k, list.slice(k), false);
        path.push(hex(this._root(list.slice(0, k))));
      }
    };
    sub(oldSize, this.leaves.slice(0, newSize), true);
    return { oldSize, newSize, path };
  }
}

export function verifyInclusion(recordDigest, proof, expectedRoot) {
  let acc = leafHash(recordDigest);
  for (const step of proof.path) {
    const sib = fromHex(step.hash);
    acc = step.side === 'right' ? nodeHash(acc, sib) : nodeHash(sib, acc);
  }
  return asRoot(acc) === expectedRoot;
}

/**
 * Verify a consistency proof.
 *
 * Returns { ok, reason }. A reason rather than a bare false, because the
 * difference between "this proof is malformed" and "these two roots describe
 * different trees" is the difference between a bug and an incident.
 */
export function verifyConsistency({ oldRoot, oldSize, newRoot, newSize, path }) {
  if (!Number.isInteger(oldSize) || !Number.isInteger(newSize) || oldSize < 0 || newSize < 0) {
    return { ok: false, reason: 'sizes must be non negative integers' };
  }
  // The headline failure. A log that reports a smaller size than one it has
  // already signed for has either lost data or is serving a second history.
  if (oldSize > newSize) return { ok: false, reason: `the log shrank from ${oldSize} to ${newSize}` };

  let steps;
  try { steps = (path ?? []).map(fromHex); } catch { return { ok: false, reason: 'proof path is not readable' }; }
  if ((path ?? []).some(h => !/^[0-9a-f]{64}$/.test(h))) return { ok: false, reason: 'proof path is not readable' };

  if (oldSize === newSize) {
    if (steps.length !== 0) return { ok: false, reason: 'a proof of no change must be empty' };
    return oldRoot === newRoot
      ? { ok: true, reason: null }
      : { ok: false, reason: 'the same size reports two different roots' };
  }
  // Everything is consistent with an empty tree, and there is nothing to prove.
  if (oldSize === 0) {
    return steps.length === 0 ? { ok: true, reason: null } : { ok: false, reason: 'a proof from an empty tree must be empty' };
  }

  let expectedOld, expectedNew;
  try { expectedOld = rootBytes(oldRoot); expectedNew = rootBytes(newRoot); }
  catch (err) { return { ok: false, reason: err.message }; }

  // When the old size is a power of two the old root is itself a node of the
  // new tree, so the proof omits it and the verifier supplies it. Omitting this
  // step makes every such proof fail, and power of two sizes are exactly the
  // ones a test with a tidy number of records will hit.
  if (isPowerOfTwo(oldSize)) steps = [expectedOld, ...steps];
  if (steps.length === 0) return { ok: false, reason: 'proof is empty but the tree grew' };

  let fn = oldSize - 1, sn = newSize - 1;
  while (fn & 1) { fn >>= 1; sn >>= 1; }

  let fr = steps[0], sr = steps[0], i = 1;
  while (sn > 0) {
    if (i >= steps.length) return { ok: false, reason: 'proof ended before the tree was reconstructed' };
    if ((fn & 1) || fn === sn) {
      fr = nodeHash(steps[i], fr);
      sr = nodeHash(steps[i], sr);
      while (fn !== 0 && !(fn & 1)) { fn >>= 1; sn >>= 1; }
    } else {
      sr = nodeHash(sr, steps[i]);
    }
    i++;
    fn >>= 1; sn >>= 1;
  }

  if (i !== steps.length) return { ok: false, reason: 'proof carries more steps than the tree needs' };
  if (asRoot(fr) !== asRoot(expectedOld)) {
    return { ok: false, reason: 'the proof does not reconstruct the earlier root' };
  }
  if (asRoot(sr) !== asRoot(expectedNew)) {
    return { ok: false, reason: 'the proof does not reconstruct the current root' };
  }
  return { ok: true, reason: null };
}
