// The witness.
//
// A checkpoint signed only by the log that produced it proves nothing against
// the log. The operator who can rebuild the log can also sign a checkpoint for
// the rebuilt version, and a reviewer holding only that checkpoint has no way to
// tell. Publishing roots on a schedule, to a location the operator controls, is
// the same problem with more steps.
//
// A witness is the smallest thing that closes it. It remembers one line per log
// and it will co-sign a new checkpoint only after being shown that the new tree
// grew from the tree it last endorsed. It makes no judgement about records, sees
// no clinical content, and holds no secrets beyond its own signing key: a
// checkpoint is an origin, a count, a hash and a time.
//
// The protection is specifically this. To rewrite history the operator now has
// to obtain a co-signature on a checkpoint that is not consistent with the one
// the witness already signed. The witness refuses, and the refusal is the
// detection. If the operator stops asking, the absence of fresh co-signed
// checkpoints is itself visible to anyone watching.
//
// Two honest limits.
//
// A witness that has never seen a log before cannot validate its history. It
// can only start from what it is shown. It says so rather than implying it
// checked, because a first checkpoint that reads like an endorsement of
// everything before it would be the most misleading object in the system.
//
// One witness run by the operator is theatre. The value comes entirely from
// independence, and independence is an organisational property that no amount
// of code establishes. That belongs in the deployment decision, not here.

import { parseCheckpoint, verifyCheckpoint, cosign } from './checkpoint.js';
import { verifyConsistency } from './merkle.js';

export class SplitView extends Error {
  constructor(message, detail) {
    super(message);
    this.name = 'SplitView';
    Object.assign(this, detail);
  }
}

export class Witness {
  /**
   * @param {object} opts
   * @param {object} opts.signer      something with sign(bytes)
   * @param {string} opts.keyId       this witness's key
   * @param {number} opts.version
   * @param {object} opts.logKeys     KeyRegistry holding the logs' public keys
   * @param {Map}    [opts.state]     origin -> { size, root, time }, injectable so
   *                                  a real deployment can make it durable
   */
  constructor({ signer, keyId, version = 1, logKeys, state = new Map() }) {
    if (!signer || typeof signer.sign !== 'function') throw new Error('a witness needs a signer');
    if (!keyId) throw new Error('a witness needs a key id');
    if (!logKeys || typeof logKeys.resolve !== 'function') throw new Error('a witness needs the log public keys');
    this.signer = signer;
    this.keyId = keyId;
    this.version = version;
    this.logKeys = logKeys;
    this.state = state;
  }

  /** What this witness last endorsed for a log, or null if it has seen none. */
  last(origin) { return this.state.get(origin) ?? null; }

  /**
   * Co-sign a checkpoint, or refuse and say why.
   *
   * @param {string} document              the log's signed checkpoint
   * @param {object} [opts]
   * @param {string[]} [opts.consistencyProof]  required whenever the log has grown
   * @returns {{ document: string, first: boolean, verified: boolean, note: string }}
   */
  cosign(document, { consistencyProof } = {}) {
    // The log's own signature first. Without this a witness can be made to
    // endorse a checkpoint the log never issued, which turns it from a control
    // into a laundering service for whatever an attacker wants to publish.
    const v = verifyCheckpoint(document, this.logKeys);
    if (!v.ok) {
      throw this._refuse(null, 'the checkpoint is not validly signed by the log',
                         { problems: v.problems });
    }
    const cp = parseCheckpoint(document);
    const prior = this.last(cp.origin);

    if (!prior) {
      // Nothing to compare against. Recorded, co-signed, and labelled for what
      // it is.
      //
      // Recorded BEFORE signing, here and in both branches below. A crash
      // between the two can then only lose the signature, which costs nothing
      // because the log simply asks again. The other order loses the memory of
      // having signed, and a witness that has issued a co-signature it does not
      // remember will accept a conflicting checkpoint next time, which is the
      // precise failure this whole class exists to prevent.
      this.state.set(cp.origin, { size: cp.size, root: cp.root, time: cp.time });
      const signed = this._sign(document);
      return {
        document: signed, first: true, verified: false,
        note: `First checkpoint seen for ${cp.origin}. This witness co-signs that it observed size ${cp.size} at ${cp.time}. It makes no statement about anything before that.`
      };
    }

    // A log that reports fewer records than it has already been witnessed for
    // has either lost data or is serving a second history. Both are incidents.
    if (cp.size < prior.size) {
      throw this._refuse(cp.origin,
`${cp.origin} reports ${cp.size} records having been witnessed at ${prior.size}`,
{ origin: cp.origin, prior, offered: { size: cp.size, root: cp.root, time: cp.time } });
    }

    if (cp.size === prior.size) {
      if (cp.root !== prior.root) {
        // The clearest possible evidence of two histories, and it needs no proof.
        throw this._refuse(cp.origin,
`${cp.origin} offers a different root at size ${cp.size}`,
{ origin: cp.origin, prior, offered: { size: cp.size, root: cp.root, time: cp.time } });
      }
      // Same tree, later time. Co-signing is still useful: it is evidence the
      // log was alive and unchanged at this moment.
      if (cp.time < prior.time) {
        throw this._refuse(cp.origin,
`${cp.origin} offers a checkpoint timed ${cp.time}, before the ${prior.time} already witnessed`,
{ origin: cp.origin, prior, offered: { size: cp.size, root: cp.root, time: cp.time } });
      }
      this.state.set(cp.origin, { size: cp.size, root: cp.root, time: cp.time });
      const signed = this._sign(document);
      return { document: signed, first: false, verified: true, note: `Unchanged at size ${cp.size}.` };
    }

    // The log grew. Nothing is co-signed without proof that it grew from the
    // tree this witness already endorsed. A missing proof is a refusal, not a
    // reason to accept on trust: that default is the entire difference between
    // a witness and a rubber stamp.
    if (!Array.isArray(consistencyProof)) {
      throw this._refuse(cp.origin,
`${cp.origin} grew from ${prior.size} to ${cp.size} without a consistency proof`,
{ origin: cp.origin, prior, offered: { size: cp.size, root: cp.root, time: cp.time }, needs: 'consistencyProof' });
    }
    const consistent = verifyConsistency({
      oldRoot: prior.root, oldSize: prior.size,
      newRoot: cp.root, newSize: cp.size,
      path: consistencyProof
    });
    if (!consistent.ok) {
      throw this._refuse(cp.origin,
`${cp.origin} cannot prove it grew from the tree already witnessed: ${consistent.reason}`,
{ origin: cp.origin, prior, offered: { size: cp.size, root: cp.root, time: cp.time }, reason: consistent.reason });
    }
    if (cp.time < prior.time) {
      throw this._refuse(cp.origin,
`${cp.origin} offers a checkpoint timed ${cp.time}, before the ${prior.time} already witnessed`,
{ origin: cp.origin, prior, offered: { size: cp.size, root: cp.root, time: cp.time } });
    }

    // State moves only after everything has passed. A witness that advanced its
    // state on a refused checkpoint would accept the rewrite on the next try.
    this.state.set(cp.origin, { size: cp.size, root: cp.root, time: cp.time });
    const signed = this._sign(document);
    return {
      document: signed, first: false, verified: true,
      note: `Grew from ${prior.size} to ${cp.size} and proved consistent with the tree previously witnessed.`
    };
  }

  /**
   * Persist a refusal, then build the error to throw.
   *
   * A split view that is detected and then lost when the process exits is not
   * evidence of anything, and the refusal is the most valuable object this
   * system produces. It is written down first so that it survives whatever
   * happens next, including the operator killing the witness on seeing it.
   *
   * Stores that cannot record a refusal, such as a plain Map in a test, simply
   * do not get one. The error is unchanged either way.
   */
  _refuse(origin, message, detail = {}) {
    if (typeof this.state.refuse === 'function') {
      try {
        this.state.refuse(origin, message, detail);
      } catch (e) {
        // A witness that cannot write down a refusal is a witness whose memory
        // is already compromised, so say both things rather than hiding one
        // behind the other.
        return new SplitView(
          `${message}. The refusal could also not be recorded: ${e.message}`,
          { ...detail, recordFailed: true });
      }
    }
    return new SplitView(message, detail);
  }

  _sign(document) {
    return cosign(document, this.signer, { keyId: this.keyId, version: this.version });
  }
}

/**
 * Whether a checkpoint carries enough independent signatures to be relied on.
 *
 * Kept separate from the witness because the threshold is a policy decision by
 * whoever relies on the checkpoint. A reviewer holding a checkpoint should be
 * able to apply their own rule rather than the log's.
 */
export function meetsQuorum(verifyResult, { logKeyId, witnesses = 1 }) {
  if (!verifyResult.ok) return { ok: false, reason: 'the checkpoint is not validly signed' };
  const signers = verifyResult.signedBy;
  if (!signers.some(s => s.keyId === logKeyId)) {
    return { ok: false, reason: `the log key ${logKeyId} did not sign this checkpoint` };
  }
  const cosigners = signers.filter(s => s.keyId !== logKeyId);
  if (cosigners.length < witnesses) {
    return { ok: false, reason: `${cosigners.length} independent signatures, ${witnesses} required` };
  }
  return { ok: true, reason: null, cosigners: cosigners.map(c => c.owner ?? c.keyId) };
}
