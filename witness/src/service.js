// A witness, as something somebody else runs.
//
// The Witness class proves continuity and refuses when it is not proved. This
// wraps it in the smallest service that an organisation with no relationship
// to MedXT can operate, because independence is the entire value and
// independence is organisational, not cryptographic. A witness we run is
// theatre. The code is identical either way; only the custody of the key is
// different, and that is the part that matters.
//
// What a witness operator is signing up for, stated plainly because anyone
// asked to run one deserves to know before they agree:
//
//   It sees no clinical data. A checkpoint is an origin, a count, a hash and
//   a time. There is no patient, no provider, no diagnosis and no money in
//   anything this service receives.
//
//   It holds one secret, its own signing key, and that key signs nothing but
//   checkpoints. It cannot create evidence, alter evidence, or approve a
//   payment.
//
//   It needs almost nothing: a few megabytes of disk, no inbound access to
//   anything of yours, and no attention unless it refuses something.
//
//   If it refuses, that refusal is the product. It means the log asked for a
//   signature on a history inconsistent with the one already endorsed, which
//   is the event the entire system exists to make visible.
//
// Three properties, in order of how badly their absence would matter.
//
// 1. It refuses by default. Anything it cannot verify is refused, recorded and
//    returned as a refusal. There is no path through this service that
//    produces a signature on an unproven checkpoint.
//
// 2. Its memory is durable and tamper evident before it signs. A witness that
//    forgets endorses the rewrite it exists to catch.
//
// 3. What it has endorsed is public. A witness nobody can query is a witness
//    nobody can hold to account, and the regress just moves one step along.

import { createServer } from 'node:http';

import { Witness, SplitView, meetsQuorum } from './witness.js';
import { DurableWitnessState, readJournal, WitnessStateError }
  from './witness-state.js';
import { KeyRegistry } from './crypto.js';
import { verifyCheckpoint, parseCheckpoint } from './checkpoint.js';

// A checkpoint is a few hundred bytes. Anything approaching this is not a
// checkpoint, and refusing at the boundary is cheaper than parsing it.
const MAX_BODY_BYTES = 64 * 1024;

export class WitnessService {
  /**
   * @param {object} opts
   * @param {object} opts.witness   a Witness, already holding its signer and state
   * @param {string} opts.name      what this witness calls itself in its answers
   */
  constructor({ witness, name = 'an independent witness' }) {
    if (!witness) throw new Error('a witness service needs a Witness');
    this.witness = witness;
    this.name = name;
  }

  /**
   * Co-sign a checkpoint, or refuse it and say exactly why.
   *
   * The refusal path is not an error path. A refusal is a successful,
   * meaningful answer and the caller gets the detail: what was offered, what
   * was previously endorsed, and which check failed. Returning a bare 500
   * would turn the most important output this system produces into an
   * operational blip somebody silences.
   */
  cosign({ document, consistencyProof }) {
    if (typeof document !== 'string' || !document.trim()) {
      return { status: 400, body: { error: 'a checkpoint document is required' } };
    }
    try {
      const result = this.witness.cosign(document, { consistencyProof });
      const cp = parseCheckpoint(result.document);
      return {
        status: 200,
        body: {
          cosigned: true,
          document: result.document,
          first: result.first,
          verified: result.verified,
          note: result.note,
          origin: cp.origin,
          size: cp.size,
          witness: this.name
        }
      };
    } catch (e) {
      if (e instanceof SplitView) {
        // 409, not 500. The service is working perfectly; the log is not.
        return {
          status: 409,
          body: {
            cosigned: false,
            refused: e.message,
            origin: e.origin ?? null,
            previouslyEndorsed: e.prior ?? null,
            offered: e.offered ?? null,
            needs: e.needs ?? null,
            witness: this.name,
            note: 'This witness will not sign a checkpoint inconsistent with the ' +
                  'history it already endorsed. The refusal is recorded and will ' +
                  'remain on the public record of this witness.'
          }
        };
      }
      if (e instanceof WitnessStateError) {
        // The witness cannot trust its own memory, so it must not sign. This
        // is the one case where being unavailable is correct.
        return { status: 503, body: { cosigned: false, error: e.message, code: e.code } };
      }
      return { status: 400, body: { cosigned: false, error: e.message } };
    }
  }

  /** What this witness last endorsed for every log it watches. */
  endorsements() {
    return {
      witness: this.name,
      watching: this.witness.state.watching?.() ?? [],
      tip: this.witness.state.tip?.() ?? null
    };
  }

  /**
   * Every refusal this witness has ever recorded.
   *
   * Public on purpose. A refusal that only the witness operator can see is
   * worth very little; the point is that anyone relying on the log can check
   * whether its witness has ever been asked for something it would not sign.
   */
  refusals() {
    return {
      witness: this.name,
      refusals: this.witness.state.refusals?.() ?? [],
      note: 'An empty list means this witness has never been asked to endorse a ' +
            'checkpoint it could not reconcile. It does not mean the log is honest, ' +
            'only that it has not been caught being otherwise by this witness.'
    };
  }
}

// ----------------------------------------------------------------- transport
export function createWitnessServer(service, { log = () => {} } = {}) {
  return createServer((req, res) => {
    const send = (status, body) => {
      const text = JSON.stringify(body, null, 2) + '\n';
      res.writeHead(status, {
        'content-type': 'application/json',
        'content-length': Buffer.byteLength(text),
        // A witness answers questions about itself. It never embeds anything.
        'x-content-type-options': 'nosniff'
      });
      res.end(text);
    };

    const url = new URL(req.url, 'http://witness.local');

    if (req.method === 'GET' && url.pathname === '/v1/endorsements') {
      return send(200, service.endorsements());
    }
    if (req.method === 'GET' && url.pathname === '/v1/refusals') {
      return send(200, service.refusals());
    }
    if (req.method === 'GET' && url.pathname === '/health') {
      // Deliberately reports whether the memory is readable, because a witness
      // whose journal is gone is not healthy even though the process is up.
      try {
        const tip = service.witness.state.tip?.();
        return send(200, { ok: true, witness: service.name, tip });
      } catch (e) {
        return send(503, { ok: false, error: e.message });
      }
    }

    if (req.method !== 'POST' || url.pathname !== '/v1/cosign') {
      return send(404, {
        error: 'not found',
        endpoints: ['POST /v1/cosign', 'GET /v1/endorsements', 'GET /v1/refusals', 'GET /health']
      });
    }

    let size = 0;
    const chunks = [];
    req.on('data', c => {
      size += c.length;
      if (size > MAX_BODY_BYTES) {
        send(413, { error: 'a checkpoint is a few hundred bytes; this is not one' });
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => {
      if (res.writableEnded) return;
      let body;
      try {
        body = JSON.parse(Buffer.concat(chunks).toString('utf8'));
      } catch {
        return send(400, { error: 'body is not JSON' });
      }
      const result = service.cosign(body);
      log(result.status, result.body);
      send(result.status, result.body);
    });
  });
}

/**
 * Build a witness from a key, a journal path and the log keys it will check.
 *
 * Separated from the service so an operator can construct one in a script, and
 * so the refusal to start without a journal is unmissable at startup rather
 * than at the first request.
 */
export function buildWitness({ signer, keyId, version = 1, logKeys, journalPath, initialize = false, name }) {
  const state = new DurableWitnessState(journalPath, { initialize });
  // The log's public keys arrive as the registry's own export format, which is
  // hex. KeyRegistry.import decodes it. Registering the entries directly would
  // leave the public keys as hex strings where the verifier expects bytes, and
  // every signature check would fail for a reason that looks like tampering.
  const registry = logKeys instanceof KeyRegistry ? logKeys : KeyRegistry.import(logKeys);
  const witness = new Witness({ signer, keyId, version, logKeys: registry, state });
  return new WitnessService({ witness, name });
}

export { meetsQuorum, verifyCheckpoint, readJournal };
