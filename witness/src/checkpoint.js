// The signed checkpoint.
//
// Everything before this file protects a record against alteration by anyone
// who does not hold the signing key. None of it protects against the operator
// of the log, who can stop the service, rebuild the log without a record, and
// start it again. Every signature still verifies. Every chain still links. The
// inconvenient record simply never existed.
//
// A checkpoint is the fix. It is a short, signed statement of the form "at this
// moment my log held exactly this many records and its root was this", handed to
// parties who keep their own copy. Once somebody else holds a checkpoint, the
// operator can no longer change the past quietly: the next checkpoint either
// proves it grew from the one already held, or it does not, and the failure to
// prove it is itself the finding.
//
// The format is newline-delimited text, not JSON, and that is deliberate.
// Canonical JSON is the hardest part of this specification to implement twice;
// it took a second implementation and a conformance suite to settle. A
// checkpoint is five values. Text has no key ordering, no number formatting and
// no escaping to disagree about, it survives being pasted into an email, a
// ticket or a commit message, and a person can read it without a tool. This is
// the same reason Certificate Transparency and the Go checksum database use a
// line format for exactly this object.
//
//   hpx/checkpoint/1
//   medxt-evidence/us-east-1
//   42
//   sha256:5f2c...
//   2026-10-01T12:00:00.000Z
//
//   sig k-log-001 1 ML-DSA-65 <base64>
//   sig k-wit-hhs 1 ML-DSA-65 <base64>
//
// The body is the five lines, each terminated by a newline. The blank line ends
// the body and the signatures follow. Signatures cover the body bytes exactly,
// including the trailing newline and excluding the blank line, so a checkpoint
// gains co-signatures without any signature having to be recomputed. That
// property is what makes witnessing possible at all.

import { VERIFIERS } from './crypto.js';

export const CHECKPOINT_SPEC = 'hpx/checkpoint/1';

// An origin names one log. It goes into the signed bytes so a signature over a
// checkpoint from one log can never be replayed as a checkpoint from another,
// which is the attack a checkpoint without an origin invites.
const ORIGIN = /^[a-z0-9][a-z0-9._\-]{2,63}(\/[a-z0-9][a-z0-9._\-]{0,63})*$/;
const ROOT = /^sha256:[0-9a-f]{64}$/;
const TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const KEY_ID = /^[a-z0-9][a-z0-9\-]{1,63}$/i;
const ALG = /^[A-Za-z0-9\-]{1,32}$/;
const B64 = /^[A-Za-z0-9+/]+={0,2}$/;

export class CheckpointMalformed extends Error {
  constructor(message) { super(message); this.name = 'CheckpointMalformed'; }
}

function assertFields({ origin, size, root, time }) {
  if (typeof origin !== 'string' || !ORIGIN.test(origin)) {
    throw new CheckpointMalformed(`origin ${JSON.stringify(origin)} is not a log name`);
  }
  if (!Number.isInteger(size) || size < 0) {
    throw new CheckpointMalformed(`size ${JSON.stringify(size)} is not a count of records`);
  }
  if (typeof root !== 'string' || !ROOT.test(root)) {
    throw new CheckpointMalformed(`root ${JSON.stringify(root)} is not a sha256 root`);
  }
  if (typeof time !== 'string' || !TIME.test(time)) {
    throw new CheckpointMalformed(`time ${JSON.stringify(time)} is not an instant with milliseconds in UTC`);
  }
  // A time that does not round trip is not a time. 2026-02-30 matches the
  // pattern and is not a date.
  if (new Date(time).toISOString() !== time) {
    throw new CheckpointMalformed(`time ${time} is not a real instant`);
  }
  return { origin, size, root, time };
}

/**
 * The exact bytes a signature covers. Nothing else is ever signed.
 */
export function checkpointBody(fields) {
  const { origin, size, root, time } = assertFields(fields);
  return `${CHECKPOINT_SPEC}\n${origin}\n${size}\n${root}\n${time}\n`;
}

const te = new TextEncoder();
export const bodyBytes = fields => te.encode(checkpointBody(fields));

const sigLine = s => `sig ${s.keyId} ${s.version} ${s.alg} ${s.value}`;

/**
 * Assemble a checkpoint document from a body and a set of signatures.
 */
export function formatCheckpoint(fields, signatures) {
  if (!Array.isArray(signatures) || signatures.length === 0) {
    throw new CheckpointMalformed('a checkpoint with no signature is not a checkpoint');
  }
  return checkpointBody(fields) + '\n' + signatures.map(sigLine).join('\n') + '\n';
}

/**
 * Sign a checkpoint. The log does this; a witness does the same thing to an
 * existing document through cosign below.
 */
export function signCheckpoint(fields, signer, { keyId, version, alg = 'ML-DSA-65' }) {
  if (!KEY_ID.test(keyId ?? '')) throw new CheckpointMalformed(`key id ${JSON.stringify(keyId)} is not usable`);
  if (!Number.isInteger(version) || version < 0) throw new CheckpointMalformed('a key version is required');
  return formatCheckpoint(fields, [{ keyId, version, alg, value: signer.sign(bodyBytes(fields)) }]);
}

/**
 * Add a signature to a document without disturbing the ones already on it.
 *
 * The body is reused verbatim rather than rebuilt from the parsed fields. If a
 * co-signer rebuilt the body and its formatting differed by one byte, it would
 * be signing a different statement while appearing to endorse this one.
 */
export function cosign(document, signer, { keyId, version, alg = 'ML-DSA-65' }) {
  const cp = parseCheckpoint(document);
  if (!KEY_ID.test(keyId ?? '')) throw new CheckpointMalformed(`key id ${JSON.stringify(keyId)} is not usable`);
  if (cp.signatures.some(s => s.keyId === keyId && s.version === version)) {
    throw new CheckpointMalformed(`${keyId}#${version} has already signed this checkpoint`);
  }
  const value = signer.sign(te.encode(cp.body));
  return cp.body + '\n' + [...cp.signatures, { keyId, version, alg, value }].map(sigLine).join('\n') + '\n';
}

/**
 * Parse a document. Strict, because a checkpoint is the one object in this
 * system that is expected to be stored by people who do not run the log, moved
 * between systems, and read years later. Anything this accepts, it has to
 * accept forever.
 */
export function parseCheckpoint(document) {
  if (typeof document !== 'string') throw new CheckpointMalformed('a checkpoint is text');
  // Carriage returns are refused rather than stripped. Stripping them means the
  // bytes verified are not the bytes stored, and a checkpoint whose stored form
  // differs from its verified form is worthless as evidence.
  if (document.includes('\r')) throw new CheckpointMalformed('a checkpoint contains no carriage returns');

  const parts = document.split('\n\n');
  if (parts.length !== 2) throw new CheckpointMalformed('a checkpoint is a body, a blank line, then signatures');
  const [bodyText, sigText] = parts;
  const lines = bodyText.split('\n');
  if (lines.length !== 5) throw new CheckpointMalformed(`a body has five lines, this has ${lines.length}`);
  const [spec, origin, sizeText, root, time] = lines;
  if (spec !== CHECKPOINT_SPEC) throw new CheckpointMalformed(`unknown checkpoint spec ${JSON.stringify(spec)}`);
  // Leading zeros and signs would give one size two spellings and therefore two
  // different signed statements.
  if (!/^(0|[1-9][0-9]*)$/.test(sizeText)) throw new CheckpointMalformed(`size ${JSON.stringify(sizeText)} is not a plain integer`);

  const fields = assertFields({ origin, size: Number(sizeText), root, time });

  // The signature block ends with exactly one newline and contains no blank
  // lines. Tolerating a stray blank line would mean two different byte
  // sequences parse to the same checkpoint, and a checkpoint is specifically an
  // object whose stored bytes have to be the bytes that were verified.
  if (!sigText.endsWith('\n')) throw new CheckpointMalformed('the signature block must end with a newline');
  const sigLines = sigText.slice(0, -1).split('\n');
  if (sigLines.some(l => l.length === 0)) throw new CheckpointMalformed('the signature block contains a blank line');

  const signatures = [];
  for (const line of sigLines) {
    const m = /^sig ([^ ]+) ([^ ]+) ([^ ]+) ([^ ]+)$/.exec(line);
    if (!m) throw new CheckpointMalformed(`unreadable signature line ${JSON.stringify(line)}`);
    const [, keyId, versionText, alg, value] = m;
    if (!KEY_ID.test(keyId)) throw new CheckpointMalformed(`key id ${JSON.stringify(keyId)} is not usable`);
    if (!/^(0|[1-9][0-9]*)$/.test(versionText)) throw new CheckpointMalformed(`key version ${JSON.stringify(versionText)} is not an integer`);
    if (!ALG.test(alg)) throw new CheckpointMalformed(`algorithm ${JSON.stringify(alg)} is not usable`);
    if (!B64.test(value)) throw new CheckpointMalformed('a signature value is not base64');
    // Two signatures from one key on one checkpoint is either a bug or an
    // attempt to make a quorum count look larger than it is.
    if (signatures.some(s => s.keyId === keyId && s.version === Number(versionText))) {
      throw new CheckpointMalformed(`${keyId}#${versionText} appears twice`);
    }
    signatures.push({ keyId, version: Number(versionText), alg, value });
  }
  if (signatures.length === 0) throw new CheckpointMalformed('a checkpoint carries at least one signature');

  // The body including its trailing newline, which is what was signed.
  return { ...fields, body: bodyText + '\n', signatures };
}

/**
 * Verify a document against a key registry.
 *
 * Returns which keys signed it validly rather than a single boolean, because a
 * quorum rule is a policy decision made by whoever is relying on the checkpoint
 * and not something this function should be making on their behalf.
 */
export function verifyCheckpoint(document, registry, { verifiers = VERIFIERS } = {}) {
  let cp;
  try { cp = parseCheckpoint(document); }
  catch (err) { return { ok: false, problems: [err.message], signedBy: [], checkpoint: null }; }

  const problems = [];
  const signedBy = [];
  const bytes = te.encode(cp.body);

  for (const s of cp.signatures) {
    const key = registry.resolve(s.keyId, s.version);
    if (!key) { problems.push(`${s.keyId}#${s.version} is not in the registry`); continue; }
    const verifier = verifiers[s.alg];
    if (!verifier) { problems.push(`unsupported algorithm ${s.alg} on ${s.keyId}#${s.version}`); continue; }
    if (!verifier(s.value, bytes, key.publicKey)) { problems.push(`signature from ${s.keyId}#${s.version} does not verify`); continue; }
    // A retired key still verifies what it signed while it was in service, and
    // a checkpoint carries the time it was made, so this is checkable.
    if (key.status === 'retired' && key.notAfter && cp.time > key.notAfter) {
      problems.push(`${s.keyId}#${s.version} was retired at ${key.notAfter} but signed a checkpoint at ${cp.time}`);
      continue;
    }
    signedBy.push({ keyId: s.keyId, version: s.version, owner: key.owner });
  }

  return {
    // Valid means at least one signature verified and nothing is in a state the
    // verifier cannot explain. An unknown key is reported and does not by
    // itself invalidate a checkpoint a known key signed.
    ok: signedBy.length > 0,
    problems,
    signedBy,
    checkpoint: { origin: cp.origin, size: cp.size, root: cp.root, time: cp.time }
  };
}
