// Every signing call goes through this interface and nothing else calls a crypto
// library directly. That is what makes the FIPS swap a deployment change rather
// than a rewrite: the federal build registers a validated-module signer here.
//
// Why there are two of these files
//
// This one holds what a record needs: the ML-DSA-65 signer, the key registry,
// and the capabilities a key may hold. crypto-possession.js holds what
// authentication needs, which at present is a secp256k1 verifier over an
// EIP-191 digest and the decoy keys that make a refusal cost what an
// acceptance costs.
//
// The split is not tidiness. This file is published verbatim as part of the
// public witness in med-xt/hpx-verifier, because a witness nobody can inspect
// is not independent in any sense that survives a question, and CI refuses a
// push where the two copies differ. The witness uses exactly three things
// from here: MlDsa65Signer, KeyRegistry and VERIFIERS. Putting the
// authentication code in the same file would make the published witness
// depend on an elliptic curve library for code it never calls, and would put
// an Ethereum signature prefix into the one artifact whose whole purpose is
// that a third party can read it and find nothing surprising.
//
// Rule 3 of CLAUDE.md says all crypto goes through the Signer interface here
// and nothing else imports a cryptographic library. That rule now names two
// files. Its purpose is unchanged: both implement the same interface, both
// are the only importers, and a validated module is still registered rather
// than rewritten into.
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';

const b64 = b => Buffer.from(b).toString('base64');
const unb64 = s => new Uint8Array(Buffer.from(s, 'base64'));

export class MlDsa65Signer {
  static alg = 'ML-DSA-65';
  constructor(secretKey) { this.secretKey = secretKey; }
  static generate() {
    const { publicKey, secretKey } = ml_dsa65.keygen();
    return { signer: new MlDsa65Signer(secretKey), publicKey };
  }
  /**
   * Load a key that already exists, rather than minting a new one.
   *
   * generate() is for tests and demonstrations. A deployment is handed a key
   * that somebody is responsible for, and a service that generates one at
   * startup would sign records under a facility that has never heard of it.
   * Those records would verify, which is the problem.
   *
   * The public key is derived rather than supplied, so a configuration cannot
   * pair a private key with somebody else's public one and produce signatures
   * that fail verification for a reason nobody can find.
   */
  static fromSecret(hexOrBytes) {
    const secretKey = typeof hexOrBytes === 'string' ? hexToBytes(hexOrBytes.trim()) : hexOrBytes;
    if (!(secretKey instanceof Uint8Array) || secretKey.length !== ml_dsa65.lengths.secretKey) {
      throw new Error(
        `an ML-DSA-65 secret key is ${ml_dsa65.lengths.secretKey} bytes; got ` +
        `${secretKey?.length ?? typeof secretKey}`);
    }
    const { publicKey } = ml_dsa65.keygen ? { publicKey: ml_dsa65.getPublicKey(secretKey) } : {};
    return { signer: new MlDsa65Signer(secretKey), publicKey };
  }
  sign(bytes) { return b64(ml_dsa65.sign(bytes, this.secretKey)); }
  static verify(sigB64, bytes, publicKey) {
    try { return ml_dsa65.verify(unb64(sigB64), bytes, publicKey); }
    catch { return false; }
  }
}

/**
 * What a key is allowed to do.
 *
 * A facility signs clinical records with a key. If that same key can also
 * answer a login challenge, then a login endpoint is a signing oracle for
 * records, and the only thing standing between the two is the convention that
 * the challenge body starts with a spec string. A convention held in one
 * file is not a boundary. A key that cannot produce a record signature at all
 * is a boundary.
 *
 * So capability is a property of the key, checked before the signature, and
 * the two sets never overlap.
 */
export const CAPABILITIES = Object.freeze({
  RECORD_SIGN: 'record.sign',     // may sign hpx/1 records
  POSSESSION: 'possession.prove',  // may answer a possession challenge
  // May vouch that a person is who they say they are. Held by an external
  // identity issuer, never by this layer, because this layer does not proof
  // anybody. See beneficiary.js.
  IDENTITY_ASSERT: 'identity.assert'
});

/**
 * Pairs that may never sit on one key.
 *
 * All three of these are mutually exclusive in practice, and they are listed
 * pairwise rather than as a blanket rule so that adding a fourth capability
 * forces somebody to decide which of the existing ones it conflicts with
 * rather than inheriting an answer.
 *
 * The identity pairs matter as much as the first. An issuer key that could
 * also sign records would let one compromised identity provider mint
 * clinical evidence, and one that could also answer a possession challenge
 * would let it authenticate as a facility.
 */
export const EXCLUSIVE_CAPABILITIES = Object.freeze([
  [CAPABILITIES.RECORD_SIGN, CAPABILITIES.POSSESSION],
  [CAPABILITIES.RECORD_SIGN, CAPABILITIES.IDENTITY_ASSERT],
  [CAPABILITIES.POSSESSION, CAPABILITIES.IDENTITY_ASSERT]
]);

export class CapabilityError extends Error {
  constructor(message, { code = 'CAPABILITY_REFUSED' } = {}) {
    super(message);
    this.name = 'CapabilityError';
    this.code = code;
  }
}

/**
 * What a key id may contain.
 *
 * This is not tidiness. Keys are stored under `${id}#${version}` and that
 * same string goes into the bytes a holder signs, so an id containing a hash
 * makes two different (id, version) pairs collide on one entry. An attacker
 * registered as `k-a#1` version 2 could ask for key id `k-a` version `1#2`,
 * sign with their own key, and be told they were `k-a`. In this layer `k-a`
 * is another hospital, and the session that came back was attributed to it.
 *
 * Two things fix that and both are here, because either alone is one review
 * away from being undone: the delimiter cannot appear in an id, and resolve()
 * returns the registry's own id and version rather than whatever was asked
 * for. See the note in possession.js verify().
 */
export const KEY_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;

export function assertKeyId(id) {
  if (typeof id !== 'string' || !KEY_ID_PATTERN.test(id)) {
    throw new Error(
      `${JSON.stringify(String(id).slice(0, 40))} is not a usable key id. ` +
      'A key id is 1 to 128 characters of letters, digits, dot, colon, ' +
      'underscore or hyphen, starting with a letter or digit. A hash is ' +
      'excluded because it separates the id from the version and an id ' +
      'containing one lets two different keys collide on one entry.');
  }
  return id;
}

/**
 * Zero is a valid version, and finding that out is the reason this is a
 * separate function with its own note.
 *
 * The first version of this check required a positive integer, which read as
 * obviously right and broke the conformance vectors: keys in the published
 * vectors are version 0, those vectors are frozen under rule 6, and a Go
 * verifier and a Python encoder both agree with them. A validation rule that
 * invalidates already-published artifacts is a specification change wearing
 * the costume of a bug fix.
 *
 * What actually has to be excluded is a version that is not an integer at
 * all, because that is what gets concatenated into the storage key and the
 * signed bytes and lets two keys collide on one entry.
 */
export function assertKeyVersion(version) {
  if (!Number.isInteger(version) || version < 0) {
    throw new Error(
      `a key version is a non-negative integer; got ${JSON.stringify(version)}. ` +
      'A string version would be concatenated into the storage key and the ' +
      'signed bytes, which is how a collision gets in.');
  }
  return version;
}

// Retired keys are retained, never deleted. A signature made in 2027 must still
// verify in 2034 after the key that made it has been rotated out of service.
export class KeyRegistry {
  constructor() { this.keys = new Map(); }
  _k(id, version) { return `${id}#${version}`; }

  /**
   * @param {string[]|null} [capabilities]  what this key may do. See
   *   CAPABILITIES. Omitting it means record signing and nothing else.
   *
   *   The default is deliberately not "everything". Every key registered
   *   before capabilities existed is a record signing key, so the default has
   *   to keep those working, and it must not silently hand them the ability
   *   to authenticate. The dangerous direction is a record key answering a
   *   login, so that direction is the one that requires saying so.
   */
  register({ id, version, alg, publicKey, owner, status = 'active', notAfter = null,
             capabilities = null }) {
    assertKeyId(id);
    assertKeyVersion(version);
    const caps = capabilities === null
      ? [CAPABILITIES.RECORD_SIGN]
      : [...new Set(capabilities)];
    const known = new Set(Object.values(CAPABILITIES));
    for (const c of caps) {
      if (!known.has(c)) {
        throw new Error(
          `unknown capability ${c} on key ${id}#${version}. ` +
          `Known: ${[...known].join(', ')}`);
      }
    }
    for (const [a, b] of EXCLUSIVE_CAPABILITIES) {
      if (caps.includes(a) && caps.includes(b)) {
        throw new CapabilityError(
          `key ${id}#${version} was registered for both ${a} and ${b}. ` +
          'A key that can sign records and answer logins makes the login ' +
          'endpoint a signing oracle for records. Register two keys.',
          { code: 'CAPABILITY_OVERLAP' });
      }
    }
    this.keys.set(this._k(id, version),
      { id, version, alg, publicKey, owner, status, notAfter, capabilities: caps });
    return this;
  }

  /**
   * Refuse a key being used for something it was not registered to do.
   *
   * Checked before the signature is verified, because this is not a secret.
   * What a key is for is a registration fact the holder already knows, and
   * ordering it first keeps a wrong capability from costing a verification.
   *
   * @throws {CapabilityError}
   */
  assertCapability(id, version, capability) {
    const k = this.resolve(id, version);
    if (!k) throw new CapabilityError(`unknown key ${id}#${version}`, { code: 'KEY_UNKNOWN' });
    if (!k.capabilities.includes(capability)) {
      throw new CapabilityError(
        `key ${id}#${version} is registered for ${k.capabilities.join(', ')} ` +
        `and was asked to ${capability}`,
        { code: 'CAPABILITY_REFUSED' });
    }
    return k;
  }

  /** Every key able to do one thing. For an operator, and for the decoy. */
  withCapability(capability) {
    return [...this.keys.values()].filter(k => k.capabilities.includes(capability));
  }
  retire(id, version, notAfter) {
    const k = this.keys.get(this._k(id, version));
    if (!k) throw new Error(`unknown key ${id}#${version}`);
    k.status = 'retired';
    k.notAfter = notAfter;
    return this;
  }
  resolve(id, version) { return this.keys.get(this._k(id, version)) || null; }

  // Public keys only. This is the object an auditor is given.
  export() {
    return [...this.keys.values()].map(k => ({
      id: k.id, version: k.version, alg: k.alg, owner: k.owner,
      status: k.status, notAfter: k.notAfter, capabilities: k.capabilities,
      publicKey: bytesToHex(k.publicKey)
    }));
  }
  static import(entries) {
    const r = new KeyRegistry();
    for (const e of entries) r.register({ ...e, publicKey: hexToBytes(e.publicKey) });
    return r;
  }
}

// The record algorithms, and only those.
//
// Authentication algorithms live in crypto-possession.js, which composes this
// object rather than replacing it. See the note at the top of this file for
// why the two are separate.
export const VERIFIERS = { 'ML-DSA-65': MlDsa65Signer.verify };

