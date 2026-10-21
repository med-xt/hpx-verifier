// Every signing call goes through this interface and nothing else calls a crypto
// library directly. That is what makes the FIPS swap a deployment change rather
// than a rewrite: the federal build registers a validated-module signer here.
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
  sign(bytes) { return b64(ml_dsa65.sign(bytes, this.secretKey)); }
  static verify(sigB64, bytes, publicKey) {
    try { return ml_dsa65.verify(unb64(sigB64), bytes, publicKey); }
    catch { return false; }
  }
}

// Retired keys are retained, never deleted. A signature made in 2027 must still
// verify in 2034 after the key that made it has been rotated out of service.
export class KeyRegistry {
  constructor() { this.keys = new Map(); }
  _k(id, version) { return `${id}#${version}`; }

  register({ id, version, alg, publicKey, owner, status = 'active', notAfter = null }) {
    this.keys.set(this._k(id, version), { id, version, alg, publicKey, owner, status, notAfter });
    return this;
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
      status: k.status, notAfter: k.notAfter, publicKey: bytesToHex(k.publicKey)
    }));
  }
  static import(entries) {
    const r = new KeyRegistry();
    for (const e of entries) r.register({ ...e, publicKey: hexToBytes(e.publicKey) });
    return r;
  }
}

export const VERIFIERS = { 'ML-DSA-65': MlDsa65Signer.verify };
