// Run a witness.
//
//   node src/server.js --journal ./witness.jsonl --log-keys ./log-keys.json --initialize
//   node src/server.js --journal ./witness.jsonl --log-keys ./log-keys.json
//
// First run needs --initialize and generates this witness's signing key. Every
// run after that must NOT pass it: an absent journal is then an error, because
// a witness that quietly starts fresh will co-sign the rewrite it exists to
// catch.
//
// The key is generated here, on the operator's machine, and never leaves it.
// That is the entire point. MedXT receives only the public half, registers it,
// and from then on cannot produce a checkpoint carrying this witness's
// signature without asking this service and being told yes.
//
// Options
//   --journal PATH    where this witness remembers what it endorsed. required
//   --log-keys PATH   public keys of the logs it will check. required
//   --key PATH        this witness's key file. default <journal>.key
//   --name NAME       what it calls itself in its answers
//   --port N          default 8787
//   --initialize      permit creating a new journal and a new key. first run only

import { readFileSync, writeFileSync, existsSync, chmodSync } from 'node:fs';

import { MlDsa65Signer } from './crypto.js';
import { buildWitness, createWitnessServer } from './service.js';

const argv = process.argv.slice(2);
const flag = n => { const i = argv.indexOf(n); return i === -1 ? null : argv[i + 1]; };
const has = n => argv.includes(n);

const JOURNAL = flag('--journal');
const LOG_KEYS = flag('--log-keys');
const NAME = flag('--name') || 'an independent witness';
const PORT = Number(flag('--port') || 8787);
const INIT = has('--initialize');
const KEYFILE = flag('--key') || (JOURNAL ? JOURNAL + '.key' : null);

if (!JOURNAL || !LOG_KEYS) {
  console.error(`
Run a witness.

  node src/server.js --journal ./witness.jsonl --log-keys ./log-keys.json --initialize

  --journal PATH    where this witness remembers what it has endorsed
  --log-keys PATH   public keys of the logs it will check, from the log operator
  --key PATH        this witness's own key. default <journal>.key
  --name NAME       what it calls itself
  --port N          default 8787
  --initialize      first run only. Creates the journal and the signing key.
`);
  process.exit(2);
}

// ------------------------------------------------------------------ the key
//
// Generated locally, written with owner-only permissions, and loaded from disk
// every run after. If this file is lost the witness cannot be rebuilt: a new
// key is a new witness, with no knowledge of what the old one endorsed, and
// every checkpoint the old one signed becomes uncheckable. Back it up, keep it
// off the machine running the log, and do not let anyone else hold a copy.
let signer, publicKey;

// Keys are byte arrays. They go to disk as hex, the same encoding the key
// registry already uses, so an operator comparing the public half against what
// the log registered is comparing two identical strings rather than two
// different renderings of the same bytes.
const toHex = b => Buffer.from(b).toString('hex');
const fromHex = h => new Uint8Array(Buffer.from(h, 'hex'));

if (existsSync(KEYFILE)) {
  if (INIT) {
    console.error(
      `\nA key already exists at ${KEYFILE}.\n\n` +
      'Refusing to run with --initialize, because initialising over an existing\n' +
      'witness would discard what it has endorsed and silently become a new\n' +
      'witness wearing the old one\'s name. Drop --initialize to start normally.\n');
    process.exit(2);
  }
  const saved = JSON.parse(readFileSync(KEYFILE, 'utf8'));
  signer = new MlDsa65Signer(fromHex(saved.secretKey));
  publicKey = saved.publicKey;
} else {
  if (!INIT) {
    console.error(
      `\nNo key at ${KEYFILE}.\n\n` +
      'Refusing to generate one without --initialize. If this witness has run\n' +
      'before, its key is missing and that is an incident, not a first run: a\n' +
      'replacement key cannot verify anything the original endorsed.\n');
    process.exit(2);
  }
  const generated = MlDsa65Signer.generate();
  signer = generated.signer;
  publicKey = toHex(generated.publicKey);
  writeFileSync(KEYFILE, JSON.stringify({
    note: 'The private half of a witness key. It never leaves this machine.',
    alg: 'ML-DSA-65',
    publicKey,
    secretKey: toHex(generated.signer.secretKey)
  }, null, 2) + '\n');
  try { chmodSync(KEYFILE, 0o600); } catch { /* best effort on platforms without it */ }
}

const logKeys = JSON.parse(readFileSync(LOG_KEYS, 'utf8'));

let service;
try {
  service = buildWitness({
    signer, keyId: flag('--key-id') || 'k-wit-001', version: 1,
    logKeys, journalPath: JOURNAL, initialize: INIT, name: NAME
  });
} catch (e) {
  console.error(`\n${e.message}\n`);
  process.exit(2);
}

const server = createWitnessServer(service);
server.listen(PORT, () => {
  const tip = service.witness.state.tip();
  console.log(`
${NAME}
${'='.repeat(NAME.length)}

  listening on      http://localhost:${PORT}
  journal           ${JOURNAL}  (${tip.entries} entries)
  key               ${KEYFILE}
  watching          ${service.witness.state.watching().length} log(s)

  endpoints
    POST /v1/cosign         a log asks for a countersignature
    GET  /v1/endorsements   what this witness has endorsed
    GET  /v1/refusals       what it has refused, which is the point
    GET  /health
`);
  if (INIT) {
    console.log(`  This witness's public key. Send it to the log operator so they can
  register it. Keep ${KEYFILE} where only you can read it.

${publicKey}
`);
  }
});
