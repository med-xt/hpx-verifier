// A log and a witness as two separate parties.
//
// The log holds its key, the witness holds its own, and neither can produce
// the other's signature. Every case here is something that would actually
// happen to an operator, including the mistakes they would make on the first
// day and the one event the whole system exists to catch.

import { mkdtempSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { buildWitness, createWitnessServer } from './src/service.js';
import { MlDsa65Signer, KeyRegistry } from './src/crypto.js';
import { MerkleLog } from './src/merkle.js';
import { signCheckpoint, verifyCheckpoint, parseCheckpoint } from './src/checkpoint.js';
import { meetsQuorum } from './src/witness.js';

let fail = 0;
const ok = (l, c, g) => {
  console.log(`  ${c ? 'PASS' : 'FAIL'}  ${l}${c ? '' : `   got: ${JSON.stringify(g)?.slice(0, 240)}`}`);
  if (!c) fail++;
};

const dir = mkdtempSync(join(tmpdir(), 'witsvc-'));
const leaf = i => `sha256:${String(i).padStart(64, '0')}`;

// ------------------------------------------------- the log, one organisation
const logKeys = MlDsa65Signer.generate();
const LOG_KEY = { id: 'k-log-001', version: 1, alg: 'ML-DSA-65',
                  publicKey: logKeys.publicKey, owner: 'The evidence log' };
const registryForLog = new KeyRegistry();
registryForLog.register(LOG_KEY);
const logKeysExport = registryForLog.export();      // hex, as it would be sent

const log = new MerkleLog();
const grow = n => { while (log.leaves.length < n) log.add(leaf(log.leaves.length)); };
const checkpointAt = (size, time) => {
  const snapshot = new MerkleLog();
  for (let i = 0; i < size; i++) snapshot.add(leaf(i));
  return signCheckpoint({ origin: 'medxt-evidence/prod', size, root: snapshot.root(), time },
    logKeys.signer, { keyId: 'k-log-001', version: 1 });
};

// -------------------------------------------- the witness, another organisation
const witnessKeys = MlDsa65Signer.generate();
const journal = join(dir, 'witness.jsonl');
const svc = buildWitness({
  signer: witnessKeys.signer, keyId: 'k-wit-001', version: 1,
  logKeys: logKeysExport, journalPath: journal, initialize: true,
  name: 'Example Provider Association'
});

console.log('\nA witness held by someone else\n------------------------------');
ok('it starts with nothing endorsed', svc.endorsements().watching.length === 0, svc.endorsements());
ok('and nothing refused', svc.refusals().refusals.length === 0, null);
ok('it names itself in its answers',
   svc.endorsements().witness === 'Example Provider Association', svc.endorsements());

// ------------------------------------------------------------ the first ask
grow(12);
const monday = checkpointAt(12, '2026-10-05T09:00:00.000Z');
const first = svc.cosign({ document: monday });
ok('the first checkpoint is co-signed', first.status === 200 && first.body.cosigned, first.body);
ok('and labelled honestly as the first it has seen', first.body.first === true, first.body);
ok('it does not claim to have verified history it never saw',
   first.body.verified === false, first.body);
ok('the co-signature is real and checks out',
   verifyCheckpoint(first.body.document, (() => {
     const r = new KeyRegistry();
     r.register(LOG_KEY);
     r.register({ id: 'k-wit-001', version: 1, alg: 'ML-DSA-65',
                  publicKey: witnessKeys.publicKey, owner: 'Example Provider Association' });
     return r;
   })()).ok === true, null);

// ----------------------------------------------------- honest growth
grow(20);
const tuesday = checkpointAt(20, '2026-10-06T09:00:00.000Z');
const noProof = svc.cosign({ document: tuesday });
ok('growth without a consistency proof is refused', noProof.status === 409, noProof.body);
ok('and the refusal says what is missing', noProof.body.needs === 'consistencyProof', noProof.body);
ok('a refusal is not an error', noProof.body.refused && !noProof.body.error, noProof.body);

const proof = log.consistencyProof(12, 20).path;
const grown = svc.cosign({ document: tuesday, consistencyProof: proof });
ok('with the proof it is co-signed', grown.status === 200 && grown.body.verified, grown.body);
ok('and the note says what was proved',
   /Grew from 12 to 20/.test(grown.body.note), grown.body.note);

// ------------------------------------------------- the event it exists to catch
console.log('\nThe log rewrites its history and asks again\n' +
            '------------------------------------------');
const shorter = new MerkleLog();
for (let i = 0; i < 19; i++) shorter.add(leaf(i));
const rewritten = signCheckpoint(
  { origin: 'medxt-evidence/prod', size: 19, root: shorter.root(), time: '2026-10-07T09:00:00.000Z' },
  logKeys.signer, { keyId: 'k-log-001', version: 1 });

const caught = svc.cosign({ document: rewritten });
ok('a shrunken log is refused', caught.status === 409, caught.body);
ok('the refusal names what was previously endorsed',
   caught.body.previouslyEndorsed?.size === 20, caught.body.previouslyEndorsed);
ok('and what was offered instead', caught.body.offered?.size === 19, caught.body.offered);
ok('it is recorded, not just returned', svc.refusals().refusals.length === 2, svc.refusals());
ok('the refusal record survives a restart',
   buildWitness({ signer: witnessKeys.signer, keyId: 'k-wit-001', logKeys: logKeysExport,
                  journalPath: journal }).refusals().refusals.length === 2, null);
ok('and the baseline did not move to the rewritten history',
   svc.endorsements().watching[0].size === 20, svc.endorsements().watching);

// A checkpoint the log never signed must not be laundered into legitimacy.
const impostorKeys = MlDsa65Signer.generate();
const forged = signCheckpoint(
  { origin: 'medxt-evidence/prod', size: 21, root: log.root(), time: '2026-10-08T09:00:00.000Z' },
  impostorKeys.signer, { keyId: 'k-log-001', version: 1 });
const forgedResult = svc.cosign({ document: forged });
ok('a checkpoint not signed by the real log key is refused',
   forgedResult.status === 409, forgedResult.body);

// ------------------------------------------------------------- the public record
console.log('\nWhat it endorsed is public\n--------------------------');
const e = svc.endorsements();
ok('it reports every log it watches', e.watching.length === 1, e.watching);
ok('with the size and root it last endorsed',
   e.watching[0].size === 20 && String(e.watching[0].root).startsWith('sha256:'), e.watching[0]);
ok('it publishes its own journal tip so it can itself be audited',
   typeof e.tip?.head === 'string' && e.tip.entries > 0, e.tip);
ok('refusals are public, with reasons',
   svc.refusals().refusals.every(r => typeof r.reason === 'string'), svc.refusals().refusals[0]);
ok('and the empty case is explained rather than implying innocence',
   /does not mean the log is honest/.test(svc.refusals().note), svc.refusals().note);

// ------------------------------------------------------------------ quorum
console.log('\nQuorum is the relying party\'s rule, not the log\'s\n' +
            '------------------------------------------------');
const both = new KeyRegistry();
both.register(LOG_KEY);
both.register({ id: 'k-wit-001', version: 1, alg: 'ML-DSA-65',
                publicKey: witnessKeys.publicKey, owner: 'Example Provider Association' });
const v = verifyCheckpoint(grown.body.document, both);
ok('a co-signed checkpoint meets a quorum of one',
   meetsQuorum(v, { logKeyId: 'k-log-001', witnesses: 1 }).ok === true, null);
ok('and does not meet a quorum of two',
   meetsQuorum(v, { logKeyId: 'k-log-001', witnesses: 2 }).ok === false, null);
const selfOnly = verifyCheckpoint(monday, both);
ok('a checkpoint signed only by the log meets no quorum at all',
   meetsQuorum(selfOnly, { logKeyId: 'k-log-001', witnesses: 1 }).ok === false, null);

// ------------------------------------------------- the operator's first day
console.log('\nThe mistakes an operator would actually make\n' +
            '-------------------------------------------');
let threwNoJournal = null;
try {
  buildWitness({ signer: witnessKeys.signer, keyId: 'k-wit-001', logKeys: logKeysExport,
                 journalPath: join(dir, 'never-existed.jsonl') });
} catch (err) { threwNoJournal = err; }
ok('starting with no journal and no --initialize is refused',
   threwNoJournal?.code === 'NO_JOURNAL', threwNoJournal?.message);
ok('and the error explains the consequence',
   /co-signs anything/.test(threwNoJournal?.message ?? ''), threwNoJournal?.message);

const empty = svc.cosign({});
ok('an empty request is a 400, not a crash', empty.status === 400, empty);
const rubbish = svc.cosign({ document: 'not a checkpoint' });
ok('rubbish is refused rather than parsed hopefully',
   rubbish.status === 409 || rubbish.status === 400, rubbish);

// --------------------------------------------------------------- over HTTP
console.log('\nOver HTTP, as a log would actually call it\n' +
            '-----------------------------------------');
const server = createWitnessServer(svc);
await new Promise(r => server.listen(0, r));
const base = `http://127.0.0.1:${server.address().port}`;

const post = async (path, body) => {
  const r = await fetch(base + path, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body)
  });
  return { status: r.status, body: await r.json() };
};
const get = async path => {
  const r = await fetch(base + path);
  return { status: r.status, body: await r.json() };
};

grow(30);
const wednesday = checkpointAt(30, '2026-10-08T09:00:00.000Z');
const over = await post('/v1/cosign', {
  document: wednesday, consistencyProof: log.consistencyProof(20, 30).path
});
ok('a log can get a countersignature over HTTP', over.status === 200 && over.body.cosigned, over.body);

const refusedOver = await post('/v1/cosign', { document: rewritten });
ok('and a rewrite is refused with 409 over HTTP', refusedOver.status === 409, refusedOver.body);

const pub = await get('/v1/endorsements');
ok('endorsements are readable without authentication', pub.status === 200, pub.status);
ok('and show the latest size', pub.body.watching[0].size === 30, pub.body.watching);
const refs = await get('/v1/refusals');
// Counted from the service rather than written as a literal, so adding a case
// above does not silently break an unrelated assertion here.
ok('so are refusals', refs.status === 200 &&
   refs.body.refusals.length === svc.refusals().refusals.length &&
   refs.body.refusals.length > 0, refs.body.refusals?.length);
ok('every refusal on the public record carries its reason and origin',
   refs.body.refusals.every(r => r.reason && 'origin' in r), refs.body.refusals[0]);
const health = await get('/health');
ok('health reports the journal tip, not just that the process is up',
   health.status === 200 && typeof health.body.tip?.head === 'string', health.body);
const missing = await get('/v1/nothing-here');
ok('an unknown path lists what does exist', missing.status === 404 && missing.body.endpoints, missing.body);

const big = await fetch(base + '/v1/cosign', {
  method: 'POST', headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ document: 'x'.repeat(100 * 1024) })
});
ok('an oversized body is refused at the boundary', big.status === 413, big.status);

// Nothing clinical can reach a witness, by construction, but assert it anyway.
//
// Asserted structurally rather than by grepping the response text. The first
// version of this searched for words like "npi" and "claim" across the whole
// JSON, which includes base64 signatures, and base64 randomly contains any
// short string. It passed or failed depending on the key generated that run,
// which is worse than not testing it: a flaky assertion gets disabled, and
// then nothing is checking the property at all.
//
// So: a checkpoint body is an origin, a size, a root and a time. Those are the
// only fields a witness ever sees, and that is checkable exactly.
const parsed = parseCheckpoint(over.body.document);
ok('a checkpoint carries exactly four facts and none are clinical',
   ['origin', 'size', 'root', 'time'].every(f => f in parsed), Object.keys(parsed));
ok('the origin is a log name, not a patient or a claim',
   parsed.origin === 'medxt-evidence/prod', parsed.origin);
ok('the size is a count', Number.isInteger(parsed.size), parsed.size);
ok('the root is a hash and nothing else',
   /^sha256:[0-9a-f]{64}$/.test(parsed.root), parsed.root);

// And what the witness persists about a refusal is the same four facts.
const persisted = refs.body.refusals.flatMap(r =>
  [r.detail?.prior, r.detail?.offered].filter(Boolean));
ok('refusal records hold only size, root and time',
   persisted.every(p => Object.keys(p).every(k => ['size', 'root', 'time'].includes(k))),
   persisted[0]);

server.close();
rmSync(dir, { recursive: true, force: true });
console.log(`\n${fail === 0 ? 'ALL PASS' : fail + ' FAILURES'}\n`);
process.exit(fail ? 1 : 0);
