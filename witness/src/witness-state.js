// Durable witness memory.
//
// The Witness in witness.js holds its state in a Map, which is correct for a
// test and useless as a control. A witness exists to refuse a checkpoint that
// disagrees with what it already endorsed, and it can only do that if it
// remembers. A witness that forgets is not a weaker control than one that
// remembers; it is worse than having no witness at all, because the operator
// can produce a co-signature on a rewritten log and point at it.
//
// The attack is one line long. Stop the witness, delete its memory, start it,
// present the rewritten log. With an empty Map the rewritten log is simply the
// first checkpoint this witness has ever seen, so it co-signs, labels the
// result "first checkpoint seen", and the operator now holds an independently
// countersigned checkpoint for a history that never happened. Everything else
// in this system is built to make that impossible, and it would be undone by a
// process restart.
//
// So three properties, and each one is a refusal rather than a best effort.
//
// It survives a restart. The journal is on disk, appended to and fsynced
// before anything is signed.
//
// It will not silently start empty. An absent journal is a refusal unless the
// operator explicitly says this is a new witness. The difference between
// "I have never seen this log" and "I have forgotten what I saw" is the whole
// control, and only a human knows which one is true.
//
// It cannot be edited quietly. Every entry carries the digest of the one
// before it, so removing or altering an entry breaks the chain and the witness
// refuses to load. An operator who tampers with a witness's memory has to
// break it loudly instead.
//
// Refusals are written down too. A split view that is detected and then
// forgotten when the process exits is not evidence of anything. The refusal is
// the single most important thing this system can produce, so it is persisted
// before it is thrown.

import { openSync, closeSync, fsyncSync, writeSync, readFileSync, existsSync,
         mkdirSync, renameSync } from 'node:fs';
import { dirname } from 'node:path';
import { createHash } from 'node:crypto';

import { canonicalize } from './canonical.js';

export const JOURNAL_SPEC = 'hpx/witness-journal/1';

// The chain catches an edited or deleted entry in the middle of the journal,
// because every later digest depends on it. It does not catch truncation of
// the tail: lop off the last three lines and what remains is a perfectly valid
// chain of an earlier length. That is precisely the rewind an operator wants,
// so it needs its own answer.
//
// The sidecar is that answer, and it is deliberately modest. It holds the
// expected entry count and chain tip, written after each append, so a truncated
// journal no longer matches and the witness refuses to load. An attacker with
// write access to the directory can edit both files, so this raises the cost
// rather than closing the hole.
//
// The real control is the tip being written down somewhere the operator does
// not control, which is what tip() is for and what the service publishes. State
// that honestly: a witness that cannot be audited from outside has only moved
// the trust problem one step along, it has not solved it.
const SIDECAR = path => path + '.head';

export class WitnessStateError extends Error {
  constructor(message, detail = {}) {
    super(message);
    this.name = 'WitnessStateError';
    Object.assign(this, detail);
  }
}

const sha256 = bytes => 'sha256:' + createHash('sha256').update(bytes).digest('hex');

// The digest covers the entry and the digest of the entry before it. Canonical
// encoding is reused from the record format so that two implementations of
// this journal agree byte for byte, the same reason records use it.
function entryDigest(entry, prev) {
  const { digest, ...rest } = entry;
  return sha256(canonicalize({ prev, entry: rest }));
}

/**
 * An append only, hash chained journal of everything a witness has endorsed or
 * refused.
 *
 * Implements get(origin) and set(origin, value) so it can be handed to the
 * Witness class in place of a Map, and adds the durability the Map cannot have.
 */
export class DurableWitnessState {
  /**
   * @param {string} path                 journal file
   * @param {object} [opts]
   * @param {boolean} [opts.initialize]   permit creating a new, empty journal.
   *   Without this an absent file is an error, because a witness that starts
   *   empty by accident endorses anything.
   */
  constructor(path, { initialize = false } = {}) {
    this.path = path;
    this.entries = [];
    this.head = null;          // digest of the last entry, the chain tip
    this.map = new Map();      // origin -> { size, root, time }

    if (existsSync(path)) {
      this._load();
    } else if (initialize) {
      mkdirSync(dirname(path), { recursive: true });
      this._append({ type: 'initialized', spec: JOURNAL_SPEC, at: new Date().toISOString() });
    } else {
      throw new WitnessStateError(
        `no witness journal at ${path}. A witness with no memory co-signs anything ` +
        'it is shown, so this is refused rather than started empty. If this really ' +
        'is a new witness, pass initialize. If it is not, find the journal: ' +
        'something has removed it.',
        { path, code: 'NO_JOURNAL' });
    }
  }

  // ------------------------------------------------------------------ loading
  _load() {
    const text = readFileSync(this.path, 'utf8');
    const lines = text.split('\n').filter(l => l.trim());
    let prev = null;

    for (const [i, line] of lines.entries()) {
      let entry;
      try {
        entry = JSON.parse(line);
      } catch {
        throw new WitnessStateError(
          `witness journal line ${i + 1} is not JSON. The journal is damaged or ` +
          'has been edited. A witness cannot safely continue from a history it ' +
          'cannot read.',
          { path: this.path, line: i + 1, code: 'MALFORMED' });
      }

      const expected = entryDigest(entry, prev);
      if (entry.digest !== expected) {
        // This is the alarm. Someone removed or altered an entry, which is
        // exactly what an operator would do to make a witness forget one
        // particular endorsement.
        throw new WitnessStateError(
          `witness journal line ${i + 1} does not match the chain. An entry has ` +
          'been altered or removed. Refusing to load: continuing would mean ' +
          'co-signing against a history that has itself been rewritten.',
          { path: this.path, line: i + 1, expected, found: entry.digest, code: 'CHAIN_BROKEN' });
      }

      prev = entry.digest;
      this.entries.push(entry);
      if (entry.type === 'endorsed') {
        this.map.set(entry.origin, { size: entry.size, root: entry.root, time: entry.time });
      }
    }

    if (!lines.length) {
      throw new WitnessStateError(
        `the witness journal at ${this.path} is empty. An empty file is not the ` +
        'same as a new witness; it is a witness whose memory was truncated.',
        { path: this.path, code: 'EMPTY' });
    }
    this.head = prev;

    // Tail truncation check. The chain alone cannot see this, because a
    // shortened journal is still internally consistent.
    const sidecarPath = SIDECAR(this.path);
    if (existsSync(sidecarPath)) {
      let expected;
      try {
        expected = JSON.parse(readFileSync(sidecarPath, 'utf8'));
      } catch {
        throw new WitnessStateError(
          `the witness head file at ${sidecarPath} is unreadable. Refusing rather ` +
          'than trusting a journal whose length cannot be confirmed.',
          { path: sidecarPath, code: 'HEAD_MALFORMED' });
      }
      if (expected.entries !== lines.length || expected.head !== this.head) {
        throw new WitnessStateError(
          `the witness journal has ${lines.length} entries ending ${this.head}, but ` +
          `the head file records ${expected.entries} ending ${expected.head}. The ` +
          'journal has been shortened or replaced. Refusing to load: a witness that ' +
          'resumes from a truncated memory will co-sign the rewrite it was meant to catch.',
          { path: this.path, code: 'TRUNCATED',
            found: { entries: lines.length, head: this.head }, expected });
      }
    }
    // An absent sidecar is not fatal. It is normal for a journal copied for
    // inspection, and refusing would make auditing a witness harder than
    // attacking one.
  }

  _writeHead() {
    // Written to a temporary name and renamed, so a crash mid write leaves
    // either the old head or the new one, never a half written file that would
    // lock the witness out of its own memory.
    const target = SIDECAR(this.path);
    const tmp = target + '.tmp';
    const fd = openSync(tmp, 'w');
    try {
      writeSync(fd, JSON.stringify(this.tip()) + '\n');
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
    renameSync(tmp, target);
  }

  // ----------------------------------------------------------------- appending
  _append(fields) {
    const entry = { seq: this.entries.length, ...fields };
    entry.digest = entryDigest(entry, this.head);

    // Written and flushed to the platform before the caller is told it
    // succeeded. The whole point of this file is to survive the process, so an
    // append that is only in the page cache has not happened.
    const fd = openSync(this.path, 'a');
    try {
      writeSync(fd, JSON.stringify(entry) + '\n');
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }

    this.entries.push(entry);
    this.head = entry.digest;
    this._writeHead();
    return entry;
  }

  // ------------------------------------------- the Map interface Witness uses
  get(origin) {
    return this.map.get(origin);
  }

  /**
   * Record an endorsement durably, then update memory.
   *
   * Witness calls this before it signs, so that a crash can only ever lose the
   * signature, never the memory of having given one. Losing a signature is
   * recoverable: the log asks again. Losing the memory is the attack.
   */
  set(origin, value) {
    this._append({
      type: 'endorsed',
      origin,
      size: value.size,
      root: value.root,
      time: value.time,
      recordedAt: new Date().toISOString()
    });
    this.map.set(origin, value);
    return this;
  }

  /**
   * Record a refusal.
   *
   * A split view detected and then lost on exit is not evidence. This is the
   * most important thing a witness ever produces and it is written down before
   * the error reaches the caller. Note that it deliberately does NOT advance
   * the endorsement state: a refused checkpoint must not become the baseline
   * for the next one.
   */
  refuse(origin, reason, detail = {}) {
    return this._append({
      type: 'refused',
      origin: origin ?? null,
      reason,
      detail,
      recordedAt: new Date().toISOString()
    });
  }

  /** Everything this witness has refused, which is what an auditor came for. */
  refusals() {
    return this.entries.filter(e => e.type === 'refused');
  }

  /** Every log this witness is watching, and where it last saw each one. */
  watching() {
    return [...this.map.entries()].map(([origin, v]) => ({ origin, ...v }));
  }

  /**
   * The chain tip, which a third party can record out of band.
   *
   * If a witness is ever suspected of having been rewound, a tip somebody else
   * wrote down settles it. The witness protects the log; this is how the
   * witness itself is held to account, and without it the regress just moves
   * one step along.
   */
  tip() {
    return { spec: JOURNAL_SPEC, entries: this.entries.length, head: this.head };
  }
}

/**
 * Read a journal without opening it for writing, for an auditor or a monitor.
 *
 * Returns the same integrity errors as loading. Separate from the class so
 * that inspecting a witness never risks appending to it.
 */
export function readJournal(path) {
  if (!existsSync(path)) throw new WitnessStateError(`no journal at ${path}`, { code: 'NO_JOURNAL' });
  const state = Object.create(DurableWitnessState.prototype);
  state.path = path;
  state.entries = [];
  state.head = null;
  state.map = new Map();
  state._load();
  return state;
}
