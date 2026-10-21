# Running a witness

For the organisation operating the witness, not for MedXT.

If you have been asked to run one of these, this is what you are agreeing to,
what it costs you, and what to do when it refuses something. Read the first two
sections before you agree.

## What you are being asked to do

An evidence log publishes a signed statement, periodically, saying "my log
currently holds N records and its root hash is X". That statement is called a
checkpoint.

A checkpoint signed only by the log proves nothing about the log. Whoever runs
it holds the key, so they can rebuild history without one record in it and sign
a checkpoint for the rebuilt version, and anyone holding only that checkpoint
cannot tell.

A witness closes that. You keep your own record of the last checkpoint you
endorsed for each log. When the log asks you to countersign a new one, this
service verifies the new tree actually grew from the tree you already endorsed,
and signs only if it did. If it did not, it refuses, and the refusal is the
thing everyone wanted.

To rewrite history the log operator now has to obtain your signature on a
checkpoint inconsistent with the one you already signed. You will not give it.
And if they stop asking you altogether, the absence of fresh countersigned
checkpoints is visible to anyone watching.

## What it costs you, honestly

**It sees no clinical data.** Not de-identified clinical data. None. A
checkpoint is an origin string, a count, a hash and a timestamp. There is no
patient, no provider, no diagnosis, no procedure and no money in anything this
service receives. If you are weighing a HIPAA question, there is no protected
health information in scope here at all.

**It holds one secret**, its own signing key, generated on your machine and
never sent anywhere. That key signs nothing but checkpoints. It cannot create
evidence, alter evidence, approve a payment or read a record.

**It needs almost nothing.** A small container or VM, a few megabytes of disk
that grows by a line per checkpoint, and no inbound access to anything else you
run. The log calls you; you call nothing.

**It needs no attention** until it refuses something, which should be never.

**What it does not do.** It does not vouch for the contents of the log. It is
not auditing care, claims or payment. It says one thing only: that the history
it was shown is consistent with the history it was shown before. Anyone citing
your signature as endorsement of anything else is overstating it, and you are
entitled to say so.

## Setting it up

You need Node 18 or later, and the log operator's public keys, which they send
you as a JSON file. Put that file somewhere you can point at; the examples
below assume it is next to the journal.

**Every command below runs from inside the `witness-svc` directory.** If you
get `Cannot find module .../src/server.js`, you are one level up.

```
cd services/witness-svc
```

First run only:

```
node src/server.js \
  --journal ~/witness/witness.jsonl \
  --log-keys ~/witness/log-keys.json \
  --name "Your Organisation" \
  --initialize
```

Use absolute paths for the journal and the keys, or at least paths that do not
depend on which directory you happen to be in. The journal is the one file
this service cannot be rebuilt without, and a relative path is how it ends up
somewhere nobody thought to back up.

This generates your signing key, writes it to `./witness.jsonl.key` with
owner-only permissions, creates the journal, and prints your public key.

**Send the printed public key to the log operator.** They register it. From
that point they cannot produce a checkpoint carrying your signature without
asking this service and being told yes.

**Back up `witness.jsonl.key` somewhere that is not the machine running the
log.** If you lose it you cannot rebuild this witness: a new key is a new
witness with no knowledge of what the old one endorsed, and every checkpoint
the old one signed becomes uncheckable.

Every run after the first, from the same directory:

```
node src/server.js \
  --journal ~/witness/witness.jsonl \
  --log-keys ~/witness/log-keys.json \
  --name "Your Organisation"
```

Do not pass `--initialize` again. It will refuse, on purpose.

## Checking it works before you rely on it

The test suite runs a log and a witness as two separate parties with two
separate keys, including a log rewriting its history and being refused over
HTTP. It needs nothing from the network and writes only to a temporary
directory.

```
cd services/witness-svc
node test-service.js
```

Forty checks. If that passes, the service on your machine behaves the way this
document describes.

## What it will refuse to do, and why that is deliberate

**It will not start if the journal is missing.** An absent journal looks
identical to a brand new witness, and a witness that starts empty will
co-sign anything it is shown as "the first checkpoint I have seen". If you see
this error, do not pass `--initialize` to make it go away. Find the journal.
Something removed it, and that is the attack this is built to stop.

**It will not start if the journal has been edited.** Every entry carries the
digest of the one before it, and a separate file records the expected length.
Altering an entry, deleting one, or truncating the file all break the check.

**It will not sign growth without proof.** If the log says it went from 20
records to 30, it must supply a consistency proof. No proof, no signature.

**It will not sign a shrunken or diverged history.** This is the real event. It
returns HTTP 409 with what you previously endorsed and what you were just
offered, and the refusal is written to the journal before you ever see it, so
it survives the process being killed.

## What to do if it refuses

A refusal for a missing consistency proof is usually a plumbing problem at the
log end. Tell them; they will fix the call.

**A refusal that names a different root or a smaller size is not a plumbing
problem.** It means the log offered you a history that contradicts one you
already signed. Do not resolve it by restarting anything, and do not delete the
journal.

1. Keep the journal. It is the evidence.
2. Record `GET /v1/refusals` output somewhere outside this machine.
3. Tell the log operator what you were offered and what you hold.
4. Tell whoever relies on this log. That is the point of you being independent.

## Endpoints

```
POST /v1/cosign         the log asks for a countersignature
GET  /v1/endorsements   what you have endorsed, per log
GET  /v1/refusals       what you have refused, with reasons
GET  /health            whether the journal is readable, not just whether the process is up
```

The two GET endpoints are readable by anyone and are meant to be. A witness
nobody can query is a witness nobody can hold to account, and the trust problem
would just have moved one step along. Publishing what you have endorsed is what
makes you worth having.

`GET /v1/endorsements` also returns a `tip`: the digest of your own journal's
last entry. Writing that down periodically, somewhere you control, is how
somebody checks that *you* have not been rewound. It costs nothing and it is
the only thing that makes the witness itself accountable.

## An honest limitation

The journal is tamper evident against editing and truncation on its own terms.
It is not proof against someone with write access to the machine who rewrites
both the journal and its head file together. Nothing stored only on one machine
can be.

The answer is the tip above: recorded elsewhere, periodically, by someone who
is not you. We would rather state this than let you believe the file alone is
sufficient.
