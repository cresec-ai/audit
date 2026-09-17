# Evidence sink — shipping sealed records off-box

Until now, evidence reached anyone by being committed to a git branch. That
worked with no infrastructure and the bundle was self-verifying, so the
transport never had to be trusted — but it is wrong for a customer in four
ways: it needs a repo and a push credential, it is batch rather than live, it
needs a human to remember to look, and **the agent under observation controls
delivery**. Evidence whose delivery the observed party controls is not
evidence.

The sink replaces that transport. `mcp-recorder` replicates the sealed chain
to a receiver as it records, within seconds, over HTTPS.

This document describes the **sender**, which is what this package ships.

---

## The claim we make, and the one we must not

> The recorder does not prove what an agent DID. It proves what REACHED the
> chain, and that what reached it has not been altered since. On an
> unsegregated machine, an agent that owns the signing key can also author
> the chain.

The sink's contribution is narrower than "tamper-proof recording" and still
worth having: it makes the record durable off-box within seconds, makes
editing it detectable, and makes withholding and silence measurable.

See [Threat model](#threat-model) for what that does and does not cover.

---

## Turning it on

One environment variable. That is the whole opt-in — there is no second
`..._ENABLED` switch, and with it absent the recorder behaves byte for byte
as it did before this feature existed.

```sh
export MCP_RECORDER_SINK=https://sink.example.com
export MCP_RECORDER_SINK_TOKEN=<opaque 256-bit install token>
# or, where a root-owned file is easier to protect than an env var:
export MCP_RECORDER_SINK_TOKEN_FILE=/etc/mcp-recorder/sink-token
```

`record`, `http` and `hook` all write to the same store, so all three pick
this up from the same place. The first of them to run starts a shipper;
everything else is automatic.

A combined `https://token@host/` form is deliberately **not** supported:
userinfo in a URL leaks into process listings, shell history and error
strings. Two variables.

`https://` only. A plain `http://` sink is refused unless the host is
loopback, and the refusal is printed. Certificate verification is never
disabled: for a corporate CA or an agent proxy, point `NODE_EXTRA_CA_CERTS`
at the CA. `HTTPS_PROXY` and `NO_PROXY` are honoured (`node:https` does not
read them itself, so the shipper tunnels through the proxy with CONNECT and
runs TLS inside the tunnel).

### Per surface

| Surface | What you configure |
|---|---|
| **Laptop** | `mcp-recorder setup` writes the two vars into the client's MCP `env` block, or you export them in your shell profile. The shipper is auto-started; nothing to install or supervise. **The agent runs as the same user and can read both values** — this configuration is for visibility, not adversarial assurance. |
| **CI job** | Two repository secrets → two env vars. Add a final step `mcp-recorder ship --drain --timeout 30s || true`, because a short-lived runner may vanish before the shipper drains. The `|| true` is the fail-open rule applied to CI: a sink outage must never fail a customer's build. |
| **Claude Code cloud session** | The two env vars in the environment config, plus the single `.claude/settings.json` hook entry `mcp-recorder hook install` already writes — unchanged. The hook picks the sink up from the environment. |
| **Managed fleet** | The same two variables, but in a root-owned MDM profile / systemd `Environment=` / launchd plist, and the hook entry in the managed-settings path rather than `.claude/settings.json`. Keys enrolled in pinned mode, a supervised `mcp-recorder ship --idle-exit 0` unit, and an alert on missing heartbeats. **This is the only configuration in which the threat-model claims below hold.** |

---

## Operator visibility

```
$ mcp-recorder ship --status
sink:         https://sink.example.com
key:          4f1c…              # = <data-dir>/identity.pub
chain_id:     9ae3…              # = hash of chain record seq 1
state:        idle (shipper running)
local head:   seq 1204
receiver:     next_seq 1205, attested_seq 1200
lag:          0 record(s) not yet at the receiver
last success: 2026-09-17T09:14:02.881Z
last error:   (none)
```

That single command is the operator's whole mental model, and it is what
turns a stall from an invisible condition into a human-legible one. It
touches no network and takes no lock.

---

## What ships

Contiguous batches of sealed `ChainRecord`s in seq order, the
`HeadSignature`s falling in that range, and a signed statement of the
sender's **current** local head.

```
POST {sink}/v1/chains/{chain_id}/records     — the only write
GET  {sink}/v1/chains/{chain_id}/cursor      — the resume oracle
GET  {sink}/v1/health                        — unauthenticated liveness, no data
```

There is no DELETE, no PUT and no PATCH anywhere in the API. That is
load-bearing (see [Auth](#auth)).

Two derived identifiers, both computable from the existing chain with zero
schema change:

- **`key`** — the 64-hex ed25519 public key in `<data-dir>/identity.pub`. One
  per data dir, therefore one per chain.
- **`chain_id`** — the `hash` of chain record seq 1, i.e.
  `sha256(GENESIS_HASH + "\n" + canonicalJson(event_1))`. Unique per chain
  *instance*, because event 1 carries a v4 `event_id`. This matters: an
  `identity.key` that survives while `evidence.db` is deleted would otherwise
  restart seq at 1 under the same key and fork. With `chain_id`, that is
  instead a visible "second chain for an enrolled key" at the receiver.

**What never ships: this token.** The recorder fingerprints credential-shaped
environment variables onto `identity.credential_fingerprints` so a blast-radius
`query` can find which sessions saw a given secret. `MCP_RECORDER_SINK_TOKEN`
(and `MCP_RECORDER_SINK_TOKEN_FILE`) are excluded from that, along with the rest
of the `MCP_RECORDER_*` namespace: the agent never sees them, so no query needs
them — and fingerprint refs are unsalted by design, so for a low-entropy token
the ref is recoverable by brute force. Shipping one would mean handing the
receiver a reversible copy of its own bearer credential, on every event it
accepted. The exclusion lives in the collector
(`collectEnvCredentialFingerprints`, `src/redact/redactor.ts`), not in a filter
somewhere downstream. Found by local dogfood 6.

### Request

```
Content-Type: application/json
Content-Encoding: gzip            (optional; receiver MUST also accept absent)
Authorization: Bearer <install token>
X-MCPR-Protocol: 1
X-MCPR-Key: <64-hex ed25519 public key>
X-MCPR-Content-Sha256: <64-hex sha256 of the DECOMPRESSED body bytes>
X-MCPR-Signature: <128-hex ed25519>
X-MCPR-Sent-At: <ISO-8601 UTC>    (advisory only, never trusted for ordering)
Idempotency-Key: <64-hex>         (= X-MCPR-Content-Sha256; optimisation only)
```

The signed payload is domain separated exactly as `signedPayload()` already
is for heads:

```
edut.mcp-recorder.sink.v1\n<chain_id>\n<from_seq>\n<to_seq>\n<content_sha256_hex>
```

The digest is over the **decompressed** bytes, deliberately: a
TLS-terminating corporate proxy or an agent proxy may re-encode the transfer,
and hashing the compressed octets would break the signature on a working
path.

Receiver order of operations: decompress under a byte budget → hash →
compare header → verify signature → **only then** `JSON.parse`. Untrusted
JSON is never parsed before the signature check.

### Body

```jsonc
{
  "protocol": 1,
  "chain_id": "<64hex>",              // MUST equal the path segment
  "key": "<64hex>",                   // MUST equal X-MCPR-Key
  "from_seq": 401,
  "to_seq": 612,
  "base_hash": "<64hex>",             // == records[0].prev_hash
  "records": [ /* ChainRecord, verbatim, contiguous, ascending */ ],
  "signatures": [ /* every stored sig with from_seq <= seq <= to_seq */ ],
  "head": { "seq": 900, "hash": "<64hex>", "signature": { /* HeadSignature */ } },
  "sender": { "tool_version": "0.1.0", "surface": "record|hook|http|ship",
              "backend": "sqlite|jsonl" }   // advisory, never authoritative
}
```

`records` are the objects `iterate()` yields, **verbatim**. Re-serialising the
transport JSON is fine (the hash is over `canonicalJson(event)`, not over the
wire bytes), but nothing inside `event` may be added, removed or rewritten —
`computeHash` would not reproduce `record.hash`.

This is what structurally enforces the no-readable-payload rule on the wire:
values were hashed to `sha256:` refs by the redactor long before they reached
the store, the sink transmits exactly what was sealed, and it **cannot** widen
that without failing verification. There is no second redaction pass and no
opportunity for one.

The body carries no session id, no tool name, no counts, nothing derived.
Everything the receiver needs is inside the sealed records. *A derived field
is a field that can lie.*

`head` is the anti-withholding device. If `head.seq > to_seq`, the receiver
knows precisely how many sealed records are being held back — and it is the
sender's own key that says so.

### Heartbeat

The same POST with `records: []`, `from_seq = to_seq = 0`, and a `head`.
Every 60 s when idle and healthy. Silence at the receiver becomes a
detectable, alertable condition.

### Caps and compression

Identity below 8 KiB, `node:zlib.gzip` (async, never `gzipSync`) above.
Sender: ≤512 records or ≤1 MiB uncompressed per POST, whichever binds first —
always at least one record even if that record alone exceeds 1 MiB. On a 413
the sender halves its batch size for that chain; a 413 on a **one**-record
batch stalls the chain rather than skipping, because a skipped record makes
every later record unverifiable at the receiver forever.

### Cursor

Returned by 200, 202 and both 409s.

```json
{ "chain_id":"<64hex>", "key":"<64hex>",
  "next_seq": 613, "head_hash":"<64hex>",
  "attested_seq": 600, "attested_at":"...Z",
  "max_records": 5000, "max_bytes": 8388608, "heartbeat_interval_s": 60 }
```

- `next_seq` — first seq the receiver does not have. **The** authoritative
  resume point.
- `head_hash` — the receiver's hash at `next_seq - 1` (`GENESIS_HASH` when
  `next_seq == 1`). The sender compares it to its own local record's hash; a
  mismatch means the receiver's view is not this chain, and the sender
  **refuses to ship** (fork or MITM — shipping would corrupt one of the two).
- `attested_seq` — highest seq covered by a signature the receiver
  cryptographically verified. Separates "delivered" from "attested".

`<data-dir>/sink-cursor.json` caches this to avoid a round trip. It is never
authoritative: the sender re-reads the receiver's cursor on startup, on any
409 and on any 4xx, and the receiver never takes the sender's word —
`from_seq` and `base_hash` are *claims* that must link to state the receiver
already holds. Overlap is legal and expected (`from_seq <= next_seq <=
to_seq + 1`); the receiver hash-checks the overlapping prefix and commits only
the suffix. That is what makes a stale cache harmless.

---

## Auth

Two layers, separate jobs. Collapsing them is the mistake this design exists
to avoid.

**Layer 1 — bearer token (channel authorisation).** One opaque 256-bit token
per install. It answers exactly one question: *may this connection write to
tenant T at all.* Rotatable and revocable server-side. On an unsegregated
laptop the observed agent can read it.

**Layer 2 — the data dir's existing ed25519 identity (content
authentication).** `src/chain/keys.ts` already mints one keypair per data dir,
signs every chain head with it, and `verify` already pins it. Every request
carries `X-MCPR-Key` plus a detached signature over the domain-separated
payload above. **The receiver files records under the key, never under the
token.**

The shipper loads it with `Signer.loadExisting(dataDir)`, never
`Signer.load()`: `load()` happily mints a fresh identity on a dir that has
none, and a shipper doing that would start signing under an identity that
never touched the evidence.

### What a stolen token lets an attacker do

| | |
|---|---|
| Write into **another install's** chain? | **No.** That needs B's *private* key, which the token is not and does not contain. Without the per-request signature this property would not exist — a token holder could POST records claiming any key. That is why the request signature is mandatory, not a nice-to-have. |
| **Forge events** that verify? | **No.** Both `verifyRecords()` and the receiver recompute `record.hash == computeHash(prev_hash, event)` and check every `HeadSignature` against its key. Forgery requires the private key. |
| **Delete** history? | **No.** There is no DELETE and no UPDATE in the API, and the commit is insert-if-absent on `(chain_id, seq)`. Retention is an operator-side policy, never a client-reachable operation. |

What it **does** buy, stated plainly so nobody oversells it: creating new
chains under the attacker's own freshly minted key if the tenant permits open
enrolment (spam — which is why enrolment should be pinned); reading the cursor
for any `chain_id` they can guess (a 256-bit hash; leaks `next_seq`/
`head_hash`, never content); and burning rate limit. All three are nuisance,
not evidence compromise. The design places no confidentiality or integrity
weight on the token.

### Enrolment

- **Pinned (fleet).** The operator registers the install's public key out of
  band; it is in `identity.pub` and printed by `setup`/`sessions`. Unknown key
  → 403. The right default for a managed fleet.
- **TOFU (laptop / self-serve).** The first key seen on a token is bound to
  it. Later keys are accepted but flagged `new_identity` and do not count as
  attested until an operator acknowledges.

Rejected: an HMAC derived from the bearer token instead of the ed25519
signature — it collapses the two layers and makes a stolen token sufficient
to forge. Also rejected: a fresh per-batch keypair, which would have nothing
binding it to the chain that `verify` already pins.

---

## Failure semantics

**The invariant first.** The sink never runs on the forwarding path. It does
not call `record()`, never holds the store's write lock while doing I/O, and
in the default deployment does not run in the proxy's process at all.

The shipper is a separate process — `mcp-recorder ship`, detached and
`unref`'d, one per data dir, single-instance via a `<data-dir>/ship.lock`
directory. `record`/`http`/`hook` do exactly one sink-related thing: a
`statSync` liveness check and, if needed, a spawn-and-forget, wrapped in
try/catch, failure a no-op.

This is forced, not preferred: `hook` is a short-lived process **per hook
invocation**, so there is no long-lived event loop to host an in-process
shipper, and blocking a hook on a POST would put sink latency directly in
front of every tool call.

**The spool is the chain.** There is no second queue and no separate spool
file; the shipper reads with `store.iterate({fromSeq, toSeq})`. The jsonl
backend's read methods do not take the advisory write lock, and sqlite reads
under WAL, so a shipper never contends with a recording process. The only
extra durable state is a few hundred bytes of cursor cache.

**The shipper never appends to the chain.** Writing a "shipped" event would
change the chain it is trying to ship.

In every case below, what the agent experiences is **nothing**: no added
latency, no denial, no non-zero exit, no changed stdout byte.

| Condition | Local store | Behaviour |
|---|---|---|
| Sink down / DNS / TLS / refused | untouched, keeps growing | exponential backoff with full jitter, `delay = random() * min(300s, 1s * 2^n)`, forever, no attempt cap, `n` reset on any 2xx. The whole backlog ships from the receiver's `next_seq` on reconnect. |
| Sink slow | untouched | 10 s connect, 30 s total. A timeout is transient: back off and re-send the same range (idempotent). The lag is quantified and signed: `head.seq - next_seq`. |
| Sink 500 | untouched | same backoff; `Retry-After` honoured when present. |
| 401 / 403 | untouched | longer backoff (base 60 s, cap 15 min), plus one immediate retry after a shipper restart (the token may have been rotated). Exactly one stderr line. `ship --status` prints `unauthorized`. |
| 429 | untouched | `Retry-After`, else standard backoff. |
| 400 twice on the same range | untouched | rebuild the batch from the store once; if it 400s again, **stall** that chain, log once, keep heartbeating. Stalled, never discarded — the receiver then sees its cursor frozen while signed heads keep climbing, which is an explicit withholding condition rather than silence. |
| 409 `chain_gap` | untouched | rewind to the receiver's `next_seq` and re-send. If the local store no longer holds it, **stall and surface**. Never jump a gap. |
| 409 `chain_fork` | untouched | **terminal** for that chain. Stop shipping it, one loud diagnostic, keep recording locally and keep heartbeating. This is the tamper signal and is never auto-reconciled. |
| The sender's OWN chain fails verification | untouched | **stall** before the batch reaches the wire, log once (pointing at `mcp-recorder verify`), keep heartbeating. See [The sender verifies its own chain](#the-sender-verifies-its-own-chain). |
| 413 on a one-record batch | untouched | long backoff, stall, surface. Never skip. |
| Process SIGKILLed with events "unsent" | untouched | there are no unsent events in the usual sense — everything `record()` sealed is already in the store. The shipper is crash-only by construction; the next start reads the receiver's cursor and ships the backlog. If the machine never comes back, the receiver holds everything up to the last 202 **plus a signed head proving how much more existed** — strictly better than the old branch-push, which on an unclean end shipped nothing at all. |
| Disk full | the existing fail-open path | there is no separate spool, so the sink adds no new disk pressure. Disk-full lands on `store.appendEvents`: `Recorder.drainOnce` retries, then counts `dropped` and writes one stderr line. Those drops surface as `SessionEndEvent.events_dropped`, **and that event itself ships**. So a disk-full drop is a *counted* drop that reaches the receiver, never a forged continuity. |

Explicitly not retried: a `chain_fork`, and a batch the sender cannot rebuild
from its own store. Both stall loudly rather than degrade quietly.

**Ordering:** strictly one in-flight POST per chain. Pipelining would let
batch N+1 land before N; a single chain's throughput is bounded by tool-call
rate, not RTT.

**Boundary with gateway mode: none.** Enforcement stays fail-closed and is
decided entirely inside the proxy process from `policy.yaml`. A sink that is
down, slow, 500ing or 401ing cannot produce a deny, cannot delay a hold, and
cannot change a hold's outcome. The two never share a code path or a timeout
budget.

### How a gap becomes visible rather than silent

Three independent mechanisms, because this is the property the whole design
turns on.

1. **Structural.** seq is contiguous and `prev_hash`-linked, so a missing
   record is a `seq_gap` that the receiver's own `verifyRecords` reports. The
   sender cannot manufacture continuity across a gap without the private key.
2. **Signed head.** Every POST and every heartbeat carries
   `head = signer.sign(localHead.seq, localHead.hash)`. Delivered-vs-claimed
   is a subtraction, attested by the sender's own key.
3. **Heartbeat absence.** The only detector for "shipper killed" or "network
   blocked" — which is why absence alerting is a contract obligation on the
   receiver, not a feature.

### The sender verifies its own chain

Shipping forward from the receiver's cursor says nothing about the records
*behind* it. Local dogfood 6 turned that into a working attack with `cp -a`
and one edited field:

1. copy a data dir, rewrite the event at seq 7 in place and leave every stored
   `hash`/`prev_hash` alone, so the head hash the receiver knows still
   matches;
2. record a new session into the copy — its shipper delivered seq 12-22 and
   the receiver accepted them, because they link to seq 11 exactly as the
   honest ones would;
3. when the honest store shipped its own seq 12, **it** got the `chain_fork`
   409 and the receiver alerted "history was rewritten" against it.

Fork detection worked. Attribution was decided by arrival order, and neither
side ever said that the copy's own store fails `mcp-recorder verify`.

So a batch is now gated on a recomputation of the sender's own chain, from
seq 1 through the last record of that batch. A store that cannot verify that
far **stalls** — the batch never reaches the wire, `ship --status` reads
`stalled` with the offending seq in `last error`, and the heartbeat keeps
running so the receiver sees the signed head climbing while the cursor stays
frozen. That is the explicit withholding condition, which is what a rewritten
history should look like from the outside.

What it costs, measured on this repo's own code (Node 22, jsonl backend):
hash recomputation runs at ~15 µs/record, while one ed25519 verification costs
~2 ms — and a store signed on every flush, which is what the recorder does,
holds roughly one signature per record. Verifying all of them would be
~2 ms/record. It is unnecessary: the chain hash at seq *j* is a running
commitment over every event at or below *j*, so recomputing the chain and then
checking **one** signature per 2 000-record window pins the whole prefix.
Measured first pass: 0.4 s over 20 000 records, 1.9 s over 100 000 — against
4.1 s for `verifyStore` over the smaller of the two — once per shipper
process, in a detached process that is on nobody's forwarding path. The
verified frontier is then monotonic, so later batches pay only for their own
records (3 ms in the same measurement), never an O(n) scan per batch. Nothing
about this touches the proxy, the hook or a tool call; recording stays
fail-open in every case.

Deliberately not done: caching "verified through seq N" in a file beside the
store. That file would be written by the same user the store is, so an
attacker who rewrites history would rewrite the receipt too. The check is
per process, and restarting the shipper is what re-runs it.

That last sentence is a real limit, not a footnote: a shipper **already
running** does not re-examine history at or below the frontier it has already
verified. Measured on a live store — a shipper up since seq 17 shipped seq
18-21 out of a store whose seq 3 had been rewritten under it and reported
`idle`, while a shipper *started* on that same store stalled immediately with
`hash_mismatch at seq 3`. The exposure is bounded by the process: every
`record` / `http` / `hook` run starts a shipper afresh, and `--idle-exit`
(15 minutes by default) retires an idle one. So a rewrite is caught on the
next shipper start rather than on the next batch, and `mcp-recorder verify` —
which reads from seq 1 every time — is what renders a verdict on a store at
any given moment.

| Rewrite | Caught by |
|---|---|
| Event edited in place, hashes untouched | `hash_mismatch` in the sender's own pass (the dogfood-6 attack) |
| Event edited and hashes re-linked, no key | the window's newest head signature still attests the pre-rewrite chain hash: `signature_chain_mismatch`. In the delivered prefix the receiver's `head_hash` also disagrees, which the head-hash guard reports as a fork |
| Record deleted, duplicated, or the tail truncated | `seq_gap` / `duplicate_seq` / `prev_hash_mismatch` |
| Rewrite below the frontier of a shipper that is **already running** | nothing until that shipper is replaced — the frontier is monotonic per process. Caught on the next shipper start (measured above), and by `mcp-recorder verify` at any time |
| Rewrite re-signed with `identity.key` | **nothing local.** The signing oracle is on the attacker's side of the boundary (see the threat model) |
| A signature by a key other than this data dir's `identity.pub` | `signature_invalid`. The check pins the key exactly as `mcp-recorder verify` does, so a chain whose history was signed under an identity that has since been replaced stalls rather than ships |
| A chain with no signatures at all | nothing: absence of a signature is not evidence of tampering, so it is a warning here and a verdict for `mcp-recorder verify`, not a reason to stall |

---

## What a receiver must do

Beyond ingest, three obligations:

- **Store `received_at` beside every record.** It is the only metadata the
  sender does not control. Event `timestamp` is `Date.now()` on the observed
  machine — a claim, not a clock.
- **Alert on absence of heartbeat.** Not optional. A receiver that does not
  alert on silence has not implemented this design.
- **Receiver-side `export` must truncate.** The receiver holds no private key,
  so it cannot re-sign. `exportBundle()` signs a fresh head at
  `records[last].seq`; a receiver-side bundle must instead truncate
  `range.to_seq` to the highest seq covered by a stored valid signature and
  set `manifest.signature` to that signature, or `verify --bundle` reports
  `bundle_manifest_mismatch`.

Per-batch verification, before committing:

1. digest matches header; ed25519 request signature verifies against `X-MCPR-Key`
2. `key` enrolled for the token's tenant; `chain_id` unbound or bound to this key
3. records contiguous and ascending; `records[0].prev_hash == base_hash`; `records[i].prev_hash == records[i-1].hash`
4. for every record, `record.hash == sha256(prev_hash + "\n" + canonicalJson(event))` — *a receiver that skips this is storing whatever it was told*
5. the batch links to what is already stored (or overlaps it identically)
6. every `HeadSignature` verifies against its `public_key`, that key equals `X-MCPR-Key`, and its `chain_hash` equals the receiver's **recomputed** hash at that seq
7. `head.signature` verifies over `signedPayload(head.seq, head.hash)`
8. commit durably, **then** respond 202

This is deliberately the same algorithm as `src/verify/verify.ts`. A reference
receiver should call that code path so the two cannot drift.

Status codes: 202 durably committed (fsync'd/transaction committed *before*
the response — "accepted" means persisted, not enqueued); 200 heartbeat/cursor
read; 400 `bad_request` (permanent for those bytes); 401 `unauthorized`; 403
`forbidden` (key not enrolled, or `chain_id` bound to a different key); 409
`chain_gap`; 409 `chain_fork`; 413 `too_large` with `{max_records, max_bytes}`;
429 with `Retry-After`. A receiver must accept ≥8 MiB uncompressed and ≥5000
records, and a single-record batch up to 32 MiB, and must bound inflation.

---

## Threat model

### What it defends against

1. **Retroactive editing.** Once a record is 202'd it is fixed. Editing the
   local store afterwards produces a `chain_fork` on the next ship, or a plain
   divergence the receiver's copy contradicts. The git-branch transport left
   the evidence local until a human remembered to export — a wide-open rewrite
   window. This closes it to seconds. And the edited store stops shipping
   altogether: the sender recomputes its own chain before extending the
   receiver's, so a rewritten history can no longer quietly append to the
   remote copy and leave an honest peer to be blamed for the fork (see
   [The sender verifies its own chain](#the-sender-verifies-its-own-chain)).
2. **Selective deletion.** Removing a record breaks `prev_hash`; re-sealing
   from that point yields different hashes at seqs the receiver already holds.
   There is no way to delete from the middle and have the tail accepted.
3. **Truncation.** Dropping the tail and continuing forks at the first reused
   seq. Dropping the tail and starting over mints a new `chain_id` under the
   same key — a loud "second chain for an enrolled key", not a silent reset.
4. **"It just didn't happen."** The signed `head` makes withholding measurable
   and self-incriminating.
5. **Silence.** Killing the shipper, blackholing DNS, dropping egress — all
   produce absence at the receiver. Absence is only a defence if the receiver
   alerts on it.
6. **A stolen sink token.** No cross-install writes, no forgery, no deletion.
7. **A hostile sink URL pointed at a real receiver.** The receiver refuses a
   batch signed by an unenrolled key (pinned mode) and refuses one that does
   not link to what it holds.

### What it cannot defend against

1. **A forged chain.** `identity.key` is mode 0600 under the *same user* the
   agent runs as. An agent that can read it can sign anything: a clean
   parallel history, events that never happened, a plausibly quiet afternoon.
   No protocol work fixes this — the signing oracle is on the attacker's side
   of the boundary. The mitigation is operational.
2. **Never recording at all.** `MCP_RECORDER_DISABLE=1`, deleting the hook
   entry from `.claude/settings.json`, editing `.mcp.json` to drop the
   wrapper, or calling the MCP server directly. The recorder sees what is
   routed through it, and the agent controls the routing on its own machine.
   (Claude Code snapshots hooks at session start, which cuts both ways: an
   agent cannot uninstall the hook mid-session, but it also cannot be
   installed mid-session.)
3. **Pointing the sink elsewhere.** If the agent can set
   `MCP_RECORDER_SINK`, it can ship to its own collector and the real receiver
   sees silence. This degrades to case 5 — detected, not prevented.
4. **Wall-clock lies.** Event `timestamp` is `Date.now()` on the observed
   machine. The receiver's `received_at` is the only trustworthy clock.
5. **A compromised receiver, or an operator who never looks.** The replica is
   only as good as the alerting on top of it.
6. **A sender that is not this program.** The self-check binds the shipper in
   this package; anyone who writes their own client can still POST a batch
   from a rewritten store. What that buys them is bounded — the receiver
   recomputes every hash and refuses anything that does not link — but if it
   *does* link, the receiver still decides which branch is canonical by
   arrival order. Deciding a fork by evidence rather than by arrival is the
   receiver's problem, not the sender's, and it is not solved here.

### What a customer must do at the OS / fleet level

- **Run the agent as a different, less-privileged user than the recorder.**
  `identity.key`, the data dir and the sink config must be unreadable and
  unwritable by the agent's uid. This is the single highest-value control and
  the only thing that defeats case 1. Everything else is secondary. Note the
  tension with today's default (`~/.mcp-recorder`, mode 0700 under the agent's
  own user).
- **Pin the config outside the agent's reach.** Sink URL and token in a
  root-owned MDM profile, systemd `Environment=`, or launchd plist — not a
  shell profile or a repo file. For Claude Code, the managed-settings path
  (`/Library/Application Support/ClaudeCode/managed-settings.json`,
  `/etc/claude-code/managed-settings.json`) rather than
  `.claude/settings.json`, which the agent can edit.
- **Make the shipper non-optional.** A supervisor restarts it and the agent's
  uid cannot signal it. A killed shipper then means a killed machine, which is
  a different and louder alert.
- **Alert on absence.** Enrolled install with no heartbeat for N intervals =
  incident. Without this, the entire design is opt-in on the attacker's side.
- **Egress control.** Allow the sink host, deny arbitrary egress from the
  agent's uid, so "ship to my own collector" is a blocked connection rather
  than a silent success.
- **Hardware-backed keys** if case 1 must be closed cryptographically. A
  TPM/Secure Enclave/YubiKey key is unexportable, so a compromised agent can
  sign while running but cannot forge history offline or on another machine.
  The sink's signer interface is two members wide (`publicKeyHex`,
  `signBytes`) precisely so an external signer is a drop-in. Not what ships.
