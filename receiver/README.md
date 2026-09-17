# Reference evidence receiver

A running endpoint that accepts sealed `ChainRecord` batches from
`mcp-recorder`, **verifies** them, and stores them as an append-only replica
off the recorded machine.

It exists so that evidence stops depending on the observed party to deliver
it. Today a bundle reaches an auditor only because someone remembered to run
`mcp-recorder export` and push a branch — batch, manual, and entirely under
the control of the agent being watched. This receiver makes the same evidence
land within seconds, makes editing it afterwards detectable, and makes
withholding and silence measurable.

```
npm run receiver -- serve --data-dir ./receiver-data --port 8787
```

---

## What this is NOT

Read this part first.

- **Not the hosted service.** No SLA, no upgrade path, no migrations.
- **Not multi-tenant hardened.** Tenancy is a string on a bearer token. There
  is no per-tenant quota, no rate limiting, no abuse handling, no billing, no
  audit log of operator reads. A tenant that misbehaves affects every other
  tenant on the process. In particular `rejections.jsonl` grows without
  bound and an *unauthenticated* caller can make it grow, so put this behind
  something that rate-limits before exposing it.
- **Not tuned.** All disk I/O is synchronous, on the request path, and every
  chain's `seq -> hash` index lives in memory for the process lifetime. That
  is fine at tool-call rates and for a dogfood; it is not fine for a fleet.
- **Not TLS by default.** It binds `127.0.0.1` and speaks plain HTTP unless
  you pass `--tls-cert`/`--tls-key`. Anything real belongs behind a TLS
  terminator. The sender refuses a non-loopback `http://` sink, so this is a
  deliberate dead end rather than a tempting shortcut.
- **Not a retention system.** Nothing here ages data out. Nothing here
  deletes. That is on purpose (see *No mutation verbs*), and it means disk is
  your problem.
- **Not an alerting system.** It raises alerts to `alerts.jsonl` and stderr
  and exposes them over HTTP. Turning those into a page at 3am is yours.

What it *is*: a complete, honest implementation of the receiving half of the
wire contract, small enough to read end to end, with the rejection cases you
actually need covered by tests.

---

## Quick start

```bash
# 1. an ingest token, the only thing an install needs besides the URL
mkdir -p ./receiver-data
cat > ./receiver-data/tokens.json <<'JSON'
{
  "tokens": [
    { "id": "laptop", "tenant": "acme", "token": "<256-bit opaque token>",
      "enrolment": "tofu" }
  ]
}
JSON

# 2. run it
npm run receiver -- serve --data-dir ./receiver-data --port 8787

# 3. point an install at it
export MCP_RECORDER_SINK=https://sink.example.com
export MCP_RECORDER_SINK_TOKEN=<the same token>

# 4. look
npm run receiver -- status --data-dir ./receiver-data
```

With no `tokens.json`, `MCPR_RECEIVER_TOKEN` (plus optional
`MCPR_RECEIVER_TENANT`, `MCPR_RECEIVER_ENROLMENT`, `MCPR_RECEIVER_KEYS`)
configures a single tenant. With neither, every POST is answered `401` — which
is the correct posture for a receiver nobody has configured, and the startup
banner says so.

An **operator token** is minted on first run into
`<data-dir>/operator-token.txt` (mode 0600) and printed at startup. It is
separate from the ingest tokens and only grants the read-only endpoints: an
install that can write cannot enumerate the fleet.

---

## The API

| Method | Path | Auth | Purpose |
| --- | --- | --- | --- |
| `POST` | `/v1/chains/{chain_id}/records` | install token | the only write |
| `GET` | `/v1/chains/{chain_id}/cursor` | install token | the resume oracle |
| `GET` | `/v1/health` | none | liveness, no data |
| `GET` | `/v1/chains` | operator token | what this receiver holds |
| `GET` | `/v1/chains/{chain_id}` | operator token | one chain, incl. fork branches |
| `GET` | `/v1/rejections` | operator token | every refusal, with its reason |
| `GET` | `/v1/alerts` | operator token | forks, silence, new identities |

### No mutation verbs

`DELETE`, `PUT` and `PATCH` return `405` on every path. That absence is
load-bearing, not tidiness: it is what makes "a stolen ingest token cannot
delete history" a property of the surface rather than a promise. Commits are
insert-if-absent on `(chain_id, seq)`; nothing a client can send removes or
rewrites a stored record. Retention is an operator-side decision, never a
client-reachable operation. (This mirrors the recorder's own posture — the
sqlite backend's `records_no_update` / `records_no_delete` triggers block
casual edits at the SQL layer.)

---

## The one deviation from the wire contract

**`X-MCPR-Range: <from_seq>-<to_seq>`**, and the receiver accepts requests
without it.

The contract says the request signature covers
`edut.mcp-recorder.sink.v1\n<chain_id>\n<from_seq>\n<to_seq>\n<content_sha256>`,
*and* that the receiver must verify that signature **before** it parses the
JSON. Those two cannot both hold as written: `from_seq` and `to_seq` are only
in the body, so a receiver has to read them from somewhere to build the
payload it is about to verify.

This receiver resolves it by accepting the range in a header, which is the
only form where "verify before parse" is literally true. Without the header
it falls back to reading just those two integers out of the (size-capped,
digest-checked) body, verifies the signature, and only then treats anything
in the body as meaningful — so a sender written to the contract as stated
still interoperates. `serve --require-range-header` turns the fallback off
for a deployment whose senders all send the header.

**Recommendation for the contract:** add `X-MCPR-Range` to the mandatory
header list. It costs one header and removes the ambiguity.

Two smaller tightenings, both strictly narrower than the contract:

- A cursor read is scoped to the token's tenant, and refuses a mismatched
  `X-MCPR-Key`. The contract accepts "read the cursor for a guessed
  `chain_id`" as a nuisance; there is no reason to leave it open.
- A chain whose first delivery is not `from_seq = 1` gets `409 chain_gap`
  pointing at `next_seq = 1`, because `chain_id` is *derived* from the seq-1
  record and cannot be checked until that record arrives. Until it does, the
  chain is flagged `chain_id_verified: false`.

---

## What it checks before it commits anything

In this order. A failure at any step stores nothing.

1. **Bearer token** → `401`. Cheap channel gate, before any cryptography.
2. **Header shapes** → `400`. `X-MCPR-Key` 64-hex, `X-MCPR-Content-Sha256`
   64-hex, `X-MCPR-Signature` 128-hex.
3. **Digest** of the *decompressed* bytes matches the header → `400`,
   compared with `timingSafeEqual`.
4. **ed25519 request signature** verifies against `X-MCPR-Key` over the
   domain-separated payload → `400`. *Before* the body is interpreted.
5. **Shape** of the parsed batch, and `chain_id` / `key` / range agreeing
   with the path, the header and the signed range → `400`.
6. **Caps** → `413` with `max_records` / `max_bytes`.
7. **Enrolment and binding** → `403`. The key must be enrolled for the
   token's tenant; a `chain_id` belongs to exactly one key, forever.
8. **The chain itself**, via `src/verify/verify.ts` — *the same function
   `mcp-recorder verify` runs*, called on purpose so the receiver's verdict
   and the tool's cannot drift:
   - records contiguous and ascending, `records[0].prev_hash == base_hash`,
     each `records[i].prev_hash == records[i-1].hash`;
   - **every** `record.hash == sha256(prev_hash + "\n" + canonicalJson(event))`
     — a receiver that skips this is storing whatever it was told;
   - the batch links to what is already stored, or overlaps it *identically*;
   - every `HeadSignature` verifies, is by `X-MCPR-Key`, and names the hash
     the receiver **recomputed** at that seq;
   - `head.signature` verifies over `signedPayload(head.seq, head.hash)`.
9. **Durable commit** — one `writeSync` plus `fsyncSync` — *then* `202`.
   "Accepted" means persisted, not enqueued.

Both ed25519 implementations run: `node:crypto` on the request/head
signatures, `@noble/ed25519` inside `verifyRecords` on the in-range head
signatures.

### The batch cannot widen redaction

`records` are stored verbatim, exactly as `iterate()` yielded them. Nothing
inside `event` may be added, removed or rewritten, because `computeHash`
would then not reproduce `record.hash` and step 8 rejects the batch. So the
"no readable payload strings" rule reaches the wire structurally: the sink
transmits precisely what the redactor already sealed, and there is no second
redaction pass and no opportunity for one.

---

## GAP is not FORK

They mean completely different things to an auditor, so they are different
responses with different consequences.

**`409 chain_gap`** — records are *missing*; what is here is still
consistent. `from_seq` is past the receiver's `next_seq`, so nothing links
the batch to the copy it holds. The cursor comes back in the body and the
sender rewinds. **Nothing is stored** and the gap is never bridged: a skipped
record makes every later record unverifiable here forever, which is far worse
than a visible stall. Ordinary cause: a sender that fell behind, lost its
cursor cache, or had its store repaired.

**`409 chain_fork`** — history was *rewritten*. A seq the receiver already
holds arrived with a different hash, or `base_hash` disagrees with the hash
at `from_seq - 1`, or the sender's own signed head names a hash the receiver
does not hold at that seq. This is **terminal** for the chain: it is marked
`forked`, it stops accepting, an alert is raised, and **both branches are
retained** — the original in `records.jsonl` with its arrival times, the
refused one verbatim in `forks.jsonl`. It is never auto-reconciled, because
auto-reconciling a fork is how a tamper signal becomes a merge conflict.

A third signal sits beside them: a **new `chain_id` under an already-enrolled
key** raises `second_chain_for_key`. That is what "the evidence store was
deleted but `identity.key` survived" looks like — a loud event rather than a
silent restart at seq 1. It is why `chain_id` is the seq-1 hash and not the
public key.

---

## Alerting on absence is an obligation, not a feature

Killing the shipper, blackholing DNS, revoking the token and switching the
machine off are indistinguishable at the receiver: nothing arrives. A
receiver that does not alert on silence has not implemented this design.

`scanForSilence()` runs on the heartbeat interval and raises `silent_chain`
once per outage (cleared by the next arrival), naming how long it has been
quiet and how many records the last signed head had already claimed. Wire it
to whatever pages you.

The complementary signal is in every POST and every heartbeat: `head` is the
sender's *current local head*, signed with its own key. `head.seq -
(next_seq - 1)` is exactly how much is sealed but undelivered — attested by
the sender's own signature, so withholding is a subtraction, not an
inference. `GET /v1/chains` reports it as `undelivered`.

---

## What lands on disk

```
<data-dir>/
  tokens.json                        you write this (or use the env form)
  operator-token.txt                 minted on first run, mode 0600
  enrolment.json                     tenant -> key -> {first_seen_at, acknowledged}
  rejections.jsonl                   every refusal, with its reason
  alerts.jsonl                       chain_fork | silent_chain | new_identity | second_chain_for_key
  chains/<chain_id>/
    meta.json                        cache; rebuilt from records.jsonl on start
    records.jsonl                    {"seq","received_at","record"} per line
    signatures.jsonl                 only signatures this receiver verified
    heads.jsonl                      every verified signed head claim + the lag then
    forks.jsonl                      the refused branch, verbatim
```

`cat`, `grep` and `jq` are the whole admin interface, and that is deliberate
for a reference implementation.

`received_at` sits beside every record because it is the only metadata the
sender does not control. Event `timestamp` is `Date.now()` on the observed
machine — a claim, not a clock.

`meta.json` is a *cache*. On startup the receiver replays `records.jsonl`,
re-derives `next_seq` / `head_hash` / `records_held`, and re-derives
`attested_seq` by checking each stored signature against the recomputed hash
at its seq. A crash between the fsync'd append and the meta rewrite repairs
itself.

---

## Enrolment

Two modes per token, the operator's choice.

- **`pinned`** (fleet, and the right default): the operator registers the
  install's public key out of band — it is in `<data-dir>/identity.pub` on
  the recording host and printed by `setup` / `sessions`. An unknown key is
  `403`.
- **`tofu`** (laptop / self-serve): the first key seen on a token is bound to
  it. Later keys are accepted and stored, but flagged `new_identity` and **do
  not count as attested** — `cursor.attested_seq` reads `0` for them — until
  an operator runs `ack-key`. Pragmatic, and the operator still gets the
  signal.

```
npm run receiver -- ack-key --tenant acme --key <64-hex>
```

---

## Exporting from the replica

The receiver holds no private key, so it cannot re-sign. `exportBundle()` on
the recording host signs a *fresh* head over the last record in the range; a
replica has nothing to sign with. So `exportReceivedChain()`:

- truncates `range.to_seq` to `attested_seq`, the highest seq covered by a
  signature this receiver itself verified, and
- uses **that stored signature** as `manifest.signature`.

Get either half wrong and `verify --bundle` reports
`bundle_manifest_mismatch` — the manifest would declare a head no signature
covers. Records past `attested_seq` are held and readable; they are simply
not in the bundle, because nothing attests them yet. The export prints how
many those are, and what the sender's last signed head claimed.

```
npm run receiver -- export --chain <chain_id> --out ./bundle
cd bundle && node verify.cjs        # zero dependencies, exit 0 = PASS
```

The bundle is produced by the product's own `exportBundle()` driven through
two read-only adapters, so the manifest, the README and the shipped
`verify.cjs` are identical to a recorder-side bundle. A stranger cannot tell
which side produced it, and does not need to.

---

## Operator commands

```
npm run receiver -- serve   [--data-dir DIR] [--host H] [--port N]
                            [--heartbeat-interval S] [--silence-after N]
                            [--require-range-header] [--tls-cert F --tls-key F]
npm run receiver -- status  [--data-dir DIR]
npm run receiver -- verify  --chain <chain_id> [--data-dir DIR]
npm run receiver -- export  --chain <chain_id> --out DIR [--zip FILE]
npm run receiver -- ack-key --tenant T --key <64hex>
```

`status` and `verify` read the data dir directly, so they work against a
receiver that is running, stopped, or on a disk you copied elsewhere.
`verify` re-runs `verifyRecords` over the whole stored replica and prints
what is attested versus what the sender claimed — the replica checking
itself, not just its ingest path.

---

## What this does and does not prove

It defends against retroactive editing (a record is fixed once `202`'d),
selective deletion and truncation (both fork at the first reused seq), "it
just didn't happen" (the signed head is self-incriminating), silence
(detectable, if you alert), a stolen ingest token (no cross-install write, no
forgery, no deletion), and a hostile sink URL pointed at a real receiver (an
unenrolled key is refused).

It does not defend against a **forged chain**. `identity.key` is mode 0600
under the same user the agent runs as; an agent that can read it can sign a
clean parallel history. No protocol work fixes that, because the signing
oracle is on the attacker's side of the boundary. Nor against **never
recording at all**, **pointing the sink elsewhere** (which degrades to
silence — detected, not prevented), or **wall-clock lies** in event
timestamps.

The claim to hold to, and not to oversell:

> The recorder does not prove what an agent DID. It proves what REACHED the
> chain, and that what reached it has not been altered since. On an
> unsegregated machine, an agent that owns the signing key can also author
> the chain.

The sink's contribution is narrower and still worth having: it makes the
record durable off-box within seconds, makes editing it detectable, and makes
withholding and silence measurable. Getting the full claim requires OS-level
controls the receiver cannot provide — running the agent as a less-privileged
user than the recorder, pinning the sink config out of the agent's reach,
supervising the shipper, alerting on absence, and controlling egress.

---

## Packaging

`receiver/` is **not** in `package.json`'s `files` array, so it is not in the
npm tarball. That is the right call: `files` ships `dist/` plus the docs a
*user of the recorder* needs, and the receiver is neither the product nor
something a recorder install should carry. It is run from a checkout
(`npm run receiver`), which is also how a customer would fork it into their
own service.

It imports only frozen modules from `src/` — `chain/hash.ts`, `chain/keys.ts`
(`publicKeyPem`), `verify/verify.ts`, `export/bundle.ts`, `schema/events.ts`,
`types.ts`, `version.ts` — and changes none of them. Nothing under `src/`
changed, so `dist/` is unaffected. It is covered by `npm run typecheck` (via
`tsconfig.test.json`'s `include`) and `npm run lint`.

Runtime dependencies: none beyond what the repo already has. `node:http`,
`node:https`, `node:zlib`, `node:crypto`, `node:fs` — plus `@noble/ed25519`
and `yazl` transitively, through `verifyRecords` and `exportBundle`.
