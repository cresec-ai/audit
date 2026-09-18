# The proof of value, and the two repositories behind it

This document does two things. It reconciles `@edut/mcp-recorder` (this
repository) with `cresec-ai/nhi` into one architecture and one backlog, and it
sets out what a proof of value actually looks like day by day — what happens in
the room, what the customer can see, and which of it is real today.

Every capability named here carries a status, and the statuses are load-bearing:

| tag | meaning |
|---|---|
| **shipped** | on `main`, with a test or a named live run behind it |
| **in-flight** | written but not landed; named branch or worktree |
| **needs-build** | does not exist; the roadmap says roughly what it costs |
| **needs-nhi** | exists in NHI but needs its control plane stood back up |
| **aspirational** | nobody has built it and it is not scheduled |

A narrative that quietly assumes a **needs-build** capability is worse than
useless — it gets caught in the room. [What we do not
claim](#what-we-do-not-claim) is the list that keeps that from happening, and it
is the most important section here.

---

## The two repositories

**`@edut/mcp-recorder`** (this repo) is the agent-side vantage point. It is a
TypeScript npm package that runs on a laptop with no server, no database and no
network after install. Three vantage points: `record` (a transparent stdio proxy
in front of a local MCP server), `hook` (a Claude Code PreToolUse/PostToolUse tap
— the only third-party visibility anyone has found into Anthropic-hosted
connectors), and `http` (a recording proxy in front of a remote HTTP MCP server).
Gateway mode adds per-tool allow / hold / deny and a tool-result boundary filter.
Evidence is a hash-chained, ed25519-signed store with `verify`, `export`,
`query`, `sessions` and a replay timeline, replicated to an evidence sink as it
is recorded.

**`cresec-ai/nhi`** is the control plane: "the very first NHI (Non-Human
Identity) credential manager". A pnpm + Go monorepo — a Fastify API over
postgres, OpenBao and OPA, a Go data-plane proxy, an edge daemon, a web console,
browser extension, mobile apps and ZTNA connectors for eight vendors. Its core
flow is the one we care about: a **synthetic** credential
(`cresec_synth_v1_<base64url32>`) goes to the consumer, the real token stays in
the vault, and `POST /broker/exchange` swaps synthetic for real per call after an
OPA decision.

### They are halves of one product, not rivals

This is settled by NHI's own planning document, not by inference. The
12-week POC plan lists as **out of scope**: *"MCP-server-mediated AI agent
creds"* and *"per-call AI-agent scope enforcement SDK"*. mcp-recorder is exactly
the piece that was cut from that POC and built separately. The seam was even
pre-built from this side: `policy compile --target rego` emits a bundle
"for the Cresec control plane".

NHI has been dormant since 2026-05-25, and it is less finished than its surface
area suggests. Established by reading and running it, not by reputation:

- `issueSynthetic` has **zero call sites** — no code path in the running system
  can hand a working synthetic to anyone.
- A clean checkout cannot serve one successful exchange: three independent
  preseed denies (`unknown_data_plane`, `unknown_synthetic`, `vault_missing_token`),
  including a literal `fakeHash` where an HMAC belongs.
- The sole OPA deny rule keys on `input.context.rate_recent_min`, which
  `exchange.ts` never sends — so OPA returns allow unconditionally. The three
  passing Rego tests supply that field by hand, which masks the gap.
- `startCronJobs` is built and tested and **never called**, so nothing in NHI
  happens on a timer.
- There is **no authentication** across 21 route plugins; tenant-scoped
  endpoints trust a caller-supplied `tenant_id`.
- The revocation "wow moment" in the web console is, by its own source comment,
  *"POC: client component with local state so the demo works offline"*.

So NHI is a **specification with a lot of real code under it**, not a service.
That is not a criticism of the work; it is the difference between what can be
demonstrated next week and what cannot.

### Which implementation wins where

| Concept | mcp-recorder | NHI | Winner, and why |
|---|---|---|---|
| Evidence / audit chain | hash chain + ed25519 head signatures, `verify`, signed portable bundles, live sink replication with fork/gap detection, shipper self-check | `SHA-256(prev ‖ seq ‖ canonicalJson)` in postgres, daily S3 anchor whose writer is "interface-only" | **mcp-recorder.** Not only larger — differently positioned. NHI's chain is written by the control plane about its own decisions, which is the "trust the vendor's log" posture. mcp-recorder's is produced and signed at the observed party's edge, then replicated so the observed party cannot silently withhold. Those are different claims to an auditor. |
| Credential brokering | none until now | synthetic issuance, `/broker/exchange`, vault, per-tenant pepper | **NHI's design.** We mirror its wire contract and synthetic format exactly rather than inventing a second one. |
| Policy | `policy.yaml` v1, local engine, Rego compiler | OPA control plane, hand-written Rego bundle | **Split.** `policy.yaml` is the authoring surface and compiles to Rego; OPA is the fleet PDP. Today there are two authoring surfaces and that is a defect — see the roadmap. |
| Proxying | stdio + HTTP MCP proxies, MCP-aware | Go data-plane proxy, mTLS, LRU cache, NATS invalidation | **Both, different layers.** mcp-recorder sits on the tool-call path; NHI's proxy sits on the network path. Neither replaces the other. |

### The unified architecture

The agent side records and enforces at the point where an agent actually decides
to do something — the MCP tool call — and seals that into a signed chain the
customer holds. The control plane holds credentials, evaluates policy for a
fleet, and receives replicated evidence. **`decision_id`** is the join: it
already exists in NHI's `/broker/exchange` response, and adding it to the
recorder's own decision events is what makes the two sides one ledger instead of
two logs. The evidence sink's wire contract is the second seam; the Rego compile
target is the third.

---

## The proof of value, stage by stage

### Stage 1 — the first installation meeting

**90 minutes, one room, one volunteer laptop.**

Install *before* the meeting. The demo needs no network; the **install does**
(`npm install -g github:cresec-ai/audit#main` reaches GitHub and the npm
registry, and `demo/agent.ts` shells `npx tsx`). Do one throwaway warm-up run
too: a cold-start transport retry replays the whole story and reports doubled
numbers (18 events, 4 matches) as success.

**Minutes 0–10 — scope the surfaces out loud, before installing anything.** Three
columns on a whiteboard: Claude Code surfaces (per-call visibility and a gate);
local and remote MCP servers (full proxy); claude.ai web chat, Desktop chat and
Cowork (**no customer-side tap and no gate at all**). Saying this on day zero
rather than week three is the single highest-trust move available, and it is
already written down in `docs/connector-coverage.md`.

**Minutes 10–25 — the scripted incident.** `npm run demo` runs a prompt-injection
exfiltration end to end in about 5–8 seconds: an agent is tricked into reading a
credential and posting it to an attacker URL. On screen: `PASS — chain intact`,
then a blast-radius query on the canary returning exactly two rows — the read
matched at `$.result.content[0].text.secret_refs[0]` and the exfil at
`$.args.body`, linked by hash alone. Then `PASS: evidence bundle verified` from a
verifier with zero dependencies.

The moment that lands is the tool arguing against itself. It prints, unprompted:
`key check : NOT independently verified — the key came from this bundle
itself… Re-run with --public-key <hex|path> using a key you obtained out of
band`. A tool that volunteers the limit of its own proof buys more credibility
than the proof did.

**Minutes 25–40 — their laptop, their prompts.** `hook install`, then the
engineer works normally for twenty minutes and runs `sessions`, `verify`, `ui`.
Qualify this before booking the meeting: the installed matcher is `mcp__.*`, so
an engineer who only uses Bash and Edit produces an empty store.

**Minutes 40–60 — the four questions.** Does it slow anything down (p50 added
latency ~0.9ms, measured). What happens when you are down (fail-open recording;
`MCP_RECORDER_DISABLE=1`). What do I have to change (one config line, or
`setup --dry-run` shown as a diff). How do I get it out (`setup --undo` is clean;
`hook install --undo` is **not** — see the caveats).

> **Grep it in front of them.** Every argument value and every result string is a
> SHA-256 ref plus a length — search the store for their secret and it is not
> there. What *is* in clear is the hostname and OS username, deliberately, so a
> call can be attributed. Say that before they grep, not after.

### Stage 2 — 24 hours later

**No meeting, no dashboard, no alert. One ordinary day of traffic, then three
commands.**

`verify` over a chain now hundreds of events long. `sessions` showing one row per
session with events, tool calls, errors and servers. `query` against a value the
customer already holds.

The question that gets answered for the first time: *what have our agents
actually been touching?* A per-server, per-tool census read from observed
traffic — not from a config someone claims is current, and not from a scan.
Their SIEM cannot answer it, their CASB cannot, and their PAM cannot, because
none of them sit on the agent's tool-call path.

Three honest caveats. Accumulation is automatic **only after** the customer fully
restarted Claude Code (hooks are snapshotted at session start) and actually spent
the day in a Claude Code surface. The census itself is a Cresec engineer querying
the store — `sessions --tools` does not exist yet. And `server.url` is a
cloud-session property: on a laptop no `/tmp/mcp-config-*.json` exists, so vendor
origin is never resolved and host-alias rules are dead there.

### Stage 3 — the second meeting, 48 hours in

**This is the beat the POV turns on: the policy is written *from* the traffic, in
the room, and every rule is smoke-tested before anyone relies on it.**

1. **Write it from the census, not from a template.** Narrowest possible band —
   destructive operations only. Nothing else is denied this week.
2. **Anchor rules on the tool, leave the server segment open.**
   `^mcp__.*__clickup_delete_task$`, never `^mcp__mcp\.clickup\.com__…$`. That
   segment is platform-controlled, varies between sessions and surfaces, and on a
   laptop is never resolved at all.
3. **Smoke-test every rule in the room, with the exact observed spelling**, by
   piping a PreToolUse event into the real binary. The thirty seconds where a
   rule someone wrote from memory prints *nothing* justifies the whole meeting.
4. Turn enforcement on.

Tell them about dogfood 4 here rather than hiding it: two redundant deny rules
matched nothing, both live calls returned real data, and the only symptom was a
zero nobody was watching. That failure is why the smoke test exists.

**The moment:** his own connector call, denied, on his own laptop, in a real
session — and the denied attempt sealed into the same chain as everything else.
Not a screenshot, not a staging tenant.

### Stage 4 — one week in

**Two halves with two different truth values, and the second is introduced with
the words "in flight" before it is described.**

**Half A — real blocks on real traffic. Shipped, live-proven, and independently
enough to close a POV.** A week of the narrow deny band firing on genuine
developer traffic, counted rather than asserted: `export`, then count
`policy_denied` in the bundle. A wire diff showing allowed calls byte-identical
across the proxy and denied calls never reaching the server. A secret rewritten
to `[redacted:sha256:…]` before the model could read it.

The closing moment: **their** auditor, who has never met us, runs one command on
bare Node against a key handed over through a different channel, and gets `PASS`
over a week of their own agents' behaviour.

**Half B — the credential swap. Working against the built binary; not yet
watched in a live agent session.** The agent holds a synthetic; the gateway
swaps it for the real token at a declared site, and the real value reaches
neither the client nor the evidence chain.

Four end-to-end tests run the real binary and assert on what crossed the wire:
the server receives the real credential while the client and the chain see only
the synthetic; a tool that hands its input back gets the **synthetic**, because
an echo is not a declared site; a declared site aimed at an undeclared host is
denied and nothing is forwarded; and a positive control confirms that a secret
nothing excludes *is* fingerprinted, so the absence assertions cannot pass
vacuously.

**Proven live in dogfood 7** (`evidence/dogfood-7`): a real Claude Code agent
called the tool, the byte journal shows `Authorization: Bearer df7-real-…`
reaching the server, the chain holds only the synthetic's ref, and a second
call to an undeclared tool carried the synthetic out as written — destination
binding doing its job.

It took three attempts, and the first two are the reason this stage is worth
telling honestly. Claude Code sent the declared argument's parent as a JSON
**string** rather than a nested object, so the dot-path resolved to nothing
and the gateway **silently forwarded the synthetic** — no swap, no deny, no
log line. The cause was the tool's own `inputSchema` leaving the property
untyped; typing it fixed it on the first try, while saying so in the prompt
did not. The gateway now refuses that case (`site_arg_unresolved`) instead of
forwarding, and [docs/policy.md](policy.md) documents the trap.

Tell that story in the room. A control that silently does nothing is the
failure mode this product exists to make impossible, and we found it in our
own feature by running it for real.

The honest claim, and say it before the demo rather than after:

> Credential brokering keeps the real credential out of the model's context,
> out of the transcript and out of the evidence chain, and turns every use of
> it into a policy-checked decision recorded under a decision id. It does not
> hide the credential from anything that can run code as the same OS user —
> which includes the agent's own shell.

On a single-uid developer laptop this is a **context and audit** control, not a
confidentiality one. It becomes a confidentiality control only when the
resolver runs as a principal the agent is not: a root-owned config and
resolver, or the hosted control plane.

---

## Feature map

| Feature | Stage | Status | Owner |
|---|---|---|---|
| Transparent stdio proxy (`record`) | 1 | shipped | recorder |
| Scripted incident demo (`npm run demo`) | 1 | shipped | recorder |
| Hash chain + ed25519 signatures + `verify` | 1 | shipped | recorder |
| Signed bundle (`export`) + dependency-free verifier | 1, 4 | shipped | recorder |
| Blast-radius `query` | 1, 4 | shipped | recorder |
| Edge redaction (unsalted refs + length) | 1 | shipped | recorder |
| Added-latency bench (~0.9ms p50) | 1 | shipped | recorder |
| Fail-open recording, `MCP_RECORDER_DISABLE=1` | 1 | shipped | recorder |
| Claude Code hook tap | 1, 2 | shipped | recorder |
| `hook install` / `--undo` | 1 | shipped (rough edges) | recorder |
| `setup --dry-run` config diff | 1 | shipped | recorder |
| Replay timeline (`ui`) | 1, 4 | shipped | recorder |
| `sessions` as a connector inventory | 2 | shipped | recorder |
| Hook connector resolution → `server.url` | 2 | shipped (cloud only) | recorder |
| Live evidence sink + reference receiver | 2, 4 | shipped | recorder |
| Shipper self-check before extending a chain | 2 | shipped | recorder |
| Hook policy deny | 3, 4 | shipped | recorder |
| Gateway allow / hold / deny (`record --policy`) | 3, 4 | shipped | recorder |
| Tool-result boundary filter (secrets) | 3, 4 | shipped | recorder |
| Tool-result injection markers (**flag, does not block**) | 3 | shipped | recorder |
| `policy validate` + Rego compiler | 3 | shipped | recorder |
| Deny-rule smoke test as a command | 3 | needs-build | recorder |
| `sessions --tools` census | 2 | needs-build | recorder |
| `DECISIONS` counting both deny shapes | 2 | needs-build | recorder |
| npm publication | 1 | needs-build | recorder |
| Broker core + 7 credential sources | 4 | shipped | recorder |
| `credentials` policy section + Rego emitter | 4 | shipped | recorder |
| Gateway synthetic→real swap + result scrub | 4 | shipped | recorder |
| Broker end-to-end suite (4 tests, real binary) | 4 | shipped | recorder |
| Live dogfood run swapping a real credential | 4 | shipped (dogfood 7) | recorder |
| `decision_id` on decision events | 4 | needs-build | recorder |
| Gateway for HTTP MCP servers (`http --policy`) | — | needs-build | recorder |
| SIEM export | — | needs-build | recorder |
| Fleet aggregation, retention, anchoring | — | needs-build | both |
| Broker against real vault-held tokens | beyond 4 | needs-nhi | NHI |
| Synthetic issuance endpoint | beyond 4 | needs-build | NHI |
| Generic revoke endpoint → a real 403 | beyond 4 | needs-build | NHI |
| Sub-second revocation (NATS) | beyond 4 | needs-build | both |
| Control-plane auth + tenancy | beyond 4 | needs-build | NHI |
| Egress enforcement | — | needs-build | v2 sidecar |
| Credential swap for hosted connectors | — | **aspirational (architecturally impossible)** | — |
| Approvals inbox, Slack, fleet console | — | aspirational | v2 |

---

## What we do not claim

Each line was checked by running the thing, not by reading about it.

**Install and packaging**
- *"Just run `npx -y @edut/mcp-recorder`."* — `npm view` returns E404. Every
  `npx` line in our docs is a future form until we publish.
- *"Nothing in the first meeting needs network."* — the demo does not; the
  install does. Pre-stage it.
- *"The demo produces exactly 9 events in 5.0 seconds."* — 4.9s to 8.3s, and a
  cold-start retry can double the chain and still report success. Announce what
  is on screen.

- *"1,503 tests."* — true only where OPA is installed. The Rego parity tests
  self-skip without the binary, so a bare `npm test` reports **1,401**. CI's
  Linux job installs OPA and sets `MCP_RECORDER_REQUIRE_OPA=1`; the Windows job
  does not. Quote the environment with the number.

**Evidence**
- *"Nothing is stored in plaintext."* — every payload string is a ref, but
  hostname and OS username are plaintext by design. Frame it as attribution.
- *"The evidence is tamper-proof."* — tamper-**evident**. Hashes are unsalted by
  design, so a low-entropy secret is recoverable from its ref. On an
  unsegregated machine, an agent that owns the signing key can author the chain.
- *"Your auditor verified the bundle."* — not until they used `--public-key` from
  a channel that is not the bundle. The tool says so itself; lean on that.
- *"If it happened, `query` will find it."* — `query` matches whole values only.
  A miss means "not found this way", not "never happened".

**Enforcement**
- *"`ui --out` just writes an empty page if you forget `--data-dir`."* — it used
  to render `~/.mcp-recorder` silently. It now names the store on stderr, and
  the page header already carried `store: jsonl · /path/to/evidence.jsonl`, so
  a page handed to someone else does say where it came from.
- *"It stops prompt injection."* — `boundary.injection: flag` is the default and
  does **not** block. What prevents harm is a deny rule on the vector.
- *"`DECISIONS` shows how much we blocked."* — it reads 0 for every hook session
  regardless of denies.
- *"You can gate your remote HTTP MCP servers."* — `http --policy` exits 2.
- *"Your policy is enforced centrally by OPA."* — `policy compile` emits a bundle
  and nothing consumes it.

**Credentials**
- *"The agent never has access to your credentials."* — it does. It can read the
  environment variable, file or command the broker reads, and the policy that
  names them. What it does not have is a credential in its context or its
  transcript, and it cannot use one without leaving a decision record.
- *"Prompt injection cannot use your credentials."* — it cannot **steal** them,
  given destination-bound swapping. It can absolutely cause an authorised,
  policy-permitted use of one. The gain is that the use is bounded and on the
  record; narrow it with `hold` on high-impact sites.
- *"The real token never leaves the vault."* — true of the hosted control plane,
  false of the local broker, where the token is resolved on the same machine as
  the agent.
- *"Synthetic credentials are useless if stolen."* — useless off the machine;
  on the machine they are redeemable, and on the machine is where the attacker
  already is.
- *"Least privilege"* / *"scoped credentials"* — only where the policy constrains
  the destination as well as the tool. A `use` site with an unconstrained host
  is a full-privilege credential with extra steps, which is why the schema makes
  it an error rather than a default-allow.
- *"Revocation is instant."* — a cached decision is live for its TTL, and
  revoking does not recall a call already in flight. Quote the number.
- *"We have demonstrated the credential swap."* — it is proven against the built
  binary by four end-to-end tests. No live agent session has swapped a real
  credential yet. That run is the next item.
- *"Point it at Cresec and your synthetics keep working."* — a locally-minted
  synthetic cannot resolve against a real NHI: the per-tenant pepper lives in
  OpenBao and the HMAC is computed there.
- *"Cresec's control plane is ready."* — it cannot serve one successful exchange
  from a clean checkout, and has no authentication.
- *"We will swap the credential on your ClickUp or Gmail connector too."* —
  architecturally impossible. Hosted connectors authenticate on Anthropic's
  infrastructure. We can deny those calls; we can never swap their credential.
- *"Here is the revocation demo."* — do not show NHI's revocation screen. It is a
  client-side animation by its own source comment.

**Positioning**
- *"This is Venice.io for AI agents."* — we ship their discovery pillar (from
  observed traffic rather than scanning) and their contextual-decision pillar,
  plus signed replayable accountability they do not have in this form. We do
  **not** ship ephemeral just-in-time privilege yet. Venice sells a deployed,
  agentless product with named displacements; do not imply parity.
- *"It rolls up across your fleet."* — no fleet view, no aggregation, no
  retention, no pruning, no external anchoring.
- *"`setup` will rewrite your configs safely."* — rated **Tested, not Verified**:
  no real client has ever launched what it wrote. Use `--dry-run` in the room.

---

## The critical path

The shortest ordered list that makes the week-one POV deliverable end to end.

1. **Pre-flight hardening** — `hook install` creates `.claude/`; `--undo` is
   byte-exact and its backups are gitignored; `ui --out` refuses to silently
   render the default store; the demo cleans up and fails on the doubling retry.
2. **`DECISIONS` counts both deny shapes** — otherwise Stage 4 under-reports the
   customer's own controls to zero.
3. ~~Land the broker core, the `credentials` policy section and the gateway
   swap, and write the end-to-end suite.~~ **Done** — landed together, wired
   into the binary, 4 end-to-end tests against the real CLI, 1,643 tests green.
4. ~~One dogfood run swapping a real credential in a live agent session.~~
   **Done** — dogfood 7, bundle and byte journal committed to
   `evidence/dogfood-7`. It also found and closed a silent no-op.
5. **`decision_id` on decision events** — the join key to the control plane.
   Now the only item left on this path.

Deliberately **not** on the path: everything in NHI. A one-week POV as scoped
here runs end to end with zero NHI infrastructure, because the broker resolves
locally. Repointing at the real control plane is week 2 or later and carries its
own list, behind a 2–4 week authentication gate before any real customer
credential may flow through it.

---

## Where to read next

- [`docs/connector-coverage.md`](connector-coverage.md) — the Stage 1 coverage statement
- [`docs/roadmap.md`](roadmap.md) — the consolidated backlog behind this story
- [`docs/gateway.md`](gateway.md) — how enforcement actually behaves
- [`docs/sink.md`](sink.md) — the evidence sink wire contract and threat model
- [`docs/deployment.md`](deployment.md) — what a customer install looks like per platform
