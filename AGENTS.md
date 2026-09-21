# Working in this repository

`@edut/mcp-recorder` is the MCP gateway and evidence-chain leg of Cresec
Governed Tools: a fail-open MCP recording proxy that wraps a stdio MCP server
and records every tool call, redacted at the edge, into a tamper-evident local
evidence store, and — with a policy file — an enforcing gateway over those
calls. Read `README.md` for the promises and `docs/event-schema.md` for the
frozen event format.

## The product this package serves

Governed Tools makes an internal tool hold no credentials: people sign in
through the company's Okta or Entra, every outbound call goes through a
gateway that resolves who the person is, checks policy for that person and
that tool version, injects that person's own credential, and writes a signed
record. Two repositories build it. The control plane — identity gate,
per-user credential vault, HTTPS egress gateway, policy, views — is
[cresec-ai/nhi](https://github.com/cresec-ai/nhi)'s job (its share of
Roadmap v2 runs through Phases 1–4 and 6. From a clean checkout of that
repository at `d1346a7` on branch `claude/routine-production-enterprise-mfrojx`,
`node tests/e2e/scripts/stack-local.mjs` brings up the api, the gateway, six
tool instances and the console against compose Postgres/OpenBao/NATS/OPA, and
its S0–S16 stack suite passes — at **L1**: nothing is deployed anywhere and
every vendor answer comes from a fake in its `tests/e2e/mocks/`). This package is the
MCP gateway and the evidence chain. `docs/pov.md` says what this package
contributes to the four-week proof of value, with a status on every
capability, and what it must not be claimed to do. Three of those five limits
still hold: no per-user identity (there is no Okta or OIDC code in this
package), no views, and no degrade mode. Two no longer do. **Actor claims on
events**: `identity.actor` (ADR 012's four fields) and `identity.actor_verified`
are stamped on every event for `record`, `http` and `hook` when the recorder is
started with `--identity-jwt` (`docs/event-schema.md:141-142`,
`test/identity.test.ts`); without a JWT an event is unattributed, as before.
**Per-user token injection**: `RemoteBroker` behind
`credentials[].broker: { kind: remote }` fetches the person's own token per call
from the control plane's `POST /v1/broker/user-token` (`src/broker/wire.ts`,
`src/broker/remote.ts`, S17a in `test/e2e/http-gateway.e2e.test.ts`) — tested
against a **fake** control plane only, never against the real one.

The build brief's invariants that bind this repository, numbered as in the
brief ([ClickUp](https://app.clickup.com/90182720801/docs/2kzmy791-558/2kzmy791-638)):

1. The tool holds no secret. Enforcement is credential absence, not policy
   text.
3. Every mediated call produces exactly one record, chained to the previous
   one, signed, verifiable offline by the customer with no network access to
   us.
4. No payload warehousing. Hash the full request, store a redacted form.
   Decide redaction before the first record exists.
8. Degrade, don't die. Gateway unreachable means the tool falls back to
   read-only, not to broken.

Invariant 3's chain, signature and offline-verifier clauses hold for the MCP
leg (the rules below are how); its exactly-one-record clause does not yet — a
gateway refusal writes a `policy_decision` and a `tool_call`, a hook call is a
`pre` + `post` pair, and fail-open recording can drop an event (see the
one-deny-event-shape ticket in `docs/pov.md`). Invariant 4 holds for the
stored form (redacted tree, hashed leaves, `result_hash` over the complete
result); a hash of the complete raw request is not recorded on `tool_call`
events. Invariant 1 is not met by this package alone: the local broker keeps
the real credential out of the model's context, the transcript and the chain
at declared swap sites, but the secret is resolvable on the agent's own
machine, so it is a context and audit control, not credential absence.
Credential absence is the control plane's per-user injection; `RemoteBroker`
is its client, wired behind `credentials[].broker: { kind: remote }` against
`POST /v1/broker/user-token`, tested against a fake control plane and not yet
run against a real one. Invariant 8 is not implemented here: `MCP_RECORDER_DISABLE=1`
removes enforcement entirely and there is no read-only fallback. A PR that
touches one of these says which. Package name, binary name, commands and the
event schema do not change with the positioning.

## Setup

Run `sh scripts/bootstrap.sh` once in a fresh checkout. It installs
dependencies (which also rebuilds `dist/`), is idempotent, and is safe to run
while other processes run it (it takes a lock). Every agent platform's own
setup hook calls the same script:

- Claude Code on the web: `.claude/hooks/session-start.sh` (SessionStart hook).
- GitHub Copilot coding agent: `.github/workflows/copilot-setup-steps.yml`.
- Cursor cloud agents: `.cursor/environment.json` (`install`).
- OpenAI Codex cloud: paste `sh scripts/bootstrap.sh` as the environment's
  Setup script (Codex has no in-repo setup file).

## Commands

- `npm run typecheck` — TypeScript, strict, over `src` AND `test`/`bench`/
  `demo`. Two configs, because `tsconfig.json` emits the committed `dist/`
  and must not compile the tests: `tsconfig.test.json` extends it with
  `noEmit` and the wider `include`. Add a new top-level TypeScript directory
  to that `include` or nothing will check it — vitest and tsx strip types
  rather than check them, so an unchecked test can call a one-argument
  function with two and stay green forever.
- `npm test` — vitest; spawns real child processes, takes about a minute.
- `npm run demo` — scripted prompt-injection incident, recorded and verified.
- `npm run bench` — latency gate (p50 added latency must stay under 5 ms).
- `npm run bench:gateway` — the same round-trip measured with a policy in
  force, so gateway-mode added latency is comparable to record mode. Opt-in;
  it does not change `npm run bench` or its gate.
- `npm run bench:boundary` — what the tool-result boundary filter costs
  synchronously on the forwarding path, by result size and content. Its ReDoS
  alarm is a ratio between cells of the same run (a scan that goes
  superlinear in input size), not a wall-clock threshold, so it holds on a
  loaded runner. Run by `npm test` and by CI.

## Rules that must hold

- `dist/` is committed, and package.json deliberately has NO `build`,
  `prepare`, `prepack` or `install` script — the compile step is `npm run
  compile`. npm runs a nested `npm install` inside a git clone whenever any of
  those script names exist, and on a global install (`npm install -g
  github:cresec-ai/audit#main`) that nested install runs in global mode and
  fails; with none of them present, npm packs the clone as-is and the
  committed `dist/` is what ships. After changing anything under `src/`, run
  `npm run compile` and commit the `dist/` changes with it — CI fails on a
  stale `dist/`. `tsconfig.json` pins `newLine: lf` so the output is identical
  on every platform.

- The event schema `edut.mcp-recorder.event.v1` is frozen: additive optional
  fields only, documented in `docs/event-schema.md`.
- Fail-open: nothing about recording may block, delay, corrupt or kill the
  traffic being forwarded. Synchronous waits on the proxy thread stay short.
- No readable payload strings ever reach the store, the replay page, or a
  bundle; tool arguments are hashed unconditionally.
- Never skip or weaken a test to get green.
- The evidence sink (`MCP_RECORDER_SINK`, `mcp-recorder ship`, `src/sink/`)
  is a read-only REPLICA and never runs on the forwarding path. It ships in
  its own detached process, one per data dir; `record`/`http`/`hook` do one
  `statSync` and at most a spawn-and-forget between them. It never calls
  `record()`, never appends to the chain, and has no second queue — the spool
  IS the chain, read with `store.iterate`. A sink that is down, slow, 500ing,
  401ing or hostile must never block a tool call, deny one, change a byte of
  stdout, change an exit code, or cost a local event. It cannot widen
  redaction either: records go on the wire verbatim, so a rewritten `event`
  stops reproducing `record.hash`. Never couple it to gateway enforcement —
  that is fail-CLOSED and decided entirely in-process. See docs/sink.md.

- Gateway mode — `record --policy` over stdio and `http --policy` over the
  streamable-HTTP transport (`src/cli.ts:219`, `--policy FILE   record / http`)
  — is the ONLY place the proxy may block, delay or rewrite traffic, and only
  for `tools/call` requests and their results. `src/proxy/http.ts:10` states the
  same rule for the HTTP leg ("GATEWAY MODE (`opts.gateway` present, i.e.
  `http --policy`) is the ONE place the above is set aside"); its tests are
  `test/http-gateway.test.ts` and `test/http-gateway-failclosed.test.ts`.
  Without `--policy` the byte-for-byte, fail-open behaviour above is
  untouched, on both transports. Inside gateway mode, recording stays fail-open (a store failure
  never becomes a deny) while enforcement fails closed (an unevaluable policy
  or an unwritable hold is a deny). Hold files under `<data-dir>/holds/` and
  `policy_decision` events carry hashed arguments only — the no-readable-
  payloads rule applies to them exactly as to the store. `policy.yaml` v1 is
  documented in `docs/policy.md` and its JSON Schema in
  `docs/policy-schema.json`; the TypeScript engine and the emitted Rego must
  stay semantically identical (the OPA parity test enforces it).

## The repository records itself

`.mcp.json` (Claude Code), `.cursor/mcp.json` (Cursor) and
`.codex/config.toml` (Codex CLI) wrap the demo `corp-notes` server and a
filesystem server with the recorder via `scripts/dogfood-wrap.sh`. Evidence
lands in `.mcp-recorder/` (gitignored); inspect it with
`npx tsx src/cli.ts sessions --data-dir .mcp-recorder`. Copilot's coding agent
and Cursor cloud agents take their MCP configuration from the platform
dashboard instead; the exact JSON is in `docs/install.md`. Never commit
`.mcp-recorder/`.

## Dogfood runs in spawned sessions

A dogfood run proves what the test suite cannot: real clients, real hosted
connectors, real failures. Past runs are on `evidence/cloud-dogfood-*`
branches, each with a `REPORT.md` and a signed bundle. Three practical notes
from the runs so far.

**The platform's names are not a stable interface, and the two sides of them
can disagree.** Claude Code picks both the `<server>` segment in
`mcp__<server>__<tool>` and the keys in `/tmp/mcp-config-<session>.json`, and
nothing makes them match. Dogfood 3 saw UUID keys with UUID tool names;
dogfood 4, a day later, saw UUID keys with *friendly* tool names
(`mcp__ClickUp__…`), and that one mismatch defeated both deny rules the run
existed to prove — both live ClickUp calls executed against the real
workspace, twice each, and the 62-event signed bundle (chain PASS) holds zero
policy decisions. Anything that resolves a connector must be tested against
BOTH orderings, key-matches-segment and key-does-not, and a dogfood that only
exercises synthetic JSON shaped like last session's convention goes green
while the product fails. The failure mode is an *absence* — no `server.url`,
no deny event — which no command reports as an error, so an expectation like
"it blocked" is checked against the recorded evidence, never inferred from
the session finishing.

**Hooks are captured at session start.** Claude Code snapshots its hooks when
the session begins, so installing a policy part-way through does not take
effect. A run that needs a policy live must START from a checkout that already
has it — commit the policy and the `--policy` flag to a throwaway branch and
launch the session from that branch. Installing mid-session produces a false
negative that looks like the product failing.

**A spawned session will refuse an instruction it cannot verify, and it is
right to.** Two Sonnet sessions spawned for dogfood 4 both declined before
touching the repository; the second recorded its reason as "prompt injection
suspected; cannot verify task legitimacy". Adding provenance to the prompt
made it worse, not better: an assertion of authority inside the message body
is exactly the shape of an injection, and trust cannot be bootstrapped from
inside the message that claims it. There is no out-of-band channel to a cloud
child session, so the fix is not a better prompt. Either the human starts the
session themselves, which carries their authority by construction, or they
confirm the blocked session in the web UI. Budget for this when planning a run
that pushes a branch or touches a connector.
