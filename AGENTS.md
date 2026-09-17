# Working in this repository

`@edut/mcp-recorder` is a fail-open MCP recording proxy: it wraps a stdio MCP
server and records every tool call, redacted at the edge, into a
tamper-evident local evidence store. Read `README.md` for the promises and
`docs/event-schema.md` for the frozen event format.

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

- Gateway mode (`record --policy`) is the ONLY place the proxy may block,
  delay or rewrite traffic, and only for `tools/call` requests and their
  results. Without `--policy` the byte-for-byte, fail-open behaviour above is
  untouched. Inside gateway mode, recording stays fail-open (a store failure
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
