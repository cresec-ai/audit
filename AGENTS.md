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

- `npm run typecheck` — TypeScript, strict.
- `npm test` — vitest; spawns real child processes, takes about a minute.
- `npm run demo` — scripted prompt-injection incident, recorded and verified.
- `npm run bench` — latency gate (p50 added latency must stay under 5 ms).
- `npm run bench:gateway` — the same round-trip measured with a policy in
  force, so gateway-mode added latency is comparable to record mode. Opt-in;
  it does not change `npm run bench` or its gate.
- `npm run bench:boundary` — what the tool-result boundary filter costs
  synchronously on the forwarding path, by result size and content. Gated on
  p99 as a ReDoS alarm, and run by `npm test` and by CI.

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
