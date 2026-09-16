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
branches, each with a `REPORT.md` and a signed bundle. Two practical notes
for anyone setting up the next one.

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
