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

- `dist/` is committed. It exists so `npm install -g github:cresec-ai/audit#main`
  works without a build (npm runs a git package's `prepare` without its
  devDependencies on a global install). After changing anything under `src/`,
  run `npm run build` and commit the `dist/` changes with it — CI fails on a
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
