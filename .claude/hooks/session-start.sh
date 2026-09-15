#!/bin/bash
set -euo pipefail

# Claude Code on the web: install dependencies once per container so tests,
# `npx tsx`, and the dogfood MCP servers declared in .mcp.json (which run the
# recorder from source) work from the first turn. Local sessions are skipped.
if [ "${CLAUDE_CODE_REMOTE:-}" != "true" ]; then
  exit 0
fi

cd "$CLAUDE_PROJECT_DIR"

if [ ! -x node_modules/.bin/tsx ] || [ ! -d node_modules/better-sqlite3 ]; then
  # npm install (not ci) keeps the cached container state reusable; `prepare`
  # builds dist/ as part of it.
  npm install --no-audit --no-fund
fi
