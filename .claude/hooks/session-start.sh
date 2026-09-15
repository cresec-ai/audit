#!/bin/bash
set -euo pipefail

# Claude Code on the web: install dependencies once per container so tests,
# `npx tsx`, and the dogfood MCP servers declared in .mcp.json (which run the
# recorder from source) work from the first turn. Local sessions are skipped.
if [ "${CLAUDE_CODE_REMOTE:-}" != "true" ]; then
  exit 0
fi

cd "$CLAUDE_PROJECT_DIR"

# The MCP servers in .mcp.json may start before this hook finishes and install
# dependencies themselves (scripts/dogfood-wrap.sh); share its lock so two
# `npm install`s never run in the same tree at once.
lock=.mcp-recorder-install.lock
waited=0
while ! mkdir "$lock" 2>/dev/null; do
  sleep 1
  waited=$((waited + 1))
  if [ "$waited" -ge 300 ]; then
    echo "[session-start] giving up on stale install lock $lock" >&2
    rmdir "$lock" 2>/dev/null || true
  fi
done
trap 'rmdir "$lock" 2>/dev/null || true' EXIT

if [ ! -x node_modules/.bin/tsx ] || [ ! -d node_modules/better-sqlite3 ]; then
  # npm install (not ci) keeps the cached container state reusable; `prepare`
  # builds dist/ as part of it.
  npm install --no-audit --no-fund
fi
