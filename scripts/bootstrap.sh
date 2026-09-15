#!/bin/sh
# Shared environment bootstrap for every agent platform that works on this
# repository (Claude Code on the web, Cursor cloud agents, GitHub Copilot's
# coding agent, OpenAI Codex, and plain clones): install dependencies once,
# then compiles dist/ (no `prepare` script: see AGENTS.md on why dist/ is committed).
#
# Idempotent and safe to run concurrently: the MCP servers in .mcp.json start
# at the same time as the platform's own setup step, so every caller waits on
# one lock directory. All output goes to stderr so a caller whose stdout is an
# MCP channel (scripts/dogfood-wrap.sh) never pollutes it.
#
#   sh scripts/bootstrap.sh            # install if node_modules is incomplete
#   sh scripts/bootstrap.sh --force    # always run npm install
set -e
cd "$(dirname "$0")/.."

needs_install() {
  [ "$1" = "--force" ] && return 0
  [ ! -x node_modules/.bin/tsx ] && return 0
  [ ! -d node_modules/better-sqlite3 ] && return 0
  return 1
}

needs_install "${1:-}" || exit 0

lock=.mcp-recorder-install.lock
waited=0
while ! mkdir "$lock" 2>/dev/null; do
  sleep 1
  waited=$((waited + 1))
  if [ "$waited" -ge 300 ]; then
    echo "[bootstrap] giving up on stale install lock $lock" >&2
    rmdir "$lock" 2>/dev/null || true
  fi
done
trap 'rmdir "$lock" 2>/dev/null || true' EXIT

# Re-check under the lock: another caller may have finished the install.
if needs_install "${1:-}"; then
  echo "[bootstrap] installing dependencies" >&2
  # npm install (not ci) keeps cached container snapshots reusable. dist/ is
  # committed but is rebuilt here so a checkout with local src/ edits is
  # current; it is a no-op when nothing changed.
  npm install --no-audit --no-fund >&2
  npm run compile >&2
fi
