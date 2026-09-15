#!/bin/sh
# Dogfood wrapper used by .mcp.json: run the recorder from source around a
# wrapped MCP server. On a fresh clone or cloud container node_modules may
# not exist yet, so dependencies are installed first — behind a lock, because
# every server in .mcp.json starts at the same time. All install output goes
# to stderr: stdout is the MCP channel and must carry nothing else.
#
#   sh scripts/dogfood-wrap.sh --name <server> -- <command> [args...]
#
# The data dir is .mcp-recorder (gitignored) unless MCP_RECORDER_DATA_DIR is set.
set -e
cd "$(dirname "$0")/.."

if [ ! -x node_modules/.bin/tsx ]; then
  lock=.mcp-recorder-install.lock
  waited=0
  while ! mkdir "$lock" 2>/dev/null; do
    sleep 1
    waited=$((waited + 1))
    if [ "$waited" -ge 300 ]; then
      echo "[dogfood-wrap] giving up on stale install lock $lock" >&2
      rmdir "$lock" 2>/dev/null || true
    fi
  done
  trap 'rmdir "$lock" 2>/dev/null || true' EXIT
  if [ ! -x node_modules/.bin/tsx ]; then
    echo "[dogfood-wrap] installing dependencies (first run)" >&2
    npm install --no-audit --no-fund >&2
  fi
  rmdir "$lock" 2>/dev/null || true
  trap - EXIT
fi

exec node_modules/.bin/tsx src/cli.ts record --data-dir "${MCP_RECORDER_DATA_DIR:-.mcp-recorder}" "$@"
