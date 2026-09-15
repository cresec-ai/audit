#!/bin/bash
set -euo pipefail

# Claude Code on the web: install dependencies once per container so tests,
# `npx tsx`, and the dogfood MCP servers declared in .mcp.json (which run the
# recorder from source) work from the first turn. Local sessions are skipped.
if [ "${CLAUDE_CODE_REMOTE:-}" != "true" ]; then
  exit 0
fi

exec sh "$CLAUDE_PROJECT_DIR/scripts/bootstrap.sh"
