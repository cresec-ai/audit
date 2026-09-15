#!/bin/sh
# Dogfood wrapper used by the repo's MCP configs: run the recorder from source
# around a wrapped MCP server, bootstrapping dependencies first on a fresh
# clone or cloud container (scripts/bootstrap.sh serializes concurrent
# callers and writes only to stderr — stdout is the MCP channel).
#
#   sh scripts/dogfood-wrap.sh --name <server> -- <command> [args...]
#
# The data dir is .mcp-recorder (gitignored) unless MCP_RECORDER_DATA_DIR is set.
set -e
cd "$(dirname "$0")/.."
sh scripts/bootstrap.sh
exec node_modules/.bin/tsx src/cli.ts record --data-dir "${MCP_RECORDER_DATA_DIR:-.mcp-recorder}" "$@"
