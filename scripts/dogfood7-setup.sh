#!/usr/bin/env bash
# Dogfood 7 setup: a credential swap a live agent can actually trigger.
#
# Wires the e2e byte-journal server (test/e2e/fixtures/wire-server.cjs) into
# this session's .mcp.json behind `record --policy`, with a credentials
# section that swaps a synthetic for a real token at ONE declared site.
#
# The journal is what makes the run meaningful: the recorder's own evidence
# is the thing under test, so it cannot also be the only witness for what
# crossed to the server.
#
# The agent is never told the real token. That is not a confidentiality
# claim — on a single-uid box the agent could read this script — it is how we
# keep the transcript honest: whatever ends up in the chain got there because
# the recorder put it there, not because the agent typed it.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN_DIR="${DOGFOOD7_DIR:-/tmp/dogfood7}"
rm -rf "$RUN_DIR"; mkdir -p "$RUN_DIR"

REAL_TOKEN="df7-real-$(head -c 18 /dev/urandom | base64 | tr -d '/+=' | head -c 24)"
SYNTHETIC="cresec_synth_v1_$(head -c 32 /dev/urandom | base64 | tr -d '/+=' | head -c 43)"

printf '%s' "$REAL_TOKEN" > "$RUN_DIR/real-token"
printf '%s' "$SYNTHETIC"  > "$RUN_DIR/synthetic"
chmod 600 "$RUN_DIR/real-token"

cat > "$RUN_DIR/policy.yaml" <<YAML
version: 1
name: dogfood7
mcp:
  default: allow
  boundary: { secrets: redact, injection: flag }
credentials:
  - id: df7-post-token
    synthetic_env: DF7_SYNTHETIC
    provider: example
    scopes: ["messages:write"]
    source:
      type: env
      var: DF7_REAL_TOKEN
    use:
      # The ONLY place a swap may happen. An undeclared site gets the
      # synthetic and the upstream rejects it — that is the control that
      # survives a tool which hands its arguments back.
      - id: post
        tool: post_message
        arg: headers.Authorization
        host:
          from_arg: url
          allow: [api.example.test]
YAML

cat > "$RUN_DIR/mcp.json" <<JSON
{
  "mcpServers": {
    "df7-wire": {
      "command": "node",
      "args": [
        "$ROOT/dist/cli.js", "record",
        "--data-dir", "$RUN_DIR/data",
        "--store", "jsonl",
        "--name", "df7-wire",
        "--policy", "$RUN_DIR/policy.yaml",
        "--", "node", "$ROOT/test/e2e/fixtures/wire-server.cjs"
      ],
      "env": {
        "E2E_JOURNAL": "$RUN_DIR/journal.jsonl",
        "DF7_REAL_TOKEN": "$REAL_TOKEN",
        "DF7_SYNTHETIC": "$SYNTHETIC"
      }
    }
  }
}
JSON

echo "run dir     : $RUN_DIR"
echo "mcp config  : $RUN_DIR/mcp.json  (merge into .mcp.json, or use --mcp-config)"
echo "policy      : $RUN_DIR/policy.yaml"
echo
echo "THE SYNTHETIC THE AGENT USES (this is not a secret):"
echo "  $SYNTHETIC"
echo
echo "The real token is in $RUN_DIR/real-token and in the recorder's env only."
