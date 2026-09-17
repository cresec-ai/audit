#!/bin/sh
# Cloud dogfood 6 scaffold. Two jobs, both of which must happen before the
# first tool hook fires, which is why SessionStart calls this.
#
# 1. Start the reference receiver in this container, so the recorder ships
#    evidence off-process to something that VERIFIES it. A cloud dogfood
#    cannot reach a receiver on anyone else's machine, so the receiver runs
#    here; that still proves the shipper works under a real agent and that
#    the replica is independently verifiable, which is the claim under test.
#
# 2. Build a FORCED-MISMATCH MCP config. Across dogfood 3, 4 and 5 the
#    declared-tool fallback (PR #16, "route 2") has run live ZERO times: the
#    config key and the tool-name segment happened to agree twice, and the
#    one time they disagreed the fallback did not exist yet. This rewrites
#    the session's own real config so the key CANNOT equal the segment,
#    leaving tools[] intact. Route 1 must then miss and route 2 is the only
#    path that can resolve the connector.
#
# The live /tmp/mcp-config-<session>.json that Claude Code itself reads is
# never modified; the hook is pointed at a copy via MCP_RECORDER_MCP_CONFIG.
set -eu
cd "${CLAUDE_PROJECT_DIR:-.}"
D=.mcp-recorder
mkdir -p "$D"

# --- 1. receiver -----------------------------------------------------------
if ! curl -sS --max-time 3 --noproxy 127.0.0.1 http://127.0.0.1:8787/v1/health >/dev/null 2>&1; then
  MCPR_RECEIVER_TOKEN=dogfood6-ingest \
    nohup npx tsx receiver/main.ts serve --data-dir "$D/receiver" --port 8787 \
    >"$D/receiver.log" 2>&1 &
  sleep 5
fi

# --- 2. forced-mismatch config --------------------------------------------
node - <<'JS'
const fs = require('fs'), path = require('path');
const dir = '/tmp';
const src = fs.readdirSync(dir).filter(f => /^mcp-config-.*\.json$/.test(f)).map(f => path.join(dir, f))[0];
const out = path.join(process.env.CLAUDE_PROJECT_DIR || '.', '.mcp-recorder', 'forced-mismatch-config.json');
if (!src) { fs.writeFileSync(out, JSON.stringify({ mcpServers: {} }, null, 1)); console.error('dogfood6: no MCP config found'); process.exit(0); }
const real = JSON.parse(fs.readFileSync(src, 'utf8'));
const servers = real.mcpServers || {};
// Rename every key to something that CANNOT be the tool-name segment, while
// leaving the entry (and its tools[]) untouched. A key that is already a UUID
// becomes a friendly-looking name and vice versa, so whichever convention
// this session uses for tool names, the key no longer matches it.
const isUuid = k => /^[0-9a-f-]{36}$/i.test(k);
const out2 = {};
for (const [k, v] of Object.entries(servers)) {
  const nk = isUuid(k) ? `renamed_${k.slice(0, 8)}` : `00000000-0000-4000-8000-${String(Math.abs(hash(k))).padStart(12, '0').slice(0, 12)}`;
  out2[nk] = v;
}
function hash(s) { let h = 0; for (const c of s) h = (h * 31 + c.charCodeAt(0)) | 0; return h; }
fs.writeFileSync(out, JSON.stringify({ mcpServers: out2 }, null, 1));
console.error(`dogfood6: forced-mismatch config written, ${Object.keys(out2).length} entries, keys renamed from [${Object.keys(servers).join(', ')}]`);
JS
