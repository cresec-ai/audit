# Gateway mode in 10 minutes — laptop and CI

`mcp-recorder` records by default and never interferes with traffic. **Gateway
mode** is the opt-in step up: hand it a `policy.yaml` and the same proxy
starts *enforcing* — per-tool allow / hold / deny on every `tools/call`, and a
boundary filter that scrubs secret-shaped values and flags prompt injection
in tool results before the model reads them. Every decision lands in the same
tamper-evident evidence chain as the recording.

```
BEFORE  {"command": "node", "args": ["/path/to/dist/cli.js", "--", "npx", "-y", "@some/mcp-server"]}
AFTER   {"command": "node", "args": ["/path/to/dist/cli.js", "--policy", "/path/to/policy.yaml", "--", "npx", "-y", "@some/mcp-server"]}
```

Nothing changes for servers you don't pass `--policy` to. The full option
reference is in [docs/policy.md](policy.md).

## 0. Install (1 minute)

```sh
npm install -g github:cresec-ai/audit#main
mcp-recorder --version
```

See [docs/install.md](install.md) for the other install routes and the
Windows/WSL notes.

## 1. Write a policy (2 minutes)

Save this as `~/.mcp-recorder/policy.yaml` (any path works; absolute paths
are safest because MCP clients launch servers from their own working
directory):

```yaml
# yaml-language-server: $schema=https://cresec.ai/schemas/agent-policy.v1.json
version: 1
name: laptop

mcp:
  default: allow
  rules:
    - id: no-exfil
      match: { tool: [http_post, "send_*", "fetch*"] }
      action: deny
      reason: outbound HTTP from agents is not allowed on this machine
    - id: destructive-needs-a-human
      match: { tool: ["delete_*", "rm*", "drop_*"] }
      action: hold
    - id: no-credential-files
      match:
        tool: read_file
        args: { path: "(^|/)(\\.env|secrets\\.env|id_rsa|\\.npmrc)$" }
      action: deny
      reason: credential files are off limits
  hold:
    timeout_ms: 90000
    on_timeout: deny
  boundary:
    secrets: redact
    injection: flag
```

Check it:

```sh
mcp-recorder policy validate ~/.mcp-recorder/policy.yaml
# ~/.mcp-recorder/policy.yaml: valid (3 mcp rules, 0 egress rules)
```

## 2. Wrap a server with the policy (2 minutes)

Add `--policy <file>` to the recorder's own arguments (before the `--` that
separates them from the server command). Either let `setup` do it for every
server in a client's config (it validates the policy first and exits 2 without
touching the config if the file is missing or invalid — better than finding a
typo when every wrapped server refuses to start):

```sh
mcp-recorder setup --client claude-desktop --policy ~/.mcp-recorder/policy.yaml --dry-run
mcp-recorder setup --client claude-desktop --policy ~/.mcp-recorder/policy.yaml
```

Servers a previous `setup` run already wrapped in plain record mode are
updated in place (they are listed as `updated policy on: ...`), so this
really does apply the policy to every stdio server in the config.

or edit one entry by hand — Claude Desktop / Claude Code / Cursor all take
the same shape:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "node",
      "args": [
        "/path/to/mcp-recorder/dist/cli.js",
        "--policy", "/Users/me/.mcp-recorder/policy.yaml",
        "--",
        "npx", "-y", "@modelcontextprotocol/server-filesystem", "/Users/me/projects"
      ]
    }
  }
}
```

Fully quit and restart the client — MCP servers only launch on startup.

If the policy file is missing or invalid the recorder exits with code 2
before the server starts, and the client shows the server as failed. A
broken policy never silently turns into "allow everything".

A policy that is *valid* but carries no `mcp` section — an `egress`-only file,
which the schema accepts because it is meaningful to the sidecar — is refused
the same way: `record --policy` and `setup --policy` exit 2 with ``policy
has no `mcp` section — nothing for the gateway to enforce``, because there is
nothing for the stdio gateway to apply. `mcp-recorder policy validate` still
exits 0 for such a file (it is a valid policy) but prints a warning line
saying exactly that, so the two commands never disagree silently.

## 3. Watch it work (3 minutes)

Ask the agent to do something the policy covers. A denied call comes back to
the model as a tool error, so the conversation continues:

> I can't do that: `mcp-recorder gateway: tools/call "http_post" denied by
> policy rule "no-exfil": outbound HTTP from agents is not allowed on this
> machine`.

The full text the model reads is two lines — the refusal, then one standard
clause so the agent does not treat a policy decision as a broken tool:

```
mcp-recorder gateway: tools/call "http_post" denied by policy rule "no-exfil": outbound HTTP from agents is not allowed on this machine
This is a policy decision by the operator, not a tool failure. Do not retry it or use another tool to get the same effect; report it to the user.
```

A refusal where the gateway FAILED CLOSED — the policy could not be evaluated,
the hold file could not be written, `MAX_HOLDS` was already reached, the proxy
was shutting down, or a result was too large to scan — gets the other clause,
because nobody decided anything about that call and a retry is often exactly
what clears it:

```
mcp-recorder gateway: tools/call "send_mail" denied by policy rule "needs-human": too many pending holds
The gateway could not reach a policy decision, so it refused this call rather than allow it unchecked. You may retry it; do not use another tool to get the same effect, and report it to the user.
```

One line of tool output is not much against a model that is mid-plan, so
[docs/agent-guidance.md](agent-guidance.md) has a snippet to paste into
`CLAUDE.md` / `AGENTS.md` / `.cursor/rules` — the agent then reads the same
thing *before* it plans, instead of after it has been refused.

A held call blocks that one tool call (only that one — everything else keeps
flowing) until you decide:

```sh
mcp-recorder holds
# ID        AGE   SERVER      TOOL         RULE                        TIMEOUT
# 5d1c9e0a  12s   filesystem  delete_file  destructive-needs-a-human   78s

mcp-recorder approve 5d1c9e0a      # or: mcp-recorder deny 5d1c9e0a
```

On approval the original request is forwarded to the server byte-for-byte.
On deny or timeout the model receives an `isError` result that names the
approval id — the same two-line shape as a deny — and nothing reaches the
server.

The boundary filter is silent unless a result carries something it
recognizes. Run the repository's scripted incident to see it fire:

```sh
git clone https://github.com/cresec-ai/audit.git && cd audit && npm ci
npm run demo -- --policy docs/examples/policy.demo.yaml
```

The demo's `vendor-onboarding.md` note carries a hidden prompt injection and
the planted canary credential is read back through `read_file`; with the
demo policy the injection marker is flagged in the record and the canary is
redacted before the model sees it, while the `http_post` exfiltration is
denied outright.

## 4. Look at the evidence

Everything above is in the chain, verifiable like any other recording:

```sh
mcp-recorder sessions                  # denied calls count as tool calls with errors
mcp-recorder ui                        # decisions are badged on the replay timeline
mcp-recorder verify                    # the chain still verifies — decisions are sealed events
mcp-recorder query 'sk-demo-EXFILTRATION-c4n4ry-9f3a7b2e'   # a redacted value is still findable by hash
mcp-recorder export --out evidence.zip
```

Three things are recorded ([docs/event-schema.md](event-schema.md)):

- `session_start.policy` — the hash and name of the policy that was in force;
- `tool_call.gateway` — the decision, rule id, hold outcome and boundary
  findings on every tool call;
- `policy_decision` — a dedicated event for every deny and every hold
  outcome (approved / denied / timeout / cancelled), with who approved.

Arguments and results stay redacted exactly as in record mode; the hold
files under `~/.mcp-recorder/holds/` contain hashed arguments, never
readable ones.

## CI: the same policy on a runner

In CI there is nobody to approve a hold, so treat `hold` as `deny` by keeping
`on_timeout: deny` (the default) and a short `timeout_ms`, or write a
CI-specific policy that uses `deny` instead of `hold`. Check the policy into
the repository and validate it as its own step so a bad edit fails fast:

```yaml
# .github/workflows/agent.yml
name: agent
on: [workflow_dispatch]
jobs:
  agent:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: 22 }
      - run: npm install -g github:cresec-ai/audit#main
      - name: Validate the agent policy
        run: mcp-recorder policy validate .agent/policy.ci.yaml
      - name: Run the agent behind the gateway
        env:
          MCP_RECORDER_DATA_DIR: ${{ runner.temp }}/mcp-recorder
        run: |
          # Whatever launches your MCP client in CI; each MCP server it starts is wrapped like so:
          #   mcp-recorder --policy .agent/policy.ci.yaml -- npx -y @modelcontextprotocol/server-filesystem .
          ./scripts/run-agent.sh
      - name: Verify and keep the evidence
        if: always()
        env:
          MCP_RECORDER_DATA_DIR: ${{ runner.temp }}/mcp-recorder
        run: |
          mcp-recorder verify
          mcp-recorder export --out evidence.zip
      - uses: actions/upload-artifact@v4
        if: always()
        with: { name: mcp-evidence, path: evidence.zip }
```

The `policy validate` step exits 0 for an `egress`-only policy (with the
warning line above) while the run step would exit 2 on it — read the
validate step's output, or grep the policy for an `mcp:` section, if your
runner's policy is generated rather than hand-written.

`MCP_RECORDER_POLICY=/path/to/policy.yaml` is honoured by `record` when
`--policy` is not given, which is convenient when the client's config is
generated and you cannot edit its argv. Exporting it in a shell is safe:
`mcp-recorder http` ignores the variable (it prints
`http: MCP_RECORDER_POLICY ignored — gateway mode is available for the stdio
transport only` on stderr and records as usual); only an explicit
`http --policy` is an error.

To ship the same policy to the Cresec control plane (the hosted gateway and
the sidecar consume Rego through its OPA bundle endpoint):

```sh
mcp-recorder policy compile .agent/policy.ci.yaml --out build/policy-bundle
opa build -b build/policy-bundle -o build/policy-bundle.tar.gz
```

## What gateway mode does not do

- It does not touch anything but `tools/call` requests and their results;
  every other JSON-RPC message is forwarded unchanged, like record mode.
  Four consequences worth knowing: a `tools/call` sent as a notification (no
  `id`) is forwarded unevaluated, since no response could be synthesized for
  it and MCP servers do not execute tool notifications — but a `tools/call`
  *request* is always evaluated, and one whose `params.name` is missing or is
  not a string is evaluated as the tool name `""`, so `mcp.default` (and any
  rule whose tool glob matches an empty string) decides it; a `hold` rule
  matched inside a JSON-RPC batch is treated as `deny` and carries the
  **fail-closed** clause rather than the policy-decision one, because a batch
  element has nowhere to park and so no operator is ever asked — sending the
  same call on its own is what reaches an approver (batching was removed
  from MCP in 2025-06-18; allowed and denied batch elements are answered
  individually, and when the server answers a forwarded batch with an array,
  every element that answers a `tools/call` goes through the boundary filter,
  with `max_scan_bytes` applied to the whole batch line); a single line larger
  than 32 MiB cannot be parsed, so it crosses unchanged and unevaluated and is
  recorded as `protocol_error` `oversized`, exactly as in record mode; and
  synthesized deny/hold responses ride the server-to-client stream, so they are
  never spliced into the middle of a server line and may be ordered after one
  that was already in flight — an approved hold is released into the
  client-to-server stream the same way, after any client line still streaming
  through.
- It does not enforce `egress` rules (the sidecar does; see
  [docs/policy.md](policy.md)).
- It does not hide denied tools from `tools/list` (v1).
- It parks at most 256 held calls at once; a hold-matching call beyond that
  is refused as a deny ("too many pending holds") rather than buffered
  without bound.
- It does not park a hold once the session has started shutting down: a
  hold-matching `tools/call` that arrives while the proxy is winding down is
  refused immediately, recorded with `outcome: session_end` and no
  `approval_id`, and no hold file is written — a hold can never outlive the
  session that created it.
- It does not let two in-flight calls share a JSON-RPC request id. A
  `tools/call` whose id is currently held for approval, or is already pending,
  is refused immediately (fail-closed) with a synthesized `isError` result and
  is never forwarded, so the call that owns the id keeps its slot and its own
  result is still correlated, boundary-filtered and recorded. The refusal is
  recorded as a `policy_decision` (`deny`, no `rule_id` — no rule was
  consulted) plus a `tool_call` carrying `error.type: 'duplicate_id'`; the
  reason appears in the text the model sees and on stderr, never as readable
  event data. The number `7` and the string `"7"` are different ids, and
  record mode (no `--policy`) keeps its last-writer-wins behaviour. Two paths
  are not checked up front, because the gateway only guards `tools/call`
  requests: a `tools/call` reusing an in-flight id inside a JSON-RPC batch,
  and a non-`tools/call` request (`tools/list`, ...) on the same id. If either
  is still pending when a hold on that id is approved, it is sealed first — a
  `tool_call` or `rpc` event with `error.type: 'duplicate_id'`, `result:
  null`, `result_hash` the hash of canonical `null` and `is_error: true` — so
  an approved hold never silently overwrites another call's evidence.
- It does not forward a `tools/call` with `id: null`. MCP forbids a null
  request id (the official SDK rejects one) and such a message is not a
  notification either, so gateway mode refuses it whatever the policy says — a
  matching `hold` rule is a deny, and the call is not evaluated at all — and
  answers `{"jsonrpc":"2.0","id":null,"error":{"code":-32600,"message":
  "mcp-recorder gateway: tools/call with a null id is not a valid request"}}`
  (JSON-RPC permits a null id on an error response). Because the event
  schema's `request_id` is `string | number`, the message is recorded exactly
  as any id-less message is — one `notification` event — with the refusal
  itself visible on stderr. Without `--policy` it crosses unevaluated, as
  before.
- It is stdio-only in v1; `mcp-recorder http --policy` is rejected (exit 2),
  and `http` ignores an exported `MCP_RECORDER_POLICY` with a one-line note
  on stderr rather than refusing to start.
- Recording stays fail-open even in gateway mode: a store failure never
  turns into a deny. Enforcement, on the other hand, fails closed — a policy
  that cannot be evaluated denies, and a hold that cannot be written is a
  deny.
  Belt and braces for `match.args` regexes: at run time every one is matched
  on a worker thread under a 25 ms deadline. A match that overruns it is
  abandoned, the pattern is disabled for the rest of the process, and the
  call is denied with `policy evaluation error: regex timed out (<rule id>)`
  — a pattern that cannot be evaluated is never treated as "did not match".
- `MCP_RECORDER_DISABLE=1` is the kill switch: it disables recording *and*
  the gateway, so a misbehaving policy can always be bypassed by the person
  who controls the environment — which is why this is a laptop/CI control,
  and the hosted gateway is the tamper-resistant one.
