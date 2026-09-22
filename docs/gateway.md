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

## Before you write anything: `mcp-recorder protect`

If you just want enforcement, you do not need this page. One command installs
a starter policy and wires every server and the Claude Code hook to it, and
ends by running `doctor` to say whether it is actually in force:

```sh
mcp-recorder protect --client claude-code
```

The file it writes is commented YAML at `<data-dir>/policy.starter.yaml` and
it is yours to edit — it is never regenerated over your changes. What is in
it, and why each rule is defensible knowing nothing about your servers, is in
the [README](../README.md#the-starter-policy-and-the-moment-you-edit-it) and
in [docs/first-run.md](first-run.md). `record --protect` / `http --protect`
select that same file for a config you edit by hand, and never write it: if it
is not there, that is exit 2 before the server is spawned, naming `protect`.
`doctor` reads a `--protect` entry as **enforcing** and resolves it to the same
`<data-dir>/policy.starter.yaml` (taking the entry's own `--data-dir` when it
has one), so a hand-edited config is not reported as "recording only" and is
not told to run `protect`, which would rewrite it.

The rest of this page is for when you outgrow it — a policy of your own,
credential swaps, CI.

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
      # `args` is keyed by a dot-path, so this only governs a tool that calls
      # its argument `path`. `any_arg` searches EVERY string leaf instead,
      # whatever the key is called and however deep it is — see
      # docs/policy.md#matchany_arg, and the starter policy, which uses it.
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

`query` matches the **exact** value: the needle is hashed whole, so
`query attacker.example` finds nothing where
`query https://attacker.example/collect` finds the call — measured in local
dogfood 6, on a store recorded by this same demo policy.

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

`MCP_RECORDER_POLICY=/path/to/policy.yaml` is honoured by **both** `record`
and `http` when `--policy` is not given, which is convenient when the client's
config is generated and you cannot edit its argv — `src/cli.ts:281` documents
it as "same as `record --policy F` / `http --policy F`", and
[features.md](features.md) says the same. The earlier refusal, in which `http`
printed that gateway mode was available for the stdio transport only, is gone:
gateway mode runs over both transports, so an exported `MCP_RECORDER_POLICY` is
enforced by `http` exactly as by `record`. Export it deliberately, not by
habit: every `http` process that inherits it becomes an enforcing gateway.

To ship the same policy to the Cresec control plane (the hosted gateway and
the sidecar consume Rego through its OPA bundle endpoint):

```sh
mcp-recorder policy compile .agent/policy.ci.yaml --out build/policy-bundle
opa build -b build/policy-bundle -o build/policy-bundle.tar.gz
```

## What gateway mode does not do

Every bullet here describes the code at this commit. The module header of
`src/proxy/stdio.ts` is the same statement in more detail; if the two ever
disagree, the header is the one kept next to the code.

- It does not touch anything but `tools/call` and its results. Every other
  JSON-RPC message is forwarded unchanged, as in record mode — but
  "unchanged" is not "unevaluated": **no client byte reaches the server
  unevaluated**, so the shapes that are not `tools/call` requests are still
  gated.
- It does not enforce `egress` rules (the sidecar does; see
  [docs/policy.md](policy.md)).
- It does not hide denied tools from `tools/list` (v1).
- It does not forward a line the policy could not be shown. Two things stop
  the policy seeing one: it is larger than the scanner can buffer (32 MiB),
  or it is not JSON. In gateway mode neither is forwarded — none of its bytes
  reach the server — and the client is answered
  `{"jsonrpc":"2.0","id":null,"error":{"code":-32600,...}}`, wrapped in an
  array when the line started with `[` so a batch gets a batch response. An
  oversized line is still recorded as `protocol_error` `oversized`. This is
  the one place an allow-all gateway is not byte-for-byte identical to the
  unwrapped server: a non-JSON line comes back as a refusal, because the
  gateway cannot know it was harmless without parsing it. **Record mode
  forwards both, unchanged** — it promises byte-for-byte and enforces
  nothing.
- It does not treat a JSON-RPC batch as a way in. Every element goes through
  the same gate its standalone form does, in the same order: a `tools/call`
  request is evaluated, a `tools/call` **notification** is evaluated (a deny
  simply drops it, which is what "notification" already promises its sender),
  an element that is itself an array is refused, and both id gates below run
  per element. A refused element is never forwarded and its refusal comes
  back as an element of the batch response; a batch with nothing refused
  crosses byte-for-byte. Ids taken by earlier elements of the same batch
  count as in flight, including the ones the gateway answered on, so a batch
  that denies id 5 and then reuses it does not send the client two responses
  for one id. A `hold` rule matched inside a batch is treated as `deny` and
  carries the **fail-closed** clause rather than the policy-decision one: a
  batch element has nowhere to park, so no operator is ever asked, and
  sending the same call on its own is what reaches an approver. (Batching was
  removed from MCP in 2025-06-18. When the server answers a forwarded batch
  with an array, every element answering a `tools/call` goes through the
  boundary filter, with `max_scan_bytes` applied to the whole batch line.)
- It does not let two in-flight calls share a request id, for **any** c2s
  request and not only `tools/call`: a same-id `tools/list` taking an
  in-flight tool call's slot loses that call from the chain just as
  thoroughly. A `tools/call` on a live (pending or held) id is refused with a
  synthesized `isError` result, recorded as a `policy_decision` (deny, no
  `rule_id` — no rule was consulted) plus a `tool_call` carrying
  `error.type: 'duplicate_id'`; any other method is refused with a plain
  -32600 and recorded as an `rpc` event with the same error type. Neither is
  forwarded, so the call that owns the id keeps its slot, its result stays
  correlated, boundary-filtered and recorded. Both gates run for a batch
  element too. The number `7` and the string `"7"` are different ids, and
  record mode (no `--policy`) keeps its last-writer-wins behaviour.
  `registerPending` also seals any live entry it would displace, and an
  approved hold reclaiming its key does the same — a last resort rather than
  the mitigation, since a seal writes a record for a call whose real result
  was already lost.
- It does not forward a `tools/call` whose id is not a string or a number.
  `{"id": null}` is not a valid MCP request and not a notification either,
  and neither is `{"id": true}`, `{"id": {}}` or `{"id": []}`. Any of them is
  refused fail-closed whatever the policy says — a matching `hold` rule is a
  deny, and the call is not evaluated at all — and the client gets
  `{"jsonrpc":"2.0","id":null,"error":{"code":-32600,"message":
  "mcp-recorder gateway: tools/call with a null id is not a valid request"}}`
  (JSON-RPC permits a null id on an error response, and it is the only honest
  answer when the request's own id cannot be echoed). Because the frozen
  schema's `request_id` is `string | number`, such a message is recorded
  exactly as any id-less message is — one `notification` event — with the
  refusal itself on stderr. This holds inside a batch as well. Without
  `--policy` it crosses unevaluated, as before.
- It parks at most 256 held calls at once; a hold-matching call beyond that
  is refused as a deny ("too many pending holds") rather than buffered
  without bound.
- It does not park a hold once the session has started shutting down: a
  hold-matching `tools/call` that arrives while the proxy is winding down is
  refused immediately, recorded with `outcome: session_end` and no
  `approval_id`, and no hold file is written — a hold can never outlive the
  session that created it.
- It does not splice a synthesized response into the middle of a server
  line: deny and hold responses ride the server-to-client stream, so they may
  be ordered after a line that was already in flight. An approved hold is
  released into the client-to-server stream the same way, after any client
  line still streaming through.
- It runs over both transports. `mcp-recorder http --target URL --policy
  policy.yaml` is the same gateway in front of a streamable-HTTP server, with
  the same policy loader (an unloadable policy exits 2 before the port is
  bound), holds dir, boundary filter, `credentials` swap and events. Over
  HTTP a `tools/call` request body and its result are buffered long enough
  to evaluate and filter them — a JSON body whole, an SSE stream one event at
  a time (each held only until the blank line that ends it) — which is the
  gateway-mode exception to the streaming promise; without `--policy` the
  HTTP proxy streams every byte as before. **Every POST is gated, whatever
  its `content-type` says** (or if it has none): the gate parses the body
  itself, so a `tools/call` sent as `text/plain` is evaluated exactly like
  one sent as `application/json`, and a POST body that is not JSON is
  refused (`400`, JSON-RPC `-32600`) rather than forwarded unread. A batch
  that carries a refused call is answered locally as a whole; a compressed
  upstream response is refused (`502`) because the filter cannot read it,
  and the gateway asks for `identity` so a compliant upstream never sends
  one. On the way back the boundary filter fails closed on both response
  shapes: a JSON body the filter blew up on is not delivered at all, and an
  SSE event carrying a tools/call result the filter blew up on is replaced
  by a blocked result for that id (the frames around it cross untouched).
  See the module header of `src/proxy/http.ts`.
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
