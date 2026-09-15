# Policy reference — `policy.yaml` schema v1

`policy.yaml` is the single policy file for agent harnesses in the Cresec
line of tools. Two consumers read it:

- **`mcp-recorder` gateway mode** (`mcp-recorder record --policy policy.yaml -- <server>`)
  enforces the `mcp` section on every MCP `tools/call` that crosses the proxy:
  per-tool **allow / hold / deny**, plus a **tool-result boundary filter** that
  redacts secret-shaped values and flags prompt-injection markers in tool
  results before the model sees them. See [docs/gateway.md](gateway.md) for the
  10-minute walkthrough.
- **The Cresec sidecar / hosted gateway** (the Go edge daemon and control plane)
  consumes the same file compiled to Rego (`mcp-recorder policy compile`) and
  served through the control plane's OPA bundle endpoint. The `egress` section
  (HTTP egress rules on host/method/path) exists for that consumer;
  `mcp-recorder` validates and compiles it but does **not** enforce it — the
  recorder never sits in the HTTP egress path.

The schema is versioned (`version: 1`) and published as JSON Schema at
[`docs/policy-schema.json`](policy-schema.json)
(`$id: https://cresec.ai/schemas/agent-policy.v1.json`). Editors that speak
`yaml-language-server` pick it up from a first-line comment:

```yaml
# yaml-language-server: $schema=https://cresec.ai/schemas/agent-policy.v1.json
```

## A complete example

```yaml
version: 1
name: laptop-default

mcp:
  default: allow                      # what happens when no rule matches
  rules:                              # ordered — FIRST MATCH WINS
    - id: no-exfil
      match:
        tool: [http_post, "send_*", "fetch*"]
      action: deny
      reason: outbound HTTP from agents is not allowed on this machine

    - id: destructive-needs-a-human
      match:
        tool: ["delete_*", "rm*", "drop_*"]
      action: hold
      reason: destructive operations need a human to approve

    - id: no-secrets-files
      match:
        tool: read_file
        args:
          path: "(^|/)(\\.env|secrets\\.env|id_rsa|\\.npmrc)$"
      action: deny
      reason: credential files are off limits

    - id: big-writes
      match:
        tool: write_file
        max_args_bytes: 262144        # rule matches only for payloads <= 256 KiB ...
      action: allow                   # ... so larger writes fall through to the next rule

    - id: huge-writes
      match:
        tool: write_file
      action: hold

  hold:
    timeout_ms: 60000                 # how long a held call waits for `mcp-recorder approve`
    on_timeout: deny                  # deny | allow

  boundary:                           # server -> client tool results
    secrets: redact                   # redact | block | flag | off
    injection: flag                   # redact | block | flag | off
    max_scan_bytes: 1048576           # results larger than this are not scanned ...
    on_oversize: flag                 # ... and are flagged (or blocked)

egress:                               # for the Cresec sidecar — compiled, not enforced here
  default: deny
  rules:
    - id: github-read
      match:
        host: api.github.com
        methods: [GET, HEAD]
        path: "/**"
      action: allow
    - id: github-write-needs-approval
      match:
        host: api.github.com
        methods: [POST, PUT, PATCH, DELETE]
      action: hold
    - id: pypi
      match:
        host: ["pypi.org", "files.pythonhosted.org"]
        methods: [GET]
      action: allow
```

## Top level

| Key | Type | Required | Notes |
| --- | --- | --- | --- |
| `version` | `1` | yes | Literal `1`. Breaking changes will bump this. |
| `name` | identifier | no | `^[A-Za-z0-9_.:/-]{1,64}$`. Stamped on the `session_start` event and into the compiled Rego header. |
| `mcp` | object | one of `mcp`/`egress` | MCP tool-call policy (enforced by `mcp-recorder`). |
| `egress` | object | one of `mcp`/`egress` | HTTP egress policy (compiled for the sidecar). |

Unknown keys are rejected everywhere (`additionalProperties: false`): a typo
never silently disables a rule.

## `mcp`

| Key | Type | Default | Notes |
| --- | --- | --- | --- |
| `default` | `allow` \| `hold` \| `deny` | `allow` | Action when no rule matches. |
| `rules` | array | `[]` | Ordered; first match wins. |
| `hold` | object | see below | Hold behaviour. |
| `boundary` | object | see below | Tool-result boundary filter. |

### `mcp.rules[]`

| Key | Type | Required | Notes |
| --- | --- | --- | --- |
| `id` | identifier | no | `^[A-Za-z0-9_.:/-]{1,64}$`, unique within the section. Defaults to `rule[<index>]`. Appears in events (`rule_id`) and in the text the model sees on a deny. |
| `match.server` | glob \| glob[] | no | Matches the recorder's logical server name (`--name`, else the name learned from the `initialize` handshake, else the wrapped command's basename). Default `*`. Delimiter `/`. |
| `match.tool` | glob \| glob[] | yes | Matches the `tools/call` `params.name`. Delimiter `/`. |
| `match.args` | object of regex | no | Each key is a dot-path into `params.arguments`; each value an RE2-compatible regex. **All** entries must match. A missing path never matches. |
| `match.max_args_bytes` | integer ≥ 0 | no | Rule matches only when the canonical JSON of `params.arguments` is at most this many bytes. |
| `action` | `allow` \| `hold` \| `deny` | yes | |
| `reason` | string ≤ 512 | no | Shown to the model on a deny / hold-denied result; also copied into the compiled Rego. |

### `mcp.hold`

| Key | Type | Default | Range |
| --- | --- | --- | --- |
| `timeout_ms` | integer | `60000` | 1 000 – 3 600 000 |
| `on_timeout` | `deny` \| `allow` | `deny` | |

### `mcp.boundary`

| Key | Type | Default | Notes |
| --- | --- | --- | --- |
| `secrets` | `redact` \| `block` \| `flag` \| `off` | `redact` | Secret-shaped values in tool results. |
| `injection` | `redact` \| `block` \| `flag` \| `off` | `flag` | Prompt-injection markers in tool results. |
| `max_scan_bytes` | integer | `1048576` | 4 096 – 67 108 864. A result line larger than this is not scanned. |
| `on_oversize` | `flag` \| `block` | `flag` | What happens to an unscanned oversize result. |

## `egress`

| Key | Type | Default | Notes |
| --- | --- | --- | --- |
| `default` | `allow` \| `hold` \| `deny` | `deny` | |
| `rules[].id` | identifier | `rule[<index>]` | Unique within the section. |
| `rules[].match.host` | glob \| glob[] | required | Delimiter `.` — `*.github.com` matches `api.github.com` but not `a.b.github.com`; `**.github.com` matches both. |
| `rules[].match.methods` | string[] | any | Upper-case HTTP methods. |
| `rules[].match.path` | glob \| glob[] | `/**` | Delimiter `/`. |
| `rules[].match.max_body_bytes` | integer ≥ 0 | — | Request body size cap for the rule to match. |
| `rules[].action` | `allow` \| `hold` \| `deny` | required | |
| `rules[].reason` | string ≤ 512 | — | |

## Matching semantics

**First match wins.** Rules are evaluated top to bottom; the first rule whose
every `match` condition holds decides the action. No rule → `default`.
This is deliberately firewall-like: put specific rules first, broad ones last.

**Globs** (identical in the TypeScript engine and in the emitted Rego, which
uses `glob.match(pattern, [delimiter], subject)`):

| Token | Meaning |
| --- | --- |
| `*` | any run of characters **not** containing the delimiter |
| `**` | any run of characters, delimiter included |
| `?` | exactly one non-delimiter character |
| anything else | literal, case-sensitive |

Delimiters: `/` for `tool`, `server` and `path`; `.` for `host`. Patterns are
anchored (they must match the whole subject).

**Regexes** (`match.args`) must stay inside the RE2 subset so that the local
JavaScript engine and OPA's RE2 agree: lookaround (`(?=`, `(?!`, `(?<=`,
`(?<!`) and backreferences (`\1`…`\9`) are rejected by `policy validate`.
Inline flag and modifier groups (`(?i)`, `(?s)`, `(?m)`, `(?U)`, `(?i:...)`,
`(?-i:...)`) are rejected as well: RE2 accepts them, JavaScript engines differ
by version (Node 24 accepts `(?i:...)`, Node 20 does not), and both sides must
agree — only `(?:...)` non-capturing and `(?<name>...)` named groups are
allowed. Use character classes (`[Aa]`) for case-insensitive matching. Regexes are
unanchored (write `^`/`$` yourself) and matching is a *search*, not a
full-string match.

**Dot-paths** (`match.args` keys) address into `params.arguments`:
`path`, `options.recursive`, `items.0.name`. Numeric segments index arrays.
Keys containing `.` are not addressable in v1. The value at the path is
coerced before matching: strings as-is, numbers and booleans via their
canonical string form (`1.5`, `true`), anything else (`null`, objects,
arrays, missing) never matches. Values longer than 64 KiB are truncated to
64 KiB before the regex runs (a bound against pathological inputs).

**`max_args_bytes`** compares against the byte length of the canonical JSON
(sorted keys, no whitespace) of `params.arguments` — the same canonical form
the evidence chain hashes.

## What the actions do (gateway mode)

| Action | Request forwarded to the server? | What the model receives |
| --- | --- | --- |
| `allow` | yes, byte-for-byte unchanged | the server's real result (after the boundary filter) |
| `deny` | **no** | a tool result with `isError: true` whose text names the rule and reason |
| `hold` | only after `mcp-recorder approve <id>` | on approval, the real result; on deny/timeout/cancel, an `isError` result naming the approval id and outcome |

A denial is a *tool error*, not a JSON-RPC protocol error, so clients keep
the session alive and the model can explain itself or try something else.
The exact text is:

```
mcp-recorder gateway: tools/call "http_post" denied by policy rule "no-exfil": outbound HTTP from agents is not allowed on this machine
```

Holds park the original request bytes in memory and write a record to
`<data-dir>/holds/<approval-id>.json` (mode `0600`, containing the tool name
and the **redacted** arguments — hashed exactly like `tool_call.args`, never
readable). Other traffic keeps flowing while a call is held. A
`notifications/cancelled` from the client for the held request cancels the
hold. Anyone who can write the data directory can approve — the data
directory is private (`0700`) and this is local trust by design; the hosted
gateway is where approvals get an identity.

## The tool-result boundary filter

Every `tools/call` result that the gateway saw the request for is scanned
before it reaches the client:

- **Secrets.** Spans matching the recorder's `alwaysPatterns` — the very same
  regexes that produce `secret_refs` in recorded events (AWS keys, GitHub and
  OpenAI tokens, Slack tokens, JWTs, PEM private keys, bearer tokens, …).
  `redact` replaces each span with `[redacted:sha256:<16 hex>]`; the full
  `sha256:<hex>` of every redacted token is recorded on the event
  (`gateway.boundary.secret_refs`) so `mcp-recorder query <value>` still finds
  the call even though the model never saw the value.
- **Injection markers.** A conservative, documented list
  (`src/gateway/injection.ts`): "ignore previous instructions", "SYSTEM
  OVERRIDE", developer-mode jailbreaks, "do not mention this step", "reveal
  your system prompt", HTML comments carrying imperative instructions, and
  similar. False positives are possible on security documentation that
  quotes such phrases; that is why the default is `flag` (record, don't
  touch).
- **Actions.** `redact` rewrites the matched span; `block` replaces the whole
  result with an `isError` result saying what was found; `flag` forwards the
  result unchanged and only records; `off` skips the scan. When secrets and
  injection resolve to different actions, `block` beats `redact` beats `flag`.
- **Scope.** `result.content[*].text` for `text` blocks and
  `result.content[*].resource.text` for embedded text resources. Binary
  blobs, images and `structuredContent` are not scanned in v1.
- **Size.** A result line larger than `max_scan_bytes` is not scanned and
  `on_oversize` decides (`flag` or `block`). The event records `scanned: false`.

When nothing changes, the server's bytes are forwarded untouched. When the
filter rewrites a result, the event keeps `result`/`result_hash` for the raw
result the server returned (their frozen meaning) and adds
`gateway.boundary.delivered_result_hash` for the result the client actually
received, so the evidence shows both what came back and what the model saw.

## Validation

```sh
mcp-recorder policy validate policy.yaml          # exit 0 valid, 1 invalid, 2 unreadable
mcp-recorder policy validate policy.yaml --json
```

Errors carry a JSON-pointer path:

```
policy.yaml: invalid
  /mcp/rules/1/match/tool: required property missing
  /mcp/rules/2/match/args/path: lookahead "(?=" is not supported (RE2 subset)
  /mcp/hold/timeout_ms: must be <= 3600000
```

`.yaml`, `.yml` and `.json` files are accepted. Duplicate YAML keys are an
error. The validator is the shipped JSON Schema plus a few semantic checks
the schema language can't express (unique ids, the RE2 subset, ranges). A
file that exists but does not parse is reported as invalid (exit 1, one error
at pointer `/`); exit 2 is reserved for a file that cannot be read at all.

`--json` prints `{ "path", "valid": true, "name"?, "hash", "source",
"mcp_rules", "egress_rules" }` for a valid file and
`{ "path", "valid": false, "errors": [{ "path", "message", "keyword" }] }`
otherwise, so a CI step can fail on `valid` and show the pointers.

## Compiling to Rego

```sh
mcp-recorder policy compile policy.yaml                 # prints cresec/mcp/tool.rego
mcp-recorder policy compile policy.yaml --out ./bundle  # writes an OPA bundle directory
# wrote 3 file(s) to /abs/path/bundle
#   .manifest
#   cresec/mcp/tool.rego
#   cresec/egress/http.rego
```

An invalid policy exits 1 with the same error listing as `validate` and
writes nothing.

The bundle follows the Cresec control plane's layout — sibling packages to
the existing `cresec.broker`, one `decision` object rule each:

```
bundle/
├── .manifest                {"revision": "<sha256 of policy.yaml>", "roots": ["cresec/mcp", "cresec/egress"]}
└── cresec/
    ├── mcp/tool.rego        package cresec.mcp
    └── egress/http.rego     package cresec.egress   (only if `egress` is present)
```

`cresec/mcp/tool.rego` is always emitted (a policy without `mcp` compiles to
`default allow`, no rules); `cresec/egress/http.rego` — and the
`"cresec/egress"` entry in `roots` — only when the policy has an `egress`
section. The two files deliberately have distinct basenames.

Input and decision shapes. The decision is a superset of the broker's
(`allow` + `deny_reason`), so a consumer that only understands those two keys
still fails closed on `hold`. `allow` is `action == "allow"`; `deny_reason` is
`""` for an allow, `rule <id>: <reason>` for a matched deny/hold rule
(`rule <id>` when the rule has no `reason`), and `default deny` /
`default hold` when no rule matched and the section `default` applied
(`matched: false`, empty `rule_id`):

```jsonc
// package cresec.mcp — input
{ "server": "filesystem", "tool": "read_file", "args": { "path": "/etc/passwd" }, "args_bytes": 21 }
// data.cresec.mcp.decision
{ "allow": false, "action": "deny", "rule_id": "no-secrets-files",
  "reason": "credential files are off limits", "matched": true,
  "deny_reason": "rule no-secrets-files: credential files are off limits" }

// package cresec.egress — input
{ "host": "api.github.com", "method": "POST", "path": "/repos/o/r/pulls", "body_bytes": 812 }
// data.cresec.egress.decision
{ "allow": false, "action": "hold", "rule_id": "github-write-needs-approval",
  "reason": "", "matched": true, "deny_reason": "rule github-write-needs-approval" }
```

Try it with OPA directly:

```sh
opa check ./bundle
opa eval -b ./bundle -i input.json 'data.cresec.mcp.decision'
opa build -b ./bundle -o policy-bundle.tar.gz
```

The TypeScript engine and the emitted Rego are kept semantically identical:
the test suite evaluates the same inputs through both (`opa eval`) and
requires the decisions to agree.

## Evidence

Gateway decisions are part of the tamper-evident chain, under the frozen
`edut.mcp-recorder.event.v1` schema (additive fields only):

- `session_start.policy` — `{ hash, name }` of the policy in force.
- `tool_call.gateway` — `{ decision, rule_id, outcome, approval_id, boundary }` on every tool call.
- `policy_decision` events — one per deny and one per hold outcome, with
  `policy_hash`, `args_hash`, `approval_id`, `waited_ms`, `approver`.

See [docs/event-schema.md](event-schema.md) for the exact fields.

## Limitations (v1)

- Gateway mode is available for the stdio transport. `mcp-recorder http
  --policy` is rejected with a clear error for now.
- `egress` rules are validated and compiled but not enforced by
  `mcp-recorder`.
- Denied tools are not hidden from `tools/list`; the model may still attempt
  them and receive the deny result.
- Hold approvals are local trust (anyone who can write the data directory).
- Injection detection is pattern-based and conservative by design; it is a
  tripwire plus evidence, not a classifier.
