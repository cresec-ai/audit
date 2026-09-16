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
| `match.server` | glob \| glob[] | no | Matches the recorder's logical server name (`--name`, else the name learned from the `initialize` handshake, else the wrapped command's basename). Any one entry of the list matching is enough. Default `*`. Delimiter `/`. |
| `match.tool` | glob \| glob[] | yes | Matches the `tools/call` `params.name`. Any one entry of the list matching is enough. Delimiter `/`. |
| `match.args` | object of regex | no | Each key is a dot-path into `params.arguments`; each value an RE2-compatible regex. **All** entries must match. A missing path — or an `arguments` that is not an object — never matches. |
| `match.max_args_bytes` | integer ≥ 0 | no | Rule matches only when the canonical JSON of `params.arguments` is at most this many bytes. |
| `action` | `allow` \| `hold` \| `deny` | yes | |
| `reason` | string ≤ 512 | no | Shown to the model on a deny / hold-denied result; also copied into the compiled Rego. Longer than 512 characters is a validation error. |

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
| `?` | **not supported in v1** — `policy validate` rejects any glob containing it |
| anything else | literal, case-sensitive |

Delimiters: `/` for `tool`, `server` and `path`; `.` for `host`. Patterns are
anchored (they must match the whole subject). `[ ] { } \` are rejected too:
OPA's glob library gives them a meaning this one does not.

`?` is out because the two engines disagree about it: OPA's `glob.match`
matches `?` against exactly one **ASCII** character, while the local engine
(a UTF-16 regex) matches any non-delimiter character — `a?b` accepts `aéb`
in the gateway and rejects it in OPA. `*` and `**` have no such split, so v1
ships without `?` rather than with two meanings for it. Use `*` instead.

**Regexes** (`match.args`) must stay inside the RE2 subset so that the local
JavaScript engine and OPA's RE2 agree. `policy validate` rejects:

- lookaround — `(?=`, `(?!`, `(?<=`, `(?<!`;
- backreferences — `\1`…`\9` and the named form `\k<name>`;
- inline flag and modifier groups — `(?i)`, `(?s)`, `(?m)`, `(?U)`,
  `(?i:...)`, `(?-i:...)`, and every other `(?` form (`(?P<name>`, `(?#`,
  `(?>`): RE2 accepts inline flags, JavaScript engines differ by version
  (Node 24 accepts `(?i:...)`, Node 20 does not), and both sides must agree —
  only `(?:...)` non-capturing and `(?<name>...)` named groups are allowed.
  Use character classes (`[Aa]`) for case-insensitive matching;
- a `]` written directly after `[` or `[^` — `[]a]` is a class containing
  `]` and `a` in RE2 but an *empty* class in JavaScript. Escape it: `[\]a]`;
- POSIX classes (`[:alpha:]`) and `\x{...}`;
- every backslash escape outside this list;
- repeated groups whose repetition is ambiguous — `(a+)+`, `(a|aa)+`,
  `(\w+[ ]?)*`, `(.*a)*`, `(ab?)*`: RE2 matches these in linear time, but the
  local JavaScript engine backtracks exponentially (`^(a+)+$` against 29
  non-matching characters takes about 14 seconds and, on the single-threaded
  proxy, stalls every other call behind it). A repeated group must end with
  something the repeated part cannot match — `([a-z0-9-]+\.)*` and
  `(\d{1,3}\.){3}\d{1,3}` are fine, as is a group that is not repeated
  (`(^|/)(\.env|id_rsa)$`) or repeated only with `?`.

Belt and braces: at run time every `match.args` regex is matched on a worker
thread under a 25 ms deadline. A match that overruns it is abandoned, the
pattern is disabled for the rest of the process, and the call is denied with
`policy evaluation error: regex timed out (<rule id>)` — enforcement fails
closed, so a pattern that cannot be evaluated is never treated as "did not
match".

The accepted escapes — each means exactly the same thing in RE2 and in V8
without the `u` flag — are:

| Escape | Meaning |
| --- | --- |
| `\d` `\D` `\w` `\W` | ASCII digit / non-digit, word / non-word character |
| `\b` `\B` | word boundary / non-boundary (**outside** a character class only — RE2 rejects `[\b]`, which JavaScript reads as a backspace) |
| `\n` `\r` `\t` `\f` `\v` | newline, carriage return, tab, form feed, vertical tab |
| `\xhh` | the byte `hh`, exactly two hex digits (`\x41`) |
| `\` + any ASCII punctuation | that character, literally (`\.` `\\` `\-` `\]` `\+` …) |

Everything else after a backslash is rejected, including `\s` and `\S`
(RE2's `\s` is ASCII-only, JavaScript's also matches Unicode spaces such as
U+00A0 — write `[ \t\r\n\f]` instead), `\0`, `\a`, `\e`, `\h`, `\z`,
`\A`, `\Z`, `\p`, `\P`, `\Q`, `\E`, `\C`, `\G`, `\u`, `\U`, `\c` and
any escaped non-ASCII character. Regexes are unanchored (write `^`/`$`
yourself) and matching is a *search*, not a full-string match.

**Dot-paths** (`match.args` keys) address into `params.arguments`:
`path`, `options.recursive`, `items.0.name`. Numeric segments index arrays
(and *only* arrays: a `{"0": ...}` object key is not reachable by `0`).
Keys containing `.` are not addressable in v1.

`params.arguments` is an object per MCP, and a dot-path only resolves when it
is one: if a client sends an array, a string, a number, a boolean or `null`
as `arguments`, **no `args` condition matches** — a rule with `args` simply
falls through. (The compiled Rego says so as an explicit
`is_object(input.args)` line, so both engines refuse a non-object root for
the same stated reason.)

The value at the path is coerced before matching: strings as-is, numbers and
booleans via their canonical string form (`1.5`, `true`), anything else
(`null`, objects, arrays, missing) never matches. A value longer than 4 KiB
(4096 UTF-16 units) is **not matched at all**, and the call is denied
fail-closed with `policy evaluation error`. It is not truncated to the cap:
truncating turned a deny into an allow, since `"x".repeat(5000) + "rm -rf /"`
then did not match a `cmd: "rm -rf /"` rule and was forwarded. The cap exists
because the local engine matches with JavaScript's backtracking RegExp and
something has to bound the work one argument can ask of it; RE2 is
linear-time, so the Rego side has no cap and only values beyond it can make
the two engines differ — in the safe direction, a local deny where the
control plane would have allowed.

The number form is JavaScript's: the shortest text that round-trips, with an
exponent only below `1e-6` or at/above `1e21`. `1234567.5` is `"1234567.5"`,
`0.00001` is `"0.00001"`, `1e-7` is `"1e-7"`, `1e21` is `"1e+21"`, `42.0` is
`"42"` and `-0` is `"0"`. The emitted Rego gets the same text from
`json.marshal` (Go's `encoding/json` formats float64 by the same rules) —
**not** from `sprintf("%v", [v])`, which would print `1.2345675e+06` for
`1234567.5` and make the two engines disagree.

One residual difference, unreachable through this gateway but worth knowing
for the hosted one: OPA keeps a JSON number exactly as it was *written on the
wire*, so a request body containing `{"n": 1.0}`, `{"n": 1e21}`, `{"n": -0}`
or an integer with more than 17 significant digits compares as `"1.0"`,
`"1e21"`, `"-0"` and its full-precision text in OPA, where JavaScript's
`JSON.parse` + `String()` produce `"1"`, `"1e+21"`, `"0"` and the nearest
float64. Any value that has been through a JavaScript `JSON.stringify` — as
everything the recorder forwards has — is already in the canonical form and
the two agree exactly. Match on strings when a number's exact spelling
matters.

**`max_args_bytes`** compares against the byte length of the canonical JSON
(sorted keys, no whitespace) of `params.arguments` — the same canonical form
the evidence chain hashes.

## What the actions do (gateway mode)

| Action | Request forwarded to the server? | What the model receives |
| --- | --- | --- |
| `allow` | yes, byte-for-byte unchanged | the server's real result (after the boundary filter) |
| `deny` | **no** | a tool result with `isError: true` whose text names the rule and reason |
| `hold` | only after `mcp-recorder approve <id>` | on approval, the real result; on deny/timeout/cancel, an `isError` result naming the approval id and outcome; when the hold could not be started at all (unwritable hold file, 256 holds already pending, or the session already shutting down) an `isError` result naming that reason instead |

A denial is a *tool error*, not a JSON-RPC protocol error, so clients keep the
session alive and the model can explain itself to the user. The exact text is
two lines — the refusal, then one standard clause telling the agent this was a
policy decision rather than a broken tool:

```
mcp-recorder gateway: tools/call "http_post" denied by policy rule "no-exfil": outbound HTTP from agents is not allowed on this machine
This is a policy decision by the operator, not a tool failure. Do not retry it or use another tool to get the same effect; report it to the user.
```

Which clause depends on **who refused**, and the recorder tracks that
explicitly rather than guessing from the reason text. A rule deny, an
`mcp.default` deny, a hold a human denied (or whose configured timeout ran
out, or that was abandoned at session end) and a boundary `block` all carry
the clause above. The refusals where the gateway **failed closed** — a policy
that could not be evaluated, an unwritable hold file, 256 holds already
pending, a hold refused because the session was shutting down, and a result
too large to scan — carry a different one:

```
The gateway could not reach a policy decision, so it refused this call rather than allow it unchecked. You may retry it; do not use another tool to get the same effect, and report it to the user.
```

Nobody decided those, so the text does not claim they did, and it does not
forbid the retry that is often the fix — `too many pending holds` clears the
moment a parked hold resolves. What it still forbids is the move that would
make the gateway pointless: getting the same effect through a tool the policy
does not name.

One refusal in the table above carries neither clause: a hold the **client**
itself cancelled (`notifications/cancelled`), where nothing was refused and
the caller already knows.

Without a clause, an agent that reads only the first line plausibly retries
the identical call forever, reaches the same effect through a tool the rule
does not name (denied `http_post` → `bash curl`), or decides the tool is
broken and gives up without telling anyone. One line of tool output is a
floor, not a fix: [docs/agent-guidance.md](agent-guidance.md) has a snippet to
paste into the agent's own instructions so it reads the same guidance *before*
it plans.

Holds park the original request bytes in memory and write a record to
`<data-dir>/holds/<approval-id>.json` (mode `0600`, containing the tool name
and the **redacted** arguments — hashed exactly like `tool_call.args`, never
readable). Other traffic keeps flowing while a call is held. A
`notifications/cancelled` from the client for the held request cancels the
hold. Anyone who can write the data directory can approve — the data
directory is private (`0700`) and this is local trust by design; the hosted
gateway is where approvals get an identity.

## The tool-result boundary filter

Every `tools/call` result is scanned before it reaches the client — the ones
the gateway saw the request for, each element of a batch array answering such
requests, and any result the gateway can no longer correlate (its request was
evicted, or the server volunteered one) that still carries `result.content`
blocks. That last case is scanned fail-closed and still recorded as
`protocol_error` `orphan_response`, exactly as in record mode:

- **Secrets.** A deliberately narrow, high-confidence subset of the recorder's
  `alwaysPatterns` (`boundarySecretPatterns()` in `src/gateway/boundary.ts`):
  AWS access key ids (`AKIA…`/`ASIA…`), GitHub tokens
  (`ghp_`/`gho_`/`ghu_`/`ghs_`/`ghr_`), `sk-…` API keys (OpenAI and Anthropic
  `sk-ant-…`), Slack tokens (`xox[baprs]-…`), JWTs (three base64url segments
  behind an `eyJ` header), PEM private-key blocks, `Bearer` authorization
  values, and `password=` / `passwd:` / `secret=` / `token:` / `api_key=`
  assignments carrying a value. The generic long-hex (32+ hex characters) and
  long-base64 (40+ characters) shapes are deliberately excluded at the
  boundary: they match git SHAs, sha256 checksums, dash-less UUIDs, container
  digests and inline base64 images, and rewriting those would corrupt ordinary
  output a coding agent reads (`git log`, `sha256sum`, lockfiles). Storage
  redaction is unchanged and still hashes every one of those shapes, so they
  never reach the evidence store in clear and `secret_refs` on stored events
  keeps its wider meaning. `redact` replaces each span with
  `[redacted:sha256:<16 hex>]`; the full `sha256:<hex>` of every redacted
  token is recorded on the event (`gateway.boundary.secret_refs`) so
  `mcp-recorder query <value>` still finds the call even though the model
  never saw the value.
- **Injection markers.** A conservative, documented list
  (`src/gateway/injection.ts`): "ignore previous instructions", "SYSTEM
  OVERRIDE", developer-mode jailbreaks, "do not mention this step", "reveal
  your system prompt", HTML comments carrying imperative instructions, and
  similar. False positives are possible on security documentation that
  quotes such phrases; that is why the default is `flag` (record, don't
  touch). Before scanning, the filter normalizes a copy of the text: every
  format character (`\p{Cf}`), every default-ignorable code point and
  U+034F are stripped — that is the whole class, not a hand-written range
  list, because a dozen characters outside the list delivered the identical
  instruction with `injection_found: 0`; NFKC folds homoglyphs (fullwidth,
  mathematical and other compatibility forms) onto their ASCII equivalents;
  combining marks are dropped in a second copy (a mark is visible, so
  dropping it for everyone would fold distinct words together); runs of
  whitespace collapse to a single space; and ANSI escape sequences are
  consumed WHOLE — CSI, the intermediate and two-character forms, OSC, DCS,
  APC, PM, SOS and the 8-bit C1 introducers — so a sequence a terminal does
  not render cannot split a marker in two. Consuming a sequence also removes
  text a model reading the raw bytes still sees, so a second copy keeps
  exactly that (a string family's data, a bare escape's final byte) and the
  two span sets are unioned. Every marker found is mapped back onto the
  original text, so what gets reported and rewritten is exactly the original
  bytes. Base64-encoded instructions and keywords split by markdown or HTML
  markup are out of scope — the filter does not decode or un-mark-up text
  before scanning.
- **Actions.** `redact` rewrites the matched span; `block` replaces the whole
  result with an `isError` result saying what was found; `flag` forwards the
  result unchanged and only records; `off` skips the scan. When secrets and
  injection resolve to different actions, `block` beats `redact` beats `flag`.
  A `block` carries the same policy-decision clause a deny does: the operator's
  `mcp.boundary` setting decided it, and reading the same content through
  another tool is exactly what the boundary exists to stop.

  Which clause a refusal carries turns on WHO decided, not on how it turned
  out. A hold a human denied, and one the operator's own `on_timeout: deny`
  ended, are both policy decisions. A hold the session simply ended under is
  not — nobody answered it — and neither is one refused inside a JSON-RPC
  batch, where there is nowhere to park and so nobody is asked; both carry the
  fail-closed clause. The sharpest case is a hold a human APPROVED that the
  proxy still could not forward because the session was already closing: the
  operator said yes, so the text must not tell the agent they refused.
- **Scope.** `result.content[*].text` for `text` blocks and
  `result.content[*].resource.text` for embedded text resources. Binary
  blobs, images and `structuredContent` are not scanned in v1.
- **Size.** A result line larger than `max_scan_bytes` is not scanned and
  `on_oversize` decides (`flag` or `block`). The event records `scanned: false`.
  For a batch answer the comparison uses the length of the whole array line, so
  an oversized batch is skipped (or blocked) as a unit. An oversize `block`
  carries the **fail-closed** clause, not the policy-decision one: nothing
  about the call was judged, so re-issuing it for less output (a page, a
  range, a narrower filter) is the correct recovery and the text must not
  discourage it.

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
file that exists but does not parse is reported as invalid (exit 1, one
error whose JSON `path` is the RFC 6901 root pointer — the empty string `""`
— which the human listing renders as `/`); exit 2 is reserved for a file
that cannot be read at all.

A **valid** policy can still carry a warning, printed after the `valid` line
and leaving the exit code at 0:

```sh
mcp-recorder policy validate egress-only.yaml
# /abs/egress-only.yaml: valid (0 mcp rules, 3 egress rules)
#   warning: no "mcp" section — nothing for the gateway to enforce (record --policy and setup --policy will refuse it)
```

A policy with no `mcp` section is valid (the top level requires one of
`mcp`/`egress`) and compiles fine for the sidecar, but `mcp-recorder record
--policy` and `mcp-recorder setup --policy` **refuse it with exit 2** —
there is nothing for the stdio gateway to enforce, and silently allowing
everything is not an option. Validate-in-CI catches everything else; this
warning is how it catches that too.

`--json` prints `{ "path", "valid": true, "name"?, "hash", "source",
"mcp_rules", "egress_rules", "warnings" }` for a valid file (`warnings` is an
array of strings, empty when there is nothing to say) and
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
  --policy` is rejected with a clear error (exit 2) for now. `mcp-recorder
  http` **ignores** an exported `MCP_RECORDER_POLICY` instead of refusing to
  start, printing `http: MCP_RECORDER_POLICY ignored — gateway mode is
  available for the stdio transport only` on stderr and recording as usual,
  so the variable can stay exported in a shell that also runs stdio servers.
- A policy without an `mcp` section is valid, and `policy validate` exits 0
  (with a warning), but `record --policy` and `setup --policy` refuse it with
  exit 2 — the gateway would have nothing to enforce.
- `egress` rules are validated and compiled but not enforced by
  `mcp-recorder`.
- Denied tools are not hidden from `tools/list`; the model may still attempt
  them and receive the deny result.
- Hold approvals are local trust (anyone who can write the data directory).
- Injection detection is pattern-based and conservative by design; it is a
  tripwire plus evidence, not a classifier.
