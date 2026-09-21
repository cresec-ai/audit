# Policy reference — `policy.yaml` schema v1

`policy.yaml` is the single policy file for agent harnesses in the Cresec
line of tools. Two consumers read it:

- **`mcp-recorder` gateway mode** (`mcp-recorder record --policy policy.yaml -- <server>`
  for a stdio server, `mcp-recorder http --target URL --policy policy.yaml` for a
  streamable-HTTP one)
  enforces the `mcp` section on every MCP `tools/call` that crosses the proxy:
  per-tool **allow / hold / deny**, plus a **tool-result boundary filter** that
  redacts secret-shaped values and flags prompt-injection markers in tool
  results before the model sees them. It also enforces the `credentials`
  section: at a declared swap site, and only there, a synthetic credential in
  an outbound argument is exchanged for a real one under a recorded decision.
  See [docs/gateway.md](gateway.md) for the 10-minute walkthrough.
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

credentials:                          # synthetic -> real, only at the sites declared here
  - id: github-issues
    provider: github                  # informational; recorded on the decision
    scopes: ["repo:issues"]           # informational; recorded on the decision
    source:
      type: env
      var: GITHUB_TOKEN
    use:
      - id: create-issue
        server: corp-notes
        tool: http_post
        arg: headers.Authorization    # the ONLY place this credential is spliced
        host:
          from_arg: url               # the destination comes from the CALL ...
          allow: ["api.github.com"]   # ... and has to be one of these

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
| `mcp` | object | one of the three | MCP tool-call policy (enforced by `mcp-recorder`). |
| `credentials` | array | one of the three | Credential-broker policy (enforced by `mcp-recorder`). |
| `egress` | object | one of the three | HTTP egress policy (compiled for the sidecar). |

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

## `credentials`

A list of credentials the gateway may hand to a server, and the **declared
swap sites** where it may do so. At a declared site the synthetic credential
found in one named argument is exchanged for the real one, under a decision
recorded in the evidence chain; everywhere else the synthetic is forwarded
untouched and the upstream rejects it.

**What this buys, stated honestly.** The real credential is absent from the
model's context and from the transcript, and every use of it is a
policy-checked, revocable decision recorded under a decision id. It is **not**
hidden from anything that can run code as the same OS user — which includes
the agent's own shell. The agent can read the env var, the file or the
command this section names, and it can read this section to learn which one to
read. Brokering is a *context and audit* control on a single-uid developer
machine, and a *confidentiality* control only when the resolver runs as a
principal the agent is not (a root-owned policy plus a root-owned resolver, or
the hosted control plane). See [docs/red-team.md](red-team.md).

```yaml
credentials:
  - id: github-issues
    provider: github
    scopes: ["repo:issues"]
    ttl_seconds: 30
    timeout_ms: 5000
    on_unresolved: deny
    source: { type: env, var: GITHUB_TOKEN }
    use:
      - id: no-deletes                # first match wins: carve-outs go first
        server: corp-notes
        tool: http_delete
        arg: headers.Authorization
        host: { from_arg: url, allow: ["api.github.com"] }
        action: deny
        reason: an issues token does not delete things
      - id: create-issue
        server: corp-notes
        tool: http_post
        arg: headers.Authorization
        host: { from_arg: url, allow: ["api.github.com"] }
```

| Key | Type | Default | Notes |
| --- | --- | --- | --- |
| `id` | identifier | required | Unique within the section. Recorded on every decision — the credential's **name**, never its value. |
| `provider` | identifier | — | Informational for a `source` credential (`github`, `clickup`, …). Recorded on the decision. For a `broker` credential it is the control plane's **connector** and must be one of `salesforce`, `gmail`, `workspace`, `slack`, `outlook` (`policy validate` refuses anything else). |
| `scopes` | string[] | — | Informational: what the **real** credential can do. Recorded on the decision, so blast radius is answerable from the chain instead of reconstructed later. |
| `source` | object | one of `source` / `broker` | Where the real credential is resolved from **on this machine**. See below. |
| `broker` | object | one of `source` / `broker` | Resolve this credential through the **Cresec control plane's per-user token endpoint** instead. See [`credentials[].broker`](#credentialsbroker--resolved-by-the-control-plane). |
| `use[]` | array | required, ≥ 1 | Declared swap sites, in order; first match wins. |
| `ttl_seconds` | integer 0–300 | `30` | How long a positive decision may be cached. |
| `timeout_ms` | integer 100–30000 | `5000` | Deadline for resolving the source. Overrunning it **denies this call**. |
| `on_unresolved` | `deny` | `deny` | The only value the schema admits. It is spelled out because the alternative — forwarding the call anyway — forwards the *synthetic* to the upstream. |

### `credentials[].source`

Named by the config and only ever by the config; a call can never choose its
own source. Every path is absolute, because a relative one would resolve
against the client's working directory rather than the policy's.

| `type` | Keys | Notes |
| --- | --- | --- |
| `env` | `var` | Environment variable of the **recorder** process. |
| `file` | `path`, `field?` | `field` is a dot-path into the file parsed as JSON; absent = the whole file, trimmed. |
| `exec` | `command`, `args?` | argv, no shell. `command` must be an absolute path: a bare name resolves through `PATH`, which the agent can prepend to. |
| `github-app` | `app_id`, `installation_id`, exactly one of `private_key_file` / `private_key_env`, `repositories?`, `permissions?` | Mints a short-lived installation token; `repositories` / `permissions` narrow it. |
| `aws-sts` | `role_arn`, `region?`, `session_name?`, `duration_seconds?` (900–43200, default 900), `external_id?` | Mints a short-lived session. |
| `vault` | `path`, `field?` (default `token`), `addr?`, `namespace?`, `token_env?` | OpenBao / Vault. `field` defaults to the key the Cresec control plane reads. |
| `clickup` | `token_env?` (default `CLICKUP_API_TOKEN`), `team_id?` | |

Prefer `github-app` and `aws-sts` over `env` even locally: they mint
short-lived, narrowly-scoped tokens, which shrinks the *window* in which a
leaked value is worth anything. None of them shrinks the *readership* — the
root credential (the app private key, the AWS credentials, the OpenBao token)
sits in an env var or a file with the same permissions, so an agent on the
same uid mints its own token rather than stealing the brokered one.

### `credentials[].use[]` — the declared swap site

| Key | Type | Default | Notes |
| --- | --- | --- | --- |
| `id` | identifier | `use[<index>]` | Unique within the credential. Recorded (and used as the Rego rule id) as `<credential id>/<id>`. |
| `server` | glob \| glob[] | `*` | The logical server name. Delimiter `/`, same globs as `mcp`. |
| `tool` | glob \| glob[] | required | The `tools/call` `params.name`. Delimiter `/`. |
| `arg` | dot-path | required | Where in `params.arguments` the swap happens — and **the only place it happens**. |
| `host` | object | required | Where the request is allowed to go. See below. |
| `path` | object | `{ from: tool }` | What `request.path_template` is. |
| `action` | `allow` \| `deny` | `allow` | `hold` is not available in v1 (see Limitations). |
| `reason` | string ≤ 512 | — | Shown to the model on a deny. |
| `action_class` | `read` \| `draft` \| `send` \| `write` | `write` | The control plane's action class for this site (`read` and `draft` need no grant there; `send` and `write` do). Sent as `action_class` on the per-user token request of a `broker` credential; informational for a local `source`. The default is the class that always needs a grant. |
| `method` | `^[A-Za-z]{1,16}$` | `POST` | The HTTP method this site's request maps onto (`target.method` on the per-user token request). Upper-cased. |

The swap is **destination-bound, never value-bound**: the real token replaces
the synthetic inside the string at `arg`, at a site whose `server`, `tool`,
`host` and `path` all match, and nowhere else the synthetic string happens to
occur. That is what stops the reflection attack — ask an `echo`-shaped tool to
return its input and it is simply not a declared site, so it receives the
synthetic and the upstream rejects it.

#### Type the argument in your server's schema

`arg` is a dot-path into `params.arguments`, so the client has to send that
structure. If the tool's `inputSchema` leaves the property untyped, a client
may send a **JSON string** where you expect an object, and
`headers.Authorization` then resolves to nothing.

This is not hypothetical. In dogfood 7 the fixture declared
`inputSchema: { type: 'object', additionalProperties: true }` with no
`properties`, and Claude Code sent:

```json
"headers": "{\"Authorization\": \"Bearer cresec_synth_v1_…\"}"
```

twice in a row — a string, not an object — and it did so again when the prompt
explicitly said to send a nested object. Adding `properties.headers.type =
"object"` to the tool's schema fixed it on the first try. **The schema, not
the prompt, is what decides this.**

When the shape does not match, the gateway now **refuses** the call with
`site_arg_unresolved` rather than forwarding it. It used to forward it
untouched, which meant the synthetic went to the upstream while the operator
believed the credential had been swapped — a control doing nothing, with no
symptom. A refusal is the version of that with a symptom.

The refusal fires only when a synthetic is actually present somewhere in the
arguments. A declared tool called without any credential is ordinary traffic
and is forwarded as written.

### `credentials[].use[].host` — the destination

Required. A swap site with no host constraint is a full-privilege credential
with extra steps: a policy that allows `corp-notes/http_post` with a
credential in `headers.Authorization` and says nothing about the destination
authorises `http_post` to `attacker.example` exactly as happily as to
`api.github.com`, and the destination is the agent's to choose.

| Form | Meaning | `host_source` on the decision |
| --- | --- | --- |
| `{ from_arg: <dot-path>, allow: <glob\|glob[]> }` | The named argument is parsed as an absolute URL and its hostname must match one of the globs (delimiter `.`). An argument that is not an absolute URL cannot be resolved to a host, and the call is denied. | `argument` |
| `{ fixed: <hostname> }` | The operator asserts the upstream a server always talks to. Checked against nothing in the call. | `declared` |
| `{ from: server }` | There is no destination: the logical server name stands in for the host, which is what NHI's contract means by "the resolved server origin or server name". This authorises the **tool**, not the **destination**. | `server_name` |

`host_source` is recorded, and it is also a condition in the compiled Rego, so
the log — and the control plane — distinguish "the host was checked" from "the
host was the server name" without anyone having to reconstruct which it was.

`path` takes the same two argument-derived / default forms:
`{ from_arg: <dot-path>, allow: <glob|glob[]> }` (delimiter `/`) or the
default `{ from: tool }`, which says `request.path_template` is the tool name.

### `credentials[].broker` — resolved by the control plane

```yaml
credentials:
  - id: gmail-drafts
    provider: gmail                       # the control plane's connector name — REQUIRED here
    broker:
      kind: remote
      url: https://api.staging.cresec.ai  # https://; http:// on loopback only
      token_env: CRESEC_INTERNAL_TOKEN    # the internal bearer, named, never its value
      tenant: e2e                         # slug or uuid; optional with an identity JWT
      identity_jwt_env: CRESEC_IDENTITY_JWT   # or start the recorder with --identity-jwt PATH
      # user_env: CRESEC_USER_ID            # the user id when no identity JWT is given
      # tool_id / tool_version              # the tool claim when no identity JWT is given
      # timeout_ms: 5000
    use:
      - id: draft
        tool: gmail_create_draft
        arg: headers.Authorization
        host: { from_arg: url, allow: [gmail.googleapis.com] }
        action_class: draft
        method: POST
```

A credential with `broker: { kind: remote }` has no local `source`: the
gateway resolves it by calling the control plane's per-user token endpoint,
`POST <url>/v1/broker/user-token`, exactly as
[`docs/internal/contracts/user-token.md`](https://github.com/cresec-ai/nhi/blob/main/docs/internal/contracts/user-token.md)
in cresec-ai/nhi specifies (the contract page spells the block
`credentials.broker`; here `credentials` is a list, so the block sits on the
credential it brokers). One call per mediated call, at the declared site and
only there:

| On the wire | From |
| --- | --- |
| `Authorization: Bearer $<token_env>` | the environment variable `token_env` names (registered as a brokered secret before the recorder opens, so it is never fingerprinted) |
| `X-Cresec-Tenant` | the identity JWT's `tenant_id`, else `broker.tenant` |
| `user_id` | the identity JWT's `sub`, else `$<user_env>` |
| `connector` | `credentials[].provider` |
| `tool` | the identity JWT's `tool` claim, else `broker.tool_id` / `tool_version` |
| `action_class` | the site's `action_class` (default `write`) |
| `target` | `{ host, path_template, method }`: the site's derived host (lowercase); its path template — the tool name for a `host: { fixed }` / `{ from: server }` site, the URL argument's path for a `host: { from_arg }` site, in both cases with **identifier segments replaced by `{id}`** (uuids, digit runs, long hex, long opaque tokens — ADR 015's rule, so a message or record id in a URL never reaches the control plane's `policy_decision` row; `cresec.credential.path_template` on the local event keeps the untemplated value); the site's `method` (upper-case) |
| `run_as` | the identity JWT's `run_as`, else `user` |
| `job_token` | `null` for a human session. For a **job token** (an identity JWT with `kind: job`, `run_as: owner` — `POST /v1/jobs/token`), the JWT itself, exactly as identity-jwt.md defines the job token; a job JWT whose raw form the recorder cannot send is a startup error (exit 2), never a `400` on every call |
| `run_id` | `null` (v1 of this leg sends none) |

The synthetic **never leaves this process** — it is what is swapped, not what
is sent — and is checked against the credential the site named, so a
placeholder issued for one credential cannot buy another credential's token.
The response is mapped the way the contract's "audit `RemoteBroker` mapping"
table says: a `200` swaps `token.access_token` at the site exactly as a local
source's value would be (the value is registered as a brokered secret first,
so no fingerprinting surface can hash it, and the reverse scrub replaces it
with the synthetic if the upstream reflects it); the response's `decision_id`
lands on the `tool_call` event as `cresec.broker.decision_id` and on the
`policy_decision` event's `decision_id` field when the call is refused. A
`403` is a **deny of the tool call with the control plane's `reason`**
(`grant_required`, `user_deactivated`, `no_connection`, …). A `503` whose
body says `vault_unavailable` or `connector_unavailable` is a deny with that
reason. Any other `5xx`, a timeout (`timeout_ms`, default 5 000 ms) or a
connection failure is a deny with reason **`control_plane_unavailable`** —
never a crash, never a hang, never a forward: the credential is absent
([ADR 013](https://github.com/cresec-ai/nhi/blob/main/docs/internal/adrs/013-degrade-mode.md):
invariant 1 wins over invariant 8; there is no read-only fallback in this
leg).

Every remote credential in one policy names the same control plane (same
`url` and `token_env`). Local and remote credentials mix freely: the swap
routes each declared site to the broker its credential named. The Rego
emitter (`policy compile`) ignores the `broker` block, `action_class` and
`method`: a remote credential compiles to exactly the module a local one
does, and the OPA parity test pins that.

Refusals at start, not at first call (exit 2): `token_env` unset; no user
(neither an identity JWT nor `user_env`); no tenant; no tool claim; a
`provider` that is not one of the control plane's connectors; a job JWT with
no raw token to send as `job_token`; two remote credentials naming different
control planes. The variables `token_env` and `identity_jwt_env` name are
registered as brokered secrets before the recorder opens, so neither the
internal token nor the identity JWT is ever fingerprinted.

**Which invariants this touches.** Invariant 1 (the tool holds no secret):
with a remote broker the per-user token is fetched per call and lives in this
process only for the reverse-scrub window; the agent's context, the transcript
and the chain hold the synthetic. It is still a context and audit control on
the agent's own machine — the process that fetches the token can read it —
so credential *absence* is the control plane's per-user injection, and this
leg is its client. Invariant 3: the control plane's `decision_id` is on the
record, and the record verifies offline as before.

### What the gateway does with all this

- **First match wins**, then **deny**. The section default is not settable:
  a use that is not declared is not authorised.
- **The decision cache is keyed on the whole tuple** — synthetic, method,
  host, path_template — for `ttl_seconds`. Keying it on the synthetic alone
  would turn one allow for `create_issue` into 30 seconds of allow for
  `delete_repo`.
- **Revocation is not instant.** A cached decision stays live for up to
  `ttl_seconds` (default 30), and revoking a synthetic does not recall a call
  already in flight. Quote the number, not the word.
- **Resolution is bounded and fail-closed.** A source that overruns
  `timeout_ms` denies *this* call rather than stalling the proxy thread the
  client is waiting on, and the failure path returns a denial — it never
  returns the request unmodified, because that would forward the synthetic.
- **The real value never enters the evidence chain.** Redaction refs are
  unsalted sha256 by design, so a ref of a brokered secret would be a
  brute-forceable copy of it. What is recorded is the credential id, the site
  id and the decision id. The same class of exclusion already exists for the
  recorder's own environment (`isRecorderOwnEnvVar` in `src/redact/redactor.ts`).

### Who may write this file

Anything that can write `policy.yaml` controls the swap: it can add a site
pointing at a host it controls, widen a host glob, or repoint a source — and
an `exec` source is arbitrary code execution by configuration, running as the
recorder, on every call. The file is also a map of where the real secrets on
this machine live.

So the loader records what the filesystem says about the file (owner and mode)
and lists the credentials that must not be resolved from it — the `exec` ones,
because a writable policy picks the *command* and not merely the value. That
is a fact about the machine rather than about the document, so `policy
validate` does not fail on it; the enforcing side (the broker, before it
resolves a source) is where it turns into a refusal. On a
single-uid developer machine that is **advisory** — the same caveat as the
documented `MCP_RECORDER_DISABLE=1` kill switch, but louder, because this file
does not merely switch enforcement off, it aims the credential. The property
to lean on is the chain: the policy's sha256 is stamped on every event, so a
mid-session edit is **evident** even where it cannot be prevented. Say
evident, not tamper-proof.

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
gets the glob as the REGEX this table translates it to — `regex.match`, not
`glob.match`; see "Compiling to Rego" below for why):

| Token | Meaning |
| --- | --- |
| `*` | any run of characters **not** containing the delimiter |
| `**` | any run of characters, delimiter included |
| `?` | **not supported in v1** — `policy validate` rejects any glob containing it |
| anything else | literal, case-sensitive |

Delimiters: `/` for `tool`, `server` and `path`; `.` for `host`. Patterns are
anchored (they must match the whole subject). `[ ] { } \` are rejected too:
OPA's glob library gives them a meaning this one does not.

`?` is out because it had two meanings when the bundle carried globs: OPA's
`glob.match` matches `?` against exactly one **ASCII** character, while the
local engine (a UTF-16 regex) matches any non-delimiter character — `a?b`
accepted `aéb` in the gateway and rejected it in OPA. The emitted bundle no
longer uses `glob.match`, so the split is gone with it, but v1 still rejects
`?` rather than quietly changing what an existing policy means. Use `*`.

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

  The assignment shapes are matched in three styles — the bare keyword
  (`password=`), an affix separated by `_`/`-` (`DB_PASSWORD=`, `X-Api-Key:`)
  and camelCase or PascalCase (`SecretAccessKey:`, `clientSecret:`), which is
  the style real tool output uses. The last two require the value to look
  like a credential (8+ characters with a digit, or 16+); the bare one takes
  any value, because a field whose whole name is `password` carries a
  credential whatever it looks like.

  That makes every style read SOURCE CODE as an assignment — the main thing
  an agent gets back from a filesystem server — so a match whose value is a
  placeholder (`${VAULT_SECRET}`, quoted or not), punctuation only, an
  expression (`decode(url.password)`, a template literal), or a one-word
  value ended by the syntax around it (`token: CommentOrToken):`,
  `Token = isClosingBraceToken;`) is dropped at the boundary.

  Two of those rules are the BARE style's alone, because only it has no
  value gate: a one-word value with NO trailing punctuation
  (`password = None`), and a keyword preceded by a `.`
  (`clean.password = ''`). Past a gate, an unterminated one-word value is a
  passphrase (`CLIENT_SECRET=supersecretpassphrase`) and a leading `.` is a
  key separator (`spring.datasource.password=`), so applying those two more
  widely subtracts credentials rather than false positives.

  The discriminator for the shared rule is that **a credential ends the
  field**: a passphrase stops at the passphrase, while a type name stops at
  the `)`, `;` or `,` of the code around it. Note that the affixed style's
  affix is optional, so its names are a superset of the bare style's — a
  rule the bare style drops is re-added by the affixed one for any value of
  16+ characters unless the shared rule covers it.

  The shapes that stay on the code side, stated rather than hidden: a
  punctuation-free value ending at its own closing bracket
  (`password=Tr0ub4dor(3)`, indistinguishable from
  `secret_key = loadFromEnvironment()` without a parser), and a letters-only
  credential with a trailing separator in a gated field
  (`DB_PASSWORD=supersecretpassphrase.`). Quoting changes nothing either
  way: the value's own delimiters are removed before the expression test, so
  `{"db":{"password":"Tr0ub4dor(3)andmore"}}` is redacted exactly as its
  unquoted twin is.

  None of this changes what is STORED. Storage redaction keeps the
  permissive patterns and hashes the value either way, so a credential the
  boundary let through is still not in the evidence store in clear.

  Measured, because this is the part that has moved most: over 1.08 million
  lines of installed third-party TypeScript the filter rewrites 692 lines,
  and `test/fixtures/third-party-source.txt` pins 138 of the at-risk ones in
  CI. This repository's own sources are deliberately NOT the measure — a
  change that corrupted 119 lines of real code showed zero regressions
  against them.
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
  not render cannot split a marker in two. That includes the SPACE
  intermediate (`CSI 2 SP q`, `ESC SP F`), which is what eight standard
  sequences use. Consuming a sequence also removes text a model reading the
  raw bytes still sees, so a second copy keeps exactly that — a string
  family's data, a bare escape's final byte, and any space a sequence
  swallowed — and the two span sets are unioned. In that copy a string
  family's HEADER is still dropped (`Pq` for DCS, `Ps ;` for OSC): it is
  digits and punctuation, it cannot carry a marker, and leaving it in put it
  between the two halves of one. Every marker found is mapped back onto the
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
├── .manifest                    {"revision": "<sha256 of policy.yaml>", "roots": ["cresec/mcp", ...]}
└── cresec/
    ├── mcp/tool.rego            package cresec.mcp
    ├── credentials/broker.rego  package cresec.credentials  (only if `credentials` is present)
    └── egress/http.rego         package cresec.egress       (only if `egress` is present)
```

`cresec/mcp/tool.rego` is always emitted (a policy without `mcp` compiles to
`default allow`, no rules); the other two modules — and their entries in
`roots` — only when the policy has that section. The files deliberately have
distinct basenames.

`cresec.credentials` is the one compiled module that is **also** enforced
locally: the gateway checks the same site list before it swaps anything, and
this module is the control plane's copy of that decision for the day the swap
is pointed at `/broker/exchange` instead. `egress`, by contrast, is compiled
and never enforced here. Its default is `deny` and is not author-settable, and
every swap site emits its `host_source` as a condition, so a request that
filled `host` with the server name cannot satisfy a site that declared a
checked destination.

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

// package cresec.credentials — input
{ "credential": "github-issues", "server": "corp-notes", "tool": "http_post",
  "host": "api.github.com", "host_source": "argument", "path_template": "http_post" }
// data.cresec.credentials.decision
{ "allow": true, "action": "allow", "rule_id": "github-issues/create-issue",
  "reason": "", "matched": true, "deny_reason": "" }

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
requires the decisions to agree, with `--strict-builtin-errors` so that a
pattern OPA cannot load fails the build instead of quietly dropping its rule
from the decision. Two consequences are visible in the emitted Rego:

- **A glob is emitted as the regex it translates to**, not as a glob to
  `glob.match`. OPA's glob library reads `A**B` as
  `HasPrefix(A) && HasSuffix(B)` with no requirement that the two not
  overlap, so a `deny` on `danger/` + a crossing wildcard + `/run` blocked
  the tool `danger/run` in the control plane and allowed it locally; an odd
  run of three or more `*` means "at least one character" there and "any
  run" here; and U+FFFD makes `glob.match` raise `could not read rune`,
  which is `undefined` in Rego and drops the rule. One translation, shared
  by both engines, removes the class.
- **An args lookup is a reference chain** (`input.args.filters[0].field`)
  behind an explicit `is_object(input.args)`, not
  `object.get(input.args, [...], null)`. `object.get` ERRORS on a non-object
  root, and an erroring builtin is `undefined` — so the agreement about a
  malformed `params.arguments` rested on a silent failure rather than on
  either engine saying anything.

## Evidence

Gateway decisions are part of the tamper-evident chain, under the frozen
`edut.mcp-recorder.event.v1` schema (additive fields only):

- `session_start.policy` — `{ hash, name }` of the policy in force.
- `tool_call.gateway` — `{ decision, rule_id, outcome, approval_id, boundary }` on every tool call.
- `policy_decision` events — one per deny and one per hold outcome, with
  `policy_hash`, `args_hash`, `approval_id`, `waited_ms`, `approver` and
  `decision_id` (the local engine's uuid, or the control plane's when a
  remote broker decided).

See [docs/event-schema.md](event-schema.md) for the exact fields.

## Limitations (v1)

- Gateway mode is available for both transports: `record --policy` (stdio)
  and `http --policy` (streamable HTTP; `MCP_RECORDER_POLICY` applies to both
  when the flag is absent). Over HTTP a `tools/call` request body and its
  result are **buffered** — a JSON body whole, an SSE stream one event at a
  time — so they can be evaluated and filtered; that is the gateway-mode
  exception AGENTS.md allows, and without `--policy` the HTTP proxy streams
  every byte as before. A JSON-RPC batch carrying a refused `tools/call` is
  answered locally as a whole (each refused call gets its deny result, every
  other element a `-32600` asking to be resent on its own). A compressed
  upstream response is refused (`502`) because the boundary filter cannot
  read it; the gateway sends `accept-encoding: identity` so a compliant
  upstream never compresses.
- A policy without an `mcp` section is valid, and `policy validate` exits 0
  (with a warning), but `record --policy` and `setup --policy` refuse it with
  exit 2 — the gateway would have nothing to enforce. That applies to a
  `credentials`-only policy too: pair the section with an `mcp` section.
- `credentials[].use[].action` is `allow` or `deny`; **`hold` is not available
  in v1**. Holding a credential call means resolving the secret only after a
  human answers — otherwise a real token sits in memory across an abandoned
  hold — and v1 has no code that does that, so the file cannot ask for it.
- A `credentials` site whose `host` is `{ fixed: ... }` or `{ from: server }`
  constrains the *tool*, not the *destination*. Only `{ from_arg: ..., allow:
  [...] }` checks where the credential actually goes.
- `egress` rules are validated and compiled but not enforced by
  `mcp-recorder`.
- Denied tools are not hidden from `tools/list`; the model may still attempt
  them and receive the deny result.
- Hold approvals are local trust (anyone who can write the data directory).
- Injection detection is pattern-based and conservative by design; it is a
  tripwire plus evidence, not a classifier.
