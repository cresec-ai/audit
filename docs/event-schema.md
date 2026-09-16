# Event schema — `edut.mcp-recorder.event.v1`

This document is the normative description of the wire/storage format produced by
`@edut/mcp-recorder`. The TypeScript source of truth is
[`src/schema/events.ts`](../src/schema/events.ts); this document transcribes it for
readers who verify or consume bundles without reading TypeScript.

## Freeze policy

The schema id is `edut.mcp-recorder.event.v1`. Every field shipped under this id is
**frozen**:

- Changes are **additive only** — new optional fields or new event kinds may be added.
- Existing fields are never renamed, retyped, or removed.
- Any breaking change requires a **new schema id** (`...event.v2`); v1 records remain
  verifiable forever, because chain hashes are computed over the canonical JSON of the
  event exactly as recorded.

## Privacy posture

Payloads never land in the store readable. String values are replaced at the edge by
**redacted refs** — a SHA-256 of the exact value plus its length. Hashes are
**deliberately unsalted** so a blast-radius query can match a known probe value by
hashing it the same way. See the tradeoff discussion in the
[README security model](../README.md#security-model-the-honest-version).

**The allowlist is position- and value-aware, not just key-aware.** A string only
survives un-hashed when BOTH hold: its key is one of a small fixed set (`type`,
`role`, `level`, `mimeType`, `protocolVersion`, `method`, `name`), AND its value
belongs to that key's structural vocabulary — an MCP content-block `type`
(`text`/`image`/`audio`/`resource`/`resource_link`), a `role` of `user`/`assistant`, a
logging `level`, a `mimeType` matching `^[\w.+-]+/[\w.+-]+$`, a `protocolVersion`
matching `^\d{4}-\d{2}-\d{2}$`, a `method` matching `^[a-z]+(/[a-zA-Z_]+)*$`, or a
`name` that is specifically `tools[*].name` / `prompts[*].name` inside a list result
(matching `^[\w.-]{1,64}$`) — never a bare top-level `name`, and never one hop deeper
(`tools[*].inputSchema.name` does not qualify). Every other string, under every other
key or position, is hashed. `code`, `status`, `kind` and `tool` were removed from the
allowlist entirely: no safe structural vocabulary exists for them, so they always hash.

**Under a `tool_call`'s `args` NOTHING passes, in any redaction mode.** Arguments are
the most attacker/user-controlled data the proxy ever sees, so every string leaf there
is hashed unconditionally — the vocabulary above only ever applies elsewhere (e.g.
`tool_call.result`, `rpc.params`, `notification.params`).

**Object keys are redacted too, not just values.** A key survives as-is only if it
matches `^[A-Za-z_$][\w$-]{0,63}$` (a plain identifier, hyphens allowed) AND does not
itself look secret-shaped (the same `alwaysPatterns` used for values, checked in every
redaction mode); otherwise the key is replaced by `sha256:<hex>` of the original key
text — still a plain JSON string, so no schema change. This closes two gaps: a map
keyed by email/username/file-path/header-line no longer lands in clear, and hashing the
key (rather than dropping it) means `query` can still find a needle that was only ever
used as a key. A literal `__proto__` key is preserved as a genuine own property (the
scrubbed tree is built without going through a normal object's prototype setter), never
silently dropped.

**Verbatim protocol strings copied off the wire are capped too (P0).** A handful of
fields are stamped onto events directly from the MCP handshake / JSON-RPC envelope
rather than through a `scrub()`-walked tree — they stay plain top-level strings by
schema, so `scrub()`'s length/vocabulary gates never applied to them:
`ToolCallEvent.tool` (and the `gen_ai.tool.name` attribute), `RpcEvent`/
`NotificationEvent.method` (and the `mcp.method.name` attribute), and the
`initialize` handshake's `protocol_version`/`client_name`/`client_version`/
`server_name`/`server_version` — plus the `client_name`/`client_version` remembered on
`IdentityContext` and the `name`/`version` learned onto `ServerContext`, both reused on
every event recorded after the handshake. A misbehaving or malicious peer could
otherwise stuff kilobytes of arbitrary text — including payload it wants to smuggle
past redaction — into every event through any one of these. `structuralString()`
(`src/redact/redactor.ts`) closes this: a value survives AS-IS only when it is at most
128 characters **and** matches a conservative shape for its kind —

| Kind | Applies to | Shape |
| --- | --- | --- |
| `identifier` | tool name, JSON-RPC method, clientInfo/serverInfo `name` | `^[A-Za-z0-9_.:/-]+$` |
| `version` | clientInfo/serverInfo `version` | `^[A-Za-z0-9_.+-]+$` |
| `protocol_version` | negotiated `protocolVersion` | `^\d{4}-\d{2}-\d{2}$` |

— otherwise the value is replaced by its `sha256:<hex>` reference, computed the exact
same way as any other redacted value (`sha256Ref`/`Redactor.hashString`), so a
blast-radius `query` for the original value still finds it. The field itself stays a
plain `string` either way — never a `RedactedRef` object — so this is not a schema
change. Each value is capped ONCE, at the point it is first read off the wire (a
request's own `method`/`params.name`, or the `initialize` handshake's
`clientInfo`/`serverInfo`); every later use of that same value — the identity/server
context stamped on every subsequent event, and the synthetic `unanswered` events sealed
at shutdown (see [`session_end`](#session_end) below) — reuses the already-capped value,
so nothing downstream needs its own cap.

Note the asymmetry on `ServerContext.name`: it is `--name` (operator-supplied, never
capped) else the serverInfo name **learned from the handshake** (capped) else a locally
derived basename of the wrapped command (not peer-controlled, not capped either).

---

## Common types

### `Sha256Ref`

A string of the form `sha256:<64 lowercase hex>`.

### `RedactedRef`

A redacted leaf value. The original never leaves the machine readable.

| Field | Type | Description |
| --- | --- | --- |
| `redacted` | `true` | Discriminator; always literally `true`. |
| `ref` | `Sha256Ref` | `sha256:<hex>` of the exact UTF-8 encoding of the original string. |
| `len` | `number` | Length of the original string in UTF-16 code units. |
| `secret_refs` | `Sha256Ref[]?` | Optional, additive (v1). Hashes of secret-shaped tokens (`alwaysPatterns` matches) found **embedded inside** this leaf — e.g. the AWS key inside `"AWS_ACCESS_KEY_ID=AKIA...\n"`. De-duplicated, capped at 8, and never includes a hash equal to `ref` itself. This exists because `query` otherwise only matches a *whole* leaf: a credential glued into a longer string (a log line, an exfiltrated file's contents, a sentence) would hash as one opaque blob and never surface. **A miss against `secret_refs` is not proof a value never appeared here** — only tokens shaped like a known `alwaysPatterns` entry are captured this way; a value that isn't secret-shaped on its own (and isn't under an allow-listed key/position) is still hashed as part of the whole leaf, but no per-token record of it exists. |

### `Scrubbed`

A JSON tree after edge redaction: structure preserved, sensitive leaves replaced.
Recursively: `string | number | boolean | null | RedactedRef | Scrubbed[] |
{ [key: string]: Scrubbed }`.

### `CredentialFingerprint`

Hash of a credential value handed to the wrapped server — never the value.

| Field | Type | Description |
| --- | --- | --- |
| `name` | `string` | Where it came from, e.g. the env var name `GITHUB_TOKEN`. |
| `ref` | `Sha256Ref` | `sha256:<hex>` of the credential value. |

### `IdentityContext`

Identity context stamped on **every** event ("identity-stamp everything").

| Field | Type | Description |
| --- | --- | --- |
| `fingerprint` | `Sha256Ref` | Stable identity hash for the acting agent/credential pair: sha256 over (os_user, hostname, label, initial server name) — the context known at proxy startup, before the MCP `initialize` handshake. `client_name`/`client_version` are learned later from that handshake and are **not** part of the fingerprint. |
| `os_user` | `string?` | OS user running the proxy. |
| `hostname` | `string?` | Host the proxy ran on. |
| `client_name` | `string?` | From the MCP `initialize` handshake clientInfo, once seen. Capped (`structuralString`, kind `identifier`) — see [above](#privacy-posture). |
| `client_version` | `string?` | From the MCP `initialize` handshake clientInfo, once seen. Capped (`structuralString`, kind `version`) — see [above](#privacy-posture). |
| `label` | `string?` | Operator-supplied label (`--identity`). |
| `credential_fingerprints` | `CredentialFingerprint[]?` | Hashes of secret-looking env values passed to the wrapped server. |

### `ServerContext`

| Field | Type | Description |
| --- | --- | --- |
| `name` | `string` | Logical server name (`--name` flag, else derived from command/initialize). The initialize-learned component is capped (`structuralString`, kind `identifier`) — see [above](#privacy-posture); an operator-supplied `--name` is not. |
| `version` | `string?` | From the MCP `initialize` result serverInfo, once seen. Capped (`structuralString`, kind `version`) — see [above](#privacy-posture). |
| `command` | `string` | stdio transport: the wrapped command line (argv, scrubbed and re-joined with spaces). http transport: the target URL, scrubbed (see below). env values never included either way. |
| `transport` | `'stdio' \| 'http'` | Transport the proxy bridged. |
| `url` | `string?` | Additive, optional (schema stays v1); hook-sourced, on `tool_call` events only. Where the server named by `name` is, **as asserted by the MCP config file `mcp-recorder hook` found** (`MCP_RECORDER_MCP_CONFIG`, else `/tmp/mcp-config-*.json` in a cloud session) — not observed on the wire; that file is writable by the agent running under the hook, see [docs/hooks.md](hooks.md#cloud-sessions-uuid-server-names-and-serverurl). The value is the vendor endpoint behind an Anthropic-hosted connector's relay (the relay URL's decoded `mcp_url`, e.g. `https://mcp.clickup.com/mcp`), else the config entry's own URL. Scrubbed like the http transport's target URL below — userinfo stripped, query string and fragment dropped — but the stripped pieces are dropped **without** `credential_fingerprints` (the hook never sends them), and more strictly on the path: every segment that is secret-shaped, **an opaque identifier** (a UUID, a cloud session id such as `cse_...`) **or not a short vocabulary token** (`[A-Za-z0-9._-]{1,32}`) is replaced in place by its `sha256:<hex>` ref, so a relay URL never carries the session id and no free text from the file reaches the store. A scrubbed URL over 2048 characters is not recorded at all. Undefined when unresolved, on session-level hook events (`session_start`/`session_end`/the Stop notification, whose `name` is the client), and on every proxy-captured event (the http proxy records its target in `command`). See [Hook-sourced events](#hook-sourced-events-additive). |

**`command` argv handling (stdio transport).** A raw `argv.join(' ')` would leak
`--api-key sk-...`, `--token ...`, and connection strings like `postgres://user:pass@host`
straight into every event, the replay HTML, and export bundles. Each argv element is
scrubbed before joining:

- an element that looks secret-shaped (`looksSecret` / `alwaysPatterns`) is replaced
  whole by `sha256:<hex>`;
- a URL carrying userinfo (`scheme://user:pass@host/path`) has the userinfo stripped —
  only `scheme://host/path` is kept, dropping the credential and any query/fragment;
- an element that is (or immediately follows) a flag whose name matches
  `/(TOKEN|SECRET|PASSW|API[_-]?KEY|CREDENTIAL|AUTH)/i` — both `--token X` and
  `--token=X` — is replaced whole by `sha256:<hex>`;
- a `--flag=value` pair whose FLAG name does **not** match that credential-name pattern
  still has its VALUE half scrubbed on its own (looks-secret check, then the
  URL-userinfo check) before being re-joined as `--flag=<scrubbed-value>` — this covers
  DSN/URL-shaped flags a fixed name list can't anticipate, e.g. `--dsn=postgres://u:p@h`
  or `--database-url=mysql://u:p@h/db`.

Every replaced or stripped piece is also recorded as a `CredentialFingerprint` on
`identity.credential_fingerprints` (`name` is the flag name when one applied, else
`argv[<index>]`), so a blast-radius `query` for the leaked value still finds the event
that carried it, even though `command` itself no longer contains it. When a piece is a
URL's `user:pass` userinfo, the joined string is fingerprinted AND (additive) the
password and username are each fingerprinted separately, so a query for the leaked
password alone — without knowing the username — still matches.

**`command` target-URL handling (http transport).** The `--target` URL can carry a
credential in three different places, not just userinfo, so all three are scrubbed
independently before the URL is recorded:

- userinfo (`http://user:pass@host/...`) is stripped from the recorded URL;
- each PATH segment that looks secret-shaped (`looksSecret`) — the shape hosted-MCP
  endpoints use, e.g. `https://host/mcp/sk-.../sse` — is replaced in place by
  `sha256:<hex>`, leaving the rest of the path intact;
- the entire QUERY STRING and fragment are dropped from the recorded URL
  unconditionally (e.g. `?api_key=...`, `?token=...`) — there is no safe subset of a
  query string to keep once any single parameter can be a bearer credential.

The real upstream connection still uses the original, unscrubbed target URL; only the
copy stamped on events is affected. Every stripped/replaced piece (userinfo — joined
and, additively, user/password separately — each secret-shaped path segment, each
secret-shaped query value) is recorded as a `CredentialFingerprint` on
`identity.credential_fingerprints`, named `target_url_userinfo`, `target_url_path[<i>]`,
or `target_url_query.<key>` respectively.

### `Attributes`

An OTel-style flat attribute bag: `Record<string, string | number | boolean>`. Keys use
OpenTelemetry semantic-convention names where one exists — see the
[mapping table](#opentelemetry-semantic-convention-mapping) below.

---

## Event envelope (`EventBase`)

Every event carries these fields:

| Field | Type | Description |
| --- | --- | --- |
| `schema` | `'edut.mcp-recorder.event.v1'` | Frozen schema id. |
| `event_id` | `string` | UUID v4, unique per event. |
| `session_id` | `string` | UUID v4, one per proxy process lifetime. |
| `timestamp` | `string` | ISO-8601 UTC with milliseconds. |
| `kind` | `EventKind` | One of the seven kinds below. |
| `identity` | `IdentityContext` | Who acted. |
| `server` | `ServerContext` | What was wrapped. |
| `attributes` | `Attributes` | Flat semconv-named attribute bag. |
| `source` | `'hook'?` | Additive, optional (schema stays v1). Set to `'hook'` when this event was captured by `mcp-recorder hook` (a Claude Code PreToolUse/PostToolUse/PostToolUseFailure/SessionEnd/Stop hook) rather than the stdio/http proxy tap. Undefined on every proxy-captured event. See [Hook-sourced events](#hook-sourced-events-additive) below. |

`EventKind` is one of: `session_start`, `initialize`, `tool_call`, `rpc`,
`notification`, `protocol_error`, `session_end`, and — additive, recorded only in
[gateway mode](#gateway-mode-fields-additive) — `policy_decision`.

## Event kinds

### `session_start`

Proxy process started; carries the redaction policy in force.

| Field | Type | Description |
| --- | --- | --- |
| `proxy_version` | `string` | Version of `@edut/mcp-recorder`. |
| `cwd` | `string` | Working directory of the proxy process. |
| `redaction_mode` | `'allowlist' \| 'off'` | Redaction policy in force for the session. |
| `policy` | `{ hash: Sha256Ref; name?: string }?` | Additive (v1). Present only in gateway mode: `hash` is the SHA-256 of the exact bytes of the `policy.yaml` in force, `name` its `name` field (capped, `structuralString` kind `identifier`). See [Gateway mode fields](#gateway-mode-fields-additive). |

### `initialize`

The MCP initialize handshake (request + response correlated).

| Field | Type | Description |
| --- | --- | --- |
| `request_id` | `string \| number` | JSON-RPC request id. |
| `protocol_version` | `string?` | Negotiated MCP protocol version. Capped (`structuralString`, kind `protocol_version`) — see [above](#privacy-posture). |
| `client_name` | `string?` | From clientInfo. Capped (`structuralString`, kind `identifier`) — see [above](#privacy-posture). |
| `client_version` | `string?` | From clientInfo. Capped (`structuralString`, kind `version`) — see [above](#privacy-posture). |
| `server_name` | `string?` | From serverInfo. Capped (`structuralString`, kind `identifier`) — see [above](#privacy-posture). |
| `server_version` | `string?` | From serverInfo. Capped (`structuralString`, kind `version`) — see [above](#privacy-posture). |
| `duration_ms` | `number` | Wall-clock ms between request and response crossing the proxy. |

### `tool_call`

A completed `tools/call` (request + response correlated). The flagship event.

| Field | Type | Description |
| --- | --- | --- |
| `tool` | `string` | Tool name (`gen_ai.tool.name`). Capped (`structuralString`, kind `identifier`) — see [above](#privacy-posture); an oversized or oddly-shaped name is stored as its `sha256:<hex>` reference instead. |
| `request_id` | `string \| number` | JSON-RPC request id (`gen_ai.tool.call.id`). |
| `args` | `Scrubbed` | Redacted argument tree. **Every string leaf is hashed, unconditionally, regardless of key or position or redaction mode** — see [Privacy posture](#privacy-posture). |
| `result_hash` | `Sha256Ref` | `sha256:<hex>` of canonical JSON of the **complete raw result, pre-redaction**. |
| `result_hash_depth_capped` | `true?` | Additive, optional (schema stays v1). Present only when the result was nested deeper than the hash depth cap (256). `result_hash` is then **not** `sha256Ref(canonicalJson(result))`: every subtree below that depth hashed as one fixed marker, so two results differing only below it share a hash. The cap is what keeps a hostile payload from overflowing the stack; this field is what stops it being silent. |
| `result` | `Scrubbed` | Redacted result tree (the position/value-aware allowlist applies here, unlike `args`). |
| `is_error` | `boolean` | Whether the call returned an error. |
| `error` | `{ code?: number; type?: string; message_ref?: Sha256Ref }?` | Error details; the message is stored only as a hash ref. `error.type` is a free-form string field. Gateway mode records `'policy_denied'` for a call it refused (see [Gateway mode fields](#gateway-mode-fields-additive)) and `'duplicate_id'` for a call refused because its JSON-RPC request id was still in flight (held for approval, or pending). `mcp-recorder hook` records the additive values `'policy_denied'` (a `--policy` deny), `'tool_error'` (the call failed: a PostToolUseFailure) and `'interrupted'` (a PostToolUseFailure with `is_interrupt`) — see [Hook-sourced events](#hook-sourced-events-additive). |
| `duration_ms` | `number` | Wall-clock ms between request and response crossing the proxy. |
| `gateway` | `GatewayOutcome?` | Additive (v1). Present on every `tool_call` recorded in gateway mode — see [Gateway mode fields](#gateway-mode-fields-additive). |
| `phase` | `'pre' \| 'post'?` | Additive, optional (schema stays v1). `mcp-recorder hook` records a tool call as two separate correlated events sharing `request_id` (a PreToolUse event, before the tool runs, and a PostToolUse or PostToolUseFailure event, after) — this says which half. Undefined for proxy-captured `tool_call` events, which are already request+response correlated into one event. See [Hook-sourced events](#hook-sourced-events-additive). |

### `rpc`

Any other correlated JSON-RPC request/response (`tools/list`, `resources/read`, ...).

| Field | Type | Description |
| --- | --- | --- |
| `method` | `string` | JSON-RPC method (`mcp.method.name`). Capped (`structuralString`, kind `identifier`) — see [above](#privacy-posture); an oversized or oddly-shaped method is stored as its `sha256:<hex>` reference instead. |
| `request_id` | `string \| number` | JSON-RPC request id. |
| `params` | `Scrubbed` | Redacted params tree. |
| `result_hash` | `Sha256Ref` | `sha256:<hex>` of canonical JSON of the complete raw result, pre-redaction. |
| `result_hash_depth_capped` | `true?` | Additive, optional (schema stays v1). Same meaning as on `tool_call`. |
| `is_error` | `boolean` | Whether the call returned an error. |
| `error` | `{ code?: number; type?: string; message_ref?: Sha256Ref }?` | Error details; message hashed. |
| `duration_ms` | `number` | Wall-clock ms between request and response. |

### `notification`

One-way JSON-RPC notification in either direction.

| Field | Type | Description |
| --- | --- | --- |
| `method` | `string` | JSON-RPC method (`mcp.method.name`). Capped (`structuralString`, kind `identifier`) — see [above](#privacy-posture); an oversized or oddly-shaped method is stored as its `sha256:<hex>` reference instead. |
| `direction` | `'client_to_server' \| 'server_to_client'` | Which way it flowed. |
| `params` | `Scrubbed` | Redacted params tree. |
| `gateway` | `GatewayOutcome?` | Additive (v1), gateway mode only. Present on the two `tools/call` shapes the gateway refuses that have no usable request id: a **notification** the policy denied, and a request whose `id` is not a `string` or a `number` (`refusal: 'invalid_request_id'`). Neither can be a `policy_decision` event, because `request_id` is `string \| number` and neither message has a value that fits it. Without this field a refusal left nothing but a line on stderr: the chain held an ordinary `notification` event, indistinguishable from a forwarded one. `mcp-recorder sessions` counts it in `policy_decision_count`. |

### `protocol_error`

Traffic the tap could not interpret.

In **record mode** forwarding is unaffected (fail-open): the bytes cross
byte-for-byte and the event is the only trace. In **gateway mode** a client
line the policy could not be shown is REFUSED — the client is answered
`-32600` and nothing reaches the server — and takes this same event, because
it has no method to record a `notification` against and no id to record
anything else against. That covers an oversized line, a line that is not
JSON, and a nested array inside a JSON-RPC batch. So in gateway mode this
kind is also part of the enforcement record, and `line_hash` is what
identifies the artifact that was refused.

| Field | Type | Description |
| --- | --- | --- |
| `direction` | `'client_to_server' \| 'server_to_client'` | Which way the bytes flowed. |
| `reason` | `'unparseable' \| 'oversized' \| 'orphan_response'` | Why the tap could not record it normally. |
| `bytes_len` | `number` | Length of the raw line in bytes. |
| `line_hash` | `Sha256Ref` | `sha256:<hex>` of the raw line, so the artifact is still identifiable. |

### `session_end`

Proxy shutting down (child exit, stdin close, or signal).

| Field | Type | Description |
| --- | --- | --- |
| `reason` | `'child_exit' \| 'stdin_closed' \| 'signal' \| 'error'` | Why the session ended. |
| `child_exit_code` | `number \| null?` | Exit code of the wrapped server, when known. |
| `events_recorded` | `number` | Events successfully written this session. |
| `events_dropped` | `number` | Events lost to fail-open recording (store failure, backpressure). |
| `spawn_error` | `string?` | errno code (e.g. `ENOENT`, `EACCES`) when the wrapped command could not be spawned at all (`reason: 'error'`). The proxy's own exit code is mapped from this: `ENOENT` → 127, `EACCES` → 126, anything else → 1. |
| `child_signal` | `string?` | Signal name (e.g. `SIGKILL`) when the wrapped process was terminated by a signal. The proxy's own exit code is `128 + <signal number>` in that case. |

Before `session_end` is recorded, any request still awaiting a response when the
session ends (the wrapped server crashed or was killed mid-call, or the client
disconnected mid-handshake) is flushed as one synthetic event per pending
request, so the chain never silently drops in-flight work: a `tools/call`
becomes a `tool_call` event, everything else (including an unanswered
`initialize`) becomes an `rpc` event. Both are marked `is_error: true`,
`error: { type: 'unanswered' }`, `result_hash` is the hash of canonical `null`
(a `tool_call` also sets `result: null`), and `duration_ms` is measured from
the request crossing the proxy to session shutdown. `error.type` is an
existing free-form string field, so this needed no schema change. The synthetic
event's `tool`/`method` is whatever was captured for the pending request — already
capped (`structuralString`, see [Privacy posture](#privacy-posture)) at the point the
request was first seen, so an unanswered call with an oversized/malformed name or
method is just as capped here as in a normal completed event. The same
synthetic shape is reused with `error.type: 'duplicate_id'` when gateway mode
seals a pending request whose id an approved hold reclaims — identical
`result_hash` / `result: null` / `is_error: true`, only the error class differs.

## Gateway mode fields (additive)

[Gateway mode](gateway.md) (`record --policy policy.yaml`) enforces a
[`policy.yaml`](policy.md) on `tools/call` traffic. Everything it records is
**additive under v1**: one new event kind and two optional fields. Records
written in record mode never carry any of them, and old records verify
exactly as before (canonical JSON drops nothing that was never there).

### `GatewayOutcome` (the `tool_call.gateway` field)

| Field | Type | Description |
| --- | --- | --- |
| `decision` | `'allow' \| 'deny' \| 'hold'` | What the policy decided for the request. |
| `rule_id` | `string?` | The rule that matched; absent when the section's `default` applied. An explicit id already matches the `structuralString` identifier shape and is kept as-is, and so is an auto-assigned `rule[<index>]`; only an off-shape id would be stored as its `sha256:<hex>` reference. |
| `refusal` | `string?` | Additive (v1). Present when the gateway refused the MESSAGE rather than evaluating it against the policy, so a `deny` with no `rule_id` is not misread as the section default having applied. An identifier naming the refusal, the way `error.type` names an error class; `invalid_request_id` — a `tools/call` whose `id` property is not a usable JSON-RPC id — is the only value the proxy writes today. |
| `outcome` | `'approved' \| 'denied' \| 'timeout' \| 'cancelled' \| 'session_end'?` | Holds only: how the hold was resolved (`session_end` = the proxy shut down while the call was still held). |
| `approval_id` | `string?` | Holds only. Absent when the call was refused before a hold file existed (see `policy_decision`). |
| `waited_ms` | `number?` | Holds only: how long the call was parked before it was resolved. |
| `boundary` | `BoundaryReport?` | Present when the result went through the tool-result boundary filter: every `allow`ed and `approved` call whose server answered, including answers delivered inside a JSON-RPC batch array. |

### `BoundaryReport`

| Field | Type | Description |
| --- | --- | --- |
| `scanned` | `boolean` | `false` when the result exceeded `boundary.max_scan_bytes` or the filter hit an internal error. |
| `action` | `'none' \| 'redact' \| 'block' \| 'flag'` | What was applied to the result the client received. |
| `secrets_found` | `number` | Secret-shaped spans found. The boundary filter runs a **narrowed** subset of `alwaysPatterns` — provider-prefixed tokens, JWTs, PEM private keys, bearer values and `secret=`-style assignments — excluding the generic long-hex and long-base64 shapes so ordinary output (git SHAs, checksums, inline images) is never rewritten. `secret_refs` on stored `RedactedRef` leaves keeps the full, wider `alwaysPatterns` meaning. |
| `injection_found` | `number` | Prompt-injection marker spans found. |
| `secret_refs` | `Sha256Ref[]?` | Hashes of the secret tokens found (de-duplicated, capped at 8) — the model may never have seen the values, `query` still finds the call. |
| `delivered_result_hash` | `Sha256Ref?` | Present only when the filter modified the result: `sha256:<hex>` of the canonical JSON of the result **the client actually received**. `result_hash`/`result` keep their frozen meaning — the complete raw result the server returned, pre-redaction and pre-filter. |
| `error` | `string?` | Internal-error class when `scanned` is `false` for a reason other than size. |

### `policy_decision`

An enforcement action taken by the gateway: one per **deny**, and one per
**hold outcome**. Allowed calls do not produce this event (their `tool_call`
carries `gateway.decision: 'allow'`), so the kind is a complete list of
everything the gateway ever refused or paused.

`mcp-recorder sessions` reports how many of these a session has: the
`DECISIONS` column, `policy_decision_count` in `--json` (an additive key both
store backends always set). It counts these **events**, so an approved hold
counts exactly like a deny — the gateway ruled on the call either way — and a
session recorded without a policy reads `0`. The synthetic `tool_call` that
carries a refusal back to the client is counted under `TOOL_CALLS` and
`ERRORS` like any other failed call, never a second time here.

It also counts the decisions that cannot BE a `policy_decision` event,
because `request_id` is `string | number` and these messages have no usable
id to write one with. Their outcome rides the additive `gateway` field on
the `notification` event each is recorded as:

- a refused `tools/call` **notification** (no `id` property at all), and
- a `tools/call` whose `id` is not a usable JSON-RPC id — `null`, but
  equally `true`, `{}` or `[]` — which is refused with a JSON-RPC `-32600`
  whatever the policy says, and carries `refusal: 'invalid_request_id'` so
  the absent `rule_id` is not read as a default deny.

Neither is ever forwarded to the server, and without the `gateway` field
neither left anything in the chain but a line on stderr.

| Field | Type | Description |
| --- | --- | --- |
| `decision` | `'deny' \| 'hold'` | The action the policy selected. |
| `outcome` | `'approved' \| 'denied' \| 'timeout' \| 'cancelled' \| 'session_end'?` | Holds only. `session_end` means the proxy shut down while the call was still held. |
| `tool` | `string` | Tool name (`gen_ai.tool.name`). Capped exactly like `tool_call.tool`. |
| `request_id` | `string \| number` | JSON-RPC request id of the call. |
| `rule_id` | `string?` | Matching rule id (capped identifier); absent when `mcp.default` applied. |
| `policy_hash` | `Sha256Ref` | SHA-256 of the exact bytes of the policy file in force. |
| `args_hash` | `Sha256Ref` | `sha256:<hex>` of the canonical JSON of the raw `params.arguments` — never the arguments themselves. |
| `approval_id` | `string?` | Holds only: the UUID the operator saw in `mcp-recorder holds`. Absent when the call was refused before a hold file ever existed — a hold-matching `tools/call` that arrives while the proxy is already shutting down is recorded as `outcome: 'session_end'` with no approval id. |
| `waited_ms` | `number?` | Holds only: how long the call was parked. |
| `approver` | `string?` | Holds only: the OS user that ran `mcp-recorder approve`/`deny`, when the hold file recorded one **as a string**. Capped exactly like any identifier copied off the wire (`structuralString`): a value longer than 128 characters or outside the identifier shape is stored as its `sha256:<hex>` reference, and a non-string `decided_by` is ignored entirely. |

Attributes on a `policy_decision`: `gen_ai.tool.name`, `gen_ai.tool.call.id`,
`mcp.method.name`, `rpc.system`, `cresec.policy.decision`, and
`cresec.policy.rule_id` when a rule matched. A `tool_call` recorded in gateway
mode carries the same two `cresec.policy.*` attributes next to its usual ones.
A call the gateway refused has `duration_ms: 0` (it never reached the server);
`waited_ms` carries the hold time, and for a hold that was approved
`duration_ms` measures from the moment the request was forwarded.

---

## Hook-sourced events (additive)

`mcp-recorder hook` (see [docs/hooks.md](hooks.md)) turns Claude Code
PreToolUse/PostToolUse/PostToolUseFailure/SessionEnd/Stop hook invocations into events using
the exact same `session_start` / `tool_call` / `session_end` / `notification`
shapes above — no new event kind was needed. `Stop` (the end of an agent
turn, which fires many times per session) becomes a `notification` event
with `method: 'claude-code/stop'` and `direction: 'client_to_server'`, so
that a session still has exactly one `session_end` (from `SessionEnd`). Four additive, optional fields distinguish a
hook-sourced event and its finer shape, none of which change any existing
field:

- **`EventBase.source: 'hook'`** — set on every event `mcp-recorder hook`
  emits; undefined on every proxy-captured event.
- **`ToolCallEvent.phase: 'pre' | 'post'`** — a hook-sourced tool call is two
  separate, separately-timestamped events (one per hook invocation) sharing
  one `request_id` (Claude Code's own `tool_use_id`), rather than the single
  request+response-correlated event the proxy records. `'pre'` carries
  redacted arguments with `result: null` and `duration_ms: 0`; `'post'`
  carries the redacted result and the measured `duration_ms` (for a
  PostToolUseFailure: `result: null`, `result_hash` of canonical `null`,
  `is_error: true` and `error` as below — Claude Code fires exactly one of
  PostToolUse / PostToolUseFailure per call). A hook `'post'` event's
  `duration_ms` is the gap between the two hook invocations (Claude Code's
  dispatch plus hook process spawn, about a second per call in cloud
  dogfood 3), not the MCP server's latency the proxy measures — see
  [docs/hooks.md](hooks.md#what-gets-recorded).
- **`ToolCallEvent.error.type: 'policy_denied' | 'tool_error' | 'interrupted'`**
  — additive values under the already free-form `error.type` string field
  (no schema change; the same string is also set as the `error.type`
  attribute). `'policy_denied'`: `mcp-recorder hook --policy FILE` denied
  the PreToolUse call; `error.message_ref` is the hash of the policy rule's
  `reason`. `'tool_error'`: the call failed (Claude Code fired
  PostToolUseFailure instead of PostToolUse); `error.message_ref` is the
  hash of the hook's `error` string, computed exactly like any redacted
  value (`Redactor.hashString`, i.e. `sha256Ref`) — the text itself is
  never stored. `'interrupted'`: the same, but the hook's `is_interrupt`
  was true (the call was aborted rather than reporting an error). A
  PostToolUse event whose `tool_response` is shaped `{isError: true}` (the
  MCP CallToolResult convention) sets `is_error: true` and the
  `'tool_error'` *attribute* only, with no `error` object.
- **`ServerContext.url`** — the endpoint of the MCP server a hook-sourced
  `tool_call` went to, as the MCP config file the hook found asserts it
  (see the `ServerContext` table above for the value, its scrubbing and
  its trust), set on both halves of the call and on nothing else: a
  session-level event names the client itself, so it carries no vendor
  URL. `server.name` itself is always what Claude Code calls the server —
  in a cloud session an opaque UUID like
  `47d587b8-3fb9-42e9-b596-f8b25371248c` (cloud dogfood 3, surprise 2) —
  so that it matches Claude Code's own hook matchers and transcripts;
  `url` is what makes such an event self-describing. Absent when the
  config file was missing, malformed, oversized, or had no usable URL for
  that server.

`SessionEndEvent.reason` is a **frozen closed union**
(`'child_exit' | 'stdin_closed' | 'signal' | 'error'`) with no member for
either of Claude Code's own `SessionEnd` reasons — additive-only means
picking the closest *existing* value rather than inventing a new one, so a
hook-sourced `session_end` reuses `'stdin_closed'` for the hook's own
`'logout'` reason and `'child_exit'` for everything else (`'clear'`/
`'resume'`/`'prompt_input_exit'`/`'other'`). `source: 'hook'`
is what actually distinguishes these from a proxy-captured `session_end` —
`reason` alone should not be read as "the wrapped process exited" for a
hook-sourced event.

`ServerContext.transport` stays `'stdio'` for hook-sourced events (the
closest existing value — a hook invocation is not literally a stdio pipe
the way `record`'s proxy is, but it is not an HTTP transport either, and the
union is frozen the same way); `server.name`/`server.command` follow
[docs/hooks.md](hooks.md#what-gets-recorded)'s own naming (the MCP server a
tool call went to, or `'claude-code'` for a built-in tool or a session-level
event).

---

## OpenTelemetry semantic-convention mapping

Field naming aligns with OTel GenAI / RPC semantic conventions where one exists. The
flat `attributes` bag on every event uses these names directly; the table maps the
typed event fields to their semconv equivalents.

| Semconv attribute | Recorder source | Notes |
| --- | --- | --- |
| `gen_ai.operation.name` | event `kind = 'tool_call'` | `execute_tool` for tool-call events. |
| `gen_ai.tool.name` | `ToolCallEvent.tool` | The MCP tool invoked. Same capped value as `tool` (see above). |
| `gen_ai.tool.call.id` | `ToolCallEvent.request_id` | The JSON-RPC request id of the call. |
| `rpc.system` | constant | `jsonrpc` — MCP is JSON-RPC 2.0. |
| `rpc.jsonrpc.request_id` | `RpcEvent.request_id`, `InitializeEvent.request_id` | Correlated request id. |
| `mcp.method.name` | `RpcEvent.method`, `NotificationEvent.method` | e.g. `tools/list`, `resources/read`. Same capped value as `method` (see above). |
| `error.type` | `error.type` on `tool_call` / `rpc` events | Stable error class; message stored only as `message_ref` hash. `policy_denied` marks a call the gateway refused; `duplicate_id` marks a call refused for reusing a request id that was still in flight, and a request sealed to hand an approved hold its pending slot back. |
| `cresec.policy.decision` | `PolicyDecisionEvent.decision`, `ToolCallEvent.gateway.decision` | `allow` / `hold` / `deny`. Not an OTel semconv name; namespaced under `cresec.` to say so. |
| `cresec.policy.rule_id` | `PolicyDecisionEvent.rule_id`, `ToolCallEvent.gateway.rule_id` | The matching `policy.yaml` rule id, when one matched. |

---

## Chain layer

Events are wrapped into the tamper-evident store as **chain records**.

### `ChainRecord`

| Field | Type | Description |
| --- | --- | --- |
| `seq` | `number` | 1-based, strictly contiguous. |
| `prev_hash` | `string` | 64-hex chain hash of the previous record (`GENESIS_HASH` for seq 1). |
| `hash` | `string` | `sha256_hex(prev_hash + "\n" + canonical_json(event))`. |
| `event` | `AnyEvent` | The sealed event. |

### Genesis

The chain anchor for seq 1 is the SHA-256 of the constant string
`edut.mcp-recorder.genesis.v1`:

```
GENESIS_HASH = sha256_hex("edut.mcp-recorder.genesis.v1")
             = 707996e896e3e9a4b1e8d1e25fa74b8e0559541bb89243d2da7ae1f1f18cff27
```

### Hash recipe

For each record *n*:

```
hash_n = sha256_hex( prev_hash + "\n" + canonical_json(event_n) )
```

where `prev_hash` is `GENESIS_HASH` for `seq = 1` and `hash_{n-1}` otherwise, the
separator is a single LF (`0x0a`), and all input is UTF-8.

### Head signatures (`HeadSignature`)

The chain head is periodically signed with a local ed25519 key.

| Field | Type | Description |
| --- | --- | --- |
| `seq` | `number` | The seq of the record whose chain hash was signed. |
| `chain_hash` | `string` | The chain hash that was signed (64-hex). |
| `algo` | `'ed25519'` | Signature algorithm. |
| `public_key` | `string` | 64-hex raw ed25519 public key. |
| `signature` | `string` | 128-hex raw ed25519 signature over the signed payload below. |
| `signed_at` | `string` | ISO-8601 UTC. |

The exact bytes signed are domain-separated with the constant string
`edut.mcp-recorder.head.v1`, so a head signature can never be confused with any other
payload:

```
signed_payload = utf8( "edut.mcp-recorder.head.v1" + "\n" + seq + "\n" + chain_hash )
```

with `seq` rendered in decimal and `chain_hash` as 64 lowercase hex characters.

### Canonical JSON rules

`canonical_json` is deterministic JSON serialization:

1. Object keys sorted **lexicographically at every level**.
2. **No whitespace** anywhere.
3. `undefined` object values are **dropped** (like `JSON.stringify`).
4. `undefined` array elements become `null` (like `JSON.stringify`).
5. Non-finite numbers (`NaN`, `±Infinity`) become `null` (like `JSON.stringify`).
6. Strings and booleans serialize exactly as `JSON.stringify` (standard JSON string
   escaping).
7. `null` and `undefined` values serialize as `null`.

Any independent implementation following these rules over the same event object yields
byte-identical output, and therefore the same chain hashes — this is what makes the
standalone `verify.cjs` in an exported bundle possible.
