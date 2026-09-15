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
| `client_name` | `string?` | From the MCP `initialize` handshake clientInfo, once seen. |
| `client_version` | `string?` | From the MCP `initialize` handshake clientInfo, once seen. |
| `label` | `string?` | Operator-supplied label (`--identity`). |
| `credential_fingerprints` | `CredentialFingerprint[]?` | Hashes of secret-looking env values passed to the wrapped server. |

### `ServerContext`

| Field | Type | Description |
| --- | --- | --- |
| `name` | `string` | Logical server name (`--name` flag, else derived from command/initialize). |
| `version` | `string?` | From the MCP `initialize` result serverInfo, once seen. |
| `command` | `string` | stdio transport: the wrapped command line (argv, scrubbed and re-joined with spaces). http transport: the target URL, scrubbed (see below). env values never included either way. |
| `transport` | `'stdio' \| 'http'` | Transport the proxy bridged. |

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

`EventKind` is one of: `session_start`, `initialize`, `tool_call`, `rpc`,
`notification`, `protocol_error`, `session_end`.

## Event kinds

### `session_start`

Proxy process started; carries the redaction policy in force.

| Field | Type | Description |
| --- | --- | --- |
| `proxy_version` | `string` | Version of `@edut/mcp-recorder`. |
| `cwd` | `string` | Working directory of the proxy process. |
| `redaction_mode` | `'allowlist' \| 'off'` | Redaction policy in force for the session. |

### `initialize`

The MCP initialize handshake (request + response correlated).

| Field | Type | Description |
| --- | --- | --- |
| `request_id` | `string \| number` | JSON-RPC request id. |
| `protocol_version` | `string?` | Negotiated MCP protocol version. |
| `client_name` | `string?` | From clientInfo. |
| `client_version` | `string?` | From clientInfo. |
| `server_name` | `string?` | From serverInfo. |
| `server_version` | `string?` | From serverInfo. |
| `duration_ms` | `number` | Wall-clock ms between request and response crossing the proxy. |

### `tool_call`

A completed `tools/call` (request + response correlated). The flagship event.

| Field | Type | Description |
| --- | --- | --- |
| `tool` | `string` | Tool name (`gen_ai.tool.name`). |
| `request_id` | `string \| number` | JSON-RPC request id (`gen_ai.tool.call.id`). |
| `args` | `Scrubbed` | Redacted argument tree. **Every string leaf is hashed, unconditionally, regardless of key or position or redaction mode** — see [Privacy posture](#privacy-posture). |
| `result_hash` | `Sha256Ref` | `sha256:<hex>` of canonical JSON of the **complete raw result, pre-redaction**. |
| `result` | `Scrubbed` | Redacted result tree (the position/value-aware allowlist applies here, unlike `args`). |
| `is_error` | `boolean` | Whether the call returned an error. |
| `error` | `{ code?: number; type?: string; message_ref?: Sha256Ref }?` | Error details; the message is stored only as a hash ref. |
| `duration_ms` | `number` | Wall-clock ms between request and response crossing the proxy. |

### `rpc`

Any other correlated JSON-RPC request/response (`tools/list`, `resources/read`, ...).

| Field | Type | Description |
| --- | --- | --- |
| `method` | `string` | JSON-RPC method (`mcp.method.name`). |
| `request_id` | `string \| number` | JSON-RPC request id. |
| `params` | `Scrubbed` | Redacted params tree. |
| `result_hash` | `Sha256Ref` | `sha256:<hex>` of canonical JSON of the complete raw result, pre-redaction. |
| `is_error` | `boolean` | Whether the call returned an error. |
| `error` | `{ code?: number; type?: string; message_ref?: Sha256Ref }?` | Error details; message hashed. |
| `duration_ms` | `number` | Wall-clock ms between request and response. |

### `notification`

One-way JSON-RPC notification in either direction.

| Field | Type | Description |
| --- | --- | --- |
| `method` | `string` | JSON-RPC method (`mcp.method.name`). |
| `direction` | `'client_to_server' \| 'server_to_client'` | Which way it flowed. |
| `params` | `Scrubbed` | Redacted params tree. |

### `protocol_error`

Traffic the tap could not interpret. Forwarding is unaffected (fail-open).

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
existing free-form string field, so this needed no schema change.

---

## OpenTelemetry semantic-convention mapping

Field naming aligns with OTel GenAI / RPC semantic conventions where one exists. The
flat `attributes` bag on every event uses these names directly; the table maps the
typed event fields to their semconv equivalents.

| Semconv attribute | Recorder source | Notes |
| --- | --- | --- |
| `gen_ai.operation.name` | event `kind = 'tool_call'` | `execute_tool` for tool-call events. |
| `gen_ai.tool.name` | `ToolCallEvent.tool` | The MCP tool invoked. |
| `gen_ai.tool.call.id` | `ToolCallEvent.request_id` | The JSON-RPC request id of the call. |
| `rpc.system` | constant | `jsonrpc` — MCP is JSON-RPC 2.0. |
| `rpc.jsonrpc.request_id` | `RpcEvent.request_id`, `InitializeEvent.request_id` | Correlated request id. |
| `mcp.method.name` | `RpcEvent.method`, `NotificationEvent.method` | e.g. `tools/list`, `resources/read`. |
| `error.type` | `error.type` on `tool_call` / `rpc` events | Stable error class; message stored only as `message_ref` hash. |

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
