/**
 * FROZEN EVENT SCHEMA — v1
 * ========================
 * This is the contract between capture (M1), the tamper-evident store (M2),
 * and replay/query/export (M3). Treat every shipped field as frozen:
 * additive changes only; breaking changes require a new `SCHEMA` id.
 *
 * Field naming aligns with OpenTelemetry GenAI / RPC semantic conventions
 * where one exists (`gen_ai.*`, `rpc.*`, `error.*`, `mcp.*`) — see
 * docs/event-schema.md for the full mapping.
 *
 * Privacy posture: payloads never land in the store readable. String values
 * are replaced at the edge by `RedactedRef`s — a SHA-256 of the exact value
 * plus its length. Hashes are deliberately unsalted so a blast-radius query
 * can match a known probe value by hashing it the same way.
 */
export declare const SCHEMA: "edut.mcp-recorder.event.v1";
export type SchemaId = typeof SCHEMA;
/** `sha256:<64 lowercase hex>` */
export type Sha256Ref = string;
/** A redacted leaf value. The original never leaves the machine readable. */
export interface RedactedRef {
    redacted: true;
    /** sha256:<hex> of the exact UTF-8 encoding of the original string. */
    ref: Sha256Ref;
    /** Length of the original string in UTF-16 code units. */
    len: number;
    /**
     * Hashes of secret-shaped tokens (alwaysPatterns matches) found EMBEDDED
     * within this leaf, e.g. an AWS key inside "AWS_ACCESS_KEY_ID=AKIA...\n".
     * De-duplicated, capped at 8, excludes any hash equal to `ref` itself.
     * Optional and additive (v1). A miss against `secret_refs` is NOT proof a
     * value never appeared here — only alwaysPatterns-shaped tokens are
     * captured this way; see docs/event-schema.md.
     */
    secret_refs?: Sha256Ref[];
}
/** JSON tree after edge redaction: structure preserved, sensitive leaves replaced. */
export type Scrubbed = string | number | boolean | null | RedactedRef | Scrubbed[] | {
    [key: string]: Scrubbed;
};
/** Hash of a credential value handed to the wrapped server — never the value. */
export interface CredentialFingerprint {
    /** Where it came from, e.g. the env var name `GITHUB_TOKEN`. */
    name: string;
    /** sha256:<hex> of the credential value. */
    ref: Sha256Ref;
}
/** Identity context stamped on every event ("identity-stamp everything"). */
export interface IdentityContext {
    /**
     * Stable identity hash for the acting agent/credential pair:
     * sha256 over (os_user, hostname, label, initial server name) — the
     * identity/server context known at proxy startup, before the MCP
     * `initialize` handshake (client_name/client_version are learned later
     * and are not part of the fingerprint).
     */
    fingerprint: Sha256Ref;
    os_user?: string;
    hostname?: string;
    /** From the MCP `initialize` handshake clientInfo, once seen. */
    client_name?: string;
    client_version?: string;
    /** Operator-supplied label (`--identity`). */
    label?: string;
    /** Hashes of secret-looking env values passed to the wrapped server. */
    credential_fingerprints?: CredentialFingerprint[];
}
export interface ServerContext {
    /** Logical server name (`--name` flag, else derived from command/initialize). */
    name: string;
    /** From the MCP `initialize` result serverInfo, once seen. */
    version?: string;
    /** The wrapped command line (argv joined), env values never included. */
    command: string;
    transport: 'stdio' | 'http';
}
export type EventKind = 'session_start' | 'initialize' | 'tool_call' | 'rpc' | 'notification' | 'protocol_error' | 'session_end';
/**
 * OTel-style flat attribute bag. Use semconv names where they exist:
 * `gen_ai.operation.name`, `gen_ai.tool.name`, `gen_ai.tool.call.id`,
 * `rpc.system`, `rpc.jsonrpc.request_id`, `mcp.method.name`, `error.type`.
 */
export type Attributes = Record<string, string | number | boolean>;
export interface EventBase {
    schema: SchemaId;
    /** UUID v4, unique per event. */
    event_id: string;
    /** UUID v4, one per proxy process lifetime — or, for hook-captured events,
     *  one per Claude Code session (the hook input's own `session_id`). */
    session_id: string;
    /** ISO-8601 UTC with milliseconds. */
    timestamp: string;
    kind: EventKind;
    identity: IdentityContext;
    server: ServerContext;
    attributes: Attributes;
    /**
     * Additive optional field (schema stays v1). Set to `'hook'` when this
     * event was captured by `mcp-recorder hook` — a Claude Code PreToolUse /
     * PostToolUse / PostToolUseFailure / SessionEnd / Stop hook — rather than
     * the stdio/http proxy tap. Undefined on every proxy-captured event.
     */
    source?: 'hook';
}
/** Proxy process started; carries the redaction policy in force. */
export interface SessionStartEvent extends EventBase {
    kind: 'session_start';
    proxy_version: string;
    cwd: string;
    redaction_mode: 'allowlist' | 'off';
}
/** The MCP initialize handshake (request + response correlated). */
export interface InitializeEvent extends EventBase {
    kind: 'initialize';
    request_id: string | number;
    protocol_version?: string;
    client_name?: string;
    client_version?: string;
    server_name?: string;
    server_version?: string;
    duration_ms: number;
}
/** A completed tools/call (request + response correlated). The flagship event. */
export interface ToolCallEvent extends EventBase {
    kind: 'tool_call';
    /** gen_ai.tool.name */
    tool: string;
    /** JSON-RPC request id (gen_ai.tool.call.id). */
    request_id: string | number;
    /** Redacted argument tree (structure preserved, string leaves hashed). */
    args: Scrubbed;
    /** sha256:<hex> of canonical JSON of the COMPLETE raw result, pre-redaction. */
    result_hash: Sha256Ref;
    /** Redacted result tree. */
    result: Scrubbed;
    is_error: boolean;
    /**
     * Error details; the message is stored only as a hash ref. `type` is a
     * free-form string: `mcp-recorder hook` records 'policy_denied' (a
     * --policy deny), 'tool_error' (PostToolUseFailure, or a PostToolUse
     * response shaped `{isError: true}`) and 'interrupted' (PostToolUseFailure
     * with is_interrupt) under it — additive values, no schema change.
     */
    error?: {
        code?: number;
        type?: string;
        message_ref?: Sha256Ref;
    };
    /** Wall-clock ms between request and response crossing the proxy. */
    duration_ms: number;
    /**
     * Additive optional field (schema stays v1). `mcp-recorder hook` records a
     * tool call as two separate correlated events sharing `request_id` — this
     * says which half. Undefined for proxy-captured tool_call events, which
     * are already request+response correlated into a single event.
     */
    phase?: 'pre' | 'post';
}
/** Any other correlated JSON-RPC request/response (tools/list, resources/read, ...). */
export interface RpcEvent extends EventBase {
    kind: 'rpc';
    /** mcp.method.name */
    method: string;
    request_id: string | number;
    params: Scrubbed;
    result_hash: Sha256Ref;
    is_error: boolean;
    error?: {
        code?: number;
        type?: string;
        message_ref?: Sha256Ref;
    };
    duration_ms: number;
}
/** One-way JSON-RPC notification in either direction. */
export interface NotificationEvent extends EventBase {
    kind: 'notification';
    method: string;
    direction: 'client_to_server' | 'server_to_client';
    params: Scrubbed;
}
/** Traffic the tap could not interpret. Forwarding is unaffected (fail-open). */
export interface ProtocolErrorEvent extends EventBase {
    kind: 'protocol_error';
    direction: 'client_to_server' | 'server_to_client';
    reason: 'unparseable' | 'oversized' | 'orphan_response';
    bytes_len: number;
    /** sha256:<hex> of the raw line, so the artifact is still identifiable. */
    line_hash: Sha256Ref;
}
/** Proxy shutting down (child exit, stdin close, or signal). */
export interface SessionEndEvent extends EventBase {
    kind: 'session_end';
    reason: 'child_exit' | 'stdin_closed' | 'signal' | 'error';
    child_exit_code?: number | null;
    events_recorded: number;
    events_dropped: number;
    /** errno code (e.g. 'ENOENT') when the wrapped command failed to spawn. */
    spawn_error?: string;
    /** Signal name (e.g. 'SIGKILL') when the wrapped process was killed by a signal. */
    child_signal?: string;
}
export type AnyEvent = SessionStartEvent | InitializeEvent | ToolCallEvent | RpcEvent | NotificationEvent | ProtocolErrorEvent | SessionEndEvent;
/** An event sealed into the hash chain. */
export interface ChainRecord {
    /** 1-based, strictly contiguous. */
    seq: number;
    /** 64-hex chain hash of the previous record (GENESIS_HASH for seq 1). */
    prev_hash: string;
    /** sha256_hex(prev_hash + "\n" + canonical_json(event)). */
    hash: string;
    event: AnyEvent;
}
/** A signature over the chain head at some point in time. */
export interface HeadSignature {
    /** The seq of the record whose chain hash was signed. */
    seq: number;
    /** The chain hash that was signed (64-hex). */
    chain_hash: string;
    algo: 'ed25519';
    /** 64-hex raw ed25519 public key. */
    public_key: string;
    /** 128-hex raw ed25519 signature over `signedPayload(seq, chain_hash)`. */
    signature: string;
    /** ISO-8601 UTC. */
    signed_at: string;
}
