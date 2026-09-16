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
    /**
     * Additive optional field (schema stays v1). Where the server named by
     * `name` is, as ASSERTED by the MCP config file Claude Code was started
     * with (src/hook/mcp-config.ts) — never observed on the wire. Set by
     * `mcp-recorder hook` on `tool_call` events only: the vendor endpoint
     * behind an Anthropic-hosted connector's relay (`mcp_url`, e.g.
     * `https://mcp.clickup.com/mcp`), else the config entry's own URL —
     * always scrubbed (userinfo stripped, query/fragment dropped, every path
     * segment that is secret-shaped, opaque such as a cloud session id, or
     * not a short vocabulary token replaced in place by `sha256:<hex>`).
     * Undefined when unresolved, on session-level hook events (`name` is the
     * client there) and on every proxy-captured event (the http proxy records
     * its target in `command`).
     */
    url?: string;
}
export type EventKind = 'session_start' | 'initialize' | 'tool_call' | 'rpc' | 'notification' | 'protocol_error' | 'session_end'
/** Additive (v1): an enforcement action taken by gateway mode. */
 | 'policy_decision';
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
    /**
     * Optional and additive (v1). Present only in gateway mode: the SHA-256 of
     * the exact bytes of the `policy.yaml` in force and, when it has one, its
     * `name` (capped via structuralString, kind `identifier`).
     */
    policy?: {
        hash: Sha256Ref;
        name?: string;
    };
}
/** What the policy decided for a tools/call request. */
export type GatewayDecision = 'allow' | 'hold' | 'deny';
/** How a held call was resolved. */
export type HoldOutcome = 'approved' | 'denied' | 'timeout' | 'cancelled' | 'session_end';
/**
 * What the tool-result boundary filter found and did. Never carries the
 * matched text — only counts, an action enum, and sha256 refs.
 */
export interface BoundaryReport {
    /** false when the result exceeded boundary.max_scan_bytes or the filter hit an internal error. */
    scanned: boolean;
    /** What was applied to the result the client received. */
    action: 'none' | 'redact' | 'block' | 'flag';
    secrets_found: number;
    injection_found: number;
    /** Hashes of the secret-shaped tokens found (de-duplicated, capped at 8). */
    secret_refs?: Sha256Ref[];
    /**
     * Present only when the filter modified the result: sha256:<hex> of the
     * canonical JSON of the result the CLIENT actually received.
     * `result_hash`/`result` keep describing the raw server result.
     */
    delivered_result_hash?: Sha256Ref;
    /** Internal-error class when `scanned` is false for a reason other than size. */
    error?: string;
}
/** Additive (v1) `gateway` field on a tool_call recorded in gateway mode. */
export interface GatewayOutcome {
    decision: GatewayDecision;
    /** Matching rule id (capped identifier); absent when the section default applied. */
    rule_id?: string;
    /** Holds only. `session_end` = the proxy shut down while the call was still held. */
    outcome?: HoldOutcome;
    /** Holds only: the approval id the operator saw in `mcp-recorder holds`. */
    approval_id?: string;
    /** Holds only: how long the call was parked before it was resolved. */
    waited_ms?: number;
    /** Present when the result went through the boundary filter. */
    boundary?: BoundaryReport;
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
     * Optional and additive (v1). Present only when the result was nested
     * deeper than the hash depth cap (256), in which case `result_hash` is NOT
     * `sha256Ref(canonicalJson(result))`: every subtree below that depth
     * hashed as one fixed marker, so two results differing only below it share
     * a hash. The cap is what keeps a hostile payload from overflowing the
     * stack; this field is what stops it being silent, so a reader who
     * recomputes the documented hash and gets a different answer knows why.
     */
    result_hash_depth_capped?: true;
    /**
     * Optional and additive (v1). Present on every tool_call recorded in
     * gateway mode: the policy decision, hold outcome and boundary-filter
     * report for this call. See docs/event-schema.md.
     */
    gateway?: GatewayOutcome;
    /**
     * Additive optional field (schema stays v1). `mcp-recorder hook` records a
     * tool call as two separate correlated events sharing `request_id` — this
     * says which half. Undefined for proxy-captured tool_call events, which
     * are already request+response correlated into a single event.
     */
    phase?: 'pre' | 'post';
}
/**
 * Additive (v1). An enforcement action taken by gateway mode: one per deny
 * and one per hold outcome. Allowed calls do not produce this event (their
 * tool_call carries `gateway.decision: 'allow'`). Never carries arguments —
 * only their canonical-JSON hash.
 */
export interface PolicyDecisionEvent extends EventBase {
    kind: 'policy_decision';
    decision: 'deny' | 'hold';
    /** Holds only. `session_end` = the proxy shut down while the call was still held. */
    outcome?: HoldOutcome;
    /** gen_ai.tool.name — capped exactly like ToolCallEvent.tool. */
    tool: string;
    request_id: string | number;
    /** Matching rule id (capped identifier); absent when mcp.default applied. */
    rule_id?: string;
    /** sha256:<hex> of the exact bytes of the policy file in force. */
    policy_hash: Sha256Ref;
    /** sha256:<hex> of the canonical JSON of the raw params.arguments. */
    args_hash: Sha256Ref;
    approval_id?: string;
    waited_ms?: number;
    /** OS user that ran `mcp-recorder approve`/`deny`, when the hold file recorded one. */
    approver?: string;
}
/** Any other correlated JSON-RPC request/response (tools/list, resources/read, ...). */
export interface RpcEvent extends EventBase {
    kind: 'rpc';
    /** mcp.method.name */
    method: string;
    request_id: string | number;
    params: Scrubbed;
    result_hash: Sha256Ref;
    /** Same meaning as {@link ToolCallEvent.result_hash_depth_capped}. */
    result_hash_depth_capped?: true;
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
    /**
     * Gateway mode only, and only on a `tools/call` NOTIFICATION the policy
     * refused. Additive and optional, like `ToolCallEvent.gateway`, which it
     * shares a shape with.
     *
     * A notification has no request id, and the frozen schema's `request_id`
     * is `string | number`, so no `policy_decision` event can be written for
     * one. Without this field the only record of the refusal was a line on
     * stderr: the chain held one ordinary `notification` event,
     * indistinguishable from a forwarded one, so `sessions` reported no
     * decisions and an auditor could not tell a blocked exfiltration attempt
     * from a notification that went through. Enforcement without evidence is
     * the failure this tool exists to prevent.
     */
    gateway?: GatewayOutcome;
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
export type AnyEvent = SessionStartEvent | InitializeEvent | ToolCallEvent | RpcEvent | NotificationEvent | ProtocolErrorEvent | SessionEndEvent | PolicyDecisionEvent;
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
