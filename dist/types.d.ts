/**
 * FROZEN MODULE CONTRACTS
 * =======================
 * Public interfaces every module implements against. Implementation files own
 * their internals, but the exported shapes below must not drift — the CLI and
 * the other modules are written against them.
 *
 * Module map (file ownership):
 *   src/chain/hash.ts      — canonicalJson, sha256Hex, GENESIS_HASH, computeHash, makeRecord, signedPayload
 *   src/chain/keys.ts      — Signer (ed25519 keypair management + head signing)
 *   src/store/sqlite.ts    — SqliteStore implements EvidenceStore
 *   src/store/jsonl.ts     — JsonlStore implements EvidenceStore
 *   src/store/index.ts     — openStore() factory with sqlite→jsonl fallback
 *   src/redact/redactor.ts — Redactor implements RedactorLike
 *   src/capture/recorder.ts— Recorder (async fail-open queue) implements RecorderLike
 *   src/proxy/framing.ts   — LineScanner (incremental newline-delimited JSON tap)
 *   src/proxy/stdio.ts     — runStdioProxy()
 *   src/proxy/http.ts      — runHttpProxy()
 *   src/verify/verify.ts   — verifyStore(), verifyRecords()
 *   src/query/touched.ts   — queryStore()
 *   src/replay/render.ts   — renderTimelineHtml()
 *   src/replay/serve.ts    — serveUi()
 *   src/export/bundle.ts   — exportBundle()
 *   src/config.ts          — resolveConfig(), data-dir/env handling
 *   src/cli.ts             — subcommand dispatch
 */
import type { AnyEvent, ChainRecord, HeadSignature, Scrubbed, Sha256Ref } from './schema/events.js';
export interface ChainHead {
    /** 0 when the chain is empty. */
    seq: number;
    /** GENESIS_HASH when the chain is empty. */
    hash: string;
}
export interface SessionSummary {
    session_id: string;
    started_at: string;
    /**
     * The session's LATEST `session_end` timestamp, when it has one. A
     * `session_end` is not necessarily the session's last event: a Claude Code
     * session resumed under the same `session_id` records more events after
     * it (cloud dogfood 4: a `session_end` at 07:59:20 followed by tool calls
     * until 12:41:08). So `ended_at` is only the session's end when it equals
     * `last_event_at`; when `last_event_at` is later the session was REOPENED,
     * and the counts below — all live aggregates over every event — cover the
     * activity after it too. `mcp-recorder sessions` renders that case as
     * `(reopened)` rather than printing a superseded end time.
     */
    ended_at?: string;
    /**
     * Additive, optional: the timestamp of the session's LAST event, whatever
     * its kind — the instant through which `event_count`, `tool_call_count`,
     * `error_count` and `server_count` run. Equal to `ended_at` for a session
     * that ended and stayed ended, later than it for a reopened one, and the
     * last activity of a session with no `session_end` at all. Both store
     * backends always set it (every session has at least one event); it is
     * optional only so a summary produced by an older reader of this contract
     * still type-checks.
     */
    last_event_at?: string;
    /**
     * `server.name` of the session's first event. For a proxy session that is
     * the one wrapped server; for a hook-captured session it is the client
     * (`claude-code`) — the MCP servers its tool calls went to are counted in
     * `server_count` and stamped on each event's own `server.name`.
     */
    server_name: string;
    identity_fingerprint: string;
    event_count: number;
    /**
     * Tool CALLS, not `tool_call` events. A proxy-captured call is one
     * request+response-correlated event (no `phase`); a hook-captured call is
     * a `phase: 'pre'` event plus, once Claude Code fired PostToolUse or
     * PostToolUseFailure for it, a `phase: 'post'` event sharing its
     * `request_id`. Only the `pre` half is counted, so a call whose post half
     * never arrived still counts exactly once.
     */
    tool_call_count: number;
    /**
     * `tool_call` / `rpc` events with `is_error: true`, whichever phase — a
     * failed hook call carries exactly one such event (the denied `pre`, or
     * the failing `post`), so this too is per call. A failing `post` whose
     * `pre` was never recorded (the hook installed mid-call) counts here but
     * not in `tool_call_count`, so `error_count` can exceed it.
     */
    error_count: number;
    /**
     * Additive, optional: the number of distinct `server.name` values over
     * the session's `tool_call` events — the servers actually called. Usually
     * 1 for a proxy session with or without `--name`, 0 for a session that
     * never called a tool, and for a hook session the number of MCP servers
     * its calls went to (ClickUp + GitHub + a local server = 3; the client's
     * own `claude-code` session-level events are not a server).
     *
     * A proxy session reads 2 when a tool call was sealed BEFORE the server's
     * `initialize` response was seen. Without `--name`, `server.name` is the
     * argv-derived basename until that response and the initialize-learned
     * `serverInfo.name` after it, so a call recorded on the early side of
     * that line carries a different name from the rest. Gateway mode makes
     * this ordinary rather than rare: a denied call is answered by the proxy
     * itself without waiting for the server, so a deny early in a session is
     * routinely sealed with the pre-handshake name while the calls that were
     * actually forwarded carry the learned one. `--name` pins a single name
     * for the whole session and avoids it. Both store backends always set
     * this; it is optional only so a summary produced by an older reader of
     * this contract still type-checks.
     */
    server_count?: number;
    /**
     * Additive, optional: the number of `policy_decision` events in the
     * session — every enforcement action gateway mode took (docs/gateway.md).
     * One per deny, and one per RESOLVED hold whatever its outcome, so a hold
     * the operator APPROVED counts too: this is what the gateway ruled on,
     * not what it refused. It does NOT count calls. An allowed call produces
     * no `policy_decision` event at all, so a session recorded without
     * `--policy`, and a gateway session that allowed everything, both read 0.
     * Nor does it count the synthetic `tool_call` carrying a refusal back to
     * the client — that one is counted in `tool_call_count` and `error_count`
     * like any other failed call, so a denied call adds 1 to each of the
     * three, and so does a call refused on protocol grounds rather than by
     * rule (a duplicate JSON-RPC id, recorded as a deny with no `rule_id`).
     * ONE decision is not a `policy_decision` event and still counts: a
     * refused `tools/call` NOTIFICATION. A notification has no request id,
     * and the frozen schema's `request_id` is `string | number`, so the
     * decision rides its `notification` event's additive `gateway` field
     * instead. Leaving it out reported `0` for a session where enforcement
     * had happened.
     *
     * When the number is surprising, read the session's `policy_decision`
     * events themselves — the POLICY rows in `mcp-recorder ui` — each of
     * which names its tool, matching rule (or none), decision and hold
     * outcome. Both store backends always set it; it is optional only so a
     * summary produced by an older reader of this contract still type-checks.
     */
    policy_decision_count?: number;
}
export interface IterateOpts {
    fromSeq?: number;
    toSeq?: number;
    sessionId?: string;
}
/**
 * Append-only evidence store. Implementations must reject (throw) any append
 * whose seq/prev_hash do not extend the current head — integrity is enforced
 * at the write boundary, not just checked at verify time.
 */
export interface EvidenceStore {
    readonly backend: 'sqlite' | 'jsonl';
    /** Filesystem path of the store (db file or jsonl file). */
    readonly path: string;
    head(): ChainHead;
    append(records: ChainRecord[]): void;
    /**
     * Seal raw events into chain records and append them, all under the
     * store's own exclusive lock (the head is read INSIDE that lock, so this
     * is safe to call from multiple processes sharing one data dir — unlike
     * `append`, which trusts a head read by the caller). Returns the sealed
     * records in the order they were written.
     */
    appendEvents(events: AnyEvent[]): ChainRecord[];
    addSignature(sig: HeadSignature): void;
    latestSignature(): HeadSignature | null;
    signatures(): HeadSignature[];
    iterate(opts?: IterateOpts): Iterable<ChainRecord>;
    count(): number;
    sessions(): SessionSummary[];
    close(): void;
}
export interface OpenStoreOpts {
    dataDir: string;
    /** Force a backend; default tries sqlite, falls back to jsonl. */
    backend?: 'sqlite' | 'jsonl';
}
export interface SignerLike {
    /** 64-hex raw ed25519 public key. */
    readonly publicKeyHex: string;
    /** Sign the chain head; payload is signedPayload(seq, chainHash). */
    sign(seq: number, chainHash: string): Promise<HeadSignature>;
}
export interface RedactionPolicy {
    /**
     * 'allowlist': every string leaf is hashed unless its key is allow-listed
     * AND its value looks structural (short, non-secret). 'off': string leaves
     * pass through, but values matching `alwaysPatterns` are still hashed.
     */
    mode: 'allowlist' | 'off';
    /** Object keys whose short string values may pass in allowlist mode. */
    allowKeys: string[];
    /** Strings longer than this are always hashed, even when allow-listed. */
    maxAllowedStringLen: number;
    /** Secret shapes that are hashed in EVERY mode (AWS keys, JWTs, PEM, ...). */
    alwaysPatterns: RegExp[];
    /** Recursion guard. */
    maxDepth: number;
}
export interface RedactorLike {
    readonly mode: RedactionPolicy['mode'];
    /** Redact a JSON tree per policy. Never throws; worst case returns a ref. */
    scrub(value: unknown): Scrubbed;
    /** sha256:<hex> of the exact string — must match RedactedRef.ref format. */
    hashString(value: string): Sha256Ref;
}
export interface RecorderStats {
    enqueued: number;
    written: number;
    dropped: number;
    storeFailed: boolean;
}
/**
 * Async, fail-open capture sink. `record()` is synchronous, O(1), and must
 * NEVER throw — a recorder failure can never become a proxy failure. Events
 * are batched to the store off the hot path; the head is signed on flush.
 */
export interface RecorderLike {
    record(event: AnyEvent): void;
    flush(): Promise<void>;
    /** Flush, final head signature, release store. Safe to call twice. */
    close(): Promise<void>;
    stats(): RecorderStats;
}
export type VerifyProblemType = 'hash_mismatch' | 'prev_hash_mismatch' | 'seq_gap' | 'duplicate_seq' | 'bad_genesis' | 'signature_invalid' | 'signature_chain_mismatch' | 'truncated_after_signature' | 'unsigned_tail' | 'malformed_record'
/** Chain has events but not one valid (crypto-verified, correctly-linked,
 *  correctly-keyed) signature attests any of it. Not a warning by default
 *  — a chain nobody can be shown to have signed proves nothing. */
 | 'no_valid_signature'
/** The unsigned suffix (see 'unsigned_tail') contains a session_end event.
 *  The recorder signs on every flush, including the session_end flush, so
 *  this is a stronger signal than a plain crash mid-session. */
 | 'unsigned_session_end'
/** Bundle mode only (`verify --bundle`): manifest.json's declared range /
 *  event_count / head_hash / signature don't match what events.jsonl and
 *  public_key.pem actually contain. A bundle is a sealed, self-declared
 *  artifact — any mismatch here means the bundle was hand-edited after
 *  export (e.g. records appended past the signed head) and is an
 *  unconditional failure, never a warning. */
 | 'bundle_manifest_mismatch';
export interface VerifyProblem {
    type: VerifyProblemType;
    /** Seq the problem was detected at (0 = chain-level). */
    seq: number;
    detail: string;
    /** True when this is a warning rather than a tamper verdict. */
    warning?: boolean;
}
export interface VerifyResult {
    ok: boolean;
    checked_events: number;
    head: ChainHead;
    problems: VerifyProblem[];
    /** The newest signature that validated, if any. */
    verified_signature?: HeadSignature;
}
export interface QueryMatch {
    seq: number;
    session_id: string;
    timestamp: string;
    kind: AnyEvent['kind'];
    /** tool or method name when applicable. */
    name?: string;
    /**
     * Where the needle matched:
     * 'ref' | 'result_hash' | 'args_hash' | 'credential' | 'name' | 'plain'.
     * `args_hash` is additive (gateway mode): the canonical-JSON hash of the
     * arguments of a call the gateway denied or held.
     */
    matched_on: 'ref' | 'result_hash' | 'args_hash' | 'plain' | 'credential' | 'name';
    /** JSON-path-ish location of the match inside the event. */
    path: string;
}
export interface QueryResult {
    needle_hash: Sha256Ref;
    matches: QueryMatch[];
    /** Distinct sessions touched, newest first. */
    sessions: SessionSummary[];
}
export interface ExportOpts {
    store: EvidenceStore;
    /** Limit to one session; default = whole chain. */
    sessionId?: string;
    /** Write a .zip at this path... */
    zipPath?: string;
    /** ...or write the bundle as a plain directory (used by tests/strangers). */
    dirPath?: string;
    toolVersion: string;
}
export interface BundleManifest {
    bundle: 'edut.mcp-recorder.bundle.v1';
    created_at: string;
    tool_version: string;
    session_id?: string;
    range: {
        from_seq: number;
        to_seq: number;
    };
    /** prev_hash of the first record — lets a segment verify without genesis. */
    base_hash: string;
    head_hash: string;
    event_count: number;
    signature: HeadSignature;
    /** SPKI PEM of the ed25519 public key, for dependency-free verification. */
    public_key_pem: string;
}
export interface RecorderConfig {
    dataDir: string;
    storeBackend?: 'sqlite' | 'jsonl';
    redactMode: 'allowlist' | 'off';
    /** Logical server name override (--name). */
    serverName?: string;
    /** Operator identity label (--identity). */
    identityLabel?: string;
    /** MCP_RECORDER_DISABLE=1 → pure passthrough, no recording. */
    disabled: boolean;
}
export declare const ENV: {
    readonly DATA_DIR: "MCP_RECORDER_DATA_DIR";
    readonly STORE: "MCP_RECORDER_STORE";
    readonly REDACT: "MCP_RECORDER_REDACT";
    readonly DISABLE: "MCP_RECORDER_DISABLE";
    /** Additive (gateway mode): policy.yaml path honoured by `record` when `--policy` is absent. */
    readonly POLICY: "MCP_RECORDER_POLICY";
    /** `hook`: MCP config file(s) to resolve server origins from — one path or
     *  comma-separated paths; default `/tmp/mcp-config-*.json` (cloud sessions).
     *  See src/hook/mcp-config.ts. */
    readonly MCP_CONFIG: "MCP_RECORDER_MCP_CONFIG";
    /**
     * Additive (evidence sink): base URL of a receiver to replicate sealed
     * records to. SETTING IT IS THE ENTIRE OPT-IN — absent, there is no sink,
     * no shipper and byte-identical behaviour to a build without the feature.
     * There is deliberately no second `..._ENABLED` switch. See src/sink.
     */
    readonly SINK: "MCP_RECORDER_SINK";
    /** Additive: the sink's bearer token (channel authorisation only — it
     *  answers "may this connection write to tenant T at all", nothing more). */
    readonly SINK_TOKEN: "MCP_RECORDER_SINK_TOKEN";
    /** Additive: a file holding the bearer token, for platforms where a
     *  root-owned file is easier to protect than an environment variable. */
    readonly SINK_TOKEN_FILE: "MCP_RECORDER_SINK_TOKEN_FILE";
};
/** File names inside the data dir. */
export declare const FILES: {
    readonly SQLITE_DB: "evidence.db";
    readonly JSONL_LOG: "evidence.jsonl";
    readonly JSONL_SIGS: "signatures.jsonl";
    readonly PRIVATE_KEY: "identity.key";
    readonly PUBLIC_KEY: "identity.pub";
    /** Evidence sink: cached copy of the receiver's cursor. A CACHE ONLY —
     *  the receiver is always the authority on what it holds. */
    readonly SINK_CURSOR: "sink-cursor.json";
    /** Evidence sink: single-instance mutex DIRECTORY for `ship`. */
    readonly SHIP_LOCK: "ship.lock";
    /** Evidence sink: what `ship --status` prints. */
    readonly SHIP_STATUS: "ship-status.json";
};
