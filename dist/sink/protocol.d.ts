/**
 * EVIDENCE SINK WIRE PROTOCOL v1 — shared by the sender (this package) and
 * any receiver that wants to accept its batches.
 *
 * The sink is a REPLICA, never a second source of truth. What ships is
 * exactly what the store already sealed: contiguous `ChainRecord`s verbatim,
 * the `HeadSignature`s that fall in their seq range, and a signed statement
 * of the sender's CURRENT local head. Nothing derived, nothing summarised —
 * a derived field is a field that can lie, and a rewritten `event` would no
 * longer reproduce `record.hash` under `computeHash`.
 *
 * That last point is what structurally enforces the no-readable-payload rule
 * on the wire: values were hashed to `sha256:` refs by the redactor long
 * before they reached the store, and the sink cannot widen that without
 * failing the receiver's own recomputation. There is no second redaction
 * pass here, and deliberately no opportunity for one.
 *
 * Two derived identifiers, both computable from the existing chain with zero
 * schema change:
 *   key      — the 64-hex ed25519 public key from <data-dir>/identity.pub.
 *              One per data dir, therefore one per chain.
 *   chain_id — the `hash` of chain record seq 1. Unique per chain INSTANCE
 *              because event 1 carries a v4 event_id, so an `identity.key`
 *              that survives while `evidence.db` is deleted does NOT silently
 *              fork a chain under the same key: it becomes a visible "second
 *              chain for an enrolled key" at the receiver.
 */
import type { ChainRecord, HeadSignature } from '../schema/events.js';
/** Bumped only for a breaking wire change; sent as X-MCPR-Protocol. */
export declare const SINK_PROTOCOL = 1;
/** Domain separator for the per-request signature (cf. `signedPayload`). */
export declare const SINK_SIGNATURE_DOMAIN = "edut.mcp-recorder.sink.v1";
/** Request headers, lowercase (node:http lowercases them anyway). */
export declare const SINK_HEADERS: {
    readonly PROTOCOL: "x-mcpr-protocol";
    readonly KEY: "x-mcpr-key";
    readonly CONTENT_SHA256: "x-mcpr-content-sha256";
    readonly SIGNATURE: "x-mcpr-signature";
    readonly SENT_AT: "x-mcpr-sent-at";
    readonly IDEMPOTENCY: "idempotency-key";
};
/** Records per POST, whichever of the two caps binds first. */
export declare const SENDER_MAX_RECORDS = 512;
/** Uncompressed body bytes per POST. Always at least ONE record even when
 *  that record alone exceeds this — skipping is never an option, because a
 *  skipped record makes every later record unverifiable at the receiver. */
export declare const SENDER_MAX_BYTES: number;
/** Below this, send identity; at or above it, gzip. */
export declare const GZIP_THRESHOLD_BYTES: number;
/** Idle heartbeat period; a receiver may override it via the cursor. */
export declare const HEARTBEAT_INTERVAL_S = 60;
export declare const CONNECT_TIMEOUT_MS = 10000;
export declare const TOTAL_TIMEOUT_MS = 30000;
/** delay = random() * min(BACKOFF_CAP_MS, BACKOFF_BASE_MS * 2^n) — full jitter. */
export declare const BACKOFF_BASE_MS = 1000;
export declare const BACKOFF_CAP_MS = 300000;
/** 401/403 back off from a minute, capped at fifteen: an install that cannot
 *  authenticate must not hammer, and it already looks (correctly) identical
 *  to an install that was switched off. */
export declare const AUTH_BACKOFF_BASE_MS = 60000;
export declare const AUTH_BACKOFF_CAP_MS = 900000;
export type SinkSurface = 'record' | 'hook' | 'http' | 'ship';
/** Advisory only. The receiver must never treat any of it as authoritative. */
export interface SinkSender {
    tool_version: string;
    surface: SinkSurface;
    backend: 'sqlite' | 'jsonl';
}
/** The sender's current local head, signed with its own key. */
export interface SinkHead {
    seq: number;
    hash: string;
    signature: HeadSignature;
}
/** POST /v1/chains/{chain_id}/records */
export interface SinkBatchBody {
    protocol: number;
    chain_id: string;
    key: string;
    from_seq: number;
    to_seq: number;
    base_hash: string;
    records: ChainRecord[];
    signatures: HeadSignature[];
    head: SinkHead;
    sender: SinkSender;
}
/** Returned by 200, 202 and both 409s. `next_seq` is THE resume point. */
export interface SinkCursor {
    chain_id: string;
    key: string;
    /** First seq the receiver does not have. */
    next_seq: number;
    /** Receiver's hash at next_seq - 1 (GENESIS_HASH when next_seq === 1). */
    head_hash: string;
    /** Highest seq covered by a signature the receiver verified. */
    attested_seq?: number;
    attested_at?: string;
    max_records?: number;
    max_bytes?: number;
    heartbeat_interval_s?: number;
}
export declare function isHex64(value: unknown): value is string;
/**
 * `chain_id` of the chain `genesis` belongs to. It is simply the hash of
 * record seq 1 — i.e. sha256(GENESIS_HASH + "\n" + canonicalJson(event_1)).
 * Throws on anything that is not a well-formed seq-1 record, because a
 * wrong chain_id would address someone else's chain.
 */
export declare function chainIdFromGenesisRecord(genesis: ChainRecord): string;
/**
 * The exact bytes signed per request, domain separated the same way
 * `signedPayload()` separates head signatures — a sink signature can never
 * be replayed as a head signature or vice versa.
 *
 * The digest is over the DECOMPRESSED body bytes on purpose: a
 * TLS-terminating corporate proxy or an agent proxy may re-encode the
 * transfer, and hashing the compressed octets would break the signature on
 * a path that is otherwise working.
 */
export declare function sinkSignedPayload(chainId: string, fromSeq: number, toSeq: number, contentSha256Hex: string): Uint8Array;
/** Path of the only write endpoint. */
export declare function recordsPath(chainId: string): string;
/** Path of the resume oracle. */
export declare function cursorPath(chainId: string): string;
/** Unauthenticated liveness, no data. */
export declare const HEALTH_PATH = "/v1/health";
/**
 * Parse a cursor out of a response body. Returns undefined for anything
 * that is not a structurally valid cursor — the sender must never act on a
 * half-understood resume point.
 */
export declare function parseCursor(value: unknown): SinkCursor | undefined;
/** Full jitter: delay = random() * min(cap, base * 2^attempt). */
export declare function backoffMs(attempt: number, random: () => number, base?: number, cap?: number): number;
