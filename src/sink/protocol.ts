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

import { GENESIS_HASH } from '../chain/hash.js';
import type { ChainRecord, HeadSignature } from '../schema/events.js';

/** Bumped only for a breaking wire change; sent as X-MCPR-Protocol. */
export const SINK_PROTOCOL = 1;

/** Domain separator for the per-request signature (cf. `signedPayload`). */
export const SINK_SIGNATURE_DOMAIN = 'edut.mcp-recorder.sink.v1';

/** Request headers, lowercase (node:http lowercases them anyway). */
export const SINK_HEADERS = {
  PROTOCOL: 'x-mcpr-protocol',
  KEY: 'x-mcpr-key',
  CONTENT_SHA256: 'x-mcpr-content-sha256',
  SIGNATURE: 'x-mcpr-signature',
  SENT_AT: 'x-mcpr-sent-at',
  IDEMPOTENCY: 'idempotency-key',
} as const;

/* ----------------------------- sender caps ----------------------------- */

/** Records per POST, whichever of the two caps binds first. */
export const SENDER_MAX_RECORDS = 512;
/** Uncompressed body bytes per POST. Always at least ONE record even when
 *  that record alone exceeds this — skipping is never an option, because a
 *  skipped record makes every later record unverifiable at the receiver. */
export const SENDER_MAX_BYTES = 1024 * 1024;
/** Below this, send identity; at or above it, gzip. */
export const GZIP_THRESHOLD_BYTES = 8 * 1024;
/** Idle heartbeat period; a receiver may override it via the cursor. */
export const HEARTBEAT_INTERVAL_S = 60;

/* ------------------------------- timeouts ------------------------------ */

export const CONNECT_TIMEOUT_MS = 10_000;
export const TOTAL_TIMEOUT_MS = 30_000;

/* ------------------------------- backoff ------------------------------- */

/** delay = random() * min(BACKOFF_CAP_MS, BACKOFF_BASE_MS * 2^n) — full jitter. */
export const BACKOFF_BASE_MS = 1_000;
export const BACKOFF_CAP_MS = 300_000;
/** 401/403 back off from a minute, capped at fifteen: an install that cannot
 *  authenticate must not hammer, and it already looks (correctly) identical
 *  to an install that was switched off. */
export const AUTH_BACKOFF_BASE_MS = 60_000;
export const AUTH_BACKOFF_CAP_MS = 900_000;

/* -------------------------------- types -------------------------------- */

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

/* ------------------------------ derivation ----------------------------- */

const HEX64 = /^[0-9a-f]{64}$/;

export function isHex64(value: unknown): value is string {
  return typeof value === 'string' && HEX64.test(value);
}

/**
 * `chain_id` of the chain `genesis` belongs to. It is simply the hash of
 * record seq 1 — i.e. sha256(GENESIS_HASH + "\n" + canonicalJson(event_1)).
 * Throws on anything that is not a well-formed seq-1 record, because a
 * wrong chain_id would address someone else's chain.
 */
export function chainIdFromGenesisRecord(genesis: ChainRecord): string {
  if (genesis.seq !== 1) {
    throw new Error(`mcp-recorder: chain_id needs the seq 1 record, got seq ${String(genesis.seq)}`);
  }
  if (genesis.prev_hash !== GENESIS_HASH) {
    throw new Error('mcp-recorder: seq 1 record does not link to the genesis anchor');
  }
  if (!isHex64(genesis.hash)) {
    throw new Error('mcp-recorder: seq 1 record has a malformed hash');
  }
  return genesis.hash;
}

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
export function sinkSignedPayload(
  chainId: string,
  fromSeq: number,
  toSeq: number,
  contentSha256Hex: string,
): Uint8Array {
  return new TextEncoder().encode(
    `${SINK_SIGNATURE_DOMAIN}\n${chainId}\n${fromSeq}\n${toSeq}\n${contentSha256Hex}`,
  );
}

/** Path of the only write endpoint. */
export function recordsPath(chainId: string): string {
  return `/v1/chains/${encodeURIComponent(chainId)}/records`;
}

/** Path of the resume oracle. */
export function cursorPath(chainId: string): string {
  return `/v1/chains/${encodeURIComponent(chainId)}/cursor`;
}

/** Unauthenticated liveness, no data. */
export const HEALTH_PATH = '/v1/health';

/**
 * Parse a cursor out of a response body. Returns undefined for anything
 * that is not a structurally valid cursor — the sender must never act on a
 * half-understood resume point.
 */
export function parseCursor(value: unknown): SinkCursor | undefined {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return undefined;
  const raw = value as Record<string, unknown>;
  const body =
    typeof raw.cursor === 'object' && raw.cursor !== null && !Array.isArray(raw.cursor)
      ? (raw.cursor as Record<string, unknown>)
      : raw;
  const nextSeq = body.next_seq;
  if (typeof nextSeq !== 'number' || !Number.isInteger(nextSeq) || nextSeq < 1) return undefined;
  if (!isHex64(body.head_hash)) return undefined;
  if (!isHex64(body.chain_id)) return undefined;
  if (!isHex64(body.key)) return undefined;
  const cursor: SinkCursor = {
    chain_id: body.chain_id,
    key: body.key,
    next_seq: nextSeq,
    head_hash: body.head_hash,
  };
  if (typeof body.attested_seq === 'number' && Number.isInteger(body.attested_seq)) {
    cursor.attested_seq = body.attested_seq;
  }
  if (typeof body.attested_at === 'string') cursor.attested_at = body.attested_at;
  if (typeof body.max_records === 'number' && body.max_records > 0) {
    cursor.max_records = Math.floor(body.max_records);
  }
  if (typeof body.max_bytes === 'number' && body.max_bytes > 0) {
    cursor.max_bytes = Math.floor(body.max_bytes);
  }
  if (typeof body.heartbeat_interval_s === 'number' && body.heartbeat_interval_s > 0) {
    cursor.heartbeat_interval_s = Math.floor(body.heartbeat_interval_s);
  }
  return cursor;
}

/** Full jitter: delay = random() * min(cap, base * 2^attempt). */
export function backoffMs(
  attempt: number,
  random: () => number,
  base: number = BACKOFF_BASE_MS,
  cap: number = BACKOFF_CAP_MS,
): number {
  const exponent = Math.min(attempt, 30);
  return Math.floor(random() * Math.min(cap, base * 2 ** exponent));
}
