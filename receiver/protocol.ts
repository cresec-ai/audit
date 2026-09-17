/**
 * The sink wire contract, receiver side.
 *
 * This module is DATA ONLY: the constants, the domain-separated signing
 * payload, the derived identifiers, and the shapes that cross the wire. It
 * imports nothing but `src/chain/hash.ts` (frozen) and the frozen event
 * schema types, so the sending half can adopt it verbatim.
 *
 * NOTE FOR INTEGRATION: when the sender (`mcp-recorder ship`) lands, this
 * file should be promoted to a single shared module both halves import —
 * duplicating the domain separator or the header names in two places is
 * exactly how a protocol drifts. See receiver/README.md.
 *
 * Two derived identifiers, both computable from today's code with zero
 * schema change:
 *   key      = the 64-hex ed25519 public key from <data-dir>/identity.pub
 *              (Signer.publicKeyHex). One per data dir, therefore one per
 *              chain.
 *   chain_id = the `hash` of chain record seq 1, i.e.
 *              sha256Hex(GENESIS_HASH + "\n" + canonicalJson(event_1)).
 *              Unique per chain INSTANCE because event_1 carries a v4
 *              event_id. This is what turns "identity.key survived while
 *              evidence.db was deleted" from a silent seq-1 restart under
 *              the same key into a visible second chain for an enrolled key.
 */

import { GENESIS_HASH } from '../src/chain/hash.js';
import type { ChainRecord, HeadSignature } from '../src/schema/events.js';

/** `X-MCPR-Protocol`. Bumped only for a breaking wire change. */
export const SINK_PROTOCOL_VERSION = 1;

/**
 * Domain separator for the per-request signature. Deliberately DIFFERENT
 * from `edut.mcp-recorder.head.v1` (src/chain/hash.ts `signedPayload`) so a
 * request signature can never be replayed as a head signature or vice versa.
 */
export const SINK_SIGNATURE_DOMAIN = 'edut.mcp-recorder.sink.v1';

/** Lowercase header names, as `node:http` delivers them. */
export const HEADERS = {
  PROTOCOL: 'x-mcpr-protocol',
  KEY: 'x-mcpr-key',
  CONTENT_SHA256: 'x-mcpr-content-sha256',
  SIGNATURE: 'x-mcpr-signature',
  SENT_AT: 'x-mcpr-sent-at',
  /**
   * `<from_seq>-<to_seq>`. NOT in the original contract — see the "one
   * deviation" section of receiver/README.md. It is what lets the request
   * signature be verified strictly BEFORE any JSON parsing, because the
   * signed payload names from_seq/to_seq and those otherwise live only in
   * the body. Optional: a sender that omits it still interoperates (the
   * receiver then extracts the two integers from the size-capped body
   * before verifying), unless the receiver runs with `requireRangeHeader`.
   */
  RANGE: 'x-mcpr-range',
  IDEMPOTENCY: 'idempotency-key',
} as const;

export const HEX64 = /^[0-9a-f]{64}$/;
export const HEX128 = /^[0-9a-f]{128}$/;

/**
 * The exact bytes an install's ed25519 key signs for one POST:
 *   edut.mcp-recorder.sink.v1\n<chain_id>\n<from_seq>\n<to_seq>\n<content_sha256_hex>
 *
 * `content_sha256_hex` is over the DECOMPRESSED body bytes, deliberately: a
 * TLS-terminating corporate proxy or the Anthropic agent proxy may re-encode
 * the transfer, and hashing the compressed octets would break the signature
 * on a working path.
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

/**
 * `chain_id` of the chain a seq-1 record opens. Throws when handed anything
 * that is not a genesis record — the caller has then been given a record it
 * cannot derive an identity from, and must not guess one.
 */
export function chainIdFromGenesisRecord(record: ChainRecord): string {
  if (record.seq !== 1) {
    throw new Error(`chain_id is derived from seq 1, got seq ${record.seq}`);
  }
  if (record.prev_hash !== GENESIS_HASH) {
    throw new Error('seq 1 record does not link to GENESIS_HASH');
  }
  return record.hash;
}

/** The sender's current local head, signed with its own key. */
export interface SinkHead {
  seq: number;
  hash: string;
  signature: HeadSignature;
}

/**
 * Advisory, never authoritative — the receiver stores it for operator
 * convenience and bases no decision on it.
 */
export interface SinkSender {
  tool_version?: string;
  surface?: string;
  backend?: string;
}

/** POST /v1/chains/{chain_id}/records body. */
export interface RecordsBatch {
  protocol: number;
  chain_id: string;
  key: string;
  from_seq: number;
  to_seq: number;
  base_hash: string;
  records: ChainRecord[];
  signatures: HeadSignature[];
  head: SinkHead;
  sender?: SinkSender;
}

/** Returned by 200, 202 and both flavours of 409. */
export interface SinkCursor {
  chain_id: string;
  key: string;
  /** First seq the receiver does not have. THE authoritative resume point. */
  next_seq: number;
  /** Receiver's hash at next_seq - 1 (GENESIS_HASH when next_seq === 1). */
  head_hash: string;
  /** Highest seq covered by a signature the receiver itself verified. */
  attested_seq: number;
  /** When that signature was accepted; null when nothing is attested yet. */
  attested_at: string | null;
  max_records: number;
  max_bytes: number;
  heartbeat_interval_s: number;
}

/**
 * Every way a POST can be refused. These are the strings an operator greps
 * for and the strings the sender switches on, so they are part of the
 * contract, not log text.
 */
export type SinkErrorCode =
  | 'bad_request'
  | 'unauthorized'
  | 'forbidden'
  | 'chain_gap'
  | 'chain_fork'
  | 'too_large'
  | 'rate_limited'
  | 'internal';

export interface SinkErrorBody {
  error: SinkErrorCode;
  /**
   * Why, in one line, for a human reading `ship --status` or the receiver's
   * rejection log. A sender must branch on `error`, never on this.
   */
  detail: string;
  /** Present on both 409s (and on any refusal where it is knowable). */
  cursor?: SinkCursor;
  /** Present on 413. */
  max_records?: number;
  max_bytes?: number;
}

/** A heartbeat is the same POST with no records and a signed head. */
export function isHeartbeat(batch: Pick<RecordsBatch, 'from_seq' | 'to_seq' | 'records'>): boolean {
  return batch.from_seq === 0 && batch.to_seq === 0 && batch.records.length === 0;
}
