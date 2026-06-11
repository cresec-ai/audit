/**
 * Hashing + canonicalization primitives. Foundational and FROZEN: every other
 * module (redaction refs, chain hashes, verify, export) depends on these
 * producing byte-identical output forever.
 */

import { createHash } from 'node:crypto';
import type { AnyEvent, ChainRecord } from '../schema/events.js';
import type { ChainHead } from '../types.js';

/**
 * Deterministic JSON: object keys sorted lexicographically at every level,
 * no whitespace. Input must be JSON-safe (events are, by construction).
 * - undefined object values are dropped (like JSON.stringify)
 * - undefined array elements become null (like JSON.stringify)
 * - non-finite numbers become null (like JSON.stringify)
 */
export function canonicalJson(value: unknown): string {
  if (value === null || value === undefined) return 'null';
  const t = typeof value;
  if (t === 'number') return Number.isFinite(value as number) ? JSON.stringify(value) : 'null';
  if (t === 'string' || t === 'boolean') return JSON.stringify(value);
  if (Array.isArray(value)) {
    return '[' + value.map((v) => (v === undefined ? 'null' : canonicalJson(v))).join(',') + ']';
  }
  if (t === 'object') {
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj)
      .filter((k) => obj[k] !== undefined)
      .sort();
    return '{' + keys.map((k) => JSON.stringify(k) + ':' + canonicalJson(obj[k])).join(',') + '}';
  }
  throw new TypeError(`canonicalJson: unsupported type ${t}`);
}

/** Lowercase hex SHA-256. */
export function sha256Hex(data: string | Uint8Array): string {
  return createHash('sha256').update(data).digest('hex');
}

/** `sha256:<hex>` ref of a string value — the RedactedRef format. */
export function sha256Ref(value: string): string {
  return 'sha256:' + sha256Hex(value);
}

/** Chain anchor for seq 1. */
export const GENESIS_HASH: string = sha256Hex('edut.mcp-recorder.genesis.v1');

/** hash_n = sha256(prev_hash + "\n" + canonical_json(event)) */
export function computeHash(prevHash: string, event: AnyEvent): string {
  return sha256Hex(prevHash + '\n' + canonicalJson(event));
}

/** Seal an event onto the given head, producing the next chain record. */
export function makeRecord(head: ChainHead, event: AnyEvent): ChainRecord {
  const prev_hash = head.seq === 0 ? GENESIS_HASH : head.hash;
  return {
    seq: head.seq + 1,
    prev_hash,
    hash: computeHash(prev_hash, event),
    event,
  };
}

/**
 * The exact bytes signed by the ed25519 key for a head signature. Domain
 * separated so a signature can never be confused with any other payload.
 */
export function signedPayload(seq: number, chainHash: string): Uint8Array {
  return new TextEncoder().encode(`edut.mcp-recorder.head.v1\n${seq}\n${chainHash}`);
}
