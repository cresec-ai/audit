/**
 * Hashing + canonicalization primitives. Foundational and FROZEN: every other
 * module (redaction refs, chain hashes, verify, export) depends on these
 * producing byte-identical output forever.
 */
import type { AnyEvent, ChainRecord } from '../schema/events.js';
import type { ChainHead } from '../types.js';
/**
 * Deterministic JSON: object keys sorted lexicographically at every level,
 * no whitespace. Input must be JSON-safe (events are, by construction).
 * - undefined object values are dropped (like JSON.stringify)
 * - undefined array elements become null (like JSON.stringify)
 * - non-finite numbers become null (like JSON.stringify)
 */
export declare function canonicalJson(value: unknown): string;
/** Lowercase hex SHA-256. */
export declare function sha256Hex(data: string | Uint8Array): string;
/** `sha256:<hex>` ref of a string value — the RedactedRef format. */
export declare function sha256Ref(value: string): string;
/** Chain anchor for seq 1. */
export declare const GENESIS_HASH: string;
/** hash_n = sha256(prev_hash + "\n" + canonical_json(event)) */
export declare function computeHash(prevHash: string, event: AnyEvent): string;
/** Seal an event onto the given head, producing the next chain record. */
export declare function makeRecord(head: ChainHead, event: AnyEvent): ChainRecord;
/**
 * The exact bytes signed by the ed25519 key for a head signature. Domain
 * separated so a signature can never be confused with any other payload.
 */
export declare function signedPayload(seq: number, chainHash: string): Uint8Array;
