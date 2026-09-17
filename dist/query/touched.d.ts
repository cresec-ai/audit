/**
 * Blast-radius query — "what did this value touch?"
 *
 * The store never holds plaintext payloads, only unsalted SHA-256 refs, so a
 * known probe value (a leaked key, a customer email, ...) can be traced by
 * hashing it the exact same way and walking the chain for matching refs.
 *
 * Match locations, in preference order (one match per event):
 *   ref         — a RedactedRef leaf whose ref equals sha256(needle), OR whose
 *                 secret_refs contains sha256(needle) (a token embedded in a
 *                 larger leaf), OR an object KEY that was itself hashed to
 *                 sha256(needle)
 *   result_hash — the event's result_hash equals sha256(needle)
 *   args_hash   — a policy_decision's args_hash equals sha256(needle), i.e.
 *                 the needle is the canonical JSON of the arguments of a call
 *                 the gateway denied or held (gateway mode; those arguments
 *                 exist nowhere else in clear)
 *   credential  — an identity credential fingerprint equals sha256(needle)
 *   name        — tool / method / server.name equals the needle (case-insensitive)
 *   plain       — a plain string leaf contains the needle (case-sensitive)
 *
 * A `ref` miss is not proof of absence: secret_refs only covers tokens that
 * matched a known alwaysPatterns shape, and a plain-string miss is limited
 * to whatever wasn't itself redacted.
 */
import type { EvidenceStore, QueryResult } from '../types.js';
/**
 * Trace a value through the evidence chain. One QueryMatch per touched event
 * (the strongest match location wins); sessions are the distinct sessions
 * touched, newest first.
 */
export declare function queryStore(store: EvidenceStore, needle: string, opts?: {
    sessionId?: string;
}): QueryResult;
