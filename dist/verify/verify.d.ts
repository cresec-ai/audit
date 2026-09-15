/**
 * Chain verification — the read side of the tamper-evidence story (M2).
 *
 * `verifyRecords` walks a (segment of a) hash chain and the head signatures
 * over it, collecting EVERY problem it finds rather than stopping at the
 * first: an auditor wants the full damage report, not just the first symptom.
 *
 * Problem taxonomy (see VerifyProblemType in src/types.ts):
 *   - structural:  malformed_record, bad_genesis, seq_gap, duplicate_seq,
 *                  prev_hash_mismatch
 *   - content:     hash_mismatch (any edited event re-hashes differently)
 *   - signatures:  signature_invalid, signature_chain_mismatch,
 *                  truncated_after_signature (tail deletion's smoking gun)
 *   - warning:     unsigned_tail (events newer than the newest valid
 *                  signature — possible on crash, not a tamper verdict)
 */
import type { ChainRecord, HeadSignature } from '../schema/events.js';
import type { EvidenceStore, VerifyResult } from '../types.js';
export interface VerifyOpts {
    /**
     * prev_hash anchor the first record must link to. Defaults to GENESIS_HASH
     * (whole-chain verification); pass the hash of seq N-1 to verify a segment
     * starting at seq N (e.g. an exported bundle's base_hash).
     */
    baseHash?: string;
    /** When set, signatures by any other key are reported signature_invalid. */
    expectedPublicKeyHex?: string;
    /**
     * Downgrade 'no_valid_signature' and 'unsigned_session_end' from failures
     * to warnings (ok stays true). Off by default: a chain with events but no
     * signature anyone can attribute to a key proves nothing, and a session_end
     * in the unsigned tail means a signature that should exist (the recorder
     * signs on every flush, including session_end) is missing outright, not
     * merely pending the next flush.
     */
    allowUnsigned?: boolean;
}
/**
 * Verify a contiguous run of chain records plus the head signatures over it.
 * Collects all problems; `ok` is true only when every problem is a warning.
 */
export declare function verifyRecords(records: Iterable<ChainRecord>, signatures: HeadSignature[], opts?: VerifyOpts): Promise<VerifyResult>;
/** Verify everything an evidence store holds (whole chain + all signatures). */
export declare function verifyStore(store: EvidenceStore, opts?: VerifyOpts): Promise<VerifyResult>;
