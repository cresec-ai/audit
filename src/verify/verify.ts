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

import * as ed from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha512';
import { GENESIS_HASH, computeHash, signedPayload } from '../chain/hash.js';
import type { ChainRecord, HeadSignature } from '../schema/events.js';
import type {
  ChainHead,
  EvidenceStore,
  VerifyProblem,
  VerifyResult,
} from '../types.js';

// @noble/ed25519 v2 ships hash-less; wire sha512 so sync verify works
// everywhere. Same wiring as src/chain/keys.ts — plain re-assignment is fine.
ed.etc.sha512Sync = (...m: Uint8Array[]) => sha512(ed.etc.concatBytes(...m));

const HEX64 = /^[0-9a-f]{64}$/;
const HEX128 = /^[0-9a-f]{128}$/;

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

/** Structural validation of one ChainRecord; returns field names in error. */
function malformedFields(record: ChainRecord): string[] {
  if (typeof record !== 'object' || record === null) return ['record'];
  const bad: string[] = [];
  const r = record as unknown as Record<string, unknown>;
  if (typeof r.seq !== 'number' || !Number.isInteger(r.seq) || r.seq < 1) bad.push('seq');
  if (typeof r.prev_hash !== 'string' || !HEX64.test(r.prev_hash)) bad.push('prev_hash');
  if (typeof r.hash !== 'string' || !HEX64.test(r.hash)) bad.push('hash');
  if (typeof r.event !== 'object' || r.event === null || Array.isArray(r.event)) bad.push('event');
  return bad;
}

/** Shape check before attempting cryptographic verification. */
function malformedSignature(sig: HeadSignature): string | undefined {
  if (typeof sig !== 'object' || sig === null) return 'signature entry is not an object';
  if (typeof sig.seq !== 'number' || !Number.isInteger(sig.seq) || sig.seq < 1) {
    return 'invalid seq';
  }
  if (typeof sig.chain_hash !== 'string' || !HEX64.test(sig.chain_hash)) {
    return 'invalid chain_hash';
  }
  if (sig.algo !== 'ed25519') return `unsupported algo ${String(sig.algo)}`;
  if (typeof sig.public_key !== 'string' || !HEX64.test(sig.public_key)) {
    return 'invalid public_key';
  }
  if (typeof sig.signature !== 'string' || !HEX128.test(sig.signature)) {
    return 'invalid signature hex';
  }
  return undefined;
}

/**
 * Verify a contiguous run of chain records plus the head signatures over it.
 * Collects all problems; `ok` is true only when every problem is a warning.
 */
export async function verifyRecords(
  records: Iterable<ChainRecord>,
  signatures: HeadSignature[],
  opts: VerifyOpts = {},
): Promise<VerifyResult> {
  const baseHash = opts.baseHash ?? GENESIS_HASH;
  const problems: VerifyProblem[] = [];

  /** Recomputed chain hash per seq — what each signature is checked against. */
  const recomputedBySeq = new Map<number, string>();
  /** seqs of well-formed session_end records, ascending — for the tail check below. */
  const sessionEndSeqs: number[] = [];
  let prev: ChainRecord | undefined;
  let checked = 0;

  for (const record of records) {
    const bad = malformedFields(record);
    if (bad.length > 0) {
      const seq =
        typeof (record as unknown as { seq?: unknown })?.seq === 'number' ? record.seq : 0;
      problems.push({
        type: 'malformed_record',
        seq,
        detail: `missing/invalid field(s): ${bad.join(', ')}`,
      });
      continue; // structurally unusable — skip the chain checks for this one
    }
    checked++;
    if (record.event.kind === 'session_end') sessionEndSeqs.push(record.seq);

    if (prev === undefined) {
      if (record.prev_hash !== baseHash) {
        problems.push({
          type: 'bad_genesis',
          seq: record.seq,
          detail: `first record prev_hash ${record.prev_hash} does not match the expected anchor ${baseHash}`,
        });
      }
    } else {
      if (record.seq <= prev.seq) {
        problems.push({
          type: 'duplicate_seq',
          seq: record.seq,
          detail: `seq ${record.seq} repeats or goes backwards after seq ${prev.seq}`,
        });
      } else if (record.seq !== prev.seq + 1) {
        problems.push({
          type: 'seq_gap',
          seq: record.seq,
          detail: `expected seq ${prev.seq + 1} after ${prev.seq}, found ${record.seq} (${record.seq - prev.seq - 1} record(s) missing)`,
        });
      }
      if (record.prev_hash !== prev.hash) {
        problems.push({
          type: 'prev_hash_mismatch',
          seq: record.seq,
          detail: `prev_hash ${record.prev_hash} does not match hash ${prev.hash} of seq ${prev.seq}`,
        });
      }
    }

    // Content check: re-derive the chain hash from this record's own
    // prev_hash + event. Any edit to the stored event lands here.
    try {
      const recomputed = computeHash(record.prev_hash, record.event);
      recomputedBySeq.set(record.seq, recomputed);
      if (recomputed !== record.hash) {
        problems.push({
          type: 'hash_mismatch',
          seq: record.seq,
          detail: `stored hash ${record.hash} != recomputed ${recomputed} — the event was altered`,
        });
      }
    } catch (err) {
      problems.push({
        type: 'malformed_record',
        seq: record.seq,
        detail: `event cannot be canonicalized: ${(err as Error).message}`,
      });
    }

    prev = record;
  }

  const head: ChainHead =
    prev === undefined ? { seq: 0, hash: baseHash } : { seq: prev.seq, hash: prev.hash };

  // ------------------------------ signatures ------------------------------
  let verified: HeadSignature | undefined;
  // A genuine signature that names a seq/hash the chain doesn't (currently)
  // have is its own unconditional failure (truncation or a rewritten tail
  // behind a real signature) — don't also report the weaker
  // no_valid_signature/unsigned_session_end verdicts for the same cause.
  let sawChainMismatchOrTruncation = false;

  for (const sig of signatures) {
    const shapeIssue = malformedSignature(sig);
    if (shapeIssue !== undefined) {
      problems.push({
        type: 'signature_invalid',
        seq: typeof (sig as unknown as { seq?: unknown })?.seq === 'number' ? sig.seq : 0,
        detail: `malformed signature: ${shapeIssue}`,
      });
      continue;
    }
    if (
      opts.expectedPublicKeyHex !== undefined &&
      sig.public_key !== opts.expectedPublicKeyHex.toLowerCase()
    ) {
      const expected = opts.expectedPublicKeyHex.toLowerCase();
      problems.push({
        type: 'signature_invalid',
        seq: sig.seq,
        detail: `signed by unexpected key ${sig.public_key.slice(0, 16)}…, expected ${expected.slice(0, 16)}… — this signature was not made by the pinned key`,
      });
      continue;
    }

    let cryptoValid = false;
    try {
      cryptoValid = ed.verify(
        ed.etc.hexToBytes(sig.signature),
        signedPayload(sig.seq, sig.chain_hash),
        ed.etc.hexToBytes(sig.public_key),
      );
    } catch {
      cryptoValid = false;
    }
    if (!cryptoValid) {
      problems.push({
        type: 'signature_invalid',
        seq: sig.seq,
        detail: 'ed25519 verification failed for the signed head payload',
      });
      continue;
    }

    // The signature itself is genuine. Now: does the chain still contain the
    // head it attested to?
    if (sig.seq > head.seq) {
      problems.push({
        type: 'truncated_after_signature',
        seq: sig.seq,
        detail: `a valid signature attests seq ${sig.seq}, but the chain ends at seq ${head.seq} — records were deleted from the tail`,
      });
      sawChainMismatchOrTruncation = true;
      continue;
    }
    const recomputed = recomputedBySeq.get(sig.seq);
    if (recomputed === undefined) {
      problems.push({
        type: 'signature_chain_mismatch',
        seq: sig.seq,
        detail: `a valid signature attests seq ${sig.seq}, but no record with that seq exists in the chain`,
      });
      sawChainMismatchOrTruncation = true;
      continue;
    }
    if (recomputed !== sig.chain_hash) {
      problems.push({
        type: 'signature_chain_mismatch',
        seq: sig.seq,
        detail: `a valid signature attests hash ${sig.chain_hash} at seq ${sig.seq}, but the chain recomputes to ${recomputed}`,
      });
      sawChainMismatchOrTruncation = true;
      continue;
    }

    // Fully valid: genuine signature AND it matches the recomputed chain.
    if (verified === undefined || sig.seq >= verified.seq) verified = sig;
  }

  // Tail newer than the newest fully-valid signature (or never signed at
  // all). Three cases, from weakest to strongest signal:
  //   - a signed prefix with a plain unsigned tail (no session_end in it):
  //     not a tamper verdict — flushes can outrun head signing on a crash —
  //     stays a warning (ok can still be true).
  //   - NO valid signature attests any part of the chain: a chain nobody can
  //     be shown to have signed proves nothing. Hard failure by default.
  //   - the unsigned tail contains a session_end event: the recorder signs
  //     on every flush INCLUDING the session_end flush (concurrent recorder
  //     processes interleave sessions in one chain, so this is "ANY
  //     session_end in the tail", not just the latest session's). A missing
  //     signature here is not a pending flush, it's a signature that should
  //     exist and doesn't. Hard failure by default.
  // Both hard failures downgrade to warnings with --allow-unsigned
  // (opts.allowUnsigned). Skipped entirely when a genuine signature already
  // named a truncation/rewrite the chain can't account for — that's its own
  // unconditional, non-downgradable failure above.
  if (head.seq > 0 && !sawChainMismatchOrTruncation) {
    const tailStartSeq = (verified?.seq ?? 0) + 1;
    const tailHasSessionEnd = sessionEndSeqs.some((seq) => seq >= tailStartSeq);
    const warnOpt = opts.allowUnsigned === true ? { warning: true as const } : {};

    if (verified === undefined) {
      problems.push({
        type: 'no_valid_signature',
        seq: head.seq,
        detail: `${checked} event(s) recorded, but no valid head signature attests any of this chain`,
        ...warnOpt,
      });
      if (tailHasSessionEnd) {
        problems.push({
          type: 'unsigned_session_end',
          seq: head.seq,
          detail:
            'the chain includes a session_end event with no valid signature covering it — ' +
            'the recorder signs on every flush, including session_end, so this signature is ' +
            'missing outright, not merely pending',
          ...warnOpt,
        });
      }
    } else if (verified.seq < head.seq) {
      if (tailHasSessionEnd) {
        problems.push({
          type: 'unsigned_session_end',
          seq: head.seq,
          detail:
            `events after seq ${verified.seq} (through ${head.seq}) are unsigned and include a ` +
            'session_end event — the recorder signs on every flush, including session_end, so ' +
            'this signature is missing outright, not merely pending',
          ...warnOpt,
        });
      } else {
        problems.push({
          type: 'unsigned_tail',
          seq: head.seq,
          detail: `events after seq ${verified.seq} (through ${head.seq}) are newer than the newest valid signature`,
          warning: true,
        });
      }
    }
  }

  const result: VerifyResult = {
    ok: problems.every((p) => p.warning === true),
    checked_events: checked,
    head,
    problems,
  };
  if (verified !== undefined) result.verified_signature = verified;
  return result;
}

/** Verify everything an evidence store holds (whole chain + all signatures). */
export async function verifyStore(
  store: EvidenceStore,
  opts: VerifyOpts = {},
): Promise<VerifyResult> {
  return verifyRecords(store.iterate(), store.signatures(), opts);
}
