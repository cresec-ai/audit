/**
 * THE SHIPPER'S SELF-CHECK — verify your own history before extending
 * somebody else's copy of it.
 *
 * WHY THIS EXISTS. The shipper used to read forward from the receiver's
 * cursor and send, and never look at the records BEHIND that cursor again.
 * Local dogfood 6 turned that into a working attack with `cp -a` and one
 * edited field:
 *
 *   1. copy a data dir, rewrite the event at seq 7 in place and leave every
 *      stored `hash`/`prev_hash` untouched (so the copy's head hash still
 *      matches what the receiver holds);
 *   2. record a new session into the copy; its shipper cheerfully delivered
 *      seq 12-22, which the receiver accepted — they link to seq 11 exactly
 *      as the honest ones would;
 *   3. when the HONEST store later shipped its own seq 12, it was the one
 *      that got the `chain_fork` 409, and the receiver raised the alert
 *      "history was rewritten" AGAINST IT.
 *
 * Fork detection worked. Attribution was decided by arrival order. Nothing on
 * either side ever said that the copy's own store fails `verify`.
 *
 * WHAT THIS DOES. Before a batch goes on the wire, the shipper recomputes its
 * own chain from seq 1 up to the last record of that batch. A chain that does
 * not verify stalls — loudly, visibly in `ship --status`, and WITHOUT posting
 * the batch. Nothing is skipped and nothing is repaired; a stall keeps the
 * receiver's cursor frozen while the signed head climbs, which is the
 * explicit withholding condition the receiver already alerts on.
 *
 * WHAT IT COSTS, AND WHY IT IS SHAPED THIS WAY. A full `verifyStore` per
 * batch would be O(n) on every POST, and ed25519 is the expensive half:
 * measured on this repo's own code (Node 22, jsonl backend, 20 000 records),
 * the hash recomputation runs at ~15 us/record while ONE @noble/ed25519
 * verification costs ~2 ms. A store signed on every flush — which is what the
 * recorder does — holds roughly one signature per record, so verifying every
 * signature would cost ~2 ms/record: 40 s for a 20 000-record store, on every
 * shipper start. Two properties make that unnecessary:
 *
 *   - The chain hash at seq j is a running commitment over EVERY event at
 *     seq <= j. So recomputing the chain (cheap) and then checking a single
 *     genuine signature at seq j pins the whole prefix below j. Verifying the
 *     other signatures adds finer-grained blame, not coverage.
 *   - The work is monotonic per process: a `ChainSelfCheck` remembers how far
 *     it got, so the first batch pays for the history and every later batch
 *     pays only for its own records.
 *
 * Hence: recompute every record once (~15 us each), and verify ONE signature
 * per window — the newest that falls inside it. Measured end to end on the
 * same machine: a 20 000-record store's first pass takes ~0.4 s and a
 * 100 000-record one ~1.9 s, in a detached background process that is not on
 * anyone's forwarding path, against 4.1 s for `verifyStore` over the smaller
 * of the two. The follow-up pass for the next batch measured 3 ms.
 *
 * WHAT IT CATCHES, AND WHAT IT DOES NOT.
 *   - An event edited in place (hashes left alone): `hash_mismatch`. This is
 *     the dogfood-6 attack, and the reason this module exists.
 *   - An event edited AND the hashes re-linked forward, without the key: the
 *     newest signature in the window still attests the pre-rewrite chain
 *     hash, so `signature_chain_mismatch`. (In the already-delivered prefix
 *     the receiver's own `head_hash` also disagrees, which the shipper's
 *     existing head-hash guard reports as a fork.)
 *   - A record deleted from the middle, a duplicated seq, a truncated tail:
 *     `seq_gap` / `duplicate_seq` / `prev_hash_mismatch`.
 *   - It does NOT catch a rewrite made BELOW THE FRONTIER OF A SHIPPER THAT IS
 *     ALREADY RUNNING. The frontier is monotonic per process (that is what
 *     makes the steady state cheap), so a shipper that has already verified
 *     through seq N re-examines nothing at or below N. Measured: a shipper
 *     live since seq 17 shipped seq 18-21 out of a store whose seq 3 had been
 *     rewritten under it, reporting `idle`, while a shipper STARTED on that
 *     same store stalled at once with `hash_mismatch at seq 3`. The window is
 *     bounded by the process: every `record`/`http`/`hook` run starts a
 *     shipper afresh, and `--idle-exit` (15m by default) retires the old one.
 *     A rewrite is therefore caught on the next shipper start, not
 *     necessarily on the next batch. `mcp-recorder verify` is what renders a
 *     verdict on a store at any moment, and does so from seq 1 every time.
 *   - It does NOT catch a rewrite re-signed with `identity.key`. The signing
 *     oracle is on the attacker's side of the boundary (docs/sink.md, threat
 *     model, "a forged chain") and no local check can fix that.
 *   - A chain carrying no signatures at all is a warning here, not a stall:
 *     absence of a signature is not evidence of tampering, and the recorder
 *     can legitimately have been killed between an append and its flush's
 *     signature. `mcp-recorder verify` is the command that renders a verdict
 *     on that; the shipper only refuses to extend a chain it can prove is
 *     broken.
 */
import { GENESIS_HASH } from '../chain/hash.js';
import { verifyRecords } from '../verify/verify.js';
/**
 * Records recomputed per verification window. Bounds the working set (the
 * per-window map of recomputed hashes) and sets how many signature checks a
 * long pass makes: one per window, so a 1 000 000-record store costs 500
 * ed25519 verifications, about a second, not 1 000 000 of them.
 */
export const SELF_CHECK_WINDOW = 2_000;
/**
 * At most this many signatures checked per window. The recorder signs each
 * flush at a distinct head, so a window normally has ONE newest signature;
 * a pile of them sharing that seq is either a store written by something
 * else or an attempt to make the shipper burn ~2 ms of ed25519 per copy. The
 * coverage argument needs only one genuine signature at that seq, so the rest
 * are a matter for `mcp-recorder verify`, which checks every one.
 */
export const SELF_CHECK_MAX_SIGS_PER_WINDOW = 4;
export function newSelfCheck() {
    return { through: 0, hash: GENESIS_HASH };
}
/** One line, in the shape the receiver and `verify` already print. */
function describe(problem) {
    return `${problem.type} at seq ${String(problem.seq)}: ${problem.detail}`;
}
/**
 * Advance `self` so it covers every record through `toSeq`, verifying what it
 * has not verified yet. Returns `undefined` when the local chain verifies
 * that far, or a one-line description of the FIRST hard problem when it does
 * not. Warnings (an unsigned tail, a chain with no signatures) never stall.
 *
 * `batch` is the records the caller is about to ship, passed in so that the
 * bytes being verified are the very bytes going on the wire rather than a
 * re-read of them. Records below `batch[0].seq` are streamed from the store
 * in one pass.
 */
export async function advanceSelfCheck(store, self, toSeq, batch, opts = {}) {
    if (self.failure !== undefined)
        return self.failure;
    if (toSeq <= self.through)
        return undefined;
    const windowSize = Math.max(1, opts.windowSize ?? SELF_CHECK_WINDOW);
    const base = self.through;
    const fail = (detail) => {
        self.failure = detail;
        return detail;
    };
    /**
     * The newest signature of each window, in ONE pass over the store's
     * signatures — never a rescan per window, which is the shape that turns a
     * long chain's pass quadratic. Records in the range are contiguous
     * (anything else fails below), so the i-th of them has seq base + 1 + i and
     * therefore lives in window floor(i / windowSize).
     */
    const newestPerWindow = new Map();
    for (const sig of store.signatures()) {
        if (sig.seq <= base || sig.seq > toSeq)
            continue;
        const index = Math.floor((sig.seq - base - 1) / windowSize);
        const current = newestPerWindow.get(index);
        if (current === undefined || sig.seq > current.seq) {
            newestPerWindow.set(index, { seq: sig.seq, sigs: [sig] });
        }
        else if (sig.seq === current.seq && current.sigs.length < SELF_CHECK_MAX_SIGS_PER_WINDOW) {
            // Same seq more than once: check a few, not a thousand.
            current.sigs.push(sig);
        }
    }
    const batchFrom = batch.length > 0 ? batch[0].seq : toSeq + 1;
    const streamTo = Math.min(toSeq, batchFrom - 1);
    /** The unverified range, in one pass: store first, then the live batch. */
    function* source() {
        if (base + 1 <= streamTo)
            yield* store.iterate({ fromSeq: base + 1, toSeq: streamTo });
        for (const record of batch) {
            if (record.seq > base && record.seq <= toSeq)
                yield record;
        }
    }
    let window = [];
    let windowIndex = 0;
    const closeWindow = async () => {
        const first = window[0].seq;
        const last = window[window.length - 1].seq;
        if (first !== self.through + 1) {
            return fail(`seq_gap at seq ${String(self.through + 1)}: the local store no longer holds it, ` +
                `the chain jumps to seq ${String(first)}`);
        }
        const result = await verifyRecords(window, newestPerWindow.get(windowIndex)?.sigs ?? [], {
            baseHash: self.hash,
            // A window is a SEGMENT of the chain, so "no signature in this window"
            // is ordinary, not a verdict. Signature problems that ARE evidence
            // (wrong key, a genuine signature over a hash the chain no longer
            // recomputes to) stay hard failures.
            allowUnsigned: true,
            ...(opts.expectedPublicKeyHex !== undefined
                ? { expectedPublicKeyHex: opts.expectedPublicKeyHex }
                : {}),
        });
        const hard = result.problems.find((problem) => problem.warning !== true);
        if (hard !== undefined)
            return fail(describe(hard));
        if (result.head.seq !== last) {
            // verifyRecords only walks records it was given; a window whose tail
            // was unusable must not advance the frontier past it.
            return fail(`malformed_record at seq ${String(result.head.seq + 1)}: the record could not be ` +
                'read as part of the chain');
        }
        self.through = result.head.seq;
        self.hash = result.head.hash;
        window = [];
        windowIndex++;
        opts.onWindow?.();
        return undefined;
    };
    for (const record of source()) {
        window.push(record);
        if (window.length >= windowSize) {
            const problem = await closeWindow();
            if (problem !== undefined)
                return problem;
        }
    }
    if (window.length > 0) {
        const problem = await closeWindow();
        if (problem !== undefined)
            return problem;
    }
    if (self.through < toSeq) {
        return fail(`seq_gap at seq ${String(self.through + 1)}: the local store stops at seq ` +
            `${String(self.through)} but seq ${String(toSeq)} was about to ship`);
    }
    return undefined;
}
//# sourceMappingURL=selfcheck.js.map