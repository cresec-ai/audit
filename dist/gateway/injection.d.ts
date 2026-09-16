/**
 * Gateway boundary filter — prompt-injection marker patterns.
 *
 * Tool results flow server -> client and are read by the model, so a
 * malicious document, web page or file can carry instructions aimed at the
 * agent rather than at the user. This module holds the CONSERVATIVE, fixed
 * list of textual markers the gateway treats as "suspected prompt
 * injection" and a pure `findInjectionSpans()` that locates them.
 *
 * Scanning happens on a NORMALIZED COPY of the text (`normalizeForScan()`):
 * invisible characters are dropped (every `Default_Ignorable_Code_Point` and
 * every `\p{Cf}` format character — which is all of Bidi_Control — plus
 * U+034F), NFKC folds homoglyph look-alikes (fullwidth, mathematical, compatibility forms) onto their
 * ASCII equivalents, and whitespace runs collapse to one space. Every span
 * is mapped back onto the ORIGINAL text before it is returned, so callers
 * report and redact exactly the original bytes and nothing else.
 *
 * Out of scope (documented in docs/policy.md): base64-encoded instructions
 * and keywords split by markdown or HTML markup are NOT decoded or
 * un-marked-up before scanning.
 *
 * Invariants:
 *  - Every pattern is case-insensitive, carries no `g`/`y` flag (no
 *    lastIndex state leaks between calls; the scanner clones with `g`), uses
 *    no nested quantifiers and bounds every open-ended repetition, so a
 *    1 MiB input scans in linear-ish time with no catastrophic backtracking.
 *  - The list is deliberately short and precise: the default policy action
 *    for injection is `flag`, but `redact`/`block` rewrite what the model
 *    sees, so a false positive costs real tool output. Each entry documents
 *    its intended true positives and its known false positives.
 *  - Normalization only ever finds MORE markers; it never moves or widens a
 *    span beyond the original characters the normalized match came from.
 *  - Pure: no I/O, no throwing on any string input.
 */
/** A located marker: `[start, end)` character offsets into the scanned text. */
export interface Span {
    start: number;
    end: number;
    /** Identifier of the pattern (or, for merged spans, of the first one). */
    id: string;
}
/** One documented marker family. */
export interface InjectionPattern {
    /** Stable identifier recorded in reports/events. */
    id: string;
    /** Case-insensitive, non-global, bounded-repetition regex. */
    re: RegExp;
    /** What it is meant to catch and what it is known to mis-catch. */
    note: string;
}
/**
 * The marker list. Order is irrelevant for matching (all patterns run);
 * ids are stable and appear in `gateway.boundary` reports.
 */
export declare const INJECTION_PATTERNS: ReadonlyArray<InjectionPattern>;
/**
 * Every match of `re` in `text` as a span, using a global clone so the
 * caller's regex keeps no lastIndex state. Zero-length matches are skipped
 * (and can never loop forever).
 */
export declare function matchSpans(re: RegExp, text: string, id: string): Span[];
/**
 * Sort spans by start (then by longer first) and merge STRICTLY overlapping
 * ones into their union, keeping the earliest span's id. Touching spans
 * (`a.end === b.start`) stay separate so each stays one token.
 */
export declare function mergeSpans(spans: readonly Span[]): Span[];
/**
 * One stretch of the normalized text and the original characters it came
 * from. `identity` runs map 1:1 in order (the overwhelmingly common case and
 * the only one where an interior offset is meaningful); a non-identity run
 * is a fold or a collapse, and any offset inside it maps to the run's whole
 * original range.
 */
interface Run {
    /** Start offset in the normalized text. */
    n: number;
    /** Length in the normalized text (always >= 1). */
    nLen: number;
    /** Start offset in the original text. */
    o: number;
    /** Length in the original text. */
    oLen: number;
    identity: boolean;
}
/** A normalized copy of some text plus the mapping back to the original. */
export interface NormalizedScan {
    /** The text the marker patterns run against. */
    text: string;
    /** True when `text` differs from the original (a mapping was needed). */
    changed: boolean;
    /** Present only when `changed`; ordered, contiguous in both coordinates. */
    runs?: Run[];
}
/**
 * Build the normalized copy of `original` used for marker scanning, together
 * with the run mapping that puts spans back on the original text. Pure and
 * total: any string is accepted, nothing throws.
 */
export declare function normalizeForScan(original: string): NormalizedScan;
/**
 * Locate every injection marker in `text`. Returns merged, sorted,
 * non-overlapping spans ON THE ORIGINAL TEXT. Scanning runs on the
 * normalized copy (see `normalizeForScan`), so markers hidden behind
 * zero-width characters or NFKC-foldable homoglyphs are found too. Never
 * throws; non-string input yields `[]`, and text beyond `MAX_SCAN_CHARS` is
 * not examined.
 */
export declare function findInjectionSpans(text: string): Span[];
export {};
