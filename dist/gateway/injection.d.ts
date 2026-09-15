/**
 * Gateway boundary filter — prompt-injection marker patterns.
 *
 * Tool results flow server -> client and are read by the model, so a
 * malicious document, web page or file can carry instructions aimed at the
 * agent rather than at the user. This module holds the CONSERVATIVE, fixed
 * list of textual markers the gateway treats as "suspected prompt
 * injection" and a pure `findInjectionSpans()` that locates them.
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
 * Locate every injection marker in `text`. Returns merged, sorted,
 * non-overlapping spans. Never throws; non-string input yields `[]`, and
 * text beyond `MAX_SCAN_CHARS` is not examined.
 */
export declare function findInjectionSpans(text: string): Span[];
