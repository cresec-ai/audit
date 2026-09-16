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
 * invisible characters are dropped (every `Default_Ignorable_Code_Point`,
 * every `\p{Cf}` format character — which is all of Bidi_Control — every
 * `\p{Cc}` control character except the five whitespace ones, whole ANSI CSI
 * escape sequences, plus U+034F), NFKC folds homoglyph look-alikes
 * (fullwidth, mathematical, compatibility forms) onto their ASCII
 * equivalents, and whitespace runs collapse to one space. Text carrying
 * combining marks is scanned a SECOND time on a copy folded with NFKD and
 * stripped of `\p{Mn}`/`\p{Me}`, and the two span sets are unioned. Every
 * span is mapped back onto the ORIGINAL text before it is returned, so
 * callers report and redact exactly the original bytes and nothing else.
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
 * Default cap on scanned characters, for a caller that passes no budget of
 * its own. It used to be a HARD cap: `max_scan_bytes` goes to 64 MiB, the
 * secret scanner honoured it, and this one stopped at 1 MiB and still
 * reported `scanned: true` — so a marker at offset 1,048,600 was delivered
 * with `injection_found: 0` while the secret three words later in the same
 * string was found and redacted. The boundary now passes its own
 * `max_scan_bytes`, which it has already enforced on the whole line, so the
 * limit never binds there and nothing is silently unscanned.
 */
export declare const MAX_SCAN_CHARS = 1048576;
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
    /**
     * Present (and `true`) only when some character of the input carries a
     * combining mark — itself an `Mn`/`Me`, or a precomposed character whose
     * NFKD decomposition contains one. It is the trigger for the SECOND,
     * marks-dropped copy in `findInjectionSpans`; text without a mark (the
     * overwhelmingly common case) never pays for that pass.
     */
    sawMark?: true;
    /**
     * Present (and `true`) when an ANSI escape sequence carrying TEXT was
     * consumed. That copy is the RENDERED view — a terminal shows none of the
     * sequence — and a model reading the raw bytes sees the payload of an OSC
     * or DCS string, so `findInjectionSpans` scans the raw view as well. Text
     * with no escape sequence in it never pays for that pass.
     */
    sawEscapeText?: true;
}
/** Options for {@link normalizeForScan}. */
export interface NormalizeOptions {
    /**
     * Fold with NFKD and drop every combining mark (`\p{Mn}`/`\p{Me}`) instead
     * of folding with NFKC. `i̇gnore` (i + COMBINING DOT ABOVE) and `ignoré`
     * (a precomposed é) both become `ignore` in this copy, so a marker hidden
     * behind stacked or substituted accents is still found. Used for the
     * second scan copy only — a mark is a VISIBLE character, so dropping it
     * unconditionally would fold distinct words together for everybody.
     */
    dropMarks?: boolean;
    /**
     * Keep the TEXT an escape sequence carries: the data string of an OSC,
     * DCS, APC, PM or SOS, and the final byte of a bare two-character escape.
     * CSI and the intermediate-form escapes are consumed as usual.
     *
     * The default copy is the RENDERED view — a terminal shows none of a
     * sequence — and consuming one therefore also removes text a model reading
     * the bytes still sees: a marker inside an OSC data string disappears from
     * the scan, and a stray ESC in front of a marker letter takes that letter
     * with it (`instr<ESC>uctions` scans as `instrctions`). This copy keeps
     * exactly those two, so neither view can hide what the other shows, and
     * the two agree everywhere else — which is why ordinary coloured output,
     * all CSI, never pays for a second pass.
     */
    keepEscapeText?: boolean;
}
/**
 * Characters removed outright, as ONE code point each (not one UTF-16 unit:
 * the plane-14 tag characters U+E0000–U+E0FFF are astral).
 *
 * The set is Unicode's own answer to "renders as nothing", not a hand-kept
 * list of ranges: `Default_Ignorable_Code_Point` (zero-width space/joiners,
 * the LTR/RTL marks, SOFT HYPHEN U+00AD, the variation selectors U+FE00–
 * U+FE0F, the Hangul fillers, the tag characters, the BOM) united with every
 * format character `\p{Cf}` (the bidi embedding/override controls U+202A–
 * U+202E, the bidi ISOLATES U+2066–U+2069, the ARABIC LETTER MARK U+061C,
 * the Arabic number signs, the interlinear-annotation anchors). Both
 * properties are available in V8 on Node 20+, this repo's floor.
 *
 * U+034F COMBINING GRAPHEME JOINER is named explicitly. It is `Mn`, so
 * `\p{Cf}` does not reach it, and while it is default-ignorable today that
 * is a DERIVED property this security check should not silently depend on.
 *
 * Hand-kept ranges covered five of these families and missed the rest, so an
 * identical marker carrying U+061C, U+2066, U+00AD, U+FE0F, U+E0061 or
 * U+034F walked past the scanner that stopped U+200B and U+202E.
 *
 * Every Bidi_Control code point (U+061C, U+200E–U+200F, U+202A–U+202E,
 * U+2066–U+2069) is `Cf`, so "bidi control characters are stripped" is now
 * true of the whole class, which is what docs/policy.md claims.
 *
 * `\p{Cc}` — the C0 and C1 control characters, DEL, and the ESC that starts
 * an ANSI escape sequence — joins them for the same reason: a terminal, a
 * log viewer and a chat client all render them as nothing, so
 * `sys<U+0001>tem override` READS as the marker while a scan of the raw
 * bytes saw two harmless fragments. The five whitespace controls
 * (\t \n \v \f \r) are deliberately NOT dropped here: they are visible as
 * layout, and the whitespace collapse below already folds them to a single
 * space, which is what keeps `ignore\nall previous instructions` matching.
 *
 * Exported so the astral table below can be re-derived from it in the tests
 * rather than restated there (a second copy would drift).
 */
export declare const INVISIBLE_RE: RegExp;
/**
 * The ONLY astral ranges `INVISIBLE_RE` contains, so an astral code point
 * costs a few integer comparisons instead of a `String.fromCodePoint`
 * allocation plus a property-escape regex test on every occurrence. Plane 14
 * (tags, variation selectors supplement) is NOT the only one, which is why
 * the list is spelled out rather than short-circuited on that block: the
 * Kaithi number signs, the Egyptian Hieroglyph and Shorthand format
 * controls, and the musical-symbol format characters are all `Cf` outside
 * it. `test/gateway-boundary.test.ts` re-derives this table from
 * `INVISIBLE_RE` across all of U+10000–U+10FFFF, so Unicode drift is a test
 * failure rather than a silent hole.
 */
export declare const ASTRAL_INVISIBLE_RANGES: readonly (readonly [number, number])[];
/**
 * Build the normalized copy of `original` used for marker scanning, together
 * with the run mapping that puts spans back on the original text. Pure and
 * total: any string is accepted, nothing throws.
 */
export declare function normalizeForScan(original: string, opts?: NormalizeOptions): NormalizedScan;
/**
 * Locate every injection marker in `text`. Returns merged, sorted,
 * non-overlapping spans ON THE ORIGINAL TEXT. Scanning runs on the
 * normalized copy (see `normalizeForScan`), so markers hidden behind
 * invisible characters or NFKC-foldable homoglyphs are found too. Never
 * throws; non-string input yields `[]`, and text beyond `MAX_SCAN_CHARS` is
 * not examined.
 *
 * Combining marks need a SECOND copy. A mark is a visible character, so
 * dropping it for everyone would fold distinct words together, but
 * `igno<U+0301>re all previous instructions` and `ignoré all previous
 * instructions` both read as the marker to whoever looks at the rendered
 * text. The second copy folds with NFKD and drops `\p{Mn}`/`\p{Me}`
 * instead, and the two span sets are unioned. It is built only when the
 * first pass actually saw a mark, and it carries its OWN run table, so the
 * mapping guarantee is unchanged: a span from either copy lands exactly on
 * the original characters its normalized match came from. (A mark hanging
 * off the LAST matched character is therefore outside the span, the same way
 * a trailing zero-width character always was: the span covers what matched,
 * so a redaction can leave a stray accent behind but never eats a neighbour.)
 */
export declare function findInjectionSpans(text: string, limit?: number): Span[];
export {};
