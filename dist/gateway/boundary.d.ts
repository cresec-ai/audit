/**
 * Gateway boundary filter — server -> client tools/call results.
 *
 * Pure, transport-agnostic functions the stdio gateway applies to the PARSED
 * JSON-RPC response of a `tools/call` before the bytes reach the client:
 *  - secret-shaped values, located with a NARROWED subset of the recorder's
 *    own `alwaysPatterns` (see `boundarySecretPatterns()`);
 *  - suspected prompt-injection markers (`./injection.js`).
 * Each family gets a policy action (`redact` | `block` | `flag` | `off`).
 *
 * Storage redaction and the boundary filter are deliberately NOT the same
 * set. Storage hashes anything that could be a secret — a miss there is
 * irreversible evidence loss, and a false positive costs nothing but a hash.
 * The boundary REWRITES what the model reads, so a false positive costs real
 * tool output: the generic "long hex run" and "long base64 blob" shapes match
 * git SHAs, sha256 checksums, dashless UUIDs, Docker digests and inline
 * images, and are excluded here. `secret_refs` in the evidence store keep
 * their full, wider meaning.
 *
 * Invariants:
 *  - `applyBoundary()` NEVER throws and NEVER mutates its input; a changed
 *    message is a fresh tree that shares only untouched subtrees.
 *  - Only `result.content[*].text` (type "text") and
 *    `result.content[*].resource.text` are scanned. Everything else in the
 *    result (images, blobs, structuredContent, meta) is forwarded verbatim.
 *  - Redaction markers carry only the sha256 prefix of the removed token,
 *    never the token; `secret_refs` carry full refs computed the same way
 *    as `Redactor.hashString`, so `query` can still find a leaked value the
 *    model never saw.
 *  - Every boundary pattern IS one of the recorder's `alwaysPatterns` (the
 *    same RegExp object, selected by source); the boundary can only ever be
 *    a subset of what storage redaction already hashes.
 *  - Precedence when secrets and injection ask for different actions:
 *    block > redact > flag.
 * Also home of the exact human-readable strings a denied/held call gets
 * back (pinned by tests — keep them short and stable).
 */
import type { BoundaryConfig, BoundaryMode } from '../policy/types.js';
import { type Span } from './injection.js';
/** Per-family action (`mcp.boundary.secrets` / `.injection`), from the policy types. */
export type BoundaryAction = BoundaryMode;
/** `mcp.boundary` section of a normalized policy.yaml v1. */
export type { BoundaryConfig };
/** What happened to one tools/call result, recorded as `gateway.boundary`. */
export interface BoundaryReport {
    /** false when skipped: oversize, both scanners off, or internal error. */
    scanned: boolean;
    action: 'none' | 'redact' | 'block' | 'flag';
    /** Distinct (merged) secret-shaped regions found across all scanned text. */
    secrets_found: number;
    /** Distinct (merged) injection markers found across all scanned text. */
    injection_found: number;
    /** `sha256:<hex>` of each secret token found (deduped, at most 8). */
    secret_refs?: string[];
    /** Present only when the filter hit an internal error (never thrown). */
    error?: string;
}
export interface BoundaryOutcome {
    /** The message the client should receive (the input itself when unchanged). */
    message: unknown;
    changed: boolean;
    report: BoundaryReport;
}
export interface BoundaryDeps {
    /** `boundarySecretPatterns()` (or a test double). */
    secretPatterns: readonly RegExp[];
    /** `Redactor.hashString` — produces `sha256:<hex>`. */
    hashString(s: string): string;
}
export interface BoundaryOptions {
    /** Byte length of the raw upstream line, compared with `max_scan_bytes`. */
    rawBytes?: number;
}
/** Cap on `secret_refs`, matching the redactor's `MAX_SECRET_REFS`. */
export declare const MAX_SECRET_REFS = 8;
/** Number of hex characters of the token hash kept in a redaction marker. */
export declare const MARKER_HASH_HEX = 16;
/** Text a redacted injection span is replaced with. */
export declare const INJECTION_MARKER = "[gateway: suspected prompt injection removed]";
/** One high-confidence secret family the boundary filter is allowed to act on. */
export interface BoundarySecretFamily {
    /** Stable, human-readable family name (reports, docs, tests). */
    id: string;
    /**
     * The storage pattern this family selects, written EXACTLY as the recorder
     * declares it in `ALWAYS_PATTERNS`. It is a selector, never the regex that
     * runs: `boundarySecretPatterns()` returns the recorder's own RegExp
     * objects, matched by `source`. A drift between the two lists therefore
     * shows up as a missing family, which the boundary test asserts against.
     */
    re: RegExp;
    /** Why this shape is safe to rewrite in text a coding agent reads. */
    note: string;
}
/**
 * The secret families the BOUNDARY filter may rewrite: provider-prefixed
 * credentials, JWTs, PEM private-key blocks and explicit secret assignments.
 * Every entry names a pattern that also lives in the recorder's
 * `alwaysPatterns`; the generic long-hex and long-base64 shapes are
 * deliberately absent (see the module header).
 */
export declare const BOUNDARY_SECRET_FAMILIES: readonly BoundarySecretFamily[];
/**
 * The secret-shape patterns the BOUNDARY filter runs — the high-confidence
 * subset of the recorder's `alwaysPatterns` described by
 * `BOUNDARY_SECRET_FAMILIES`. Generic long-hex (git SHAs, sha256 checksums,
 * dashless UUIDs) and generic base64 (inline images, Docker digests) are NOT
 * here; they still hash in the evidence store.
 */
export declare function boundarySecretPatterns(): readonly RegExp[];
/**
 * Locate secret-shaped tokens in `text`. Returns merged, sorted,
 * non-overlapping spans whose `id` is `secret:<pattern index>` of the
 * earliest contributing pattern. Never throws on non-string input.
 */
export declare function findSecretSpans(text: string, patterns: readonly RegExp[]): Span[];
/**
 * Rebuild `text` with every span replaced by `replacer(span, matched)`.
 * Spans are sorted first; a span overlapping an earlier one is skipped and
 * out-of-range spans are clamped, so any input is safe.
 */
export declare function redactSpans(text: string, spans: readonly Span[], replacer: (span: Span, matched: string) => string): string;
/** The exact isError text of a blocked result (pinned by tests). */
export declare function blockedText(secrets: number, injections: number): string;
/** The exact isError text of a result blocked for exceeding max_scan_bytes. */
export declare function oversizeBlockedText(rawBytes: number, maxScanBytes: number): string;
/**
 * Apply the boundary policy to a parsed tools/call response. See the module
 * header for the contract. `message` is returned as-is (same reference)
 * whenever nothing had to change.
 */
export declare function applyBoundary(message: unknown, config: BoundaryConfig, deps: BoundaryDeps, opts?: BoundaryOptions): BoundaryOutcome;
/** Outcome of a hold that ended without the call being forwarded. */
export type DeniedHoldOutcome = 'denied' | 'timeout' | 'cancelled' | 'session_end';
export interface DeniedTextInput {
    tool: string;
    /**
     * Absent when no rule matched: the policy default applied, the policy could
     * not be evaluated (fail-closed, `reason` says so), or the proxy refused
     * the call itself (hold limit, `reason` says so).
     */
    ruleId?: string;
    reason?: string;
    /** Present for hold outcomes; names the hold in the text. */
    approvalId?: string;
    outcome?: DeniedHoldOutcome;
}
/**
 * The text the model sees for a call the gateway did not forward:
 *   mcp-recorder gateway: tools/call "<tool>" denied by policy rule "<rule>": <reason>
 *   mcp-recorder gateway: tools/call "<tool>" denied by policy (no rule matched; mcp.default is deny)
 *   mcp-recorder gateway: tools/call "<tool>" denied by policy: policy evaluation error: <detail>
 *   mcp-recorder gateway: tools/call "<tool>" denied by policy rule "<rule>" (hold <id> timed out): <reason>
 *
 * A deny without a rule id says "denied by policy", never "by policy
 * default": an evaluation-error deny or a hold-limit refusal is not the
 * default acting, and the text must not claim it is. The default case is
 * the one with neither a rule nor a reason, and it says so explicitly.
 */
export declare function deniedText(input: DeniedTextInput): string;
/** JSON-RPC response carrying a tool-execution error (MCP `isError`). */
export declare function synthesizeDeniedResult(id: string | number, text: string): {
    jsonrpc: '2.0';
    id: string | number;
    result: {
        content: {
            type: 'text';
            text: string;
        }[];
        isError: true;
    };
};
