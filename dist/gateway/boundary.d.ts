/**
 * Gateway boundary filter — server -> client tools/call results.
 *
 * Pure, transport-agnostic functions the stdio gateway applies to the PARSED
 * JSON-RPC response of a `tools/call` before the bytes reach the client:
 *  - secret-shaped values, located with the recorder's own `alwaysPatterns`
 *    (see `defaultSecretPatterns()`), so "secret" means exactly the same
 *    thing here as it does for `secret_refs` in the evidence store;
 *  - suspected prompt-injection markers (`./injection.js`).
 * Each family gets a policy action (`redact` | `block` | `flag` | `off`).
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
    /** The recorder's `alwaysPatterns` (or a test double). */
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
/** The recorder's secret-shape patterns (same array the `Redactor` uses). */
export declare function defaultSecretPatterns(): readonly RegExp[];
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
    /** Absent when the policy default action applied. */
    ruleId?: string;
    reason?: string;
    /** Present for hold outcomes; names the hold in the text. */
    approvalId?: string;
    outcome?: DeniedHoldOutcome;
}
/**
 * The text the model sees for a call the gateway did not forward:
 *   mcp-recorder gateway: tools/call "<tool>" denied by policy rule "<rule>": <reason>
 *   mcp-recorder gateway: tools/call "<tool>" denied by policy default
 *   mcp-recorder gateway: tools/call "<tool>" denied by policy rule "<rule>" (hold <id> timed out): <reason>
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
