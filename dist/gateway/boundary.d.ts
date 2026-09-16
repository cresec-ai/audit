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
 * What the narrowing must NOT do is drop a shape that is a credential and
 * nothing else. Three did: an env-var-shaped assignment
 * (`AWS_SECRET_ACCESS_KEY=...`), a `github_pat_` fine-grained token, and a
 * URL carrying userinfo (`postgres://user:pass@host/db`). All three are back
 * — and since the boundary may only name patterns storage already hashes,
 * all three had to be fixed in `ALWAYS_PATTERNS` first, where the same three
 * shapes were missing (or, for the assignment, blinded by a `\b` that `_`
 * defeats).
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
/**
 * The clause a refusal carries when the OPERATOR decided it: a rule denied
 * the call, `mcp.default` denied it, a human denied the hold (or let it time
 * out / lapse at session end), or the boundary filter blocked the result.
 *
 * An agent that reads a bare refusal plausibly does the wrong thing with it:
 * retries the identical call in a loop, reaches the same effect through a
 * tool the policy does not name (denied `http_post` -> `bash curl`), or
 * decides the tool is broken and gives up without telling anyone. A policy
 * the agent routes around is not a policy. Almost no agent will have
 * `docs/agent-guidance.md` installed, so this line is the only guidance the
 * model is guaranteed to see.
 *
 * It is a directive ("do not retry"), not a prediction ("retrying will
 * fail"): a held call that nobody answered could in principle go through on
 * a second attempt, and the text must not claim otherwise. It is two short
 * sentences because it is appended to the agent's context on every refusal
 * of this kind.
 */
export declare const POLICY_REFUSAL_GUIDANCE: string;
/**
 * The clause a refusal carries when the gateway FAILED CLOSED: it could not
 * reach a decision, so it refused rather than forward the call unchecked.
 * Nobody decided anything about this call — the policy could not be
 * evaluated, the hold file could not be written, the hold cap was already
 * full, the proxy was shutting down, or a result was too large to scan.
 *
 * This one must NOT forbid a retry. `too many pending holds` clears as soon
 * as a parked hold resolves, and an oversize block clears as soon as the
 * agent asks for less output — a retry is the recovery, and {@link
 * POLICY_REFUSAL_GUIDANCE} would forbid exactly the move that works. The two
 * instructions that still hold are the ones that make the gateway a control
 * rather than a speed bump: do not route around it, and tell the user.
 */
export declare const FAIL_CLOSED_REFUSAL_GUIDANCE: string;
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
/**
 * The exact isError text of a blocked result (pinned by tests).
 *
 * Unlike a deny, this withheld a RESULT: the call already ran on the server
 * and whatever it did is done. {@link POLICY_REFUSAL_GUIDANCE} still belongs
 * here — the operator's `mcp.boundary` setting decided this, and re-running
 * a side-effecting tool to get the same bytes back, or reading the same
 * content through a tool the policy does not name, are the two moves the
 * boundary exists to stop.
 */
export declare function blockedText(secrets: number, injections: number): string;
/**
 * The exact isError text of a result blocked for exceeding max_scan_bytes.
 *
 * This carries {@link FAIL_CLOSED_REFUSAL_GUIDANCE}, not the policy-decision
 * clause. Nothing about the call or its content was judged: the line was too
 * large to scan, so `on_oversize` blocked it unread — the definition of
 * failing closed. Asking for less output (a page, a byte range, a narrower
 * filter) is the correct recovery, and the fail-closed clause permits
 * exactly that while still refusing the one move that would defeat the
 * boundary: reading the same bytes through a tool that is not scanned.
 */
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
    /**
     * True when the gateway FAILED CLOSED rather than the operator deciding:
     * the policy could not be evaluated, the hold file could not be written,
     * the hold cap was full, or the proxy was already shutting down. It
     * selects {@link FAIL_CLOSED_REFUSAL_GUIDANCE} over
     * {@link POLICY_REFUSAL_GUIDANCE} and nothing else — the first line is
     * unchanged, so every text the docs quote still reads exactly as before.
     * The caller must set it explicitly; `deniedText` never guesses it from
     * the reason string, which is free-form and comes from the policy file.
     */
    failClosed?: boolean;
}
/**
 * The text the model sees for a call the gateway did not forward. The first
 * line is the refusal itself:
 *   mcp-recorder gateway: tools/call "<tool>" denied by policy rule "<rule>": <reason>
 *   mcp-recorder gateway: tools/call "<tool>" denied by policy (no rule matched; mcp.default is deny)
 *   mcp-recorder gateway: tools/call "<tool>" denied by policy: policy evaluation error: <detail>
 *   mcp-recorder gateway: tools/call "<tool>" denied by policy rule "<rule>" (hold <id> timed out): <reason>
 * and one guidance clause follows on a second line.
 *
 * A deny without a rule id says "denied by policy", never "by policy
 * default": an evaluation-error deny or a hold-limit refusal is not the
 * default acting, and the text must not claim it is. The default case is
 * the one with neither a rule nor a reason, and it says so explicitly.
 *
 * WHICH clause is not a property of the text: a refusal the operator decided
 * (a rule deny, an `mcp.default` deny, a hold denied / timed out / abandoned
 * at session end) gets {@link POLICY_REFUSAL_GUIDANCE}, and one where the
 * gateway failed closed instead (`failClosed`) gets
 * {@link FAIL_CLOSED_REFUSAL_GUIDANCE}, which does not forbid the retry that
 * is often the fix. `failClosed` wins over the outcome: a hold REFUSED
 * because the session was already closing reads `session_end` too, but
 * nobody decided it.
 *
 * The one outcome that gets NO clause is `cancelled`: there the CLIENT
 * withdrew its own request with `notifications/cancelled` and the gateway
 * merely stopped waiting. Nothing was refused, the caller already knows
 * (per MCP it should ignore this response entirely), and its own reason for
 * cancelling may well make a fresh attempt correct — so either clause would
 * be untrue.
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
