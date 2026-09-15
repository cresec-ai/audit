/**
 * Replay timeline renderer — one self-contained, dark-theme HTML page.
 *
 * Zero external requests: all CSS and JS are inline, and the blast-radius
 * search hashes its input client-side with crypto.subtle, so a saved page
 * works fully offline. XSS hygiene: every interpolated string is HTML-escaped
 * (tool names, methods, paths are attacker-influenced), and the embedded JSON
 * blob escapes '<' as < so a payload can never close the script tag.
 */
import type { EvidenceStore, VerifyResult } from '../types.js';
/** Hard cap on events embedded in one page (static mode renders every session). */
export declare const MAX_EMBED_EVENTS = 5000;
export interface RenderOpts {
    sessionId?: string;
    verify?: VerifyResult;
}
/**
 * Render the evidence replay page. With `sessionId` only that session's
 * timeline is shown; without it, the session picker plus every session's
 * timeline stacked (static mode), capped at MAX_EMBED_EVENTS events.
 */
export declare function renderTimelineHtml(store: EvidenceStore, opts?: RenderOpts): string;
