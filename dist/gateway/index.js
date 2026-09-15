/**
 * Gateway primitives barrel: transport-agnostic building blocks for
 * `record --policy` (design §2). The stdio proxy, recorder events and CLI
 * are wired against exactly this surface.
 */
export { INJECTION_PATTERNS, findInjectionSpans, matchSpans, mergeSpans, } from './injection.js';
export { INJECTION_MARKER, MARKER_HASH_HEX, MAX_SECRET_REFS, applyBoundary, blockedText, defaultSecretPatterns, deniedText, findSecretSpans, oversizeBlockedText, redactSpans, synthesizeDeniedResult, } from './boundary.js';
export { DEFAULT_POLL_MS, HoldError, HoldStore, } from './holds.js';
//# sourceMappingURL=index.js.map