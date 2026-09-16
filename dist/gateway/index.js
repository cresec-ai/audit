/**
 * Gateway primitives barrel: transport-agnostic building blocks for
 * `record --policy` (design §2). The stdio proxy, recorder events and CLI
 * are wired against exactly this surface.
 */
export { INJECTION_PATTERNS, findInjectionSpans, matchSpans, mergeSpans, normalizeForScan, } from './injection.js';
export { BOUNDARY_SECRET_FAMILIES, FAIL_CLOSED_REFUSAL_GUIDANCE, INJECTION_MARKER, MARKER_HASH_HEX, MAX_SECRET_REFS, POLICY_REFUSAL_GUIDANCE, applyBoundary, blockedText, boundarySecretPatterns, deniedText, findSecretSpans, isCodeShapedAssignment, oversizeBlockedText, redactSpans, synthesizeDeniedResult, } from './boundary.js';
export { DEFAULT_POLL_MS, HoldError, HoldStore, } from './holds.js';
//# sourceMappingURL=index.js.map