/**
 * Gateway primitives barrel: transport-agnostic building blocks for
 * `record --policy` (design §2). The stdio proxy, recorder events and CLI
 * are wired against exactly this surface.
 */
export { INJECTION_PATTERNS, findInjectionSpans, matchSpans, mergeSpans, normalizeForScan, } from './injection.js';
export { BOUNDARY_SECRET_FAMILIES, FAIL_CLOSED_REFUSAL_GUIDANCE, INJECTION_MARKER, MARKER_HASH_HEX, MAX_SECRET_REFS, POLICY_REFUSAL_GUIDANCE, applyBoundary, blockedText, boundarySecretPatterns, deniedText, findSecretSpans, isCodeShapedAssignment, isCodeShapedValue, oversizeBlockedText, redactSpans, synthesizeDeniedResult, } from './boundary.js';
export { BROKER_EXCHANGE_DEADLINE_MS, CredentialSwap, CredentialsConfigError, MAX_INFLIGHT_SWAPS, MAX_LIVE_TOKENS, SCRUB_MAX_RETENTION_MS, SCRUB_MIN_RETENTION_MS, SWAP_DENY, TokenScrubber, isResolutionFailure, normalizeCredentialsConfig, planSwaps, swapAttributes, swapDenyReason, unplannableSwap, } from './credentials.js';
export { DEFAULT_POLL_MS, HoldError, HoldStore, } from './holds.js';
//# sourceMappingURL=index.js.map