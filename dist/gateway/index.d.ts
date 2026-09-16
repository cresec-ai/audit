/**
 * Gateway primitives barrel: transport-agnostic building blocks for
 * `record --policy` (design §2). The stdio proxy, recorder events and CLI
 * are wired against exactly this surface.
 */
export { INJECTION_PATTERNS, findInjectionSpans, matchSpans, mergeSpans, normalizeForScan, type InjectionPattern, type NormalizeOptions, type NormalizedScan, type Span, } from './injection.js';
export { BOUNDARY_SECRET_FAMILIES, FAIL_CLOSED_REFUSAL_GUIDANCE, INJECTION_MARKER, MARKER_HASH_HEX, MAX_SECRET_REFS, POLICY_REFUSAL_GUIDANCE, applyBoundary, blockedText, boundarySecretPatterns, deniedText, findSecretSpans, isCodeShapedAssignment, isCodeShapedValue, oversizeBlockedText, redactSpans, synthesizeDeniedResult, type BoundaryAction, type BoundaryConfig, type BoundaryDeps, type BoundaryOptions, type BoundaryOutcome, type BoundaryReport, type BoundarySecretFamily, type DeniedHoldOutcome, type DeniedTextInput, } from './boundary.js';
export { DEFAULT_POLL_MS, HoldError, HoldStore, type HoldCreateInput, type HoldDecision, type HoldErrorCode, type HoldRecord, type HoldStatus, type HoldWaitOptions, type HoldWaitResult, } from './holds.js';
