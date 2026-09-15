/**
 * @edut/mcp-recorder — public API.
 *
 * Everything the CLI wires together is importable as a library: schema,
 * hashing/signing primitives, stores, redaction, the recorder, both proxies,
 * verification, blast-radius query, replay rendering/serving, and bundle
 * export.
 */
export * from './schema/events.js';
export * from './types.js';
export { canonicalJson, sha256Hex, sha256Ref, GENESIS_HASH, computeHash, makeRecord, signedPayload, } from './chain/hash.js';
export { Signer, publicKeyPem, publicKeyHexFromPem } from './chain/keys.js';
export { openStore, SqliteStore, JsonlStore, isSqliteAvailable } from './store/index.js';
export { Redactor, DEFAULT_POLICY, looksSecret, scrubArgv, scrubToolArguments, } from './redact/redactor.js';
export type { ScrubbedArgv } from './redact/redactor.js';
export { Recorder } from './capture/recorder.js';
export type { RecorderOpts } from './capture/recorder.js';
export { runStdioProxy } from './proxy/stdio.js';
export type { StdioProxyOpts } from './proxy/stdio.js';
export { runHttpProxy } from './proxy/http.js';
export type { HttpProxyOpts, HttpProxyHandle } from './proxy/http.js';
export { verifyStore, verifyRecords } from './verify/verify.js';
export type { VerifyOpts } from './verify/verify.js';
export { queryStore } from './query/touched.js';
export { renderTimelineHtml, MAX_EMBED_EVENTS } from './replay/render.js';
export type { RenderOpts } from './replay/render.js';
export { serveUi } from './replay/serve.js';
export type { ServeUiOpts, ServeUiHandle } from './replay/serve.js';
export { exportBundle, BUNDLE_FILES } from './export/bundle.js';
export { DEFAULTS as POLICY_DEFAULTS, ID_PATTERN as POLICY_ID_PATTERN, LIMITS as POLICY_LIMITS, REGEX_VALUE_CAP, autoRuleId, normalizePolicy, } from './policy/types.js';
export type { Action as PolicyAction, BoundaryConfig, BoundaryConfigInput, BoundaryMode, EgressMatch, EgressMatchInput, EgressPolicy, EgressPolicyInput, EgressRule, EgressRuleInput, GlobOrList, HoldConfig, HoldConfigInput, McpMatch, McpMatchInput, McpPolicy, McpPolicyInput, McpRule, McpRuleInput, OnOversize, OnTimeout, Policy, PolicyInput, } from './policy/types.js';
export { POLICY_SCHEMA, POLICY_SCHEMA_ID } from './policy/schema.js';
export { validateAgainstSchema } from './policy/jsonschema.js';
export type { JsonSchema, SchemaError } from './policy/jsonschema.js';
export { checkGlob, checkRe2Subset, formatPolicyErrors, validatePolicyObject } from './policy/validate.js';
export { checkCatastrophicShape } from './policy/redos.js';
export { REGEX_DEADLINE_MS, REGEX_STARTUP_MS, RegexGuardError, configureRegexGuard, regexGuardState, resetRegexGuard, setRegexGuardDiag, warmRegexGuard, } from './policy/regex-guard.js';
export type { RegexGuardFailure, RegexGuardOptions } from './policy/regex-guard.js';
export type { PolicyError, ValidationResult as PolicyValidationResult } from './policy/validate.js';
export { PolicyLoadError, PolicyValidationError, findNonJsonValue, loadPolicyFile, parsePolicyText, sourceForPath, } from './policy/load.js';
export type { LoadedPolicy, PolicySource } from './policy/load.js';
export { compileGlob, globMatch, globToRegExp } from './policy/glob.js';
export type { GlobDelimiter } from './policy/glob.js';
export { evaluateEgress, evaluateMcp, getPath, ruleLabel } from './policy/engine.js';
export type { Decision as PolicyDecision, EgressDecision, EgressRequestInput, McpDecision, McpRequestInput, } from './policy/engine.js';
export { bundleFileOrder, compileToRego, policyRevision, renderEgressModule, renderMcpModule, } from './policy/rego.js';
export type { CompileOptions as RegoCompileOptions, RegoBundle } from './policy/rego.js';
export { BOUNDARY_SECRET_FAMILIES, INJECTION_MARKER, INJECTION_PATTERNS, MARKER_HASH_HEX, MAX_SECRET_REFS as BOUNDARY_MAX_SECRET_REFS, applyBoundary, blockedText, boundarySecretPatterns, deniedText, findInjectionSpans, findSecretSpans, matchSpans, mergeSpans, oversizeBlockedText, redactSpans, synthesizeDeniedResult, DEFAULT_POLL_MS as HOLD_DEFAULT_POLL_MS, HoldError, HoldStore, } from './gateway/index.js';
export type { BoundaryAction, BoundaryDeps, BoundaryOptions, BoundaryOutcome, BoundaryReport as BoundaryFilterReport, DeniedHoldOutcome, DeniedTextInput, HoldCreateInput, HoldDecision, HoldErrorCode, HoldRecord, HoldStatus, HoldWaitOptions, HoldWaitResult, InjectionPattern, Span, } from './gateway/index.js';
export type { GatewayOptions } from './gateway/options.js';
export { resolveConfig } from './config.js';
export type { ResolveConfigOpts } from './config.js';
export { VERSION } from './version.js';
