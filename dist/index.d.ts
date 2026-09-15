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
export { resolveConfig } from './config.js';
export type { ResolveConfigOpts } from './config.js';
export { VERSION } from './version.js';
