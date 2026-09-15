/**
 * @edut/mcp-recorder — public API.
 *
 * Everything the CLI wires together is importable as a library: schema,
 * hashing/signing primitives, stores, redaction, the recorder, both proxies,
 * verification, blast-radius query, replay rendering/serving, and bundle
 * export.
 */

/* schema + module contracts */
export * from './schema/events.js';
export * from './types.js';

/* hashing / chain primitives */
export {
  canonicalJson,
  sha256Hex,
  sha256Ref,
  GENESIS_HASH,
  computeHash,
  makeRecord,
  signedPayload,
} from './chain/hash.js';

/* keys + signing */
export { Signer, publicKeyPem, publicKeyHexFromPem } from './chain/keys.js';

/* evidence stores */
export { openStore, SqliteStore, JsonlStore, isSqliteAvailable } from './store/index.js';

/* redaction */
export {
  Redactor,
  DEFAULT_POLICY,
  looksSecret,
  scrubArgv,
  scrubToolArguments,
} from './redact/redactor.js';
export type { ScrubbedArgv } from './redact/redactor.js';

/* capture */
export { Recorder } from './capture/recorder.js';
export type { RecorderOpts } from './capture/recorder.js';

/* proxies */
export { runStdioProxy } from './proxy/stdio.js';
export type { StdioProxyOpts } from './proxy/stdio.js';
export { runHttpProxy } from './proxy/http.js';
export type { HttpProxyOpts, HttpProxyHandle } from './proxy/http.js';

/* verification */
export { verifyStore, verifyRecords } from './verify/verify.js';
export type { VerifyOpts } from './verify/verify.js';

/* blast-radius query */
export { queryStore } from './query/touched.js';

/* replay */
export { renderTimelineHtml, MAX_EMBED_EVENTS } from './replay/render.js';
export type { RenderOpts } from './replay/render.js';
export { serveUi } from './replay/serve.js';
export type { ServeUiOpts, ServeUiHandle } from './replay/serve.js';

/* export */
export { exportBundle, BUNDLE_FILES } from './export/bundle.js';

/* config + version */
export { resolveConfig } from './config.js';
export type { ResolveConfigOpts } from './config.js';
export { VERSION } from './version.js';
