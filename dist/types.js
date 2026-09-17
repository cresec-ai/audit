/**
 * FROZEN MODULE CONTRACTS
 * =======================
 * Public interfaces every module implements against. Implementation files own
 * their internals, but the exported shapes below must not drift — the CLI and
 * the other modules are written against them.
 *
 * Module map (file ownership):
 *   src/chain/hash.ts      — canonicalJson, sha256Hex, GENESIS_HASH, computeHash, makeRecord, signedPayload
 *   src/chain/keys.ts      — Signer (ed25519 keypair management + head signing)
 *   src/store/sqlite.ts    — SqliteStore implements EvidenceStore
 *   src/store/jsonl.ts     — JsonlStore implements EvidenceStore
 *   src/store/index.ts     — openStore() factory with sqlite→jsonl fallback
 *   src/redact/redactor.ts — Redactor implements RedactorLike
 *   src/capture/recorder.ts— Recorder (async fail-open queue) implements RecorderLike
 *   src/proxy/framing.ts   — LineScanner (incremental newline-delimited JSON tap)
 *   src/proxy/stdio.ts     — runStdioProxy()
 *   src/proxy/http.ts      — runHttpProxy()
 *   src/verify/verify.ts   — verifyStore(), verifyRecords()
 *   src/query/touched.ts   — queryStore()
 *   src/replay/render.ts   — renderTimelineHtml()
 *   src/replay/serve.ts    — serveUi()
 *   src/export/bundle.ts   — exportBundle()
 *   src/config.ts          — resolveConfig(), data-dir/env handling
 *   src/cli.ts             — subcommand dispatch
 */
export const ENV = {
    DATA_DIR: 'MCP_RECORDER_DATA_DIR',
    STORE: 'MCP_RECORDER_STORE',
    REDACT: 'MCP_RECORDER_REDACT',
    DISABLE: 'MCP_RECORDER_DISABLE',
    /** Additive (gateway mode): policy.yaml path honoured by `record` when `--policy` is absent. */
    POLICY: 'MCP_RECORDER_POLICY',
    /** `hook`: MCP config file(s) to resolve server origins from — one path or
     *  comma-separated paths; default `/tmp/mcp-config-*.json` (cloud sessions).
     *  See src/hook/mcp-config.ts. */
    MCP_CONFIG: 'MCP_RECORDER_MCP_CONFIG',
    /**
     * Additive (evidence sink): base URL of a receiver to replicate sealed
     * records to. SETTING IT IS THE ENTIRE OPT-IN — absent, there is no sink,
     * no shipper and byte-identical behaviour to a build without the feature.
     * There is deliberately no second `..._ENABLED` switch. See src/sink.
     */
    SINK: 'MCP_RECORDER_SINK',
    /** Additive: the sink's bearer token (channel authorisation only — it
     *  answers "may this connection write to tenant T at all", nothing more). */
    SINK_TOKEN: 'MCP_RECORDER_SINK_TOKEN',
    /** Additive: a file holding the bearer token, for platforms where a
     *  root-owned file is easier to protect than an environment variable. */
    SINK_TOKEN_FILE: 'MCP_RECORDER_SINK_TOKEN_FILE',
};
/** File names inside the data dir. */
export const FILES = {
    SQLITE_DB: 'evidence.db',
    JSONL_LOG: 'evidence.jsonl',
    JSONL_SIGS: 'signatures.jsonl',
    PRIVATE_KEY: 'identity.key',
    PUBLIC_KEY: 'identity.pub',
    /** Evidence sink: cached copy of the receiver's cursor. A CACHE ONLY —
     *  the receiver is always the authority on what it holds. */
    SINK_CURSOR: 'sink-cursor.json',
    /** Evidence sink: single-instance mutex DIRECTORY for `ship`. */
    SHIP_LOCK: 'ship.lock',
    /** Evidence sink: what `ship --status` prints. */
    SHIP_STATUS: 'ship-status.json',
};
//# sourceMappingURL=types.js.map