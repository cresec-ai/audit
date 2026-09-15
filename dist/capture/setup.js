/**
 * Shared "spin up a fail-open Recorder for one CLI invocation" logic. Used by
 * `record`/`http` (src/cli.ts) and `hook` (src/hook/run.ts) — moved out of
 * cli.ts into its own module so `hook` can reuse it without an import cycle
 * (cli.ts -> src/hook/run.ts -> cli.ts).
 *
 * ANY init failure is fail-open: warn (via the caller-supplied `diag`) and
 * degrade — a store that can't be opened means nothing can be recorded (the
 * returned recorder just drops everything); a signer that can't be loaded
 * still leaves the store usable (recording continues, without head
 * signatures). This is also where the data directory gets created, so a bad
 * --data-dir/MCP_RECORDER_DATA_DIR degrades gracefully here rather than
 * throwing before the caller can do its own work (forward traffic for
 * record/http; still answer the hook's stdin for `hook`).
 */
import { Recorder } from './recorder.js';
import { Signer } from '../chain/keys.js';
import { ensureDataDir } from '../config.js';
import { openStore, openStoreReadOnly } from '../store/index.js';
import { Redactor } from '../redact/redactor.js';
/**
 * `readOnly: true` (used by the inspection commands — verify/query/sessions/
 * ui/export) resolves the backend without ever creating a store file as a
 * side effect of merely looking: on a data dir where nothing has recorded
 * yet, it returns an empty store instead of the write path's "create
 * whichever backend is available" behavior (see src/store/index.ts).
 */
export function openConfiguredStore(config, opts = {}) {
    const storeOpts = config.storeBackend !== undefined
        ? { dataDir: config.dataDir, backend: config.storeBackend }
        : { dataDir: config.dataDir };
    return opts.readOnly === true ? openStoreReadOnly(storeOpts) : openStore(storeOpts);
}
/** Wrap a recorder so the caller learns the session id of the first event. */
function tapSessionId(recorder) {
    let sessionId;
    const wrapped = {
        record(event) {
            if (sessionId === undefined)
                sessionId = event.session_id;
            recorder.record(event);
        },
        flush: () => recorder.flush(),
        close: () => recorder.close(),
        stats: () => recorder.stats(),
    };
    return { recorder: wrapped, sessionId: () => sessionId };
}
/**
 * Build redactor/store/signer/recorder for one CLI invocation. `diag` is the
 * caller's own stderr diagnostic writer (record/http and hook each keep
 * their own, matching their own message prefix conventions).
 */
export async function setupProxyRecording(config, diag) {
    const redactor = new Redactor({ mode: config.redactMode });
    let store = null;
    let signer = null;
    if (config.disabled) {
        diag('MCP_RECORDER_DISABLE=1 — recording disabled, pure passthrough');
    }
    else {
        try {
            ensureDataDir(config.dataDir);
            store = openConfiguredStore(config);
        }
        catch (cause) {
            const msg = cause instanceof Error ? cause.message : String(cause);
            diag(`recording disabled (init failed, traffic unaffected): ${msg}`);
            try {
                store?.close();
            }
            catch {
                /* fail-open */
            }
            store = null;
        }
        if (store !== null) {
            try {
                signer = await Signer.load(config.dataDir);
            }
            catch (cause) {
                const msg = cause instanceof Error ? cause.message : String(cause);
                diag(`recording without head signatures (identity key init failed): ${msg}`);
                signer = null;
            }
        }
    }
    const inner = new Recorder({ store, signer });
    const { recorder, sessionId } = tapSessionId(inner);
    return {
        recorder,
        redactor,
        sessionId,
        storePath: store?.path,
        stats: () => inner.stats(),
    };
}
//# sourceMappingURL=setup.js.map