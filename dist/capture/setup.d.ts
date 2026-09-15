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
import { Redactor } from '../redact/redactor.js';
import type { EvidenceStore, RecorderConfig, RecorderLike } from '../types.js';
/**
 * `readOnly: true` (used by the inspection commands — verify/query/sessions/
 * ui/export) resolves the backend without ever creating a store file as a
 * side effect of merely looking: on a data dir where nothing has recorded
 * yet, it returns an empty store instead of the write path's "create
 * whichever backend is available" behavior (see src/store/index.ts).
 */
export declare function openConfiguredStore(config: RecorderConfig, opts?: {
    readOnly?: boolean;
}): EvidenceStore;
export interface ProxySetup {
    recorder: RecorderLike;
    redactor: Redactor;
    sessionId(): string | undefined;
    storePath: string | undefined;
    stats(): {
        written: number;
        dropped: number;
    };
}
/**
 * Build redactor/store/signer/recorder for one CLI invocation. `diag` is the
 * caller's own stderr diagnostic writer (record/http and hook each keep
 * their own, matching their own message prefix conventions).
 */
export declare function setupProxyRecording(config: RecorderConfig, diag: (msg: string) => void): Promise<ProxySetup>;
