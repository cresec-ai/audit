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
import { resolveSinkConfig } from '../sink/config.js';
import { ensureShipper } from '../sink/spawn.js';
import type { SinkSurface } from '../sink/protocol.js';
import type { AnyEvent } from '../schema/events.js';
import type { EvidenceStore, RecorderConfig, RecorderLike, SignerLike } from '../types.js';

/**
 * `readOnly: true` (used by the inspection commands — verify/query/sessions/
 * ui/export) resolves the backend without ever creating a store file as a
 * side effect of merely looking: on a data dir where nothing has recorded
 * yet, it returns an empty store instead of the write path's "create
 * whichever backend is available" behavior (see src/store/index.ts).
 */
export function openConfiguredStore(config: RecorderConfig, opts: { readOnly?: boolean } = {}): EvidenceStore {
  const storeOpts =
    config.storeBackend !== undefined
      ? { dataDir: config.dataDir, backend: config.storeBackend }
      : { dataDir: config.dataDir };
  return opts.readOnly === true ? openStoreReadOnly(storeOpts) : openStore(storeOpts);
}

/** Wrap a recorder so the caller learns the session id of the first event. */
function tapSessionId(recorder: Recorder): { recorder: RecorderLike; sessionId(): string | undefined } {
  let sessionId: string | undefined;
  const wrapped: RecorderLike = {
    record(event: AnyEvent): void {
      if (sessionId === undefined) sessionId = event.session_id;
      recorder.record(event);
    },
    flush: () => recorder.flush(),
    close: () => recorder.close(),
    stats: () => recorder.stats(),
  };
  return { recorder: wrapped, sessionId: () => sessionId };
}

export interface ProxySetup {
  recorder: RecorderLike;
  redactor: Redactor;
  sessionId(): string | undefined;
  storePath: string | undefined;
  stats(): { written: number; dropped: number };
}

export interface SetupRecordingOpts {
  /**
   * Which surface is recording. Advisory metadata on the wire, and the only
   * thing that differs between `record`, `http` and `hook` here — all three
   * write to the SAME store, so the sink belongs at this shared seam rather
   * than bolted onto one command.
   */
  surface?: SinkSurface;
  /** Flags that may carry --sink/--token/--token-file; env is read anyway. */
  flags?: Record<string, string | boolean | string[] | undefined>;
}

/**
 * Build redactor/store/signer/recorder for one CLI invocation. `diag` is the
 * caller's own stderr diagnostic writer (record/http and hook each keep
 * their own, matching their own message prefix conventions).
 *
 * If (and only if) a sink is configured, this ALSO makes sure a shipper
 * process exists for the data dir. That is a `statSync` plus, at most, a
 * detached spawn that is immediately `unref`'d — no awaiting, no I/O on the
 * forwarding path, and a failure is a silent no-op. The sink never runs in
 * this process.
 */
export async function setupProxyRecording(
  config: RecorderConfig,
  diag: (msg: string) => void,
  opts: SetupRecordingOpts = {},
): Promise<ProxySetup> {
  const redactor = new Redactor({ mode: config.redactMode });
  let store: EvidenceStore | null = null;
  let signer: SignerLike | null = null;
  if (config.disabled) {
    diag('MCP_RECORDER_DISABLE=1 — recording disabled, pure passthrough');
  } else {
    try {
      ensureDataDir(config.dataDir);
      store = openConfiguredStore(config);
    } catch (cause) {
      const msg = cause instanceof Error ? cause.message : String(cause);
      diag(`recording disabled (init failed, traffic unaffected): ${msg}`);
      try {
        store?.close();
      } catch {
        /* fail-open */
      }
      store = null;
    }
    if (store !== null) {
      try {
        signer = await Signer.load(config.dataDir);
      } catch (cause) {
        const msg = cause instanceof Error ? cause.message : String(cause);
        diag(`recording without head signatures (identity key init failed): ${msg}`);
        signer = null;
      }
    }
  }
  if (store !== null) {
    // Fail-open by construction: resolveSinkConfig never throws, ensureShipper
    // never throws, and neither one can delay or deny a single byte of the
    // traffic being forwarded.
    const { sink, warnings } = resolveSinkConfig({
      ...(opts.flags !== undefined ? { flags: opts.flags } : {}),
      env: process.env,
    });
    // `hook` is a fresh process per tool call, so an advisory that repeats on
    // every invocation is noise in the agent's own stderr. A misconfiguration
    // that actually DISABLED the sink is still said out loud there.
    if (sink === undefined || opts.surface !== 'hook') {
      for (const w of warnings) diag(w);
    }
    if (sink !== undefined) {
      ensureShipper({ config, sink, surface: opts.surface ?? 'record' });
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
