/**
 * Spawn-and-forget of the shipper from the RECORDING surfaces.
 *
 * `record` / `http` / `hook` do exactly one sink-related thing between them:
 * a `statSync` liveness check on `<data-dir>/ship.lock` and, if nothing is
 * running, a detached `mcp-recorder ship` — the whole thing wrapped in
 * try/catch, with failure a no-op. Nothing here awaits anything, nothing
 * here can throw into the caller, and the child is `unref`'d so it can never
 * hold the proxy's exit open.
 *
 * That is the entire coupling between the forwarding path and the sink. A
 * sink that is down, slow, 500ing, 401ing or hostile cannot add latency to a
 * tool call, cannot turn into a deny, cannot make the proxy exit non-zero
 * and cannot change one byte of its stdout — because it is not on that path
 * at all.
 */
import { spawn } from 'node:child_process';
import type { RecorderConfig } from '../types.js';
import type { SinkConfig } from './config.js';
import type { SinkSurface } from './protocol.js';
/**
 * Absolute path of this install's CLI entry point. Derived from THIS
 * module's own location so it is right in both worlds: `dist/sink/spawn.js`
 * resolves to `dist/cli.js`, and `src/sink/spawn.ts` (tsx, dogfooding, the
 * test suite) resolves to `src/cli.ts`.
 */
export declare function cliEntryPoint(moduleUrl?: string): string;
export interface SpawnShipperOpts {
    config: RecorderConfig;
    sink: SinkConfig;
    surface: SinkSurface;
    /** Defaults to process.env. */
    env?: NodeJS.ProcessEnv;
    /** Test seam; the real spawn is node:child_process.spawn. */
    spawnFn?: typeof spawn;
}
/**
 * Start a shipper for this data dir unless one already looks alive.
 * Returns true when a child was spawned — for tests and diagnostics only;
 * no caller may branch on it in a way that affects traffic.
 */
export declare function ensureShipper(opts: SpawnShipperOpts): boolean;
