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
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ENV } from '../types.js';
import type { RecorderConfig } from '../types.js';
import type { SinkConfig } from './config.js';
import { shipperLooksAlive } from './state.js';
import type { SinkSurface } from './protocol.js';

/**
 * Absolute path of this install's CLI entry point. Derived from THIS
 * module's own location so it is right in both worlds: `dist/sink/spawn.js`
 * resolves to `dist/cli.js`, and `src/sink/spawn.ts` (tsx, dogfooding, the
 * test suite) resolves to `src/cli.ts`.
 */
export function cliEntryPoint(moduleUrl: string = import.meta.url): string {
  const here = fileURLToPath(moduleUrl);
  const ext = here.endsWith('.ts') ? '.ts' : '.js';
  return join(dirname(dirname(here)), `cli${ext}`);
}

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
export function ensureShipper(opts: SpawnShipperOpts): boolean {
  try {
    if (opts.config.disabled) return false;
    if (shipperLooksAlive(opts.config.dataDir)) return false;
    const env = opts.env ?? process.env;
    const args = [
      // Preserve whatever loader the current process runs under (tsx's
      // --import, a --require preflight, ...) so a dev/dogfood run spawning
      // a .ts entry point works exactly like an installed .js one.
      ...process.execArgv,
      cliEntryPoint(),
      'ship',
      '--data-dir',
      opts.config.dataDir,
      '--surface',
      opts.surface,
    ];
    if (opts.config.storeBackend !== undefined) args.push('--store', opts.config.storeBackend);
    const childEnv: NodeJS.ProcessEnv = { ...env, [ENV.SINK]: opts.sink.url };
    // The child re-resolves the token from the inherited environment. A token
    // that came from MCP_RECORDER_SINK_TOKEN_FILE is deliberately NOT
    // materialised into the child's env: the whole point of the file form is
    // that a root-owned file is easier to protect than an env var, and
    // copying its contents into a process environment would undo that.
    const inherited =
      (env[ENV.SINK_TOKEN] ?? '') !== '' || (env[ENV.SINK_TOKEN_FILE] ?? '') !== '';
    if (!inherited && opts.sink.token !== undefined) childEnv[ENV.SINK_TOKEN] = opts.sink.token;
    const spawnFn = opts.spawnFn ?? spawn;
    const child = spawnFn(process.execPath, args, {
      detached: true,
      stdio: 'ignore',
      env: childEnv,
    });
    child.unref();
    return true;
  } catch {
    // A shipper that will not start is a visibility problem, never a traffic
    // problem. Silence here is deliberate: the recording surfaces have
    // already said what they had to say about the sink config.
    return false;
  }
}
