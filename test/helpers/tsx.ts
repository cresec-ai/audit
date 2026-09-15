/**
 * Spawn tsx directly, portably.
 *
 * `spawn('npx', ['tsx', ...])` shells out to npm's `npx`, which on Windows
 * is a `.cmd` shim — `child_process.spawn` won't run a `.cmd` file without
 * `shell: true`, and even with that, quoting/argv semantics differ from
 * POSIX. `node_modules/.bin/tsx` has the same problem (it's also a `.cmd`
 * shim on Windows). Resolving tsx's own CLI entry point and running it with
 * `process.execPath` sidesteps both: it's just `node <script> <args>`,
 * which behaves identically on every platform node itself supports.
 */
import { spawn, spawnSync } from 'node:child_process';
import type {
  ChildProcess,
  SpawnOptionsWithoutStdio,
  SpawnSyncOptionsWithStringEncoding,
  SpawnSyncReturns,
} from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const HELPERS_DIR = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HELPERS_DIR, '..', '..');

/** Absolute path to tsx's CLI entry point (a devDependency of this repo). */
export const TSX_CLI = join(ROOT, 'node_modules', 'tsx', 'dist', 'cli.mjs');

/** Spawn `tsx <args>` asynchronously, e.g. `spawnTsx(['src/cli.ts', '--help'], { cwd: ROOT })`. */
export function spawnTsx(args: string[], options: SpawnOptionsWithoutStdio = {}): ChildProcess {
  return spawn(process.execPath, [TSX_CLI, ...args], options);
}

/** Synchronous counterpart of {@link spawnTsx}, for tests that want a blocking run. */
export function spawnTsxSync(
  args: string[],
  options: SpawnSyncOptionsWithStringEncoding,
): SpawnSyncReturns<string> {
  return spawnSync(process.execPath, [TSX_CLI, ...args], options);
}
