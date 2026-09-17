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
  ChildProcessWithoutNullStreams,
  SpawnOptions,
  SpawnOptionsWithoutStdio,
  SpawnSyncOptionsWithStringEncoding,
  SpawnSyncReturns,
} from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const HELPERS_DIR = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HELPERS_DIR, '..', '..');

/** Absolute path to tsx's CLI entry point (a devDependency of this repo). */
export const TSX_CLI = join(ROOT, 'node_modules', 'tsx', 'dist', 'cli.mjs');

/**
 * Spawn `tsx <args>` asynchronously, e.g. `spawnTsx(['src/cli.ts', '--help'], { cwd: ROOT })`.
 *
 * Overloaded the way `child_process.spawn` itself is, because the two cases
 * differ in what they hand back. Left to the default stdio, all three streams
 * exist and `ChildProcessWithoutNullStreams` says so, which is what lets a
 * caller write `proc.stdout.on(...)` without an assertion. Pass `stdio`
 * explicitly and any of them may be `'ignore'`, so the streams are nullable
 * and the caller has to say which ones it knows are there.
 *
 * This used to take `SpawnOptionsWithoutStdio` — which rejects
 * `stdio: [..., 'ignore', ...]` — and return the widened `ChildProcess`
 * anyway, so it managed to be wrong in both directions at once: callers
 * passing `'ignore'` were type errors, and callers using the default stdio
 * lost the non-null guarantee `spawn` had already given them.
 */
export function spawnTsx(args: string[], options?: SpawnOptionsWithoutStdio): ChildProcessWithoutNullStreams;
export function spawnTsx(args: string[], options: SpawnOptions): ChildProcess;
export function spawnTsx(args: string[], options: SpawnOptions = {}): ChildProcess {
  return spawn(process.execPath, [TSX_CLI, ...args], options);
}

/** Absolute path to tsx's loader entry (`import 'tsx'`), for in-process registration. */
export const TSX_LOADER = join(ROOT, 'node_modules', 'tsx', 'dist', 'loader.mjs');

/**
 * Run a TypeScript script in ONE node process (`node --import <tsx loader> <script>`)
 * instead of through tsx's CLI.
 *
 * The tsx CLI is a parent that spawns the real script as a child and RELAYS
 * signals to it: on SIGINT/SIGTERM it forwards the signal, then gives the
 * child ~30 ms to acknowledge over IPC before SIGKILLing it and exiting
 * 128+signal. On a loaded CI runner that window is missed often enough that
 * a test which sends SIGINT and expects the script's own clean-shutdown exit
 * code becomes flaky. Loading tsx in-process removes the relay: the signal
 * reaches the script directly and its exit code is the script's. Use this
 * for tests that stop a long-running command with a signal; everything else
 * can keep {@link spawnTsx}.
 */
export function spawnTsxInProcess(
  args: string[],
  options?: SpawnOptionsWithoutStdio,
): ChildProcessWithoutNullStreams;
export function spawnTsxInProcess(args: string[], options: SpawnOptions): ChildProcess;
export function spawnTsxInProcess(args: string[], options: SpawnOptions = {}): ChildProcess {
  return spawn(process.execPath, ['--import', pathToFileURL(TSX_LOADER).href, ...args], options);
}

/** Synchronous counterpart of {@link spawnTsx}, for tests that want a blocking run. */
export function spawnTsxSync(
  args: string[],
  options: SpawnSyncOptionsWithStringEncoding,
): SpawnSyncReturns<string> {
  return spawnSync(process.execPath, [TSX_CLI, ...args], options);
}
