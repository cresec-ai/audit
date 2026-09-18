/**
 * End-to-end harness: the REAL built binary, REAL server processes, a REAL
 * store on disk.
 *
 * WHY THIS EXISTS AT ALL. Two regressions this repo shipped were invisible to
 * the unit suites, and both were invisible for the same reason — the unit
 * exercised a function, never the thing the user runs:
 *
 *   - the shipper's self-check passed its unit test while a LIVE shipper
 *     shipped tampered history, because the verified frontier is per-process
 *     and no unit test ever started one (src/sink/selfcheck.ts, "what it does
 *     not catch");
 *   - a test that called `cliEntryPoint()` with hand-written POSIX file URLs
 *     passed on Linux and failed on Windows CI, because it never went through
 *     the real URL-building path (src/sink/spawn.ts).
 *
 * So the rules here, which every suite under test/e2e/ follows:
 *
 *   1. Drive `dist/cli.js` — the file `package.json`'s `bin` actually
 *      publishes — with `process.execPath`. Never `src/*.ts`, never an
 *      imported function. A test that imports the module under test cannot
 *      see a packaging, path-building or spawn-layout bug.
 *   2. Assert on artifacts an auditor could look at without this repo: bytes
 *      on the wire, files in the data dir, HTTP requests the receiver
 *      actually received, process exit codes, stdout octets.
 *   3. Every test carries a NEGATIVE CONTROL, named in a comment: the edit
 *      that makes it fail. A green e2e test that would stay green with the
 *      feature ripped out is worse than no test, because it buys confidence
 *      with nothing behind it.
 *
 * COST. The whole suite is a few dozen short-lived processes and nothing
 * else: no sleeps longer than a shipper's 1 s poll, no network beyond
 * loopback, no fixtures larger than a few hundred bytes. Measured on this
 * machine (Node 22, 4 vCPU): 6.8 s wall for all of test/e2e under vitest's
 * default file-level parallelism (13.8 s of summed test time across six
 * files), inside a full `npm test` of 101 s. The slowest file is the
 * ship/receiver one at ~4.6 s, because it starts a second program and waits
 * for replication. Everything here is dominated by process startup, so the
 * cost scales with the number of CLI invocations, not with the assertions.
 */

import { spawn } from 'node:child_process';
import type { ChildProcessWithoutNullStreams } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  existsSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { Buffer } from 'node:buffer';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { afterEach, expect } from 'vitest';
import type { ChainRecord } from '../../../src/schema/events.js';

export const REPO_ROOT = fileURLToPath(new URL('../../..', import.meta.url));

/**
 * The published entry point, not a source file. `package.json` maps
 * `bin.mcp-recorder` to `dist/cli.js`, and `dist/` is committed and gated in
 * CI ("dist/ is committed and current"), so this is the exact artifact a user
 * installs.
 */
export const CLI_JS = join(REPO_ROOT, 'dist', 'cli.js');

export const E2E_FIXTURES = fileURLToPath(new URL('../fixtures/', import.meta.url));

/** The wire fixture server: a real stdio JSON-RPC server with a byte journal. */
export const WIRE_SERVER = join(E2E_FIXTURES, 'wire-server.cjs');

/* --------------------------- build freshness ----------------------------- */

function newestMtimeMs(dir: string, suffix: string): number {
  let newest = 0;
  const walk = (path: string): void => {
    for (const entry of readdirSync(path, { withFileTypes: true })) {
      const child = join(path, entry.name);
      if (entry.isDirectory()) walk(child);
      else if (entry.name.endsWith(suffix)) newest = Math.max(newest, statSync(child).mtimeMs);
    }
  };
  walk(dir);
  return newest;
}

/**
 * Resolve the binary under test, and refuse to test a stale one.
 *
 * Testing `dist/` only means something if `dist/` is the current `src/`. CI
 * builds before it tests, so this never fires there; locally it turns "my e2e
 * assertions disagree with the code I just wrote" into one sentence naming
 * the command. The 5 s slack absorbs a fresh clone or `git worktree add`,
 * which writes `dist/` and `src/` seconds apart with no compile in between —
 * a false "stale" there would fail the suite for nobody's benefit, while a
 * genuinely stale `dist/` is minutes or hours behind, not seconds.
 *
 * `MCP_RECORDER_E2E_CLI` overrides the path outright (for testing a packed
 * tarball's install); `MCP_RECORDER_E2E_ALLOW_STALE=1` keeps the staleness
 * check quiet when you know what you are doing.
 */
export function builtCli(): string {
  const override = process.env.MCP_RECORDER_E2E_CLI;
  if (override !== undefined && override !== '') return override;
  if (!existsSync(CLI_JS)) {
    throw new Error(`e2e: ${CLI_JS} does not exist — run \`npm run compile\` first`);
  }
  if (process.env.MCP_RECORDER_E2E_ALLOW_STALE === '1') return CLI_JS;
  const built = statSync(CLI_JS).mtimeMs;
  const newestSource = newestMtimeMs(join(REPO_ROOT, 'src'), '.ts');
  if (newestSource > built + 5_000) {
    throw new Error(
      'e2e: dist/ is older than src/ — these tests drive the BUILT binary, so they would ' +
        'be testing yesterday\'s code. Run `npm run compile` (or set ' +
        'MCP_RECORDER_E2E_ALLOW_STALE=1 to test dist/ as it stands).',
    );
  }
  return CLI_JS;
}

/**
 * tsx's LOADER entry (`node --import <loader> script.ts`), for the two
 * fixtures that are TypeScript: the reference receiver and the demo server.
 *
 * The loader rather than tsx's CLI, because the CLI is a parent process that
 * spawns the real script and relays signals to it — a teardown kill can leave
 * the child holding a port (test/helpers/tsx.ts documents the same trap). It
 * is resolved through node's own lookup rather than by path, so a git
 * worktree sharing its parent checkout's node_modules still finds it.
 */
export function tsxLoader(): string | undefined {
  try {
    const require = createRequire(join(REPO_ROOT, 'noop.js'));
    return join(dirname(require.resolve('tsx/package.json')), 'dist', 'loader.mjs');
  } catch {
    return undefined;
  }
}

/** tsx is a devDependency, so this is true in CI; a bare checkout may differ. */
export const TSX_AVAILABLE = tsxLoader() !== undefined;

/* ------------------------------- teardown -------------------------------- */

const cleanups: Array<() => void> = [];

afterEach(() => {
  while (cleanups.length > 0) {
    try {
      cleanups.pop()!();
    } catch {
      /* best-effort teardown: a leaked temp dir must not fail a green test */
    }
  }
});

export function onCleanup(fn: () => void): void {
  cleanups.push(fn);
}

export function tmpDir(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  cleanups.push(() => rmSync(dir, { recursive: true, force: true }));
  return dir;
}

/* --------------------------------- env ----------------------------------- */

/**
 * A clean environment for a child.
 *
 * Every MCP_RECORDER_* / MCPR_RECEIVER_* variable is stripped before the
 * per-test overrides go on. A developer who exports MCP_RECORDER_SINK or
 * MCP_RECORDER_DISABLE in their shell (both documented workflows) would
 * otherwise silently change what these tests measure — MCP_RECORDER_DISABLE=1
 * in particular turns every enforcement assertion into a vacuous pass.
 */
export function cleanEnv(overrides: Record<string, string | undefined> = {}): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = { ...process.env };
  for (const key of Object.keys(env)) {
    if (key.startsWith('MCP_RECORDER_') || key.startsWith('MCPR_RECEIVER_')) delete env[key];
  }
  for (const [key, value] of Object.entries(overrides)) {
    if (value === undefined) delete env[key];
    else env[key] = value;
  }
  return env;
}

/* ------------------------------ running it ------------------------------- */

export interface CliResult {
  code: number | null;
  stdout: string;
  stderr: string;
}

/** Run the built CLI to completion with stdin closed. */
export function runCli(
  args: string[],
  env: Record<string, string | undefined> = {},
): Promise<CliResult> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [builtCli(), ...args], {
      cwd: REPO_ROOT,
      env: cleanEnv(env),
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', (c: string) => (stdout += c));
    child.stderr.on('data', (c: string) => (stderr += c));
    child.stdin.end();
    child.once('error', reject);
    child.once('close', (code) => resolve({ code, stdout, stderr }));
  });
}

export interface RpcMessage {
  jsonrpc?: string;
  id?: string | number | null;
  method?: string;
  result?: Record<string, unknown>;
  error?: { code: number; message: string };
}

/**
 * A driven `record`/gateway session: the client half of the stdio wire.
 *
 * stdout is kept as RAW BYTES as well as lines, because byte transparency is
 * one of the properties under test and a string round-trip through a decoder
 * is exactly the kind of thing that would hide a breach of it.
 */
export interface RecorderSession {
  readonly child: ChildProcessWithoutNullStreams;
  /** Write bytes to the recorder's stdin verbatim (no newline added). */
  writeRaw(bytes: string | Buffer): void;
  /** Write one JSON-RPC message as a `\n`-terminated line. */
  send(message: unknown): void;
  /** Next stdout LINE (terminator stripped), or reject on timeout. */
  nextLine(timeoutMs?: number): Promise<string>;
  /** Next stdout line that parses as JSON-RPC with this id. */
  response(id: number, timeoutMs?: number): Promise<RpcMessage>;
  /** Everything the recorder has written to stdout so far, as raw bytes. */
  stdoutBytes(): Buffer;
  stderr(): string;
  /** Close stdin and wait for exit; resolves with the exit code. */
  end(timeoutMs?: number): Promise<number | null>;
  kill(): void;
}

export function startRecorder(
  args: string[],
  env: Record<string, string | undefined> = {},
): RecorderSession {
  const child = spawn(process.execPath, [builtCli(), ...args], {
    cwd: REPO_ROOT,
    env: cleanEnv(env),
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  cleanups.push(() => {
    if (child.exitCode === null) child.kill('SIGKILL');
  });

  const chunks: Buffer[] = [];
  const ready: string[] = [];
  const waiters: Array<{ resolve(line: string): void; timer: NodeJS.Timeout }> = [];
  let pending = '';
  let stderrText = '';

  child.stdout.on('data', (chunk: Buffer) => {
    chunks.push(Buffer.from(chunk));
    pending += chunk.toString('utf8');
    let nl: number;
    while ((nl = pending.indexOf('\n')) !== -1) {
      const line = pending.slice(0, nl).replace(/\r$/, '');
      pending = pending.slice(nl + 1);
      if (line === '') continue;
      const waiter = waiters.shift();
      if (waiter !== undefined) {
        clearTimeout(waiter.timer);
        waiter.resolve(line);
      } else ready.push(line);
    }
  });
  child.stderr.setEncoding('utf8');
  child.stderr.on('data', (chunk: string) => (stderrText += chunk));

  const nextLine = (timeoutMs = 20_000): Promise<string> => {
    const got = ready.shift();
    if (got !== undefined) return Promise.resolve(got);
    return new Promise<string>((resolve, reject) => {
      const timer = setTimeout(
        () => reject(new Error(`e2e: timed out waiting for a stdout line; stderr so far:\n${stderrText}`)),
        timeoutMs,
      );
      waiters.push({ resolve, timer });
    });
  };

  return {
    child,
    writeRaw(bytes) {
      child.stdin.write(bytes);
    },
    send(message) {
      child.stdin.write(JSON.stringify(message) + '\n');
    },
    nextLine,
    async response(id, timeoutMs = 20_000) {
      // Bounded: a server may interleave notifications, but not forever.
      for (let i = 0; i < 25; i++) {
        const line = await nextLine(timeoutMs);
        let msg: RpcMessage;
        try {
          msg = JSON.parse(line) as RpcMessage;
        } catch {
          continue; // non-JSON noise on the wire is not this helper's business
        }
        if (msg.id === id) return msg;
      }
      throw new Error(`e2e: no JSON-RPC response with id ${String(id)}`);
    },
    stdoutBytes: () => Buffer.concat(chunks),
    stderr: () => stderrText,
    end(timeoutMs = 30_000) {
      child.stdin.end();
      return new Promise<number | null>((resolve, reject) => {
        const timer = setTimeout(() => {
          child.kill('SIGKILL');
          reject(new Error(`e2e: recorder did not exit within ${String(timeoutMs)} ms`));
        }, timeoutMs);
        child.once('close', (code) => {
          clearTimeout(timer);
          resolve(code);
        });
      });
    },
    kill() {
      if (child.exitCode === null) child.kill('SIGKILL');
    },
  };
}

/** The standard MCP handshake opener, so every suite starts the same way. */
export const INITIALIZE = {
  jsonrpc: '2.0',
  id: 1,
  method: 'initialize',
  params: {
    protocolVersion: '2024-11-05',
    clientInfo: { name: 'mcp-recorder-e2e', version: '0.0.1' },
    capabilities: {},
  },
} as const;

/* ------------------------- the server's own record ------------------------ */

export interface JournalEntry {
  /** Exactly the bytes the server read, terminator included. */
  raw: Buffer;
  /** Convenience: `raw` as utf8 with the terminator trimmed. */
  text: string;
}

/**
 * What the upstream server ACTUALLY received.
 *
 * This is the only honest place to assert "the denied call never reached the
 * server" or "the real credential arrived, and the synthetic did not": the
 * recorder's own evidence is the thing under test, so it cannot also be the
 * witness.
 */
export function readJournal(path: string): JournalEntry[] {
  if (!existsSync(path)) return [];
  return readFileSync(path, 'utf8')
    .split('\n')
    .filter((l) => l.trim() !== '')
    .map((l) => {
      const parsed = JSON.parse(l) as { b64: string };
      const raw = Buffer.from(parsed.b64, 'base64');
      return { raw, text: raw.toString('utf8').replace(/\r?\n$/, '') };
    });
}

/** Every `tools/call` the server saw, in order, already parsed. */
export function journalToolCalls(path: string): Array<{ name: string; arguments: Record<string, unknown> }> {
  const calls: Array<{ name: string; arguments: Record<string, unknown> }> = [];
  for (const entry of readJournal(path)) {
    let msg: { method?: string; params?: { name?: string; arguments?: Record<string, unknown> } };
    try {
      msg = JSON.parse(entry.text) as typeof msg;
    } catch {
      continue;
    }
    if (msg.method !== 'tools/call' || typeof msg.params?.name !== 'string') continue;
    calls.push({ name: msg.params.name, arguments: msg.params.arguments ?? {} });
  }
  return calls;
}

/* ------------------------------ the store -------------------------------- */

export function readChain(dataDir: string): ChainRecord[] {
  return readFileSync(join(dataDir, 'evidence.jsonl'), 'utf8')
    .split('\n')
    .filter((l) => l.trim() !== '')
    .map((l) => JSON.parse(l) as ChainRecord);
}

export function sha256Hex(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

/** The `ref` form the recorder writes into events (`sha256:<hex>`). */
export function sha256Ref(value: string): string {
  return `sha256:${sha256Hex(value)}`;
}

export interface DataDirHit {
  file: string;
  /** Which form was found: the value itself, or its unsalted sha256 ref. */
  form: 'literal' | 'ref';
}

/**
 * Scan every byte of a data directory for a value AND for its unsalted
 * sha256.
 *
 * Both forms matter. Redaction refs are unsalted sha256 by design, so a ref
 * of a brokered secret is a brute-forceable copy of it: for a value that must
 * never enter the evidence chain, "the literal is absent" is only half the
 * claim (src/redact/redactor.ts, `isRecorderOwnEnvVar`).
 */
export function scanDataDir(dataDir: string, needle: string): DataDirHit[] {
  const literal = Buffer.from(needle, 'utf8');
  const ref = Buffer.from(sha256Hex(needle), 'utf8');
  const hits: DataDirHit[] = [];
  const walk = (dir: string): void => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const path = join(dir, entry.name);
      if (entry.isDirectory()) {
        walk(path);
        continue;
      }
      if (!entry.isFile()) continue;
      const bytes = readFileSync(path);
      if (bytes.includes(literal)) hits.push({ file: path, form: 'literal' });
      if (bytes.includes(ref)) hits.push({ file: path, form: 'ref' });
    }
  };
  if (existsSync(dataDir)) walk(dataDir);
  return hits;
}

/* ------------------------------ misc waits -------------------------------- */

export async function waitFor(
  predicate: () => boolean | Promise<boolean>,
  what: string,
  timeoutMs = 30_000,
  stepMs = 50,
): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    if (await predicate()) return;
    if (Date.now() >= deadline) throw new Error(`e2e: timed out waiting for ${what}`);
    await new Promise((resolve) => setTimeout(resolve, stepMs));
  }
}

/**
 * Kill a detached shipper that `record` auto-started for this data dir.
 *
 * `ensureShipper` spawns it `detached` + `unref`'d with the default
 * `--idle-exit 15m`, so without this a suite would leave background processes
 * behind holding a deleted temp dir open. The pid is in the lock's own
 * provenance file (src/sink/state.ts).
 */
export function killDetachedShipper(dataDir: string): void {
  const owner = join(dataDir, 'ship.lock', 'owner');
  if (!existsSync(owner)) return;
  const pid = Number(readFileSync(owner, 'utf8').trim().split(/\s+/)[0]);
  if (!Number.isInteger(pid) || pid <= 0) return;
  try {
    process.kill(pid, 'SIGKILL');
  } catch {
    /* already gone, which is the outcome we wanted anyway */
  }
}

/**
 * Assert a needle appears nowhere in the data dir, printing WHERE it does.
 * A bare `expect(hits).toEqual([])` reports "[] !== [ ...20 lines... ]".
 */
export function expectAbsentFromDataDir(dataDir: string, needle: string, what: string): void {
  const hits = scanDataDir(dataDir, needle);
  expect(hits.map((h) => `${h.form} in ${h.file}`), `${what} leaked into the evidence`).toEqual([]);
}
