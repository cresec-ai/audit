/**
 * Start the REFERENCE RECEIVER (receiver/) as a real process, over real HTTP.
 *
 * Not the in-test fake in test/helpers/sink-receiver.ts: that one exists to
 * assert the sender's wire behaviour under hostile receivers, and it lives in
 * the same process as the test. Here the point is the opposite — a separate
 * program, listening on a real port, writing its own files — because the
 * regression this suite is shaped around (a live shipper extending a chain
 * whose history had been rewritten) only exists when both halves are
 * processes.
 *
 * Run through tsx's loader rather than tsx's CLI: the CLI is a parent that
 * spawns the real script and relays signals, so killing it in teardown can
 * leave the server holding the port (test/helpers/tsx.ts documents the same
 * trap for signal tests).
 */

import { spawn } from 'node:child_process';
import type { ChildProcessByStdio } from 'node:child_process';
import type { Readable } from 'node:stream';
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { REPO_ROOT, cleanEnv, onCleanup, tsxLoader } from './harness.js';
import type { ChainRecord } from '../../../src/schema/events.js';

export { TSX_AVAILABLE } from './harness.js';

export interface RunningReceiver {
  url: string;
  dataDir: string;
  token: string;
  stdout(): string;
  /** Chain ids the receiver has created a directory for. */
  chainIds(): string[];
  /** Records the receiver has durably stored for a chain, in seq order. */
  records(chainId: string): ChainRecord[];
  /** Every refusal the receiver wrote down, with its reason. */
  rejections(): Array<{ status: number; error: string; detail: string }>;
  alerts(): Array<{ kind: string; detail: string }>;
  stop(): void;
}

export interface ReceiverOptions {
  /**
   * `pinned` enrolment with exactly these 64-hex keys (receiver/auth.ts):
   * a sender whose key is not listed is refused with 403 and stores
   * nothing. Default: `tofu`, the posture a one-shot test deployment has.
   */
  pinnedKeys?: string[];
}

export async function startReceiver(dataDir: string, token: string, opts: ReceiverOptions = {}): Promise<RunningReceiver> {
  const loader = tsxLoader();
  if (loader === undefined) throw new Error('e2e: tsx is not installed; cannot run the receiver');

  // stdin is 'ignore': the receiver reads nothing, and a pipe nobody writes
  // to is one more handle keeping teardown open.
  const child: ChildProcessByStdio<null, Readable, Readable> = spawn(
    process.execPath,
    [
      '--import',
      pathToFileURL(loader).href,
      join(REPO_ROOT, 'receiver', 'main.ts'),
      'serve',
      '--data-dir',
      dataDir,
      '--host',
      '127.0.0.1',
      '--port',
      '0',
    ],
    {
      cwd: REPO_ROOT,
      env: cleanEnv({
        MCPR_RECEIVER_TOKEN: token,
        // The install's key is minted by the recorder at first run, so the
        // receiver cannot have been told about it in advance. 'tofu' binds
        // the first key it sees and flags it `new_identity` — the posture a
        // one-shot test deployment actually has. `pinned` is the fleet
        // posture (S18): the operator registered the key out of band.
        ...(opts.pinnedKeys === undefined
          ? { MCPR_RECEIVER_ENROLMENT: 'tofu' }
          : { MCPR_RECEIVER_ENROLMENT: 'pinned', MCPR_RECEIVER_KEYS: opts.pinnedKeys.join(',') }),
      }),
      stdio: ['ignore', 'pipe', 'pipe'],
    },
  );
  onCleanup(() => {
    if (child.exitCode === null) child.kill('SIGKILL');
  });

  let stdout = '';
  let stderr = '';
  child.stdout.setEncoding('utf8');
  child.stderr.setEncoding('utf8');
  child.stdout.on('data', (c: string) => (stdout += c));
  child.stderr.on('data', (c: string) => (stderr += c));

  const url = await new Promise<string>((resolve, reject) => {
    const timer = setTimeout(
      () => reject(new Error(`e2e: receiver did not report a listen address.\n${stdout}\n${stderr}`)),
      30_000,
    );
    const poll = setInterval(() => {
      const match = /listening\s+(\S+)/.exec(stdout);
      if (match === null) return;
      clearInterval(poll);
      clearTimeout(timer);
      resolve(match[1]!);
    }, 50);
    child.once('exit', (code) => {
      clearInterval(poll);
      clearTimeout(timer);
      reject(new Error(`e2e: receiver exited with ${String(code)}.\n${stdout}\n${stderr}`));
    });
  });

  const readJsonl = <T>(path: string): T[] =>
    existsSync(path)
      ? readFileSync(path, 'utf8')
          .split('\n')
          .filter((l) => l.trim() !== '')
          .map((l) => JSON.parse(l) as T)
      : [];

  return {
    url,
    dataDir,
    token,
    stdout: () => stdout,
    chainIds() {
      const dir = join(dataDir, 'chains');
      return existsSync(dir) ? readdirSync(dir) : [];
    },
    records(chainId) {
      return readJsonl<{ seq: number; record: ChainRecord }>(
        join(dataDir, 'chains', chainId, 'records.jsonl'),
      )
        .sort((a, b) => a.seq - b.seq)
        .map((r) => r.record);
    },
    rejections: () => readJsonl(join(dataDir, 'rejections.jsonl')),
    alerts: () => readJsonl(join(dataDir, 'alerts.jsonl')),
    stop() {
      if (child.exitCode === null) child.kill('SIGKILL');
    },
  };
}
