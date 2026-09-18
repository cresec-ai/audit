/**
 * e2e 5 — `verify` / `query` / `sessions` / `export` against a real store.
 *
 * These are the commands an incident actually runs, and the failure mode they
 * have to exclude is disagreement between processes: `record` writing one
 * backend while `verify` reads another, `export` producing a bundle only this
 * repo can check, `query` finding a value it should not or missing one it
 * should. All of that is invisible to a test that calls the functions — it
 * needs two separate runs of the built binary over one directory on disk,
 * which is what this file does.
 *
 * The bundle case goes one step further and runs the bundle's own
 * `verify.cjs` with plain `node` and no flags, because "a stranger can verify
 * this with nothing but Node.js" is the claim, and the only way to test that
 * claim is to be the stranger.
 */

import { describe, expect, it } from 'vitest';
import { spawn } from 'node:child_process';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  INITIALIZE,
  WIRE_SERVER,
  readChain,
  runCli,
  startRecorder,
  tmpDir,
} from './helpers/harness.js';

const NOTE_A = 'e2e-inspect-alpha-8d21f6';
const NOTE_B = 'e2e-inspect-beta-3a77c9';
/** Never sent anywhere. The needle that must find nothing. */
const NEVER_SENT = 'e2e-inspect-never-sent-0000ff';

interface QueryOutput {
  matches: Array<{ kind: string; matched_on: string; name?: string; session_id: string }>;
}

async function recordNote(
  dataDir: string,
  journal: string,
  note: string,
  extraArgs: string[] = [],
): Promise<string> {
  const rec = startRecorder(
    ['record', '--data-dir', dataDir, ...extraArgs, '--', process.execPath, WIRE_SERVER],
    { E2E_JOURNAL: journal },
  );
  rec.send(INITIALIZE);
  await rec.response(1);
  rec.send({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'echo', arguments: { note } } });
  await rec.response(2);
  expect(await rec.end()).toBe(0);
  return rec.stderr();
}

function runNode(args: string[], cwd: string): Promise<{ code: number | null; stdout: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, args, { cwd, stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '';
    child.stdout.setEncoding('utf8');
    child.stdout.on('data', (c: string) => (stdout += c));
    child.stderr.setEncoding('utf8');
    child.stderr.on('data', (c: string) => (stdout += c));
    child.once('error', reject);
    child.once('close', (code) => resolve({ code, stdout }));
  });
}

describe('e2e inspection commands over a real store', () => {
  it('sessions / query / verify agree with each other across separate processes', async () => {
    const dir = tmpDir('e2e-inspect-');
    const dataDir = join(dir, 'data');
    const store = ['--store', 'jsonl'];

    await recordNote(dataDir, join(dir, 'a.jsonl'), NOTE_A, store);
    await recordNote(dataDir, join(dir, 'b.jsonl'), NOTE_B, store);
    const chain = readChain(dataDir);

    const sessions = await runCli(['sessions', '--data-dir', dataDir, ...store, '--json']);
    expect(sessions.code).toBe(0);
    const list = JSON.parse(sessions.stdout) as Array<{
      session_id: string;
      tool_call_count: number;
      event_count: number;
    }>;
    expect(list).toHaveLength(2);
    expect(list.map((s) => s.tool_call_count)).toEqual([1, 1]);
    expect(list.reduce((n, s) => n + s.event_count, 0)).toBe(chain.length);

    // `query` finds the argument by its ref: the value never entered the
    // store, but the chain can still answer "was this touched?".
    const hit = await runCli(['query', NOTE_A, '--data-dir', dataDir, ...store, '--json']);
    expect(hit.code).toBe(0);
    const found = JSON.parse(hit.stdout) as QueryOutput;
    expect(found.matches.some((m) => m.kind === 'tool_call' && m.matched_on === 'ref' && m.name === 'echo')).toBe(true);
    // Scoped to the session that actually used it, not to both.
    expect(new Set(found.matches.map((m) => m.session_id)).size).toBe(1);

    // NEGATIVE CONTROL (in-suite): a needle of exactly the same shape that
    // was never sent finds nothing. Without it, "query found a match" could
    // mean "query matches everything" — which is the failure mode a
    // hash-based index has when the hashing is skipped.
    const miss = await runCli(['query', NEVER_SENT, '--data-dir', dataDir, ...store, '--json']);
    expect(miss.code).toBe(0);
    expect((JSON.parse(miss.stdout) as QueryOutput).matches).toEqual([]);

    const verify = await runCli(['verify', '--data-dir', dataDir, ...store, '--json']);
    expect(verify.code).toBe(0);
    const verdict = JSON.parse(verify.stdout) as { ok: boolean; checked_events: number };
    expect(verdict.ok).toBe(true);
    expect(verdict.checked_events).toBe(chain.length);
  }, 120_000);

  it('an exported bundle verifies with plain node, and stops verifying when edited', async () => {
    const dir = tmpDir('e2e-bundle-');
    const dataDir = join(dir, 'data');
    const store = ['--store', 'jsonl'];
    await recordNote(dataDir, join(dir, 'a.jsonl'), NOTE_A, store);

    const bundleDir = join(dir, 'bundle');
    const exported = await runCli(['export', '--data-dir', dataDir, ...store, '--dir', bundleDir]);
    expect(exported.code).toBe(0);
    for (const file of ['events.jsonl', 'manifest.json', 'public_key.pem', 'verify.cjs', 'README.txt']) {
      expect(existsSync(join(bundleDir, file)), `${file} should be in the bundle`).toBe(true);
    }

    // The stranger's test: plain node, no flags, no repo.
    const stranger = await runNode(['verify.cjs'], bundleDir);
    expect(stranger.code).toBe(0);
    expect(stranger.stdout).toContain('PASS');

    const ours = await runCli(['verify', '--bundle', bundleDir]);
    expect(ours.code).toBe(0);
    expect(ours.stdout).toContain('PASS');

    // NEGATIVE CONTROL (in-suite): edit one word inside an exported event and
    // both verifiers must refuse it. A `verify.cjs` that printed PASS
    // unconditionally — or that checked only the manifest — would pass the
    // three assertions above and fail here.
    const events = join(bundleDir, 'events.jsonl');
    const original = readFileSync(events, 'utf8');
    const edited = original.replace('"echo"', '"ech0"');
    expect(edited).not.toBe(original);
    writeFileSync(events, edited);

    const strangerAfter = await runNode(['verify.cjs'], bundleDir);
    expect(strangerAfter.code).toBe(1);
    expect(strangerAfter.stdout).toContain('FAIL');
    const oursAfter = await runCli(['verify', '--bundle', bundleDir]);
    expect(oursAfter.code).toBe(1);
  }, 120_000);

  it('the default store backend is the same one in every command (no --store anywhere)', async () => {
    // The backend is resolved per process from config + what optional deps
    // are installed. A `record` that writes sqlite while `verify` reads jsonl
    // is a silent "0 events" rather than an error, and no unit test can see
    // it: both processes have to be real, and neither may be told which
    // backend to use.
    const dir = tmpDir('e2e-default-store-');
    const dataDir = join(dir, 'data');
    const stderr = await recordNote(dataDir, join(dir, 'a.jsonl'), NOTE_A);

    const sessionPrefix = /session ([0-9a-f]{8}) recorded (\d+) events/.exec(stderr);
    expect(sessionPrefix, `no session summary in:\n${stderr}`).not.toBeNull();
    const [, prefix, recordedCount] = sessionPrefix!;

    const backends = ['evidence.db', 'evidence.jsonl'].filter((f) => existsSync(join(dataDir, f)));
    expect(backends).toHaveLength(1);

    const sessions = await runCli(['sessions', '--data-dir', dataDir, '--json']);
    expect(sessions.code).toBe(0);
    const list = JSON.parse(sessions.stdout) as Array<{ session_id: string; event_count: number }>;
    expect(list).toHaveLength(1);

    // NEGATIVE CONTROL (in-suite): the session id and the event count both
    // have to match what the recording process printed on its own stderr. A
    // reader that opened an empty store of the other backend would return
    // zero sessions; one that returned a session from somewhere else would
    // disagree on the id.
    expect(list[0]!.session_id.startsWith(prefix!)).toBe(true);
    // The summary line counts every event of the run, session_start and
    // session_end included, so it is directly comparable with the store's own
    // count for a single-session data dir.
    expect(list[0]!.event_count).toBe(Number(recordedCount));

    const verify = await runCli(['verify', '--data-dir', dataDir]);
    expect(verify.code).toBe(0);
    expect(verify.stdout).toContain('PASS');

    const hit = await runCli(['query', NOTE_A, '--data-dir', dataDir, '--json']);
    expect(hit.code).toBe(0);
    expect((JSON.parse(hit.stdout) as QueryOutput).matches.length).toBeGreaterThan(0);
  }, 120_000);
});
