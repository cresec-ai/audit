import { mkdtempSync, appendFileSync, existsSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { once } from 'node:events';
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterEach, describe, expect, it } from 'vitest';
import { spawnTsx, spawnTsxSync } from './helpers/tsx.js';
import { openStore, isSqliteAvailable } from '../src/store/index.js';
import { DurableDelivery } from '../src/capture/spool.js';
import { reconcileStore } from '../src/capture/reconcile.js';
import { verifyStore } from '../src/verify/verify.js';
import { FILES } from '../src/types.js';

const root = fileURLToPath(new URL('..', import.meta.url));
const cleanups: Array<() => void | Promise<void>> = [];
afterEach(async () => { for (const cleanup of cleanups.splice(0).reverse()) await cleanup(); });
function directory(): string {
  const dir = mkdtempSync(join(tmpdir(), 'mcp-fault-'));
  cleanups.push(() => rmSync(dir, { recursive: true, force: true })); return dir;
}
async function until(predicate: () => boolean, hint: () => string = () => ''): Promise<void> {
  const deadline = Date.now() + 20_000;
  while (!predicate()) {
    if (Date.now() > deadline) throw new Error('fault checkpoint not reached: ' + hint());
    await new Promise((r) => setTimeout(r, 25));
  }
}
function child(args: string[]) {
  const proc = spawnTsx(args, { cwd: root });
  let output = ''; proc.stdout.on('data', (c: Buffer) => { output += c.toString(); });
  proc.stderr.on('data', (c: Buffer) => { output += c.toString(); });
  cleanups.push(async () => { if (proc.exitCode === null && proc.signalCode === null) await kill(proc); });
  return { proc, output: () => output };
}
async function kill(proc: ChildProcessWithoutNullStreams): Promise<void> {
  const exited = once(proc, 'exit');
  proc.kill('SIGKILL'); // Node maps this to forced TerminateProcess on Windows.
  await exited;
}
function cli(dataDir: string, backend: string, args: string[]) {
  return spawnTsxSync(['src/cli.ts', ...args, '--data-dir', dataDir, '--store', backend], { cwd: root, encoding: 'utf8', timeout: 30_000 });
}

for (const backend of ['jsonl', ...(isSqliteAvailable() ? ['sqlite' as const] : [])] as const) {
  describe(`${backend} actual process death`, () => {
    for (const mode of ['append', 'committed', 'offline', ...(backend === 'jsonl' ? ['signature', 'journal', 'full', 'queue'] : [])]) {
      it(`recovers ${mode} without duplicated evidence or invented success`, async () => {
        const dataDir = directory();
        const { proc, output } = child(['test/fixtures/evidence-fault.ts', dataDir, backend, mode]);
        await until(() => existsSync(join(dataDir, 'fault-ready')), output);
        const expected = JSON.parse(readFileSync(join(dataDir, 'expected.json'), 'utf8')) as string[];
        expect(existsSync(join(dataDir, 'delivery/pending.jsonl'))).toBe(mode !== 'queue');
        await kill(proc);
        // Recovery runs in a new OS process. JSONL may retain the existing
        // store's short-lived stale lock after termination inside append.
        let recovery = cli(dataDir, backend, ['reconcile', '--recover', '--json']);
        await until(() => {
          if (recovery.status === 3 && JSON.parse(recovery.stdout).delivery.pending_events === 0) return true;
          recovery = cli(dataDir, backend, ['reconcile', '--recover', '--json']);
          return false;
        }, () => recovery.stderr + recovery.stdout);
        expect(recovery.status, recovery.stderr).toBe(3); // dirty exit is always a gap
        const store = openStore({ dataDir, backend });
        let count: number;
        try {
          const events = [...store.iterate()].map((r) => r.event);
          const ids = events.map((e) => e.event_id);
          expect(new Set(ids).size).toBe(ids.length);
          if (mode === 'queue') expect(expected.filter((id) => ids.includes(id))).toHaveLength(0);
          else if (mode === 'journal') expect(expected.filter((id) => ids.includes(id))).toHaveLength(1);
          else if (mode === 'full') expect(expected.filter((id) => ids.includes(id)).length).toBeLessThan(expected.length);
          else for (const id of expected) expect(ids.filter((found) => found === id)).toHaveLength(1);
          const gaps = reconcileStore(store).gaps;
          expect(gaps.some((g) => g.reason === 'recorder_exit')).toBe(true);
          if (mode === 'journal') expect(gaps.some((g) => g.reason === 'torn_spool')).toBe(true);
          if (mode === 'full') expect(gaps.some((g) => g.reason === 'spool_full')).toBe(true);
          expect(events.some((e) => e.kind === 'action_lifecycle' && e.outcome === 'success')).toBe(false);
          expect((await verifyStore(store)).ok).toBe(true);
          count = store.count();
        } finally { store.close(); }
        expect(cli(dataDir, backend, ['reconcile', '--recover']).status).toBe(3);
        const check = openStore({ dataDir, backend });
        try { expect(check.count()).toBe(count); } finally { check.close(); }
      }, 40_000);
    }
  });
}

for (const transport of ['stdio', 'http'] as const) {
  it(`${transport}: a killed gateway with an admitted pending write recovers unknown, never re-executes`, async () => {
    const dataDir = directory();
    const policy = join(dataDir, 'allow.json');
    writeFileSync(policy, JSON.stringify({ version: 1, mcp: { default: 'allow', rules: [] } }));
    const request = { jsonrpc: '2.0', id: 7, method: 'tools/call', params: { name: 'write', arguments: { token: 'sk-live-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123' } } };
    const journal = join(dataDir, 'upstream.jsonl');
    let targetUrl = '';
    if (transport === 'http') {
      const target = createServer(async (req, res) => {
        const chunks: Buffer[] = []; for await (const chunk of req) chunks.push(Buffer.from(chunk));
        appendFileSync(journal, Buffer.concat(chunks).toString() + '\n');
        res.writeHead(202); res.end(); // RPC response remains outstanding
      });
      target.listen(0, '127.0.0.1'); await once(target, 'listening');
      targetUrl = `http://127.0.0.1:${(target.address() as AddressInfo).port}`;
      cleanups.push(() => new Promise<void>((r) => target.close(() => r())));
    }
    const common = ['--policy', policy, '--data-dir', dataDir, '--store', 'jsonl'];
    const { proc, output } = child(transport === 'stdio'
      ? ['src/cli.ts', 'record', ...common, '--', process.execPath, 'test/fixtures/pending-write-server.cjs', journal]
      : ['src/cli.ts', 'http', ...common, '--target', targetUrl, '--port', '0']);
    if (transport === 'stdio') proc.stdin.write(JSON.stringify(request) + '\n');
    else {
      await until(() => /http proxy listening at (http:\/\/[^ ]+)/.test(output()), output);
      const url = /http proxy listening at (http:\/\/[^ ]+)/.exec(output())![1]!;
      expect((await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(request) })).status).toBe(202);
    }
    cleanups.push(() => {
      if (existsSync(journal + '.pid')) { try { process.kill(Number(readFileSync(journal + '.pid', 'utf8')), 'SIGKILL'); } catch { /* child exited on stdin EOF */ } }
    });
    await until(() => {
      try { return existsSync(journal) && readFileSync(join(dataDir, FILES.JSONL_LOG), 'utf8').includes('"phase":"decision"'); }
      catch { return false; }
    }, output);
    await kill(proc);
    const report = cli(dataDir, 'jsonl', ['reconcile', '--recover', '--json']);
    expect(report.status, report.stderr).toBe(3);
    const parsed = JSON.parse(report.stdout);
    expect(parsed.allowed).toBe(1); expect(parsed.missing_outcomes).toHaveLength(0);
    expect(parsed.unknown_outcomes).toHaveLength(1);
    const unknown = parsed.unknown_outcomes[0];
    expect(unknown).toMatchObject({ outcome: 'unknown', reason: 'recorder_exit' });
    expect(parsed.gaps.some((g: { reason: string }) => g.reason === 'recorder_exit')).toBe(true);
    const initial = readFileSync(journal, 'utf8');
    expect(initial.trim().split('\n')).toHaveLength(1);
    expect(cli(dataDir, 'jsonl', ['reconcile', '--recover']).status).toBe(3);
    expect(readFileSync(journal, 'utf8')).toBe(initial);
    const chain = readFileSync(join(dataDir, FILES.JSONL_LOG), 'utf8');
    expect(chain).not.toContain(request.params.arguments.token);
    expect(chain).not.toContain('"outcome":"success"');
    // A recovered bundle is still verifiable by the dependency-free v1 verifier.
    const bundle = join(dataDir, 'bundle');
    expect(cli(dataDir, 'jsonl', ['export', '--dir', bundle]).status).toBe(0);
    const verified = spawnSync(process.execPath, [join(bundle, 'verify.cjs')], { cwd: bundle, encoding: 'utf8' });
    expect(verified.status, verified.stderr + verified.stdout).toBe(0);
  }, 40_000);
}

it('read-only inspection reports pending evidence before next-start recovery', async () => {
  const dataDir = directory();
  // Read-only CLI inspection cannot claim a clean report while a spool awaits replay.
  const { proc, output } = child(['test/fixtures/evidence-fault.ts', dataDir, 'jsonl', 'offline']);
  await until(() => existsSync(join(dataDir, 'fault-ready')), output);
  const pending = cli(dataDir, 'jsonl', ['reconcile', '--json']);
  expect(pending.status).toBe(3); expect(JSON.parse(pending.stdout).delivery.pending_events).toBe(2);
  await kill(proc);
  const delivery = new DurableDelivery({ dataDir, openStore: () => openStore({ dataDir, backend: 'jsonl' }) });
  await delivery.start(); await delivery.close();
  expect(existsSync(join(dataDir, 'delivery/pending.jsonl'))).toBe(false);
});

it('the live recorder replays on its timer after store recovery, with no new traffic', async () => {
  const dataDir = directory();
  const { proc, output } = child(['test/fixtures/evidence-fault.ts', dataDir, 'jsonl', 'recovering']);
  await until(() => existsSync(join(dataDir, 'fault-ready')), output);
  expect(existsSync(join(dataDir, 'delivery/pending.jsonl'))).toBe(true);
  writeFileSync(join(dataDir, 'restore'), '');
  await until(() => !existsSync(join(dataDir, 'delivery/pending.jsonl')), output);
  expect(proc.exitCode).toBe(null);
  const store = openStore({ dataDir, backend: 'jsonl' });
  try { expect(store.count()).toBe(2); expect((await verifyStore(store)).ok).toBe(true); }
  finally { store.close(); }
  await kill(proc);
});

it('an upstream JSON-RPC timeout is unknown and the write is sent only once', async () => {
  const dataDir = directory(); let calls = 0;
  const target = createServer(async (req, res) => {
    req.resume(); await once(req, 'end');
    calls++;
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ jsonrpc: '2.0', id: 9, error: { code: -32001, message: 'timeout' } }));
  });
  target.listen(0, '127.0.0.1'); await once(target, 'listening');
  cleanups.push(() => new Promise<void>((r) => target.close(() => r())));
  const policy = join(dataDir, 'allow.json');
  writeFileSync(policy, JSON.stringify({ version: 1, mcp: { default: 'allow', rules: [] } }));
  const { proc, output } = child(['src/cli.ts', 'http', '--data-dir', dataDir, '--store', 'jsonl',
    '--policy', policy, '--port', '0', '--target', `http://127.0.0.1:${(target.address() as AddressInfo).port}`]);
  await until(() => /http proxy listening at (http:\/\/[^ ]+)/.test(output()), output);
  const url = /http proxy listening at (http:\/\/[^ ]+)/.exec(output())![1]!;
  const response = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 9, method: 'tools/call', params: { name: 'write', arguments: {} } }) });
  expect((await response.json() as { error: { code: number } }).error.code).toBe(-32001);
  await until(() => {
    try { return readFileSync(join(dataDir, FILES.JSONL_LOG), 'utf8').includes('"outcome":"unknown"'); }
    catch { return false; }
  });
  expect(calls).toBe(1);
  await kill(proc);
  const report = cli(dataDir, 'jsonl', ['reconcile', '--recover', '--json']);
  expect(JSON.parse(report.stdout).unknown_outcomes).toHaveLength(1);
  expect(calls).toBe(1);
});

it('a hook session ending without its post callback resolves the durable allow as unknown', () => {
  const dataDir = directory(); const policy = join(dataDir, 'allow.json');
  writeFileSync(policy, JSON.stringify({ version: 1, mcp: { default: 'allow', rules: [] } }));
  const session_id = 'a5a57f2e-05a6-42a9-95a0-a7149fcb0af7';
  const hook = (input: object) => spawnTsxSync(['src/cli.ts', 'hook', '--data-dir', dataDir, '--store', 'jsonl', '--policy', policy], {
    cwd: root, encoding: 'utf8', timeout: 30_000, input: JSON.stringify(input),
  });
  expect(hook({ session_id, hook_event_name: 'PreToolUse', tool_use_id: 'write-once',
    tool_name: 'mcp__server__write', tool_input: {} }).status).toBe(0);
  const pending = JSON.parse(cli(dataDir, 'jsonl', ['reconcile', '--json']).stdout);
  expect(pending.missing_outcomes).toHaveLength(1);
  expect(hook({ session_id, hook_event_name: 'SessionEnd', reason: 'logout' }).status).toBe(0);
  const report = JSON.parse(cli(dataDir, 'jsonl', ['reconcile', '--json']).stdout);
  expect(report.missing_outcomes).toHaveLength(0);
  expect(report.unknown_outcomes).toHaveLength(1);
  expect(report.unknown_outcomes[0].action_id).toBe(pending.missing_outcomes[0].action_id);
});
