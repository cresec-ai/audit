import { spawn } from 'node:child_process';
import type { ChildProcess } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { Readable } from 'node:stream';
import { fileURLToPath } from 'node:url';
import { afterEach, describe, expect, it } from 'vitest';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const ECHO_SERVER = fileURLToPath(new URL('./fixtures/echo-server.cjs', import.meta.url));

/* ------------------------------- helpers -------------------------------- */

const cleanups: Array<() => void> = [];
afterEach(() => {
  while (cleanups.length > 0) {
    try {
      cleanups.pop()!();
    } catch {
      /* best-effort teardown */
    }
  }
});

function tmpDir(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  cleanups.push(() => rmSync(dir, { recursive: true, force: true }));
  return dir;
}

function spawnCli(args: string[], env: Record<string, string | undefined> = {}): ChildProcess {
  const child = spawn('npx', ['tsx', 'src/cli.ts', ...args], {
    cwd: ROOT,
    env: { ...process.env, MCP_RECORDER_DISABLE: undefined, ...env },
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  cleanups.push(() => {
    if (child.exitCode === null) child.kill('SIGKILL');
  });
  return child;
}

interface CliResult {
  code: number | null;
  stdout: string;
  stderr: string;
}

function collect(stream: Readable | null): () => string {
  let text = '';
  stream?.setEncoding('utf8');
  stream?.on('data', (chunk: string) => {
    text += chunk;
  });
  return () => text;
}

function waitExit(child: ChildProcess): Promise<number | null> {
  return new Promise((resolve) => child.once('close', (code) => resolve(code)));
}

async function runCli(
  args: string[],
  env: Record<string, string | undefined> = {},
): Promise<CliResult> {
  const child = spawnCli(args, env);
  const stdout = collect(child.stdout);
  const stderr = collect(child.stderr);
  child.stdin?.end();
  const code = await waitExit(child);
  return { code, stdout: stdout(), stderr: stderr() };
}

interface LineReader {
  next(timeoutMs?: number): Promise<string>;
}

function lineReader(stream: Readable): LineReader {
  const ready: string[] = [];
  const waiters: Array<(line: string) => void> = [];
  let buf = '';
  stream.setEncoding('utf8');
  stream.on('data', (chunk: string) => {
    buf += chunk;
    let nl: number;
    while ((nl = buf.indexOf('\n')) !== -1) {
      const line = buf.slice(0, nl).trim();
      buf = buf.slice(nl + 1);
      if (line === '') continue;
      const waiter = waiters.shift();
      if (waiter !== undefined) waiter(line);
      else ready.push(line);
    }
  });
  return {
    next(timeoutMs = 20_000): Promise<string> {
      const got = ready.shift();
      if (got !== undefined) return Promise.resolve(got);
      return new Promise((resolve, reject) => {
        const timer = setTimeout(
          () => reject(new Error('timed out waiting for a stdout line')),
          timeoutMs,
        );
        waiters.push((line) => {
          clearTimeout(timer);
          resolve(line);
        });
      });
    },
  };
}

interface RpcMsg {
  jsonrpc: string;
  id?: string | number;
  method?: string;
  result?: Record<string, unknown>;
  error?: unknown;
}

async function readResponse(reader: LineReader, id: number): Promise<RpcMsg> {
  for (let i = 0; i < 20; i++) {
    const line = await reader.next();
    let msg: RpcMsg;
    try {
      msg = JSON.parse(line) as RpcMsg;
    } catch {
      continue; // non-JSON noise is not ours to judge
    }
    if (msg.id === id) return msg;
  }
  throw new Error(`no response with id ${id}`);
}

const PROBE = 'blast-probe-needle-12345';

/** Drive initialize + tools/call through a record-mode CLI child. */
async function driveSession(child: ChildProcess): Promise<void> {
  const reader = lineReader(child.stdout!);
  const send = (msg: unknown): void => {
    child.stdin!.write(JSON.stringify(msg) + '\n');
  };

  send({
    jsonrpc: '2.0',
    id: 1,
    method: 'initialize',
    params: {
      protocolVersion: '2024-11-05',
      clientInfo: { name: 'cli-test-client', version: '0.0.1' },
      capabilities: {},
    },
  });
  const init = await readResponse(reader, 1);
  expect((init.result as { serverInfo: { name: string } }).serverInfo.name).toBe('echo-server');

  send({
    jsonrpc: '2.0',
    id: 2,
    method: 'tools/call',
    params: { name: 'echo', arguments: { note: PROBE } },
  });
  const call = await readResponse(reader, 2);
  expect(JSON.stringify(call.result)).toContain(PROBE);

  child.stdin!.end();
}

/* --------------------------------- tests -------------------------------- */

describe('mcp-recorder CLI', () => {
  it('--help exits 0 and lists every subcommand', async () => {
    const res = await runCli(['--help']);
    expect(res.code).toBe(0);
    for (const sub of ['record', 'verify', 'query', 'sessions', 'ui', 'export', 'http']) {
      expect(res.stdout).toContain(sub);
    }
  }, 30_000);

  it('--version prints 0.1.0', async () => {
    const res = await runCli(['--version']);
    expect(res.code).toBe(0);
    expect(res.stdout.trim()).toBe('0.1.0');
  }, 30_000);

  it('a junk subcommand exits 2', async () => {
    const res = await runCli(['frobnicate']);
    expect(res.code).toBe(2);
    expect(res.stderr).toContain('[mcp-recorder] error:');
  }, 30_000);

  it('record e2e: proxy, then verify / sessions / query / ui / export all work', async () => {
    const dataDir = tmpDir('mcp-rec-cli-');

    // --- record (implicit subcommand via '--') -----------------------------
    const child = spawnCli(['--data-dir', dataDir, '--', 'node', ECHO_SERVER]);
    const stderrText = collect(child.stderr);
    await driveSession(child);
    const exitCode = await waitExit(child);
    expect(exitCode).toBe(0);
    expect(stderrText()).toMatch(/\[mcp-recorder\] session [0-9a-f]{8} recorded \d+ events/);

    // --- verify -------------------------------------------------------------
    const verify = await runCli(['verify', '--data-dir', dataDir]);
    expect(verify.code).toBe(0);
    expect(verify.stdout).toContain('PASS');

    const verifyJson = await runCli(['verify', '--data-dir', dataDir, '--json']);
    expect(verifyJson.code).toBe(0);
    const verifyResult = JSON.parse(verifyJson.stdout) as { ok: boolean; checked_events: number };
    expect(verifyResult.ok).toBe(true);
    expect(verifyResult.checked_events).toBeGreaterThanOrEqual(4);

    // --- sessions -----------------------------------------------------------
    const sessions = await runCli(['sessions', '--data-dir', dataDir, '--json']);
    expect(sessions.code).toBe(0);
    const list = JSON.parse(sessions.stdout) as Array<{ tool_call_count: number }>;
    expect(list).toHaveLength(1);
    expect(list[0]!.tool_call_count).toBe(1);

    const sessionsHuman = await runCli(['sessions', '--data-dir', dataDir]);
    expect(sessionsHuman.code).toBe(0);
    expect(sessionsHuman.stdout).toContain('SESSION');

    // --- query for the planted probe value ----------------------------------
    const query = await runCli(['query', PROBE, '--data-dir', dataDir]);
    expect(query.code).toBe(0);
    const summary = /(\d+) matches across (\d+) sessions/.exec(query.stdout);
    expect(summary).not.toBeNull();
    expect(Number(summary![1])).toBeGreaterThanOrEqual(1);
    expect(Number(summary![2])).toBe(1);
    expect(query.stdout).toContain('ref'); // matched on the redacted ref, not plaintext

    // --- ui --out FILE -------------------------------------------------------
    const htmlPath = join(tmpDir('mcp-rec-ui-'), 'replay.html');
    const ui = await runCli(['ui', '--data-dir', dataDir, '--out', htmlPath, '--no-open']);
    expect(ui.code).toBe(0);
    const html = readFileSync(htmlPath, 'utf8');
    expect(html).toContain('<!doctype html');
    expect(html).toContain('<span class="tool">echo</span>');
    expect(html).not.toContain(PROBE); // redacted evidence stays redacted in the UI

    // --- export --dir, then independent verification ------------------------
    const bundleDir = tmpDir('mcp-rec-bundle-');
    const exported = await runCli(['export', '--data-dir', dataDir, '--dir', bundleDir]);
    expect(exported.code).toBe(0);
    expect(exported.stderr).toContain('exported');
    for (const f of ['events.jsonl', 'manifest.json', 'public_key.pem', 'verify.cjs']) {
      expect(existsSync(join(bundleDir, f))).toBe(true);
    }

    const verifier = spawn('node', ['verify.cjs'], { cwd: bundleDir, stdio: ['ignore', 'pipe', 'pipe'] });
    const verifierOut = collect(verifier.stdout);
    const verifierCode = await waitExit(verifier);
    expect(verifierCode).toBe(0);
    expect(verifierOut()).toContain('PASS');

    // --- verify --bundle on the exported directory ---------------------------
    const bundleVerify = await runCli(['verify', '--bundle', bundleDir]);
    expect(bundleVerify.code).toBe(0);
    expect(bundleVerify.stdout).toContain('PASS');
  }, 240_000);

  it('MCP_RECORDER_DISABLE=1: traffic still flows, nothing is ever stored', async () => {
    const dataDir = tmpDir('mcp-rec-disabled-');
    const child = spawnCli(['--data-dir', dataDir, '--', 'node', ECHO_SERVER], {
      MCP_RECORDER_DISABLE: '1',
    });
    await driveSession(child);
    const exitCode = await waitExit(child);
    expect(exitCode).toBe(0);

    for (const f of ['evidence.db', 'evidence.jsonl', 'signatures.jsonl', 'identity.key']) {
      expect(existsSync(join(dataDir, f))).toBe(false);
    }
  }, 120_000);

  it('export on an empty store exits 1', async () => {
    const dataDir = tmpDir('mcp-rec-empty-');
    const res = await runCli(['export', '--data-dir', dataDir, '--dir', join(dataDir, 'bundle')]);
    expect(res.code).toBe(1);
    expect(res.stderr).toContain('nothing to export');
  }, 60_000);

  it('an invalid MCP_RECORDER_REDACT value warns and falls back instead of failing to spawn', async () => {
    const dataDir = tmpDir('mcp-rec-badenv-');
    const child = spawnCli(['--data-dir', dataDir, '--', 'node', ECHO_SERVER], {
      MCP_RECORDER_REDACT: 'bogus',
    });
    const stderrText = collect(child.stderr);
    await driveSession(child);
    const exitCode = await waitExit(child);
    expect(exitCode).toBe(0);
    expect(stderrText()).toContain("invalid redact mode 'bogus'");
    expect(stderrText()).toContain("using 'allowlist'");

    const sessions = await runCli(['sessions', '--data-dir', dataDir, '--json']);
    const list = JSON.parse(sessions.stdout) as Array<{ tool_call_count: number }>;
    expect(list).toHaveLength(1);
    expect(list[0]!.tool_call_count).toBe(1);
  }, 60_000);

  it('an invalid MCP_RECORDER_STORE value warns and falls back instead of failing to spawn', async () => {
    const dataDir = tmpDir('mcp-rec-badstore-');
    const child = spawnCli(['--data-dir', dataDir, '--', 'node', ECHO_SERVER], {
      MCP_RECORDER_STORE: 'postgres',
    });
    const stderrText = collect(child.stderr);
    await driveSession(child);
    const exitCode = await waitExit(child);
    expect(exitCode).toBe(0);
    expect(stderrText()).toContain("invalid store backend 'postgres'");
  }, 60_000);

  it('an unwritable --data-dir still spawns the server and exits with its code (fail-open)', async () => {
    const child = spawnCli([
      '--data-dir',
      '/dev/null/mcp-recorder-not-a-real-dir',
      '--',
      'node',
      '-e',
      'process.exit(5)',
    ]);
    const stderrText = collect(child.stderr);
    child.stdin!.end();
    const exitCode = await waitExit(child);
    expect(exitCode).toBe(5);
    expect(stderrText()).toContain('recording disabled (init failed, traffic unaffected)');
  }, 30_000);

  it('a command that cannot be spawned (ENOENT) exits 127', async () => {
    const dataDir = tmpDir('mcp-rec-enoent-');
    const res = await runCli(['--data-dir', dataDir, '--', '/definitely/not/a/real/binary-xyz']);
    expect(res.code).toBe(127);
    expect(res.stderr).toContain('failed to run');
  }, 30_000);
});
