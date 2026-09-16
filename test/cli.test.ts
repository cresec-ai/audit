import { spawn } from 'node:child_process';
import type { ChildProcess } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { Readable } from 'node:stream';
import { fileURLToPath } from 'node:url';
import { afterEach, describe, expect, it } from 'vitest';
import { spawnTsx } from './helpers/tsx.js';
import { GENESIS_HASH, makeRecord, sha256Ref } from '../src/chain/hash.js';
import { Signer, publicKeyPem } from '../src/chain/keys.js';
import { openStore } from '../src/store/index.js';
import { SCHEMA } from '../src/schema/events.js';
import type {
  AnyEvent,
  ChainRecord,
  IdentityContext,
  ServerContext,
  SessionEndEvent,
  SessionStartEvent,
  ToolCallEvent,
} from '../src/schema/events.js';
import type { ChainHead } from '../src/types.js';

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
  const child = spawnTsx(['src/cli.ts', ...args], {
    cwd: ROOT,
    env: { ...process.env, MCP_RECORDER_DISABLE: undefined, ...env },
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  cleanups.push(() => {
    if (child.exitCode === null) child.kill('SIGKILL');
  });
  return child;
}

/**
 * Like spawnCli, but detached into its own process group so cleanup can kill
 * the WHOLE tsx -> node(loader) tree it creates. A signal to just the top pid
 * (what spawnCli's cleanup does) does not reliably reach a long-running
 * server like `ui` down that chain — only a full process-group kill does.
 * Use this for any test that starts `ui` without `--out`.
 *
 * Windows has no POSIX process groups (`detached`/`process.kill(-pid, ...)`
 * are a no-op/error there), so on win32 this just falls back to killing the
 * one child directly — tsx spawns `ui`'s HTTP server in-process (no further
 * child tree here, unlike the npx/sh chain this used to go through), so that
 * single kill is enough.
 */
function spawnCliDetached(args: string[], env: Record<string, string | undefined> = {}): ChildProcess {
  const child = spawnTsx(['src/cli.ts', ...args], {
    cwd: ROOT,
    env: { ...process.env, MCP_RECORDER_DISABLE: undefined, ...env },
    stdio: ['pipe', 'pipe', 'pipe'],
    detached: process.platform !== 'win32',
  });
  cleanups.push(() => {
    if (child.pid === undefined) return;
    try {
      if (process.platform === 'win32') {
        child.kill('SIGKILL');
      } else {
        process.kill(-child.pid, 'SIGKILL');
      }
    } catch {
      /* whole tree already gone */
    }
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

/* --------------------- direct-store fixtures (no proxy) ------------------- *
 * A few tests below need session ids/event volumes the recorder's random
 * uuids can't guarantee (a shared 8-char prefix; thousands of matching rows),
 * so they seed a jsonl store directly with sealed ChainRecords, same as
 * test/store.test.ts and test/export.test.ts do — then drive the real CLI
 * against that data dir.
 */

const FIXTURE_IDENTITY: IdentityContext = { fingerprint: sha256Ref('cli-fixture-identity') };
const FIXTURE_SERVER: ServerContext = {
  name: 'fixture-server',
  command: 'node fixture.js',
  transport: 'stdio',
};

let fixtureEventCounter = 0;
function fixtureEventId(): string {
  return `00000000-0000-4000-8000-${(fixtureEventCounter++).toString(16).padStart(12, '0')}`;
}

function fixtureSessionStart(sessionId: string, timestamp: string): SessionStartEvent {
  return {
    schema: SCHEMA,
    event_id: fixtureEventId(),
    session_id: sessionId,
    timestamp,
    kind: 'session_start',
    identity: FIXTURE_IDENTITY,
    server: FIXTURE_SERVER,
    attributes: {},
    proxy_version: '0.1.0',
    cwd: '/tmp',
    redaction_mode: 'allowlist',
  };
}

/**
 * Seed a jsonl store with one session_start event per given (deterministic)
 * session id. Also creates a real signing key first, same as an honest
 * `record` run would — `export` (Signer.loadExisting) now refuses to run
 * against a data dir with no identity.key, so any fixture `export` is
 * expected to succeed against needs one already in place.
 */
async function seedSessions(dataDir: string, sessionIds: string[]): Promise<void> {
  await Signer.load(dataDir);
  const store = openStore({ dataDir, backend: 'jsonl' });
  try {
    let head: ChainHead = { seq: 0, hash: GENESIS_HASH };
    const records = sessionIds.map((id, i) => {
      const record = makeRecord(
        head,
        fixtureSessionStart(id, new Date(Date.UTC(2026, 0, 1, 0, 0, i)).toISOString()),
      );
      head = { seq: record.seq, hash: record.hash };
      return record;
    });
    store.append(records);
  } finally {
    store.close();
  }
}

/** Seed a jsonl store with `count` tool_call events that all match `needle`. */
function seedManyMatchingEvents(dataDir: string, needle: string, count: number): void {
  const needleHash = sha256Ref(needle);
  const sessionId = 'bbbbbbbb-0000-4000-8000-000000000000';
  const store = openStore({ dataDir, backend: 'jsonl' });
  try {
    let head: ChainHead = { seq: 0, hash: GENESIS_HASH };
    const records: ChainRecord[] = [];
    for (let i = 0; i < count; i++) {
      const event: ToolCallEvent = {
        schema: SCHEMA,
        event_id: fixtureEventId(),
        session_id: sessionId,
        timestamp: new Date(Date.UTC(2026, 0, 1, 0, 0, 0, i)).toISOString(),
        kind: 'tool_call',
        identity: FIXTURE_IDENTITY,
        server: FIXTURE_SERVER,
        attributes: {},
        tool: 'probe_tool',
        request_id: i,
        args: { note: { redacted: true, ref: needleHash, len: needle.length } },
        result_hash: sha256Ref('{}'),
        result: {},
        is_error: false,
        duration_ms: 1,
      };
      const record = makeRecord(head, event);
      head = { seq: record.seq, hash: record.hash };
      records.push(record);
    }
    store.append(records);
  } finally {
    store.close();
  }
}

/**
 * Seed a jsonl store with one hook-captured Claude Code session (the shape
 * `mcp-recorder hook` records — `source: 'hook'`, `phase`, the MCP server on
 * `server.name`): a session_start, then three calls that went to two
 * different servers, one of which never completed (pre without post).
 */
function seedHookSession(dataDir: string, sessionId: string): void {
  const hookServer = (name: string): ServerContext => ({
    name,
    command: 'hook:claude-code',
    transport: 'stdio',
  });
  const call = (
    i: number,
    server: string,
    tool: string,
    requestId: string,
    phase: 'pre' | 'post',
  ): ToolCallEvent => ({
    schema: SCHEMA,
    event_id: fixtureEventId(),
    session_id: sessionId,
    timestamp: new Date(Date.UTC(2026, 0, 1, 0, 0, i)).toISOString(),
    kind: 'tool_call',
    identity: FIXTURE_IDENTITY,
    server: hookServer(server),
    attributes: {},
    source: 'hook',
    tool,
    request_id: requestId,
    args: { task_id: { redacted: true, ref: sha256Ref('abc123'), len: 6 } },
    result_hash: sha256Ref(phase === 'pre' ? 'null' : '{}'),
    result: phase === 'pre' ? null : {},
    is_error: false,
    duration_ms: phase === 'pre' ? 0 : 1,
    phase,
  });
  const events: AnyEvent[] = [
    {
      ...fixtureSessionStart(sessionId, new Date(Date.UTC(2026, 0, 1, 0, 0, 0)).toISOString()),
      server: hookServer('claude-code'),
      source: 'hook',
    },
    call(1, 'ClickUp', 'clickup_get_task', 'toolu_1', 'pre'),
    call(2, 'ClickUp', 'clickup_get_task', 'toolu_1', 'post'),
    call(3, 'github', 'pull_request_read', 'toolu_2', 'pre'),
    call(4, 'github', 'pull_request_read', 'toolu_2', 'post'),
    call(5, 'ClickUp', 'clickup_get_list', 'toolu_3', 'pre'), // never completed
  ];
  const store = openStore({ dataDir, backend: 'jsonl' });
  try {
    let head: ChainHead = { seq: 0, hash: GENESIS_HASH };
    const records = events.map((event) => {
      const record = makeRecord(head, event);
      head = { seq: record.seq, hash: record.hash };
      return record;
    });
    store.append(records);
  } finally {
    store.close();
  }
}

/**
 * Seed a jsonl store with one session that recorded its session_end and then
 * KEPT RECORDING — the shape a Claude Code session resumed under the same
 * session_id leaves behind (cloud dogfood 4: session_end at 07:59:20, tool
 * calls until 12:41:08). `sessions` must not present this as simply ENDED.
 */
function seedReopenedSession(dataDir: string, sessionId: string): void {
  const at = (h: number, m: number, sec: number): string =>
    new Date(Date.UTC(2026, 0, 1, h, m, sec)).toISOString();
  const call = (timestamp: string, tool: string, requestId: number): ToolCallEvent => ({
    schema: SCHEMA,
    event_id: fixtureEventId(),
    session_id: sessionId,
    timestamp,
    kind: 'tool_call',
    identity: FIXTURE_IDENTITY,
    server: FIXTURE_SERVER,
    attributes: {},
    tool,
    request_id: requestId,
    args: {},
    result_hash: sha256Ref('{}'),
    result: {},
    is_error: false,
    duration_ms: 1,
  });
  const end: SessionEndEvent = {
    schema: SCHEMA,
    event_id: fixtureEventId(),
    session_id: sessionId,
    timestamp: at(7, 59, 20),
    kind: 'session_end',
    identity: FIXTURE_IDENTITY,
    server: FIXTURE_SERVER,
    attributes: {},
    reason: 'child_exit',
    child_exit_code: 0,
    events_recorded: 3,
    events_dropped: 0,
  };
  const events: AnyEvent[] = [
    fixtureSessionStart(sessionId, at(7, 0, 0)),
    call(at(7, 30, 0), 'list_issues', 1),
    end,
    // ... resumed here, same session_id, no second session_start.
    call(at(12, 40, 0), 'create_issue', 2),
    call(at(12, 41, 8), 'get_file_contents', 3),
  ];
  const store = openStore({ dataDir, backend: 'jsonl' });
  try {
    let head: ChainHead = { seq: 0, hash: GENESIS_HASH };
    const records = events.map((event) => {
      const record = makeRecord(head, event);
      head = { seq: record.seq, hash: record.hash };
      return record;
    });
    store.append(records);
  } finally {
    store.close();
  }
}

function waitMs(ms: number): Promise<void> {
  return new Promise((resolveWait) => setTimeout(resolveWait, ms));
}

/** Poll `getText()` until it matches `pattern`, for tests that watch a growing stderr buffer. */
async function waitForMatch(
  getText: () => string,
  pattern: RegExp,
  timeoutMs = 25_000,
): Promise<void> {
  const start = Date.now();
  while (!pattern.test(getText())) {
    if (Date.now() - start > timeoutMs) {
      throw new Error(`timed out waiting for ${String(pattern)} in: ${getText()}`);
    }
    await waitMs(25);
  }
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
    const list = JSON.parse(sessions.stdout) as Array<{ tool_call_count: number; server_count: number }>;
    expect(list).toHaveLength(1);
    expect(list[0]!.tool_call_count).toBe(1);

    const sessionsHuman = await runCli(['sessions', '--data-dir', dataDir]);
    expect(sessionsHuman.code).toBe(0);
    expect(sessionsHuman.stdout).toContain('SESSION');
    expect(sessionsHuman.stdout).toContain('SERVERS');
    // Recorded without --name: server.name is the argv basename before the
    // initialize handshake and the learned name after it, yet the session
    // wrapped ONE server and must read so (review of the integrated change).
    const [sessionsHeader, sessionsRow] = sessionsHuman.stdout.trim().split('\n');
    const sessionsHeaders = sessionsHeader!.trim().split(/\s+/);
    const sessionsCells = sessionsRow!.trim().split(/\s+/);
    expect(sessionsCells[sessionsHeaders.indexOf('SERVERS')]).toBe('1');
    expect(list[0]!.server_count).toBe(1);

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

  it('sessions: a hook-captured session shows one row per session, calls counted once, and a SERVERS column', async () => {
    const dataDir = tmpDir('mcp-rec-sessions-hook-');
    const sessionId = 'cccccccc-0000-4000-8000-000000000000';
    seedHookSession(dataDir, sessionId);

    const human = await runCli(['sessions', '--data-dir', dataDir]);
    expect(human.code).toBe(0);
    const [headerLine, ...rowLines] = human.stdout.trim().split('\n');
    const headers = headerLine!.trim().split(/\s+/);
    // New columns are appended LAST: every column that existed before them
    // keeps its position.
    expect(headers).toEqual([
      'SESSION',
      'STARTED',
      'ENDED',
      'SERVER',
      'EVENTS',
      'TOOL_CALLS',
      'ERRORS',
      'SERVERS',
      'LAST_EVENT',
    ]);
    expect(rowLines).toHaveLength(1);
    const cells = rowLines[0]!.trim().split(/\s+/);
    const cell = (name: string): string => cells[headers.indexOf(name)]!;
    expect(cell('SESSION')).toBe('cccccccc');
    expect(cell('SERVER')).toBe('claude-code'); // the first event's server: the client itself
    expect(cell('SERVERS')).toBe('2'); // the servers called: ClickUp + github (claude-code is not one)
    expect(cell('EVENTS')).toBe('6'); // session_start + 5 tool_call events
    expect(cell('TOOL_CALLS')).toBe('3'); // 2 pre+post pairs + 1 lone pre = 3 calls, not 5
    expect(cell('ERRORS')).toBe('0');

    const json = await runCli(['sessions', '--data-dir', dataDir, '--json']);
    expect(json.code).toBe(0);
    const list = JSON.parse(json.stdout) as Array<{
      session_id: string;
      server_name: string;
      server_count: number;
      event_count: number;
      tool_call_count: number;
      error_count: number;
    }>;
    expect(list).toHaveLength(1);
    expect(list[0]).toMatchObject({
      session_id: sessionId,
      server_name: 'claude-code',
      server_count: 2,
      event_count: 6,
      tool_call_count: 3,
      error_count: 0,
    });
  }, 60_000);

  it('sessions: a session whose events continue past its session_end reads (reopened), not ENDED', async () => {
    const dataDir = tmpDir('mcp-rec-sessions-reopened-');
    const sessionId = 'dddddddd-0000-4000-8000-000000000000';
    seedReopenedSession(dataDir, sessionId);

    const human = await runCli(['sessions', '--data-dir', dataDir]);
    expect(human.code).toBe(0);
    const [headerLine, ...rowLines] = human.stdout.trim().split('\n');
    const headers = headerLine!.trim().split(/\s+/);
    expect(rowLines).toHaveLength(1);
    const cells = rowLines[0]!.trim().split(/\s+/);
    const cell = (name: string): string => cells[headers.indexOf(name)]!;
    // The session_end at 07:59:20 was superseded by later events, so it is
    // NOT printed as an end time — printing it invites "ended at 07:59:20,
    // so the 5 events must be stale", which is exactly the misreading cloud
    // dogfood 4's report made of a real row.
    expect(cell('ENDED')).toBe('(reopened)');
    expect(human.stdout).not.toContain('07:59:20');
    // LAST_EVENT is the instant the counts run through.
    expect(cell('LAST_EVENT')).toBe('2026-01-01T12:41:08.000Z');
    expect(cell('STARTED')).toBe('2026-01-01T07:00:00.000Z');
    expect(cell('EVENTS')).toBe('5'); // session_start + 3 calls + the session_end
    expect(cell('TOOL_CALLS')).toBe('3'); // 1 before the session_end, 2 after

    // --json keeps the session_end itself: nothing recorded is hidden, the
    // human table just refuses to call a superseded one an end.
    const json = await runCli(['sessions', '--data-dir', dataDir, '--json']);
    expect(json.code).toBe(0);
    const list = JSON.parse(json.stdout) as Array<{
      session_id: string;
      started_at: string;
      ended_at?: string;
      last_event_at?: string;
      event_count: number;
    }>;
    expect(list).toHaveLength(1);
    expect(list[0]).toMatchObject({
      session_id: sessionId,
      started_at: '2026-01-01T07:00:00.000Z',
      ended_at: '2026-01-01T07:59:20.000Z',
      last_event_at: '2026-01-01T12:41:08.000Z',
      event_count: 5,
    });
  }, 60_000);

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
    // A path *underneath a regular file* can't be created on any platform
    // (ENOTDIR on POSIX, ENOENT on Windows) — unlike /dev/null/..., which a
    // Windows runner happily turns into D:\dev\null\... and creates.
    const blocker = join(tmpDir('mcp-rec-unwritable-'), 'not-a-directory');
    writeFileSync(blocker, '');
    const child = spawnCli([
      '--data-dir',
      join(blocker, 'mcp-recorder-not-a-real-dir'),
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

  /* -------------------- verify: key pinning + unsigned-tail rules -------------------- */

  function notif(i: number): AnyEvent {
    return {
      schema: SCHEMA,
      event_id: `e${i}`,
      session_id: 's1',
      timestamp: new Date(1700000000000 + i).toISOString(),
      kind: 'notification',
      identity: { fingerprint: sha256Ref('cli-verify-test-identity') },
      server: { name: 'cli-verify-test-server', command: 'node x', transport: 'stdio' },
      attributes: {},
      method: `m${i}`,
      direction: 'client_to_server',
      params: null,
    } as AnyEvent;
  }

  function sealAll(events: AnyEvent[]): ChainRecord[] {
    let head: ChainHead = { seq: 0, hash: GENESIS_HASH };
    const out: ChainRecord[] = [];
    for (const event of events) {
      const record = makeRecord(head, event);
      out.push(record);
      head = { seq: record.seq, hash: record.hash };
    }
    return out;
  }

  it('verify pins identity.pub by default: a chain rewritten and re-signed with a foreign key FAILS', async () => {
    const dataDir = tmpDir('mcp-rec-pin-');
    const signer = await Signer.load(dataDir);
    const store = openStore({ dataDir, backend: 'jsonl' });
    store.append(sealAll([notif(1), notif(2), notif(3)]));
    const head = store.head();
    store.addSignature(await signer.sign(head.seq, head.hash));
    store.close();

    // Sanity: the honestly-signed chain verifies, and says what it pinned to.
    // --store jsonl throughout: this test builds a jsonl-backed store
    // directly and must point the CLI at the same backend (verify/export
    // otherwise default to trying sqlite first).
    const honest = await runCli(['verify', '--data-dir', dataDir, '--store', 'jsonl']);
    expect(honest.code).toBe(0);
    expect(honest.stdout).toContain('PASS');
    expect(honest.stdout).toContain('pinned signer');
    expect(honest.stdout).toContain('identity.pub');

    // Attacker: rewrite the chain from scratch and re-sign with their OWN
    // key — identity.key in dataDir is never touched.
    const attackerDir = tmpDir('mcp-rec-pin-attacker-');
    const attacker = await Signer.load(attackerDir);
    const forged = sealAll([notif(1), notif(99)]);
    const forgedHead = { seq: forged[forged.length - 1]!.seq, hash: forged[forged.length - 1]!.hash };
    const forgedSig = await attacker.sign(forgedHead.seq, forgedHead.hash);
    writeFileSync(join(dataDir, 'evidence.jsonl'), forged.map((r) => JSON.stringify(r)).join('\n') + '\n');
    writeFileSync(join(dataDir, 'signatures.jsonl'), JSON.stringify(forgedSig) + '\n');

    const forgedResult = await runCli(['verify', '--data-dir', dataDir, '--store', 'jsonl']);
    expect(forgedResult.code).toBe(1);
    expect(forgedResult.stdout).toContain('FAIL');
    expect(forgedResult.stdout).toContain('signature_invalid');
    expect(forgedResult.stdout).toContain('no_valid_signature');
  }, 60_000);

  it('--public-key overrides the default identity.pub pin', async () => {
    const dataDir = tmpDir('mcp-rec-pubkey-');
    const signer = await Signer.load(dataDir);
    const store = openStore({ dataDir, backend: 'jsonl' });
    store.append(sealAll([notif(1), notif(2)]));
    const head = store.head();
    store.addSignature(await signer.sign(head.seq, head.hash));
    store.close();

    const wrongKey = 'ab'.repeat(32);
    const wrong = await runCli([
      'verify', '--data-dir', dataDir, '--store', 'jsonl', '--public-key', wrongKey,
    ]);
    expect(wrong.code).toBe(1);
    expect(wrong.stdout).toContain('FAIL');
    expect(wrong.stdout).toContain('--public-key');

    const right = await runCli([
      'verify', '--data-dir', dataDir, '--store', 'jsonl', '--public-key', signer.publicKeyHex,
    ]);
    expect(right.code).toBe(0);
    expect(right.stdout).toContain('PASS');
    expect(right.stdout).toContain('--public-key');

    // A PEM file path is also accepted.
    const pemPath = join(dataDir, 'external-key.pem');
    writeFileSync(pemPath, publicKeyPem(signer.publicKeyHex));
    const viaPem = await runCli([
      'verify', '--data-dir', dataDir, '--store', 'jsonl', '--public-key', pemPath,
    ]);
    expect(viaPem.code).toBe(0);
    expect(viaPem.stdout).toContain('PASS');
  }, 60_000);

  it('an unsigned chain FAILS by default and PASSES (unsigned tail) with --allow-unsigned', async () => {
    const dataDir = tmpDir('mcp-rec-unsigned-');
    await Signer.load(dataDir); // creates identity.pub; nothing below ever signs the chain
    const store = openStore({ dataDir, backend: 'jsonl' });
    store.append(sealAll([notif(1), notif(2), notif(3)]));
    store.close();

    const strict = await runCli(['verify', '--data-dir', dataDir, '--store', 'jsonl']);
    expect(strict.code).toBe(1);
    expect(strict.stdout).toContain('FAIL');
    expect(strict.stdout).toContain('no_valid_signature');

    const lenient = await runCli([
      'verify', '--data-dir', dataDir, '--store', 'jsonl', '--allow-unsigned',
    ]);
    expect(lenient.code).toBe(0);
    expect(lenient.stdout).toContain('PASS (unsigned tail)');
  }, 60_000);

  it('a store with no identity.pub and no --public-key is an unpinned PASS, loudly labeled as such', async () => {
    const dataDir = tmpDir('mcp-rec-unpinned-');
    const signer = await Signer.load(dataDir);
    const store = openStore({ dataDir, backend: 'jsonl' });
    store.append(sealAll([notif(1), notif(2)]));
    const head = store.head();
    store.addSignature(await signer.sign(head.seq, head.hash));
    store.close();
    rmSync(join(dataDir, 'identity.pub')); // e.g. a store copied without it, or the file deleted

    const human = await runCli(['verify', '--data-dir', dataDir, '--store', 'jsonl']);
    expect(human.code).toBe(0); // the chain really is intact — this is a PASS, just an unpinned one
    expect(human.stdout).toContain('WARNING');
    expect(human.stdout).toContain('no public key to pin against');
    expect(human.stdout).toContain('PASS (unpinned)');
    expect(human.stdout).not.toMatch(/^PASS —/m); // never an indistinguishable plain PASS

    const json = await runCli(['verify', '--data-dir', dataDir, '--store', 'jsonl', '--json']);
    expect(json.code).toBe(0);
    const payload = JSON.parse(json.stdout) as { ok: boolean; pinned_public_key: unknown; unpinned?: boolean };
    expect(payload.ok).toBe(true);
    expect(payload.pinned_public_key).toBeNull();
    expect(payload.unpinned).toBe(true);
  }, 60_000);

  it('export refuses to mint a new signing key: a store copied without identity.key exits 2 and creates no key files, verify still passes after', async () => {
    const hostDir = tmpDir('mcp-rec-export-host-');
    const signer = await Signer.load(hostDir);
    const store = openStore({ dataDir: hostDir, backend: 'jsonl' });
    store.append(sealAll([notif(1), notif(2)]));
    const head = store.head();
    store.addSignature(await signer.sign(head.seq, head.hash));
    store.close();

    // Simulate "copied the evidence dir to another machine": only the store
    // files come along, not the private key.
    const copyDir = tmpDir('mcp-rec-export-copy-');
    writeFileSync(join(copyDir, 'evidence.jsonl'), readFileSync(join(hostDir, 'evidence.jsonl')));
    writeFileSync(join(copyDir, 'signatures.jsonl'), readFileSync(join(hostDir, 'signatures.jsonl')));

    const exported = await runCli([
      'export', '--data-dir', copyDir, '--store', 'jsonl', '--dir', join(copyDir, 'bundle'),
    ]);
    expect(exported.code).toBe(2);
    expect(exported.stderr).toContain('no signing key in');
    expect(exported.stderr).toContain('export must run on the recording host');
    expect(existsSync(join(copyDir, 'identity.key'))).toBe(false);
    expect(existsSync(join(copyDir, 'identity.pub'))).toBe(false);
    expect(existsSync(join(copyDir, 'bundle'))).toBe(false);

    // The chain itself was never touched — verify (pinned to the honest
    // signer's key, since identity.pub wasn't copied either) still passes.
    const verify = await runCli([
      'verify', '--data-dir', copyDir, '--store', 'jsonl', '--public-key', signer.publicKeyHex,
    ]);
    expect(verify.code).toBe(0);
    expect(verify.stdout).toContain('PASS');
  }, 60_000);

  it('verify --bundle --public-key pins to an externally supplied key', async () => {
    const dataDir = tmpDir('mcp-rec-bundle-pin-');
    const signer = await Signer.load(dataDir);
    const store = openStore({ dataDir, backend: 'jsonl' });
    store.append(sealAll([notif(1), notif(2)]));
    const head = store.head();
    store.addSignature(await signer.sign(head.seq, head.hash));
    store.close();

    const bundleDir = tmpDir('mcp-rec-bundle-pin-out-');
    const exported = await runCli([
      'export', '--data-dir', dataDir, '--store', 'jsonl', '--dir', bundleDir,
    ]);
    expect(exported.code).toBe(0);

    const right = await runCli(['verify', '--bundle', bundleDir, '--public-key', signer.publicKeyHex]);
    expect(right.code).toBe(0);
    expect(right.stdout).toContain('PASS');

    const wrong = await runCli(['verify', '--bundle', bundleDir, '--public-key', 'ab'.repeat(32)]);
    expect(wrong.code).toBe(1);
    expect(wrong.stdout).toContain('FAIL');
  }, 60_000);

  it("ui's integrity banner agrees with verify: FAILED banner for a chain verify rejects (foreign-key re-signed), not a green PASS", async () => {
    const dataDir = tmpDir('mcp-rec-ui-banner-');
    await Signer.load(dataDir); // creates dataDir's own identity.pub
    const store = openStore({ dataDir, backend: 'jsonl' });
    store.append(sealAll([notif(1), notif(2), notif(3)]));
    store.close();

    // Attacker: re-sign the (otherwise honest) chain with a foreign key —
    // identity.key/.pub in dataDir untouched, so verify's default pin rejects it.
    const attackerDir = tmpDir('mcp-rec-ui-banner-attacker-');
    const attacker = await Signer.load(attackerDir);
    const lines = readFileSync(join(dataDir, 'evidence.jsonl'), 'utf8').trim().split('\n');
    const last = JSON.parse(lines[lines.length - 1]!) as ChainRecord;
    writeFileSync(
      join(dataDir, 'signatures.jsonl'),
      JSON.stringify(await attacker.sign(last.seq, last.hash)) + '\n',
    );

    const verify = await runCli(['verify', '--data-dir', dataDir, '--store', 'jsonl']);
    expect(verify.code).toBe(1);
    expect(verify.stdout).toContain('FAIL');

    const htmlPath = join(dataDir, 'replay.html');
    const ui = await runCli(['ui', '--data-dir', dataDir, '--store', 'jsonl', '--out', htmlPath]);
    expect(ui.code).toBe(0);
    const html = readFileSync(htmlPath, 'utf8');
    // Before the fix, ui called verifyStore(store) with no pin at all, so the
    // foreign-but-cryptographically-valid signature verified and the banner
    // showed green even though `verify` itself FAILs this exact chain.
    expect(html).toContain('banner bad');
    expect(html).not.toContain('banner ok');
    expect(html).toContain('signature_invalid');
  }, 60_000);
});

describe('--session prefix resolution (export / query / ui)', () => {
  // Deterministic ids so two of them share an 8-char (and beyond) prefix —
  // real recorded session ids are random uuids and won't collide like this.
  const SESSION_SHARED_A = 'aaaaaaaa-1111-4111-8111-111111111111';
  const SESSION_SHARED_B = 'aaaaaaab-2222-4222-8222-222222222222';
  const SESSION_UNIQUE = 'ffffffff-3333-4333-8333-333333333333';

  async function seededDataDir(): Promise<string> {
    const dataDir = tmpDir('mcp-rec-session-prefix-');
    await seedSessions(dataDir, [SESSION_SHARED_A, SESSION_SHARED_B, SESSION_UNIQUE]);
    return dataDir;
  }

  it('a unique id prefix (the 8 chars `sessions` prints) resolves for export / query / ui', async () => {
    const dataDir = await seededDataDir();

    const bundleDir = join(dataDir, 'bundle');
    const exported = await runCli([
      'export',
      '--data-dir',
      dataDir,
      '--session',
      'ffffffff',
      '--dir',
      bundleDir,
    ]);
    expect(exported.code).toBe(0);
    const manifest = JSON.parse(readFileSync(join(bundleDir, 'manifest.json'), 'utf8')) as {
      session_id: string;
    };
    expect(manifest.session_id).toBe(SESSION_UNIQUE);

    const query = await runCli([
      'query',
      'anything',
      '--data-dir',
      dataDir,
      '--session',
      'ffffffff',
    ]);
    expect(query.code).toBe(0); // resolves fine even when the needle itself has 0 matches

    const htmlPath = join(dataDir, 'replay.html');
    const ui = await runCli([
      'ui',
      '--data-dir',
      dataDir,
      '--session',
      'ffffffff',
      '--out',
      htmlPath,
    ]);
    expect(ui.code).toBe(0);
    expect(existsSync(htmlPath)).toBe(true);
  }, 60_000);

  it('an exact full session id still works (unchanged behavior)', async () => {
    const dataDir = await seededDataDir();
    const query = await runCli(['query', 'anything', '--data-dir', dataDir, '--session', SESSION_UNIQUE]);
    expect(query.code).toBe(0);
  }, 60_000);

  it('an ambiguous --session prefix exits 2 and lists the candidates', async () => {
    const dataDir = await seededDataDir();

    const exported = await runCli([
      'export',
      '--data-dir',
      dataDir,
      '--session',
      'aaaaaaa',
      '--dir',
      join(dataDir, 'bundle'),
    ]);
    expect(exported.code).toBe(2);
    expect(exported.stderr).toContain('ambiguous');
    expect(exported.stderr).toContain('aaaaaaaa');
    expect(exported.stderr).toContain('aaaaaaab');

    const query = await runCli(['query', 'x', '--data-dir', dataDir, '--session', 'aaaaaaa']);
    expect(query.code).toBe(2);
    expect(query.stderr).toContain('ambiguous');

    const ui = await runCli([
      'ui',
      '--data-dir',
      dataDir,
      '--session',
      'aaaaaaa',
      '--out',
      join(dataDir, 'replay.html'),
    ]);
    expect(ui.code).toBe(2);
    expect(ui.stderr).toContain('ambiguous');
  }, 60_000);

  it('a --session with no match exits 2 with a clear message (query: not a silent 0 matches)', async () => {
    const dataDir = await seededDataDir();

    const query = await runCli(['query', 'x', '--data-dir', dataDir, '--session', 'deadbeef']);
    expect(query.code).toBe(2);
    expect(query.stderr).toContain('matches no recorded session');
    expect(query.stdout).toBe(''); // no "0 matches across 0 sessions" success-shaped output

    const exported = await runCli([
      'export',
      '--data-dir',
      dataDir,
      '--session',
      'deadbeef',
      '--dir',
      join(dataDir, 'bundle'),
    ]);
    expect(exported.code).toBe(2);
    expect(exported.stderr).toContain('matches no recorded session');
  }, 60_000);
});

describe('inspection commands: EPIPE handling', () => {
  it('a reader that closes early (e.g. `| head -1`) exits quietly, no crash stack trace', async () => {
    const dataDir = tmpDir('mcp-rec-epipe-');
    // Big enough that the CLI is still writing when the reader goes away —
    // small output can finish before a `head`-style reader even closes.
    seedManyMatchingEvents(dataDir, 'epipe-needle', 4000);

    const child = spawnCli(['query', 'epipe-needle', '--data-dir', dataDir]);
    const stderrText = collect(child.stderr);

    await new Promise<void>((resolveData) => {
      child.stdout!.once('data', () => {
        // Closing our read end mid-write is exactly what `| head -1` does
        // once it has read what it wants.
        child.stdout!.destroy();
        resolveData();
      });
    });

    const code = await waitExit(child);
    const stderrOut = stderrText();
    expect(stderrOut).not.toMatch(/EPIPE/);
    expect(stderrOut).not.toMatch(/Emitted 'error' event/i);
    expect(stderrOut).not.toMatch(/at WriteStream/);
    expect(code).toBe(0);
  }, 60_000);

  it('a FAILing verify piped through a reader that closes early still exits 1, not 0', async () => {
    const dataDir = tmpDir('mcp-rec-epipe-failcode-');
    seedManyMatchingEvents(dataDir, 'epipe-failcode-needle', 4000);
    // Tamper every record (leaving their stored hash untouched) so verify's
    // problems table has one hash_mismatch row per record — big enough that
    // the CLI is still mid-write when the reader below closes early, exactly
    // the condition under which guardStdoutEpipe's exit(0) used to mask a
    // real FAIL's exit code (cmdVerify used to set process.exitCode AFTER
    // printing, so the EPIPE handler never saw it).
    const evidencePath = join(dataDir, 'evidence.jsonl');
    const tampered =
      readFileSync(evidencePath, 'utf8')
        .trim()
        .split('\n')
        .map((line) => {
          const record = JSON.parse(line) as ChainRecord;
          (record.event as ToolCallEvent).tool = 'doctored';
          return JSON.stringify(record);
        })
        .join('\n') + '\n';
    writeFileSync(evidencePath, tampered);

    const sanity = await runCli(['verify', '--data-dir', dataDir, '--store', 'jsonl']);
    expect(sanity.code).toBe(1);
    expect(sanity.stdout).toContain('FAIL');

    const child = spawnCli(['verify', '--data-dir', dataDir, '--store', 'jsonl']);
    await new Promise<void>((resolveData) => {
      child.stdout!.once('data', () => {
        child.stdout!.destroy();
        resolveData();
      });
    });
    const code = await waitExit(child);
    expect(code).toBe(1); // NOT 0 — a reader going away must not turn a FAIL into apparent success
  }, 60_000);
});

describe('ui: best-effort browser open', () => {
  /** A fake `xdg-open` on PATH that just touches a marker file when run. */
  function makeFakeOpener(): { binDir: string; marker: string } {
    const binDir = tmpDir('mcp-rec-fake-opener-bin-');
    const marker = join(tmpDir('mcp-rec-fake-opener-marker-'), 'opened');
    writeFileSync(join(binDir, 'xdg-open'), `#!/bin/sh\ntouch '${marker}'\nexit 0\n`, {
      mode: 0o755,
    });
    return { binDir, marker };
  }

  // Every test below fakes out the *Linux* opener (`xdg-open`, a `#!/bin/sh`
  // script granted the exec bit) — on win32 the CLI reaches for a different
  // opener entirely (see cli.ts's platform switch) and PATH itself uses a
  // different separator (`;` not `:`), so this whole fixture doesn't apply.
  it.skipIf(process.platform === 'win32')(
    'spawns the platform opener for the served URL by default (a display is present)',
    async () => {
      const dataDir = tmpDir('mcp-rec-ui-open-');
      const { binDir, marker } = makeFakeOpener();
      const child = spawnCliDetached(['ui', '--data-dir', dataDir], {
        PATH: `${binDir}:${process.env.PATH ?? ''}`,
        DISPLAY: ':99',
      });
      const stderrText = collect(child.stderr);
      await waitForMatch(stderrText, /replay UI at http/);
      await waitMs(1000);
      expect(existsSync(marker)).toBe(true);
    },
    30_000,
  );

  it.skipIf(process.platform === 'win32')(
    '--no-open never spawns the opener, even with a display present',
    async () => {
      const dataDir = tmpDir('mcp-rec-ui-noopen-');
      const { binDir, marker } = makeFakeOpener();
      const child = spawnCliDetached(['ui', '--data-dir', dataDir, '--no-open'], {
        PATH: `${binDir}:${process.env.PATH ?? ''}`,
        DISPLAY: ':99',
      });
      const stderrText = collect(child.stderr);
      await waitForMatch(stderrText, /replay UI at http/);
      await waitMs(1000);
      expect(existsSync(marker)).toBe(false);
    },
    30_000,
  );

  it.skipIf(process.platform === 'win32')(
    '--out never spawns the opener (there is no server to open)',
    async () => {
      const dataDir = tmpDir('mcp-rec-ui-outnoopen-');
      const { binDir, marker } = makeFakeOpener();
      const res = await runCli(['ui', '--data-dir', dataDir, '--out', join(dataDir, 'replay.html')], {
        PATH: `${binDir}:${process.env.PATH ?? ''}`,
        DISPLAY: ':99',
      });
      expect(res.code).toBe(0);
      expect(existsSync(marker)).toBe(false);
    },
    30_000,
  );

  it.skipIf(process.platform === 'win32')(
    'does not hang on a headless host (no DISPLAY) and never spawns an opener',
    async () => {
      const dataDir = tmpDir('mcp-rec-ui-headless-');
      const { binDir, marker } = makeFakeOpener();
      const started = Date.now();
      const child = spawnCliDetached(['ui', '--data-dir', dataDir], {
        PATH: `${binDir}:${process.env.PATH ?? ''}`,
        DISPLAY: undefined,
        WAYLAND_DISPLAY: undefined,
      });
      const stderrText = collect(child.stderr);
      await waitForMatch(stderrText, /replay UI at http/);
      // The server came up promptly — nothing blocked on a (nonexistent) opener.
      expect(Date.now() - started).toBeLessThan(10_000);
      await waitMs(1000);
      expect(existsSync(marker)).toBe(false);
    },
    30_000,
  );
});
