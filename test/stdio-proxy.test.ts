import { spawn } from 'node:child_process';
import { PassThrough, Writable } from 'node:stream';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

import { GENESIS_HASH, canonicalJson, computeHash, makeRecord, sha256Ref } from '../src/chain/hash.js';
import { Recorder } from '../src/capture/recorder.js';
import { runStdioProxy } from '../src/proxy/stdio.js';
import { queryStore } from '../src/query/touched.js';
import type {
  AnyEvent,
  ChainRecord,
  HeadSignature,
  InitializeEvent,
  NotificationEvent,
  ProtocolErrorEvent,
  RpcEvent,
  Scrubbed,
  SessionEndEvent,
  SessionStartEvent,
  ToolCallEvent,
} from '../src/schema/events.js';
import type {
  ChainHead,
  EvidenceStore,
  IterateOpts,
  RedactorLike,
  SessionSummary,
} from '../src/types.js';

const ECHO_SERVER = fileURLToPath(new URL('./fixtures/echo-server.cjs', import.meta.url));
const SECRET = 'sk-test-AAAABBBBCCCC1111';

/* ------------------------------ fakes ---------------------------------- */

class FakeStore implements EvidenceStore {
  readonly backend = 'jsonl' as const;
  readonly path = ':memory:';
  records: ChainRecord[] = [];
  sigs: HeadSignature[] = [];

  head(): ChainHead {
    const last = this.records[this.records.length - 1];
    return last ? { seq: last.seq, hash: last.hash } : { seq: 0, hash: GENESIS_HASH };
  }
  append(records: ChainRecord[]): void {
    let head = this.head();
    for (const r of records) {
      const expectedPrev = head.seq === 0 ? GENESIS_HASH : head.hash;
      if (r.seq !== head.seq + 1 || r.prev_hash !== expectedPrev) {
        throw new Error(`append does not extend head at seq ${r.seq}`);
      }
      if (r.hash !== computeHash(r.prev_hash, r.event)) {
        throw new Error(`bad hash at seq ${r.seq}`);
      }
      this.records.push(r);
      head = { seq: r.seq, hash: r.hash };
    }
  }
  appendEvents(events: AnyEvent[]): ChainRecord[] {
    let head = this.head();
    const sealed: ChainRecord[] = [];
    for (const event of events) {
      const record = makeRecord(head, event);
      sealed.push(record);
      head = { seq: record.seq, hash: record.hash };
    }
    this.records.push(...sealed);
    return sealed;
  }
  addSignature(sig: HeadSignature): void {
    this.sigs.push(sig);
  }
  latestSignature(): HeadSignature | null {
    return this.sigs[this.sigs.length - 1] ?? null;
  }
  signatures(): HeadSignature[] {
    return [...this.sigs];
  }
  *iterate(opts?: IterateOpts): Iterable<ChainRecord> {
    for (const r of this.records) {
      if (opts?.fromSeq !== undefined && r.seq < opts.fromSeq) continue;
      if (opts?.toSeq !== undefined && r.seq > opts.toSeq) continue;
      yield r;
    }
  }
  count(): number {
    return this.records.length;
  }
  sessions(): SessionSummary[] {
    return [];
  }
  close(): void {
    /* noop */
  }
  events(): AnyEvent[] {
    return this.records.map((r) => r.event);
  }
}

/** Hash-everything redactor: every string leaf becomes a RedactedRef. */
const fakeRedactor: RedactorLike = {
  mode: 'allowlist',
  hashString: (value: string) => sha256Ref(value),
  scrub(value: unknown): Scrubbed {
    const walk = (v: unknown, depth: number): Scrubbed => {
      if (depth > 32) return { redacted: true, ref: sha256Ref('[deep]'), len: 0 };
      if (v === null || v === undefined) return null;
      if (typeof v === 'string') return { redacted: true, ref: sha256Ref(v), len: v.length };
      if (typeof v === 'number' || typeof v === 'boolean') return v;
      if (Array.isArray(v)) return v.map((x) => walk(x, depth + 1));
      if (typeof v === 'object') {
        const out: Record<string, Scrubbed> = {};
        for (const [k, val] of Object.entries(v as Record<string, unknown>)) {
          out[k] = walk(val, depth + 1);
        }
        return out;
      }
      return null;
    };
    return walk(value, 0);
  },
};

/* ----------------------------- helpers ---------------------------------- */

function collectLines(stream: PassThrough): { lines: () => string[]; raw: () => string } {
  let buf = '';
  stream.on('data', (c: Buffer) => {
    buf += c.toString('utf8');
  });
  return {
    raw: () => buf,
    lines: () => buf.split('\n').filter((l) => l.trim().length > 0),
  };
}

async function waitFor(cond: () => boolean, what: string, timeoutMs = 10_000): Promise<void> {
  const t0 = Date.now();
  while (!cond()) {
    if (Date.now() - t0 > timeoutMs) throw new Error(`timeout waiting for ${what}`);
    await new Promise((r) => setTimeout(r, 5));
  }
}

const CLIENT_SCRIPT = [
  {
    jsonrpc: '2.0',
    id: 1,
    method: 'initialize',
    params: {
      protocolVersion: '2024-11-05',
      clientInfo: { name: 'vitest-client', version: '9.9.9' },
      capabilities: {},
    },
  },
  { jsonrpc: '2.0', method: 'notifications/initialized' },
  { jsonrpc: '2.0', id: 2, method: 'tools/list' },
  {
    jsonrpc: '2.0',
    id: 3,
    method: 'tools/call',
    params: { name: 'echo', arguments: { secret: SECRET } },
  },
] as const;

/** Run echo-server.cjs directly (no proxy) and return its stdout lines. */
async function runDirect(env?: NodeJS.ProcessEnv): Promise<string[]> {
  const child = spawn(process.execPath, [ECHO_SERVER], {
    stdio: ['pipe', 'pipe', 'pipe'],
    env: env ?? process.env,
  });
  let out = '';
  child.stdout.on('data', (c: Buffer) => {
    out += c.toString('utf8');
  });
  for (const msg of CLIENT_SCRIPT) child.stdin.write(JSON.stringify(msg) + '\n');
  child.stdin.end();
  await new Promise<void>((resolve, reject) => {
    child.on('close', () => resolve());
    child.on('error', reject);
  });
  return out.split('\n').filter((l) => l.trim().length > 0);
}

interface ProxyRun {
  exitCode: number;
  store: FakeStore;
  stdoutLines: string[];
  stderrRaw: string;
}

/** Run the same session through the proxy with PassThrough streams. */
async function runProxied(env?: NodeJS.ProcessEnv): Promise<ProxyRun> {
  const store = new FakeStore();
  const recorder = new Recorder({ store, signer: null });
  const stdin = new PassThrough();
  const stdout = new PassThrough();
  const stderr = new PassThrough();
  const out = collectLines(stdout);
  const err = collectLines(stderr);

  const done = runStdioProxy({
    command: [process.execPath, ECHO_SERVER],
    recorder,
    redactor: fakeRedactor,
    proxyVersion: '0.1.0-test',
    identityLabel: 'ci',
    stdin,
    stdout,
    stderr,
    env: env ?? process.env,
  });

  const responded = (id: number) => () =>
    out.lines().some((l) => {
      try {
        const m = JSON.parse(l) as { id?: unknown };
        return m.id === id;
      } catch {
        return false;
      }
    });

  stdin.write(JSON.stringify(CLIENT_SCRIPT[0]) + '\n');
  await waitFor(responded(1), 'initialize response');
  stdin.write(JSON.stringify(CLIENT_SCRIPT[1]) + '\n');
  stdin.write(JSON.stringify(CLIENT_SCRIPT[2]) + '\n');
  await waitFor(responded(2), 'tools/list response');
  stdin.write(JSON.stringify(CLIENT_SCRIPT[3]) + '\n');
  await waitFor(responded(3), 'tools/call response');
  stdin.end();

  const exitCode = await done;
  return { exitCode, store, stdoutLines: out.lines(), stderrRaw: err.raw() };
}

/* ------------------------------- tests ---------------------------------- */

describe('runStdioProxy (e2e against echo-server fixture)', () => {
  it('forwards bytes unchanged and records the full session', async () => {
    const [direct, proxied] = await Promise.all([runDirect(), runProxied()]);

    // (1) Byte-identical client-side traffic (as sets of lines, since the
    // server notification can interleave differently between runs).
    expect([...proxied.stdoutLines].sort()).toEqual([...direct].sort());

    // (6, main run) clean exit propagates as 0.
    expect(proxied.exitCode).toBe(0);

    const events = proxied.store.events();
    const kinds = events.map((e) => e.kind);

    // (2) The session storyline is captured.
    expect(kinds[0]).toBe('session_start');
    expect(kinds).toContain('initialize');
    expect(kinds).toContain('rpc');
    expect(kinds).toContain('tool_call');
    expect(kinds).toContain('notification');
    expect(kinds[kinds.length - 1]).toBe('session_end');

    const init = events.find((e) => e.kind === 'initialize');
    expect(init).toMatchObject({
      request_id: 1,
      protocol_version: '2024-11-05',
      client_name: 'vitest-client',
      client_version: '9.9.9',
      server_name: 'echo-server',
      server_version: '1.0.0',
    });

    const rpc = events.find((e): e is RpcEvent => e.kind === 'rpc');
    expect(rpc?.method).toBe('tools/list');
    expect(rpc?.is_error).toBe(false);
    expect(rpc?.request_id).toBe(2);

    const call = events.find((e): e is ToolCallEvent => e.kind === 'tool_call');
    expect(call).toBeDefined();
    expect(call!.tool).toBe('echo');
    expect(call!.request_id).toBe(3);
    expect(call!.is_error).toBe(false);
    expect(call!.duration_ms).toBeGreaterThan(0);
    expect(call!.attributes).toMatchObject({
      'gen_ai.operation.name': 'execute_tool',
      'gen_ai.tool.name': 'echo',
      'gen_ai.tool.call.id': '3',
      'mcp.method.name': 'tools/call',
      'rpc.system': 'jsonrpc',
    });

    const notes = events.filter((e): e is NotificationEvent => e.kind === 'notification');
    expect(notes.some((n) => n.direction === 'client_to_server' && n.method === 'notifications/initialized')).toBe(true);
    expect(notes.some((n) => n.direction === 'server_to_client' && n.method === 'notifications/message')).toBe(true);

    const end = events.find((e): e is SessionEndEvent => e.kind === 'session_end');
    expect(end?.child_exit_code).toBe(0);
    expect(end?.reason).toBe('stdin_closed');

    // Identity learned from the handshake is stamped on later events.
    expect(call!.identity.client_name).toBe('vitest-client');
    expect(call!.server.name).toBe('echo-server');
    expect(call!.server.version).toBe('1.0.0');
    expect(call!.identity.fingerprint).toMatch(/^sha256:[0-9a-f]{64}$/);

    // (3) The planted secret appears nowhere in the stored evidence.
    expect(JSON.stringify(events)).not.toContain(SECRET);
    expect(JSON.stringify(proxied.store.records)).not.toContain(SECRET);

    // (4) result_hash matches a hash recomputed from the raw transcript.
    const rawCallResponse = proxied.stdoutLines
      .map((l) => JSON.parse(l) as { id?: unknown; result?: unknown })
      .find((m) => m.id === 3);
    expect(rawCallResponse).toBeDefined();
    expect(call!.result_hash).toBe(sha256Ref(canonicalJson(rawCallResponse!.result)));

    // Chain integrity of everything the proxy stored.
    let prev = GENESIS_HASH;
    proxied.store.records.forEach((r, idx) => {
      expect(r.seq).toBe(idx + 1);
      expect(r.prev_hash).toBe(prev);
      expect(r.hash).toBe(computeHash(prev, r.event));
      prev = r.hash;
    });
  });

  it('ECHO_NOISE=1: noise still reaches the client AND yields an unparseable protocol_error', async () => {
    const env = { ...process.env, ECHO_NOISE: '1' };
    const proxied = await runProxied(env);

    expect(proxied.stdoutLines).toContain('boot: ready');

    const errs = proxied.store
      .events()
      .filter((e): e is ProtocolErrorEvent => e.kind === 'protocol_error');
    const unparseable = errs.find((e) => e.reason === 'unparseable');
    expect(unparseable).toBeDefined();
    expect(unparseable!.direction).toBe('server_to_client');
    expect(unparseable!.bytes_len).toBe(Buffer.byteLength('boot: ready'));
    expect(unparseable!.line_hash).toBe(sha256Ref('boot: ready'));

    // Forwarding still works end to end despite the noise.
    const direct = await runDirect(env);
    expect([...proxied.stdoutLines].sort()).toEqual([...direct].sort());
  });

  it('propagates the child exit code', async () => {
    const store = new FakeStore();
    const recorder = new Recorder({ store, signer: null });
    const code = await runStdioProxy({
      command: [process.execPath, '-e', 'process.exit(3)'],
      recorder,
      redactor: fakeRedactor,
      proxyVersion: '0.1.0-test',
      stdin: new PassThrough(),
      stdout: new PassThrough(),
      stderr: new PassThrough(),
    });
    expect(code).toBe(3);
    const end = store.events().find((e): e is SessionEndEvent => e.kind === 'session_end');
    expect(end?.reason).toBe('child_exit');
    expect(end?.child_exit_code).toBe(3);
  });

  it('a spawn failure (ENOENT) exits 127 and records spawn_error', async () => {
    const store = new FakeStore();
    const recorder = new Recorder({ store, signer: null });
    const code = await runStdioProxy({
      command: ['/definitely/not/a/real/binary-xyz'],
      recorder,
      redactor: fakeRedactor,
      proxyVersion: '0.1.0-test',
      stdin: new PassThrough(),
      stdout: new PassThrough(),
      stderr: new PassThrough(),
    });
    expect(code).toBe(127);
    const end = store.events().find((e): e is SessionEndEvent => e.kind === 'session_end');
    expect(end?.reason).toBe('error');
    expect(end?.spawn_error).toBe('ENOENT');
  });

  it('a child killed by a signal exits 128+<signal number> and records child_signal', async () => {
    const store = new FakeStore();
    const recorder = new Recorder({ store, signer: null });
    const code = await runStdioProxy({
      command: [process.execPath, '-e', "process.kill(process.pid, 'SIGKILL')"],
      recorder,
      redactor: fakeRedactor,
      proxyVersion: '0.1.0-test',
      stdin: new PassThrough(),
      stdout: new PassThrough(),
      stderr: new PassThrough(),
    });
    expect(code).toBe(128 + 9); // SIGKILL = 9 on POSIX
    const end = store.events().find((e): e is SessionEndEvent => e.kind === 'session_end');
    expect(end?.child_signal).toBe('SIGKILL');
  });

  it('EPIPE on the proxy stdout does not crash the proxy, and a session_end is still written', async () => {
    const store = new FakeStore();
    const recorder = new Recorder({ store, signer: null });
    const stdin = new PassThrough();
    const stderr = new PassThrough();
    stderr.on('data', () => {
      /* drain */
    });

    // Simulates the MCP client closing its read end mid-session: the first
    // write to the proxy's stdout succeeds, every write after that fails
    // with EPIPE. Every chunk is also buffered so the test can wait for the
    // actual initialize REPLY to land (a positive signal), instead of
    // guessing a fixed delay.
    let writes = 0;
    const written: Buffer[] = [];
    const stdout = new Writable({
      write(chunk, _enc, cb) {
        writes++;
        written.push(Buffer.from(chunk as Buffer));
        if (writes > 1) {
          const err = new Error('write EPIPE') as NodeJS.ErrnoException;
          err.code = 'EPIPE';
          cb(err);
          return;
        }
        cb();
      },
    });
    const hasReply = (id: number) => () =>
      Buffer.concat(written)
        .toString('utf8')
        .split('\n')
        .some((l) => {
          try {
            const m = JSON.parse(l) as { id?: unknown; result?: unknown };
            return m.id === id && 'result' in m;
          } catch {
            return false;
          }
        });

    const done = runStdioProxy({
      command: [process.execPath, ECHO_SERVER],
      recorder,
      redactor: fakeRedactor,
      proxyVersion: '0.1.0-test',
      stdin,
      stdout,
      stderr,
    });

    stdin.write(JSON.stringify(CLIENT_SCRIPT[0]) + '\n'); // initialize
    // Wait for the actual reply to land on the proxy's stdout (the first
    // write always succeeds) rather than sleeping a fixed amount.
    await waitFor(hasReply(1), 'initialize reply on proxy stdout');

    // The handshake's reply and its immediate follow-up notification are
    // written back to back by echo-server and may or may not already have
    // coalesced into that single first write — force a second, temporally
    // distinct server->client message so a write attempt strictly AFTER
    // the first one is guaranteed, and EPIPE is guaranteed to fire.
    stdin.write(JSON.stringify(CLIENT_SCRIPT[2]) + '\n'); // tools/list

    // Deliberately never end the client-facing stdin ourselves. The only
    // thing that can end the child's real stdin in this test is the
    // proxy's own EPIPE handler (src/proxy/stdio.ts's
    // `proxyStdout.on('error', ...)`, the branch that ends `child.stdin`
    // once the client is gone) — that's what lets echo-server exit on its
    // own. If that branch never ran, `done` would hang (and this test
    // would time out) instead of passing vacuously.
    const exitCode = await done; // must resolve, not hang or throw
    expect(exitCode).toBe(0);
    expect(writes).toBeGreaterThan(1); // the forced second write actually happened

    const end = store.events().find((e): e is SessionEndEvent => e.kind === 'session_end');
    expect(end).toBeDefined();
    // 'child_exit' (never 'stdin_closed', since this test's own stdin was
    // never ended) is the proof that the shutdown was driven by the EPIPE
    // handler ending child.stdin, i.e. that the EPIPE branch actually ran —
    // not merely that the process happened to exit 0.
    expect(end!.reason).toBe('child_exit');

    stdin.destroy();
  });

  it('keeps numeric and string JSON-RPC ids distinct in the pending-request map', async () => {
    const store = new FakeStore();
    const recorder = new Recorder({ store, signer: null });
    const stdin = new PassThrough();
    const stdout = new PassThrough();
    const stderr = new PassThrough();
    const out = collectLines(stdout);
    stderr.on('data', () => {
      /* drain */
    });

    const done = runStdioProxy({
      command: [process.execPath, ECHO_SERVER],
      recorder,
      redactor: fakeRedactor,
      proxyVersion: '0.1.0-test',
      stdin,
      stdout,
      stderr,
    });

    // id 1 (number) and id "1" (string) are distinct JSON-RPC ids in flight
    // at once; a key scheme that collapses them would misroute one response
    // to the other's pending entry and orphan the other.
    stdin.write(JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' }) + '\n');
    stdin.write(
      JSON.stringify({
        jsonrpc: '2.0',
        id: '1',
        method: 'tools/call',
        params: { name: 'echo', arguments: {} },
      }) + '\n',
    );
    await waitFor(() => out.lines().length >= 2, 'both responses');
    stdin.end();
    await done;

    const events = store.events();
    expect(events.filter((e) => e.kind === 'protocol_error')).toHaveLength(0);

    const rpc = events.find((e): e is RpcEvent => e.kind === 'rpc' && e.method === 'tools/list');
    expect(rpc?.request_id).toBe(1);
    const call = events.find((e): e is ToolCallEvent => e.kind === 'tool_call');
    expect(call?.request_id).toBe('1');
  });

  it('deriveServerName skips runner flags (npx -y <pkg> shape)', async () => {
    const store = new FakeStore();
    const recorder = new Recorder({ store, signer: null });
    const stdin = new PassThrough();
    const stdout = new PassThrough();
    const stderr = new PassThrough();
    stdout.on('data', () => {
      /* drain */
    });
    stderr.on('data', () => {
      /* drain */
    });

    // 'node' is a known runner; '-y' must be skipped when deriving the
    // server name, the same shape as the README's own `npx -y <pkg>`
    // wrapping (deriveServerName previously returned '-y' itself here).
    const done = runStdioProxy({
      command: [process.execPath, '-y', ECHO_SERVER],
      recorder,
      redactor: fakeRedactor,
      proxyVersion: '0.1.0-test',
      stdin,
      stdout,
      stderr,
    });
    await new Promise((r) => setTimeout(r, 50));
    stdin.end();
    await done;

    const start = store.events().find((e): e is SessionStartEvent => e.kind === 'session_start');
    expect(start?.server.name).toBe('echo-server.cjs');
  });

  it('a tools/call still pending at shutdown yields a tool_call event with error.type "unanswered"', async () => {
    const store = new FakeStore();
    const recorder = new Recorder({ store, signer: null });
    const stdin = new PassThrough();
    const stdout = new PassThrough();
    const stderr = new PassThrough();
    stdout.on('data', () => {
      /* drain */
    });
    stderr.on('data', () => {
      /* drain */
    });

    const done = runStdioProxy({
      // Reads the request and simply never replies.
      command: [process.execPath, '-e', "process.stdin.once('data', () => {})"],
      recorder,
      redactor: fakeRedactor,
      proxyVersion: '0.1.0-test',
      stdin,
      stdout,
      stderr,
    });

    stdin.write(
      JSON.stringify({
        jsonrpc: '2.0',
        id: 7,
        method: 'tools/call',
        params: { name: 'delete_everything', arguments: { path: '/' } },
      }) + '\n',
    );
    await new Promise((r) => setTimeout(r, 300));
    stdin.end();
    await done;

    const events = store.events();
    expect(events.filter((e) => e.kind === 'protocol_error')).toHaveLength(0);
    const call = events.find((e): e is ToolCallEvent => e.kind === 'tool_call');
    expect(call).toBeDefined();
    expect(call!.tool).toBe('delete_everything');
    expect(call!.request_id).toBe(7);
    expect(call!.is_error).toBe(true);
    expect(call!.error?.type).toBe('unanswered');
    expect(call!.result).toBeNull();
    expect(call!.result_hash).toBe(sha256Ref(canonicalJson(null)));
    expect(call!.duration_ms).toBeGreaterThan(0);

    // Also present, before session_end, so the trace is never silently lost.
    const end = events.find((e): e is SessionEndEvent => e.kind === 'session_end');
    expect(events.indexOf(call!)).toBeLessThan(events.indexOf(end!));
  });
});

/* --- P2: credential-fingerprint cap reservation. Env-derived fingerprints
 * used to share the SAME 32-slot cap as argv/URL-derived ones, so a wrapped
 * server with >=32 credential-shaped env vars silently crowded out every
 * argv-derived fingerprint (e.g. a leaked `--token` value) — `query` could
 * never find it. Env is now capped on its own at 32, reserving room for
 * argv/URL-derived fingerprints up to a total of 64. */
describe('credential-fingerprint cap reservation (P2)', () => {
  it('an argv-derived fingerprint is never dropped just because env filled the 32-slot budget first', async () => {
    const store = new FakeStore();
    const recorder = new Recorder({ store, signer: null });

    // 40 distinct credential-shaped env vars: more than the old shared cap
    // of 32, so a naive shared counter would leave zero room for argv. Start
    // from a minimal env (not a spread of process.env) so ambient
    // credential-shaped vars from the outer environment (GITHUB_TOKEN,
    // AWS_SECRET_ACCESS_KEY, ...) cannot shift the count.
    const env: NodeJS.ProcessEnv = { PATH: process.env.PATH ?? '' };
    for (let i = 0; i < 40; i++) {
      env[`SERVICE_TOKEN_${i}`] = `env-credential-value-number-${i}`;
    }

    const argvSecret = 'argv-secret-should-still-be-fingerprinted';
    const code = await runStdioProxy({
      command: [process.execPath, '-e', 'process.exit(0)', '--', '--token', argvSecret],
      recorder,
      redactor: fakeRedactor,
      proxyVersion: '0.1.0-test',
      stdin: new PassThrough(),
      stdout: new PassThrough(),
      stderr: new PassThrough(),
      env,
    });
    expect(code).toBe(0);

    const start = store.events().find((e): e is SessionStartEvent => e.kind === 'session_start');
    expect(start).toBeDefined();
    const fps = start!.identity.credential_fingerprints ?? [];

    // Env-derived fingerprints are capped at 32...
    const envFps = fps.filter((f) => f.name.startsWith('SERVICE_TOKEN_'));
    expect(envFps.length).toBe(32);

    // ...but the argv-derived one is still present (not silently dropped),
    // and the total never exceeds the reserved 64-slot cap.
    const argvHash = sha256Ref(argvSecret);
    expect(fps.some((f) => f.ref === argvHash)).toBe(true);
    expect(fps.length).toBeLessThanOrEqual(64);
  });
});

/* --- P0: capping verbatim protocol strings (tool name, method, clientInfo/
 * serverInfo, protocolVersion). A misbehaving or malicious peer used to be
 * able to stuff kilobytes of arbitrary text into every event through these
 * fields, uncapped by length or character shape — structuralString() now
 * caps each one at the edge. */
describe('structuralString capping of protocol strings (P0)', () => {
  const HUGE_NAME = 'x'.repeat(5000);
  const NAME_WITH_SPACES = 'not a valid tool name';
  const NAME_WITH_NEWLINE = 'bad\nname';
  const HUGE_METHOD = 'y'.repeat(5000);
  const MALFORMED_PROTOCOL_VERSION = 'not-a-date';

  /** node -e script: replies to ONE initialize request with an oversized,
   *  malformed serverInfo (name/version), no dependency on echo-server.cjs. */
  const HUGE_SERVER_INFO_SCRIPT =
    "let buf = ''; process.stdin.setEncoding('utf8'); " +
    "process.stdin.on('data', (c) => { buf += c; }); " +
    "process.stdin.on('end', () => { " +
    'const msg = JSON.parse(buf); ' +
    "process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: msg.id, result: { " +
    "protocolVersion: '2024-11-05', " +
    "serverInfo: { name: 'srv-'.concat('z'.repeat(5000)), version: 'bad version' }, " +
    'capabilities: {} } })); ' +
    'process.exitCode = 0; ' +
    '});';

  it('an oversized / space-containing / newline-containing tools/call name is capped to a sha256 ref in tool_call.tool and the gen_ai.tool.name attribute, and a blast-radius query for the original name finds it', async () => {
    const store = new FakeStore();
    const recorder = new Recorder({ store, signer: null });
    const stdin = new PassThrough();
    const stdout = new PassThrough();
    const stderr = new PassThrough();
    const out = collectLines(stdout);
    stderr.on('data', () => {
      /* drain */
    });

    const done = runStdioProxy({
      command: [process.execPath, ECHO_SERVER],
      recorder,
      redactor: fakeRedactor,
      proxyVersion: '0.1.0-test',
      stdin,
      stdout,
      stderr,
    });

    const names = [HUGE_NAME, NAME_WITH_SPACES, NAME_WITH_NEWLINE];
    names.forEach((name, i) => {
      stdin.write(
        JSON.stringify({
          jsonrpc: '2.0',
          id: 100 + i,
          method: 'tools/call',
          params: { name, arguments: {} },
        }) + '\n',
      );
    });
    await waitFor(() => out.lines().length >= names.length, 'all tool_call responses');
    stdin.end();
    await done;

    const calls = store.events().filter((e): e is ToolCallEvent => e.kind === 'tool_call');
    expect(calls).toHaveLength(3);
    calls.forEach((call, i) => {
      const name = names[i]!;
      const expectedRef = sha256Ref(name);
      expect(call.tool).toBe(expectedRef);
      expect(call.attributes['gen_ai.tool.name']).toBe(expectedRef);
      expect(call.tool).not.toContain(name);

      // A blast-radius query for the ORIGINAL (uncapped) name still finds
      // the event, via the tool field's sha256 ref.
      const result = queryStore(store, name);
      expect(result.matches.some((m) => m.matched_on === 'ref' && m.path === '$.tool')).toBe(true);
    });
  });

  it('a normal, short tool name passes through unchanged', async () => {
    const store = new FakeStore();
    const recorder = new Recorder({ store, signer: null });
    const stdin = new PassThrough();
    const stdout = new PassThrough();
    const stderr = new PassThrough();
    const out = collectLines(stdout);
    stderr.on('data', () => {
      /* drain */
    });

    const done = runStdioProxy({
      command: [process.execPath, ECHO_SERVER],
      recorder,
      redactor: fakeRedactor,
      proxyVersion: '0.1.0-test',
      stdin,
      stdout,
      stderr,
    });

    stdin.write(
      JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: 'tools/call',
        params: { name: 'echo', arguments: {} },
      }) + '\n',
    );
    await waitFor(() => out.lines().length >= 1, 'tool_call response');
    stdin.end();
    await done;

    const call = store.events().find((e): e is ToolCallEvent => e.kind === 'tool_call');
    expect(call?.tool).toBe('echo');
    expect(call?.attributes['gen_ai.tool.name']).toBe('echo');
  });

  it('an oversized JSON-RPC method is capped to a sha256 ref in rpc.method / notification.method and the mcp.method.name attribute, and query finds the original method', async () => {
    const store = new FakeStore();
    const recorder = new Recorder({ store, signer: null });
    const stdin = new PassThrough();
    const stdout = new PassThrough();
    const stderr = new PassThrough();
    const out = collectLines(stdout);
    stderr.on('data', () => {
      /* drain */
    });

    const done = runStdioProxy({
      command: [process.execPath, ECHO_SERVER],
      recorder,
      redactor: fakeRedactor,
      proxyVersion: '0.1.0-test',
      stdin,
      stdout,
      stderr,
    });

    // A request with a huge method: echo-server replies -32601 (method not
    // found), but the proxy must still cap and record it as an `rpc` event.
    stdin.write(JSON.stringify({ jsonrpc: '2.0', id: 1, method: HUGE_METHOD }) + '\n');
    await waitFor(() => out.lines().length >= 1, 'rpc error response');
    // A notification (no id) carrying the same oversized method.
    stdin.write(JSON.stringify({ jsonrpc: '2.0', method: HUGE_METHOD }) + '\n');
    await new Promise((r) => setTimeout(r, 100));
    stdin.end();
    await done;

    const expectedRef = sha256Ref(HUGE_METHOD);
    const rpc = store.events().find((e): e is RpcEvent => e.kind === 'rpc');
    expect(rpc).toBeDefined();
    expect(rpc!.method).toBe(expectedRef);
    expect(rpc!.attributes['mcp.method.name']).toBe(expectedRef);

    const note = store
      .events()
      .find((e): e is NotificationEvent => e.kind === 'notification' && e.direction === 'client_to_server');
    expect(note).toBeDefined();
    expect(note!.method).toBe(expectedRef);
    expect(note!.attributes['mcp.method.name']).toBe(expectedRef);

    const result = queryStore(store, HUGE_METHOD);
    expect(result.matches.some((m) => m.matched_on === 'ref' && m.path === '$.method')).toBe(true);
  });

  it('an oversized clientInfo name/version and a malformed protocolVersion are capped on the initialize event, and the capped client_name is what later events carry as identity context', async () => {
    const store = new FakeStore();
    const recorder = new Recorder({ store, signer: null });
    const stdin = new PassThrough();
    const stdout = new PassThrough();
    const stderr = new PassThrough();
    const out = collectLines(stdout);
    stderr.on('data', () => {
      /* drain */
    });

    const done = runStdioProxy({
      command: [process.execPath, ECHO_SERVER],
      recorder,
      redactor: fakeRedactor,
      proxyVersion: '0.1.0-test',
      stdin,
      stdout,
      stderr,
    });

    stdin.write(
      JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: 'initialize',
        params: {
          protocolVersion: MALFORMED_PROTOCOL_VERSION,
          clientInfo: { name: HUGE_NAME, version: NAME_WITH_SPACES },
          capabilities: {},
        },
      }) + '\n',
    );
    await waitFor(() => out.lines().length >= 1, 'initialize response');
    stdin.write(
      JSON.stringify({
        jsonrpc: '2.0',
        id: 2,
        method: 'tools/call',
        params: { name: 'echo', arguments: {} },
      }) + '\n',
    );
    await waitFor(() => out.lines().length >= 2, 'tool_call response');
    stdin.end();
    await done;

    const expectedNameRef = sha256Ref(HUGE_NAME);
    const expectedVersionRef = sha256Ref(NAME_WITH_SPACES);
    const expectedProtoRef = sha256Ref(MALFORMED_PROTOCOL_VERSION);

    const init = store.events().find((e): e is InitializeEvent => e.kind === 'initialize');
    expect(init).toBeDefined();
    expect(init!.client_name).toBe(expectedNameRef);
    expect(init!.client_version).toBe(expectedVersionRef);
    expect(init!.protocol_version).toBe(expectedProtoRef);
    expect(init!.client_name).not.toContain(HUGE_NAME.slice(0, 50));

    // The remembered clientName/clientVersion feed identity context on every
    // LATER event too, not just the initialize event itself.
    const call = store.events().find((e): e is ToolCallEvent => e.kind === 'tool_call');
    expect(call!.identity.client_name).toBe(expectedNameRef);
    expect(call!.identity.client_version).toBe(expectedVersionRef);
  });

  it('an oversized/malformed serverInfo learned from the handshake is capped on the initialize event, and later events carry the capped server name/version', async () => {
    const store = new FakeStore();
    const recorder = new Recorder({ store, signer: null });
    const stdin = new PassThrough();
    const stdout = new PassThrough();
    const stderr = new PassThrough();
    const out = collectLines(stdout);
    stderr.on('data', () => {
      /* drain */
    });

    const done = runStdioProxy({
      command: [process.execPath, '-e', HUGE_SERVER_INFO_SCRIPT],
      recorder,
      redactor: fakeRedactor,
      proxyVersion: '0.1.0-test',
      stdin,
      stdout,
      stderr,
    });

    // HUGE_SERVER_INFO_SCRIPT only replies once ITS stdin ends (it has no
    // \n-framing of its own — see the script above), so end stdin right
    // after writing the request rather than waiting for a response first.
    stdin.write(
      JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: 'initialize',
        params: { protocolVersion: '2024-11-05', clientInfo: { name: 'vitest', version: '1.0.0' }, capabilities: {} },
      }) + '\n',
    );
    stdin.end();
    await waitFor(() => out.lines().length >= 1, 'initialize response');
    await done;

    const hugeServerName = 'srv-'.concat('z'.repeat(5000));
    const expectedNameRef = sha256Ref(hugeServerName);
    const expectedVersionRef = sha256Ref('bad version');

    const init = store.events().find((e): e is InitializeEvent => e.kind === 'initialize');
    expect(init).toBeDefined();
    expect(init!.server_name).toBe(expectedNameRef);
    expect(init!.server_version).toBe(expectedVersionRef);

    // server.name / server.version stamped on the SessionStartEvent (which
    // predates the handshake) stay the pre-handshake fallback, but every
    // event recorded AFTER the handshake carries the capped, learned value.
    expect(init!.server.name).toBe(expectedNameRef);
    expect(init!.server.version).toBe(expectedVersionRef);
  });
});
