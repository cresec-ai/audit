import { spawn } from 'node:child_process';
import { PassThrough } from 'node:stream';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

import { GENESIS_HASH, canonicalJson, computeHash, sha256Ref } from '../src/chain/hash.js';
import { Recorder } from '../src/capture/recorder.js';
import { runStdioProxy } from '../src/proxy/stdio.js';
import type {
  AnyEvent,
  ChainRecord,
  HeadSignature,
  NotificationEvent,
  ProtocolErrorEvent,
  RpcEvent,
  Scrubbed,
  SessionEndEvent,
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
});
