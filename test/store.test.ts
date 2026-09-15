import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import {
  appendFileSync,
  existsSync,
  mkdtempSync,
  readdirSync,
  statSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createRequire } from 'node:module';
import { GENESIS_HASH, computeHash, makeRecord, sha256Hex, sha256Ref } from '../src/chain/hash.js';
import { openStore, openStoreReadOnly, isSqliteAvailable } from '../src/store/index.js';
import { verifyStore } from '../src/verify/verify.js';
import { ENV, FILES } from '../src/types.js';
import type { ChainHead, EvidenceStore } from '../src/types.js';
import type {
  AnyEvent,
  ChainRecord,
  HeadSignature,
  IdentityContext,
  ServerContext,
  SessionEndEvent,
  SessionStartEvent,
  ToolCallEvent,
} from '../src/schema/events.js';
import { SCHEMA } from '../src/schema/events.js';
import { jsonlIoStats } from '../src/store/jsonl.js';

/* ------------------------------ fixtures ------------------------------ */

let eventCounter = 0;

function fakeUuid(): string {
  // Deterministic UUID-shaped ids keep fixtures reproducible.
  const n = (eventCounter++).toString(16).padStart(12, '0');
  return `00000000-0000-4000-8000-${n}`;
}

const IDENTITY: IdentityContext = {
  fingerprint: sha256Ref('jonirap|test-host|claude-code|1.2.3|ci'),
  os_user: 'jonirap',
  hostname: 'test-host',
  client_name: 'claude-code',
  client_version: '1.2.3',
  label: 'ci',
};

const SERVER: ServerContext = {
  name: 'github-mcp',
  version: '2.1.0',
  command: 'npx -y @modelcontextprotocol/server-github',
  transport: 'stdio',
};

function sessionStart(sessionId: string, timestamp: string): SessionStartEvent {
  return {
    schema: SCHEMA,
    event_id: fakeUuid(),
    session_id: sessionId,
    timestamp,
    kind: 'session_start',
    identity: IDENTITY,
    server: SERVER,
    attributes: { 'mcp.method.name': 'session_start' },
    proxy_version: '0.1.0',
    cwd: '/home/jonirap/project',
    redaction_mode: 'allowlist',
  };
}

function toolCall(
  sessionId: string,
  timestamp: string,
  tool: string,
  opts: { isError?: boolean; requestId?: string | number } = {},
): ToolCallEvent {
  const isError = opts.isError ?? false;
  const event: ToolCallEvent = {
    schema: SCHEMA,
    event_id: fakeUuid(),
    session_id: sessionId,
    timestamp,
    kind: 'tool_call',
    identity: IDENTITY,
    server: SERVER,
    attributes: {
      'gen_ai.operation.name': 'execute_tool',
      'gen_ai.tool.name': tool,
      'rpc.system': 'jsonrpc',
    },
    tool,
    request_id: opts.requestId ?? 7,
    args: {
      owner: { redacted: true, ref: sha256Ref('octocat'), len: 7 },
      repo: { redacted: true, ref: sha256Ref('hello-world'), len: 11 },
      per_page: 30,
      verbose: true,
      filter: null,
    },
    result_hash: sha256Ref(`{"ok":${!isError}}`),
    result: {
      content: [
        { type: 'text', text: { redacted: true, ref: sha256Ref('result body'), len: 11 } },
      ],
    },
    is_error: isError,
    duration_ms: 12.5,
  };
  if (isError) {
    event.error = { code: -32000, type: 'ToolError', message_ref: sha256Ref('boom') };
  }
  return event;
}

function sessionEnd(sessionId: string, timestamp: string): SessionEndEvent {
  return {
    schema: SCHEMA,
    event_id: fakeUuid(),
    session_id: sessionId,
    timestamp,
    kind: 'session_end',
    identity: IDENTITY,
    server: SERVER,
    attributes: {},
    reason: 'child_exit',
    child_exit_code: 0,
    events_recorded: 4,
    events_dropped: 0,
  };
}

/** Seal events into a contiguous chain starting at `head`. */
function seal(events: AnyEvent[], head: ChainHead = { seq: 0, hash: GENESIS_HASH }): ChainRecord[] {
  const out: ChainRecord[] = [];
  let h = head;
  for (const event of events) {
    const record = makeRecord(h, event);
    out.push(record);
    h = { seq: record.seq, hash: record.hash };
  }
  return out;
}

const SESSION_A = '11111111-1111-4111-8111-111111111111';
const SESSION_B = '22222222-2222-4222-8222-222222222222';

/** Two realistic sessions: A is complete (with one failed call), B is still open. */
function twoSessionFixture(): ChainRecord[] {
  return seal([
    sessionStart(SESSION_A, '2026-06-11T10:00:00.000Z'),
    toolCall(SESSION_A, '2026-06-11T10:00:01.000Z', 'list_issues', { requestId: 1 }),
    toolCall(SESSION_A, '2026-06-11T10:00:02.000Z', 'create_issue', {
      requestId: 2,
      isError: true,
    }),
    sessionEnd(SESSION_A, '2026-06-11T10:00:03.000Z'),
    sessionStart(SESSION_B, '2026-06-11T11:00:00.000Z'),
    toolCall(SESSION_B, '2026-06-11T11:00:01.000Z', 'get_file_contents', { requestId: 1 }),
  ]);
}

function fakeSignature(record: ChainRecord, signedAt: string): HeadSignature {
  return {
    seq: record.seq,
    chain_hash: record.hash,
    algo: 'ed25519',
    public_key: 'ab'.repeat(32),
    signature: 'cd'.repeat(64),
    signed_at: signedAt,
  };
}

/* ------------------------- parametrized suite ------------------------- */

const backends: Array<'sqlite' | 'jsonl'> = ['sqlite', 'jsonl'];

describe.each(backends)('EvidenceStore (%s)', (backend) => {
  let dir: string;
  let opened: EvidenceStore[];

  function open(): EvidenceStore {
    const store = openStore({ dataDir: dir, backend });
    opened.push(store);
    return store;
  }

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), `mcp-recorder-store-${backend}-`));
    opened = [];
  });

  afterEach(() => {
    for (const store of opened) {
      try {
        store.close();
      } catch {
        /* already closed */
      }
    }
    rmSync(dir, { recursive: true, force: true });
  });

  it('reports the requested backend and an existing path', () => {
    const store = open();
    expect(store.backend).toBe(backend);
    expect(store.path.startsWith(dir)).toBe(true);
  });

  it('empty store: genesis head, zero count, no sessions or signatures', () => {
    const store = open();
    expect(store.head()).toEqual({ seq: 0, hash: GENESIS_HASH });
    expect(store.count()).toBe(0);
    expect(store.sessions()).toEqual([]);
    expect(store.signatures()).toEqual([]);
    expect(store.latestSignature()).toBeNull();
    expect([...store.iterate()]).toEqual([]);
  });

  it('append + head + iterate round-trip', () => {
    const records = twoSessionFixture();
    const store = open();
    store.append(records);

    const last = records[records.length - 1]!;
    expect(store.head()).toEqual({ seq: last.seq, hash: last.hash });
    expect(store.count()).toBe(records.length);
    expect([...store.iterate()]).toEqual(records);
  });

  it('append in multiple batches extends the chain', () => {
    const records = twoSessionFixture();
    const store = open();
    store.append(records.slice(0, 3));
    store.append(records.slice(3));
    expect(store.count()).toBe(records.length);
    expect([...store.iterate()]).toEqual(records);
    expect(store.append([])).toBeUndefined(); // empty append is a no-op
  });

  it('persists across reopen', () => {
    const records = twoSessionFixture();
    const store = open();
    store.append(records);
    store.addSignature(fakeSignature(records[records.length - 1]!, '2026-06-11T11:00:02.000Z'));
    store.close();

    const reopened = open();
    expect(reopened.head()).toEqual({ seq: 6, hash: records[5]!.hash });
    expect(reopened.count()).toBe(6);
    expect([...reopened.iterate()]).toEqual(records);
    expect(reopened.latestSignature()?.chain_hash).toBe(records[5]!.hash);

    // And the chain keeps extending from the persisted head.
    const more = seal(
      [toolCall(SESSION_B, '2026-06-11T11:00:05.000Z', 'search_code', { requestId: 2 })],
      reopened.head(),
    );
    reopened.append(more);
    expect(reopened.head().seq).toBe(7);
  });

  it('rejects an append with a seq gap', () => {
    const records = twoSessionFixture();
    const store = open();
    store.append(records.slice(0, 2));
    expect(() => store.append([records[3]!])).toThrow(/chain integrity violation.*seq/);
    expect(store.count()).toBe(2);
  });

  it('rejects a duplicate seq', () => {
    const records = twoSessionFixture();
    const store = open();
    store.append(records.slice(0, 2));
    expect(() => store.append([records[1]!])).toThrow(/chain integrity violation.*seq/);
    expect(store.count()).toBe(2);
  });

  it('rejects a bad prev_hash even when the record hash is self-consistent', () => {
    const records = twoSessionFixture();
    const store = open();
    store.append(records.slice(0, 2));

    const event = toolCall(SESSION_A, '2026-06-11T10:00:09.000Z', 'forged');
    const bogusPrev = sha256Hex('not-the-head');
    const forged: ChainRecord = {
      seq: 3,
      prev_hash: bogusPrev,
      hash: computeHash(bogusPrev, event),
      event,
    };
    expect(() => store.append([forged])).toThrow(/chain integrity violation.*prev_hash/);
    expect(store.count()).toBe(2);
  });

  it('rejects a record whose hash does not match its content', () => {
    const records = twoSessionFixture();
    const store = open();
    store.append(records.slice(0, 2));

    const good = makeRecord(store.head(), toolCall(SESSION_A, '2026-06-11T10:00:09.000Z', 'x'));
    const tampered: ChainRecord = { ...good, hash: sha256Hex('tampered') };
    expect(() => store.append([tampered])).toThrow(/chain integrity violation.*hash/);
    expect(store.count()).toBe(2);
  });

  it('a bad record mid-batch leaves nothing of the batch behind', () => {
    const records = twoSessionFixture();
    const store = open();
    const tampered: ChainRecord = { ...records[1]!, hash: sha256Hex('tampered') };
    expect(() => store.append([records[0]!, tampered, records[2]!])).toThrow(
      /chain integrity violation/,
    );
    expect(store.count()).toBe(0);
    expect(store.head()).toEqual({ seq: 0, hash: GENESIS_HASH });
  });

  it('sessions() aggregates per session', () => {
    const store = open();
    store.append(twoSessionFixture());

    const sessions = store.sessions();
    expect(sessions).toHaveLength(2);

    const a = sessions.find((s) => s.session_id === SESSION_A)!;
    expect(a).toBeDefined();
    expect(a.started_at).toBe('2026-06-11T10:00:00.000Z');
    expect(a.ended_at).toBe('2026-06-11T10:00:03.000Z');
    expect(a.server_name).toBe('github-mcp');
    expect(a.identity_fingerprint).toBe(IDENTITY.fingerprint);
    expect(a.event_count).toBe(4);
    expect(a.tool_call_count).toBe(2);
    expect(a.error_count).toBe(1);

    const b = sessions.find((s) => s.session_id === SESSION_B)!;
    expect(b).toBeDefined();
    expect(b.started_at).toBe('2026-06-11T11:00:00.000Z');
    expect(b.ended_at).toBeUndefined();
    expect(b.server_name).toBe('github-mcp');
    expect(b.identity_fingerprint).toBe(IDENTITY.fingerprint);
    expect(b.event_count).toBe(2);
    expect(b.tool_call_count).toBe(1);
    expect(b.error_count).toBe(0);
  });

  it('signatures round-trip in insertion order', () => {
    const records = twoSessionFixture();
    const store = open();
    store.append(records);

    const sig1 = fakeSignature(records[2]!, '2026-06-11T10:00:02.500Z');
    const sig2 = fakeSignature(records[5]!, '2026-06-11T11:00:01.500Z');
    store.addSignature(sig1);
    store.addSignature(sig2);

    expect(store.signatures()).toEqual([sig1, sig2]);
    expect(store.latestSignature()).toEqual(sig2);
  });

  it('iterate honors seq range and session filters', () => {
    const records = twoSessionFixture();
    const store = open();
    store.append(records);

    expect([...store.iterate({ fromSeq: 2, toSeq: 4 })].map((r) => r.seq)).toEqual([2, 3, 4]);
    expect([...store.iterate({ fromSeq: 6 })].map((r) => r.seq)).toEqual([6]);
    expect([...store.iterate({ toSeq: 1 })].map((r) => r.seq)).toEqual([1]);

    const sessionB = [...store.iterate({ sessionId: SESSION_B })];
    expect(sessionB.map((r) => r.seq)).toEqual([5, 6]);
    expect(sessionB.every((r) => r.event.session_id === SESSION_B)).toBe(true);

    expect([...store.iterate({ sessionId: SESSION_A, fromSeq: 2 })].map((r) => r.seq)).toEqual([
      2, 3, 4,
    ]);
    expect([...store.iterate({ sessionId: 'no-such-session' })]).toEqual([]);
  });

  it('appendEvents seals raw events into a contiguous, verifiable chain', () => {
    const store = open();
    const events: AnyEvent[] = [
      sessionStart(SESSION_A, '2026-06-11T10:00:00.000Z'),
      toolCall(SESSION_A, '2026-06-11T10:00:01.000Z', 'list_issues', { requestId: 1 }),
      sessionEnd(SESSION_A, '2026-06-11T10:00:02.000Z'),
    ];
    const sealed = store.appendEvents(events);

    expect(sealed).toHaveLength(3);
    let prev = GENESIS_HASH;
    sealed.forEach((record, idx) => {
      expect(record.seq).toBe(idx + 1);
      expect(record.prev_hash).toBe(prev);
      expect(record.hash).toBe(computeHash(prev, record.event));
      expect(record.event).toEqual(events[idx]);
      prev = record.hash;
    });
    expect(store.head()).toEqual({ seq: 3, hash: sealed[2]!.hash });
    expect(store.count()).toBe(3);
    expect([...store.iterate()]).toEqual(sealed);
  });

  it('appendEvents keeps the chain linked across multiple calls', () => {
    const store = open();
    const first = store.appendEvents([sessionStart(SESSION_A, '2026-06-11T10:00:00.000Z')]);
    const second = store.appendEvents([
      toolCall(SESSION_A, '2026-06-11T10:00:01.000Z', 'list_issues', { requestId: 1 }),
      sessionEnd(SESSION_A, '2026-06-11T10:00:02.000Z'),
    ]);
    expect(first[0]!.seq).toBe(1);
    expect(second[0]!.seq).toBe(2);
    expect(second[0]!.prev_hash).toBe(first[0]!.hash);
    expect(second[1]!.seq).toBe(3);
    expect(second[1]!.prev_hash).toBe(second[0]!.hash);
    expect(store.count()).toBe(3);
    expect(store.append([])).toBeUndefined();
    expect(store.appendEvents([])).toEqual([]);
  });
});

/* --------------------------- sqlite-specific --------------------------- */

describe('SqliteStore append-only triggers', () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'mcp-recorder-sqlite-raw-'));
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('raw UPDATE/DELETE via a second connection are blocked', () => {
    expect(isSqliteAvailable()).toBe(true);
    const records = twoSessionFixture();
    const store = openStore({ dataDir: dir, backend: 'sqlite' });
    store.append(records);
    store.addSignature(fakeSignature(records[5]!, '2026-06-11T11:00:02.000Z'));
    store.close();

    const require = createRequire(import.meta.url);
    const Database = require('better-sqlite3') as typeof import('better-sqlite3');
    const raw = new Database(join(dir, FILES.SQLITE_DB));
    try {
      expect(() => raw.prepare("UPDATE records SET hash = 'evil' WHERE seq = 1").run()).toThrow(
        /append-only/,
      );
      expect(() => raw.prepare('DELETE FROM records WHERE seq = 3').run()).toThrow(/append-only/);
      expect(() =>
        raw.prepare("UPDATE signatures SET signature = 'evil'").run(),
      ).toThrow(/append-only/);
      expect(() => raw.prepare('DELETE FROM signatures').run()).toThrow(/append-only/);
    } finally {
      raw.close();
    }

    // Nothing changed.
    const reopened = openStore({ dataDir: dir, backend: 'sqlite' });
    expect(reopened.count()).toBe(6);
    expect(reopened.signatures()).toHaveLength(1);
    reopened.close();
  });
});

/* ---------------------------- jsonl-specific --------------------------- */

describe('JsonlStore trailing partial line', () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'mcp-recorder-jsonl-partial-'));
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('ignores a truncated final line with a stderr warning', async () => {
    const records = twoSessionFixture();
    const store = openStore({ dataDir: dir, backend: 'jsonl' });
    store.append(records);
    store.close();

    // Simulate a crash mid-write: a partial JSON line with no newline.
    appendFileSync(join(dir, FILES.JSONL_LOG), '{"seq":7,"prev_hash":"trunc');

    const stderrSpy = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
    try {
      const reopened = openStore({ dataDir: dir, backend: 'jsonl' });
      expect(reopened.count()).toBe(6);
      expect(reopened.head()).toEqual({ seq: 6, hash: records[5]!.hash });
      expect(
        stderrSpy.mock.calls.some((call) => String(call[0]).includes('trailing partial line')),
      ).toBe(true);
      // The store still appends correctly after recovery.
      const more = seal(
        [toolCall(SESSION_B, '2026-06-11T11:00:09.000Z', 'after_crash')],
        reopened.head(),
      );
      reopened.append(more);
      expect(reopened.count()).toBe(7);
      // The writer trimmed the torn bytes (which never formed a sealed record)
      // so the new record was not glued onto them.
      expect(
        stderrSpy.mock.calls.some((call) => String(call[0]).includes('discarded a torn trailing line')),
      ).toBe(true);
      expect(readFileSync(join(dir, FILES.JSONL_LOG), 'utf8')).not.toContain('"trunc');
      reopened.close();

      // ...and it all survives a fresh open + a second append + verification:
      // before the repair, the glued line was either silently dropped as a
      // "trailing partial line" (losing seq 7) or, once seq 8 followed it,
      // became mid-file corruption that made the store unopenable.
      const again = openStore({ dataDir: dir, backend: 'jsonl' });
      expect(again.count()).toBe(7);
      expect(again.head()).toEqual({ seq: 7, hash: more[0]!.hash });
      const sealed = again.appendEvents([
        toolCall(SESSION_B, '2026-06-11T11:00:10.000Z', 'after_recovery'),
      ]);
      expect(sealed[0]!.seq).toBe(8);
      again.close();
      const third = openStore({ dataDir: dir, backend: 'jsonl' });
      expect(third.count()).toBe(8);
      expect((await verifyStore(third, { allowUnsigned: true })).ok).toBe(true);
      third.close();
    } finally {
      stderrSpy.mockRestore();
    }
  });

  it('throws on corruption that is not a trailing partial line', () => {
    const records = twoSessionFixture();
    const store = openStore({ dataDir: dir, backend: 'jsonl' });
    store.append(records.slice(0, 2));
    store.close();

    const logPath = join(dir, FILES.JSONL_LOG);
    const lines = readFileSync(logPath, 'utf8').split('\n');
    lines[0] = lines[0]!.slice(0, 20); // corrupt the FIRST line
    writeFileSync(logPath, lines.join('\n'));

    expect(() => openStore({ dataDir: dir, backend: 'jsonl' })).toThrow(/corrupt JSONL line 1/);
  });
});

describe('JsonlStore incremental catch-up', () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'mcp-recorder-jsonl-incr-'));
    // `jsonlIoStats` is process-wide test instrumentation (see its doc
    // comment in src/store/jsonl.ts): a small internal hook, used here
    // instead of spying on `node:fs` directly, because `vi.spyOn` cannot
    // reliably intercept a *named* import's bare call site (`readFileSync`,
    // as jsonl.ts uses it) — under Vitest/Vite's module transform that name
    // is bound once at import time rather than read live off the module
    // object, so a spy on the object silently never gets invoked. Reset the
    // counters so each test only sees its own I/O.
    jsonlIoStats.fullReloadBytes = 0;
    jsonlIoStats.fullReloadCalls = 0;
    jsonlIoStats.incrementalReadBytes = 0;
    jsonlIoStats.incrementalReadCalls = 0;
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it("a second instance's many appended batches are picked up without any full-file re-read", () => {
    const storeA = openStore({ dataDir: dir, backend: 'jsonl' });
    const storeB = openStore({ dataDir: dir, backend: 'jsonl' });
    try {
      // Seed one record through A so B's first catch-up has a non-empty
      // head to reconcile against, same as a real hand-off between two
      // `mcp-recorder record` processes.
      const seeded = seal([sessionStart(SESSION_A, '2026-06-11T10:00:00.000Z')]);
      storeA.append(seeded);
      expect(storeA.count()).toBe(1);

      // Everything from here on must go through the incremental path: no
      // full reload (of either store) is allowed for the rest of this test.
      jsonlIoStats.fullReloadCalls = 0;

      const N_BATCHES = 40;
      const BATCH_SIZE = 25;
      for (let b = 0; b < N_BATCHES; b++) {
        const events: AnyEvent[] = [];
        for (let i = 0; i < BATCH_SIZE; i++) {
          events.push(
            toolCall(
              SESSION_A,
              `2026-06-11T10:01:${String(b).padStart(2, '0')}.${String(i).padStart(3, '0')}Z`,
              `t_${b}_${i}`,
            ),
          );
        }
        // storeB is the "other process": it never re-reads anything either
        // (its own writes update its cache directly), but its appends are
        // what storeA must catch up to below.
        storeB.appendEvents(events);
      }

      const total = 1 + N_BATCHES * BATCH_SIZE;
      // storeA wrote none of this — every one of these must come from disk
      // via storeA's own catch-up logic, purely incrementally.
      expect(storeA.count()).toBe(total);
      expect(storeA.head().seq).toBe(total);
      expect([...storeA.iterate()]).toHaveLength(total);

      expect(jsonlIoStats.fullReloadCalls).toBe(0);
      // And it really did read incrementally (not just "nothing happened").
      expect(jsonlIoStats.incrementalReadCalls).toBeGreaterThan(0);
    } finally {
      storeA.close();
      storeB.close();
    }
  });

  it('a torn trailing line from another process is skipped by sync, then consumed once completed', () => {
    const storeA = openStore({ dataDir: dir, backend: 'jsonl' });
    try {
      const seeded = seal([sessionStart(SESSION_A, '2026-06-11T10:00:00.000Z')]);
      storeA.append(seeded);
      expect(storeA.count()).toBe(1);

      // A real, well-formed second record — written byte-for-byte so the
      // "crash" below is a genuine torn line, not just invalid JSON.
      const next = seal(
        [toolCall(SESSION_A, '2026-06-11T10:00:01.000Z', 'partial_write')],
        storeA.head(),
      )[0]!;
      const line = JSON.stringify(next);
      const logPath = join(dir, FILES.JSONL_LOG);
      const half = Math.floor(line.length / 2);

      // Simulate a second process mid-write: half the line lands, no
      // trailing newline yet. storeA is NOT holding the lock (there is no
      // lock on a read), so its sync must tolerate observing this.
      appendFileSync(logPath, line.slice(0, half));
      expect(storeA.count()).toBe(1);
      expect(storeA.head()).toEqual({ seq: 1, hash: seeded[0]!.hash });
      expect([...storeA.iterate()]).toHaveLength(1);
      // Sync again with nothing new on disk: still tolerated, still stable.
      expect(storeA.count()).toBe(1);

      // The "crashed" process's continuation lands, completing the line.
      appendFileSync(logPath, line.slice(half) + '\n');

      expect(storeA.count()).toBe(2);
      expect(storeA.head()).toEqual({ seq: 2, hash: next.hash });
      expect([...storeA.iterate()].map((r) => r.seq)).toEqual([1, 2]);
    } finally {
      storeA.close();
    }
  });

  it('a shrunk file triggers a full reload', () => {
    const storeA = openStore({ dataDir: dir, backend: 'jsonl' });
    try {
      const seeded = twoSessionFixture();
      storeA.append(seeded);
      expect(storeA.count()).toBe(6);

      const logPath = join(dir, FILES.JSONL_LOG);
      const text = readFileSync(logPath, 'utf8');
      const lines = text.split('\n').filter((l) => l.trim() !== '');
      // Simulate the log having been replaced by a shorter one (e.g. a
      // rotation) that keeps only the first two records.
      writeFileSync(logPath, lines.slice(0, 2).join('\n') + '\n');
      expect(statSync(logPath).size).toBeLessThan(text.length);

      jsonlIoStats.fullReloadCalls = 0;
      expect(storeA.count()).toBe(2);
      expect(jsonlIoStats.fullReloadCalls).toBeGreaterThan(0);
      expect(storeA.head()).toEqual({ seq: 2, hash: seeded[1]!.hash });
      expect([...storeA.iterate()].map((r) => r.seq)).toEqual([1, 2]);
    } finally {
      storeA.close();
    }
  });

  it('a grown-but-replaced file (misaligned with the old offset) triggers a full reload', () => {
    const storeA = openStore({ dataDir: dir, backend: 'jsonl' });
    try {
      storeA.append(seal([sessionStart(SESSION_A, '2026-06-11T10:00:00.000Z')]));
      expect(storeA.count()).toBe(1);

      const logPath = join(dir, FILES.JSONL_LOG);
      const original = readFileSync(logPath, 'utf8');
      // Replace with different, larger content shifted by one byte, so the
      // byte at the previous end-of-file no longer marks the start of a
      // line — the cheap "still the same file, just longer" check must
      // catch this even though the file only grew.
      writeFileSync(logPath, ' ' + original + original);

      jsonlIoStats.fullReloadCalls = 0;
      expect(storeA.count()).toBe(2); // full, tolerant reparse of the new content
      expect(jsonlIoStats.fullReloadCalls).toBeGreaterThan(0); // fell back to a full reload
    } finally {
      storeA.close();
    }
  });
});

describe('JsonlStore appendEvents across instances (simulates separate processes)', () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'mcp-recorder-jsonl-xproc-'));
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('two stores appending alternately produce one contiguous, verifiable chain', async () => {
    const SESSION_C = '33333333-3333-4333-8333-333333333333';
    const SESSION_D = '44444444-4444-4444-8444-444444444444';
    const track = (sessionId: string, tag: string): AnyEvent[] => [
      sessionStart(sessionId, '2026-06-11T12:00:00.000Z'),
      toolCall(sessionId, '2026-06-11T12:00:01.000Z', `tool_${tag}`, { requestId: 1 }),
      sessionEnd(sessionId, '2026-06-11T12:00:02.000Z'),
    ];
    const eventsA = track(SESSION_C, 'a');
    const eventsB = track(SESSION_D, 'b');

    // Two independent JsonlStore instances on the same data dir — each one
    // stands in for a separate `mcp-recorder record` process, appending one
    // event at a time so the instances truly interleave on disk.
    const storeA = openStore({ dataDir: dir, backend: 'jsonl' });
    const storeB = openStore({ dataDir: dir, backend: 'jsonl' });
    try {
      for (let i = 0; i < eventsA.length; i++) {
        storeA.appendEvents([eventsA[i]!]);
        storeB.appendEvents([eventsB[i]!]);
      }
    } finally {
      storeA.close();
      storeB.close();
    }

    const verifyOpen = openStore({ dataDir: dir, backend: 'jsonl' });
    try {
      expect(verifyOpen.count()).toBe(6);
      const seqs = [...verifyOpen.iterate()].map((r) => r.seq);
      expect(seqs).toEqual([1, 2, 3, 4, 5, 6]);

      const result = await verifyStore(verifyOpen, { allowUnsigned: true });
      expect(result.problems.filter((p) => p.warning !== true)).toEqual([]);
      expect(result.checked_events).toBe(6);

      const sessions = verifyOpen.sessions();
      expect(sessions).toHaveLength(2);
      for (const s of sessions) {
        expect(s.event_count).toBe(3);
        expect(s.ended_at).toBeDefined();
      }
    } finally {
      verifyOpen.close();
    }
  });
});

/* ----------------------------- factory env ----------------------------- */

describe('openStore backend resolution', () => {
  let dir: string;
  const savedEnv = process.env[ENV.STORE];

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'mcp-recorder-factory-'));
  });

  afterEach(() => {
    if (savedEnv === undefined) delete process.env[ENV.STORE];
    else process.env[ENV.STORE] = savedEnv;
    rmSync(dir, { recursive: true, force: true });
  });

  it(`honors ${ENV.STORE} when no backend is forced`, () => {
    process.env[ENV.STORE] = 'jsonl';
    const store = openStore({ dataDir: dir });
    expect(store.backend).toBe('jsonl');
    store.close();
  });

  it('defaults to sqlite when available', () => {
    delete process.env[ENV.STORE];
    const store = openStore({ dataDir: dir });
    expect(store.backend).toBe(isSqliteAvailable() ? 'sqlite' : 'jsonl');
    store.close();
  });
});

/* ------------------- prefers whichever backend file exists ------------------- */

describe('openStore prefers an already-existing evidence file', () => {
  let dir: string;
  const savedEnv = process.env[ENV.STORE];

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'mcp-recorder-existing-backend-'));
    delete process.env[ENV.STORE];
  });

  afterEach(() => {
    if (savedEnv === undefined) delete process.env[ENV.STORE];
    else process.env[ENV.STORE] = savedEnv;
    rmSync(dir, { recursive: true, force: true });
  });

  it('an existing evidence.jsonl wins over sqlite availability (no backend forced)', () => {
    expect(isSqliteAvailable()).toBe(true); // the interesting case: sqlite IS available

    const seeded = openStore({ dataDir: dir, backend: 'jsonl' });
    seeded.append(seal([sessionStart(SESSION_A, '2026-06-11T10:00:00.000Z')]));
    seeded.close();
    expect(existsSync(join(dir, FILES.JSONL_LOG))).toBe(true);
    expect(existsSync(join(dir, FILES.SQLITE_DB))).toBe(false);

    // No --store, no env: auto-detection must not silently pick sqlite and
    // "lose" the existing jsonl chain.
    const reopened = openStore({ dataDir: dir });
    expect(reopened.backend).toBe('jsonl');
    expect(reopened.count()).toBe(1);
    reopened.close();
    expect(existsSync(join(dir, FILES.SQLITE_DB))).toBe(false);
  });

  it('warns on stderr and prefers sqlite when both evidence files exist', () => {
    const sq = openStore({ dataDir: dir, backend: 'sqlite' });
    sq.append(seal([sessionStart(SESSION_A, '2026-06-11T10:00:00.000Z')]));
    sq.close();
    // A second, independent jsonl file shows up in the same data dir (e.g. a
    // native-module availability flip caused a later run to fall back).
    const jl = openStore({ dataDir: dir, backend: 'jsonl' });
    jl.append(seal([sessionStart(SESSION_B, '2026-06-11T11:00:00.000Z')]));
    jl.close();

    const stderrSpy = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
    try {
      const store = openStore({ dataDir: dir });
      expect(store.backend).toBe('sqlite');
      expect(store.count()).toBe(1); // the sqlite chain's own single event
      expect(
        stderrSpy.mock.calls.some(
          (call) =>
            String(call[0]).includes('both') &&
            String(call[0]).includes(FILES.SQLITE_DB) &&
            String(call[0]).includes(FILES.JSONL_LOG),
        ),
      ).toBe(true);
      store.close();
    } finally {
      stderrSpy.mockRestore();
    }
  });

  it('fails loudly (not a silent jsonl fallback) when evidence.db exists but better-sqlite3 cannot load', async () => {
    const sq = openStore({ dataDir: dir, backend: 'sqlite' });
    sq.append(seal([sessionStart(SESSION_A, '2026-06-11T10:00:00.000Z')]));
    sq.close();

    vi.resetModules();
    vi.doMock('../src/store/sqlite.js', async (importOriginal) => {
      const actual = await importOriginal<typeof import('../src/store/sqlite.js')>();
      return { ...actual, isSqliteAvailable: () => false };
    });
    try {
      const { openStore: openStoreWithMockedSqlite } = await import('../src/store/index.js');
      expect(() => openStoreWithMockedSqlite({ dataDir: dir })).toThrow(
        /evidence\.db exists but better-sqlite3 cannot load/,
      );
      // And it must not have started a second (empty) chain in jsonl instead.
      expect(existsSync(join(dir, FILES.JSONL_LOG))).toBe(false);
    } finally {
      vi.doUnmock('../src/store/sqlite.js');
      vi.resetModules();
    }
  });
});

/* --------------------- openStoreReadOnly: no side-effect files -------------------- */

describe('openStoreReadOnly (used by inspection commands)', () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'mcp-recorder-readonly-'));
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('opening an empty data dir creates no evidence files', () => {
    expect(isSqliteAvailable()).toBe(true); // the case that used to create evidence.db
    const store = openStoreReadOnly({ dataDir: dir });
    expect(store.count()).toBe(0);
    expect(store.sessions()).toEqual([]);
    store.close();
    expect(readdirSync(dir)).toEqual([]);
  });

  it('still opens an existing store normally (no behavior change when data exists)', () => {
    const seeded = openStore({ dataDir: dir, backend: 'jsonl' });
    seeded.append(seal([sessionStart(SESSION_A, '2026-06-11T10:00:00.000Z')]));
    seeded.close();

    const store = openStoreReadOnly({ dataDir: dir });
    expect(store.backend).toBe('jsonl');
    expect(store.count()).toBe(1);
    store.close();
  });
});

describe('data dir hygiene', () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'mcp-recorder-hygiene-'));
  });
  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it.skipIf(process.platform === 'win32')('openStore creates the data dir 0700', () => {
    const dataDir = join(dir, 'fresh');
    const store = openStore({ dataDir, backend: 'jsonl' });
    store.close();
    expect(statSync(dataDir).mode & 0o777).toBe(0o700);
  });

  it('openStoreReadOnly on a dir nothing recorded to creates no files and no directory', () => {
    const dataDir = join(dir, 'never-recorded');
    const store = openStoreReadOnly({ dataDir });
    expect(store.count()).toBe(0);
    expect(store.sessions()).toEqual([]);
    expect([...store.iterate()]).toEqual([]);
    expect(store.latestSignature()).toBeNull();
    expect(() => store.appendEvents([])).toThrow(/read-only/);
    store.close();
    expect(existsSync(dataDir)).toBe(false);
  });

  it('openStoreReadOnly with a forced backend never creates that backend\'s file', () => {
    for (const backend of ['sqlite', 'jsonl'] as const) {
      const store = openStoreReadOnly({ dataDir: dir, backend });
      expect(store.backend).toBe(backend);
      expect(store.count()).toBe(0);
      store.close();
    }
    expect(existsSync(join(dir, FILES.SQLITE_DB))).toBe(false);
    expect(existsSync(join(dir, FILES.JSONL_LOG))).toBe(false);
  });

  it('jsonl: a complete last record that merely lacks its newline is kept, not discarded', async () => {
    const records = twoSessionFixture();
    const store = openStore({ dataDir: dir, backend: 'jsonl' });
    store.append(records);
    store.close();
    const logPath = join(dir, FILES.JSONL_LOG);
    const text = readFileSync(logPath, 'utf8');
    expect(text.endsWith('\n')).toBe(true);
    writeFileSync(logPath, text.slice(0, -1)); // the write was cut at the final byte

    const stderrSpy = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
    try {
      const reopened = openStore({ dataDir: dir, backend: 'jsonl' });
      expect(reopened.count()).toBe(records.length);
      const sealed = reopened.appendEvents([
        toolCall(SESSION_B, '2026-06-11T11:00:09.000Z', 'after_cut_newline'),
      ]);
      expect(sealed[0]!.seq).toBe(records.length + 1);
      reopened.close();
      expect(
        stderrSpy.mock.calls.some((call) => String(call[0]).includes('discarded a torn trailing line')),
      ).toBe(false);
    } finally {
      stderrSpy.mockRestore();
    }
    const third = openStore({ dataDir: dir, backend: 'jsonl' });
    expect(third.count()).toBe(records.length + 1);
    expect((await verifyStore(third, { allowUnsigned: true })).ok).toBe(true);
    third.close();
  });
});

describe('openStoreReadOnly on a data dir it cannot use', () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'mcp-recorder-ro-err-'));
  });
  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('throws when the data dir path is a regular file instead of a directory', () => {
    const notADir = join(dir, 'evidence-file');
    writeFileSync(notADir, 'not a directory');
    expect(() => openStoreReadOnly({ dataDir: notADir })).toThrow(/not a directory/);
  });

  it('still treats a missing dir under a missing parent as nothing recorded', () => {
    const store = openStoreReadOnly({ dataDir: join(dir, 'missing', 'deeper') });
    expect(store.count()).toBe(0);
    expect(existsSync(join(dir, 'missing'))).toBe(false);
  });
});
