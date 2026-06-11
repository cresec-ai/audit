import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { appendFileSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createRequire } from 'node:module';
import { GENESIS_HASH, computeHash, makeRecord, sha256Hex, sha256Ref } from '../src/chain/hash.js';
import { openStore, isSqliteAvailable } from '../src/store/index.js';
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

  it('ignores a truncated final line with a stderr warning', () => {
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
      reopened.close();
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
