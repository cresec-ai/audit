import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { GENESIS_HASH, makeRecord, sha256Ref } from '../src/chain/hash.js';
import { openStore } from '../src/store/index.js';
import { Redactor } from '../src/redact/redactor.js';
import { queryStore } from '../src/query/touched.js';
import type { ChainHead, EvidenceStore } from '../src/types.js';
import type {
  AnyEvent,
  ChainRecord,
  IdentityContext,
  ServerContext,
  SessionEndEvent,
  SessionStartEvent,
  ToolCallEvent,
} from '../src/schema/events.js';
import { SCHEMA } from '../src/schema/events.js';

/* ------------------------------ fixtures ------------------------------ */

const SECRET = 'sk-test-XYZ-12345678';
const CREDENTIAL = 'ghp_FAKEFAKEFAKEFAKEFAKE12';
const RAW_RESULT = '{"content":[{"text":"issue created","type":"text"}]}';

const SESSION_A = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'; // older
const SESSION_B = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'; // newer

let eventCounter = 0;
function fakeUuid(): string {
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

const IDENTITY_WITH_CRED: IdentityContext = {
  ...IDENTITY,
  credential_fingerprints: [{ name: 'GITHUB_TOKEN', ref: sha256Ref(CREDENTIAL) }],
};

const SERVER: ServerContext = {
  name: 'github-mcp',
  version: '2.1.0',
  command: 'npx -y @modelcontextprotocol/server-github',
  transport: 'stdio',
};

function sessionStart(
  sessionId: string,
  timestamp: string,
  identity: IdentityContext,
): SessionStartEvent {
  return {
    schema: SCHEMA,
    event_id: fakeUuid(),
    session_id: sessionId,
    timestamp,
    kind: 'session_start',
    identity,
    server: SERVER,
    attributes: {},
    proxy_version: '0.1.0',
    cwd: '/home/jonirap/project',
    redaction_mode: 'allowlist',
  };
}

function toolCall(
  sessionId: string,
  timestamp: string,
  tool: string,
  rawArgs: unknown,
): ToolCallEvent {
  const redactor = new Redactor();
  return {
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
    },
    tool,
    request_id: 1,
    args: redactor.scrub(rawArgs),
    result_hash: sha256Ref(RAW_RESULT),
    result: redactor.scrub(JSON.parse(RAW_RESULT)),
    is_error: false,
    duration_ms: 4.2,
  };
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
    events_recorded: 3,
    events_dropped: 0,
  };
}

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

/* -------------------------------- suite -------------------------------- */

describe('queryStore (blast radius)', () => {
  let dir: string;
  let store: EvidenceStore;

  beforeAll(() => {
    dir = mkdtempSync(join(tmpdir(), 'mcp-recorder-query-'));
    store = openStore({ dataDir: dir, backend: 'sqlite' });
    store.append(
      seal([
        // Session A (older): credential fingerprint on its session_start,
        // a tool call whose args contain the planted secret.
        sessionStart(SESSION_A, '2026-06-11T10:00:00.000Z', IDENTITY_WITH_CRED),
        toolCall(SESSION_A, '2026-06-11T10:00:01.000Z', 'create_issue', {
          api_key: SECRET,
          // Vocabulary-passing structural value (P0: bare `name` no longer
          // passes anywhere under tool_call.args) — still a 'plain' probe.
          mimeType: 'text/x-probe-target',
          title: 'hello world',
        }),
        sessionEnd(SESSION_A, '2026-06-11T10:00:02.000Z'),
        // Session B (newer): the same secret leaks into a second tool call.
        // (The leaf must be exactly the secret — refs hash whole leaves.)
        sessionStart(SESSION_B, '2026-06-11T11:00:00.000Z', IDENTITY),
        toolCall(SESSION_B, '2026-06-11T11:00:01.000Z', 'send_email', {
          token: SECRET,
          subject: 'rotation',
        }),
      ]),
    );
  });

  afterAll(() => {
    store.close();
    rmSync(dir, { recursive: true, force: true });
  });

  it('finds a planted secret via RedactedRef with a sensible path', () => {
    const result = queryStore(store, SECRET);

    expect(result.needle_hash).toBe(sha256Ref(SECRET));
    expect(result.matches).toHaveLength(2);

    const [first, second] = result.matches;
    expect(first).toMatchObject({
      seq: 2,
      session_id: SESSION_A,
      kind: 'tool_call',
      name: 'create_issue',
      matched_on: 'ref',
      path: '$.args.api_key',
    });
    expect(second).toMatchObject({
      seq: 5,
      session_id: SESSION_B,
      kind: 'tool_call',
      name: 'send_email',
      matched_on: 'ref',
      path: '$.args.token',
    });
    expect(first!.timestamp).toBe('2026-06-11T10:00:01.000Z');
  });

  it('lists touched sessions newest first', () => {
    const result = queryStore(store, SECRET);
    expect(result.sessions.map((s) => s.session_id)).toEqual([SESSION_B, SESSION_A]);
    const a = result.sessions[1]!;
    expect(a.server_name).toBe('github-mcp');
    expect(a.tool_call_count).toBe(1);
  });

  it('matches a credential value via identity fingerprints', () => {
    const result = queryStore(store, CREDENTIAL);
    expect(result.matches).toHaveLength(1);
    expect(result.matches[0]).toMatchObject({
      seq: 1,
      session_id: SESSION_A,
      kind: 'session_start',
      matched_on: 'credential',
      path: '$.identity.credential_fingerprints[0].ref',
    });
    expect(result.matches[0]!.name).toBeUndefined();
    expect(result.sessions.map((s) => s.session_id)).toEqual([SESSION_A]);
  });

  it('matches a tool name as name (not plain), case-insensitively', () => {
    const exact = queryStore(store, 'create_issue');
    expect(exact.matches).toHaveLength(1);
    expect(exact.matches[0]).toMatchObject({
      seq: 2,
      matched_on: 'name',
      path: '$.tool',
      name: 'create_issue',
    });

    const upper = queryStore(store, 'CREATE_ISSUE');
    expect(upper.matches).toHaveLength(1);
    expect(upper.matches[0]!.matched_on).toBe('name');
  });

  it('matches the server name on every event of every session', () => {
    const result = queryStore(store, 'github-mcp');
    expect(result.matches).toHaveLength(store.count());
    expect(result.matches.every((m) => m.matched_on === 'name')).toBe(true);
    expect(result.matches.every((m) => m.path === '$.server.name')).toBe(true);
  });

  it('matches an allow-listed plain string leaf as plain', () => {
    const result = queryStore(store, 'x-probe-target');
    expect(result.matches).toHaveLength(1);
    expect(result.matches[0]).toMatchObject({
      seq: 2,
      matched_on: 'plain',
      path: '$.args.mimeType',
    });

    // case-sensitive substring semantics
    expect(queryStore(store, 'probe-targ').matches).toHaveLength(1);
    expect(queryStore(store, 'PROBE-TARGET').matches).toHaveLength(0);
  });

  it('matches the raw result preimage via result_hash', () => {
    const result = queryStore(store, RAW_RESULT);
    expect(result.matches.length).toBeGreaterThanOrEqual(1);
    expect(result.matches[0]).toMatchObject({
      seq: 2,
      matched_on: 'result_hash',
      path: '$.result_hash',
    });
  });

  it('returns nothing for a value that never crossed the proxy', () => {
    const result = queryStore(store, 'zzz-never-seen-anywhere-zzz');
    expect(result.matches).toEqual([]);
    expect(result.sessions).toEqual([]);
    expect(result.needle_hash).toBe(sha256Ref('zzz-never-seen-anywhere-zzz'));
  });

  it('honors the sessionId filter', () => {
    const result = queryStore(store, SECRET, { sessionId: SESSION_A });
    expect(result.matches).toHaveLength(1);
    expect(result.matches[0]!.session_id).toBe(SESSION_A);
    expect(result.sessions.map((s) => s.session_id)).toEqual([SESSION_A]);
  });

  it('an empty needle matches nothing', () => {
    const result = queryStore(store, '');
    expect(result.matches).toEqual([]);
    expect(result.sessions).toEqual([]);
  });
});

/* --------------------- hashed keys & secret_refs (P1) -------------------- */

describe('queryStore finds needles hashed as KEYS or embedded via secret_refs', () => {
  const EMAIL_KEY = 'alice@corp.example.com';
  const EMBEDDED_AWS = 'AKIAIOSFODNN7EXAMPLE';
  const SESSION_C = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';

  let dir: string;
  let store: EvidenceStore;

  beforeAll(() => {
    dir = mkdtempSync(join(tmpdir(), 'mcp-recorder-query-keys-'));
    store = openStore({ dataDir: dir, backend: 'sqlite' });
    store.append(
      seal([
        sessionStart(SESSION_C, '2026-06-12T09:00:00.000Z', IDENTITY),
        // The needle appears ONLY as an object key (P1 key redaction) — a
        // map keyed by email, never as a value leaf anywhere in the tree.
        toolCall(SESSION_C, '2026-06-12T09:00:01.000Z', 'list_users', {
          users: { [EMAIL_KEY]: { role: 'admin' } },
        }),
        // The needle appears embedded INSIDE a larger leaf, not as a whole
        // leaf by itself (P1 blast-radius miss / secret_refs).
        toolCall(SESSION_C, '2026-06-12T09:00:02.000Z', 'http_post', {
          body: `AWS_ACCESS_KEY_ID=${EMBEDDED_AWS}\nregion=us-east-1\n`,
        }),
        sessionEnd(SESSION_C, '2026-06-12T09:00:03.000Z'),
      ]),
    );
  });

  afterAll(() => {
    store.close();
    rmSync(dir, { recursive: true, force: true });
  });

  it('finds a needle that was only ever used as an object key', () => {
    const result = queryStore(store, EMAIL_KEY);
    expect(result.matches).toHaveLength(1);
    expect(result.matches[0]).toMatchObject({
      seq: 2,
      kind: 'tool_call',
      name: 'list_users',
      matched_on: 'ref',
    });
    // the path marks it as a key hit, not a value leaf.
    expect(result.matches[0]!.path).toContain('#key');
  });

  it('finds a secret embedded inside a larger leaf via secret_refs', () => {
    const result = queryStore(store, EMBEDDED_AWS);
    expect(result.matches).toHaveLength(1);
    expect(result.matches[0]).toMatchObject({
      seq: 3,
      kind: 'tool_call',
      name: 'http_post',
      matched_on: 'ref',
    });
    expect(result.matches[0]!.path).toContain('secret_refs');
  });
});
