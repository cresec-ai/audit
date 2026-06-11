import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { GENESIS_HASH, makeRecord, sha256Ref } from '../src/chain/hash.js';
import { openStore } from '../src/store/index.js';
import { Redactor } from '../src/redact/redactor.js';
import { renderTimelineHtml, MAX_EMBED_EVENTS } from '../src/replay/render.js';
import { serveUi } from '../src/replay/serve.js';
import type { ChainHead, EvidenceStore, VerifyResult } from '../src/types.js';
import type {
  AnyEvent,
  ChainRecord,
  IdentityContext,
  InitializeEvent,
  NotificationEvent,
  ProtocolErrorEvent,
  RpcEvent,
  ServerContext,
  SessionEndEvent,
  SessionStartEvent,
  ToolCallEvent,
} from '../src/schema/events.js';
import { SCHEMA } from '../src/schema/events.js';

/* ------------------------------ fixtures ------------------------------ */

const SECRET = 'sk-test-XYZ-12345678';
const CREDENTIAL = 'ghp_FAKEFAKEFAKEFAKEFAKE12';
const EVIL_TOOL = 'x<script>alert(1)</script>';

const SESSION_A = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const SESSION_B = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';

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
  credential_fingerprints: [{ name: 'GITHUB_TOKEN', ref: sha256Ref(CREDENTIAL) }],
};

const SERVER: ServerContext = {
  name: 'github-mcp',
  version: '2.1.0',
  command: 'npx -y @modelcontextprotocol/server-github',
  transport: 'stdio',
};

function base(sessionId: string, timestamp: string) {
  return {
    schema: SCHEMA,
    event_id: fakeUuid(),
    session_id: sessionId,
    timestamp,
    identity: IDENTITY,
    server: SERVER,
    attributes: {},
  } as const;
}

function sessionStart(sessionId: string, timestamp: string): SessionStartEvent {
  return {
    ...base(sessionId, timestamp),
    kind: 'session_start',
    proxy_version: '0.1.0',
    cwd: '/home/jonirap/project',
    redaction_mode: 'allowlist',
  };
}

function initialize(sessionId: string, timestamp: string): InitializeEvent {
  return {
    ...base(sessionId, timestamp),
    kind: 'initialize',
    request_id: 0,
    protocol_version: '2025-03-26',
    client_name: 'claude-code',
    client_version: '1.2.3',
    server_name: 'github-mcp',
    server_version: '2.1.0',
    duration_ms: 8,
  };
}

function toolCall(
  sessionId: string,
  timestamp: string,
  tool: string,
  rawArgs: unknown,
  opts: { isError?: boolean } = {},
): ToolCallEvent {
  const redactor = new Redactor();
  const isError = opts.isError ?? false;
  const event: ToolCallEvent = {
    ...base(sessionId, timestamp),
    kind: 'tool_call',
    attributes: { 'gen_ai.operation.name': 'execute_tool', 'gen_ai.tool.name': tool },
    tool,
    request_id: 1,
    args: redactor.scrub(rawArgs),
    result_hash: sha256Ref('{"ok":true}'),
    result: redactor.scrub({ content: [{ type: 'text', text: 'done' }] }),
    is_error: isError,
    duration_ms: 12.5,
  };
  if (isError) event.error = { code: -32000, type: 'ToolError', message_ref: sha256Ref('boom') };
  return event;
}

function rpc(sessionId: string, timestamp: string): RpcEvent {
  return {
    ...base(sessionId, timestamp),
    kind: 'rpc',
    method: 'tools/list',
    request_id: 2,
    params: {},
    result_hash: sha256Ref('{"tools":[]}'),
    is_error: false,
    duration_ms: 1.5,
  };
}

function notification(sessionId: string, timestamp: string): NotificationEvent {
  return {
    ...base(sessionId, timestamp),
    kind: 'notification',
    method: 'notifications/progress',
    direction: 'server_to_client',
    params: {},
  };
}

function protocolError(sessionId: string, timestamp: string): ProtocolErrorEvent {
  return {
    ...base(sessionId, timestamp),
    kind: 'protocol_error',
    direction: 'server_to_client',
    reason: 'unparseable',
    bytes_len: 132,
    line_hash: sha256Ref('not json at all'),
  };
}

function sessionEnd(sessionId: string, timestamp: string): SessionEndEvent {
  return {
    ...base(sessionId, timestamp),
    kind: 'session_end',
    reason: 'child_exit',
    child_exit_code: 0,
    events_recorded: 6,
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

function extractEmbeddedJson(html: string): unknown {
  const m = html.match(
    /<script type="application\/json" id="evidence-data">([\s\S]*?)<\/script>/,
  );
  expect(m).not.toBeNull();
  return JSON.parse(m![1]!);
}

interface EmbeddedData {
  truncated: boolean;
  sessions: Array<{ session_id: string }>;
  events: ChainRecord[];
}

/* -------------------------------- suite -------------------------------- */

describe('renderTimelineHtml', () => {
  let dir: string;
  let store: EvidenceStore;
  const totalEvents = 9;

  beforeAll(() => {
    dir = mkdtempSync(join(tmpdir(), 'mcp-recorder-replay-'));
    store = openStore({ dataDir: dir, backend: 'sqlite' });
    store.append(
      seal([
        sessionStart(SESSION_A, '2026-06-11T10:00:00.000Z'),
        initialize(SESSION_A, '2026-06-11T10:00:00.100Z'),
        toolCall(SESSION_A, '2026-06-11T10:00:01.000Z', 'create_issue', { api_key: SECRET }),
        rpc(SESSION_A, '2026-06-11T10:00:02.000Z'),
        notification(SESSION_A, '2026-06-11T10:00:03.000Z'),
        protocolError(SESSION_A, '2026-06-11T10:00:04.000Z'),
        sessionEnd(SESSION_A, '2026-06-11T10:00:05.000Z'),
        sessionStart(SESSION_B, '2026-06-11T11:00:00.000Z'),
        toolCall(SESSION_B, '2026-06-11T11:00:01.000Z', EVIL_TOOL, { q: 'x' }, { isError: true }),
      ]),
    );
  });

  afterAll(() => {
    store.close();
    rmSync(dir, { recursive: true, force: true });
  });

  it('renders a self-contained page with header, sessions, and tool names', () => {
    const html = renderTimelineHtml(store);
    expect(html).toContain('mcp-recorder — evidence replay');
    expect(html).toContain('evidence.db');
    expect(html).toContain(SESSION_A);
    expect(html).toContain(SESSION_B);
    expect(html).toContain('create_issue');
    // every event kind got a card/row
    for (const tag of ['SESSION START', 'SEE', 'ACT', 'EFFECT', 'RPC', 'NOTIFY', 'PROTOCOL', 'SESSION END']) {
      expect(html).toContain(tag);
    }
    // no external requests: no http(s) URLs in src/href attributes
    expect(html).not.toMatch(/(?:src|href)="https?:\/\//);
  });

  it('shows lock chips for redacted refs and never the raw secret', () => {
    const html = renderTimelineHtml(store);
    const ref = sha256Ref(SECRET);
    expect(html).toContain(`data-ref="${ref}"`);
    // short display form: sha256:<first 8 hex>…
    expect(html).toContain('sha256:' + ref.slice('sha256:'.length, 'sha256:'.length + 8));
    expect(html).toContain(`title="${ref} (len ${SECRET.length})"`);
    // the planted raw values must be absent
    expect(html).not.toContain(SECRET);
    expect(html).not.toContain(CREDENTIAL);
    // credential fingerprints render as chips too
    expect(html).toContain(`data-ref="${sha256Ref(CREDENTIAL)}"`);
  });

  it('escapes attacker-controlled strings (tool name script injection)', () => {
    const html = renderTimelineHtml(store);
    expect(html).not.toContain('<script>alert');
    expect(html).toContain('&lt;script&gt;alert(1)&lt;/script&gt;');
  });

  it('embeds parseable JSON that round-trips the events', () => {
    const html = renderTimelineHtml(store);
    const data = extractEmbeddedJson(html) as EmbeddedData;
    expect(data.truncated).toBe(false);
    expect(data.events).toHaveLength(totalEvents);
    expect(data.sessions.map((s) => s.session_id)).toEqual([SESSION_A, SESSION_B]);
    const evil = data.events.find(
      (r) => r.event.kind === 'tool_call' && r.event.tool === EVIL_TOOL,
    );
    expect(evil).toBeDefined();
    // the blob itself never contains a raw '<'
    const blob = html.match(
      /<script type="application\/json" id="evidence-data">([\s\S]*?)<\/script>/,
    )![1]!;
    expect(blob).not.toContain('<');
  });

  it('renders a single session when sessionId is given', () => {
    const html = renderTimelineHtml(store, { sessionId: SESSION_A });
    expect(html).toContain(SESSION_A);
    expect(html).not.toContain(SESSION_B);
    const data = extractEmbeddedJson(html) as EmbeddedData;
    expect(data.events).toHaveLength(7);
    expect(data.events.every((r) => r.event.session_id === SESSION_A)).toBe(true);
  });

  it('renders a notice for an unknown session', () => {
    const html = renderTimelineHtml(store, { sessionId: 'no-such-session' });
    expect(html).toContain('No events recorded for session');
  });

  it('shows a green integrity banner for a passing verify', () => {
    const head = store.head();
    const verify: VerifyResult = {
      ok: true,
      checked_events: totalEvents,
      head,
      problems: [],
      verified_signature: {
        seq: head.seq,
        chain_hash: head.hash,
        algo: 'ed25519',
        public_key: 'ab'.repeat(32),
        signature: 'cd'.repeat(64),
        signed_at: '2026-06-11T11:00:02.000Z',
      },
    };
    const html = renderTimelineHtml(store, { verify });
    expect(html).toContain('chain intact');
    expect(html).toContain(`${totalEvents} events`);
    expect(html).toContain('ab'.repeat(8)); // short pubkey (first 16 hex)
    expect(html).toContain('2026-06-11T11:00:02.000Z');
  });

  it('shows a red banner listing problems for a failing verify', () => {
    const verify: VerifyResult = {
      ok: false,
      checked_events: totalEvents,
      head: store.head(),
      problems: [
        { type: 'hash_mismatch', seq: 3, detail: 'record 3 was altered after sealing' },
      ],
    };
    const html = renderTimelineHtml(store, { verify });
    expect(html).toContain('FAILED');
    expect(html).toContain('hash_mismatch');
    expect(html).toContain('record 3 was altered after sealing');
  });

  it('includes the offline blast-radius box', () => {
    const html = renderTimelineHtml(store);
    expect(html).toContain('id="blast-form"');
    expect(html).toContain('id="blast-input"');
    expect(html).toContain('crypto.subtle.digest');
    expect(html).toContain('data-result-hash');
  });
});

describe('renderTimelineHtml truncation cap', () => {
  it(`caps embedded events at ${MAX_EMBED_EVENTS} with a visible notice`, () => {
    const dir = mkdtempSync(join(tmpdir(), 'mcp-recorder-replay-cap-'));
    const store = openStore({ dataDir: dir, backend: 'sqlite' });
    try {
      const events: AnyEvent[] = [sessionStart(SESSION_A, '2026-06-11T10:00:00.000Z')];
      for (let i = 0; i < MAX_EMBED_EVENTS + 100; i++) {
        events.push(notification(SESSION_A, '2026-06-11T10:00:01.000Z'));
      }
      store.append(seal(events));

      const html = renderTimelineHtml(store);
      expect(html).toContain('truncated');
      const data = extractEmbeddedJson(html) as EmbeddedData;
      expect(data.truncated).toBe(true);
      expect(data.events).toHaveLength(MAX_EMBED_EVENTS);
    } finally {
      store.close();
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('serveUi', () => {
  let dir: string;
  let store: EvidenceStore;

  beforeAll(() => {
    dir = mkdtempSync(join(tmpdir(), 'mcp-recorder-serve-'));
    store = openStore({ dataDir: dir, backend: 'sqlite' });
    store.append(
      seal([
        sessionStart(SESSION_A, '2026-06-11T10:00:00.000Z'),
        toolCall(SESSION_A, '2026-06-11T10:00:01.000Z', 'create_issue', { api_key: SECRET }),
        sessionEnd(SESSION_A, '2026-06-11T10:00:02.000Z'),
        sessionStart(SESSION_B, '2026-06-11T11:00:00.000Z'),
        toolCall(SESSION_B, '2026-06-11T11:00:01.000Z', 'send_email', { to: 'x' }),
      ]),
    );
  });

  afterAll(() => {
    store.close();
    rmSync(dir, { recursive: true, force: true });
  });

  it('serves the picker, per-session pages, and healthz on an ephemeral port', async () => {
    const handle = await serveUi({ store, port: 0 });
    try {
      expect(handle.port).toBeGreaterThan(0);
      expect(handle.url).toBe(`http://127.0.0.1:${handle.port}/`);

      const root = await fetch(handle.url);
      expect(root.status).toBe(200);
      expect(root.headers.get('content-type')).toContain('text/html');
      const rootHtml = await root.text();
      expect(rootHtml).toContain('mcp-recorder — evidence replay');
      expect(rootHtml).toContain(SESSION_A);
      expect(rootHtml).toContain(SESSION_B);

      const sessionRes = await fetch(`${handle.url}?session=${SESSION_A}`);
      expect(sessionRes.status).toBe(200);
      const sessionHtml = await sessionRes.text();
      expect(sessionHtml).toContain(SESSION_A);
      expect(sessionHtml).toContain('create_issue');
      expect(sessionHtml).not.toContain(SESSION_B);
      expect(sessionHtml).not.toContain(SECRET);

      const health = await fetch(`${handle.url}healthz`);
      expect(health.status).toBe(200);
      expect(await health.text()).toBe('ok');

      const missing = await fetch(`${handle.url}does-not-exist`);
      expect(missing.status).toBe(404);

      const post = await fetch(handle.url, { method: 'POST', body: 'nope' });
      expect(post.status).toBe(405);
    } finally {
      await handle.close();
    }
    // socket is really gone after close()
    await expect(fetch(handle.url)).rejects.toThrow();
  });

  it('uses opts.sessionId as the default page for GET /', async () => {
    const handle = await serveUi({ store, sessionId: SESSION_B });
    try {
      const res = await fetch(handle.url);
      expect(res.status).toBe(200);
      const html = await res.text();
      expect(html).toContain(SESSION_B);
      expect(html).toContain('send_email');
      expect(html).not.toContain(SESSION_A);
    } finally {
      await handle.close();
    }
  });

  it('close() resolves cleanly and is safe to await', async () => {
    const handle = await serveUi({ store });
    await expect(handle.close()).resolves.toBeUndefined();
  });
});
