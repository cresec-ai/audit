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
    expect(html).toContain(`<code>${APPROVAL_ID}</code>`);
    // args_hash is a traceable ref (blast-radius data-ref), never the args
    expect(html).toContain(`data-ref="${sha256Ref('{"url":"https://evil.example"}')}"`);
    expect(html).not.toContain('evil.example');
  });

  it('tool_call cards carry gw-allow / gw-hold / gw-deny badges and a boundary summary', () => {
    const html = renderTimelineHtml(store, { sessionId: SESSION_C });
    expect(html).toContain('<span class="badge gw gw-deny"');
    expect(html).toContain('<span class="badge gw gw-hold"');
    expect(html).toContain('<span class="badge gw gw-allow"');
    expect(html).toContain('gateway hold · approved');
    expect(html).toContain('redacted 2 secrets · redacted 1 injection marker');
    expect(html).toContain('scanned clean');
    // the redacted secret is findable by the client-side blast search, never readable
    expect(html).toContain(`data-secret-refs="${sha256Ref(BOUNDARY_SECRET)}"`);
    expect(html).not.toContain(BOUNDARY_SECRET);
    expect(html).not.toContain(SECRET);
    expect(html).toContain(`delivered result ${sha256Ref('delivered')}`);
  });

  it('escapes an attacker-shaped rule id everywhere it appears', () => {
    const html = renderTimelineHtml(store, { sessionId: SESSION_C });
    expect(html).not.toContain('<img src=x');
    expect(html).toContain(escapeHtmlLike(EVIL_RULE));
  });

  it('the page still lists every other kind (the new row is additive)', () => {
    const html = renderTimelineHtml(store, { sessionId: SESSION_C });
    for (const tag of ['SESSION START', 'ACT', 'EFFECT', 'POLICY', 'SESSION END']) expect(html).toContain(tag);
    const data = extractEmbeddedJson(html) as EmbeddedData;
    expect(data.events).toHaveLength(7);
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
