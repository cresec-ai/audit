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
  HoldOutcome,
  IdentityContext,
  PolicyDecisionEvent,
  NotificationEvent,
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

/** Two realistic proxy-captured sessions: A is complete (with one failed call), B is still open. */
function twoSessionEvents(): AnyEvent[] {
  return [
    sessionStart(SESSION_A, '2026-06-11T10:00:00.000Z'),
    toolCall(SESSION_A, '2026-06-11T10:00:01.000Z', 'list_issues', { requestId: 1 }),
    toolCall(SESSION_A, '2026-06-11T10:00:02.000Z', 'create_issue', {
      requestId: 2,
      isError: true,
    }),
    sessionEnd(SESSION_A, '2026-06-11T10:00:03.000Z'),
    sessionStart(SESSION_B, '2026-06-11T11:00:00.000Z'),
    toolCall(SESSION_B, '2026-06-11T11:00:01.000Z', 'get_file_contents', { requestId: 1 }),
  ];
}

function twoSessionFixture(): ChainRecord[] {
  return seal(twoSessionEvents());
}

/* ----------------------- hook-captured session fixture ----------------------- */

/** One Claude Code session (keyed by Claude Code's own session_id) as `mcp-recorder hook` records it. */
const SESSION_HOOK = '33333333-3333-4333-8333-333333333333';

function hookServer(name: string): ServerContext {
  return { name, command: 'hook:claude-code', transport: 'stdio' };
}

/**
 * A hook-sourced tool_call: one `pre` event per call, plus a `post` event
 * sharing its request_id only when the tool ran to completion — the exact
 * shape src/hook/run.ts records (`source: 'hook'`, `phase`, the MCP server
 * split out of `mcp__<server>__<tool>` onto server.name).
 */
function hookToolCall(
  timestamp: string,
  server: string,
  tool: string,
  requestId: string,
  phase: 'pre' | 'post',
  opts: { isError?: boolean; errorType?: string } = {},
): ToolCallEvent {
  const isError = opts.isError ?? false;
  const event: ToolCallEvent = {
    schema: SCHEMA,
    event_id: fakeUuid(),
    session_id: SESSION_HOOK,
    timestamp,
    kind: 'tool_call',
    identity: IDENTITY,
    server: hookServer(server),
    attributes: {
      'gen_ai.operation.name': 'execute_tool',
      'gen_ai.tool.name': tool,
      'gen_ai.tool.call.id': requestId,
      'mcp.method.name': 'tools/call',
      'rpc.system': 'hook',
    },
    source: 'hook',
    tool,
    request_id: requestId,
    args: { task_id: { redacted: true, ref: sha256Ref('abc123'), len: 6 } },
    result_hash: sha256Ref(phase === 'pre' ? 'null' : '{"ok":true}'),
    result:
      phase === 'pre'
        ? null
        : { content: [{ type: 'text', text: { redacted: true, ref: sha256Ref('result body'), len: 11 } }] },
    is_error: isError,
    duration_ms: phase === 'pre' ? 0 : 1164,
    phase,
  };
  if (isError) {
    event.error = { type: opts.errorType ?? 'tool_error', message_ref: sha256Ref('boom') };
  }
  return event;
}

/** The `Stop` turn boundary: a notification, not a second session_end. */
function hookStop(timestamp: string): NotificationEvent {
  return {
    schema: SCHEMA,
    event_id: fakeUuid(),
    session_id: SESSION_HOOK,
    timestamp,
    kind: 'notification',
    identity: IDENTITY,
    server: hookServer('claude-code'),
    attributes: { 'mcp.method.name': 'claude-code/stop', 'rpc.system': 'hook' },
    source: 'hook',
    method: 'claude-code/stop',
    direction: 'client_to_server',
    params: { stop_hook_active: false },
  };
}

/**
 * Modelled on cloud dogfood 3: one Claude Code session whose tool calls
 * went to two hosted connectors and one local server. Five CALLS in eight
 * tool_call events —
 *   1. ClickUp get_workspace_hierarchy: pre + post (completed)
 *   2. ClickUp get_list:               pre only (the connector errored and
 *                                      PostToolUse never fired)
 *   3. github pull_request_read:       pre + post with is_error (failing post)
 *   4. ClickUp delete_task:            pre denied by policy (is_error, no post)
 *   5. corp-notes list_notes:          pre + post (completed)
 * — so a correct summary reads 5 calls, 2 errors, and 3 distinct servers
 * called (ClickUp, github, corp-notes; the claude-code session-level events
 * are not a server the session called).
 */
function hookSessionEvents(): AnyEvent[] {
  const t = (s: number) => `2026-09-15T21:02:${String(s).padStart(2, '0')}.000Z`;
  return [
    { ...sessionStart(SESSION_HOOK, t(0)), server: hookServer('claude-code'), source: 'hook' },
    hookToolCall(t(1), 'ClickUp', 'clickup_get_workspace_hierarchy', 'toolu_1', 'pre'),
    hookToolCall(t(2), 'ClickUp', 'clickup_get_workspace_hierarchy', 'toolu_1', 'post'),
    hookToolCall(t(3), 'ClickUp', 'clickup_get_list', 'toolu_2', 'pre'),
    hookToolCall(t(4), 'github', 'pull_request_read', 'toolu_3', 'pre'),
    hookToolCall(t(5), 'github', 'pull_request_read', 'toolu_3', 'post', { isError: true }),
    hookToolCall(t(6), 'ClickUp', 'clickup_delete_task', 'toolu_4', 'pre', {
      isError: true,
      errorType: 'policy_denied',
    }),
    hookToolCall(t(7), 'corp-notes', 'list_notes', 'toolu_5', 'pre'),
    hookToolCall(t(8), 'corp-notes', 'list_notes', 'toolu_5', 'post'),
    hookStop(t(9)),
  ];
}

/* --- Gateway mode (additive v1): a denied call is a tool_call with is_error
 * + error.type policy_denied, preceded by a policy_decision event that
 * carries NO top-level is_error. */
const SESSION_G = '33333333-3333-4333-8333-333333333333';

function policyDecision(sessionId: string, timestamp: string, requestId: number): PolicyDecisionEvent {
  return {
    schema: SCHEMA,
    event_id: fakeUuid(),
    session_id: sessionId,
    timestamp,
    kind: 'policy_decision',
    identity: IDENTITY,
    server: SERVER,
    attributes: { 'gen_ai.tool.name': 'http_post', 'cresec.policy.decision': 'deny', 'cresec.policy.rule_id': 'no-exfil' },
    decision: 'deny',
    tool: 'http_post',
    request_id: requestId,
    rule_id: 'no-exfil',
    policy_hash: sha256Ref('policy bytes'),
    args_hash: sha256Ref('{"url":"https://evil.example"}'),
  };
}

/**
 * A hold the proxy resolved: one policy_decision per OUTCOME, whatever the
 * outcome was — an approved hold is an enforcement action the gateway took
 * just as much as a denied one, and is recorded the same way.
 */
function holdDecision(
  sessionId: string,
  timestamp: string,
  requestId: number,
  outcome: HoldOutcome,
): PolicyDecisionEvent {
  const ev: PolicyDecisionEvent = {
    ...policyDecision(sessionId, timestamp, requestId),
    decision: 'hold',
    outcome,
    tool: 'send_mail',
    rule_id: 'needs-human',
    approval_id: `a1b2c3d4-0000-4000-8000-${String(requestId).padStart(12, '0')}`,
    waited_ms: 1500,
  };
  ev.attributes = {
    ...ev.attributes,
    'gen_ai.tool.name': 'send_mail',
    'cresec.policy.decision': 'hold',
    'cresec.policy.rule_id': 'needs-human',
  };
  if (outcome === 'approved') ev.approver = 'alice';
  return ev;
}

function deniedToolCall(
  sessionId: string,
  timestamp: string,
  requestId: number,
  tool = 'http_post',
): ToolCallEvent {
  const ev = toolCall(sessionId, timestamp, tool, { isError: true, requestId });
  ev.error = { type: 'policy_denied' };
  ev.attributes['error.type'] = 'policy_denied';
  ev.gateway = { decision: 'deny', rule_id: 'no-exfil' };
  return ev;
}

/** One gateway session: an allowed call, a denied call (decision + synthetic tool_call), a held-then-approved call. */
function gatewaySessionFixture(): ChainRecord[] {
  const allowed = toolCall(SESSION_G, '2026-06-11T12:00:01.000Z', 'read_note', { requestId: 1 });
  allowed.gateway = { decision: 'allow', boundary: { scanned: true, action: 'none', secrets_found: 0, injection_found: 0 } };
  const approvedDecision: PolicyDecisionEvent = {
    ...policyDecision(SESSION_G, '2026-06-11T12:00:03.000Z', 3),
    decision: 'hold',
    outcome: 'approved',
    tool: 'send_mail',
    rule_id: 'needs-human',
    approval_id: 'a1b2c3d4-0000-4000-8000-000000000000',
    waited_ms: 1500,
    approver: 'alice',
  };
  const approved = toolCall(SESSION_G, '2026-06-11T12:00:04.000Z', 'send_mail', { requestId: 3 });
  approved.gateway = {
    decision: 'hold',
    rule_id: 'needs-human',
    outcome: 'approved',
    approval_id: 'a1b2c3d4-0000-4000-8000-000000000000',
    waited_ms: 1500,
    boundary: { scanned: true, action: 'redact', secrets_found: 1, injection_found: 0, secret_refs: [sha256Ref('AKIAIOSFODNN7EXAMPLE')], delivered_result_hash: sha256Ref('delivered') },
  };
  const start = sessionStart(SESSION_G, '2026-06-11T12:00:00.000Z');
  start.policy = { hash: sha256Ref('policy bytes'), name: 'laptop' };
  return seal([
    start,
    allowed,
    policyDecision(SESSION_G, '2026-06-11T12:00:02.000Z', 2),
    deniedToolCall(SESSION_G, '2026-06-11T12:00:02.001Z', 2),
    approvedDecision,
    approved,
    sessionEnd(SESSION_G, '2026-06-11T12:00:05.000Z'),
  ]);
}

/* --- Gateway enforcement as `sessions` reports it: sessions that differ
 * only in what the gateway denied, held or let through. */
const SESSION_DENY_ONLY = '77777777-7777-4777-8777-777777777777';
const SESSION_HOLDS = '88888888-8888-4888-8888-888888888888';
const SESSION_POLICY_MIX = '99999999-9999-4999-8999-999999999999';
const SESSION_NO_ENFORCEMENT = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const SESSION_ODD_POLICY = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const SESSION_NOTIFICATION_DENY = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';

/**
 * Five sessions recorded in gateway mode, interleaved in one chain the way
 * concurrent `record` wrappers share a data dir: denies only, resolved
 * holds (one of them APPROVED — the call ran, the gateway still ruled on
 * it), a mix of allow + deny + hold, one where the gateway refused nothing
 * at all, and one whose policy_decision records are malformed.
 */
function enforcementSessionEvents(): AnyEvent[] {
  const at = (hour: number, second: number): string =>
    `2026-06-12T${String(hour).padStart(2, '0')}:00:${String(second).padStart(2, '0')}.000Z`;
  /** Allowed: forwarded and boundary-filtered, and NOT a policy_decision. */
  const allowed = (sessionId: string, timestamp: string, requestId: number): ToolCallEvent => {
    const ev = toolCall(sessionId, timestamp, 'read_note', { requestId });
    ev.gateway = {
      decision: 'allow',
      boundary: { scanned: true, action: 'none', secrets_found: 0, injection_found: 0 },
    };
    return ev;
  };
  /** A deny: the decision, then the synthetic tool_call the client was handed. */
  const denied = (sessionId: string, hour: number, second: number, id: number): AnyEvent[] => [
    policyDecision(sessionId, at(hour, second), id),
    deniedToolCall(sessionId, at(hour, second + 1), id),
  ];
  /** A resolved hold: the decision, then the call — forwarded iff approved. */
  const held = (
    sessionId: string,
    hour: number,
    second: number,
    id: number,
    outcome: HoldOutcome,
  ): AnyEvent[] => {
    const decision = holdDecision(sessionId, at(hour, second), id, outcome);
    const call =
      outcome === 'approved'
        ? toolCall(sessionId, at(hour, second + 1), 'send_mail', { requestId: id })
        : deniedToolCall(sessionId, at(hour, second + 1), id, 'send_mail');
    call.gateway = {
      decision: 'hold',
      rule_id: 'needs-human',
      outcome,
      approval_id: decision.approval_id!,
      waited_ms: 1500,
    };
    return [decision, call];
  };
  /** A policy_decision bent into a shape no writer of ours produces. */
  const odd = (
    base: PolicyDecisionEvent,
    drop: Array<keyof PolicyDecisionEvent>,
    overrides: Record<string, unknown>,
  ): AnyEvent => {
    const ev: Record<string, unknown> = { ...base, ...overrides };
    for (const key of drop) delete ev[key];
    return ev as unknown as AnyEvent;
  };
  return [
    sessionStart(SESSION_DENY_ONLY, at(9, 0)),
    ...denied(SESSION_DENY_ONLY, 9, 1, 1),
    ...denied(SESSION_DENY_ONLY, 9, 3, 2),
    sessionEnd(SESSION_DENY_ONLY, at(9, 9)),

    sessionStart(SESSION_HOLDS, at(10, 0)),
    ...held(SESSION_HOLDS, 10, 1, 1, 'approved'),
    ...held(SESSION_HOLDS, 10, 3, 2, 'denied'),
    ...held(SESSION_HOLDS, 10, 5, 3, 'timeout'),
    sessionEnd(SESSION_HOLDS, at(10, 9)),

    sessionStart(SESSION_POLICY_MIX, at(11, 0)),
    allowed(SESSION_POLICY_MIX, at(11, 1), 1),
    ...denied(SESSION_POLICY_MIX, 11, 2, 2),
    ...held(SESSION_POLICY_MIX, 11, 4, 3, 'approved'),
    sessionEnd(SESSION_POLICY_MIX, at(11, 9)),

    sessionStart(SESSION_NO_ENFORCEMENT, at(12, 0)),
    allowed(SESSION_NO_ENFORCEMENT, at(12, 1), 1),
    allowed(SESSION_NO_ENFORCEMENT, at(12, 2), 2),
    sessionEnd(SESSION_NO_ENFORCEMENT, at(12, 9)),

    // Shapes no writer of ours produces, pinned so the backends cannot
    // drift: a policy_decision with no `decision` at all and one whose
    // `decision`/`outcome` are off-vocabulary still count (neither backend
    // reads below the kind), while a tool_call that merely CARRIES
    // `gateway.decision: 'deny'` with no decision event of its own does not
    // — the count is of policy_decision events, not of refused calls.
    sessionStart(SESSION_ODD_POLICY, at(13, 0)),
    odd(policyDecision(SESSION_ODD_POLICY, at(13, 1), 1), ['decision', 'tool'], {}),
    odd(policyDecision(SESSION_ODD_POLICY, at(13, 2), 2), [], { decision: 'maybe', outcome: 42 }),
    deniedToolCall(SESSION_ODD_POLICY, at(13, 3), 3),

    // A refused `tools/call` NOTIFICATION is the one decision that cannot be
    // a policy_decision event: a notification has no request id, and the
    // frozen schema's request_id is `string | number`. It carries its
    // outcome on the notification event instead, and counts all the same —
    // otherwise the column reports 0 for a session where enforcement
    // happened. The forwarded notification beside it carries nothing.
    sessionStart(SESSION_NOTIFICATION_DENY, at(14, 0)),
    deniedNotification(SESSION_NOTIFICATION_DENY, at(14, 1)),
    plainNotification(SESSION_NOTIFICATION_DENY, at(14, 2)),
    sessionEnd(SESSION_NOTIFICATION_DENY, at(14, 3)),
  ];
}

/** A `tools/call` notification the gateway refused, with its outcome on it. */
function deniedNotification(sessionId: string, timestamp: string): NotificationEvent {
  return {
    ...plainNotification(sessionId, timestamp),
    gateway: { decision: 'deny', rule_id: 'no-delete' },
  };
}

/** The same shape, forwarded: no gateway field, so not a decision. */
function plainNotification(sessionId: string, timestamp: string): NotificationEvent {
  return {
    schema: SCHEMA,
    event_id: fakeUuid(),
    session_id: sessionId,
    timestamp,
    kind: 'notification',
    identity: IDENTITY,
    server: SERVER,
    attributes: { 'mcp.method.name': 'tools/call', 'rpc.system': 'jsonrpc' },
    method: 'tools/call',
    direction: 'client_to_server',
    params: null,
  };
}

/* --------------------- resumed ("reopened") session --------------------- */

/**
 * A session that recorded its session_end and then KEPT RECORDING: cloud
 * dogfood 4's Claude Code session was resumed under the same session_id, so
 * a session_end at 07:59:20 is followed by real tool calls until 12:41:08.
 * The counts are live aggregates over all of it, so a reader who takes
 * ENDED as "nothing happened after this" misreads the row — the shape this
 * fixture pins.
 */
const SESSION_REOPENED = '77777777-7777-4777-8777-777777777777';

function reopenedSessionEvents(): AnyEvent[] {
  return [
    sessionStart(SESSION_REOPENED, '2026-09-15T07:00:00.000Z'),
    toolCall(SESSION_REOPENED, '2026-09-15T07:30:00.000Z', 'list_issues', { requestId: 1 }),
    sessionEnd(SESSION_REOPENED, '2026-09-15T07:59:20.000Z'),
    // ... resumed here, under the same session_id and with no second
    // session_start (the client only ever emits one per session).
    toolCall(SESSION_REOPENED, '2026-09-15T12:40:00.000Z', 'create_issue', { requestId: 2 }),
    toolCall(SESSION_REOPENED, '2026-09-15T12:41:08.000Z', 'get_file_contents', {
      requestId: 3,
      isError: true,
    }),
  ];
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
    // Ended and stayed ended: the session_end IS the last event, so
    // last_event_at repeats it and `sessions` prints the end time.
    expect(a.last_event_at).toBe('2026-06-11T10:00:03.000Z');
    expect(a.server_name).toBe('github-mcp');
    expect(a.identity_fingerprint).toBe(IDENTITY.fingerprint);
    expect(a.event_count).toBe(4);
    expect(a.tool_call_count).toBe(2);
    expect(a.error_count).toBe(1);
    expect(a.server_count).toBe(1);
    expect(a.policy_decision_count).toBe(0); // recorded without a policy: the gateway never ruled

    const b = sessions.find((s) => s.session_id === SESSION_B)!;
    expect(b).toBeDefined();
    expect(b.started_at).toBe('2026-06-11T11:00:00.000Z');
    expect(b.ended_at).toBeUndefined();
    expect(b.last_event_at).toBe('2026-06-11T11:00:01.000Z'); // still open: last activity
    expect(b.server_name).toBe('github-mcp');
    expect(b.identity_fingerprint).toBe(IDENTITY.fingerprint);
    expect(b.event_count).toBe(2);
    expect(b.tool_call_count).toBe(1);
    expect(b.error_count).toBe(0);
    expect(b.server_count).toBe(1);
  });

  it('sessions() counts a hook-captured session per call, per failure and per server', () => {
    const store = open();
    // Proxy sessions and the hook session interleave in one chain, exactly
    // as they do in a data dir shared by `record` wrappers and the hook.
    store.append(seal([...twoSessionEvents(), ...hookSessionEvents()]));

    const sessions = store.sessions();
    expect(sessions.map((s) => s.session_id)).toEqual([SESSION_A, SESSION_B, SESSION_HOOK]);

    // Proxy-only sessions keep exactly today's counts.
    const a = sessions.find((s) => s.session_id === SESSION_A)!;
    expect(a.event_count).toBe(4);
    expect(a.tool_call_count).toBe(2);
    expect(a.error_count).toBe(1);
    expect(a.server_count).toBe(1);
    const b = sessions.find((s) => s.session_id === SESSION_B)!;
    expect(b.event_count).toBe(2);
    expect(b.tool_call_count).toBe(1);
    expect(b.error_count).toBe(0);
    expect(b.server_count).toBe(1);

    const hook = sessions.find((s) => s.session_id === SESSION_HOOK)!;
    expect(hook).toBeDefined();
    expect(hook.started_at).toBe('2026-09-15T21:02:00.000Z');
    expect(hook.ended_at).toBeUndefined(); // Stop is a turn boundary, not a session_end
    expect(hook.server_name).toBe('claude-code'); // first event: the session-level session_start
    expect(hook.event_count).toBe(10); // session_start + 8 tool_call events + Stop
    // Eight tool_call events, but five CALLS: pre+post pairs count once, a
    // lone pre (never completed) counts once, a denied pre counts once.
    expect(hook.tool_call_count).toBe(5);
    // Exactly one is_error event per failed call: the denied pre and the
    // failing post. The lone pre with no post is NOT an error here.
    expect(hook.error_count).toBe(2);
    // ONE decision: the denied `clickup_delete_task` pre event. A hook deny
    // is the call's own `pre` tool_call with `error.type: 'policy_denied'`
    // (no JSON-RPC id, so no policy_decision event), and it counts here
    // exactly as a gateway deny does — the same arithmetic (1 decision, 1
    // call, 1 error) for both shapes of "this call was denied" [z8n6b5z1zr].
    // NEGATIVE CONTROL: drop the `policy_denied` errorType from the fixture
    // and this reads 0 again.
    expect(hook.policy_decision_count).toBe(1);
    // The servers the session's tool calls went to: ClickUp + github +
    // corp-notes. The claude-code session_start/Stop events are not one.
    expect(hook.server_count).toBe(3);
  });

  it('sessions() counts a proxy session recorded without --name as one server, and a session with no tool call as zero', () => {
    // Without --name the proxy stamps the argv-derived basename on the
    // events before the initialize handshake and the learned serverInfo.name
    // after it (src/proxy/stdio.ts), so counting distinct names over EVERY
    // event read 2 for the README's plain `record -- <server>` form (review
    // of the integrated change). Only the servers actually called count.
    const MIXED = '44444444-4444-4444-8444-444444444444';
    const NO_CALLS = '55555555-5555-4555-8555-555555555555';
    const named = (ev: AnyEvent, name: string): AnyEvent => ({ ...ev, server: { ...ev.server, name } });
    const store = open();
    store.append(
      seal([
        named(sessionStart(MIXED, '2026-09-15T22:10:28.020Z'), 'echo-server.cjs'),
        named(toolCall(MIXED, '2026-09-15T22:10:28.050Z', 'echo', { requestId: 2 }), 'echo-server'),
        named(toolCall(MIXED, '2026-09-15T22:10:28.060Z', 'echo', { requestId: 3 }), 'echo-server'),
        named(sessionEnd(MIXED, '2026-09-15T22:10:28.072Z'), 'echo-server'),
        sessionStart(NO_CALLS, '2026-09-15T22:11:00.000Z'),
        sessionEnd(NO_CALLS, '2026-09-15T22:11:01.000Z'),
      ]),
    );
    const sessions = store.sessions();
    const mixed = sessions.find((s) => s.session_id === MIXED)!;
    expect(mixed.server_name).toBe('echo-server.cjs'); // SERVER stays the first event's name
    expect(mixed.server_count).toBe(1);
    expect(mixed.tool_call_count).toBe(2);
    const noCalls = sessions.find((s) => s.session_id === NO_CALLS)!;
    expect(noCalls.server_count).toBe(0);
    expect(noCalls.tool_call_count).toBe(0);
  });

  it('sessions() keeps a session honest when its events continue past its session_end', () => {
    const store = open();
    // The normally-ended session A shares the chain, so "unchanged for a
    // clean end" is asserted against the same code path.
    store.append(seal([...twoSessionEvents(), ...reopenedSessionEvents()]));

    const sessions = store.sessions();
    const reopened = sessions.find((s) => s.session_id === SESSION_REOPENED)!;
    expect(reopened).toBeDefined();
    expect(reopened.started_at).toBe('2026-09-15T07:00:00.000Z');
    // The session_end is still reported — it happened — but it is NOT the
    // session's last event, and last_event_at says so: the row cannot be
    // read as "ended at 07:59:20, nothing after".
    expect(reopened.ended_at).toBe('2026-09-15T07:59:20.000Z');
    expect(reopened.last_event_at).toBe('2026-09-15T12:41:08.000Z');
    expect(reopened.last_event_at! > reopened.ended_at!).toBe(true);
    // The counts are live aggregates over the WHOLE session, before and
    // after the session_end — that is what makes the plain ENDED reading
    // wrong, and it does not change here.
    expect(reopened.event_count).toBe(5);
    expect(reopened.tool_call_count).toBe(3);
    expect(reopened.error_count).toBe(1);
    expect(reopened.server_count).toBe(1);

    // A session that ended and stayed ended is untouched: its session_end is
    // its last event, so ended_at and last_event_at agree.
    const a = sessions.find((s) => s.session_id === SESSION_A)!;
    expect(a.ended_at).toBe('2026-06-11T10:00:03.000Z');
    expect(a.last_event_at).toBe('2026-06-11T10:00:03.000Z');
    // And one that never ended reports its last activity, not an end.
    const b = sessions.find((s) => s.session_id === SESSION_B)!;
    expect(b.ended_at).toBeUndefined();
    expect(b.last_event_at).toBe('2026-06-11T11:00:01.000Z');
  });

  it('sessions() reads non-conforming records the same way on both backends', () => {
    // Shapes no writer of ours produces, pinned so the two backends cannot
    // drift apart on them: an explicit `phase: null` (a call, like an
    // absent phase), a server.name that is not a string (not a server),
    // and is_error on a kind that is neither tool_call nor rpc (not an
    // error).
    const ODD = '66666666-6666-4666-8666-666666666666';
    const t = (s: number) => `2026-09-15T22:12:${String(s).padStart(2, '0')}.000Z`;
    const phaseNull = { ...toolCall(ODD, t(1), 'a', { requestId: 1 }), phase: null } as unknown as AnyEvent;
    const numericName = {
      ...toolCall(ODD, t(2), 'b', { requestId: 2 }),
      server: { ...SERVER, name: 42 },
    } as unknown as AnyEvent;
    const erroringNotification = {
      schema: SCHEMA,
      event_id: fakeUuid(),
      session_id: ODD,
      timestamp: t(3),
      kind: 'notification',
      identity: IDENTITY,
      server: SERVER,
      attributes: {},
      method: 'notifications/message',
      direction: 'server_to_client',
      params: {},
      is_error: true,
    } as unknown as AnyEvent;
    const store = open();
    store.append(seal([sessionStart(ODD, t(0)), phaseNull, numericName, erroringNotification]));
    const odd = store.sessions().find((s) => s.session_id === ODD)!;
    expect(odd.event_count).toBe(4);
    expect(odd.tool_call_count).toBe(2); // phase null and the numeric-name call both count as calls
    expect(odd.server_count).toBe(1); // github-mcp; 42 is not a server name
    expect(odd.error_count).toBe(0); // is_error on a notification is not an error
  });

  it('sessions() counts a gateway session: a denied call is 1 tool call + 1 error, and each policy_decision is 1 decision', () => {
    const store = open();
    const records = gatewaySessionFixture();
    store.append(records);

    const sessions = store.sessions();
    expect(sessions).toHaveLength(1);
    const g = sessions[0]!;
    expect(g.session_id).toBe(SESSION_G);
    expect(g.started_at).toBe('2026-06-11T12:00:00.000Z');
    expect(g.ended_at).toBe('2026-06-11T12:00:05.000Z');
    expect(g.server_name).toBe('github-mcp');
    // 7 events: start, allowed, decision, denied, decision, approved, end.
    expect(g.event_count).toBe(7);
    // allowed + denied + approved — the two policy_decision events are not tool calls.
    expect(g.tool_call_count).toBe(3);
    // exactly the denied call (policy_decision carries no is_error).
    expect(g.error_count).toBe(1);
    // The gateway ruled twice: the deny, and the hold it resolved by
    // approving — the allowed call produced no policy_decision at all.
    expect(g.policy_decision_count).toBe(2);

    // The new kind round-trips through the store byte-exactly and the chain still verifies.
    const back = [...store.iterate({ sessionId: SESSION_G })].map((r) => r.event);
    expect(back.map((e) => e.kind)).toEqual([
      'session_start',
      'tool_call',
      'policy_decision',
      'tool_call',
      'policy_decision',
      'tool_call',
      'session_end',
    ]);
    expect(back[2]).toEqual(records[2]!.event);
    expect('is_error' in back[2]!).toBe(false);
    expect((back[3] as ToolCallEvent).gateway).toEqual({ decision: 'deny', rule_id: 'no-exfil' });
    expect((back[0] as SessionStartEvent).policy).toEqual({ hash: sha256Ref('policy bytes'), name: 'laptop' });
  });

  it('sessions() counts enforcement: denies, every hold outcome (approved included), malformed decisions, and 0 when the gateway refused nothing', () => {
    const store = open();
    store.append(seal(enforcementSessionEvents()));
    const byId = new Map(store.sessions().map((s) => [s.session_id, s]));

    // Denies only: each refusal is one decision AND one (failed) call.
    const denies = byId.get(SESSION_DENY_ONLY)!;
    expect(denies.policy_decision_count).toBe(2);
    expect(denies.tool_call_count).toBe(2);
    expect(denies.error_count).toBe(2);
    expect(denies.event_count).toBe(6);

    // Hold outcomes: one decision per RESOLVED hold, including the approved
    // one — whose call was forwarded and is therefore not an error.
    const holds = byId.get(SESSION_HOLDS)!;
    expect(holds.policy_decision_count).toBe(3);
    expect(holds.tool_call_count).toBe(3);
    expect(holds.error_count).toBe(2);

    // A mix: the allowed call contributes a call and no decision.
    const mixed = byId.get(SESSION_POLICY_MIX)!;
    expect(mixed.policy_decision_count).toBe(2);
    expect(mixed.tool_call_count).toBe(3);
    expect(mixed.error_count).toBe(1);

    // Gateway mode that never refused anything reads exactly like a session
    // recorded without a policy at all.
    const quiet = byId.get(SESSION_NO_ENFORCEMENT)!;
    expect(quiet.policy_decision_count).toBe(0);
    expect(quiet.tool_call_count).toBe(2);

    // A refused tools/call NOTIFICATION counts, though it is not a
    // policy_decision event and cannot be one; the forwarded notification
    // beside it does not.
    const noteDeny = byId.get(SESSION_NOTIFICATION_DENY)!;
    expect(noteDeny.policy_decision_count).toBe(1);
    expect(noteDeny.tool_call_count).toBe(0);
    expect(noteDeny.event_count).toBe(4);

    // Malformed decisions still count (neither backend reads below the
    // kind); a tool_call that merely carries `gateway.decision: 'deny'`
    // does not.
    const odd = byId.get(SESSION_ODD_POLICY)!;
    expect(odd.policy_decision_count).toBe(2);
    expect(odd.tool_call_count).toBe(1);
    expect(odd.error_count).toBe(1);
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

/* ---------------- the two backends over one identical chain ---------------- */

/**
 * The suite above runs each fixture through both backends against the same
 * expected numbers. This pins the property that actually has to hold for
 * the aggregate to be trustworthy: given ONE chain, the two backends
 * produce identical summaries, field for field — not merely numbers that
 * each happened to match a hand-written expectation.
 */
describe('sessions() is identical across backends for the same chain', () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'mcp-recorder-store-parity-'));
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('sqlite and jsonl agree on enforcement, allowed calls and malformed decisions', () => {
    expect(isSqliteAvailable()).toBe(true); // the interesting case: both backends are real
    const records = seal([...twoSessionEvents(), ...enforcementSessionEvents()]);
    const sqlite = openStore({ dataDir: join(dir, 'sqlite'), backend: 'sqlite' });
    const jsonl = openStore({ dataDir: join(dir, 'jsonl'), backend: 'jsonl' });
    try {
      sqlite.append(records);
      jsonl.append(records);
      const fromSqlite = sqlite.sessions();
      expect(fromSqlite).toEqual(jsonl.sessions());
      // A, B (no policy at all), then denies / holds / mix / none /
      // malformed / a refused tools/call notification. The two backends
      // agree on every one, including the notification, which sqlite counts
      // in SQL and jsonl in TypeScript.
      expect(fromSqlite.map((s) => s.policy_decision_count)).toEqual([0, 0, 2, 3, 2, 0, 2, 1]);
    } finally {
      sqlite.close();
      jsonl.close();
    }
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

/* -------------------- one chain, one answer, two backends -------------------- */

describe('sessions() is backend-independent', () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'mcp-recorder-store-parity-'));
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('sqlite and jsonl serialize the same summaries for the same chain', () => {
    // The parametrized suite above pins the same expectations on each
    // backend separately; this compares them directly, which is the check
    // that catches a field one backend sets and the other does not.
    expect(isSqliteAvailable()).toBe(true); // the comparison is vacuous without it
    const records = seal([
      ...twoSessionEvents(),
      ...hookSessionEvents(),
      ...reopenedSessionEvents(),
    ]);
    const sqlite = openStore({ dataDir: join(dir, 'sqlite'), backend: 'sqlite' });
    const jsonl = openStore({ dataDir: join(dir, 'jsonl'), backend: 'jsonl' });
    try {
      sqlite.append(records);
      jsonl.append(records);
      const fromSqlite = sqlite.sessions();
      expect(fromSqlite.map((s) => s.session_id)).toEqual([
        SESSION_A,
        SESSION_B,
        SESSION_HOOK,
        SESSION_REOPENED,
      ]);
      // JSON.stringify, not toEqual: `sessions --json` is the stable machine
      // interface (README), so the KEY ORDER and which optional keys are
      // present must not depend on which backend produced it either.
      expect(JSON.stringify(fromSqlite, null, 2)).toBe(JSON.stringify(jsonl.sessions(), null, 2));
    } finally {
      sqlite.close();
      jsonl.close();
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
