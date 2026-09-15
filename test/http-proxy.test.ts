import { createServer } from 'node:http';
import type { IncomingMessage, Server, ServerResponse } from 'node:http';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { AddressInfo } from 'node:net';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { Recorder } from '../src/capture/recorder.js';
import { sha256Ref } from '../src/chain/hash.js';
import { Signer } from '../src/chain/keys.js';
import { runHttpProxy } from '../src/proxy/http.js';
import { Redactor } from '../src/redact/redactor.js';
import { openStore } from '../src/store/index.js';
import { verifyStore } from '../src/verify/verify.js';
import type {
  AnyEvent,
  InitializeEvent,
  ToolCallEvent,
} from '../src/schema/events.js';

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
});

function tmpDataDir(): string {
  const dir = mkdtempSync(join(tmpdir(), 'mcp-rec-http-'));
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

interface Rpc {
  jsonrpc: '2.0';
  id?: string | number;
  method?: string;
  params?: Record<string, unknown>;
  result?: unknown;
  error?: unknown;
}

/** Plain JSON target: initialize + tools/call over POST. */
async function startJsonTarget(): Promise<{ url: string }> {
  const server = createServer(async (req, res) => {
    const body = await readBody(req);
    const msg = JSON.parse(body) as Rpc;
    let result: unknown;
    if (msg.method === 'initialize') {
      result = {
        protocolVersion: '2025-03-26',
        serverInfo: { name: 'http-target', version: '9.9.9' },
        capabilities: {},
      };
    } else if (msg.method === 'tools/call') {
      result = { content: [{ type: 'text', text: JSON.stringify(msg.params) }] };
    } else {
      result = { ok: true };
    }
    const out = JSON.stringify({ jsonrpc: '2.0', id: msg.id, result });
    res.writeHead(200, {
      'content-type': 'application/json',
      'content-length': Buffer.byteLength(out),
      'x-target-marker': 'json-target',
    });
    res.end(out);
  });
  const url = (await listen(server)) + '/mcp';
  cleanups.push(() => new Promise<void>((r) => server.close(() => r())));
  return { url };
}

/** SSE target: POST tools/call answered as text/event-stream, two frames. */
async function startSseTarget(): Promise<{ url: string }> {
  const server = createServer(async (req, res) => {
    const body = await readBody(req);
    const msg = JSON.parse(body) as Rpc;
    res.writeHead(200, {
      'content-type': 'text/event-stream',
      'cache-control': 'no-cache',
    });
    const notification = JSON.stringify({
      jsonrpc: '2.0',
      method: 'notifications/message',
      params: { level: 'info', data: 'working on it' },
    });
    res.write(`event: message\ndata: ${notification}\n\n`);
    setTimeout(() => {
      const reply = JSON.stringify({
        jsonrpc: '2.0',
        id: msg.id,
        result: { content: [{ type: 'text', text: 'sse done' }] },
      });
      res.write(`data: ${reply}\n\n`);
      res.end();
    }, 30);
  });
  const url = (await listen(server)) + '/mcp';
  cleanups.push(() => new Promise<void>((r) => server.close(() => r())));
  return { url };
}

async function startProxy(targetUrl: string, dataDir: string) {
  const store = openStore({ dataDir });
  const signer = await Signer.load(dataDir);
  const recorder = new Recorder({ store, signer });
  const proxy = await runHttpProxy({
    targetUrl,
    recorder,
    redactor: new Redactor(),
    proxyVersion: '0.0.0-test',
  });
  cleanups.push(() => proxy.close());
  return proxy;
}

function loadEvents(dataDir: string): AnyEvent[] {
  const store = openStore({ dataDir });
  try {
    return [...store.iterate()].map((r) => r.event);
  } finally {
    store.close();
  }
}

const post = (url: string, body: unknown): Promise<Response> =>
  fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream' },
    body: JSON.stringify(body),
  });

const initializeMsg: Rpc = {
  jsonrpc: '2.0',
  id: 1,
  method: 'initialize',
  params: {
    protocolVersion: '2025-03-26',
    clientInfo: { name: 'vitest-client', version: '1.2.3' },
    capabilities: {},
  },
};
const toolCallMsg: Rpc = {
  jsonrpc: '2.0',
  id: 2,
  method: 'tools/call',
  params: { name: 'echo', arguments: { city: 'lisbon', token: 'sk-veryverysecret000111' } },
};

/* --------------------------------- tests -------------------------------- */

describe('runHttpProxy', () => {
  it('forwards JSON-RPC byte-identically and records initialize + tool_call', async () => {
    const target = await startJsonTarget();
    const dataDir = tmpDataDir();
    const proxy = await startProxy(target.url, dataDir);

    for (const msg of [initializeMsg, toolCallMsg]) {
      const direct = await post(target.url, msg);
      const proxied = await post(proxy.url, msg);
      expect(proxied.status).toBe(direct.status);
      expect(proxied.headers.get('content-type')).toBe(direct.headers.get('content-type'));
      expect(proxied.headers.get('x-target-marker')).toBe('json-target');
      const directBytes = Buffer.from(await direct.arrayBuffer());
      const proxiedBytes = Buffer.from(await proxied.arrayBuffer());
      expect(proxiedBytes.equals(directBytes)).toBe(true);
    }

    await proxy.close();
    await proxy.close(); // idempotent

    const events = loadEvents(dataDir);
    const kinds = events.map((e) => e.kind);
    expect(kinds[0]).toBe('session_start');
    expect(kinds).toContain('initialize');
    expect(kinds).toContain('tool_call');
    expect(kinds[kinds.length - 1]).toBe('session_end');

    const init = events.find((e) => e.kind === 'initialize') as InitializeEvent;
    expect(init.client_name).toBe('vitest-client');
    expect(init.server_name).toBe('http-target');
    expect(init.protocol_version).toBe('2025-03-26');
    expect(init.server.transport).toBe('http');
    expect(init.server.command).toBe(target.url);

    const call = events.find((e) => e.kind === 'tool_call') as ToolCallEvent;
    expect(call.tool).toBe('echo');
    expect(call.request_id).toBe(2);
    expect(call.is_error).toBe(false);
    // args are redacted: structure preserved, secret never stored readable
    expect(JSON.stringify(call.args)).not.toContain('sk-veryverysecret000111');
    expect(call.args).toHaveProperty('token');

    // the whole chain verifies
    const store = openStore({ dataDir });
    try {
      const result = await verifyStore(store);
      expect(result.ok).toBe(true);
      expect(result.checked_events).toBe(events.length);
    } finally {
      store.close();
    }
  });

  it('streams SSE responses verbatim and still captures the tool_call', async () => {
    const target = await startSseTarget();
    const dataDir = tmpDataDir();
    const proxy = await startProxy(target.url, dataDir);

    const direct = await post(target.url, toolCallMsg);
    const directText = await direct.text();
    const proxied = await post(proxy.url, toolCallMsg);
    expect(proxied.status).toBe(200);
    expect(proxied.headers.get('content-type')).toBe('text/event-stream');
    const proxiedText = await proxied.text();
    expect(proxiedText).toBe(directText);
    expect(proxiedText).toContain('data: ');

    await proxy.close();

    const events = loadEvents(dataDir);
    const call = events.find((e) => e.kind === 'tool_call') as ToolCallEvent | undefined;
    expect(call).toBeDefined();
    expect(call!.tool).toBe('echo');
    expect(call!.is_error).toBe(false);
    const note = events.find((e) => e.kind === 'notification');
    expect(note).toBeDefined();
  });

  it('answers 502 with a JSON-RPC error body when the target is down', async () => {
    // Grab a port that is definitely closed: listen, note it, close it.
    const probe = createServer();
    const probeUrl = await listen(probe);
    await new Promise<void>((r) => probe.close(() => r()));

    const dataDir = tmpDataDir();
    const proxy = await startProxy(probeUrl + '/mcp', dataDir);

    const res = await post(proxy.url, toolCallMsg);
    expect(res.status).toBe(502);
    const body = (await res.json()) as { jsonrpc: string; error: { code: number; message: string } };
    expect(body.jsonrpc).toBe('2.0');
    expect(body.error.code).toBe(-32001);
    expect(body.error.message).toContain('upstream request failed');

    // proxy survives: a second request gets the same treatment, then closes cleanly
    const res2 = await post(proxy.url, initializeMsg);
    expect(res2.status).toBe(502);
    await proxy.close();
  });

  it('correlates concurrent clients that both use JSON-RPC id 1 (no collision)', async () => {
    // Every MCP client starts its id counter at 1; the target answers the
    // *first* call (id 1, tool A) after the *second* call (id 1, tool B) has
    // already been sent, so a process-wide pending map keyed on id alone
    // would misattribute one response to the other client's tool/args.
    const server = createServer(async (req, res) => {
      const body = await readBody(req);
      const msg = JSON.parse(body) as Rpc;
      const params = msg.params as { name: string };
      const delay = params.name === 'A_tool' ? 60 : 10; // A answers last
      setTimeout(() => {
        const out = JSON.stringify({
          jsonrpc: '2.0',
          id: msg.id,
          result: { content: [{ type: 'text', text: 'from ' + params.name }] },
        });
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(out);
      }, delay);
    });
    const url = (await listen(server)) + '/mcp';
    cleanups.push(() => new Promise<void>((r) => server.close(() => r())));

    const dataDir = tmpDataDir();
    const proxy = await startProxy(url, dataDir);

    const call = (tool: string) =>
      post(proxy.url, {
        jsonrpc: '2.0',
        id: 1,
        method: 'tools/call',
        params: { name: tool, arguments: { who: tool } },
      }).then((r) => r.json() as Promise<Rpc>);

    const [a, b] = await Promise.all([
      call('A_tool'),
      new Promise((r) => setTimeout(r, 5)).then(() => call('B_tool')),
    ]);
    // Forwarding is untouched: each client gets its own correct wire reply.
    const aText = (a.result as { content: [{ text: string }] }).content[0].text;
    const bText = (b.result as { content: [{ text: string }] }).content[0].text;
    expect(aText).toBe('from A_tool');
    expect(bText).toBe('from B_tool');

    await proxy.close();

    const events = loadEvents(dataDir);
    expect(events.some((e) => e.kind === 'protocol_error')).toBe(false);
    const calls = events.filter((e) => e.kind === 'tool_call') as ToolCallEvent[];
    expect(calls).toHaveLength(2);
    const byTool = new Map(calls.map((c) => [c.tool, c]));
    // "who" is not allow-listed, so it's redacted — assert the ref matches
    // that CLIENT's own value, i.e. args were not swapped between clients.
    const redactor = new Redactor();
    expect(byTool.get('A_tool')?.args).toEqual(redactor.scrub({ who: 'A_tool' }));
    expect(byTool.get('B_tool')?.args).toEqual(redactor.scrub({ who: 'B_tool' }));
    // Duration also confirms no swap: A was delayed 60ms, B only 10ms.
    expect(byTool.get('A_tool')!.duration_ms).toBeGreaterThan(byTool.get('B_tool')!.duration_ms);
  });

  it('numeric id 1 and string id "1" do not collide', async () => {
    const server = createServer(async (req, res) => {
      const body = await readBody(req);
      const msg = JSON.parse(body) as Rpc;
      const out = JSON.stringify({
        jsonrpc: '2.0',
        id: msg.id,
        result: { content: [{ type: 'text', text: `id-type:${typeof msg.id}` }] },
      });
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(out);
    });
    const url = (await listen(server)) + '/mcp';
    cleanups.push(() => new Promise<void>((r) => server.close(() => r())));

    const dataDir = tmpDataDir();
    const proxy = await startProxy(url, dataDir);

    const numeric = await post(proxy.url, {
      jsonrpc: '2.0',
      id: 1,
      method: 'tools/call',
      params: { name: 'numeric', arguments: {} },
    }).then((r) => r.json() as Promise<Rpc>);
    const stringy = await post(proxy.url, {
      jsonrpc: '2.0',
      id: '1',
      method: 'tools/call',
      params: { name: 'stringy', arguments: {} },
    }).then((r) => r.json() as Promise<Rpc>);

    expect(typeof numeric.id).toBe('number');
    expect(typeof stringy.id).toBe('string');

    await proxy.close();
    const events = loadEvents(dataDir);
    expect(events.some((e) => e.kind === 'protocol_error')).toBe(false);
    const calls = events.filter((e) => e.kind === 'tool_call') as ToolCallEvent[];
    expect(calls).toHaveLength(2);
    const num = calls.find((c) => c.tool === 'numeric')!;
    const str = calls.find((c) => c.tool === 'stringy')!;
    expect(num.request_id).toBe(1);
    expect(str.request_id).toBe('1');
  });

  it('an idle SSE stream survives past a short upstream-headers timeout', async () => {
    const upstream = createServer((req, res) => {
      res.writeHead(200, { 'content-type': 'text/event-stream' });
      res.write(': open\n\n');
      // then stay silent — headers already sent, this must not be torn down
    });
    const upstreamUrl = await listen(upstream);
    cleanups.push(() => new Promise<void>((r) => upstream.close(() => r())));

    const dataDir = tmpDataDir();
    const store = openStore({ dataDir });
    const signer = await Signer.load(dataDir);
    const recorder = new Recorder({ store, signer });
    // Budgeted in the hundreds of ms, not tens: a busy test runner can
    // easily burn 50ms of scheduling delay before this same-process
    // upstream's handler even gets to call writeHead/write, which would
    // trip a too-tight header-wait timeout before headers ever arrive and
    // fail the test for a reason that has nothing to do with the behavior
    // under test. The point under test is that this timeout is cleared the
    // instant headers arrive and never applies again afterwards, so the
    // idle period below is picked to clearly (4x) exceed it.
    const headersTimeoutMs = 300;
    const proxy = await runHttpProxy({
      targetUrl: upstreamUrl + '/mcp',
      recorder,
      redactor: new Redactor(),
      proxyVersion: '0.0.0-test',
      upstreamHeadersTimeoutMs: headersTimeoutMs,
    });
    cleanups.push(() => proxy.close());

    const res = await fetch(proxy.url, { headers: { accept: 'text/event-stream' } });
    expect(res.status).toBe(200);
    const reader = res.body!.getReader();
    const first = await reader.read();
    expect(Buffer.from(first.value!).toString()).toContain('open');

    // Idle for several times the header timeout: the stream must still be
    // alive (no error, no premature close) once headers arrived.
    const idleMs = headersTimeoutMs * 4;
    const raced = await Promise.race([
      reader.read().then(() => 'more-data' as const),
      new Promise<'still-open'>((r) => setTimeout(() => r('still-open'), idleMs)),
    ]);
    expect(raced).toBe('still-open');
    await reader.cancel();
  });

  it('a long-silent POST (no response yet) survives with no default timeout', async () => {
    const upstream = createServer((req, res) => {
      setTimeout(() => {
        const out = JSON.stringify({ jsonrpc: '2.0', id: 1, result: { ok: true } });
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(out);
      }, 300); // no bytes at all — not even headers — for 300ms
    });
    const url = (await listen(upstream)) + '/mcp';
    cleanups.push(() => new Promise<void>((r) => upstream.close(() => r())));

    const dataDir = tmpDataDir();
    // No upstreamHeadersTimeoutMs configured: default is no cap at all.
    const proxy = await startProxy(url, dataDir);

    const res = await post(proxy.url, {
      jsonrpc: '2.0',
      id: 1,
      method: 'tools/call',
      params: { name: 'slow', arguments: {} },
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as Rpc;
    expect(body.result).toEqual({ ok: true });
    await proxy.close();
  });

  it('aborts the upstream connection when the client disconnects early', async () => {
    let opened = 0;
    let closed = 0;
    const upstream = createServer((req, res) => {
      opened++;
      res.writeHead(200, { 'content-type': 'text/event-stream' });
      res.write(': open\n\n');
      const ping = setInterval(() => {
        try {
          res.write(': ping\n\n');
        } catch {
          /* ignore */
        }
      }, 20);
      res.on('close', () => {
        closed++;
        clearInterval(ping);
      });
    });
    const url = (await listen(upstream)) + '/mcp';
    cleanups.push(() => new Promise<void>((r) => upstream.close(() => r())));

    const dataDir = tmpDataDir();
    const proxy = await startProxy(url, dataDir);

    const ac = new AbortController();
    const res = await fetch(proxy.url, {
      headers: { accept: 'text/event-stream' },
      signal: ac.signal,
    });
    const reader = res.body!.getReader();
    await reader.read();
    ac.abort();

    await vi.waitFor(() => expect(closed).toBe(opened), { timeout: 2000 });
    expect(opened).toBe(1);
    await proxy.close();
  });

  it('records an unanswered event for a request still pending at close()', async () => {
    // A positive signal that the request has fully reached the upstream,
    // in place of a fixed sleep: the proxy's tap parses the request body
    // (registering the pending entry) in the SAME 'end' event tick as it
    // pipes the body onward to upReq — see the request-body handling in
    // src/proxy/http.ts, where the tap's own `req.on('end', ...)` listener
    // is attached before `req.pipe(upReq)`, so it always runs first. That
    // means the pending entry is registered strictly before `upReq.end()`
    // is even called, which itself happens strictly before this upstream
    // stub can physically observe the end of the request body below — so
    // waiting for THIS promise guarantees the proxy has already registered
    // the pending entry, on any runner speed.
    let requestReceived: () => void;
    const received = new Promise<void>((resolve) => {
      requestReceived = resolve;
    });
    const upstream = createServer((req) => {
      // Never respond — simulates a tool call still in flight at shutdown.
      // Consume (don't just ignore) the body so 'end' actually fires.
      req.resume();
      req.on('end', () => requestReceived());
    });
    const url = (await listen(upstream)) + '/mcp';
    cleanups.push(() => new Promise<void>((r) => upstream.close(() => r())));

    const dataDir = tmpDataDir();
    const proxy = await startProxy(url, dataDir);

    // Attach the rejection handler in the same tick the fetch starts, so
    // the inevitable socket-close-on-shutdown never counts as unhandled.
    const pending = post(proxy.url, {
      jsonrpc: '2.0',
      id: 42,
      method: 'tools/call',
      params: { name: 'never_returns', arguments: { x: 1 } },
    }).catch(() => undefined);
    await received;
    await proxy.close();
    // The client-facing response socket is torn down by close(); swallow.
    await pending;

    const events = loadEvents(dataDir);
    const call = events.find(
      (e) => e.kind === 'tool_call' && (e as ToolCallEvent).tool === 'never_returns',
    ) as ToolCallEvent | undefined;
    expect(call).toBeDefined();
    expect(call!.is_error).toBe(true);
    expect(call!.result).toBeNull();
    expect(call!.error?.type).toBe('unanswered');
    expect(call!.request_id).toBe(42);

    // Recorded strictly before session_end.
    const callIdx = events.indexOf(call!);
    const endIdx = events.findIndex((e) => e.kind === 'session_end');
    expect(endIdx).toBeGreaterThan(callIdx);
  });

  it('never stores target URL userinfo in ServerContext.command or any event', async () => {
    const target = await startJsonTarget();
    const withCreds = target.url.replace('http://', 'http://svcuser:sup3rSecr3t@');

    const dataDir = tmpDataDir();
    const store = openStore({ dataDir });
    const signer = await Signer.load(dataDir);
    const recorder = new Recorder({ store, signer });
    const proxy = await runHttpProxy({
      targetUrl: withCreds,
      recorder,
      redactor: new Redactor(),
      proxyVersion: '0.0.0-test',
    });
    cleanups.push(() => proxy.close());

    // The credentials must still reach the upstream server (forwarding is
    // unaffected); the plain target has no auth check here, so this just
    // proves traffic still flows through the credentialed URL.
    const res = await post(proxy.url, initializeMsg);
    expect(res.status).toBe(200);

    await proxy.close();

    const events = loadEvents(dataDir);
    expect(events.length).toBeGreaterThan(0);
    const serialized = JSON.stringify(events);
    expect(serialized).not.toContain('svcuser');
    expect(serialized).not.toContain('sup3rSecr3t');
    for (const e of events) {
      expect(e.server.command).not.toContain('svcuser');
      expect(e.server.command).not.toContain('sup3rSecr3t');
      expect(e.server.command.startsWith('http://')).toBe(true);
    }

    // P2: the password is fingerprinted separately from the joined
    // "user:pass" string, so a blast-radius query for the leaked PASSWORD
    // ALONE — without knowing the username — still finds the event.
    const passwordHash = sha256Ref('sup3rSecr3t');
    const userHash = sha256Ref('svcuser');
    const hitPassword = events.some((e) =>
      e.identity.credential_fingerprints?.some((f) => f.ref === passwordHash),
    );
    const hitUser = events.some((e) =>
      e.identity.credential_fingerprints?.some((f) => f.ref === userHash),
    );
    expect(hitPassword).toBe(true);
    expect(hitUser).toBe(true);
  });

  /* --- P1: hosted-MCP URLs sometimes carry the credential in the PATH
   * (`https://host/mcp/sk-.../sse`) or QUERY STRING (`?api_key=...`,
   * `?token=...`) rather than userinfo. Previously only userinfo was
   * stripped, so both shapes landed readable in ServerContext.command on
   * every event (session_start, rpc, session_end, ...), in replay and in
   * export bundles. */
  it('never stores a credential embedded in the target URL PATH (hosted-MCP shape)', async () => {
    const target = await startJsonTarget(); // .../mcp
    const secretSegment = 'sk-ak-1234567890abcdefXYZ';
    const withPathCred = target.url + '/' + secretSegment + '/sse';

    const dataDir = tmpDataDir();
    const proxy = await startProxy(withPathCred, dataDir);

    const res = await post(proxy.url, initializeMsg);
    expect(res.status).toBe(200);
    await proxy.close();

    const events = loadEvents(dataDir);
    expect(events.length).toBeGreaterThan(0);
    const serialized = JSON.stringify(events);
    expect(serialized).not.toContain(secretSegment);

    for (const e of events) {
      expect(e.server.command).not.toContain(secretSegment);
      expect(e.server.command.startsWith('http://')).toBe(true);
    }

    // A blast-radius query for the path-embedded credential still finds it.
    const needleHash = sha256Ref(secretSegment);
    const hit = events.some((e) =>
      e.identity.credential_fingerprints?.some((f) => f.ref === needleHash),
    );
    expect(hit).toBe(true);
  });

  it('never stores credentials in the target URL QUERY STRING, and drops the query entirely', async () => {
    const target = await startJsonTarget(); // .../mcp
    const apiKey = 'AKIAABCDEFGHIJKLMNOP';
    const token = 'ghp_abcdefghijklmnopqrstuvwxyz1234';
    const withQueryCreds = `${target.url}?api_key=${apiKey}&token=${token}`;

    const dataDir = tmpDataDir();
    const proxy = await startProxy(withQueryCreds, dataDir);

    const res = await post(proxy.url, initializeMsg);
    expect(res.status).toBe(200);
    await proxy.close();

    const events = loadEvents(dataDir);
    expect(events.length).toBeGreaterThan(0);
    const serialized = JSON.stringify(events);
    expect(serialized).not.toContain(apiKey);
    expect(serialized).not.toContain(token);

    for (const e of events) {
      // The query string is dropped entirely, not merely scrubbed in place.
      expect(e.server.command).not.toContain('?');
      expect(e.server.command).not.toContain(apiKey);
      expect(e.server.command).not.toContain(token);
      expect(e.server.command).toBe(target.url);
    }

    const apiKeyHash = sha256Ref(apiKey);
    const tokenHash = sha256Ref(token);
    const hitApiKey = events.some((e) =>
      e.identity.credential_fingerprints?.some((f) => f.ref === apiKeyHash),
    );
    const hitToken = events.some((e) =>
      e.identity.credential_fingerprints?.some((f) => f.ref === tokenHash),
    );
    expect(hitApiKey).toBe(true);
    expect(hitToken).toBe(true);
  });
});
