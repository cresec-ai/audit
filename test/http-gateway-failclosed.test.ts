/**
 * `http --policy`, the SSE path: the boundary filter fails CLOSED.
 *
 * The filter itself never throws (`applyBoundary` catches), so the only way
 * to exercise the proxy's guard around it is to make the splice it calls
 * afterwards throw — `spliceRewrittenText`, imported from ./stdio.js — for
 * the one event that carries a rewritten tools/call result. That is what the
 * module mock below does, and why this lives in its own file: the mock is
 * hoisted and module-wide, and test/http-gateway.test.ts must keep the real
 * splice for its own assertions.
 *
 * Asserted the same way round as the rest of the suite: what the CLIENT
 * received (bytes), never the recorder's word for it.
 */

import { createServer } from 'node:http';
import type { IncomingMessage, Server } from 'node:http';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { AddressInfo } from 'node:net';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { Recorder } from '../src/capture/recorder.js';
import { sha256Ref } from '../src/chain/hash.js';
import { Signer } from '../src/chain/keys.js';
import { HoldStore } from '../src/gateway/holds.js';
import type { GatewayOptions } from '../src/gateway/options.js';
import { formatPolicyErrors, validatePolicyObject } from '../src/policy/validate.js';
import type { LoadedPolicy } from '../src/policy/load.js';
import { runHttpProxy } from '../src/proxy/http.js';
import { Redactor } from '../src/redact/redactor.js';
import { openStore } from '../src/store/index.js';
import type { AnyEvent, ProtocolErrorEvent, ToolCallEvent } from '../src/schema/events.js';

const SECRET = 'sk-live-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123';

vi.mock('../src/proxy/stdio.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../src/proxy/stdio.js')>();
  return {
    ...actual,
    spliceRewrittenText: (text: string | null, before: unknown, after: unknown): string | undefined => {
      if (typeof text === 'string' && text.includes(SECRET)) throw new Error('synthetic splice failure');
      return actual.spliceRewrittenText(text, before, after);
    },
  };
});

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

/** An SSE target: a notification frame, the tools/call result carrying a secret, then a trailing notification. */
async function startSseTarget(): Promise<string> {
  const server = createServer(async (req, res) => {
    const body = await readBody(req);
    const msg = JSON.parse(body) as { id: number; method: string };
    res.writeHead(200, { 'content-type': 'text/event-stream', 'cache-control': 'no-cache' });
    const note = JSON.stringify({ jsonrpc: '2.0', method: 'notifications/message', params: { level: 'info', data: 'working on it' } });
    res.write(`event: message\r\nid: 7\r\ndata: ${note}\r\n\r\n`);
    setTimeout(() => {
      const reply = msg.method === 'tools/call'
        ? `{"jsonrpc":"2.0","id":${String(msg.id)},"result":{"content":[{"type":"text","text":"key=${SECRET}"}]}}`
        : JSON.stringify({ jsonrpc: '2.0', id: msg.id, result: { ok: true } });
      res.write(`event: message\r\nid: 8\r\ndata: ${reply}\r\n\r\n`);
      res.write(`data: ${JSON.stringify({ jsonrpc: '2.0', method: 'notifications/message', params: { level: 'info', data: 'done' } })}\n\n`);
      res.end();
    }, 30);
  });
  const url = (await listen(server)) + '/mcp';
  cleanups.push(() => new Promise<void>((r) => server.close(() => r())));
  return url;
}

const POLICY = { version: 1, name: 'http-gw-failclosed', mcp: { default: 'allow', boundary: { secrets: 'redact', injection: 'flag' } } };

function loadedPolicy(doc: Record<string, unknown>): LoadedPolicy {
  const r = validatePolicyObject(doc);
  if (!r.ok) throw new Error(formatPolicyErrors(r.errors));
  return { policy: r.policy, hash: sha256Ref(JSON.stringify(doc)), source: 'json', path: '/policy.json' };
}

describe('http --policy: the SSE boundary path fails closed', () => {
  it('when filtering a tools/call result throws, the client gets a blocked result for that id, the secret never crosses, and the frames around it are untouched', async () => {
    const dataDir = mkdtempSync(join(tmpdir(), 'mcp-rec-http-gw-fc-'));
    cleanups.push(() => rmSync(dataDir, { recursive: true, force: true }));
    const targetUrl = await startSseTarget();
    const store = openStore({ dataDir });
    const signer = await Signer.load(dataDir);
    const recorder = new Recorder({ store, signer });
    const gateway: GatewayOptions = { policy: loadedPolicy(POLICY), holdStore: new HoldStore(dataDir), pollMs: 20 };
    const proxy = await runHttpProxy({ targetUrl, recorder, redactor: new Redactor(), proxyVersion: '0.0.0-test', gateway });
    cleanups.push(() => proxy.close());

    const res = await fetch(proxy.url, {
      method: 'POST',
      headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 7, method: 'tools/call', params: { name: 'leak', arguments: {} } }),
    });
    expect(res.headers.get('content-type')).toContain('text/event-stream');
    const text = await res.text();
    await proxy.close();

    // The secret-shaped bytes did not cross — not redacted, WITHHELD.
    expect(text).not.toContain(SECRET);
    expect(text).not.toContain('[redacted:sha256:');
    // The client was answered on the id, as a tool error it can read, with
    // the fail-closed clause (nobody decided anything about this call).
    const frames = text.split(/\r?\n\r?\n/).filter((f) => f !== '');
    expect(frames).toHaveLength(3);
    expect(frames[0]).toBe('event: message\r\nid: 7\r\ndata: {"jsonrpc":"2.0","method":"notifications/message","params":{"level":"info","data":"working on it"}}');
    expect(frames[1]!.startsWith('event: message\r\nid: 8\r\ndata: ')).toBe(true);
    const blocked = JSON.parse(frames[1]!.slice('event: message\r\nid: 8\r\ndata: '.length)) as { id: number; result: { isError: boolean; content: Array<{ text: string }> } };
    expect(blocked.id).toBe(7);
    expect(blocked.result.isError).toBe(true);
    expect(blocked.result.content[0]!.text).toContain('withheld');
    expect(blocked.result.content[0]!.text).toContain('could not reach a policy decision');
    expect(frames[2]).toBe('data: {"jsonrpc":"2.0","method":"notifications/message","params":{"level":"info","data":"done"}}');

    // The chain: the raw result was still recorded (hashed) and the withheld
    // event left a protocol_error — an auditor sees that something was
    // withheld here, not a clean allow.
    const events = [...openStore({ dataDir }).iterate()].map((r) => r.event) as AnyEvent[];
    const calls = events.filter((e): e is ToolCallEvent => e.kind === 'tool_call');
    expect(calls).toHaveLength(1);
    expect(JSON.stringify(calls[0])).not.toContain(SECRET);
    const errors = events.filter((e): e is ProtocolErrorEvent => e.kind === 'protocol_error');
    expect(errors.map((e) => [e.direction, e.reason])).toEqual([['server_to_client', 'unparseable']]);
    // NEGATIVE CONTROL: with the old `out = ev.raw` fallback in place, `text`
    // contains SECRET and frames[1] is the vendor's frame verbatim.
  });
});
