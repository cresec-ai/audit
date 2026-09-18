#!/usr/bin/env node
/**
 * The e2e fixture server: a real stdio JSON-RPC (MCP-shaped) server that
 * KEEPS A BYTE JOURNAL of everything it was handed.
 *
 * The journal is the point. The recorder's own evidence is the thing under
 * test, so it cannot also be the witness for "what actually crossed to the
 * server" — a swap that never happened, a denied call that got through, or a
 * line the proxy quietly re-serialized would all look fine from the inside.
 * Every raw stdin line is appended to `E2E_JOURNAL` as base64 of the exact
 * octets, terminator included, so whitespace, CRLF, `1.0` vs `1` and integers
 * past 2^53 all survive to the assertion.
 *
 * No dependencies on purpose: this must start in ~40 ms on every platform CI
 * runs, and it must not drag a JSON-RPC library's own framing opinions into a
 * test about bytes.
 *
 * Environment:
 *   E2E_JOURNAL      path to append the byte journal to (required)
 *   E2E_EXIT_CODE    process exit code once stdin closes (default 0)
 *   E2E_STDERR       one line written to stderr at startup
 *   E2E_RAW_LINE     verbatim response line for the `wire/raw` method
 *   E2E_RAW_RESULT   verbatim response line for the `raw` tool
 *                    (in both, `__ID__` is replaced by the request id)
 *   E2E_SECRET       what the `leak` tool puts in its result text
 */
'use strict';

const fs = require('node:fs');

const JOURNAL = process.env.E2E_JOURNAL;
const EXIT_CODE = Number(process.env.E2E_EXIT_CODE ?? '0');

if (process.env.E2E_STDERR !== undefined && process.env.E2E_STDERR !== '') {
  process.stderr.write(process.env.E2E_STDERR + '\n');
}

function journal(rawLine) {
  if (JOURNAL === undefined || JOURNAL === '') return;
  // Append-only, one JSON object per line. `appendFileSync` keeps ordering
  // honest without a buffer that a crash could lose.
  fs.appendFileSync(JOURNAL, JSON.stringify({ b64: rawLine.toString('base64') }) + '\n');
}

function send(msg) {
  process.stdout.write(JSON.stringify(msg) + '\n');
}

function sendRaw(line) {
  process.stdout.write(line + '\n');
}

function text(value) {
  return { content: [{ type: 'text', text: value }] };
}

const TOOLS = [
  { name: 'echo', description: 'Echo the arguments back as JSON text', inputSchema: { type: 'object', additionalProperties: true } },
  { name: 'reflect', description: 'Return the `value` argument verbatim', inputSchema: { type: 'object', additionalProperties: true } },
  { name: 'leak', description: 'Return a secret-shaped string in the result', inputSchema: { type: 'object', additionalProperties: true } },
  { name: 'raw', description: 'Answer with a hand-crafted raw line', inputSchema: { type: 'object', additionalProperties: true } },
  { name: 'post_message', description: 'Pretend to POST somewhere with an Authorization header', inputSchema: { type: 'object', additionalProperties: true } },
];

function handleToolCall(id, params) {
  const name = params && params.name;
  const args = (params && params.arguments) || {};
  switch (name) {
    case 'reflect':
      // The reflection shape: whatever the client sent comes straight back in
      // the result, which is where a value-bound credential swap would hand
      // the real token to the model.
      send({ jsonrpc: '2.0', id, result: text(String(args.value ?? '')) });
      return;
    case 'leak':
      send({ jsonrpc: '2.0', id, result: text(String(args.text ?? process.env.E2E_SECRET ?? '')) });
      return;
    case 'raw': {
      const template = process.env.E2E_RAW_RESULT;
      if (template === undefined || template === '') {
        send({ jsonrpc: '2.0', id, error: { code: -32603, message: 'E2E_RAW_RESULT unset' } });
        return;
      }
      sendRaw(template.split('__ID__').join(String(id)));
      return;
    }
    case 'post_message':
      // Deliberately does NOT echo the credential: only the journal proves
      // what arrived, which is what makes the swap assertion meaningful.
      send({
        jsonrpc: '2.0',
        id,
        result: text(JSON.stringify({ status: 200, url: String(args.url ?? ''), delivered: true })),
      });
      return;
    default:
      send({ jsonrpc: '2.0', id, result: text(JSON.stringify(args)) });
  }
}

function handle(msg) {
  if (typeof msg !== 'object' || msg === null) return;
  const { id, method, params } = msg;
  if (method === undefined) return; // a response to us; not ours to answer
  if (id === undefined || id === null) return; // notification

  switch (method) {
    case 'initialize':
      send({
        jsonrpc: '2.0',
        id,
        result: {
          protocolVersion: '2024-11-05',
          serverInfo: { name: 'wire-server', version: '1.0.0' },
          capabilities: { tools: {} },
        },
      });
      return;
    case 'tools/list':
      send({ jsonrpc: '2.0', id, result: { tools: TOOLS } });
      return;
    case 'tools/call':
      handleToolCall(id, params);
      return;
    case 'wire/raw': {
      const template = process.env.E2E_RAW_LINE;
      if (template === undefined || template === '') {
        send({ jsonrpc: '2.0', id, error: { code: -32603, message: 'E2E_RAW_LINE unset' } });
        return;
      }
      sendRaw(template.split('__ID__').join(String(id)));
      return;
    }
    default:
      send({ jsonrpc: '2.0', id, error: { code: -32601, message: 'Method not found: ' + method } });
  }
}

/* Read stdin as BUFFERS: the journal has to hold the octets, not a decoded
 * approximation of them. Lines are split on 0x0A and kept with their
 * terminator. */
let buf = Buffer.alloc(0);
process.stdin.on('data', (chunk) => {
  buf = Buffer.concat([buf, chunk]);
  for (;;) {
    const nl = buf.indexOf(0x0a);
    if (nl === -1) break;
    const raw = buf.subarray(0, nl + 1);
    buf = buf.subarray(nl + 1);
    journal(raw);
    const trimmed = raw.toString('utf8').replace(/\r?\n$/, '').trim();
    if (trimmed === '') continue;
    let msg;
    try {
      msg = JSON.parse(trimmed);
    } catch {
      continue; // garbage is journalled and ignored, exactly like a real server
    }
    if (Array.isArray(msg)) msg.forEach(handle);
    else handle(msg);
  }
});

process.stdin.on('end', () => {
  if (buf.length > 0) journal(buf);
  process.exitCode = Number.isInteger(EXIT_CODE) ? EXIT_CODE : 0;
});
