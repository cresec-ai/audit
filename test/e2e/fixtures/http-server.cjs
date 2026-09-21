#!/usr/bin/env node
/**
 * The e2e fixture for the HTTP transport: a real streamable-HTTP JSON-RPC
 * (MCP-shaped) server that KEEPS A BYTE JOURNAL of every request body it was
 * handed — the vendor's remote MCP, as far as `http --policy` can tell.
 *
 * As with wire-server.cjs, the journal is the point: the recorder's own
 * evidence is the thing under test, so it cannot also be the witness for
 * "what actually crossed to the vendor". Every request body is appended to
 * `E2E_JOURNAL` as base64 of the exact octets, with the request headers.
 *
 * Tools: `echo` (arguments back as text), `post_message` (answers a fixed
 * text and NEVER echoes its Authorization header — only the journal proves
 * what arrived, which is what makes the swap assertion meaningful),
 * `reflect` (the `value` argument back verbatim). `E2E_SSE=1` answers
 * tools/call over text/event-stream instead of application/json.
 *
 * Prints `listening http://127.0.0.1:<port>/mcp` on stdout once bound.
 */
'use strict';

const fs = require('node:fs');
const http = require('node:http');

const JOURNAL = process.env.E2E_JOURNAL;
const SSE = process.env.E2E_SSE === '1';

function journal(entry) {
  if (JOURNAL === undefined || JOURNAL === '') return;
  fs.appendFileSync(JOURNAL, JSON.stringify(entry) + '\n');
}

function text(value) {
  return { content: [{ type: 'text', text: value }] };
}

function answer(msg) {
  const id = msg.id;
  if (msg.method === 'initialize') {
    return { jsonrpc: '2.0', id, result: { protocolVersion: '2025-03-26', serverInfo: { name: 'e2e-vendor-mcp', version: '1.0.0' }, capabilities: { tools: {} } } };
  }
  if (msg.method === 'tools/list') {
    return { jsonrpc: '2.0', id, result: { tools: [{ name: 'echo' }, { name: 'post_message' }, { name: 'reflect' }] } };
  }
  if (msg.method === 'tools/call') {
    const name = msg.params && msg.params.name;
    const args = (msg.params && msg.params.arguments) || {};
    if (name === 'post_message') return { jsonrpc: '2.0', id, result: text('posted (e2e vendor)') };
    if (name === 'reflect') return { jsonrpc: '2.0', id, result: text(String(args.value ?? '')) };
    return { jsonrpc: '2.0', id, result: text(JSON.stringify(args)) };
  }
  return { jsonrpc: '2.0', id, error: { code: -32601, message: `unknown method ${String(msg.method)}` } };
}

const server = http.createServer((req, res) => {
  const chunks = [];
  req.on('data', (c) => chunks.push(c));
  req.on('end', () => {
    const body = Buffer.concat(chunks);
    journal({ method: req.method, url: req.url, headers: req.headers, b64: body.toString('base64') });
    if (req.method !== 'POST') {
      res.writeHead(405, { allow: 'POST' });
      res.end();
      return;
    }
    let msg;
    try {
      msg = JSON.parse(body.toString('utf8'));
    } catch {
      res.writeHead(400, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'parse error' } }));
      return;
    }
    if (msg.id === undefined) {
      res.writeHead(202);
      res.end();
      return;
    }
    const out = JSON.stringify(answer(msg));
    if (SSE) {
      res.writeHead(200, { 'content-type': 'text/event-stream', 'cache-control': 'no-cache' });
      res.write(`event: message\ndata: ${out}\n\n`);
      res.end();
      return;
    }
    res.writeHead(200, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(out) });
    res.end(out);
  });
});

server.listen(0, '127.0.0.1', () => {
  process.stdout.write(`listening http://127.0.0.1:${server.address().port}/mcp\n`);
});
