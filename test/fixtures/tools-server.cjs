#!/usr/bin/env node
/**
 * A minimal stdio MCP server with a REALISTIC tool vocabulary, for the
 * `protect` / `doctor` tests.
 *
 * `echo-server.cjs` exposes one tool called `echo`, which the starter policy
 * correctly matches no name rule against — useful for proving doctor FAILS on
 * "enforcement is on and matches nothing", and useless for proving it passes.
 * This one exposes the shapes real servers use, so a test can tell the two
 * apart: a read, a write, a delete (held), a send (held) and a shell.
 *
 * `tools/call` echoes its arguments back. Nothing here touches the disk — a
 * call that reaches this server has, by construction, been ALLOWED, and the
 * tests assert on what the gateway did before that.
 */

'use strict';

const TOOLS = [
  { name: 'read_text_file', description: 'Read a file' },
  { name: 'write_file', description: 'Write a file' },
  { name: 'delete_file', description: 'Delete a file' },
  { name: 'send_message', description: 'Send a message to someone' },
  { name: 'bash', description: 'Run a shell command' },
];

function send(msg) {
  process.stdout.write(JSON.stringify(msg) + '\n');
}

function handle(msg) {
  const { id, method, params } = msg || {};
  if (id === undefined) return; // a notification
  switch (method) {
    case 'initialize':
      send({
        jsonrpc: '2.0',
        id,
        result: {
          protocolVersion: '2024-11-05',
          serverInfo: { name: 'tools-server', version: '1.0.0' },
          capabilities: {},
        },
      });
      return;
    case 'tools/list':
      send({
        jsonrpc: '2.0',
        id,
        result: {
          tools: TOOLS.map((t) => ({ ...t, inputSchema: { type: 'object', additionalProperties: true } })),
        },
      });
      return;
    case 'tools/call':
      send({
        jsonrpc: '2.0',
        id,
        result: { content: [{ type: 'text', text: JSON.stringify((params && params.arguments) || {}) }] },
      });
      return;
    default:
      send({ jsonrpc: '2.0', id, error: { code: -32601, message: 'Method not found: ' + method } });
  }
}

let buf = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', (chunk) => {
  buf += chunk;
  let nl;
  while ((nl = buf.indexOf('\n')) !== -1) {
    const line = buf.slice(0, nl).replace(/\r$/, '');
    buf = buf.slice(nl + 1);
    if (line.trim() === '') continue;
    try {
      handle(JSON.parse(line));
    } catch {
      /* ignore garbage */
    }
  }
});
process.stdin.on('end', () => {
  process.exitCode = 0;
});
