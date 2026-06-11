#!/usr/bin/env node
/**
 * Minimal MCP-ish JSON-RPC stdio server for proxy tests. No dependencies.
 * One JSON message per \n-delimited line.
 *
 * ECHO_NOISE=1 -> prints one non-JSON line to stdout at startup (exercises
 * the proxy's unparseable path) and writes one line to stderr.
 */
'use strict';

if (process.env.ECHO_NOISE === '1') {
  process.stdout.write('boot: ready\n');
  process.stderr.write('echo-server: noisy startup\n');
}

function send(msg) {
  process.stdout.write(JSON.stringify(msg) + '\n');
}

function reply(id, result) {
  send({ jsonrpc: '2.0', id, result });
}

function replyError(id, code, message) {
  send({ jsonrpc: '2.0', id, error: { code, message } });
}

function handle(msg) {
  if (typeof msg !== 'object' || msg === null) return;
  const { id, method, params } = msg;

  if (method === undefined) return; // a response to us; ignore

  if (id === undefined || id === null) {
    // Notification. 'notifications/initialized' (and anything else) ignored.
    return;
  }

  switch (method) {
    case 'initialize': {
      reply(id, {
        protocolVersion: '2024-11-05',
        serverInfo: { name: 'echo-server', version: '1.0.0' },
        capabilities: {},
      });
      // Server-initiated notification right after the handshake.
      send({
        jsonrpc: '2.0',
        method: 'notifications/message',
        params: { level: 'info', data: 'echo-server online' },
      });
      return;
    }
    case 'tools/list': {
      reply(id, {
        tools: [
          {
            name: 'echo',
            description: 'Echoes its arguments back as text',
            inputSchema: { type: 'object', additionalProperties: true },
          },
        ],
      });
      return;
    }
    case 'tools/call': {
      const args = (params && params.arguments) || {};
      reply(id, { content: [{ type: 'text', text: JSON.stringify(args) }] });
      return;
    }
    case 'echo/delay': {
      const ms = (params && params.ms) || 0;
      setTimeout(() => reply(id, { waited: ms }), ms);
      return;
    }
    default:
      replyError(id, -32601, 'Method not found: ' + method);
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
    let msg;
    try {
      msg = JSON.parse(line);
    } catch {
      continue; // ignore garbage
    }
    if (Array.isArray(msg)) msg.forEach(handle);
    else handle(msg);
  }
});
process.stdin.on('end', () => {
  // Exit once stdin closes (after any pending timers fire).
  process.exitCode = 0;
});
