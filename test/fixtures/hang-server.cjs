#!/usr/bin/env node
// An MCP server that completes the handshake and then NEVER answers
// tools/list. This is the ordinary case of a slow or wedged server, and it is
// what drives doctor's C4 to INCOMPLETE while the hook leg's connector
// coverage stays non-zero — the state in which "no example could be chosen"
// and "nothing is covered" are different facts.
process.stdin.setEncoding('utf8');
let buf = '';
process.stdin.on('data', (chunk) => {
  buf += chunk;
  let i;
  while ((i = buf.indexOf('\n')) >= 0) {
    const line = buf.slice(0, i).trim();
    buf = buf.slice(i + 1);
    if (line === '') continue;
    let msg;
    try {
      msg = JSON.parse(line);
    } catch {
      continue;
    }
    if (msg.method === 'initialize') {
      process.stdout.write(
        JSON.stringify({
          jsonrpc: '2.0',
          id: msg.id,
          result: {
            protocolVersion: '2024-11-05',
            capabilities: { tools: {} },
            serverInfo: { name: 'hang-server', version: '0.0.0' },
          },
        }) + '\n',
      );
    }
    // tools/list: deliberately no reply, ever.
  }
});
