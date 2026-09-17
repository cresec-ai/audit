/**
 * e2e 1 — `record`: byte transparency, exit-code passthrough, evidence on disk.
 *
 * Driven end to end through `dist/cli.js` against a real stdio server, and
 * asserted on the two artifacts an outsider can check: the bytes the SERVER
 * received (its own journal) and the bytes the CLIENT received (the
 * recorder's stdout, kept as octets).
 *
 * "Byte-transparent" is the load-bearing claim of record mode, and the
 * failure it has to exclude is not "the proxy dropped a message" — it is the
 * quiet one: a proxy that parses a line and re-serializes it. That costs
 * `12345678901234567890` its last three digits, turns `1.0` into `1`, folds
 * `A` into `A` and strips insignificant whitespace, and every one of
 * those is a difference a server or a signature check can see. The repo has
 * met this before: `spliceRewrittenLine` (src/proxy/stdio.ts) exists because
 * re-serializing a whole message to rewrite one string rewrote unrelated
 * numbers in it.
 */

import { describe, expect, it } from 'vitest';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { Buffer } from 'node:buffer';
import {
  INITIALIZE,
  WIRE_SERVER,
  journalToolCalls,
  readChain,
  readJournal,
  runCli,
  startRecorder,
  tmpDir,
} from './helpers/harness.js';
import type { SessionEndEvent, ToolCallEvent } from '../../src/schema/events.js';

/**
 * A line no re-serializer can reproduce: an integer past 2^53, a float that
 * loses its `.0`, an escape that would be folded, a `\/` that would be
 * unescaped, and whitespace that would be dropped.
 */
const AWKWARD_REQUEST =
  '{"jsonrpc":"2.0", "id":2, "method":"tools/call", "params":{"name":"echo","arguments":' +
  '{"big":12345678901234567890,"float":1.0,"esc":"caf\\u00e9 \\u0041","slash":"a\\/b","pad":   "  spaced  "}}}';

const AWKWARD_RESPONSE =
  '{"jsonrpc":"2.0", "id":__ID__, "result":{"content":[{"type":"text","text":"ok"}],' +
  '"big":98765432109876543210,"float":2.0,"esc":"caf\\u00e9 \\u0041"}  }';

function session(dataDir: string, journal: string, env: Record<string, string | undefined> = {}) {
  return startRecorder(
    ['record', '--data-dir', dataDir, '--store', 'jsonl', '--', process.execPath, WIRE_SERVER],
    { E2E_JOURNAL: journal, E2E_RAW_LINE: AWKWARD_RESPONSE, ...env },
  );
}

describe('e2e record: the proxied stream', () => {
  it('forwards client bytes to the server verbatim, awkward JSON and all', async () => {
    const dir = tmpDir('e2e-record-c2s-');
    const dataDir = join(dir, 'data');
    const journal = join(dir, 'journal.jsonl');

    const rec = session(dataDir, journal);
    rec.send(INITIALIZE);
    await rec.response(1);

    // Written as raw bytes, not via send(): the point is that THESE octets
    // arrive, and JSON.stringify would never have produced them.
    rec.writeRaw(AWKWARD_REQUEST + '\n');
    await rec.response(2);

    // CRLF, which the MCP stdio framing tolerates and a naive rewriter eats.
    rec.writeRaw('{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo","arguments":{"crlf":true}}}\r\n');
    await rec.response(3);

    // Not JSON at all. Record mode is a recorder, not a validator: it
    // forwards what it cannot parse and notes a protocol_error.
    rec.writeRaw('this is not json at all\n');

    rec.send({ jsonrpc: '2.0', id: 4, method: 'tools/call', params: { name: 'echo', arguments: { last: true } } });
    await rec.response(4);
    expect(await rec.end()).toBe(0);

    const seen = readJournal(journal).map((e) => e.raw.toString('utf8'));
    expect(seen).toContain(AWKWARD_REQUEST + '\n');
    expect(seen).toContain('{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo","arguments":{"crlf":true}}}\r\n');
    expect(seen).toContain('this is not json at all\n');

    // NEGATIVE CONTROL (in-suite): prove the assertion above discriminates.
    // This is what a proxy that parsed and re-emitted the line would have
    // delivered; it must NOT be what the server saw. Without this arm, a
    // passing test would only mean "some bytes arrived".
    const reserialized = JSON.stringify(JSON.parse(AWKWARD_REQUEST)) + '\n';
    expect(reserialized).not.toBe(AWKWARD_REQUEST + '\n');
    expect(seen).not.toContain(reserialized);
  }, 60_000);

  it('forwards server bytes to the client verbatim, including a line it never asked about', async () => {
    const dir = tmpDir('e2e-record-s2c-');
    const dataDir = join(dir, 'data');
    const journal = join(dir, 'journal.jsonl');

    const rec = session(dataDir, journal);
    rec.send(INITIALIZE);
    await rec.response(1);

    // `wire/raw` makes the server emit E2E_RAW_LINE byte for byte.
    rec.send({ jsonrpc: '2.0', id: 5, method: 'wire/raw' });
    await rec.response(5);
    expect(await rec.end()).toBe(0);

    const expected = Buffer.from(AWKWARD_RESPONSE.split('__ID__').join('5') + '\n', 'utf8');
    expect(rec.stdoutBytes().includes(expected)).toBe(true);

    // NEGATIVE CONTROL (in-suite): the re-serialized form is a different byte
    // string, and it is absent. `98765432109876543210` -> ...872 and `2.0` ->
    // `2` are the two that bite in practice.
    const reserialized = Buffer.from(
      JSON.stringify(JSON.parse(AWKWARD_RESPONSE.split('__ID__').join('5'))) + '\n',
      'utf8',
    );
    expect(reserialized.equals(expected)).toBe(false);
    expect(rec.stdoutBytes().includes(reserialized)).toBe(false);

    // stdout is the MCP wire and nothing else: a diagnostic line that leaked
    // onto it would desynchronise a real client's framing. Every line the
    // recorder emitted has to be a JSON-RPC message the server produced.
    for (const line of rec.stdoutBytes().toString('utf8').split('\n')) {
      if (line.trim() === '') continue;
      expect(() => JSON.parse(line) as unknown, `non-JSON on the wire: ${line}`).not.toThrow();
    }
    expect(rec.stderr()).toContain('[mcp-recorder]');
  }, 60_000);

  it('passes the wrapped server exit code through, and it is not a constant', async () => {
    // NEGATIVE CONTROL (in-suite): three codes, two of them non-zero and
    // distinct. A proxy that hard-coded `process.exit(0)`, or that leaked its
    // own exit code, passes at most one arm of this.
    for (const code of [0, 42, 3]) {
      const dir = tmpDir(`e2e-record-exit-${String(code)}-`);
      const dataDir = join(dir, 'data');
      const journal = join(dir, 'journal.jsonl');
      const rec = session(dataDir, journal, { E2E_EXIT_CODE: String(code), E2E_STDERR: 'wire-server: up' });
      rec.send(INITIALIZE);
      await rec.response(1);
      expect(await rec.end()).toBe(code);

      // The server's own stderr reached the operator's terminal untouched...
      expect(rec.stderr()).toContain('wire-server: up');
      // ...and the recorder's summary went to stderr, never to the MCP wire.
      expect(rec.stderr()).toMatch(/\[mcp-recorder\] session [0-9a-f]{8} recorded \d+ events/);

      const end = readChain(dataDir).at(-1)!.event as SessionEndEvent;
      expect(end.kind).toBe('session_end');
      expect(end.child_exit_code).toBe(code);
    }
  }, 120_000);

  it('writes a verifiable chain, and the tool call in it carries refs rather than values', async () => {
    const dir = tmpDir('e2e-record-evidence-');
    const dataDir = join(dir, 'data');
    const journal = join(dir, 'journal.jsonl');
    const NOTE = 'e2e-evidence-note-4f19c2';

    const rec = session(dataDir, journal);
    rec.send(INITIALIZE);
    await rec.response(1);
    rec.send({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'echo', arguments: { note: NOTE } } });
    await rec.response(2);
    expect(await rec.end()).toBe(0);

    for (const file of ['evidence.jsonl', 'identity.key', 'identity.pub', 'signatures.jsonl']) {
      expect(existsSync(join(dataDir, file)), `${file} should exist`).toBe(true);
    }

    const chain = readChain(dataDir);
    expect(chain.map((r) => r.event.kind)).toEqual(
      expect.arrayContaining(['session_start', 'initialize', 'tool_call', 'session_end']),
    );
    expect(chain.map((r) => r.seq)).toEqual(chain.map((_, i) => i + 1));

    const call = chain.find((r) => r.event.kind === 'tool_call')!.event as ToolCallEvent;
    expect(call.tool).toBe('echo');
    expect(call.is_error).toBe(false);

    // The value went to the server but not into the store: redaction is on by
    // default, so the chain holds a ref of it.
    expect(journalToolCalls(journal)[0]!.arguments).toEqual({ note: NOTE });

    const verify = await runCli(['verify', '--data-dir', dataDir, '--store', 'jsonl']);
    expect(verify.code).toBe(0);
    expect(verify.stdout).toContain('PASS');

    // NEGATIVE CONTROL (in-suite): one byte flipped inside a recorded event
    // must turn that PASS into a FAIL with exit 1. Without this arm "verify
    // said PASS" could mean "verify says PASS about anything".
    const path = join(dataDir, 'evidence.jsonl');
    writeFileSync(path, readFileSync(path, 'utf8').replace('"echo"', '"ech0"'));
    const after = await runCli(['verify', '--data-dir', dataDir, '--store', 'jsonl']);
    expect(after.code).toBe(1);
    expect(after.stdout + after.stderr).toContain('FAIL');
  }, 60_000);

  it('MCP_RECORDER_DISABLE=1 is a real kill switch: traffic flows, nothing is stored', async () => {
    const dir = tmpDir('e2e-record-disabled-');
    const dataDir = join(dir, 'data');
    const journal = join(dir, 'journal.jsonl');

    const rec = session(dataDir, journal, { MCP_RECORDER_DISABLE: '1' });
    rec.send(INITIALIZE);
    await rec.response(1);
    rec.send({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'echo', arguments: { note: 'kill-switch' } } });
    const call = await rec.response(2);
    expect(JSON.stringify(call.result)).toContain('kill-switch');
    expect(await rec.end()).toBe(0);

    // NEGATIVE CONTROL (in-suite): the call DID cross to the server, so an
    // empty data dir means "recording was switched off", not "nothing
    // happened". The documented kill switch is honest in both directions:
    // it stops the recording, not the traffic.
    expect(journalToolCalls(journal).map((c) => c.name)).toContain('echo');
    expect(existsSync(dataDir)).toBe(false);
  }, 60_000);
});
