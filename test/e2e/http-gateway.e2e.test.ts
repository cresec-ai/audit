/**
 * e2e 7 — S17a: `http --policy` in front of a journaling fake vendor MCP,
 * with the per-user token fetched from a fake control plane
 * (`POST /v1/broker/user-token`, cresec-ai/nhi docs/internal/contracts/
 * user-token.md), the identity JWT stamped on every event as the ADR 012
 * actor claim, and the chain verified offline by the bundle's own
 * `verify.cjs`.
 *
 * The three witnesses, none of them the recorder:
 *
 *   1. the VENDOR's request journal — the real per-user token arrived, and
 *      a denied call did not (test/e2e/fixtures/http-server.cjs);
 *   2. the CONTROL PLANE's request journal — the request was the contract's,
 *      field for field (test/e2e/fixtures/control-plane.cjs);
 *   3. the CLIENT's bytes — only the synthetic ever came back.
 *
 * The chain is then read for what it must hold (the synthetic's ref, the
 * control plane's decision_id, the actor) and scanned for what it must not
 * (the access token, its unsalted sha256, the internal token).
 *
 * Every deny arm has the allow arm beside it, and the reason for each deny
 * is asserted — a `control_plane_unavailable` and a `grant_required` must
 * not be confused, because they say different things about the customer.
 */

import { describe, expect, it } from 'vitest';
import { spawn } from 'node:child_process';
import type { ChildProcessByStdio } from 'node:child_process';
import type { Readable } from 'node:stream';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  CLI_JS,
  E2E_FIXTURES,
  REPO_ROOT,
  builtCli,
  cleanEnv,
  expectAbsentFromDataDir,
  onCleanup,
  readChain,
  runCli,
  startRecorder,
  tmpDir,
  waitFor,
} from './helpers/harness.js';
import type { PolicyDecisionEvent, SessionStartEvent, ToolCallEvent } from '../../src/schema/events.js';

const SYNTHETIC = 'cresec_synth_v1_' + Buffer.alloc(32, 0x5a).toString('base64url');
/** Dana's per-user token, as the control plane would hand it out. The canary. */
const ACCESS_TOKEN = 'ya29.e2e-dana-gmail-CANARY-DO-NOT-STORE-3f9a1c';
/** The internal service token the recorder calls the control plane with. Also a canary. */
const INTERNAL_TOKEN = 'e2e-internal-token-fake-0123456789abcdef';
const TENANT_ID = '0b7b4e5a-0c1d-4e2f-8a3b-4c5d6e7f8a9b';
const USER_ID = '3c9f2d0e-4b1a-4f7e-9d21-6a0b1c2d3e4f';
const TOOL_ID = '9e1d7c3a-2f4b-4c6d-8e0f-1a2b3c4d5e6f';

/** An identity JWT the control plane would mint: decoded, not verified (no --identity-jwks here). */
function identityJwt(): string {
  const b64 = (v: unknown): string => Buffer.from(JSON.stringify(v), 'utf8').toString('base64url');
  const now = Math.floor(Date.now() / 1000);
  const claims = {
    iss: 'cresec',
    aud: 'cresec-gateway',
    sub: USER_ID,
    jti: '11111111-2222-4333-8444-555555555555',
    iat: now - 60,
    exp: now + 28_800,
    kind: 'human',
    run_as: 'user',
    tenant_id: TENANT_ID,
    tenant: 'e2e',
    email: 'dana@cresec.ai',
    idp: 'okta',
    idp_sub: '00u1abcXYZ',
    role: 'rep',
    tool: { id: TOOL_ID, name: 'outreach-tool', version: '3' },
    host: { origin: 'https://tool.staging.cresec.ai', kind: 'vercel' },
  };
  // A signature-shaped third segment; nothing verifies it in this suite and
  // the events must say so (identity.actor_verified: false).
  return `${b64({ alg: 'EdDSA', kid: 'e2e-1', typ: 'JWT' })}.${b64(claims)}.${Buffer.alloc(64, 7).toString('base64url')}`;
}

interface Fixture {
  url: string;
  stop(): void;
}

/** Start a fixture that prints `listening <url>` on stdout. */
async function startFixture(script: string, env: Record<string, string>): Promise<Fixture> {
  const child: ChildProcessByStdio<null, Readable, Readable> = spawn(process.execPath, [join(E2E_FIXTURES, script)], {
    cwd: REPO_ROOT,
    env: cleanEnv(env),
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  onCleanup(() => {
    if (child.exitCode === null) child.kill('SIGKILL');
  });
  let stdout = '';
  let stderr = '';
  child.stdout.setEncoding('utf8');
  child.stderr.setEncoding('utf8');
  child.stdout.on('data', (c: string) => (stdout += c));
  child.stderr.on('data', (c: string) => (stderr += c));
  await waitFor(() => /listening\s+\S+/.test(stdout), `${script} to listen (${stderr})`, 30_000);
  const url = /listening\s+(\S+)/.exec(stdout)![1]!;
  return {
    url,
    stop: () => {
      if (child.exitCode === null) child.kill('SIGKILL');
    },
  };
}

interface JournalEntry {
  headers: Record<string, string>;
  b64?: string;
  body?: string;
}
function readJournalFile(path: string): JournalEntry[] {
  if (!existsSync(path)) return [];
  return readFileSync(path, 'utf8')
    .split('\n')
    .filter((l) => l.trim() !== '')
    .map((l) => JSON.parse(l) as JournalEntry);
}
const decoded = (e: JournalEntry): string => Buffer.from(e.b64 ?? '', 'base64').toString('utf8');

function writePolicy(dir: string, controlPlaneUrl: string): string {
  const path = join(dir, 'policy.yaml');
  writeFileSync(
    path,
    [
      'version: 1',
      'name: e2e-http-gateway',
      'mcp:',
      '  default: allow',
      '  rules:',
      '    - id: no-reflect',
      '      match: { tool: reflect }',
      '      action: deny',
      '      reason: reflection is off limits in this session',
      '  boundary: { secrets: redact, injection: flag }',
      'credentials:',
      '  - id: gmail-drafts',
      '    provider: gmail',
      '    broker:',
      '      kind: remote',
      `      url: ${controlPlaneUrl}`,
      '      token_env: CRESEC_INTERNAL_TOKEN',
      '      identity_jwt_env: CRESEC_IDENTITY_JWT',
      '    use:',
      '      - id: draft',
      '        tool: post_message',
      '        arg: headers.Authorization',
      '        host:',
      '          from_arg: url',
      '          allow: [gmail.googleapis.com, mail.example.test]',
      '        action_class: draft',
      '        method: POST',
      '',
    ].join('\n'),
  );
  return path;
}

/** The gateway as the customer runs it: the built CLI, `http --policy`, stopped with Ctrl-C. */
async function startGateway(
  dataDir: string,
  vendorUrl: string,
  policy: string,
  env: Record<string, string | undefined>,
): Promise<{ url: string; stop(): Promise<number | null>; stderr(): string }> {
  const rec = startRecorder(['http', '--target', vendorUrl, '--port', '0', '--data-dir', dataDir, '--store', 'jsonl', '--policy', policy], env);
  await waitFor(() => rec.stderr().includes('http proxy listening at'), `the gateway to listen (${rec.stderr()})`, 30_000);
  const url = /http proxy listening at (\S+)/.exec(rec.stderr())![1]!;
  return {
    url,
    stderr: () => rec.stderr(),
    stop: async () => {
      rec.child.kill('SIGINT');
      return rec.end(30_000);
    },
  };
}

/**
 * Ctrl-C is a clean exit 0 on POSIX. Windows has no SIGINT: child.kill() is
 * TerminateProcess, so the exit code carries no signal there (the same caveat
 * test/gateway-cli.test.ts documents); the assertions on the journals and the
 * chain are what count.
 */
function expectCleanStop(code: number | null): void {
  if (process.platform !== 'win32') expect(code).toBe(0);
}

const post = (url: string, body: unknown): Promise<Response> =>
  fetch(url, { method: 'POST', headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream' }, body: JSON.stringify(body) });

const INITIALIZE = { jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-03-26', clientInfo: { name: 'mcp-recorder-e2e', version: '0.0.1' }, capabilities: {} } };
const draft = (id: number, host: string) => ({
  jsonrpc: '2.0',
  id,
  method: 'tools/call',
  params: { name: 'post_message', arguments: { url: `https://${host}/gmail/v1/users/me/drafts`, headers: { Authorization: `Bearer ${SYNTHETIC}` }, body: 'e2e draft' } },
});

describe('e2e S17a: http --policy with the per-user token from the control plane', () => {
  it('the vendor gets Dana\'s token; the control plane got the contract\'s request; the client and the chain hold only the synthetic, the decision_id and the actor', async () => {
    const dir = tmpDir('e2e-http-gw-');
    const dataDir = join(dir, 'data');
    const vendorJournal = join(dir, 'vendor.jsonl');
    const cpJournal = join(dir, 'control-plane.jsonl');
    const vendor = await startFixture('http-server.cjs', { E2E_JOURNAL: vendorJournal });
    const controlPlane = await startFixture('control-plane.cjs', {
      E2E_CP_JOURNAL: cpJournal,
      E2E_CP_INTERNAL_TOKEN: INTERNAL_TOKEN,
      E2E_CP_TENANT: TENANT_ID,
      E2E_CP_ACCESS_TOKEN: ACCESS_TOKEN,
      E2E_CP_DENY_HOSTS: 'mail.example.test',
    });
    const policy = writePolicy(dir, controlPlane.url);
    const gateway = await startGateway(dataDir, vendor.url, policy, {
      MCP_RECORDER_SYNTHETIC_GMAIL_DRAFTS: SYNTHETIC,
      CRESEC_INTERNAL_TOKEN: INTERNAL_TOKEN,
      CRESEC_IDENTITY_JWT: identityJwt(),
    });

    expect(((await (await post(gateway.url, INITIALIZE)).json()) as { result: { serverInfo: { name: string } } }).result.serverInfo.name).toBe('e2e-vendor-mcp');

    /* --- the allowed draft: swapped at the declared site --------------- */
    const allowed = await post(gateway.url, draft(2, 'gmail.googleapis.com'));
    expect(allowed.status).toBe(200);
    const allowedText = await allowed.text();
    expect(allowedText).toContain('posted (e2e vendor)');

    /* --- an undeclared host: denied by the gateway, the control plane never asked */
    const undeclared = await post(gateway.url, draft(3, 'attacker.example'));
    const undeclaredRes = (await undeclared.json()) as { result: { isError: boolean; content: Array<{ text: string }> } };
    expect(undeclaredRes.result.isError).toBe(true);
    expect(undeclaredRes.result.content[0]!.text).toContain('host_not_allowed');

    /* --- a declared host the CONTROL PLANE denies: 403 grant_required ---- */
    const cpDenied = await post(gateway.url, draft(4, 'mail.example.test'));
    const cpDeniedRes = (await cpDenied.json()) as { result: { isError: boolean; content: Array<{ text: string }> } };
    expect(cpDeniedRes.result.isError).toBe(true);
    expect(cpDeniedRes.result.content[0]!.text).toContain('grant_required');

    /* --- a plain policy deny, no credential involved -------------------- */
    const reflected = await post(gateway.url, { jsonrpc: '2.0', id: 5, method: 'tools/call', params: { name: 'reflect', arguments: { value: 'x' } } });
    expect(((await reflected.json()) as { result: { isError: boolean } }).result.isError).toBe(true);

    /* --- an ordinary allowed call, echoed ------------------------------ */
    const echo = await post(gateway.url, { jsonrpc: '2.0', id: 6, method: 'tools/call', params: { name: 'echo', arguments: { note: 'e2e-http-echo' } } });
    expect(await echo.text()).toContain('e2e-http-echo');

    expectCleanStop(await gateway.stop());
    vendor.stop();
    controlPlane.stop();

    /* 1. the vendor's journal ------------------------------------------- */
    const vendorCalls = readJournalFile(vendorJournal).map(decoded).filter((b) => b.includes('"tools/call"'));
    const postMessages = vendorCalls.filter((b) => b.includes('"post_message"'));
    expect(postMessages).toHaveLength(1); // ids 3 and 4 never crossed
    expect(postMessages[0]).toContain(`Bearer ${ACCESS_TOKEN}`);
    // NEGATIVE CONTROL: the client sent the synthetic; a gateway that
    // forwarded the arguments untouched would put the synthetic here.
    expect(postMessages[0]).not.toContain(SYNTHETIC);
    expect(vendorCalls.some((b) => b.includes('"reflect"'))).toBe(false);
    expect(vendorCalls.some((b) => b.includes('e2e-http-echo'))).toBe(true);

    /* 2. the control plane's journal: the contract, field for field ------ */
    const cpRequests = readJournalFile(cpJournal);
    expect(cpRequests).toHaveLength(2); // the allow and the grant_required deny; never the undeclared host
    for (const r of cpRequests) {
      expect(r.headers.authorization).toBe(`Bearer ${INTERNAL_TOKEN}`);
      expect(r.headers['x-cresec-tenant']).toBe(TENANT_ID);
      expect(r.headers['content-type']).toBe('application/json');
      expect(r.body).not.toContain(SYNTHETIC);
    }
    expect(JSON.parse(cpRequests[0]!.body!)).toEqual({
      user_id: USER_ID,
      connector: 'gmail',
      tool: { id: TOOL_ID, version: '3' },
      action_class: 'draft',
      target: { host: 'gmail.googleapis.com', path_template: '/gmail/v1/users/me/drafts', method: 'POST' },
      run_as: 'user',
      job_token: null,
      run_id: null,
    });
    expect(JSON.parse(cpRequests[1]!.body!)).toMatchObject({ target: { host: 'mail.example.test' } });

    /* 3. the client saw no credential ----------------------------------- */
    expect(allowedText).not.toContain(ACCESS_TOKEN);
    expect(allowedText).not.toContain(INTERNAL_TOKEN);

    /* the chain: what it must not hold ---------------------------------- */
    expectAbsentFromDataDir(dataDir, ACCESS_TOKEN, "Dana's access token");
    expectAbsentFromDataDir(dataDir, INTERNAL_TOKEN, 'the internal token');
    const query = await runCli(['query', ACCESS_TOKEN, '--data-dir', dataDir, '--store', 'jsonl', '--json']);
    expect((JSON.parse(query.stdout) as { matches: unknown[] }).matches).toEqual([]);

    /* the chain: what it must hold -------------------------------------- */
    const chain = readChain(dataDir);
    const events = chain.map((r) => r.event);
    const calls = events.filter((e): e is ToolCallEvent => e.kind === 'tool_call');
    const decisions = events.filter((e): e is PolicyDecisionEvent => e.kind === 'policy_decision');
    const swapped = calls.find((c) => c.request_id === 2)!;
    expect(swapped.gateway?.decision).toBe('allow');
    expect(swapped.attributes['cresec.credential.id']).toBe('gmail-drafts');
    expect(swapped.attributes['cresec.credential.host']).toBe('gmail.googleapis.com');
    const allowDecisionId = String(swapped.attributes['cresec.broker.decision_id']);
    expect(allowDecisionId).toMatch(/^[0-9a-f-]{36}$/);
    // The synthetic is what the chain records for the argument: its REF (unsalted, by design).
    expect(JSON.stringify(swapped.args)).not.toContain(SYNTHETIC);
    expect(JSON.stringify(swapped.args)).toContain('"redacted":true');

    // One policy_decision per refusal, each with a decision_id; the control
    // plane's own id on the one it decided, joined to the same call's
    // `cresec.broker.decision_id`.
    expect(decisions.map((d) => d.request_id)).toEqual([3, 4, 5]);
    for (const d of decisions) expect(d.decision_id).toMatch(/^[0-9a-f-]{36}$/);
    const cpDeny = decisions.find((d) => d.request_id === 4)!;
    expect(cpDeny.attributes['cresec.broker.decision_id']).toBe(cpDeny.decision_id);
    expect(cpDeny.attributes['cresec.credential.deny_reason']).toBe('grant_required');
    const deniedCall = calls.find((c) => c.request_id === 4)!;
    expect(deniedCall.attributes['cresec.policy.decision_id']).toBe(cpDeny.decision_id);
    expect(deniedCall.gateway?.decision).toBe('deny');
    // The undeclared host never reached the control plane: no broker id, a local one.
    const hostDeny = decisions.find((d) => d.request_id === 3)!;
    expect(hostDeny.attributes['cresec.broker.decision_id']).toBeUndefined();
    expect(hostDeny.decision_id).not.toBe(cpDeny.decision_id);

    // The actor, on EVERY event: ADR 012's four fields exactly (what the
    // control plane's own record would carry), and beside it — never inside
    // it — the honest flag that nothing here verified the signature.
    const actor = { user: { id: USER_ID, email: 'dana@cresec.ai', idp: 'okta', idp_sub: '00u1abcXYZ' }, tool: { id: TOOL_ID, name: 'outreach-tool', version: '3' }, host: { origin: 'https://tool.staging.cresec.ai', kind: 'vercel' }, run_as: 'user' };
    expect(events.length).toBeGreaterThan(5);
    for (const e of events) {
      expect(e.identity.actor, e.kind).toEqual(actor);
      expect(e.identity.actor_verified, e.kind).toBe(false);
    }
    expect((events[0] as SessionStartEvent).policy?.name).toBe('e2e-http-gateway');
    expect(events[0]!.server.transport).toBe('http');

    /* the bundle verifies offline, actor events and all ------------------ */
    const bundleDir = join(dir, 'bundle');
    expect((await runCli(['export', '--data-dir', dataDir, '--store', 'jsonl', '--dir', bundleDir])).code).toBe(0);
    const stranger = await new Promise<{ code: number | null; stdout: string }>((resolve) => {
      const child = spawn(process.execPath, ['verify.cjs'], { cwd: bundleDir, stdio: ['ignore', 'pipe', 'pipe'] });
      let stdout = '';
      child.stdout.setEncoding('utf8');
      child.stdout.on('data', (c: string) => (stdout += c));
      child.on('close', (code) => resolve({ code, stdout }));
    });
    expect(stranger.code).toBe(0);
    expect(stranger.stdout).toContain('PASS');
    expect(readFileSync(join(bundleDir, 'events.jsonl'), 'utf8')).toContain('"actor":{');
    // And the DECISIONS column counts the three refusals.
    const sessions = await runCli(['sessions', '--data-dir', dataDir, '--store', 'jsonl', '--json']);
    expect((JSON.parse(sessions.stdout) as Array<{ policy_decision_count: number }>)[0]!.policy_decision_count).toBe(3);
  }, 180_000);

  it('a control plane answering 503 is a deny with reason vault_unavailable; one that is down is control_plane_unavailable — never a crash, never a forward', async () => {
    const dir = tmpDir('e2e-http-gw-503-');
    const vendorJournal = join(dir, 'vendor.jsonl');
    const vendor = await startFixture('http-server.cjs', { E2E_JOURNAL: vendorJournal });

    const run = async (mode: '503' | 'down', expectReason: string): Promise<void> => {
      const dataDir = join(dir, `data-${mode}`);
      const controlPlane = await startFixture('control-plane.cjs', {
        E2E_CP_JOURNAL: join(dir, `cp-${mode}.jsonl`),
        E2E_CP_INTERNAL_TOKEN: INTERNAL_TOKEN,
        E2E_CP_TENANT: TENANT_ID,
        E2E_CP_ACCESS_TOKEN: ACCESS_TOKEN,
        E2E_CP_MODE: mode,
      });
      const policy = writePolicy(dir, controlPlane.url);
      const gateway = await startGateway(dataDir, vendor.url, policy, {
        MCP_RECORDER_SYNTHETIC_GMAIL_DRAFTS: SYNTHETIC,
        CRESEC_INTERNAL_TOKEN: INTERNAL_TOKEN,
        CRESEC_IDENTITY_JWT: identityJwt(),
      });
      const res = await post(gateway.url, draft(2, 'gmail.googleapis.com'));
      expect(res.status).toBe(200);
      const body = (await res.json()) as { result: { isError: boolean; content: Array<{ text: string }> } };
      expect(body.result.isError).toBe(true);
      expect(body.result.content[0]!.text).toContain(expectReason);
      // Fail CLOSED, not "fail open when the control plane is away".
      expect(body.result.content[0]!.text).not.toContain(ACCESS_TOKEN);
      expectCleanStop(await gateway.stop());
      controlPlane.stop();
      const decisions = readChain(dataDir).map((r) => r.event).filter((e): e is PolicyDecisionEvent => e.kind === 'policy_decision');
      expect(decisions).toHaveLength(1);
      expect(decisions[0]!.attributes['cresec.credential.deny_reason']).toBe(expectReason);
      expect(decisions[0]!.decision_id).toMatch(/^[0-9a-f-]{36}$/);
      expectAbsentFromDataDir(dataDir, ACCESS_TOKEN, "Dana's access token");
    };
    await run('503', 'vault_unavailable');
    await run('down', 'control_plane_unavailable');
    vendor.stop();
    // NEGATIVE CONTROL: nothing reached the vendor in either arm.
    expect(readJournalFile(vendorJournal).map(decoded).filter((b) => b.includes('post_message'))).toEqual([]);
  }, 180_000);

  it('without --policy the http proxy is the byte-for-byte recorder it always was (the record-only e2e is the control)', async () => {
    // Belt and braces beside test/http-proxy.test.ts: the built binary, no
    // policy, a synthetic in the arguments crosses UNTOUCHED (no broker was
    // ever wired) and nothing about the exchange is buffered or rewritten.
    const dir = tmpDir('e2e-http-plain-');
    const vendorJournal = join(dir, 'vendor.jsonl');
    const vendor = await startFixture('http-server.cjs', { E2E_JOURNAL: vendorJournal });
    const rec = startRecorder(['http', '--target', vendor.url, '--port', '0', '--data-dir', join(dir, 'data'), '--store', 'jsonl'], {
      MCP_RECORDER_SYNTHETIC_GMAIL_DRAFTS: SYNTHETIC,
    });
    await waitFor(() => rec.stderr().includes('http proxy listening at'), 'the proxy to listen', 30_000);
    const url = /http proxy listening at (\S+)/.exec(rec.stderr())![1]!;
    const raw = '{"jsonrpc":"2.0", "id":2, "method":"tools/call", "params":{"name":"post_message","arguments":{"big":12345678901234567890,"headers":{"Authorization":"Bearer ' + SYNTHETIC + '"}}}}';
    const res = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: raw });
    expect(res.status).toBe(200);
    rec.child.kill('SIGINT');
    expectCleanStop(await rec.end(30_000));
    vendor.stop();
    expect(readJournalFile(vendorJournal).map(decoded)).toEqual([raw]);
    expect(rec.stderr()).not.toContain('gateway');
    expect(existsSync(CLI_JS)).toBe(true);
    expect(builtCli()).toBe(CLI_JS);
  }, 120_000);
});
