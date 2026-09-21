/**
 * e2e 4 — `ship` + the reference receiver: live replication, and the
 * self-check stall on a rewritten store.
 *
 * This is the suite the regression list asks for by name. The shipper's
 * self-check had a passing unit test while a LIVE shipper extended a chain
 * whose history had been rewritten, because the verified frontier is
 * per-process and the unit test never started one (src/sink/selfcheck.ts).
 * Nothing short of two real processes and a socket between them can see that,
 * so:
 *
 *   - `record` gets a sink in its environment and AUTO-STARTS the shipper
 *     itself. That path resolves the CLI to spawn from the running module's
 *     own location (`cliEntryPoint`, src/sink/spawn.ts) — the function whose
 *     unit test passed on Linux and failed on Windows CI for want of the real
 *     URL-building path. Here it is exercised in the built `dist/` layout, on
 *     whichever platform is running the suite, and the proof is that records
 *     turn up in another process's files.
 *   - the tamper arm rewrites an already-delivered event in place, appends a
 *     new session, and starts a FRESH shipper. A stall is the pass condition,
 *     and "the receiver received nothing new" is how it is checked — from the
 *     receiver's own directory, not from the sender's status file.
 */

import { describe, expect, it } from 'vitest';
import { spawn } from 'node:child_process';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import {
  INITIALIZE,
  REPO_ROOT,
  WIRE_SERVER,
  cleanEnv,
  killDetachedShipper,
  readChain,
  runCli,
  startRecorder,
  tmpDir,
  tsxLoader,
  waitFor,
} from './helpers/harness.js';
import { TSX_AVAILABLE, startReceiver } from './helpers/receiver.js';

const TOKEN = 'e2e-ingest-token-0123456789abcdef';

/** One short recorded session against the fixture server. */
async function recordOneSession(
  dataDir: string,
  journal: string,
  note: string,
  env: Record<string, string | undefined> = {},
): Promise<void> {
  const rec = startRecorder(
    ['record', '--data-dir', dataDir, '--store', 'jsonl', '--', process.execPath, WIRE_SERVER],
    { E2E_JOURNAL: journal, ...env },
  );
  rec.send(INITIALIZE);
  await rec.response(1);
  rec.send({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'echo', arguments: { note } } });
  await rec.response(2);
  expect(await rec.end()).toBe(0);
}

describe.skipIf(!TSX_AVAILABLE)('e2e ship: live replication to a real receiver', () => {
  it("a recording session replicates itself, byte for byte, into the receiver's own store", async () => {
    const dir = tmpDir('e2e-ship-live-');
    const dataDir = join(dir, 'data');
    const receiver = await startReceiver(join(dir, 'receiver'), TOKEN);

    // No `ship` command anywhere in this test: `record` starts the shipper.
    await recordOneSession(dataDir, join(dir, 'journal.jsonl'), 'live-replication-e2e', {
      MCP_RECORDER_SINK: receiver.url,
      MCP_RECORDER_SINK_TOKEN: TOKEN,
    });

    const local = readChain(dataDir);
    await waitFor(
      () => {
        const ids = receiver.chainIds();
        return ids.length === 1 && receiver.records(ids[0]!).length >= local.length;
      },
      `the receiver to hold all ${String(local.length)} records`,
      60_000,
    );
    killDetachedShipper(dataDir);

    const chainId = receiver.chainIds()[0]!;
    const replicated = receiver.records(chainId);
    // Byte-identical records, not merely the same count: the receiver
    // recomputes every hash before it stores one, so a difference here would
    // have been a 400 rather than a mismatch — but assert the contents
    // anyway, because "it stored something" is not the claim.
    expect(replicated.map((r) => r.hash)).toEqual(local.map((r) => r.hash));
    expect(JSON.stringify(replicated)).toBe(JSON.stringify(local));
    expect(chainId).toBe(local[0]!.hash);

    // Nothing was refused on the way in.
    expect(receiver.rejections()).toEqual([]);

    // NEGATIVE CONTROL (in-suite): a second session recorded into a SEPARATE
    // data dir with no sink configured must not appear at the receiver. It
    // shares this machine, this receiver and this token; the only difference
    // is the opt-in, and MCP_RECORDER_SINK being the entire opt-in is a
    // documented promise (docs/sink.md). Without this arm, "the receiver has
    // a chain" could just mean "the receiver picks things up somehow".
    const unshippedDir = join(dir, 'unshipped');
    await recordOneSession(unshippedDir, join(dir, 'journal2.jsonl'), 'never-shipped-e2e');
    expect(existsSync(join(unshippedDir, 'ship.lock'))).toBe(false);
    await new Promise((resolve) => setTimeout(resolve, 1_500)); // a shipper's poll interval is 1 s
    expect(receiver.chainIds()).toEqual([chainId]);

    receiver.stop();
  }, 180_000);

  it('a rewritten history stalls the next shipper: nothing new reaches the receiver', async () => {
    const dir = tmpDir('e2e-ship-tamper-');
    const dataDir = join(dir, 'data');
    const journal = join(dir, 'journal.jsonl');
    const receiver = await startReceiver(join(dir, 'receiver'), TOKEN);
    const sinkEnv = { MCP_RECORDER_SINK: receiver.url, MCP_RECORDER_SINK_TOKEN: TOKEN };

    /* --- POSITIVE ARM: an honest store ships ---------------------------- */
    await recordOneSession(dataDir, journal, 'honest-session-e2e');
    const honest = await runCli(['ship', '--drain', '--data-dir', dataDir, '--store', 'jsonl'], sinkEnv);
    expect(honest.code).toBe(0);
    expect(honest.stderr).toContain('ship: delivered');

    const chainId = receiver.chainIds()[0]!;
    const deliveredFirst = receiver.records(chainId).length;
    expect(deliveredFirst).toBe(readChain(dataDir).length);

    /* --- the dogfood-6 attack: edit an event, leave every hash alone ----- */
    // seq 4 is the tool_call of the session just delivered. Same length, so
    // the file's structure is untouched and every stored hash/prev_hash still
    // links exactly as before — which is precisely why the receiver's own
    // fork detection cannot see it and the SENDER has to.
    const evidencePath = join(dataDir, 'evidence.jsonl');
    const before = readFileSync(evidencePath, 'utf8');
    const tampered = before.replace('"tool":"echo"', '"tool":"ech0"');
    expect(tampered).not.toBe(before);
    writeFileSync(evidencePath, tampered);

    // Something new to ship, so the shipper has a batch to self-check.
    await recordOneSession(dataDir, journal, 'after-the-rewrite-e2e');
    const localAfter = readChain(dataDir);
    expect(localAfter.length).toBeGreaterThan(deliveredFirst);

    /* --- a FRESH shipper re-verifies from seq 1 and stalls -------------- */
    const stalled = await runCli(['ship', '--drain', '--data-dir', dataDir, '--store', 'jsonl'], sinkEnv);
    // Fail-open: a stall is loud, never a non-zero exit that would fail a
    // build (docs/sink.md — "put it in a final step with || true").
    expect(stalled.code).toBe(0);
    expect(stalled.stderr).toContain('sink stalled');
    expect(stalled.stderr).toContain('hash_mismatch');

    // The receiver holds exactly what it held before: the shipper withheld
    // the batch rather than posting it and being refused.
    expect(receiver.records(chainId).length).toBe(deliveredFirst);
    expect(receiver.rejections()).toEqual([]);

    // And the condition is legible to an operator without reading a log.
    const status = await runCli(['ship', '--status', '--json', '--data-dir', dataDir, '--store', 'jsonl'], sinkEnv);
    expect(status.code).toBe(0);
    const report = JSON.parse(status.stdout) as { state: string; lag: number; last_error?: string };
    expect(report.state).toBe('stalled');
    expect(report.last_error ?? '').toContain('hash_mismatch');
    expect(report.lag).toBeGreaterThan(0);

    // NEGATIVE CONTROL: the positive arm above. Same binary, same receiver,
    // same token, same data dir, one edited byte apart — it delivered, and
    // `ship: delivered` is in that stderr. Remove the self-check
    // (src/sink/selfcheck.ts) and the second drain delivers too, which is the
    // exact regression this test exists for.
    //
    // `verify` is the independent second opinion on the same store.
    const verify = await runCli(['verify', '--data-dir', dataDir, '--store', 'jsonl']);
    expect(verify.code).toBe(1);
    expect(verify.stdout + verify.stderr).toContain('FAIL');

    killDetachedShipper(dataDir);
    receiver.stop();
  }, 180_000);

  it('S18 pinned enrolment: a sender whose key is not pinned is refused (403) and stores nothing; the pinned key ships, is attested, and its replica exports a bundle that verifies against the pinned key', async () => {
    const dir = tmpDir('e2e-ship-pinned-');
    const dataDir = join(dir, 'data');
    const journal = join(dir, 'journal.jsonl');

    // The recorder's identity exists once it has recorded; the operator pins
    // its PUBLIC half out of band (S18: `receiver-tokens-json` lists the key
    // from `e2e-recorder-identity-key`; here, from <data-dir>/identity.pub).
    await recordOneSession(dataDir, journal, 'pinned-enrolment-e2e');
    // identity.pub holds the raw key as 64 hex (src/chain/keys.ts), the form
    // the receiver's `keys` list and CRESEC_E2E_RECORDER_PUBLIC_KEY_HEX take.
    const ourKey = readFileSync(join(dataDir, 'identity.pub'), 'utf8').trim();
    expect(ourKey).toMatch(/^[0-9a-f]{64}$/);
    const localBefore = readChain(dataDir);

    /* --- NEGATIVE ARM: pinned to somebody else's key -------------------- */
    const strangerKey = 'ab'.repeat(32);
    const wrong = await startReceiver(join(dir, 'receiver-wrong'), TOKEN, { pinnedKeys: [strangerKey] });
    const refused = await runCli(['ship', '--drain', '--data-dir', dataDir, '--store', 'jsonl'], {
      MCP_RECORDER_SINK: wrong.url,
      MCP_RECORDER_SINK_TOKEN: TOKEN,
    });
    // Fail-open on the sender: a refusal is loud, never a non-zero exit, and
    // nothing was delivered.
    expect(refused.code).toBe(0);
    expect(refused.stderr).toContain("sink refused this install's credential (403)");
    expect(refused.stderr).toContain('ship: delivered 0 record(s)');
    // The receiver wrote the refusal down and stored NOTHING.
    expect(wrong.chainIds()).toEqual([]);
    const rejections = wrong.rejections();
    expect(rejections.length).toBeGreaterThan(0);
    expect(rejections[0]).toMatchObject({ status: 403, error: 'forbidden' });
    expect(rejections[0]!.detail).toContain('not enrolled');
    expect(rejections[0]!.detail).toContain(ourKey);
    wrong.stop();
    // And the LOCAL chain is untouched by any of it: same records, still verifies.
    expect(readChain(dataDir)).toEqual(localBefore);
    const verifyLocal = await runCli(['verify', '--data-dir', dataDir, '--store', 'jsonl']);
    expect(verifyLocal.code).toBe(0);
    expect(verifyLocal.stdout).toContain('PASS');

    /* --- POSITIVE ARM: pinned to OUR key -------------------------------- */
    const pinned = await startReceiver(join(dir, 'receiver-pinned'), TOKEN, { pinnedKeys: [ourKey] });
    const delivered = await runCli(['ship', '--drain', '--data-dir', dataDir, '--store', 'jsonl'], {
      MCP_RECORDER_SINK: pinned.url,
      MCP_RECORDER_SINK_TOKEN: TOKEN,
    });
    expect(delivered.code).toBe(0);
    expect(delivered.stderr).toContain('ship: delivered');
    const chainId = pinned.chainIds()[0]!;
    expect(chainId).toBe(localBefore[0]!.hash);
    const replicated = pinned.records(chainId);
    expect(JSON.stringify(replicated)).toBe(JSON.stringify(localBefore));
    expect(pinned.rejections()).toEqual([]);
    // A pinned key is acknowledged the moment it writes: no `new_identity`
    // alert, so every delivered record counts as attested once its head
    // signature arrives.
    expect(pinned.alerts().filter((a) => a.kind === 'new_identity')).toEqual([]);
    pinned.stop();

    // `receiver verify --chain` and `receiver export --chain --out`, the two
    // commands S18's nightly runs over the replica (both flags required).
    const loader = tsxLoader()!;
    const receiverCli = (args: string[]): Promise<{ code: number | null; stdout: string; stderr: string }> =>
      new Promise((resolve) => {
        const child = spawn(process.execPath, ['--import', pathToFileURL(loader).href, join(REPO_ROOT, 'receiver', 'main.ts'), ...args], {
          cwd: REPO_ROOT,
          env: cleanEnv(),
          stdio: ['ignore', 'pipe', 'pipe'],
        });
        let stdout = '';
        let stderr = '';
        child.stdout.setEncoding('utf8');
        child.stderr.setEncoding('utf8');
        child.stdout.on('data', (c: string) => (stdout += c));
        child.stderr.on('data', (c: string) => (stderr += c));
        child.on('close', (code) => resolve({ code, stdout, stderr }));
      });
    const verified = await receiverCli(['verify', '--chain', chainId, '--data-dir', pinned.dataDir]);
    expect(verified.stdout, verified.stderr).toContain('PASS');
    expect(verified.code).toBe(0);
    const bundleDir = join(dir, 'replica-bundle');
    const exported = await receiverCli(['export', '--chain', chainId, '--out', bundleDir, '--data-dir', pinned.dataDir]);
    expect(exported.code, exported.stderr).toBe(0);
    expect(existsSync(join(bundleDir, 'verify.cjs'))).toBe(true);

    // The stranger's verification, pinned to the recorder's public key the
    // way S18 pins CRESEC_E2E_RECORDER_PUBLIC_KEY_HEX: plain node, no repo.
    const stranger = await new Promise<{ code: number | null; stdout: string }>((resolve) => {
      const child = spawn(process.execPath, ['verify.cjs', '--public-key', ourKey], { cwd: bundleDir, stdio: ['ignore', 'pipe', 'pipe'] });
      let stdout = '';
      child.stdout.setEncoding('utf8');
      child.stdout.on('data', (c: string) => (stdout += c));
      child.on('close', (code) => resolve({ code, stdout }));
    });
    expect(stranger.code).toBe(0);
    expect(stranger.stdout).toContain('PASS');
    expect(stranger.stdout).toContain('matches the --public-key you pinned');
    // NEGATIVE CONTROL: pinned to the stranger's key, the same bundle FAILS.
    const mismatch = await new Promise<{ code: number | null }>((resolve) => {
      const child = spawn(process.execPath, ['verify.cjs', '--public-key', strangerKey], { cwd: bundleDir, stdio: ['ignore', 'pipe', 'pipe'] });
      child.on('close', (code) => resolve({ code }));
    });
    expect(mismatch.code).toBe(1);
  }, 180_000);
});
