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
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  INITIALIZE,
  WIRE_SERVER,
  killDetachedShipper,
  readChain,
  runCli,
  startRecorder,
  tmpDir,
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
});
