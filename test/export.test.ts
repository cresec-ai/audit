import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import {
  createWriteStream,
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { inflateRawSync } from 'node:zlib';
import yazl from 'yazl';
import { spawnTsxSync } from './helpers/tsx.js';
import { GENESIS_HASH, makeRecord, sha256Ref } from '../src/chain/hash.js';
import { Signer, publicKeyPem } from '../src/chain/keys.js';
import { openStore } from '../src/store/index.js';
import { exportBundle, BUNDLE_FILES } from '../src/export/bundle.js';
import { verifyRecords } from '../src/verify/verify.js';
import type { ChainHead, EvidenceStore } from '../src/types.js';
import type {
  AnyEvent,
  ChainRecord,
  IdentityContext,
  ServerContext,
  SessionStartEvent,
  ToolCallEvent,
} from '../src/schema/events.js';
import { SCHEMA } from '../src/schema/events.js';

const ROOT = fileURLToPath(new URL('..', import.meta.url));

/* ------------------------------ fixtures ------------------------------ */

const IDENTITY: IdentityContext = { fingerprint: sha256Ref('export-test-identity') };
const SERVER: ServerContext = {
  name: 'export-test-server',
  command: 'node server.js',
  transport: 'stdio',
};
const SESSION_A = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const SESSION_B = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';

let eventCounter = 0;

function fakeUuid(): string {
  return `00000000-0000-4000-8000-${(eventCounter++).toString(16).padStart(12, '0')}`;
}

function sessionStart(sessionId: string, n: number): SessionStartEvent {
  return {
    schema: SCHEMA,
    event_id: fakeUuid(),
    session_id: sessionId,
    timestamp: new Date(Date.UTC(2026, 5, 11, 10, 0, n)).toISOString(),
    kind: 'session_start',
    identity: IDENTITY,
    server: SERVER,
    attributes: {},
    proxy_version: '0.1.0',
    cwd: '/tmp',
    redaction_mode: 'allowlist',
  };
}

function toolCall(sessionId: string, n: number, tool = 'list_issues'): ToolCallEvent {
  return {
    schema: SCHEMA,
    event_id: fakeUuid(),
    session_id: sessionId,
    timestamp: new Date(Date.UTC(2026, 5, 11, 10, 0, n)).toISOString(),
    kind: 'tool_call',
    identity: IDENTITY,
    server: SERVER,
    attributes: { 'gen_ai.tool.name': tool },
    tool,
    request_id: n,
    args: { repo: { redacted: true, ref: sha256Ref('hello-world'), len: 11 } },
    result_hash: sha256Ref('{"ok":true}'),
    result: { ok: true },
    is_error: false,
    duration_ms: 3,
  };
}

function seal(events: AnyEvent[], head: ChainHead = { seq: 0, hash: GENESIS_HASH }): ChainRecord[] {
  const out: ChainRecord[] = [];
  let h = head;
  for (const event of events) {
    const record = makeRecord(h, event);
    out.push(record);
    h = { seq: record.seq, hash: record.hash };
  }
  return out;
}

/**
 * Ten events across two interleaved sessions. Session B spans seq 3..8 with
 * session A records woven through (seq 4 and 7) — exercising the contiguous
 * range selection of session-scoped exports.
 */
function tenRecords(): ChainRecord[] {
  return seal([
    sessionStart(SESSION_A, 0), //  seq 1  A
    toolCall(SESSION_A, 1), //      seq 2  A
    sessionStart(SESSION_B, 2), //  seq 3  B
    toolCall(SESSION_A, 3), //      seq 4  A (interleaved)
    toolCall(SESSION_B, 4), //      seq 5  B
    toolCall(SESSION_B, 5, 'create_issue'), // seq 6  B
    toolCall(SESSION_A, 6), //      seq 7  A (interleaved)
    toolCall(SESSION_B, 7, 'search_code'), //  seq 8  B
    toolCall(SESSION_A, 8), //      seq 9  A
    toolCall(SESSION_A, 9), //      seq 10 A
  ]);
}

function runVerifyCjs(
  bundleDir: string,
  args: string[] = [],
): { status: number | null; stdout: string } {
  const result = spawnSync(process.execPath, [BUNDLE_FILES.VERIFY, ...args], {
    cwd: bundleDir,
    encoding: 'utf8',
  });
  return { status: result.status, stdout: result.stdout };
}

/**
 * Minimal standalone ZIP entry reader (central directory -> local header ->
 * stored/deflate data), independent of anything in src/. yauzl is not
 * installed (see the note below), so this is what closes the "rely on dir
 * mode for content-level checks" gap: it proves the .zip exportBundle writes
 * actually decodes back to the same bytes as dir mode, not just that some
 * non-trivial file exists.
 */
function readZipEntry(zipPath: string, name: string): Buffer {
  const buf = readFileSync(zipPath);
  const eocd = buf.lastIndexOf(Buffer.from([0x50, 0x4b, 0x05, 0x06]));
  expect(eocd).toBeGreaterThanOrEqual(0);
  const totalEntries = buf.readUInt16LE(eocd + 10);
  let pos = buf.readUInt32LE(eocd + 16);
  for (let i = 0; i < totalEntries; i++) {
    expect(buf.readUInt32LE(pos)).toBe(0x02014b50); // central dir signature
    const method = buf.readUInt16LE(pos + 10);
    const compressedSize = buf.readUInt32LE(pos + 20);
    const nameLen = buf.readUInt16LE(pos + 28);
    const extraLen = buf.readUInt16LE(pos + 30);
    const commentLen = buf.readUInt16LE(pos + 32);
    const localHeaderOffset = buf.readUInt32LE(pos + 42);
    const entryName = buf.toString('utf8', pos + 46, pos + 46 + nameLen);
    pos += 46 + nameLen + extraLen + commentLen;
    if (entryName !== name) continue;

    expect(buf.readUInt32LE(localHeaderOffset)).toBe(0x04034b50); // local header signature
    const localNameLen = buf.readUInt16LE(localHeaderOffset + 26);
    const localExtraLen = buf.readUInt16LE(localHeaderOffset + 28);
    const dataStart = localHeaderOffset + 30 + localNameLen + localExtraLen;
    const compressed = buf.subarray(dataStart, dataStart + compressedSize);
    return method === 0 ? Buffer.from(compressed) : inflateRawSync(compressed);
  }
  throw new Error(`entry ${name} not found in ${zipPath}`);
}

/** Zip up every file currently in a bundle directory (post-tamper contents included). */
async function zipBundleDir(bundleDir: string, zipPath: string): Promise<void> {
  const zf = new yazl.ZipFile();
  for (const name of Object.values(BUNDLE_FILES)) {
    zf.addBuffer(readFileSync(join(bundleDir, name)), name);
  }
  await new Promise<void>((resolve, reject) => {
    const out = createWriteStream(zipPath);
    out.on('close', () => resolve());
    out.on('error', reject);
    zf.outputStream.on('error', reject);
    zf.outputStream.pipe(out);
    zf.end();
  });
}

function runCliVerifyBundle(bundlePath: string): { status: number | null; stdout: string } {
  const result = spawnTsxSync(['src/cli.ts', 'verify', '--bundle', bundlePath], {
    cwd: ROOT,
    encoding: 'utf8',
  });
  return { status: result.status, stdout: result.stdout };
}

/* -------------------------------- suite -------------------------------- */

describe('exportBundle', () => {
  let dir: string;
  let records: ChainRecord[];
  let signer: Signer;
  let store: EvidenceStore;

  beforeEach(async () => {
    dir = mkdtempSync(join(tmpdir(), 'mcp-recorder-export-'));
    records = tenRecords();
    signer = await Signer.load(join(dir, 'data'));
    store = openStore({ dataDir: join(dir, 'data'), backend: 'jsonl' });
    store.append(records);
  });

  afterEach(() => {
    try {
      store.close();
    } catch {
      /* already closed */
    }
    rmSync(dir, { recursive: true, force: true });
  });

  it('dir mode: sane manifest, five files, and a stranger-verifiable bundle', async () => {
    const bundleDir = join(dir, 'bundle');
    const manifest = await exportBundle({
      store,
      dirPath: bundleDir,
      toolVersion: '0.1.0-test',
      signer,
    });

    // Manifest sanity.
    expect(manifest.bundle).toBe('edut.mcp-recorder.bundle.v1');
    expect(manifest.tool_version).toBe('0.1.0-test');
    expect(manifest.session_id).toBeUndefined();
    expect(manifest.range).toEqual({ from_seq: 1, to_seq: 10 });
    expect(manifest.base_hash).toBe(GENESIS_HASH);
    expect(manifest.head_hash).toBe(records[9]!.hash);
    expect(manifest.event_count).toBe(10);
    expect(manifest.signature.seq).toBe(10);
    expect(manifest.signature.chain_hash).toBe(records[9]!.hash);
    expect(manifest.signature.public_key).toBe(signer.publicKeyHex);
    expect(manifest.public_key_pem).toContain('-----BEGIN PUBLIC KEY-----');

    // All five files exist.
    for (const name of Object.values(BUNDLE_FILES)) {
      expect(existsSync(join(bundleDir, name)), `${name} should exist`).toBe(true);
    }

    // events.jsonl round-trips the exact records, in seq order.
    const lines = readFileSync(join(bundleDir, BUNDLE_FILES.EVENTS), 'utf8')
      .split('\n')
      .filter((line) => line.trim() !== '');
    expect(lines.map((line) => JSON.parse(line) as ChainRecord)).toEqual(records);

    // manifest.json on disk matches the returned manifest.
    const onDisk = JSON.parse(readFileSync(join(bundleDir, BUNDLE_FILES.MANIFEST), 'utf8'));
    expect(onDisk).toEqual(manifest);

    // README has the promised four lines.
    const readme = readFileSync(join(bundleDir, BUNDLE_FILES.README), 'utf8');
    expect(readme.trimEnd().split('\n')).toHaveLength(4);
    expect(readme).toContain('node verify.cjs');

    // Our own verifier accepts the exported segment + fresh signature.
    const ours = await verifyRecords(
      lines.map((line) => JSON.parse(line) as ChainRecord),
      [manifest.signature],
      { baseHash: manifest.base_hash, expectedPublicKeyHex: signer.publicKeyHex },
    );
    expect(ours.ok).toBe(true);
    expect(ours.verified_signature?.seq).toBe(10);

    // The stranger's path: node verify.cjs, zero deps, exit 0 + PASS.
    const verdict = runVerifyCjs(bundleDir);
    expect(verdict.stdout).toContain('PASS');
    expect(verdict.status).toBe(0);
  });

  it('a tampered bundle makes verify.cjs exit 1 with FAIL', async () => {
    const bundleDir = join(dir, 'bundle-tampered');
    await exportBundle({ store, dirPath: bundleDir, toolVersion: '0.1.0-test', signer });

    const eventsPath = join(bundleDir, BUNDLE_FILES.EVENTS);
    const lines = readFileSync(eventsPath, 'utf8')
      .split('\n')
      .filter((line) => line.trim() !== '');
    const record = JSON.parse(lines[4]!) as ChainRecord;
    (record.event as ToolCallEvent).tool = 'doctored_tool';
    lines[4] = JSON.stringify(record);
    writeFileSync(eventsPath, lines.join('\n') + '\n');

    const verdict = runVerifyCjs(bundleDir);
    expect(verdict.status).toBe(1);
    expect(verdict.stdout).toContain('FAIL');
    expect(verdict.stdout).toContain('seq 5'); // pinpoints the first failing seq
  });

  it('a truncated bundle makes verify.cjs exit 1 with FAIL', async () => {
    const bundleDir = join(dir, 'bundle-truncated');
    await exportBundle({ store, dirPath: bundleDir, toolVersion: '0.1.0-test', signer });

    const eventsPath = join(bundleDir, BUNDLE_FILES.EVENTS);
    const lines = readFileSync(eventsPath, 'utf8')
      .split('\n')
      .filter((line) => line.trim() !== '');
    writeFileSync(eventsPath, lines.slice(0, 8).join('\n') + '\n');

    const verdict = runVerifyCjs(bundleDir);
    expect(verdict.status).toBe(1);
    expect(verdict.stdout).toContain('FAIL');
  });

  it('a bundle with its signature deleted makes verify.cjs exit 1 with FAIL', async () => {
    const bundleDir = join(dir, 'bundle-unsigned');
    const manifest = await exportBundle({
      store,
      dirPath: bundleDir,
      toolVersion: '0.1.0-test',
      signer,
    });

    const manifestPath = join(bundleDir, BUNDLE_FILES.MANIFEST);
    const onDisk = JSON.parse(readFileSync(manifestPath, 'utf8')) as Record<string, unknown>;
    expect(onDisk.signature).toEqual(manifest.signature); // sanity: it really was there
    delete onDisk.signature;
    writeFileSync(manifestPath, JSON.stringify(onDisk, null, 2) + '\n');

    const verdict = runVerifyCjs(bundleDir);
    expect(verdict.status).toBe(1);
    expect(verdict.stdout).toContain('FAIL');
    expect(verdict.stdout).toContain('manifest.signature');
  });

  it('verify.cjs --public-key pins to an externally-obtained key: accepts the real one, rejects any other', async () => {
    const bundleDir = join(dir, 'bundle-pinned');
    await exportBundle({ store, dirPath: bundleDir, toolVersion: '0.1.0-test', signer });

    // The correct key, passed as raw hex.
    const okHex = runVerifyCjs(bundleDir, ['--public-key', signer.publicKeyHex]);
    expect(okHex.status).toBe(0);
    expect(okHex.stdout).toContain('PASS');
    expect(okHex.stdout).toContain('independently verified');

    // The correct key, passed as a path to the bundled PEM (also valid input).
    const okPem = runVerifyCjs(bundleDir, [
      '--public-key',
      join(bundleDir, BUNDLE_FILES.PUBLIC_KEY),
    ]);
    expect(okPem.status).toBe(0);
    expect(okPem.stdout).toContain('PASS');

    // An unrelated (but well-formed) key is rejected, even though the bundle
    // is internally self-consistent and self-pinned verification would pass.
    const otherSigner = await Signer.load(join(dir, 'other-signer'));
    const bad = runVerifyCjs(bundleDir, ['--public-key', otherSigner.publicKeyHex]);
    expect(bad.status).toBe(1);
    expect(bad.stdout).toContain('FAIL');
    expect(bad.stdout).toContain('unexpected key');

    // Without --public-key at all, the bundle still verifies (self-pinned)
    // but says so isn't independently checked.
    const unpinned = runVerifyCjs(bundleDir);
    expect(unpinned.status).toBe(0);
    expect(unpinned.stdout).toContain('NOT independently verified');
  });

  it('session-scoped export covers the contiguous range incl. interleaved records', async () => {
    const bundleDir = join(dir, 'bundle-session');
    const manifest = await exportBundle({
      store,
      sessionId: SESSION_B,
      dirPath: bundleDir,
      toolVersion: '0.1.0-test',
      signer,
    });

    // Session B owns seq 3,5,6,8 — the bundle must carry the contiguous run
    // 3..8 including the interleaved session-A records at seq 4 and 7.
    expect(manifest.session_id).toBe(SESSION_B);
    expect(manifest.range).toEqual({ from_seq: 3, to_seq: 8 });
    expect(manifest.event_count).toBe(6);
    expect(manifest.base_hash).toBe(records[1]!.hash); // hash of seq 2
    expect(manifest.head_hash).toBe(records[7]!.hash); // hash of seq 8
    expect(manifest.signature.seq).toBe(8);

    const bundled = readFileSync(join(bundleDir, BUNDLE_FILES.EVENTS), 'utf8')
      .split('\n')
      .filter((line) => line.trim() !== '')
      .map((line) => JSON.parse(line) as ChainRecord);
    expect(bundled.map((r) => r.seq)).toEqual([3, 4, 5, 6, 7, 8]);
    expect(bundled.map((r) => r.event.session_id)).toEqual([
      SESSION_B,
      SESSION_A,
      SESSION_B,
      SESSION_B,
      SESSION_A,
      SESSION_B,
    ]);

    const verdict = runVerifyCjs(bundleDir);
    expect(verdict.stdout).toContain('PASS');
    expect(verdict.status).toBe(0);
  });

  it('zipPath mode produces a non-trivial .zip (and can combine with dirPath)', async () => {
    const zipPath = join(dir, 'out', 'evidence.zip');
    const bundleDir = join(dir, 'bundle-both');
    const manifest = await exportBundle({
      store,
      zipPath,
      dirPath: bundleDir,
      toolVersion: '0.1.0-test',
      signer,
    });

    expect(manifest.event_count).toBe(10);
    expect(existsSync(zipPath)).toBe(true);
    expect(statSync(zipPath).size).toBeGreaterThan(500);
    expect(existsSync(join(bundleDir, BUNDLE_FILES.MANIFEST))).toBe(true);

    // yauzl is not installed, so decode the .zip's entries directly (see
    // readZipEntry above) and confirm they match dir mode byte-for-byte —
    // not just "some non-trivial file exists".
    for (const name of Object.values(BUNDLE_FILES)) {
      const fromZip = readZipEntry(zipPath, name);
      const fromDir = readFileSync(join(bundleDir, name));
      expect(fromZip.equals(fromDir), `${name} should round-trip through the zip`).toBe(true);
    }
  });

  it('rejects an export with no destination, an empty store, and an unknown session', async () => {
    await expect(
      exportBundle({ store, toolVersion: '0.1.0-test', signer }),
    ).rejects.toThrow(/dirPath and\/or zipPath/);

    await expect(
      exportBundle({
        store,
        sessionId: 'no-such-session',
        dirPath: join(dir, 'nope'),
        toolVersion: '0.1.0-test',
        signer,
      }),
    ).rejects.toThrow(/no events recorded for session/);

    const emptyStore = openStore({ dataDir: join(dir, 'empty'), backend: 'jsonl' });
    try {
      await expect(
        exportBundle({
          store: emptyStore,
          dirPath: join(dir, 'nope2'),
          toolVersion: '0.1.0-test',
          signer,
        }),
      ).rejects.toThrow(/empty store/);
    } finally {
      emptyStore.close();
    }
  });

  it('export --out .zip, then `mcp-recorder verify --bundle` on it: PASS; a tampered .zip: FAIL', async () => {
    const zipPath = join(dir, 'evidence.zip');
    await exportBundle({ store, zipPath, toolVersion: '0.1.0-test', signer });

    const ok = spawnTsxSync(['src/cli.ts', 'verify', '--bundle', zipPath], {
      cwd: ROOT,
      encoding: 'utf8',
    });
    expect(ok.status).toBe(0);
    expect(ok.stdout).toContain('PASS');

    // Tamper by rebuilding the zip with one doctored event, same shape as
    // the directory-mode tamper test above.
    const eventsBuf = readZipEntry(zipPath, BUNDLE_FILES.EVENTS);
    const lines = eventsBuf
      .toString('utf8')
      .split('\n')
      .filter((line) => line.trim() !== '');
    const record = JSON.parse(lines[4]!) as ChainRecord;
    (record.event as ToolCallEvent).tool = 'doctored_tool';
    lines[4] = JSON.stringify(record);

    const tamperedZip = join(dir, 'evidence-tampered.zip');
    const zf = new yazl.ZipFile();
    for (const name of Object.values(BUNDLE_FILES)) {
      const data = name === BUNDLE_FILES.EVENTS ? Buffer.from(lines.join('\n') + '\n', 'utf8') : readZipEntry(zipPath, name);
      zf.addBuffer(data, name);
    }
    await new Promise<void>((res, reject) => {
      const out = createWriteStream(tamperedZip);
      out.on('close', res);
      out.on('error', reject);
      zf.outputStream.on('error', reject);
      zf.outputStream.pipe(out);
      zf.end();
    });

    const bad = spawnTsxSync(['src/cli.ts', 'verify', '--bundle', tamperedZip], {
      cwd: ROOT,
      encoding: 'utf8',
    });
    expect(bad.status).toBe(1);
    expect(bad.stdout).toContain('FAIL');
    expect(bad.stdout).toMatch(/hash_mismatch\s+5\b/); // pinpoints the doctored record at seq 5
  }, 30_000);

  /* --------- review-fix R1: forged-tail, PEM-swap, and duplicate-ZIP-entry bundles --------- */

  it('P0: a forged tail chained onto the real signed head (no key needed) FAILS verify --bundle, dir and zip', async () => {
    const bundleDir = join(dir, 'bundle-forged-tail');
    await exportBundle({ store, dirPath: bundleDir, toolVersion: '0.1.0-test', signer });

    // Attacker: append records that chain correctly onto the genuine signed
    // head — self-consistent, no key required — same shape as any honest
    // tail. Nothing else in the bundle is touched.
    const eventsPath = join(bundleDir, BUNDLE_FILES.EVENTS);
    const genuineLines = readFileSync(eventsPath, 'utf8').split('\n').filter((l) => l.trim() !== '');
    const lastGenuine = JSON.parse(genuineLines[genuineLines.length - 1]!) as ChainRecord;
    let head: ChainHead = { seq: lastGenuine.seq, hash: lastGenuine.hash };
    const forged: ChainRecord[] = [];
    for (let i = 0; i < 3; i++) {
      const r = makeRecord(head, toolCall(SESSION_A, 900 + i, 'FORGED_exfiltrate'));
      forged.push(r);
      head = { seq: r.seq, hash: r.hash };
    }
    writeFileSync(
      eventsPath,
      [...genuineLines, ...forged.map((r) => JSON.stringify(r))].join('\n') + '\n',
    );

    // The in-package verifier must reject it (this is the bug: it used to
    // report only a downgradable "unsigned tail" warning and PASS).
    const cliDir = runCliVerifyBundle(bundleDir);
    expect(cliDir.status).toBe(1);
    expect(cliDir.stdout).toContain('FAIL');
    expect(cliDir.stdout).toContain('bundle_manifest_mismatch');

    // The standalone verifier shipped in the bundle must agree.
    const cjsDir = runVerifyCjs(bundleDir);
    expect(cjsDir.status).toBe(1);
    expect(cjsDir.stdout).toContain('FAIL');

    // Same forged tail, packaged as a .zip.
    const zipPath = join(dir, 'forged-tail.zip');
    await zipBundleDir(bundleDir, zipPath);
    const cliZip = runCliVerifyBundle(zipPath);
    expect(cliZip.status).toBe(1);
    expect(cliZip.stdout).toContain('FAIL');
    expect(cliZip.stdout).toContain('bundle_manifest_mismatch');
  }, 30_000);

  it('P1: a forgery re-signed with an attacker key that ships the real public_key.pem FAILS verify --bundle, dir and zip', async () => {
    // A fully self-consistent bundle signed end-to-end by an ATTACKER key —
    // internally it verifies perfectly against its own manifest.
    const attacker = await Signer.load(join(dir, 'attacker'));
    const attackerDir = join(dir, 'bundle-attacker');
    const attackerStore = openStore({ dataDir: join(dir, 'attacker-data'), backend: 'jsonl' });
    attackerStore.append(seal([toolCall(SESSION_A, 0, 'FORGED_exfiltrate')]));
    await exportBundle({
      store: attackerStore,
      dirPath: attackerDir,
      toolVersion: '0.1.0-test',
      signer: attacker,
    });
    attackerStore.close();

    // ...but public_key.pem still ships the OPERATOR's genuine key (e.g. the
    // attacker only had write access to events.jsonl/manifest.json, or
    // forgot to swap it). manifest.public_key_pem is left pointing at the
    // attacker's own PEM, matching manifest.signature — only the shipped
    // public_key.pem FILE is the operator's.
    writeFileSync(join(attackerDir, BUNDLE_FILES.PUBLIC_KEY), publicKeyPem(signer.publicKeyHex));

    const cliDir = runCliVerifyBundle(attackerDir);
    expect(cliDir.status).toBe(1);
    expect(cliDir.stdout).toContain('FAIL');
    expect(cliDir.stdout).toContain('public_key.pem does not match the manifest signing key');

    const cjsDir = runVerifyCjs(attackerDir);
    expect(cjsDir.status).toBe(1);
    expect(cjsDir.stdout).toContain('FAIL');

    const zipPath = join(dir, 'attacker.zip');
    await zipBundleDir(attackerDir, zipPath);
    const cliZip = runCliVerifyBundle(zipPath);
    expect(cliZip.status).toBe(1);
    expect(cliZip.stdout).toContain('FAIL');
    expect(cliZip.stdout).toContain('public_key.pem does not match the manifest signing key');
  }, 30_000);

  it('P1/P2: a .zip with a duplicate events.jsonl entry (genuine then forged) is rejected, not silently resolved to either copy', async () => {
    const bundleDir = join(dir, 'bundle-dup');
    await exportBundle({ store, dirPath: bundleDir, toolVersion: '0.1.0-test', signer });

    const genuineEvents = readFileSync(join(bundleDir, BUNDLE_FILES.EVENTS));
    const forgedEvents = Buffer.from(
      genuineEvents.toString('utf8').replace('list_issues', 'FORGED_exfiltrate'),
      'utf8',
    );

    // A real unzip/extractAllTo writes whichever duplicate-named entry comes
    // LAST — verify --bundle must not silently trust the FIRST instead (which
    // would let a bundle verify against a genuine copy while extracting a
    // forged one to disk).
    const zipPath = join(dir, 'dup-entry.zip');
    const zf = new yazl.ZipFile();
    zf.addBuffer(genuineEvents, BUNDLE_FILES.EVENTS); // genuine, first
    for (const name of Object.values(BUNDLE_FILES)) {
      if (name === BUNDLE_FILES.EVENTS) continue;
      zf.addBuffer(readFileSync(join(bundleDir, name)), name);
    }
    zf.addBuffer(forgedEvents, BUNDLE_FILES.EVENTS); // forged, second — duplicate name
    await new Promise<void>((resolve, reject) => {
      const out = createWriteStream(zipPath);
      out.on('close', () => resolve());
      out.on('error', reject);
      zf.outputStream.on('error', reject);
      zf.outputStream.pipe(out);
      zf.end();
    });

    const cli = spawnTsxSync(['src/cli.ts', 'verify', '--bundle', zipPath], {
      cwd: ROOT,
      encoding: 'utf8',
    });
    expect(cli.status).toBe(2); // usage/malformed-input error, not a verify verdict either way
    expect(cli.stderr).toContain('malformed ZIP: duplicate entry events.jsonl');
  }, 30_000);

  /* --------- unsigned manifest metadata: session_id/created_at/tool_version --------- */

  it('created_at/tool_version are unsigned: editing them still PASSES, and both verifiers label them as such', async () => {
    const bundleDir = join(dir, 'bundle-unsigned-metadata');
    await exportBundle({ store, dirPath: bundleDir, toolVersion: '0.1.0-test', signer });

    // Only the head signature (seq + chain_hash) is covered by the signature —
    // created_at and tool_version are the exporting tool's own say-so.
    // Doctoring them must NOT break verification.
    const manifestPath = join(bundleDir, BUNDLE_FILES.MANIFEST);
    const onDisk = JSON.parse(readFileSync(manifestPath, 'utf8')) as Record<string, unknown>;
    onDisk.created_at = '2099-01-01T00:00:00.000Z';
    onDisk.tool_version = '99.99.99-doctored';
    writeFileSync(manifestPath, JSON.stringify(onDisk, null, 2) + '\n');

    const UNSIGNED_LABEL = 'UNSIGNED metadata (not covered by the signature - informational only)';

    // (a) node verify.cjs still PASSES, and shows the doctored fields under
    // the clearly-labeled unsigned section.
    const cjs = runVerifyCjs(bundleDir);
    expect(cjs.status).toBe(0);
    expect(cjs.stdout).toContain('PASS');
    expect(cjs.stdout).toContain(UNSIGNED_LABEL);
    expect(cjs.stdout).toContain('2099-01-01T00:00:00.000Z');
    expect(cjs.stdout).toContain('99.99.99-doctored');

    // (b) `mcp-recorder verify --bundle` agrees: still PASSES, same label,
    // same (unverified) values surfaced for the operator to see.
    const cli = runCliVerifyBundle(bundleDir);
    expect(cli.status).toBe(0);
    expect(cli.stdout).toContain('PASS');
    expect(cli.stdout).toContain(UNSIGNED_LABEL);
    expect(cli.stdout).toContain('2099-01-01T00:00:00.000Z');
    expect(cli.stdout).toContain('99.99.99-doctored');
  });

  it('a genuine bundle also shows the unsigned-metadata label (not just a tampered one)', async () => {
    const bundleDir = join(dir, 'bundle-unsigned-metadata-genuine');
    const manifest = await exportBundle({
      store,
      dirPath: bundleDir,
      toolVersion: '0.1.0-test',
      signer,
    });

    const UNSIGNED_LABEL = 'UNSIGNED metadata (not covered by the signature - informational only)';

    const cjs = runVerifyCjs(bundleDir);
    expect(cjs.status).toBe(0);
    expect(cjs.stdout).toContain(UNSIGNED_LABEL);
    expect(cjs.stdout).toContain(manifest.created_at);
    expect(cjs.stdout).toContain(manifest.tool_version);

    const cli = runCliVerifyBundle(bundleDir);
    expect(cli.status).toBe(0);
    expect(cli.stdout).toContain(UNSIGNED_LABEL);
    expect(cli.stdout).toContain(manifest.created_at);
    expect(cli.stdout).toContain(manifest.tool_version);
  });
});
