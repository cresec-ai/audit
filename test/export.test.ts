import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { GENESIS_HASH, makeRecord, sha256Ref } from '../src/chain/hash.js';
import { Signer } from '../src/chain/keys.js';
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

function runVerifyCjs(bundleDir: string): { status: number | null; stdout: string } {
  const result = spawnSync(process.execPath, [BUNDLE_FILES.VERIFY], {
    cwd: bundleDir,
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
    // yauzl is not installed; assert the artifact exists and has substance,
    // and rely on dir mode (same entries) for content-level checks.
    expect(existsSync(zipPath)).toBe(true);
    expect(statSync(zipPath).size).toBeGreaterThan(500);
    expect(existsSync(join(bundleDir, BUNDLE_FILES.MANIFEST))).toBe(true);
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
});
