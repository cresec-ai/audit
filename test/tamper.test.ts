/**
 * M2 definition-of-done: "altering, inserting, or deleting any stored row
 * makes verify fail loudly." Each test tampers with the store at the file
 * level (below the append-only API) and asserts verify pinpoints the exact
 * seq and problem type.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createRequire } from 'node:module';
import {
  GENESIS_HASH,
  canonicalJson,
  computeHash,
  makeRecord,
  sha256Ref,
} from '../src/chain/hash.js';
import { Signer } from '../src/chain/keys.js';
import { openStore, isSqliteAvailable } from '../src/store/index.js';
import { verifyStore } from '../src/verify/verify.js';
import { FILES } from '../src/types.js';
import type { ChainHead, VerifyResult } from '../src/types.js';
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

const IDENTITY: IdentityContext = { fingerprint: sha256Ref('tamper-test-identity') };
const SERVER: ServerContext = {
  name: 'tamper-test-server',
  command: 'node server.js',
  transport: 'stdio',
};
const SESSION_A = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';

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

function sixRecords(): ChainRecord[] {
  return seal([
    sessionStart(SESSION_A, 0),
    toolCall(SESSION_A, 1),
    toolCall(SESSION_A, 2, 'create_issue'),
    toolCall(SESSION_A, 3),
    toolCall(SESSION_A, 4, 'search_code'),
    toolCall(SESSION_A, 5),
  ]);
}

function problemAt(result: VerifyResult, type: string, seq: number): boolean {
  return result.problems.some((p) => p.type === type && p.seq === seq);
}

/* ------------------------------- sqlite -------------------------------- */

type RawDb = import('better-sqlite3').Database;

describe('tamper evidence (sqlite)', () => {
  let dir: string;
  let records: ChainRecord[];

  beforeEach(async () => {
    expect(isSqliteAvailable()).toBe(true);
    dir = mkdtempSync(join(tmpdir(), 'mcp-recorder-tamper-sqlite-'));
    records = sixRecords();
    const signer = await Signer.load(dir);
    const store = openStore({ dataDir: dir, backend: 'sqlite' });
    store.append(records);
    const head = store.head();
    store.addSignature(await signer.sign(head.seq, head.hash));
    store.close();
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  /** Open the db file directly and drop the append-only triggers — i.e. an
   *  attacker with file access and sqlite knowledge. */
  function rawTamper(mutate: (raw: RawDb) => void): void {
    const require = createRequire(import.meta.url);
    const Database = require('better-sqlite3') as typeof import('better-sqlite3');
    const raw: RawDb = new Database(join(dir, FILES.SQLITE_DB));
    try {
      raw.exec(
        'DROP TRIGGER records_no_update; DROP TRIGGER records_no_delete;' +
          'DROP TRIGGER signatures_no_update; DROP TRIGGER signatures_no_delete;',
      );
      mutate(raw);
    } finally {
      raw.close();
    }
  }

  async function verifyTampered(): Promise<VerifyResult> {
    const store = openStore({ dataDir: dir, backend: 'sqlite' });
    try {
      return await verifyStore(store);
    } finally {
      store.close();
    }
  }

  it('UPDATE of an event JSON → hash_mismatch at that seq', async () => {
    rawTamper((raw) => {
      const row = raw.prepare('SELECT event FROM records WHERE seq = 3').get() as {
        event: string;
      };
      const event = JSON.parse(row.event) as ToolCallEvent;
      event.tool = 'totally_innocent_tool';
      raw.prepare('UPDATE records SET event = ? WHERE seq = 3').run(JSON.stringify(event));
    });

    const result = await verifyTampered();
    expect(result.ok).toBe(false);
    expect(problemAt(result, 'hash_mismatch', 3)).toBe(true);
  });

  it('DELETE of a middle row → seq_gap at the following seq', async () => {
    rawTamper((raw) => {
      raw.prepare('DELETE FROM records WHERE seq = 3').run();
    });

    const result = await verifyTampered();
    expect(result.ok).toBe(false);
    expect(problemAt(result, 'seq_gap', 4)).toBe(true);
    // The missing link also surfaces as a broken prev_hash on the next record.
    expect(problemAt(result, 'prev_hash_mismatch', 4)).toBe(true);
  });

  it('forged row spliced mid-chain (self-consistent hash) → prev_hash_mismatch on the next record', async () => {
    rawTamper((raw) => {
      // The forger replaces seq 3 with a fabricated event, correctly
      // recomputing its chain hash from seq 2 — the strongest forgery
      // possible without rewriting every later row.
      const row2 = raw.prepare('SELECT hash FROM records WHERE seq = 2').get() as {
        hash: string;
      };
      const forgedEvent = toolCall(SESSION_A, 33, 'forged_tool');
      const forgedHash = computeHash(row2.hash, forgedEvent);
      raw.prepare('DELETE FROM records WHERE seq = 3').run();
      raw
        .prepare(
          'INSERT INTO records (seq, prev_hash, hash, session_id, kind, timestamp, event) VALUES (?, ?, ?, ?, ?, ?, ?)',
        )
        .run(
          3,
          row2.hash,
          forgedHash,
          forgedEvent.session_id,
          forgedEvent.kind,
          forgedEvent.timestamp,
          canonicalJson(forgedEvent),
        );
    });

    const result = await verifyTampered();
    expect(result.ok).toBe(false);
    // The forged row itself verifies — the record AFTER it betrays the splice.
    expect(problemAt(result, 'prev_hash_mismatch', 4)).toBe(true);
  });

  it('DELETE of the tail while keeping signatures → truncated_after_signature', async () => {
    rawTamper((raw) => {
      raw.prepare('DELETE FROM records WHERE seq > 4').run();
    });

    const result = await verifyTampered();
    expect(result.ok).toBe(false);
    expect(problemAt(result, 'truncated_after_signature', 6)).toBe(true);
    expect(result.head.seq).toBe(4);
    expect(result.verified_signature).toBeUndefined();
  });

  it('corrupted signature hex → signature_invalid', async () => {
    rawTamper((raw) => {
      const row = raw.prepare('SELECT signature FROM signatures LIMIT 1').get() as {
        signature: string;
      };
      const flipped = (row.signature[0] === '0' ? 'f' : '0') + row.signature.slice(1);
      raw.prepare('UPDATE signatures SET signature = ?').run(flipped);
    });

    const result = await verifyTampered();
    expect(result.ok).toBe(false);
    expect(problemAt(result, 'signature_invalid', 6)).toBe(true);
    expect(result.verified_signature).toBeUndefined();
  });
});

/* -------------------------------- jsonl -------------------------------- */

describe('tamper evidence (jsonl)', () => {
  let dir: string;
  let records: ChainRecord[];
  let logPath: string;
  let sigsPath: string;

  beforeEach(async () => {
    dir = mkdtempSync(join(tmpdir(), 'mcp-recorder-tamper-jsonl-'));
    records = sixRecords();
    const signer = await Signer.load(dir);
    const store = openStore({ dataDir: dir, backend: 'jsonl' });
    store.append(records);
    const head = store.head();
    store.addSignature(await signer.sign(head.seq, head.hash));
    store.close();
    logPath = join(dir, FILES.JSONL_LOG);
    sigsPath = join(dir, FILES.JSONL_SIGS);
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  function readLines(path: string): string[] {
    return readFileSync(path, 'utf8').split('\n').filter((line) => line.trim() !== '');
  }

  function writeLines(path: string, lines: string[]): void {
    writeFileSync(path, lines.join('\n') + '\n');
  }

  async function verifyTampered(): Promise<VerifyResult> {
    const store = openStore({ dataDir: dir, backend: 'jsonl' });
    try {
      return await verifyStore(store);
    } finally {
      store.close();
    }
  }

  it('rewriting a line\'s event field → hash_mismatch at that seq', async () => {
    const lines = readLines(logPath);
    const record = JSON.parse(lines[2]!) as ChainRecord;
    (record.event as ToolCallEvent).tool = 'totally_innocent_tool';
    lines[2] = JSON.stringify(record);
    writeLines(logPath, lines);

    const result = await verifyTampered();
    expect(result.ok).toBe(false);
    expect(problemAt(result, 'hash_mismatch', 3)).toBe(true);
  });

  it('removing a middle line → seq_gap at the following seq', async () => {
    const lines = readLines(logPath);
    lines.splice(2, 1); // drop seq 3
    writeLines(logPath, lines);

    const result = await verifyTampered();
    expect(result.ok).toBe(false);
    expect(problemAt(result, 'seq_gap', 4)).toBe(true);
  });

  it('inserting a forged duplicate-seq line → duplicate_seq', async () => {
    const lines = readLines(logPath);
    const forgedEvent = toolCall(SESSION_A, 44, 'forged_tool');
    const forged: ChainRecord = {
      seq: 3,
      prev_hash: records[1]!.hash,
      hash: computeHash(records[1]!.hash, forgedEvent),
      event: forgedEvent,
    };
    lines.splice(3, 0, JSON.stringify(forged)); // after the real seq 3
    writeLines(logPath, lines);

    const result = await verifyTampered();
    expect(result.ok).toBe(false);
    expect(problemAt(result, 'duplicate_seq', 3)).toBe(true);
  });

  it('truncating the tail while keeping signatures → truncated_after_signature', async () => {
    const lines = readLines(logPath);
    writeLines(logPath, lines.slice(0, 4)); // keep seq 1..4, signature is at 6

    const result = await verifyTampered();
    expect(result.ok).toBe(false);
    expect(problemAt(result, 'truncated_after_signature', 6)).toBe(true);
    expect(result.head.seq).toBe(4);
    expect(result.verified_signature).toBeUndefined();
  });

  it('corrupted signature hex → signature_invalid', async () => {
    const lines = readLines(sigsPath);
    const sig = JSON.parse(lines[0]!) as { signature: string };
    sig.signature = (sig.signature[0] === '0' ? 'f' : '0') + sig.signature.slice(1);
    lines[0] = JSON.stringify(sig);
    writeLines(sigsPath, lines);

    const result = await verifyTampered();
    expect(result.ok).toBe(false);
    expect(problemAt(result, 'signature_invalid', 6)).toBe(true);
  });
});
