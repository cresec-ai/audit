/**
 * Reference receiver (receiver/) — the acceptance suite.
 *
 * The property under test throughout: a receiver that ACCEPTS a broken chain
 * is worse than no receiver, because it launders tampering into apparent
 * evidence. So every case here is either "the good batch lands, durably and
 * exactly once" or "this specific breakage is refused with a reason an
 * auditor can act on", and a GAP is never confused with a FORK.
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { gzipSync } from 'node:zlib';
import { Buffer } from 'node:buffer';
import * as ed from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha512';
import { GENESIS_HASH, makeRecord, sha256Ref, signedPayload } from '../src/chain/hash.js';
import { verifyRecords } from '../src/verify/verify.js';
import { SCHEMA } from '../src/schema/events.js';
import type {
  AnyEvent,
  ChainRecord,
  HeadSignature,
  IdentityContext,
  ServerContext,
  SessionStartEvent,
  ToolCallEvent,
} from '../src/schema/events.js';
import type { ChainHead } from '../src/types.js';
import { serveReceiver } from '../receiver/server.js';
import type { ServerHandle } from '../receiver/server.js';
import { exportReceivedChain } from '../receiver/export.js';
import { HEADERS, sinkSignedPayload } from '../receiver/protocol.js';
import type { RecordsBatch, SinkCursor, SinkHead } from '../receiver/protocol.js';

ed.etc.sha512Sync = (...m: Uint8Array[]) => sha512(ed.etc.concatBytes(...m));

const INGEST_TOKEN = 'test-ingest-token-0123456789abcdef';
const OPERATOR_TOKEN = 'test-operator-token-abcdef0123456789';

/* ------------------------------ fixtures ------------------------------ */

const IDENTITY: IdentityContext = { fingerprint: sha256Ref('receiver-test-identity') };
const SERVER: ServerContext = {
  name: 'receiver-test-server',
  command: 'node server.js',
  transport: 'stdio',
};
const SESSION = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';

function event(n: number, marker = 'x'): AnyEvent {
  const base = {
    schema: SCHEMA,
    event_id: `00000000-0000-4000-8000-${n.toString(16).padStart(12, '0')}`,
    session_id: SESSION,
    timestamp: new Date(Date.UTC(2026, 8, 17, 10, 0, Math.min(n, 59))).toISOString(),
    identity: IDENTITY,
    server: SERVER,
  };
  if (n === 1) {
    return {
      ...base,
      kind: 'session_start',
      // `marker` reaches seq 1 too, so two different runs mint two different
      // chain_ids — which is the whole point of chain_id being the seq-1 hash.
      attributes: { marker },
      proxy_version: '0.1.0',
      cwd: '/tmp',
      redaction_mode: 'allowlist',
    } satisfies SessionStartEvent;
  }
  return {
    ...base,
    kind: 'tool_call',
    attributes: { 'gen_ai.tool.name': `tool_${n}`, marker },
    tool: `tool_${n}`,
    request_id: n,
    args: { path: { redacted: true, ref: sha256Ref(`arg-${n}-${marker}`), len: 8 } },
    result_hash: sha256Ref(`result-${n}-${marker}`),
    result: { ok: true },
    is_error: false,
    duration_ms: 3,
  } satisfies ToolCallEvent;
}

/** Seal events 1..n into a chain, exactly as the recorder would. */
function buildChain(n: number, marker = 'x'): ChainRecord[] {
  let head: ChainHead = { seq: 0, hash: GENESIS_HASH };
  const records: ChainRecord[] = [];
  for (let seq = 1; seq <= n; seq++) {
    const record = makeRecord(head, event(seq, marker));
    records.push(record);
    head = { seq: record.seq, hash: record.hash };
  }
  return records;
}

/** Continue an existing chain with divergent content (the fork branch). */
function forkFrom(records: ChainRecord[], atSeq: number, extra: number, marker: string): ChainRecord[] {
  const prefix = records.filter((r) => r.seq < atSeq);
  let head: ChainHead =
    prefix.length === 0
      ? { seq: 0, hash: GENESIS_HASH }
      : { seq: prefix[prefix.length - 1]!.seq, hash: prefix[prefix.length - 1]!.hash };
  const out: ChainRecord[] = [];
  for (let seq = atSeq; seq < atSeq + extra; seq++) {
    const record = makeRecord(head, event(seq, marker));
    out.push(record);
    head = { seq: record.seq, hash: record.hash };
  }
  return out;
}

/* -------------------------------- keys -------------------------------- */

interface Identity {
  priv: Uint8Array;
  pub: string;
}

function newIdentity(): Identity {
  const priv = new Uint8Array(randomBytes(32));
  return { priv, pub: ed.etc.bytesToHex(ed.getPublicKey(priv)) };
}

function headSignature(id: Identity, seq: number, chainHash: string): HeadSignature {
  return {
    seq,
    chain_hash: chainHash,
    algo: 'ed25519',
    public_key: id.pub,
    signature: ed.etc.bytesToHex(ed.sign(signedPayload(seq, chainHash), id.priv)),
    signed_at: new Date().toISOString(),
  };
}

function headFor(id: Identity, records: ChainRecord[]): SinkHead {
  const last = records[records.length - 1]!;
  return { seq: last.seq, hash: last.hash, signature: headSignature(id, last.seq, last.hash) };
}

/* ------------------------------ harness ------------------------------- */

let dataDir = '';
let handle: ServerHandle | undefined;

async function start(overrides: Record<string, unknown> = {}): Promise<ServerHandle> {
  writeFileSync(
    join(dataDir, 'tokens.json'),
    JSON.stringify({
      tokens: [{ id: 'test', tenant: 'acme', token: INGEST_TOKEN, enrolment: 'tofu' }],
    }),
  );
  handle = await serveReceiver({
    dataDir,
    operatorToken: OPERATOR_TOKEN,
    silenceScanMs: 0,
    ...overrides,
  });
  return handle;
}

interface PostOpts {
  chainId: string;
  id: Identity;
  from: number;
  to: number;
  baseHash: string;
  records: ChainRecord[];
  signatures?: HeadSignature[];
  head: SinkHead;
  /* deliberate breakages, for the negative cases */
  token?: string;
  signWith?: Identity;
  keyHeader?: string;
  bodyOverride?: Buffer;
  digestOverride?: string;
  omitRangeHeader?: boolean;
  gzip?: boolean;
  mutate?: (batch: RecordsBatch) => void;
  pathChainId?: string;
}

interface PostResult {
  status: number;
  body: { error?: string; detail?: string; cursor?: SinkCursor } & Partial<SinkCursor>;
}

async function post(url: string, opts: PostOpts): Promise<PostResult> {
  const batch: RecordsBatch = {
    protocol: 1,
    chain_id: opts.chainId,
    key: opts.id.pub,
    from_seq: opts.from,
    to_seq: opts.to,
    base_hash: opts.baseHash,
    records: opts.records,
    signatures: opts.signatures ?? [],
    head: opts.head,
    sender: { tool_version: '0.1.0', surface: 'ship', backend: 'jsonl' },
  };
  opts.mutate?.(batch);
  const body = opts.bodyOverride ?? Buffer.from(JSON.stringify(batch), 'utf8');
  const digest = opts.digestOverride ?? createHash('sha256').update(body).digest('hex');
  const signer = opts.signWith ?? opts.id;
  const signature = ed.etc.bytesToHex(
    ed.sign(
      sinkSignedPayload(opts.pathChainId ?? opts.chainId, opts.from, opts.to, digest),
      signer.priv,
    ),
  );
  const headers: Record<string, string> = {
    'content-type': 'application/json',
    authorization: `Bearer ${opts.token ?? INGEST_TOKEN}`,
    [HEADERS.PROTOCOL]: '1',
    [HEADERS.KEY]: opts.keyHeader ?? opts.id.pub,
    [HEADERS.CONTENT_SHA256]: digest,
    [HEADERS.SIGNATURE]: signature,
    [HEADERS.SENT_AT]: new Date().toISOString(),
    [HEADERS.IDEMPOTENCY]: digest,
  };
  if (opts.omitRangeHeader !== true) headers[HEADERS.RANGE] = `${opts.from}-${opts.to}`;
  let payload = body;
  if (opts.gzip === true) {
    payload = gzipSync(body);
    headers['content-encoding'] = 'gzip';
  }
  const res = await fetch(`${url}/v1/chains/${opts.pathChainId ?? opts.chainId}/records`, {
    method: 'POST',
    headers,
    body: new Uint8Array(payload),
  });
  return { status: res.status, body: (await res.json()) as PostResult['body'] };
}

function storedLines(chainId: string, file: string): string[] {
  const path = join(dataDir, 'chains', chainId, file);
  if (!existsSync(path)) return [];
  return readFileSync(path, 'utf8').split('\n').filter((l) => l.trim() !== '');
}

beforeEach(() => {
  dataDir = mkdtempSync(join(tmpdir(), 'mcpr-receiver-'));
});

afterEach(async () => {
  await handle?.close();
  handle = undefined;
  rmSync(dataDir, { recursive: true, force: true });
});

/* =========================== the happy path =========================== */

describe('receiver: a well-formed batch', () => {
  it('accepts it, stores it durably, and returns a cursor that resumes', async () => {
    const server = await start();
    const id = newIdentity();
    const records = buildChain(3);
    const chainId = records[0]!.hash;

    const res = await post(server.url, {
      chainId,
      id,
      from: 1,
      to: 3,
      baseHash: GENESIS_HASH,
      records,
      signatures: [headSignature(id, 3, records[2]!.hash)],
      head: headFor(id, records),
    });

    expect(res.status).toBe(202);
    expect(res.body.next_seq).toBe(4);
    expect(res.body.head_hash).toBe(records[2]!.hash);
    expect(res.body.attested_seq).toBe(3);
    expect(res.body.key).toBe(id.pub);

    // Durable, on disk, with the ONE piece of metadata the sender does not
    // control: when it actually arrived.
    const lines = storedLines(chainId, 'records.jsonl');
    expect(lines).toHaveLength(3);
    const first = JSON.parse(lines[0]!) as { received_at: string; record: ChainRecord };
    expect(first.record.hash).toBe(records[0]!.hash);
    expect(Date.parse(first.received_at)).toBeGreaterThan(0);

    // ...and what it holds verifies with the product's own verifier.
    const verification = await verifyRecords(
      storedLines(chainId, 'records.jsonl').map(
        (l) => (JSON.parse(l) as { record: ChainRecord }).record,
      ),
      storedLines(chainId, 'signatures.jsonl').map(
        (l) => (JSON.parse(l) as { signature: HeadSignature }).signature,
      ),
      { expectedPublicKeyHex: id.pub },
    );
    expect(verification.ok).toBe(true);
  });

  it('accepts a gzip body and an identity body identically', async () => {
    const server = await start();
    const id = newIdentity();
    const records = buildChain(2);
    const chainId = records[0]!.hash;
    const res = await post(server.url, {
      chainId,
      id,
      from: 1,
      to: 2,
      baseHash: GENESIS_HASH,
      records,
      head: headFor(id, records),
      gzip: true,
    });
    expect(res.status).toBe(202);
    expect(res.body.next_seq).toBe(3);
  });

  it('interoperates with a sender that omits X-MCPR-Range (range read from the body)', async () => {
    const server = await start();
    const id = newIdentity();
    const records = buildChain(2);
    const chainId = records[0]!.hash;
    const res = await post(server.url, {
      chainId,
      id,
      from: 1,
      to: 2,
      baseHash: GENESIS_HASH,
      records,
      head: headFor(id, records),
      omitRangeHeader: true,
    });
    expect(res.status).toBe(202);
  });

  it('refuses a missing X-MCPR-Range when the receiver is run strict', async () => {
    const server = await start({ requireRangeHeader: true });
    const id = newIdentity();
    const records = buildChain(2);
    const chainId = records[0]!.hash;
    const res = await post(server.url, {
      chainId,
      id,
      from: 1,
      to: 2,
      baseHash: GENESIS_HASH,
      records,
      head: headFor(id, records),
      omitRangeHeader: true,
    });
    expect(res.status).toBe(400);
    expect(res.body.detail).toContain(HEADERS.RANGE);
  });

  it('commits only the suffix of an overlapping batch — a stale sender cursor is harmless', async () => {
    const server = await start();
    const id = newIdentity();
    const records = buildChain(5);
    const chainId = records[0]!.hash;

    const first = await post(server.url, {
      chainId,
      id,
      from: 1,
      to: 3,
      baseHash: GENESIS_HASH,
      records: records.slice(0, 3),
      head: headFor(id, records.slice(0, 3)),
    });
    expect(first.status).toBe(202);

    // Sender's cache said 2; the receiver already has through 3.
    const second = await post(server.url, {
      chainId,
      id,
      from: 2,
      to: 5,
      baseHash: records[0]!.hash,
      records: records.slice(1, 5),
      head: headFor(id, records),
    });
    expect(second.status).toBe(202);
    expect(second.body.next_seq).toBe(6);
    expect(storedLines(chainId, 'records.jsonl')).toHaveLength(5);
  });
});

/* ============================ idempotency ============================= */

describe('receiver: replay', () => {
  it('a byte-identical POST twice leaves next_seq unchanged and stores no duplicate', async () => {
    const server = await start();
    const id = newIdentity();
    const records = buildChain(4);
    const chainId = records[0]!.hash;
    const args = {
      chainId,
      id,
      from: 1,
      to: 4,
      baseHash: GENESIS_HASH,
      records,
      signatures: [headSignature(id, 4, records[3]!.hash)],
      head: headFor(id, records),
    };

    const first = await post(server.url, { ...args });
    const second = await post(server.url, { ...args });

    expect(first.status).toBe(202);
    expect(second.status).toBe(202);
    expect(second.body.next_seq).toBe(first.body.next_seq);
    expect(storedLines(chainId, 'records.jsonl')).toHaveLength(4);
    expect(storedLines(chainId, 'signatures.jsonl')).toHaveLength(1);
  });
});

/* =============================== the gap ============================== */

describe('receiver: a gap is refused, never bridged', () => {
  it('409 chain_gap when from_seq is past next_seq, and stores nothing', async () => {
    const server = await start();
    const id = newIdentity();
    const records = buildChain(6);
    const chainId = records[0]!.hash;

    await post(server.url, {
      chainId,
      id,
      from: 1,
      to: 3,
      baseHash: GENESIS_HASH,
      records: records.slice(0, 3),
      head: headFor(id, records.slice(0, 3)),
    });

    const res = await post(server.url, {
      chainId,
      id,
      from: 5,
      to: 6,
      baseHash: records[3]!.hash,
      records: records.slice(4, 6),
      head: headFor(id, records),
    });

    expect(res.status).toBe(409);
    expect(res.body.error).toBe('chain_gap');
    expect(res.body.cursor?.next_seq).toBe(4);
    // Nothing was written: a skipped record makes everything after it
    // unverifiable here forever, so a stall beats a hole.
    expect(storedLines(chainId, 'records.jsonl')).toHaveLength(3);
    expect(storedLines(chainId, 'forks.jsonl')).toHaveLength(0);
  });

  it('a brand-new chain that does not start at seq 1 is a gap, not a fork', async () => {
    const server = await start();
    const id = newIdentity();
    const records = buildChain(4);
    const chainId = records[0]!.hash;
    const res = await post(server.url, {
      chainId,
      id,
      from: 3,
      to: 4,
      baseHash: records[1]!.hash,
      records: records.slice(2, 4),
      head: headFor(id, records),
    });
    expect(res.status).toBe(409);
    expect(res.body.error).toBe('chain_gap');
    expect(res.body.cursor?.next_seq).toBe(1);
    expect(res.body.cursor?.head_hash).toBe(GENESIS_HASH);
  });
});

/* ============================== the fork ============================== */

describe('receiver: a fork is an incident, and both branches are kept', () => {
  it('409 chain_fork when a held seq arrives with a different hash', async () => {
    const server = await start();
    const id = newIdentity();
    const records = buildChain(4);
    const chainId = records[0]!.hash;

    await post(server.url, {
      chainId,
      id,
      from: 1,
      to: 4,
      baseHash: GENESIS_HASH,
      records,
      signatures: [headSignature(id, 4, records[3]!.hash)],
      head: headFor(id, records),
    });

    // History rewritten from seq 3: same seqs, different events.
    const branch = forkFrom(records, 3, 2, 'rewritten');
    const res = await post(server.url, {
      chainId,
      id,
      from: 3,
      to: 4,
      baseHash: records[1]!.hash,
      records: branch,
      head: { seq: 4, hash: branch[1]!.hash, signature: headSignature(id, 4, branch[1]!.hash) },
    });

    expect(res.status).toBe(409);
    expect(res.body.error).toBe('chain_fork');
    expect(res.body.detail).toMatch(/already stored with hash/);

    // BOTH branches are retained, with arrival times: ours on the chain, the
    // refused one in forks.jsonl. Nothing is reconciled.
    expect(storedLines(chainId, 'records.jsonl')).toHaveLength(4);
    const forks = storedLines(chainId, 'forks.jsonl').map(
      (l) => JSON.parse(l) as { at_seq: number; stored_hash: string; offered_hash: string; received_at: string },
    );
    expect(forks).toHaveLength(1);
    expect(forks[0]!.at_seq).toBe(3);
    expect(forks[0]!.stored_hash).toBe(records[2]!.hash);
    expect(forks[0]!.offered_hash).toBe(branch[0]!.hash);
    expect(Date.parse(forks[0]!.received_at)).toBeGreaterThan(0);

    const alerts = readFileSync(join(dataDir, 'alerts.jsonl'), 'utf8');
    expect(alerts).toContain('chain_fork');

    // Terminal: the chain stops accepting, even the honest continuation.
    const after = await post(server.url, {
      chainId,
      id,
      from: 5,
      to: 5,
      baseHash: records[3]!.hash,
      records: buildChain(5).slice(4, 5),
      head: headFor(id, buildChain(5)),
    });
    expect(after.status).toBe(409);
    expect(after.body.error).toBe('chain_fork');
  });

  it('409 chain_fork when base_hash disagrees with the stored hash at from_seq-1', async () => {
    const server = await start();
    const id = newIdentity();
    const records = buildChain(3);
    const chainId = records[0]!.hash;
    await post(server.url, {
      chainId,
      id,
      from: 1,
      to: 3,
      baseHash: GENESIS_HASH,
      records,
      head: headFor(id, records),
    });

    // A continuation that claims a different history behind it.
    const bogusBase = createHash('sha256').update('not the real prefix').digest('hex');
    let head: ChainHead = { seq: 3, hash: bogusBase };
    const next = makeRecord(head, event(4, 'other'));
    head = { seq: next.seq, hash: next.hash };

    const res = await post(server.url, {
      chainId,
      id,
      from: 4,
      to: 4,
      baseHash: bogusBase,
      records: [next],
      head: { seq: 4, hash: next.hash, signature: headSignature(id, 4, next.hash) },
    });
    expect(res.status).toBe(409);
    expect(res.body.error).toBe('chain_fork');
    expect(res.body.detail).toMatch(/base_hash .* disagrees/);
    expect(storedLines(chainId, 'records.jsonl')).toHaveLength(3);
  });

  it("409 chain_fork when the sender's own signed head contradicts a held seq", async () => {
    const server = await start();
    const id = newIdentity();
    const records = buildChain(3);
    const chainId = records[0]!.hash;
    await post(server.url, {
      chainId,
      id,
      from: 1,
      to: 3,
      baseHash: GENESIS_HASH,
      records,
      head: headFor(id, records),
    });

    const lie = createHash('sha256').update('a head that was never this chain').digest('hex');
    const res = await post(server.url, {
      chainId,
      id,
      from: 0,
      to: 0,
      baseHash: GENESIS_HASH,
      records: [],
      head: { seq: 2, hash: lie, signature: headSignature(id, 2, lie) },
    });
    expect(res.status).toBe(409);
    expect(res.body.error).toBe('chain_fork');
  });
});

/* ======================= content and signatures ======================= */

describe('receiver: content must recompute', () => {
  it('400 when one event field is mutated but the hashes are left alone', async () => {
    const server = await start();
    const id = newIdentity();
    const records = buildChain(3);
    const chainId = records[0]!.hash;

    const res = await post(server.url, {
      chainId,
      id,
      from: 1,
      to: 3,
      baseHash: GENESIS_HASH,
      records,
      head: headFor(id, records),
      mutate: (batch) => {
        // Exactly the tamper the sink exists to catch: the sealed event
        // altered in flight, hash left as it was.
        const target = batch.records[1]! as ChainRecord & { event: { attributes: Record<string, string> } };
        target.event.attributes.marker = 'tampered';
      },
    });

    expect(res.status).toBe(400);
    expect(res.body.error).toBe('bad_request');
    expect(res.body.detail).toContain('hash_mismatch');
    expect(storedLines(chainId, 'records.jsonl')).toHaveLength(0);
  });

  it('400 when records inside a batch are non-contiguous', async () => {
    const server = await start();
    const id = newIdentity();
    const records = buildChain(4);
    const chainId = records[0]!.hash;
    const res = await post(server.url, {
      chainId,
      id,
      from: 1,
      to: 3,
      baseHash: GENESIS_HASH,
      records: [records[0]!, records[1]!, records[3]!],
      head: headFor(id, records),
    });
    expect(res.status).toBe(400);
    expect(res.body.detail).toMatch(/seq_gap|prev_hash_mismatch/);
  });

  it('400 when a batch goes backwards inside itself (seq rewind)', async () => {
    const server = await start();
    const id = newIdentity();
    const records = buildChain(3);
    const chainId = records[0]!.hash;
    const res = await post(server.url, {
      chainId,
      id,
      from: 1,
      to: 3,
      baseHash: GENESIS_HASH,
      records: [records[0]!, records[1]!, records[1]!],
      head: headFor(id, records),
    });
    expect(res.status).toBe(400);
    expect(res.body.detail).toMatch(/duplicate_seq/);
  });

  it('400 when chain_id is not the hash of the seq-1 record (chain_id is derived, not chosen)', async () => {
    const server = await start();
    const id = newIdentity();
    const records = buildChain(2);
    const wrongChainId = createHash('sha256').update('a chain id I made up').digest('hex');
    const res = await post(server.url, {
      chainId: wrongChainId,
      id,
      from: 1,
      to: 2,
      baseHash: GENESIS_HASH,
      records,
      head: headFor(id, records),
    });
    expect(res.status).toBe(400);
    expect(res.body.detail).toMatch(/not the hash of the seq-1 record/);
  });

  it('400 when a head signature does not verify', async () => {
    const server = await start();
    const id = newIdentity();
    const other = newIdentity();
    const records = buildChain(2);
    const chainId = records[0]!.hash;
    const res = await post(server.url, {
      chainId,
      id,
      from: 1,
      to: 2,
      baseHash: GENESIS_HASH,
      records,
      // A head signed by a different key than the batch claims.
      head: {
        seq: 2,
        hash: records[1]!.hash,
        signature: { ...headSignature(other, 2, records[1]!.hash), public_key: id.pub },
      },
    });
    expect(res.status).toBe(400);
    expect(res.body.detail).toMatch(/head\.signature does not verify/);
    expect(storedLines(chainId, 'records.jsonl')).toHaveLength(0);
  });

  it('400 when an in-range signature attests a hash the batch does not recompute to', async () => {
    const server = await start();
    const id = newIdentity();
    const records = buildChain(3);
    const chainId = records[0]!.hash;
    const lie = createHash('sha256').update('not the hash at seq 2').digest('hex');
    const res = await post(server.url, {
      chainId,
      id,
      from: 1,
      to: 3,
      baseHash: GENESIS_HASH,
      records,
      signatures: [headSignature(id, 2, lie)],
      head: headFor(id, records),
    });
    expect(res.status).toBe(400);
    expect(storedLines(chainId, 'records.jsonl')).toHaveLength(0);
  });
});

/* ================================ auth ================================ */

describe('receiver: auth', () => {
  it('401 without a valid bearer token, and nothing is stored', async () => {
    const server = await start();
    const id = newIdentity();
    const records = buildChain(2);
    const chainId = records[0]!.hash;
    const res = await post(server.url, {
      chainId,
      id,
      from: 1,
      to: 2,
      baseHash: GENESIS_HASH,
      records,
      head: headFor(id, records),
      token: 'not-the-token',
    });
    expect(res.status).toBe(401);
    expect(res.body.error).toBe('unauthorized');
    expect(storedLines(chainId, 'records.jsonl')).toHaveLength(0);
  });

  it('400 when the request is signed by a key other than X-MCPR-Key — before the body is parsed', async () => {
    const server = await start();
    const id = newIdentity();
    const attacker = newIdentity();
    const records = buildChain(2);
    const chainId = records[0]!.hash;

    // The body is not even JSON. A receiver that parsed first would complain
    // about JSON; this one never gets that far, because the signature is
    // checked against X-MCPR-Key before the bytes are interpreted at all.
    const garbage = Buffer.from('{ this is not json at all', 'utf8');
    const res = await post(server.url, {
      chainId,
      id,
      from: 1,
      to: 2,
      baseHash: GENESIS_HASH,
      records,
      head: headFor(id, records),
      signWith: attacker,
      bodyOverride: garbage,
    });
    expect(res.status).toBe(400);
    expect(res.body.detail).toContain(HEADERS.SIGNATURE);
    expect(res.body.detail).not.toMatch(/JSON/i);
    expect(storedLines(chainId, 'records.jsonl')).toHaveLength(0);
  });

  it('400 when the content digest header does not match the body', async () => {
    const server = await start();
    const id = newIdentity();
    const records = buildChain(2);
    const chainId = records[0]!.hash;
    const res = await post(server.url, {
      chainId,
      id,
      from: 1,
      to: 2,
      baseHash: GENESIS_HASH,
      records,
      head: headFor(id, records),
      digestOverride: createHash('sha256').update('something else').digest('hex'),
    });
    expect(res.status).toBe(400);
    expect(res.body.detail).toContain(HEADERS.CONTENT_SHA256);
  });

  it('403 when the key is not enrolled for the tenant (pinned enrolment)', async () => {
    writeFileSync(
      join(dataDir, 'tokens.json'),
      JSON.stringify({
        tokens: [
          {
            id: 'fleet',
            tenant: 'acme',
            token: INGEST_TOKEN,
            enrolment: 'pinned',
            keys: [newIdentity().pub],
          },
        ],
      }),
    );
    handle = await serveReceiver({ dataDir, operatorToken: OPERATOR_TOKEN, silenceScanMs: 0 });

    const id = newIdentity();
    const records = buildChain(2);
    const chainId = records[0]!.hash;
    const res = await post(handle.url, {
      chainId,
      id,
      from: 1,
      to: 2,
      baseHash: GENESIS_HASH,
      records,
      head: headFor(id, records),
    });
    expect(res.status).toBe(403);
    expect(res.body.error).toBe('forbidden');
    expect(res.body.detail).toMatch(/not enrolled/);
    expect(storedLines(chainId, 'records.jsonl')).toHaveLength(0);
  });

  it('403 when a chain_id already bound to one key is addressed by another', async () => {
    const server = await start();
    const owner = newIdentity();
    const attacker = newIdentity();
    const records = buildChain(2);
    const chainId = records[0]!.hash;

    await post(server.url, {
      chainId,
      id: owner,
      from: 1,
      to: 2,
      baseHash: GENESIS_HASH,
      records,
      head: headFor(owner, records),
    });

    // The attacker holds the (stolen) token and signs correctly with its OWN
    // key — and still cannot write into someone else's chain.
    const branch = forkFrom(records, 3, 1, 'attacker');
    const res = await post(server.url, {
      chainId,
      id: attacker,
      from: 3,
      to: 3,
      baseHash: records[1]!.hash,
      records: branch,
      head: { seq: 3, hash: branch[0]!.hash, signature: headSignature(attacker, 3, branch[0]!.hash) },
    });
    expect(res.status).toBe(403);
    expect(res.body.detail).toMatch(/bound to key/);
    expect(storedLines(chainId, 'records.jsonl')).toHaveLength(2);
  });

  it('flags a second identity on a TOFU token and does not count it as attested', async () => {
    const server = await start();
    const first = newIdentity();
    const firstRecords = buildChain(2);
    await post(server.url, {
      chainId: firstRecords[0]!.hash,
      id: first,
      from: 1,
      to: 2,
      baseHash: GENESIS_HASH,
      records: firstRecords,
      signatures: [headSignature(first, 2, firstRecords[1]!.hash)],
      head: headFor(first, firstRecords),
    });

    const second = newIdentity();
    const secondRecords = buildChain(2, 'second');
    const res = await post(server.url, {
      chainId: secondRecords[0]!.hash,
      id: second,
      from: 1,
      to: 2,
      baseHash: GENESIS_HASH,
      records: secondRecords,
      signatures: [headSignature(second, 2, secondRecords[1]!.hash)],
      head: headFor(second, secondRecords),
    });
    expect(res.status).toBe(202);
    // Delivered, stored, but NOT attested until an operator acknowledges.
    expect(res.body.attested_seq).toBe(0);
    expect(readFileSync(join(dataDir, 'alerts.jsonl'), 'utf8')).toContain('new_identity');

    server.receiver.store.acknowledgeKey('acme', second.pub);
    expect(server.receiver.cursorFor(secondRecords[0]!.hash).attested_seq).toBe(2);
  });
});

/* ================================ caps ================================ */

describe('receiver: size caps', () => {
  it('413 with max_records/max_bytes when the batch is too big, and stores nothing', async () => {
    const server = await start({ maxRecords: 2, maxBytes: 4096, maxSingleRecordBytes: 8192 });
    const id = newIdentity();
    const records = buildChain(3);
    const chainId = records[0]!.hash;
    const res = await post(server.url, {
      chainId,
      id,
      from: 1,
      to: 3,
      baseHash: GENESIS_HASH,
      records,
      head: headFor(id, records),
    });
    expect(res.status).toBe(413);
    expect(res.body.error).toBe('too_large');
    expect((res.body as { max_records?: number }).max_records).toBe(2);
    expect((res.body as { max_bytes?: number }).max_bytes).toBe(4096);
    expect(storedLines(chainId, 'records.jsonl')).toHaveLength(0);
  });

  it('refuses a gzip bomb instead of inflating it', async () => {
    const server = await start({ maxSingleRecordBytes: 64 * 1024 });
    const id = newIdentity();
    const records = buildChain(1);
    const chainId = records[0]!.hash;
    const bomb = Buffer.alloc(4 * 1024 * 1024, 0x41);
    const res = await post(server.url, {
      chainId,
      id,
      from: 1,
      to: 1,
      baseHash: GENESIS_HASH,
      records,
      head: headFor(id, records),
      bodyOverride: bomb,
      gzip: true,
    });
    expect(res.status).toBe(413);
    expect(res.body.error).toBe('too_large');
  });
});

/* ============================== heartbeat ============================= */

describe('receiver: heartbeat and absence', () => {
  it('accepts a heartbeat and records the signed head, making withholding a subtraction', async () => {
    const server = await start();
    const id = newIdentity();
    const records = buildChain(10);
    const chainId = records[0]!.hash;

    await post(server.url, {
      chainId,
      id,
      from: 1,
      to: 3,
      baseHash: GENESIS_HASH,
      records: records.slice(0, 3),
      head: headFor(id, records.slice(0, 3)),
    });

    // The sender is at 10 and has delivered 3 — and says so with its own key.
    const res = await post(server.url, {
      chainId,
      id,
      from: 0,
      to: 0,
      baseHash: GENESIS_HASH,
      records: [],
      head: headFor(id, records),
    });
    expect(res.status).toBe(200);
    expect(res.body.next_seq).toBe(4);

    const state = server.receiver.store.chain(chainId)!;
    expect(state.claimed_head_seq).toBe(10);
    expect(state.claimed_head_seq - (state.next_seq - 1)).toBe(7);

    const heads = storedLines(chainId, 'heads.jsonl').map(
      (l) => JSON.parse(l) as { delivered_next_seq: number; head: SinkHead },
    );
    expect(heads.at(-1)!.head.seq).toBe(10);
    expect(heads.at(-1)!.delivered_next_seq).toBe(4);
  });

  it('alerts on silence, exactly once per outage', async () => {
    let clock = Date.parse('2026-09-17T10:00:00.000Z');
    const server = await start({
      heartbeatIntervalS: 60,
      silenceAfterIntervals: 3,
      now: () => new Date(clock),
    });
    const id = newIdentity();
    const records = buildChain(2);
    const chainId = records[0]!.hash;
    await post(server.url, {
      chainId,
      id,
      from: 1,
      to: 2,
      baseHash: GENESIS_HASH,
      records,
      head: headFor(id, records),
    });

    expect(server.receiver.scanForSilence()).toHaveLength(0);
    clock += 10 * 60 * 1000;
    const raised = server.receiver.scanForSilence();
    expect(raised).toHaveLength(1);
    expect(raised[0]!.kind).toBe('silent_chain');
    expect(raised[0]!.chain_id).toBe(chainId);
    // Not repeated on the next scan — one incident, not one per poll.
    expect(server.receiver.scanForSilence()).toHaveLength(0);
  });
});

/* ============================== surface =============================== */

describe('receiver: the API surface', () => {
  it('answers health without a token and leaks no data', async () => {
    const server = await start();
    const res = await fetch(`${server.url}/v1/health`);
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.status).toBe('ok');
    expect(Object.keys(body).sort()).toEqual(['protocol', 'status', 'time']);
  });

  it('has no DELETE, PUT or PATCH anywhere', async () => {
    const server = await start();
    for (const method of ['DELETE', 'PUT', 'PATCH']) {
      const res = await fetch(`${server.url}/v1/chains/${'a'.repeat(64)}/records`, {
        method,
        headers: { authorization: `Bearer ${INGEST_TOKEN}` },
      });
      expect(res.status).toBe(405);
      expect(res.headers.get('allow')).not.toContain(method);
    }
  });

  it('answers a malformed path or an unknown Content-Encoding with 400, never 500', async () => {
    const server = await start();
    const badPath = await fetch(`${server.url}/v1/chains/%E0%A4%A/records`, {
      method: 'POST',
      headers: { authorization: `Bearer ${INGEST_TOKEN}` },
      body: '{}',
    });
    expect(badPath.status).toBe(400);

    const badEncoding = await fetch(`${server.url}/v1/chains/${'a'.repeat(64)}/records`, {
      method: 'POST',
      headers: { authorization: `Bearer ${INGEST_TOKEN}`, 'content-encoding': 'br' },
      body: 'x',
    });
    expect(badEncoding.status).toBe(400);
    expect(((await badEncoding.json()) as { detail: string }).detail).toContain('Content-Encoding');
  });

  it('serves the cursor as the authoritative resume point, across a restart', async () => {
    const server = await start();
    const id = newIdentity();
    const records = buildChain(3);
    const chainId = records[0]!.hash;
    await post(server.url, {
      chainId,
      id,
      from: 1,
      to: 3,
      baseHash: GENESIS_HASH,
      records,
      signatures: [headSignature(id, 3, records[2]!.hash)],
      head: headFor(id, records),
    });
    await server.close();

    // Same data dir, fresh process state: the cursor must survive, or a
    // restarted shipper cannot resume without re-sending everything.
    handle = await serveReceiver({ dataDir, operatorToken: OPERATOR_TOKEN, silenceScanMs: 0 });
    const res = await fetch(`${handle.url}/v1/chains/${chainId}/cursor`, {
      headers: { authorization: `Bearer ${INGEST_TOKEN}`, [HEADERS.KEY]: id.pub },
    });
    expect(res.status).toBe(200);
    const cursor = (await res.json()) as SinkCursor;
    expect(cursor.next_seq).toBe(4);
    expect(cursor.head_hash).toBe(records[2]!.hash);
    expect(cursor.attested_seq).toBe(3);

    // ...and the next batch links onto it with no re-send of the backlog.
    const more = buildChain(5);
    const res2 = await post(handle.url, {
      chainId,
      id,
      from: cursor.next_seq,
      to: 5,
      baseHash: cursor.head_hash,
      records: more.slice(3, 5),
      head: headFor(id, more),
    });
    expect(res2.status).toBe(202);
    expect(res2.body.next_seq).toBe(6);
    expect(storedLines(chainId, 'records.jsonl')).toHaveLength(5);
  });

  it('shows an operator what it holds, what it refused, and who went quiet', async () => {
    const server = await start();
    const id = newIdentity();
    const records = buildChain(6);
    const chainId = records[0]!.hash;
    await post(server.url, {
      chainId,
      id,
      from: 1,
      to: 2,
      baseHash: GENESIS_HASH,
      records: records.slice(0, 2),
      head: headFor(id, records),
    });
    // ...and one refusal, so the rejection log has something in it.
    await post(server.url, {
      chainId,
      id,
      from: 5,
      to: 6,
      baseHash: records[3]!.hash,
      records: records.slice(4, 6),
      head: headFor(id, records),
    });

    const auth = { authorization: `Bearer ${OPERATOR_TOKEN}` };
    const chains = (await (await fetch(`${server.url}/v1/chains`, { headers: auth })).json()) as {
      chains: Array<{ chain_id: string; undelivered: number; next_seq: number; records_held: number }>;
    };
    expect(chains.chains).toHaveLength(1);
    expect(chains.chains[0]!.chain_id).toBe(chainId);
    expect(chains.chains[0]!.records_held).toBe(2);
    expect(chains.chains[0]!.undelivered).toBe(4);

    const rejections = (await (
      await fetch(`${server.url}/v1/rejections`, { headers: auth })
    ).json()) as { rejections: Array<{ error: string; from_seq: number }> };
    expect(rejections.rejections.at(-1)!.error).toBe('chain_gap');
    expect(rejections.rejections.at(-1)!.from_seq).toBe(5);

    const denied = await fetch(`${server.url}/v1/chains`);
    expect(denied.status).toBe(401);
  });
});

/* ============================ replica export ========================== */

describe('receiver: exporting from the replica', () => {
  it('truncates the bundle to the attested head and reuses the stored signature', async () => {
    const server = await start();
    const id = newIdentity();
    const records = buildChain(5);
    const chainId = records[0]!.hash;

    // Five delivered, but only seq 3 is attested by a signature we verified.
    await post(server.url, {
      chainId,
      id,
      from: 1,
      to: 5,
      baseHash: GENESIS_HASH,
      records,
      signatures: [headSignature(id, 3, records[2]!.hash)],
      head: headFor(id, records),
    });

    const out = join(dataDir, 'bundle');
    const result = await exportReceivedChain({
      store: server.receiver.store,
      chainId,
      dirPath: out,
      toolVersion: '0.1.0',
    });

    // The receiver holds no private key, so the bundle can only claim what a
    // stored signature already covers.
    expect(result.manifest.range).toEqual({ from_seq: 1, to_seq: 3 });
    expect(result.manifest.head_hash).toBe(records[2]!.hash);
    expect(result.manifest.signature.public_key).toBe(id.pub);
    expect(result.unattested_records).toBe(2);
    expect(result.claimed_head_seq).toBe(5);

    // The stranger's path: zero dependencies, exit 0, PASS.
    const proc = spawnSync(process.execPath, ['verify.cjs'], { cwd: out, encoding: 'utf8' });
    expect(proc.status).toBe(0);
    expect(proc.stdout).toContain('PASS');
  });

  it('refuses to export a chain nothing has attested, rather than bundling an unsigned head', async () => {
    const server = await start();
    const id = newIdentity();
    const records = buildChain(2);
    const chainId = records[0]!.hash;
    await post(server.url, {
      chainId,
      id,
      from: 1,
      to: 2,
      baseHash: GENESIS_HASH,
      records,
      head: headFor(id, records),
    });
    await expect(
      exportReceivedChain({
        store: server.receiver.store,
        chainId,
        dirPath: join(dataDir, 'bundle2'),
        toolVersion: '0.1.0',
      }),
    ).rejects.toThrow(/no verified signature/);
  });
});
