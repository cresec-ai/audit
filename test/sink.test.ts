/**
 * Evidence sink — SENDER half.
 *
 * What these tests are actually defending:
 *   1. fail-open, absolutely (a hanging / 500ing / 401ing / unresolvable sink
 *      changes nothing about the proxy's bytes, latency or exit code);
 *   2. the wire carries only what the redactor already sealed;
 *   3. a gap is never manufactured — a sender that cannot link STALLS, and
 *      the stall is visible rather than silent;
 *   4. resume after a restart picks up from the RECEIVER's cursor;
 *   5. an idempotent replay does not fork or duplicate.
 */

import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomUUID } from 'node:crypto';
import { afterEach, describe, expect, it } from 'vitest';

import { GENESIS_HASH, computeHash, sha256Ref } from '../src/chain/hash.js';
import { Signer } from '../src/chain/keys.js';
import { openStore } from '../src/store/index.js';
import { verifyRecords } from '../src/verify/verify.js';
import { SCHEMA } from '../src/schema/events.js';
import type { AnyEvent, ChainRecord } from '../src/schema/events.js';
import { normalizeSinkUrl, resolveSinkConfig } from '../src/sink/config.js';
import { SINK_HEADERS, chainIdFromGenesisRecord, sinkSignedPayload } from '../src/sink/protocol.js';
import { advanceSelfCheck, newSelfCheck } from '../src/sink/selfcheck.js';
import { runShipper } from '../src/sink/shipper.js';
import { cliEntryPoint, ensureShipper } from '../src/sink/spawn.js';
import {
  acquireShipLock,
  readCursorCache,
  readShipStatus,
  shipperLooksAlive,
} from '../src/sink/state.js';
import type { EvidenceStore } from '../src/types.js';
import { ENV } from '../src/types.js';
import { spawnTsx } from './helpers/tsx.js';
import { startHangingSink, startSinkReceiver } from './helpers/sink-receiver.js';
import type { SinkReceiver } from './helpers/sink-receiver.js';

const ROOT = resolve(fileURLToPath(new URL('..', import.meta.url)));
const ECHO_SERVER = join(ROOT, 'test', 'fixtures', 'echo-server.cjs');

const cleanups: Array<() => void | Promise<void>> = [];
afterEach(async () => {
  while (cleanups.length > 0) {
    const fn = cleanups.pop()!;
    try {
      await fn();
    } catch {
      /* best effort */
    }
  }
});

function tempDir(tag: string): string {
  const dir = mkdtempSync(join(tmpdir(), `mcp-recorder-sink-${tag}-`));
  cleanups.push(() => rmSync(dir, { recursive: true, force: true }));
  return dir;
}

/** A recorded event whose payload is ALREADY hashed, as the redactor leaves it. */
function toolCallEvent(sessionId: string, tool: string, secret: string): AnyEvent {
  return {
    schema: SCHEMA,
    event_id: randomUUID(),
    session_id: sessionId,
    timestamp: new Date().toISOString(),
    kind: 'tool_call',
    identity: { fingerprint: sha256Ref('identity') },
    server: { name: 'echo-server', command: 'node echo', transport: 'stdio' },
    attributes: {},
    tool,
    request_id: 1,
    args: { token: { redacted: true, ref: sha256Ref(secret), len: secret.length } },
    result_hash: sha256Ref('result'),
    result: { text: { redacted: true, ref: sha256Ref(secret), len: secret.length } },
    is_error: false,
    duration_ms: 3,
  };
}

interface Fixture {
  dataDir: string;
  store: EvidenceStore;
  signer: Signer;
  chainId: string;
  seal(count: number, secret?: string): ChainRecord[];
}

async function fixture(tag: string, seed = 3, secret = 'sk-test-secret'): Promise<Fixture> {
  const dataDir = tempDir(tag);
  const store = openStore({ dataDir, backend: 'jsonl' });
  cleanups.push(() => store.close());
  const signer = await Signer.load(dataDir);
  const sessionId = randomUUID();
  const seal = (count: number, s = secret): ChainRecord[] => {
    const events: AnyEvent[] = [];
    for (let i = 0; i < count; i++) events.push(toolCallEvent(sessionId, `tool_${String(i)}`, s));
    const sealed = store.appendEvents(events);
    return sealed;
  };
  seal(seed);
  // Sign the head, as the recorder does on every flush.
  const head = store.head();
  store.addSignature(await signer.sign(head.seq, head.hash));
  const genesis = [...store.iterate({ fromSeq: 1, toSeq: 1 })][0]!;
  return { dataDir, store, signer, chainId: chainIdFromGenesisRecord(genesis), seal };
}

function receiver(handle: SinkReceiver): SinkReceiver {
  cleanups.push(() => handle.close());
  return handle;
}

const FAST = {
  pollIntervalMs: 5,
  connectTimeoutMs: 1_000,
  totalTimeoutMs: 2_000,
  heartbeatIntervalMs: 10_000,
} as const;

/* ------------------------------------------------------------------ */
/* config                                                              */
/* ------------------------------------------------------------------ */

describe('sink config', () => {
  it('opts in on MCP_RECORDER_SINK alone and stays off without it', () => {
    expect(resolveSinkConfig({ env: {} }).sink).toBeUndefined();
    const on = resolveSinkConfig({
      env: { [ENV.SINK]: 'https://sink.example.com/', [ENV.SINK_TOKEN]: 't' },
    });
    expect(on.sink).toEqual({ url: 'https://sink.example.com', token: 't' });
    expect(on.warnings).toEqual([]);
  });

  it('refuses plain http off loopback, and says so instead of throwing', () => {
    const res = resolveSinkConfig({ env: { [ENV.SINK]: 'http://sink.example.com' } });
    expect(res.sink).toBeUndefined();
    expect(res.warnings.join(' ')).toMatch(/refusing plain http/);
    // Loopback is the one exception, so tests and a local relay still work.
    expect(normalizeSinkUrl('http://127.0.0.1:9/ingest')).toEqual({
      url: 'http://127.0.0.1:9/ingest',
    });
  });

  it('refuses a userinfo URL — it would leak into process listings', () => {
    const res = resolveSinkConfig({ env: { [ENV.SINK]: 'https://tok@sink.example.com' } });
    expect(res.sink).toBeUndefined();
    expect(res.warnings.join(' ')).toMatch(/userinfo/);
  });

  it('never throws on a malformed URL; it disables the sink and warns', () => {
    const res = resolveSinkConfig({ env: { [ENV.SINK]: 'not a url' } });
    expect(res.sink).toBeUndefined();
    expect(res.warnings.join(' ')).toMatch(/evidence sink disabled/);
  });
});

/* ------------------------------------------------------------------ */
/* delivery, verification and the wire itself                          */
/* ------------------------------------------------------------------ */

describe('sink delivery', () => {
  it('ships sealed records the receiver can verify with the ordinary verifier', async () => {
    const f = await fixture('deliver');
    const sink = receiver(await startSinkReceiver({ requireToken: 'tok' }));

    const result = await runShipper({
      dataDir: f.dataDir,
      sink: { url: sink.url, token: 'tok' },
      store: f.store,
      signer: f.signer,
      toolVersion: '0.0.0-test',
      surface: 'ship',
      drain: true,
      drainTimeoutMs: 5_000,
      ...FAST,
    });

    expect(result.state).toBe('idle');
    expect(result.delivered).toBe(3);
    expect(result.lag).toBe(0);

    const stored = sink.chain(f.chainId)!;
    const records = [...stored.records.values()].sort((a, b) => a.seq - b.seq);
    expect(records.map((r) => r.seq)).toEqual([1, 2, 3]);

    // The receiver's copy verifies under verify/verify.ts — deliberately the
    // same algorithm, so the two halves cannot drift.
    const verdict = await verifyRecords(records, stored.signatures, {
      expectedPublicKeyHex: f.signer.publicKeyHex,
    });
    expect(verdict.ok).toBe(true);
    expect(verdict.checked_events).toBe(3);

    // received_at is the only metadata the sender does not control.
    expect(stored.receivedAt.get(1)).toBeTruthy();
  });

  it('signs every request over the domain-separated payload, under the data dir key', async () => {
    const f = await fixture('signature');
    const sink = receiver(await startSinkReceiver());
    await runShipper({
      dataDir: f.dataDir,
      sink: { url: sink.url },
      store: f.store,
      signer: f.signer,
      toolVersion: '0.0.0-test',
      surface: 'ship',
      drain: true,
      drainTimeoutMs: 5_000,
      ...FAST,
    });

    const post = sink.posts.find((p) => p.status === 202)!;
    expect(post.headers[SINK_HEADERS.KEY]).toBe(f.signer.publicKeyHex);
    expect(post.headers[SINK_HEADERS.PROTOCOL]).toBe('1');
    // The digest header is over the DECOMPRESSED bytes; the helper already
    // enforced that, and would have answered 400 otherwise.
    expect(post.status).toBe(202);
    // Domain separation: the sink payload prefix is not the head prefix.
    const payload = sinkSignedPayload(f.chainId, 1, 3, String(post.headers[SINK_HEADERS.CONTENT_SHA256]));
    expect(Buffer.from(payload).toString('utf8')).toMatch(/^edut\.mcp-recorder\.sink\.v1\n/);
  });

  it('puts nothing on the wire that is not already in the store', async () => {
    const secret = 'CORRELATED-PLAINTEXT-a7f3c1';
    const f = await fixture('wire', 4, secret);
    const sink = receiver(await startSinkReceiver());
    await runShipper({
      dataDir: f.dataDir,
      sink: { url: sink.url },
      store: f.store,
      signer: f.signer,
      toolVersion: '0.0.0-test',
      surface: 'ship',
      drain: true,
      drainTimeoutMs: 5_000,
      ...FAST,
    });

    expect(sink.posts.length).toBeGreaterThan(0);
    for (const post of sink.posts) {
      const text = post.raw.toString('utf8');
      expect(text).not.toContain(secret);
      // The hash of the value IS expected — that is what the redactor sealed.
      expect(text).toContain(sha256Ref(secret));
    }

    // And the same holds for the local store: the wire is a copy of it.
    const onDisk = readFileSync(join(f.dataDir, 'evidence.jsonl'), 'utf8');
    expect(onDisk).not.toContain(secret);
  });

  it('gzips a large batch and still signs the DECOMPRESSED bytes', async () => {
    const f = await fixture('gzip', 40);
    const sink = receiver(await startSinkReceiver());
    const result = await runShipper({
      dataDir: f.dataDir,
      sink: { url: sink.url },
      store: f.store,
      signer: f.signer,
      toolVersion: '0.0.0-test',
      surface: 'ship',
      drain: true,
      drainTimeoutMs: 5_000,
      gzipThresholdBytes: 1, // force the compressed path
      ...FAST,
    });
    expect(result.delivered).toBe(40);
    const post = sink.posts.find((p) => p.status === 202)!;
    expect(post.headers['content-encoding']).toBe('gzip');
    // The receiver hashed what it DECOMPRESSED and the signature verified —
    // a 202 is only reachable that way. A TLS-terminating proxy that
    // re-encodes the transfer therefore cannot break the signature.
    expect(post.status).toBe(202);
    expect(post.raw.toString('utf8').startsWith('{"protocol":1')).toBe(true);
  });
});

/* ------------------------------------------------------------------ */
/* resume, idempotency, and never manufacturing a gap                  */
/* ------------------------------------------------------------------ */

describe('sink resume and idempotency', () => {
  it('resumes from the receiver cursor after a restart, with no gap and no full re-send', async () => {
    const f = await fixture('resume', 3);
    const sink = receiver(await startSinkReceiver());
    const base = {
      dataDir: f.dataDir,
      sink: { url: sink.url },
      store: f.store,
      signer: f.signer,
      toolVersion: '0.0.0-test',
      surface: 'ship' as const,
      drain: true,
      drainTimeoutMs: 5_000,
      ...FAST,
    };

    const first = await runShipper(base);
    expect(first.delivered).toBe(3);
    expect(sink.nextSeq(f.chainId)).toBe(4);

    // "Restart": more events are sealed while nothing is shipping, then a
    // brand-new shipper run starts from scratch.
    f.seal(2);
    f.store.addSignature(await f.signer.sign(f.store.head().seq, f.store.head().hash));

    const postsBefore = sink.posts.filter((p) => p.status === 202).length;
    const second = await runShipper(base);
    expect(second.delivered).toBe(2); // only the new ones
    expect(second.lag).toBe(0);
    expect(sink.nextSeq(f.chainId)).toBe(6);

    const newPosts = sink.posts.filter((p) => p.status === 202).slice(postsBefore);
    expect(newPosts).toHaveLength(1);
    expect(newPosts[0]!.body!.from_seq).toBe(4);
    expect(newPosts[0]!.body!.to_seq).toBe(5);

    const stored = sink.chain(f.chainId)!;
    expect([...stored.records.keys()].sort((a, b) => a - b)).toEqual([1, 2, 3, 4, 5]);
    expect(stored.forkedSeqs).toEqual([]);
  });

  it('replaying a byte-identical batch leaves next_seq unchanged and stores no duplicate', async () => {
    const f = await fixture('idempotent', 2);
    const sink = receiver(await startSinkReceiver());
    const genesis = [...f.store.iterate({ fromSeq: 1, toSeq: 1 })][0]!;
    const head = f.store.head();

    const { SinkClient } = await import('../src/sink/client.js');
    const client = new SinkClient({
      sink: { url: sink.url },
      signer: f.signer,
      chainId: f.chainId,
      sender: { tool_version: '0.0.0-test', surface: 'ship', backend: f.store.backend },
    });
    const body = client.buildBody({
      fromSeq: 1,
      toSeq: 2,
      baseHash: genesis.prev_hash,
      records: [...f.store.iterate({ fromSeq: 1, toSeq: 2 })],
      signatures: [],
      head: { seq: head.seq, hash: head.hash, signature: await f.signer.sign(head.seq, head.hash) },
    });

    const first = await client.postBatch(body);
    expect(first.kind).toBe('ok');
    const afterFirst = sink.nextSeq(f.chainId);

    const second = await client.postBatch(body);
    expect(second.kind).toBe('ok');
    expect(sink.nextSeq(f.chainId)).toBe(afterFirst);
    expect(sink.chain(f.chainId)!.records.size).toBe(2);
    expect(sink.chain(f.chainId)!.forkedSeqs).toEqual([]);
  });

  it('rewinds on 409 chain_gap instead of skipping — a receiver that cannot link is never jumped', async () => {
    const f = await fixture('gap', 4);
    const sink = receiver(await startSinkReceiver());
    const { SinkClient } = await import('../src/sink/client.js');
    const client = new SinkClient({
      sink: { url: sink.url },
      signer: f.signer,
      chainId: f.chainId,
      sender: { tool_version: '0.0.0-test', surface: 'ship', backend: f.store.backend },
    });
    const head = f.store.head();
    const tail = [...f.store.iterate({ fromSeq: 3, toSeq: 4 })];

    // Claim a range the receiver cannot link to: it holds nothing yet.
    const outcome = await client.postBatch(
      client.buildBody({
        fromSeq: 3,
        toSeq: 4,
        baseHash: tail[0]!.prev_hash,
        records: tail,
        signatures: [],
        head: { seq: head.seq, hash: head.hash, signature: await f.signer.sign(head.seq, head.hash) },
      }),
    );
    expect(outcome.kind).toBe('gap');
    expect(sink.chain(f.chainId)).toBeUndefined(); // and it stored nothing

    // The shipper then starts from the receiver's next_seq, which is 1.
    const result = await runShipper({
      dataDir: f.dataDir,
      sink: { url: sink.url },
      store: f.store,
      signer: f.signer,
      toolVersion: '0.0.0-test',
      surface: 'ship',
      drain: true,
      drainTimeoutMs: 5_000,
      ...FAST,
    });
    expect(result.delivered).toBe(4);
    expect([...sink.chain(f.chainId)!.records.keys()].sort((a, b) => a - b)).toEqual([1, 2, 3, 4]);
  });

  it('a mutated event fails the receiver hash recomputation with 400', async () => {
    const f = await fixture('mutated', 2);
    const sink = receiver(await startSinkReceiver());
    const { SinkClient } = await import('../src/sink/client.js');
    const client = new SinkClient({
      sink: { url: sink.url },
      signer: f.signer,
      chainId: f.chainId,
      sender: { tool_version: '0.0.0-test', surface: 'ship', backend: f.store.backend },
    });
    const head = f.store.head();
    const records = [...f.store.iterate({ fromSeq: 1, toSeq: 2 })].map((r) => ({ ...r }));
    // Widen ONE field inside the sealed event — exactly what a sink that
    // tried to add readable context would have to do.
    records[1] = {
      ...records[1]!,
      event: { ...records[1]!.event, tool: 'rewritten_by_the_sender' } as AnyEvent,
    };

    const outcome = await client.postBatch(
      client.buildBody({
        fromSeq: 1,
        toSeq: 2,
        baseHash: records[0]!.prev_hash,
        records,
        signatures: [],
        head: { seq: head.seq, hash: head.hash, signature: await f.signer.sign(head.seq, head.hash) },
      }),
    );
    expect(outcome.kind).toBe('bad_request');
    expect(sink.chain(f.chainId)).toBeUndefined();
  });

  it('a batch signed by another key is rejected before the body is trusted', async () => {
    const f = await fixture('wrongkey', 2);
    const other = await Signer.load(tempDir('otherkey'));
    const sink = receiver(await startSinkReceiver());
    const { SinkClient } = await import('../src/sink/client.js');
    // X-MCPR-Key says `other`, the signature is made by `other` too — but the
    // records were sealed under f.signer, so nothing links this batch to the
    // chain it claims. The receiver files under (key, chain_id) and refuses.
    const client = new SinkClient({
      sink: { url: sink.url },
      signer: {
        publicKeyHex: other.publicKeyHex,
        // Sign with the WRONG key relative to X-MCPR-Key: f's key is
        // advertised nowhere, so the signature cannot verify.
        signBytes: (payload: Uint8Array) => f.signer.signBytes(payload),
      },
      chainId: f.chainId,
      sender: { tool_version: '0.0.0-test', surface: 'ship', backend: f.store.backend },
    });
    const head = f.store.head();
    const records = [...f.store.iterate({ fromSeq: 1, toSeq: 2 })];
    const outcome = await client.postBatch(
      client.buildBody({
        fromSeq: 1,
        toSeq: 2,
        baseHash: records[0]!.prev_hash,
        records,
        signatures: [],
        head: { seq: head.seq, hash: head.hash, signature: await f.signer.sign(head.seq, head.hash) },
      }),
    );
    expect(outcome.kind).toBe('bad_request');
    expect(sink.chain(f.chainId)).toBeUndefined();
  });
});

/* ------------------------------------------------------------------ */
/* withholding, stalls, and the signed head                            */
/* ------------------------------------------------------------------ */

describe('sink visibility', () => {
  it('a 400 on the same range twice STALLS visibly instead of skipping', async () => {
    const f = await fixture('stall', 3);
    const sink = receiver(await startSinkReceiver({ mode: 'badrequest' }));
    const lines: string[] = [];

    const result = await runShipper({
      dataDir: f.dataDir,
      sink: { url: sink.url },
      store: f.store,
      signer: f.signer,
      toolVersion: '0.0.0-test',
      surface: 'ship',
      drain: true,
      drainTimeoutMs: 5_000,
      log: (m) => lines.push(m),
      ...FAST,
    });

    expect(result.state).toBe('stalled');
    // Nothing skipped: the receiver still has nothing, and the sender has not
    // advanced past the range it could not deliver.
    expect(result.nextSeq).toBe(1);
    expect(result.lag).toBe(3);
    expect(lines.join('\n')).toMatch(/stalled on seq 1-3/);

    // ...and the stall is written down, not merely logged. This is the
    // difference between an invisible condition and a human-legible one.
    const status = readShipStatus(f.dataDir)!;
    expect(status.state).toBe('stalled');
    expect(status.lag).toBe(3);
    expect(status.last_error).toMatch(/twice/);
  });

  it('the signed head quantifies what is being withheld, in the sender own key', async () => {
    const f = await fixture('withheld', 6);
    // The receiver caps batches at 2, so the first POST provably leaves 4
    // sealed records behind — and has to say so.
    const sink = receiver(await startSinkReceiver({ maxRecords: 2 }));
    await runShipper({
      dataDir: f.dataDir,
      sink: { url: sink.url },
      store: f.store,
      signer: f.signer,
      toolVersion: '0.0.0-test',
      surface: 'ship',
      maxPosts: 1,
      ...FAST,
    });

    const post = sink.posts[0]!;
    expect(post.body!.to_seq).toBe(2);
    expect(post.body!.head.seq).toBe(6);
    // head.seq - to_seq is exactly how much the sender is admitting it holds
    // back. It is a subtraction, attested by the sender's own key.
    expect(post.body!.head.seq - post.body!.to_seq).toBe(4);
    expect(post.body!.head.signature.public_key).toBe(f.signer.publicKeyHex);
  });

  it('413 on a ONE-record batch stalls rather than skipping the record', async () => {
    const f = await fixture('toolarge', 2);
    const sink = receiver(await startSinkReceiver({ mode: 'toolarge', maxRecords: 1 }));
    const result = await runShipper({
      dataDir: f.dataDir,
      sink: { url: sink.url },
      store: f.store,
      signer: f.signer,
      toolVersion: '0.0.0-test',
      surface: 'ship',
      drain: true,
      drainTimeoutMs: 5_000,
      random: () => 0,
      ...FAST,
    });
    expect(result.state).toBe('stalled');
    expect(result.nextSeq).toBe(1); // nothing advanced, nothing skipped
    expect(readShipStatus(f.dataDir)!.last_error).toMatch(/too large/);
  });

  it('refuses to ship when the receiver head_hash is not this chain', async () => {
    const f = await fixture('mitm', 3);
    const sink = receiver(await startSinkReceiver());

    // Seed the receiver with a DIFFERENT chain under the same chain_id by
    // storing a record whose hash disagrees, then let the shipper look.
    const bogus: ChainRecord = {
      seq: 1,
      prev_hash: GENESIS_HASH,
      hash: 'f'.repeat(64),
      event: toolCallEvent('other', 'other', 'x'),
    };
    sink.chains.set(f.chainId, {
      key: f.signer.publicKeyHex,
      records: new Map([[1, bogus]]),
      signatures: [],
      attestedSeq: 0,
      forkedSeqs: [],
      receivedAt: new Map([[1, new Date().toISOString()]]),
    });

    const lines: string[] = [];
    const result = await runShipper({
      dataDir: f.dataDir,
      sink: { url: sink.url },
      store: f.store,
      signer: f.signer,
      toolVersion: '0.0.0-test',
      surface: 'ship',
      drain: true,
      drainTimeoutMs: 5_000,
      log: (m) => lines.push(m),
      ...FAST,
    });

    expect(result.state).toBe('forked');
    expect(lines.join('\n')).toMatch(/FORK DETECTED/);
    // It shipped nothing: the receiver's copy is untouched.
    expect(sink.chain(f.chainId)!.records.size).toBe(1);
  });

  it('401 parks the shipper as unauthorized and says so exactly once', async () => {
    const f = await fixture('unauth', 2);
    const sink = receiver(await startSinkReceiver({ mode: 'unauthorized' }));
    const lines: string[] = [];
    const result = await runShipper({
      dataDir: f.dataDir,
      sink: { url: sink.url, token: 'wrong' },
      store: f.store,
      signer: f.signer,
      toolVersion: '0.0.0-test',
      surface: 'ship',
      drain: true,
      drainTimeoutMs: 5_000,
      log: (m) => lines.push(m),
      ...FAST,
    });
    expect(result.state).toBe('unauthorized');
    expect(lines.filter((l) => /refused this install's credential/.test(l))).toHaveLength(1);
    expect(readShipStatus(f.dataDir)!.state).toBe('unauthorized');
  });

  it('keeps the local store intact and retries forever against a 500ing sink', async () => {
    const f = await fixture('fivehundred', 2);
    const sink = receiver(await startSinkReceiver({ failFirstWrites: 2 }));
    const result = await runShipper({
      dataDir: f.dataDir,
      sink: { url: sink.url },
      store: f.store,
      signer: f.signer,
      toolVersion: '0.0.0-test',
      surface: 'ship',
      drain: true,
      drainTimeoutMs: 8_000,
      random: () => 0, // deterministic full-jitter: no waiting in the test
      ...FAST,
    });
    expect(result.delivered).toBe(2);
    expect(sink.posts.filter((p) => p.status === 500)).toHaveLength(2);
    expect(f.store.count()).toBe(2); // untouched by any of it
  });

  it('caches the receiver cursor but never treats the cache as authoritative', async () => {
    const f = await fixture('cursor', 2);
    const sink = receiver(await startSinkReceiver());
    const opts = {
      dataDir: f.dataDir,
      sink: { url: sink.url },
      store: f.store,
      signer: f.signer,
      toolVersion: '0.0.0-test',
      surface: 'ship' as const,
      drain: true,
      drainTimeoutMs: 5_000,
      ...FAST,
    };
    await runShipper(opts);
    const cached = readCursorCache(f.dataDir, sink.url)!;
    expect(cached.next_seq).toBe(3);
    expect(cached.chain_id).toBe(f.chainId);

    // Wipe the receiver: a stale cache must not cause a silent gap. The
    // shipper asks on startup, is told next_seq is 1, and re-sends.
    sink.chains.delete(f.chainId);
    const again = await runShipper(opts);
    expect(again.delivered).toBe(2);
    expect([...sink.chain(f.chainId)!.records.keys()].sort((a, b) => a - b)).toEqual([1, 2]);
  });
});

/* ------------------------------------------------------------------ */
/* the shipper verifies its OWN chain before extending the receiver's  */
/* ------------------------------------------------------------------ */

/** Every record on disk, in seq order. */
function readRecords(dataDir: string): ChainRecord[] {
  return readFileSync(join(dataDir, 'evidence.jsonl'), 'utf8')
    .split('\n')
    .filter((line) => line.length > 0)
    .map((line) => JSON.parse(line) as ChainRecord);
}

function writeRecords(dataDir: string, records: ChainRecord[]): void {
  writeFileSync(
    join(dataDir, 'evidence.jsonl'),
    records.map((r) => JSON.stringify(r)).join('\n') + '\n',
  );
}

/**
 * Local dogfood 6's attack, exactly: rewrite one sealed event and leave every
 * stored `hash`/`prev_hash` alone, so the head hash the receiver knows still
 * matches and the tampered store can keep extending the remote chain.
 */
function rewriteEventInPlace(dataDir: string, seq: number, tool: string): void {
  writeRecords(
    dataDir,
    readRecords(dataDir).map((record) =>
      record.seq === seq ? { ...record, event: { ...record.event, tool } as AnyEvent } : record,
    ),
  );
}

/**
 * The careful version: rewrite an event AND re-link every hash after it, so
 * the chain is internally consistent again. Only a head signature made before
 * the rewrite can still tell.
 */
function rewriteAndRelink(dataDir: string, seq: number, tool: string): void {
  const records = readRecords(dataDir);
  let prevHash = records[0]!.prev_hash;
  writeRecords(
    dataDir,
    records.map((record) => {
      const event = record.seq === seq ? ({ ...record.event, tool } as AnyEvent) : record.event;
      const rewritten: ChainRecord = {
        ...record,
        prev_hash: prevHash,
        hash: computeHash(prevHash, event),
        event,
      };
      prevHash = rewritten.hash;
      return rewritten;
    }),
  );
}

/** A second handle on the same data dir — what the real shipper process has. */
function reopen(dataDir: string): EvidenceStore {
  const store = openStore({ dataDir, backend: 'jsonl' });
  cleanups.push(() => store.close());
  return store;
}

/** Wraps a store so a test can see exactly which records were read back. */
function countingStore(inner: EvidenceStore): { store: EvidenceStore; read: number[] } {
  const read: number[] = [];
  const store: EvidenceStore = {
    get backend() {
      return inner.backend;
    },
    get path() {
      return inner.path;
    },
    head: () => inner.head(),
    append: (records) => inner.append(records),
    appendEvents: (events) => inner.appendEvents(events),
    addSignature: (sig) => inner.addSignature(sig),
    latestSignature: () => inner.latestSignature(),
    signatures: () => inner.signatures(),
    *iterate(opts) {
      for (const record of inner.iterate(opts)) {
        read.push(record.seq);
        yield record;
      }
    },
    count: () => inner.count(),
    sessions: () => inner.sessions(),
    close: () => inner.close(),
  };
  return { store, read };
}

describe('sink self-check', () => {
  it('stops shipping when history the receiver ALREADY HOLDS was rewritten', async () => {
    // Dogfood 6, step C: the tampered copy shipped seq 12-22 unchallenged and
    // the honest store was the one blamed for the fork. Shipping forward from
    // the receiver's cursor never looked behind it.
    const f = await fixture('selfcheck-delivered', 6);
    const sink = receiver(await startSinkReceiver());
    const lines: string[] = [];
    const opts = {
      dataDir: f.dataDir,
      sink: { url: sink.url },
      signer: f.signer,
      toolVersion: '0.0.0-test',
      surface: 'ship' as const,
      drain: true,
      drainTimeoutMs: 5_000,
      log: (m: string) => lines.push(m),
      // Small windows so the real shipper walks several of them, as it would
      // on a store far too big to verify in one.
      selfCheckWindow: 4,
      ...FAST,
    };

    const honest = await runShipper({ ...opts, store: f.store });
    expect(honest.delivered).toBe(6);

    // Three more sessions' worth of records, then the edit: seq 3 is already
    // at the receiver, and its stored hashes are left untouched so the head
    // the receiver knows still matches.
    f.seal(3);
    f.store.close();
    rewriteEventInPlace(f.dataDir, 3, 'quietly_rewritten');

    const tampered = await runShipper({ ...opts, store: reopen(f.dataDir) });

    expect(tampered.state).toBe('stalled');
    expect(tampered.delivered).toBe(0);
    expect(tampered.lag).toBe(3);
    // Not one of the new records reached the wire, let alone the receiver.
    expect(sink.posts.filter((p) => p.body !== undefined && p.body.records.length > 0)).toHaveLength(1);
    expect([...sink.chain(f.chainId)!.records.keys()].sort((a, b) => a - b)).toEqual([1, 2, 3, 4, 5, 6]);

    // ...and the stall names the rewritten seq, in the file `ship --status`
    // reads. A stall nobody can see is the failure mode being fixed here.
    const status = readShipStatus(f.dataDir)!;
    expect(status.state).toBe('stalled');
    expect(status.last_error).toMatch(/local evidence does not verify/);
    expect(status.last_error).toMatch(/hash_mismatch at seq 3/);
    expect(status.lag).toBe(3);
    expect(lines.join('\n')).toMatch(/sink stalled: local evidence does not verify/);
    expect(lines.join('\n')).toMatch(/mcp-recorder verify/);
  });

  it('catches a rewrite that re-links the hashes, because the old signature still attests', async () => {
    // Re-linking makes the chain self-consistent, so hash recomputation alone
    // cannot see it and the receiver would happily store it. The head
    // signature made before the rewrite is what still disagrees — which is
    // why the self-check verifies one signature per window rather than none.
    const f = await fixture('selfcheck-relink', 4);
    const sink = receiver(await startSinkReceiver());
    f.store.close();
    rewriteAndRelink(f.dataDir, 2, 'quietly_rewritten');

    const result = await runShipper({
      dataDir: f.dataDir,
      sink: { url: sink.url },
      store: reopen(f.dataDir),
      signer: f.signer,
      toolVersion: '0.0.0-test',
      surface: 'ship',
      drain: true,
      drainTimeoutMs: 5_000,
      ...FAST,
    });

    expect(result.state).toBe('stalled');
    expect(result.delivered).toBe(0);
    expect(readShipStatus(f.dataDir)!.last_error).toMatch(/signature_chain_mismatch at seq 4/);
    expect(sink.chain(f.chainId)).toBeUndefined();
  });

  it('leaves an honest store alone: a receiver far behind still gets everything', async () => {
    // "Merely behind" is not "tampered": nothing has been delivered yet, the
    // batches are capped so there are four of them, and the tail is unsigned
    // (the recorder signs per flush, so a tail newer than the last flush is
    // ordinary). None of that may stall the chain.
    const f = await fixture('selfcheck-behind', 3);
    f.seal(4);
    const sink = receiver(await startSinkReceiver({ maxRecords: 2 }));

    const result = await runShipper({
      dataDir: f.dataDir,
      sink: { url: sink.url },
      store: f.store,
      signer: f.signer,
      toolVersion: '0.0.0-test',
      surface: 'ship',
      drain: true,
      drainTimeoutMs: 5_000,
      ...FAST,
    });

    expect(result.state).toBe('idle');
    expect(result.delivered).toBe(7);
    expect(result.lag).toBe(0);
    expect([...sink.chain(f.chainId)!.records.keys()].sort((a, b) => a - b)).toEqual([
      1, 2, 3, 4, 5, 6, 7,
    ]);
    expect(readShipStatus(f.dataDir)!.state).toBe('idle');
  });

  it('says nothing about a store that has never recorded anything', async () => {
    const dataDir = tempDir('selfcheck-empty');
    const store = openStore({ dataDir, backend: 'jsonl' });
    cleanups.push(() => store.close());
    const signer = await Signer.load(dataDir);
    const sink = receiver(await startSinkReceiver());
    const lines: string[] = [];

    const result = await runShipper({
      dataDir,
      sink: { url: sink.url },
      store,
      signer,
      toolVersion: '0.0.0-test',
      surface: 'ship',
      drain: true,
      drainTimeoutMs: 5_000,
      log: (m) => lines.push(m),
      ...FAST,
    });

    expect(result.state).toBe('idle');
    expect(result.localHeadSeq).toBe(0);
    expect(lines).toEqual([]);
    expect(readShipStatus(dataDir)!.state).toBe('idle');
  });

  it('recomputes the history once, then pays only for the records being shipped', async () => {
    // The cost property: O(n) once per process, never O(n) per batch. If this
    // ever regresses, a shipper on a large store re-reads the whole chain
    // every poll interval.
    const f = await fixture('selfcheck-incremental', 6);
    const counted = countingStore(f.store);
    const self = newSelfCheck();

    const batch = [...f.store.iterate({ fromSeq: 5, toSeq: 6 })];
    counted.read.length = 0;
    expect(await advanceSelfCheck(counted.store, self, 6, batch)).toBeUndefined();
    expect(self.through).toBe(6);
    // Only the records BELOW the batch were read back; the batch itself was
    // verified as the objects about to go on the wire.
    expect(counted.read).toEqual([1, 2, 3, 4]);

    f.seal(2);
    const next = [...f.store.iterate({ fromSeq: 7, toSeq: 8 })];
    counted.read.length = 0;
    expect(await advanceSelfCheck(counted.store, self, 8, next)).toBeUndefined();
    expect(self.through).toBe(8);
    expect(counted.read).toEqual([]);

    // A later window still anchors on the earlier one, so a rewrite anywhere
    // below it is caught the next time the frontier has to move.
    expect(self.hash).toBe(f.store.head().hash);
  });

  it('walks a long chain in windows, and a rewrite in a middle one still stops it', async () => {
    // Windows bound the working set on a big store; each one anchors on the
    // previous one's recomputed hash and checks the newest signature inside
    // it, so a rewrite must not be able to hide between two of them.
    const f = await fixture('selfcheck-windows', 7);
    const pinned = { windowSize: 2, expectedPublicKeyHex: f.signer.publicKeyHex };

    const clean = newSelfCheck();
    expect(await advanceSelfCheck(f.store, clean, 7, [...f.store.iterate()], pinned)).toBeUndefined();
    expect(clean.through).toBe(7);

    f.store.close();
    rewriteEventInPlace(f.dataDir, 5, 'quietly_rewritten');
    const tampered = reopen(f.dataDir);
    const self = newSelfCheck();
    const problem = await advanceSelfCheck(tampered, self, 7, [...tampered.iterate()], pinned);
    expect(problem).toMatch(/hash_mismatch at seq 5/);
    // The frontier stopped at the last sound window instead of running on.
    expect(self.through).toBe(4);
    // And a failed chain stays failed without re-scanning it every poll.
    expect(await advanceSelfCheck(tampered, self, 7, [], pinned)).toBe(problem);
  });
});

/* ------------------------------------------------------------------ */
/* the shipper is a separate process, and one per data dir             */
/* ------------------------------------------------------------------ */

describe('shipper process', () => {
  it('resolves its own CLI entry point in both the tsx and the dist world', () => {
    expect(cliEntryPoint('file:///pkg/dist/sink/spawn.js')).toBe(join('/pkg', 'dist', 'cli.js'));
    expect(cliEntryPoint('file:///pkg/src/sink/spawn.ts')).toBe(join('/pkg', 'src', 'cli.ts'));
  });

  it('spawns at most one shipper per data dir, detached and unref-ed', () => {
    const dataDir = tempDir('spawn');
    const calls: Array<{ args: string[]; detached: unknown; stdio: unknown }> = [];
    const fakeSpawn = ((_cmd: string, args: string[], options: Record<string, unknown>) => {
      calls.push({ args, detached: options.detached, stdio: options.stdio });
      return { unref: () => undefined };
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
    }) as any;

    const config = { dataDir, redactMode: 'allowlist' as const, disabled: false };
    expect(ensureShipper({ config, sink: { url: 'https://s' }, surface: 'record', spawnFn: fakeSpawn })).toBe(true);
    expect(calls).toHaveLength(1);
    expect(calls[0]!.detached).toBe(true);
    expect(calls[0]!.stdio).toBe('ignore');
    expect(calls[0]!.args).toContain('ship');
    expect(calls[0]!.args).toContain(dataDir);

    // No lock yet (the fake child never took one), so a second call spawns
    // again; once a lock exists, it must not.
    const lock = acquireShipLock(dataDir)!;
    cleanups.push(() => lock.release());
    expect(shipperLooksAlive(dataDir)).toBe(true);
    expect(ensureShipper({ config, sink: { url: 'https://s' }, surface: 'record', spawnFn: fakeSpawn })).toBe(false);
    expect(calls).toHaveLength(1);
  });

  it('never spawns when recording is disabled by the kill switch', () => {
    const dataDir = tempDir('killswitch');
    let spawned = 0;
    const fakeSpawn = (() => {
      spawned++;
      return { unref: () => undefined };
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
    }) as any;
    expect(
      ensureShipper({
        config: { dataDir, redactMode: 'allowlist', disabled: true },
        sink: { url: 'https://s' },
        surface: 'record',
        spawnFn: fakeSpawn,
      }),
    ).toBe(false);
    expect(spawned).toBe(0);
  });
});

/* ------------------------------------------------------------------ */
/* the CLI surface an operator actually touches                        */
/* ------------------------------------------------------------------ */

function runCli(args: string[], env: NodeJS.ProcessEnv = {}): Promise<{ code: number | null; stdout: string; stderr: string }> {
  return new Promise((resolveRun) => {
    const child = spawnTsx(['src/cli.ts', ...args], { cwd: ROOT, env: { ...process.env, ...env } });
    let stdout = '';
    let stderr = '';
    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', (c: string) => {
      stdout += c;
    });
    child.stderr.on('data', (c: string) => {
      stderr += c;
    });
    child.on('close', (code) => resolveRun({ code, stdout, stderr }));
  });
}

describe('ship CLI', () => {
  it.skipIf(process.platform === 'win32')(
    'documents the flag AND the env var in --help',
    async () => {
      const help = await runCli(['--help']);
      expect(help.code).toBe(0);
      expect(help.stdout).toMatch(/mcp-recorder ship/);
      expect(help.stdout).toMatch(/--sink URL/);
      expect(help.stdout).toMatch(/MCP_RECORDER_SINK=URL/);
      expect(help.stdout).toMatch(/MCP_RECORDER_SINK_TOKEN_FILE/);
      expect(help.stdout).toMatch(/--drain/);
      expect(help.stdout).toMatch(/--status/);
    },
    30_000,
  );

  it.skipIf(process.platform === 'win32')(
    'drains a backlog and exits, and --status then reports zero lag',
    async () => {
      const f = await fixture('cli-drain', 3);
      const sink = receiver(await startSinkReceiver({ requireToken: 'tok' }));
      f.store.close();

      const drain = await runCli(
        ['ship', '--data-dir', f.dataDir, '--store', 'jsonl', '--drain', '--timeout', '10s'],
        { [ENV.SINK]: sink.url, [ENV.SINK_TOKEN]: 'tok' },
      );
      expect(drain.code ?? 0).toBe(0);
      expect(drain.stderr).toMatch(/delivered 3 record\(s\)/);
      expect(sink.nextSeq(f.chainId)).toBe(4);

      const status = await runCli(
        ['ship', '--data-dir', f.dataDir, '--store', 'jsonl', '--status', '--json'],
        { [ENV.SINK]: sink.url, [ENV.SINK_TOKEN]: 'tok' },
      );
      expect(status.code ?? 0).toBe(0);
      const report = JSON.parse(status.stdout) as Record<string, unknown>;
      expect(report.chain_id).toBe(f.chainId);
      expect(report.key).toBe(f.signer.publicKeyHex);
      expect(report.local_head_seq).toBe(3);
      expect(report.next_seq).toBe(4);
      expect(report.lag).toBe(0);
      expect(report.state).toBe('idle');
      // --status touched no network and left no lock behind.
      expect(existsSync(join(f.dataDir, 'ship.lock'))).toBe(false);
    },
    60_000,
  );

  it.skipIf(process.platform === 'win32')(
    'the daemon keeps running and picks up records sealed after it started',
    async () => {
      // This is what an unref-ed sleep timer silently broke: node keeps the
      // event loop alive for neither an unref-ed timer nor a signal handler,
      // so the daemon shipped its backlog once and then died — looking, at
      // the receiver, exactly like a killed machine.
      const f = await fixture('daemon', 2);
      const sink = receiver(await startSinkReceiver({ requireToken: 'tok' }));

      const child = spawnTsx(
        ['src/cli.ts', 'ship', '--data-dir', f.dataDir, '--store', 'jsonl', '--idle-exit', '60s'],
        {
          cwd: ROOT,
          env: { ...process.env, [ENV.SINK]: sink.url, [ENV.SINK_TOKEN]: 'tok' },
          stdio: ['ignore', 'ignore', 'ignore'],
        },
      );
      const exited = new Promise<number | null>((r) => child.on('close', (c) => r(c)));
      cleanups.push(async () => {
        child.kill('SIGTERM');
        await exited;
      });

      const waitFor = async (seq: number): Promise<void> => {
        const deadline = Date.now() + 20_000;
        while (Date.now() < deadline && sink.nextSeq(f.chainId) <= seq) {
          await new Promise((r) => setTimeout(r, 50));
        }
      };

      await waitFor(2);
      expect(sink.nextSeq(f.chainId)).toBe(3);

      // Seal two more from THIS process, the way a live proxy would while the
      // shipper is already running.
      f.seal(2);
      await waitFor(4);
      expect(sink.nextSeq(f.chainId)).toBe(5);
      expect([...sink.chain(f.chainId)!.records.keys()].sort((a, b) => a - b)).toEqual([1, 2, 3, 4]);

      child.kill('SIGTERM');
      expect(await exited).toBe(0);
      // ...and it let go of its single-instance lock on the way out.
      expect(shipperLooksAlive(f.dataDir)).toBe(false);
    },
    60_000,
  );

  it.skipIf(process.platform === 'win32')(
    'a drain against a sink that is down exits 0 — a sink outage must never fail a build',
    async () => {
      const f = await fixture('cli-down', 2);
      f.store.close();
      const run = await runCli(
        ['ship', '--data-dir', f.dataDir, '--store', 'jsonl', '--drain', '--timeout', '2s'],
        { [ENV.SINK]: 'https://sink.invalid.invalid.test', [ENV.SINK_TOKEN]: 'tok' },
      );
      expect(run.code ?? 0).toBe(0);
      expect(readShipStatus(f.dataDir)!.lag).toBe(2); // and the lag is on the record
    },
    60_000,
  );

  it.skipIf(process.platform === 'win32')(
    'a rewritten history stalls the real `ship` process, and `--status` says so',
    async () => {
      // The operator-visible half, end to end: dogfood 6's sequence run
      // through the real `ship` process rather than an in-process shipper.
      const f = await fixture('cli-selfcheck', 4);
      const sink = receiver(await startSinkReceiver({ requireToken: 'tok' }));
      const env = { [ENV.SINK]: sink.url, [ENV.SINK_TOKEN]: 'tok' };

      const honest = await runCli(
        ['ship', '--data-dir', f.dataDir, '--store', 'jsonl', '--drain', '--timeout', '10s'],
        env,
      );
      expect(honest.stderr).toMatch(/delivered 4 record\(s\)/);

      // Seal three more, then rewrite seq 2 — which the receiver already
      // holds — leaving the stored hashes alone.
      f.seal(3);
      f.store.close();
      rewriteEventInPlace(f.dataDir, 2, 'quietly_rewritten');

      const drain = await runCli(
        ['ship', '--data-dir', f.dataDir, '--store', 'jsonl', '--drain', '--timeout', '10s'],
        env,
      );
      expect(drain.code ?? 0).toBe(0); // a stall is still fail-open for the build
      expect(drain.stderr).toMatch(/delivered 0 record\(s\)/);
      expect(drain.stderr).toMatch(/local evidence does not verify/);
      // The receiver's copy is exactly what the honest run left it.
      expect([...sink.chain(f.chainId)!.records.keys()].sort((a, b) => a - b)).toEqual([1, 2, 3, 4]);

      const status = await runCli(
        ['ship', '--data-dir', f.dataDir, '--store', 'jsonl', '--status'],
        env,
      );
      expect(status.code ?? 0).toBe(0);
      expect(status.stdout).toMatch(/state: *stalled/);
      expect(status.stdout).toMatch(/lag: *3 record\(s\) not yet at the receiver/);
      expect(status.stdout).toMatch(/last error: *local evidence does not verify/);
      expect(status.stdout).toMatch(/hash_mismatch at seq 2/);
    },
    60_000,
  );
});

/* ------------------------------------------------------------------ */
/* FAIL-OPEN: the property the whole design is built around            */
/* ------------------------------------------------------------------ */

interface ProxyRun {
  code: number | null;
  stdout: string;
  stderr: string;
  elapsedMs: number;
}

/** Drive one initialize + one tools/call through `record` and collect stdout. */
async function runProxy(dataDir: string, env: NodeJS.ProcessEnv): Promise<ProxyRun> {
  const started = Date.now();
  return new Promise<ProxyRun>((resolveRun) => {
    const child = spawnTsx(
      ['src/cli.ts', 'record', '--data-dir', dataDir, '--store', 'jsonl', '--', process.execPath, ECHO_SERVER],
      { cwd: ROOT, env: { ...process.env, ...env } },
    );
    let stdout = '';
    let stderr = '';
    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', (c: string) => {
      stdout += c;
    });
    child.stderr.on('data', (c: string) => {
      stderr += c;
    });
    child.stdin.write(
      JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2024-11-05' } }) + '\n',
    );
    child.stdin.write(
      JSON.stringify({
        jsonrpc: '2.0',
        id: 2,
        method: 'tools/call',
        params: { name: 'echo', arguments: { note: 'FAILOPEN-PROBE-9d21' } },
      }) + '\n',
    );
    child.stdin.end();
    child.on('close', (code) => {
      resolveRun({ code, stdout, stderr, elapsedMs: Date.now() - started });
    });
  });
}

/**
 * Every sink failure mode, measured against the only thing that matters: the
 * agent's experience. The proxy must forward the same bytes, exit 0, and not
 * hang — whatever the sink is doing.
 */
describe('sink fail-open (end to end through `record`)', () => {
  it.skipIf(process.platform === 'win32')(
    'a sink that accepts and never responds changes nothing about the proxy',
    async () => {
      const hanging = await startHangingSink();
      cleanups.push(() => hanging.close());

      const baseline = await runProxy(tempDir('failopen-base'), {});
      const withSink = await runProxy(tempDir('failopen-hang'), {
        [ENV.SINK]: hanging.url,
        [ENV.SINK_TOKEN]: 'tok',
      });

      expect(withSink.code).toBe(0);
      expect(withSink.stdout).toBe(baseline.stdout);
      expect(withSink.stdout).toContain('FAILOPEN-PROBE-9d21');
      // "does not hang": the proxy exits with stdin, it never waits on the sink.
      expect(withSink.elapsedMs).toBeLessThan(20_000);
    },
    30_000,
  );

  it.skipIf(process.platform === 'win32')(
    'a 500ing sink, a 401ing sink and an unresolvable host are all invisible to the proxy',
    async () => {
      const five = receiver(await startSinkReceiver({ mode: 'error500' }));
      const unauth = receiver(await startSinkReceiver({ mode: 'unauthorized' }));

      const baseline = await runProxy(tempDir('failopen-base2'), {});
      for (const [tag, url] of [
        ['500', five.url],
        ['401', unauth.url],
        // A host that cannot resolve: DNS failure, the shape a blackholed
        // sink or a typo'd MDM profile takes.
        ['dns', 'https://sink.invalid.invalid.test'],
      ] as const) {
        const dataDir = tempDir(`failopen-${tag}`);
        const run = await runProxy(dataDir, { [ENV.SINK]: url, [ENV.SINK_TOKEN]: 'tok' });
        expect(run.code, tag).toBe(0);
        expect(run.stdout, tag).toBe(baseline.stdout);
        // ...and the local store is intact, which is the other half of the
        // promise: the sink never costs a local event.
        const store = openStore({ dataDir, backend: 'jsonl' });
        cleanups.push(() => store.close());
        expect(store.count(), tag).toBeGreaterThan(0);
      }
    },
    60_000,
  );

  it.skipIf(process.platform === 'win32')(
    'record auto-starts a shipper that delivers after the proxy has exited',
    async () => {
      const sink = receiver(await startSinkReceiver({ requireToken: 'tok' }));
      const dataDir = tempDir('autostart');
      const run = await runProxy(dataDir, {
        [ENV.SINK]: sink.url,
        [ENV.SINK_TOKEN]: 'tok',
      });
      expect(run.code).toBe(0);

      // The shipper is a DIFFERENT, detached process; give it a moment.
      const deadline = Date.now() + 20_000;
      while (Date.now() < deadline && sink.chains.size === 0) {
        await new Promise((r) => setTimeout(r, 100));
      }
      cleanups.push(() => {
        // Stop the detached shipper so the suite leaves nothing behind.
        const status = readShipStatus(dataDir);
        if (status?.pid !== undefined) {
          try {
            process.kill(status.pid, 'SIGTERM');
          } catch {
            /* already gone */
          }
        }
      });

      expect(existsSync(join(dataDir, 'ship.lock'))).toBe(true);
      expect(sink.chains.size).toBe(1);
      const stored = [...sink.chains.values()][0]!;
      expect(stored.records.size).toBeGreaterThan(0);
      const verdict = await verifyRecords(
        [...stored.records.values()].sort((a, b) => a.seq - b.seq),
        stored.signatures,
      );
      expect(verdict.problems.filter((p) => p.warning !== true)).toEqual([]);
    },
    60_000,
  );

  it.skipIf(process.platform === 'win32')(
    'hook reaches the sink too — all three surfaces share the same seam',
    async () => {
      const sink = receiver(await startSinkReceiver({ requireToken: 'tok' }));
      const dataDir = tempDir('hook-sink');
      const hookInput = JSON.stringify({
        session_id: randomUUID(),
        cwd: ROOT,
        hook_event_name: 'PreToolUse',
        tool_name: 'mcp__corp-notes__read_note',
        tool_input: { id: 'HOOK-SINK-PROBE-4c8a' },
        tool_use_id: 'toolu_sink_1',
      });

      const run = await new Promise<{ code: number | null; stdout: string }>((resolveRun) => {
        const child = spawnTsx(['src/cli.ts', 'hook', '--data-dir', dataDir, '--store', 'jsonl'], {
          cwd: ROOT,
          env: { ...process.env, [ENV.SINK]: sink.url, [ENV.SINK_TOKEN]: 'tok' },
        });
        let stdout = '';
        child.stdout.setEncoding('utf8');
        child.stdout.on('data', (c: string) => {
          stdout += c;
        });
        child.stdin.end(hookInput);
        child.on('close', (code) => resolveRun({ code, stdout }));
      });

      // Fail-open first: the hook allowed the call and printed nothing.
      expect(run.code).toBe(0);
      expect(run.stdout).toBe('');

      const deadline = Date.now() + 20_000;
      while (Date.now() < deadline && sink.chains.size === 0) {
        await new Promise((r) => setTimeout(r, 100));
      }
      cleanups.push(() => {
        const status = readShipStatus(dataDir);
        if (status?.pid !== undefined) {
          try {
            process.kill(status.pid, 'SIGTERM');
          } catch {
            /* already gone */
          }
        }
      });
      expect(sink.chains.size).toBe(1);
      for (const post of sink.posts) {
        expect(post.raw.toString('utf8')).not.toContain('HOOK-SINK-PROBE-4c8a');
      }
    },
    60_000,
  );
});

/* ------------------------------------------------------------------ */
/* the sink's own token is not evidence (finding 12, local dogfood 6)  */
/* ------------------------------------------------------------------ */

/**
 * Local dogfood 6 found the recorder fingerprinting its OWN transport
 * credential: with a sink configured, every event carried
 * `{name: "MCP_RECORDER_SINK_TOKEN", ref: sha256(<token>)}` — and the
 * shipper then delivered those events to the receiver that accepts that very
 * token. Refs are unsalted by design (that is what makes `query` work), so
 * for a low-entropy token the ref is recoverable by brute force: the sink was
 * being handed a reversible copy of its own bearer token, on every event.
 *
 * This is checked on the WIRE — the octets the receiver actually got — with
 * a positive control in the same bodies, so the negative cannot pass by the
 * events simply carrying no fingerprints at all.
 */
describe('the sink is never shipped a copy of its own bearer token', () => {
  it.skipIf(process.platform === 'win32')(
    'no POST body names MCP_RECORDER_SINK_TOKEN or carries its ref, while a real credential still ships',
    async () => {
      // Deliberately low entropy, exactly as in the report: sha256 of this
      // is reversible by anyone who can guess a short string.
      const token = 'local-ingest';
      const serverToken = 'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456';
      const sink = receiver(await startSinkReceiver({ requireToken: token }));
      const dataDir = tempDir('own-token');

      const run = await runProxy(dataDir, {
        [ENV.SINK]: sink.url,
        [ENV.SINK_TOKEN]: token,
        // The wrapped server's own credential — the kind credential
        // fingerprints exist for, and this test's positive control.
        GITHUB_TOKEN: serverToken,
      });
      expect(run.code).toBe(0);

      const deadline = Date.now() + 20_000;
      while (Date.now() < deadline && sink.chains.size === 0) {
        await new Promise((r) => setTimeout(r, 100));
      }
      cleanups.push(() => {
        const status = readShipStatus(dataDir);
        if (status?.pid !== undefined) {
          try {
            process.kill(status.pid, 'SIGTERM');
          } catch {
            /* already gone */
          }
        }
      });

      const bodies = sink.posts.map((p) => p.raw.toString('utf8'));
      expect(bodies.length).toBeGreaterThan(0);

      // Positive control: the wire IS carrying credential fingerprints, so
      // the assertions below are about the sink token specifically.
      expect(bodies.some((b) => b.includes(sha256Ref(serverToken)))).toBe(true);
      expect(bodies.some((b) => b.includes('GITHUB_TOKEN'))).toBe(true);

      for (const body of bodies) {
        expect(body).not.toContain('MCP_RECORDER_SINK_TOKEN');
        expect(body).not.toContain(sha256Ref(token));
        expect(body).not.toContain(token); // the token itself, obviously
      }

      // And the same holds for the local store the wire is a copy of.
      const onDisk = readFileSync(join(dataDir, 'evidence.jsonl'), 'utf8');
      expect(onDisk).not.toContain('MCP_RECORDER_SINK_TOKEN');
      expect(onDisk).not.toContain(sha256Ref(token));
      expect(onDisk).toContain(sha256Ref(serverToken));
    },
    60_000,
  );
});
