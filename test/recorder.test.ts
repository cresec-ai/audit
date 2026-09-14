import { describe, expect, it } from 'vitest';
import { Recorder } from '../src/capture/recorder.js';
import { GENESIS_HASH, computeHash, makeRecord, signedPayload, sha256Hex } from '../src/chain/hash.js';
import { SCHEMA, type AnyEvent, type ChainRecord, type HeadSignature } from '../src/schema/events.js';
import type {
  ChainHead,
  EvidenceStore,
  IterateOpts,
  SessionSummary,
  SignerLike,
} from '../src/types.js';

/** In-memory EvidenceStore honoring the append-boundary contract. */
class FakeStore implements EvidenceStore {
  readonly backend = 'jsonl' as const;
  readonly path = ':memory:';
  records: ChainRecord[] = [];
  sigs: HeadSignature[] = [];
  closed = 0;
  failAppend = false;

  head(): ChainHead {
    const last = this.records[this.records.length - 1];
    return last ? { seq: last.seq, hash: last.hash } : { seq: 0, hash: GENESIS_HASH };
  }
  append(records: ChainRecord[]): void {
    if (this.failAppend) throw new Error('disk on fire');
    let head = this.head();
    for (const r of records) {
      const expectedPrev = head.seq === 0 ? GENESIS_HASH : head.hash;
      if (r.seq !== head.seq + 1 || r.prev_hash !== expectedPrev) {
        throw new Error(`append does not extend head at seq ${r.seq}`);
      }
      if (r.hash !== computeHash(r.prev_hash, r.event)) {
        throw new Error(`bad hash at seq ${r.seq}`);
      }
      this.records.push(r);
      head = { seq: r.seq, hash: r.hash };
    }
  }
  appendEvents(events: AnyEvent[]): ChainRecord[] {
    if (this.failAppend) throw new Error('disk on fire');
    let head = this.head();
    const sealed: ChainRecord[] = [];
    for (const event of events) {
      const record = makeRecord(head, event);
      sealed.push(record);
      head = { seq: record.seq, hash: record.hash };
    }
    this.records.push(...sealed);
    return sealed;
  }
  addSignature(sig: HeadSignature): void {
    this.sigs.push(sig);
  }
  latestSignature(): HeadSignature | null {
    return this.sigs[this.sigs.length - 1] ?? null;
  }
  signatures(): HeadSignature[] {
    return [...this.sigs];
  }
  *iterate(opts?: IterateOpts): Iterable<ChainRecord> {
    for (const r of this.records) {
      if (opts?.fromSeq !== undefined && r.seq < opts.fromSeq) continue;
      if (opts?.toSeq !== undefined && r.seq > opts.toSeq) continue;
      if (opts?.sessionId !== undefined && r.event.session_id !== opts.sessionId) continue;
      yield r;
    }
  }
  count(): number {
    return this.records.length;
  }
  sessions(): SessionSummary[] {
    return [];
  }
  close(): void {
    this.closed++;
  }
}

class FakeSigner implements SignerLike {
  readonly publicKeyHex = '00'.repeat(32);
  calls: Array<{ seq: number; chainHash: string }> = [];
  async sign(seq: number, chainHash: string): Promise<HeadSignature> {
    this.calls.push({ seq, chainHash });
    return {
      seq,
      chain_hash: chainHash,
      algo: 'ed25519',
      public_key: this.publicKeyHex,
      // Not a real signature; recorder only transports it.
      signature: sha256Hex(signedPayload(seq, chainHash)).repeat(2),
      signed_at: new Date().toISOString(),
    };
  }
}

function makeEvent(i: number): AnyEvent {
  return {
    schema: SCHEMA,
    event_id: `00000000-0000-4000-8000-${String(i).padStart(12, '0')}`,
    session_id: '11111111-1111-4111-8111-111111111111',
    timestamp: new Date().toISOString(),
    kind: 'notification',
    identity: { fingerprint: 'sha256:' + '0'.repeat(64) },
    server: { name: 'fake', command: 'fake', transport: 'stdio' },
    attributes: { 'rpc.system': 'jsonrpc' },
    method: `note/${i}`,
    direction: 'client_to_server',
    params: { i },
  };
}

describe('Recorder', () => {
  it('seals 100 events into a contiguous, hash-linked chain and signs the head', async () => {
    const store = new FakeStore();
    const signer = new FakeSigner();
    const rec = new Recorder({ store, signer });

    for (let i = 1; i <= 100; i++) rec.record(makeEvent(i));
    await rec.flush();

    expect(store.records).toHaveLength(100);
    let prev = GENESIS_HASH;
    store.records.forEach((r, idx) => {
      expect(r.seq).toBe(idx + 1);
      expect(r.prev_hash).toBe(prev);
      expect(r.hash).toBe(computeHash(prev, r.event));
      prev = r.hash;
    });

    expect(signer.calls.length).toBeGreaterThan(0);
    const lastCall = signer.calls[signer.calls.length - 1];
    expect(lastCall.seq).toBe(100);
    expect(lastCall.chainHash).toBe(store.records[99].hash);
    expect(store.latestSignature()?.seq).toBe(100);

    const stats = rec.stats();
    expect(stats).toMatchObject({ enqueued: 100, written: 100, dropped: 0, storeFailed: false });
    await rec.close();
    expect(store.closed).toBe(1);
  });

  it('flushes automatically via setImmediate without an explicit flush()', async () => {
    const store = new FakeStore();
    const rec = new Recorder({ store, signer: null });
    rec.record(makeEvent(1));
    await new Promise((r) => setImmediate(() => setImmediate(r)));
    expect(store.records).toHaveLength(1);
    await rec.close();
  });

  it('keeps the chain linked across multiple flush batches', async () => {
    const store = new FakeStore();
    const rec = new Recorder({ store, signer: null });
    rec.record(makeEvent(1));
    await rec.flush();
    rec.record(makeEvent(2));
    rec.record(makeEvent(3));
    await rec.flush();
    expect(store.records.map((r) => r.seq)).toEqual([1, 2, 3]);
    expect(store.records[1].prev_hash).toBe(store.records[0].hash);
    expect(store.records[2].prev_hash).toBe(store.records[1].hash);
    await rec.close();
  });

  it('fails open when the store throws: never rejects, counts drops, sets storeFailed', async () => {
    const store = new FakeStore();
    store.failAppend = true;
    const rec = new Recorder({ store, signer: new FakeSigner() });

    for (let i = 1; i <= 100; i++) rec.record(makeEvent(i));
    await expect(rec.flush()).resolves.toBeUndefined();

    let stats = rec.stats();
    expect(stats.dropped).toBe(100);
    expect(stats.written).toBe(0);
    expect(stats.storeFailed).toBe(true);

    // From now on events are dropped silently but still counted.
    rec.record(makeEvent(101));
    await rec.flush();
    stats = rec.stats();
    expect(stats.enqueued).toBe(101);
    expect(stats.dropped).toBe(101);

    await expect(rec.close()).resolves.toBeUndefined();
  });

  it('record() never throws even if internal state is abused', () => {
    const rec = new Recorder({ store: null, signer: null });
    expect(() => rec.record(makeEvent(1))).not.toThrow();
    // even a hostile event object must not break the hot path
    expect(() => rec.record(undefined as unknown as AnyEvent)).not.toThrow();
  });

  it('null store (disabled mode) no-ops but still counts enqueued/dropped', async () => {
    const rec = new Recorder({ store: null, signer: null });
    for (let i = 1; i <= 5; i++) rec.record(makeEvent(i));
    await rec.flush();
    await rec.close();
    expect(rec.stats()).toEqual({ enqueued: 5, written: 0, dropped: 5, storeFailed: false });
  });

  it('signer failure does not poison stored events', async () => {
    const store = new FakeStore();
    const badSigner: SignerLike = {
      publicKeyHex: 'ff'.repeat(32),
      sign: async () => {
        throw new Error('hsm unplugged');
      },
    };
    const rec = new Recorder({ store, signer: badSigner });
    rec.record(makeEvent(1));
    await rec.flush();
    expect(store.records).toHaveLength(1);
    expect(rec.stats().written).toBe(1);
    expect(rec.stats().storeFailed).toBe(false);
    await rec.close();
  });

  it('close() is idempotent', async () => {
    const store = new FakeStore();
    const rec = new Recorder({ store, signer: null });
    rec.record(makeEvent(1));
    await rec.close();
    await rec.close();
    expect(store.closed).toBe(1);
    expect(store.records).toHaveLength(1);
  });

  it('signEveryFlush:false skips signing', async () => {
    const store = new FakeStore();
    const signer = new FakeSigner();
    const rec = new Recorder({ store, signer, signEveryFlush: false });
    rec.record(makeEvent(1));
    await rec.flush();
    expect(signer.calls).toHaveLength(0);
    expect(store.sigs).toHaveLength(0);
    await rec.close();
  });
});
