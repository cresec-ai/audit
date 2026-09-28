import { mkdtempSync, readFileSync, rmSync, statSync, writeFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { afterEach, describe, expect, it } from 'vitest';
import { Recorder } from '../src/capture/recorder.js';
import { DurableDelivery, inspectDelivery } from '../src/capture/spool.js';
import { reconcileStore } from '../src/capture/reconcile.js';
import { canonicalJson, sha256Ref } from '../src/chain/hash.js';
import { openStore, isSqliteAvailable } from '../src/store/index.js';
import { verifyStore } from '../src/verify/verify.js';
import { SCHEMA, type AnyEvent, type ActionLifecycleEvent } from '../src/schema/events.js';

const dirs: string[] = [];
afterEach(() => { for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true }); });
function dir(): string { const d = mkdtempSync(join(tmpdir(), 'coverage-')); dirs.push(d); return d; }
function event(): ActionLifecycleEvent {
  return { schema: SCHEMA, kind: 'action_lifecycle', event_id: randomUUID(), session_id: randomUUID(),
    action_id: randomUUID(), attempt_id: randomUUID(), timestamp: new Date().toISOString(),
    phase: 'decision', decision: 'allow', tool: 'write', identity: { fingerprint: sha256Ref('identity') },
    server: { name: 'test', command: '', transport: 'stdio' }, attributes: {} };
}

for (const backend of ['jsonl', ...(isSqliteAvailable() ? ['sqlite' as const] : [])] as const) {
  describe(`${backend} durable delivery`, () => {
    it('deduplicates committed deliveries and rejects conflicting IDs atomically', () => {
      const dataDir = dir(); const a = openStore({ dataDir, backend }); const b = openStore({ dataDir, backend });
      try {
        const e = event(); const later = event();
        expect(a.appendEvents([e, e])).toHaveLength(1);
        expect(b.appendEvents([e])).toHaveLength(0);
        expect(() => b.appendEvents([later, { ...e, tool: 'changed' }])).toThrow('collision');
        expect([...a.iterate()]).toHaveLength(1);
      } finally { a.close(); b.close(); }
    });

    it('spools while unavailable, replays on next start and never duplicates a partial commit', async () => {
      const dataDir = dir(); const store = openStore({ dataDir, backend });
      const append = store.appendEvents.bind(store);
      let unavailable = true;
      store.appendEvents = (events) => {
        if (unavailable) { append(events.slice(0, 1)); throw new Error('uncertain acknowledgement'); }
        return append(events);
      };
      const delivery = new DurableDelivery({ dataDir, store, openStore: () => store });
      const a = event(); const b = event();
      const result = await delivery.deliver([a, b]);
      expect(result.pending).toBe(true); expect(result.dropped).toBe(0);
      expect(readFileSync(join(dataDir, 'delivery/pending.jsonl'), 'utf8')).toContain(b.event_id);
      unavailable = false;
      await delivery.close();
      const reopened = new DurableDelivery({ dataDir, openStore: () => openStore({ dataDir, backend }) });
      await reopened.start(); await reopened.close();
      const check = openStore({ dataDir, backend });
      try {
        expect([...check.iterate()].map((r) => r.event.event_id)).toEqual([a.event_id, b.event_id]);
        expect((await verifyStore(check)).ok).toBe(true);
      } finally { check.close(); }
    });
  });
}

it('bounds a shared spool and reserves a durable, explicit gap on saturation', async () => {
  const dataDir = dir(); let unavailable = true;
  const delivery = new DurableDelivery({ dataDir, maxBytes: 1200,
    openStore: () => { if (unavailable) throw new Error('offline'); return openStore({ dataDir, backend: 'jsonl' }); } });
  const many = Array.from({ length: 20 }, event);
  const result = await delivery.deliver(many);
  expect(result.dropped).toBeGreaterThan(0);
  expect(statSync(join(dataDir, 'delivery/pending.jsonl')).size).toBeLessThanOrEqual(1200 + 8192);
  unavailable = false;
  await delivery.deliver([]); await delivery.close();
  const store = openStore({ dataDir, backend: 'jsonl' });
  try {
    const report = reconcileStore(store);
    expect(report.gaps).toHaveLength(1);
    expect(report.gaps[0]).toMatchObject({ reason: 'spool_full', coverage: 'incomplete' });
    expect(report.missing_outcomes.length).toBeGreaterThan(0);
  } finally { store.close(); }
});

it('records a torn spool gap, preserves its intact prefix and admits later evidence', async () => {
  const dataDir = dir(); const first = event();
  mkdirSync(join(dataDir, 'delivery'), { recursive: true });
  writeFileSync(join(dataDir, 'delivery/pending.jsonl'), canonicalJson(first) + '\n{"partial":');
  const delivery = new DurableDelivery({ dataDir, openStore: () => openStore({ dataDir, backend: 'jsonl' }) });
  await delivery.start(); await delivery.deliver([event()]); await delivery.close();
  const store = openStore({ dataDir, backend: 'jsonl' });
  try {
    expect([...store.iterate()].map((r) => r.event.event_id)).toContain(first.event_id);
    expect(reconcileStore(store).gaps[0]?.reason).toBe('torn_spool');
    expect((await verifyStore(store)).ok).toBe(true);
  } finally { store.close(); }
});

it('reconciliation reports each allow with no outcome, unknown separately and missing companion records', () => {
  const store = openStore({ dataDir: dir(), backend: 'jsonl' });
  try {
    const a = event(); const b = event(); const c = event();
    const outcomes: AnyEvent[] = [
      { ...b, event_id: randomUUID(), phase: 'outcome', outcome: 'unknown' },
      { ...c, event_id: randomUUID(), phase: 'outcome', outcome: 'success', record_event_id: 'missing' },
    ];
    store.appendEvents([a, b, c, ...outcomes]);
    const report = reconcileStore(store);
    expect(report.allowed).toBe(3); expect(report.missing_outcomes.map((e) => e.event_id)).toEqual([a.event_id]);
    expect(report.unknown_outcomes).toHaveLength(1); expect(report.missing_companion_records).toHaveLength(1);
  } finally { store.close(); }
});

it('record() returns before any journal I/O completes and reports bounded queue overflow', async () => {
  const dataDir = dir(); let writes = 0;
  const store = openStore({ dataDir, backend: 'jsonl' }); const original = store.appendEvents.bind(store);
  store.appendEvents = (events) => { writes++; return original(events); };
  const delivery = new DurableDelivery({ dataDir, store, openStore: () => store });
  const recorder = new Recorder({ store, signer: null, delivery });
  for (let i = 0; i < 4100; i++) recorder.record(event());
  expect(writes).toBe(0); expect(recorder.stats().dropped).toBe(4);
  await recorder.close();
  const check = openStore({ dataDir, backend: 'jsonl' });
  try { expect(reconcileStore(check).gaps[0]).toMatchObject({ reason: 'queue_full', dropped_at_least: 4 }); }
  finally { check.close(); }
});

it('concurrent deliveries sharing a directory preserve one chain and every distinct ID', async () => {
  const dataDir = dir(); const events = Array.from({ length: 8 }, event);
  const deliveries = events.map(() => new DurableDelivery({ dataDir, openStore: () => openStore({ dataDir, backend: 'jsonl' }) }));
  await Promise.all(deliveries.map((d, i) => d.deliver([events[i]!, events[0]!])));
  await Promise.all(deliveries.map((d) => d.close()));
  const store = openStore({ dataDir, backend: 'jsonl' });
  try {
    expect(new Set([...store.iterate()].map((r) => r.event.event_id))).toEqual(new Set(events.map((e) => e.event_id)));
    expect(store.count()).toBe(8); expect((await verifyStore(store)).ok).toBe(true);
  } finally { store.close(); }
});

it('inspection includes allowed decisions waiting in an unavailable-store spool', async () => {
  const dataDir = dir(); const allow = event();
  const delivery = new DurableDelivery({ dataDir, openStore: () => { throw new Error('offline'); } });
  await delivery.deliver([allow]);
  const snapshot = await inspectDelivery(dataDir);
  expect(snapshot.pending_events).toBe(1);
  expect(snapshot.events[0]).toEqual(allow);
  expect(snapshot.active_runs).toBe(1);
  await delivery.close();
});

it('startup without abandoned leases does not scan historical evidence', async () => {
  const dataDir = dir(); const store = openStore({ dataDir, backend: 'jsonl' });
  store.appendEvents([event()]);
  const iterate = store.iterate.bind(store); let scans = 0;
  store.iterate = (opts) => { scans++; return iterate(opts); };
  const delivery = new DurableDelivery({ dataDir, store, openStore: () => store });
  await delivery.start(false);
  expect(scans).toBe(0);
  await delivery.close();
  expect(scans).toBe(1); // explicit close reconciliation
});

for (const backend of ['jsonl', ...(isSqliteAvailable() ? ['sqlite' as const] : [])] as const) {
  it(`${backend}: shared replay credits the original run, including an acknowledgement by another process`, async () => {
    const dataDir = dir(); let offline = true;
    const a = new DurableDelivery({ dataDir, openStore: () => {
      if (offline) throw new Error('offline'); return openStore({ dataDir, backend });
    } });
    const b = new DurableDelivery({ dataDir, openStore: () => openStore({ dataDir, backend }) });
    const one = event(); const two = event();
    expect((await a.deliver([one])).written).toBe(0);
    expect((await b.deliver([two])).written).toBe(1);
    offline = false;
    expect((await a.deliver([])).written).toBe(1);
    expect((await a.deliver([])).written).toBe(0);
    await a.close(); await b.close();
  });
}
