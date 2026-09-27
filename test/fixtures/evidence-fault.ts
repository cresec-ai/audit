/** Real child-process fault harness. No production environment switches. */
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import { syncBuiltinESMExports } from 'node:module';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import type Database from 'better-sqlite3';
import { Recorder } from '../../src/capture/recorder.js';
import { DurableDelivery } from '../../src/capture/spool.js';
import { openStore } from '../../src/store/index.js';
import { SCHEMA, type AnyEvent } from '../../src/schema/events.js';
import { sha256Ref } from '../../src/chain/hash.js';
import { FILES } from '../../src/types.js';

const [dataDir, backend, mode] = process.argv.slice(2) as [string, 'jsonl' | 'sqlite', string];
const signal = () => fs.writeFileSync(join(dataDir, 'fault-ready'), mode);
const block = (): never => { signal(); for (;;) Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0); };
const store = openStore({ dataDir, backend });
const events: AnyEvent[] = Array.from({ length: mode === 'full' ? 20 : 2 }, () => ({
  schema: SCHEMA, kind: 'notification', event_id: randomUUID(), session_id: 'fault-session',
  timestamp: new Date().toISOString(), identity: { fingerprint: sha256Ref('fixture') },
  server: { name: 'fault', command: '', transport: 'stdio' }, attributes: {},
  method: 'notifications/test', direction: 'client_to_server', params: { note: 'already-redacted' },
}));
fs.writeFileSync(join(dataDir, 'expected.json'), JSON.stringify(events.map((e) => e.event_id)));

if (mode === 'append' && backend === 'sqlite') {
  // Terminate with an actual SQLite transaction open, after the first insert.
  const db = (store as unknown as { db: Database.Database }).db;
  db.function('fault_point', block);
  db.exec('CREATE TEMP TRIGGER fault_after_insert AFTER INSERT ON records BEGIN SELECT fault_point(); END');
} else if (mode === 'append' || mode === 'signature') {
  const original = fs.appendFileSync;
  const target = join(dataDir, mode === 'signature' ? FILES.JSONL_SIGS : FILES.JSONL_LOG);
  fs.appendFileSync = ((path, data, options) => {
    if (path !== target) return original(path, data, options);
    const text = String(data);
    // One complete record plus an incomplete next record, or a torn signature.
    const end = mode === 'signature' ? 30 : text.indexOf('\n') + 30;
    original(path, text.slice(0, end), options);
    const fd = fs.openSync(target, 'r+'); fs.fsyncSync(fd); fs.closeSync(fd);
    block();
  }) as typeof fs.appendFileSync;
  syncBuiltinESMExports();
} else if (mode === 'journal') {
  const original = fsp.open;
  fsp.open = (async (...args: Parameters<typeof fsp.open>) => {
    const fd = await original(...args);
    if (args[0] === join(dataDir, 'delivery/pending.jsonl') && args[1] === 'a') {
      const write = fd.writeFile.bind(fd);
      fd.writeFile = async (data) => {
        const text = String(data);
        await write(text.slice(0, text.indexOf('\n') + 30)); await fd.sync(); block();
      };
    }
    return fd;
  }) as typeof fsp.open;
  syncBuiltinESMExports();
} else if (mode === 'committed') {
  const append = store.appendEvents.bind(store);
  store.appendEvents = (batch) => { append(batch); return block(); };
} else if (mode === 'recovering') {
  const append = store.appendEvents.bind(store);
  store.appendEvents = (batch) => {
    if (!fs.existsSync(join(dataDir, 'restore'))) throw new Error('injected outage');
    return append(batch);
  };
} else if (mode === 'offline' || mode === 'full') {
  store.appendEvents = () => { throw new Error('injected store outage'); };
}
const delivery = new DurableDelivery({ dataDir, store, openStore: () => store,
  ...(mode === 'full' ? { maxBytes: 1200 } : {}), warn: (s) => process.stderr.write(s + '\n') });
for (const e of events) e.recorder_run_id = delivery.runId;
if (mode === 'queue') {
  await delivery.start();
  const recorder = new Recorder({ store, signer: null, delivery });
  for (const e of events) recorder.record(e);
  block(); // before setImmediate can drain: only the process lease survives
}
await delivery.deliver(events);
if (mode === 'recovering') new Recorder({ store, signer: null, delivery });
signal();
setInterval(() => {}, 1000);
