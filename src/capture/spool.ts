/** Bounded, append-only write-ahead delivery journal. All filesystem waits use
 * promises and run in the recorder drain, never in record() or admission.
 * The journal is retained until the chain AND its signature have been synced.
 * A failed/uncertain append replays evidence IDs, never upstream operations.
 */
import { link, mkdir, open, readFile, readdir, rename, rm, stat } from 'node:fs/promises';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { canonicalJson, sha256Ref } from '../chain/hash.js';
import { Signer } from '../chain/keys.js';
import { SCHEMA, type ActionLifecycleEvent, type AnyEvent, type CoverageGapEvent, type EventBase } from '../schema/events.js';
import type { EvidenceStore, SignerLike } from '../types.js';
import { reconcileStore, type Reconciliation } from './reconcile.js';

export const SPOOL_MAX_BYTES = 64 * 1024 * 1024;
const GAP_RESERVE_BYTES = 8192;
const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));
function missing(err: unknown): boolean { return (err as NodeJS.ErrnoException).code === 'ENOENT'; }
function alive(pid: number): boolean {
  try { process.kill(pid, 0); return true; }
  catch (err) { return (err as NodeJS.ErrnoException).code !== 'ESRCH'; }
}

/** POSIX directory durability; Windows cannot open/fsync directory handles in
 * Node. File handles are still fsynced and closed before unlink on Windows. */
async function syncDirectory(path: string): Promise<void> {
  if (process.platform === 'win32') return;
  const fd = await open(path, 'r');
  try { await fd.sync(); } finally { await fd.close(); }
}

export function coverageGap(base: EventBase, reason: CoverageGapEvent['reason'], count: number): CoverageGapEvent {
  // Deliberately carry only common context, never a payload or upstream error.
  return { schema: SCHEMA, kind: 'coverage_gap', event_id: randomUUID(),
    session_id: base.session_id, timestamp: new Date().toISOString(),
    identity: base.identity, server: base.server, attributes: {},
    ...(base.recorder_run_id === undefined ? {} : { recorder_run_id: base.recorder_run_id }),
    coverage: 'incomplete', reason, dropped_at_least: count };
}

export interface DeliveryResult { written: number; dropped: number; pending: boolean }
interface Lease { pid: number; run_id: string; started_at: string }

export class DurableDelivery {
  readonly runId = randomUUID();
  readonly directory: string;
  private readonly journal: string;
  private readonly locks: string;
  private readonly runs: string;
  private readonly leasePath: string;
  private store: EvidenceStore | null;
  private signer: SignerLike | null;
  private ready = false;
  private tail: Promise<unknown> = Promise.resolve();
  private warned = new Set<string>();
  private lostGap: CoverageGapEvent | undefined;

  constructor(private readonly opts: {
    dataDir: string; openStore: () => EvidenceStore;
    store?: EvidenceStore | null; signer?: SignerLike | null;
    maxBytes?: number; warn?: (message: string) => void;
  }) {
    this.directory = join(opts.dataDir, 'delivery');
    this.journal = join(this.directory, 'pending.jsonl');
    this.locks = join(this.directory, 'locks');
    this.runs = join(this.directory, 'runs');
    this.leasePath = join(this.runs, this.runId + '.json');
    this.store = opts.store ?? null;
    this.signer = opts.signer ?? null;
  }

  private warn(key: string, message: string): void {
    if (this.warned.has(key)) return;
    this.warned.add(key);
    try { this.opts.warn?.(message); } catch { /* diagnostics are fail-open */ }
  }

  private async initialize(): Promise<void> {
    if (this.ready) return;
    await mkdir(this.runs, { recursive: true, mode: 0o700 });
    await mkdir(this.locks, { recursive: true, mode: 0o700 });
    const fd = await open(this.leasePath, 'w', 0o600);
    try {
      await fd.writeFile(JSON.stringify({ pid: process.pid, run_id: this.runId, started_at: new Date().toISOString() }));
      await fd.sync();
    } finally { await fd.close(); }
    await syncDirectory(this.runs);
    this.ready = true;
  }

  /** Filesystem bakery lock: publish choosing before reading the largest
   * ticket, then wait for lower tickets and unfinished choices. Immutable,
   * uniquely named tickets avoid stale-lock deletion racing a new owner.
   * Fully written files are published atomically (hardlink/rename); a kill
   * cannot leave an ownerless lock. Dead owners are ignored and cleaned up.
   * Requires a local filesystem with coherent directory reads (NTFS/POSIX).
   */
  private async withLock<T>(fn: () => Promise<T>): Promise<T> {
    await this.initialize();
    const id = process.pid + '-' + randomUUID();
    const choosing = join(this.locks, id + '.choosing');
    const ticketPath = join(this.locks, id + '.ticket');
    const temp = join(this.locks, id + '.tmp');
    const scan = async (): Promise<Array<{ name: string; number?: number }>> => {
      const entries: Array<{ name: string; number?: number }> = [];
      for (const name of await readdir(this.locks)) {
        const pid = Number(name.split('-')[0]);
        if (!Number.isSafeInteger(pid) || pid <= 0) throw new Error('unidentifiable delivery lock');
        if (!alive(pid)) { await rm(join(this.locks, name), { force: true }); continue; }
        if (name.endsWith('.choosing')) entries.push({ name });
        else if (name.endsWith('.ticket')) {
          try {
            const owner = JSON.parse(await readFile(join(this.locks, name), 'utf8')) as { ticket: number };
            if (!Number.isSafeInteger(owner.ticket) || owner.ticket < 1) throw new Error('invalid delivery ticket');
            entries.push({ name, number: owner.ticket });
          } catch (err) { if (!missing(err)) throw err; }
        }
      }
      return entries;
    };
    try {
      await link(this.leasePath, choosing);
      const number = 1 + Math.max(0, ...(await scan()).map((e) => e.number ?? 0));
      const fd = await open(temp, 'wx', 0o600);
      try { await fd.writeFile(JSON.stringify({ pid: process.pid, run_id: this.runId, ticket: number })); await fd.sync(); }
      finally { await fd.close(); }
      await rename(temp, ticketPath);
      await rm(choosing);
      const deadline = Date.now() + 2000;
      for (;;) {
        const entries = await scan();
        const blocked = entries.some((e) => e.name !== id + '.ticket' &&
          (e.number === undefined || e.number < number || (e.number === number && e.name < id + '.ticket')));
        if (!blocked) break;
        if (Date.now() >= deadline) throw new Error('delivery journal lock unavailable');
        await sleep(10);
      }
      return await fn();
    } finally {
      await rm(choosing, { force: true });
      await rm(ticketPath, { force: true });
      await rm(temp, { force: true });
    }
  }

  private serial<T>(fn: () => Promise<T>): Promise<T> {
    const next = this.tail.then(fn); this.tail = next.catch(() => undefined); return next;
  }

  /** Persist before attempting the store: even a kill inside a partial append
   * can be retried safely. This is off the forwarding path, not durable intent
   * before execution. Each frame is independently parseable on recovery. */
  private async append(events: AnyEvent[]): Promise<number> {
    let bytes = 0;
    try { bytes = (await stat(this.journal)).size; } catch (e) { if (!missing(e)) throw e; }
    const cap = this.opts.maxBytes ?? SPOOL_MAX_BYTES;
    const lines: string[] = [];
    let dropped = 0;
    for (const event of events) {
      const line = canonicalJson(event) + '\n';
      const length = Buffer.byteLength(line);
      if (bytes + length > cap) { dropped++; continue; }
      bytes += length; lines.push(line);
    }
    if (dropped > 0) {
      // One durable gap per saturation episode, with a lower bound rather
      // than a fictitious exact count after subsequent drops/process death.
      const old = await readFile(this.journal, 'utf8').catch((e: unknown) => { if (missing(e)) return ''; throw e; });
      const gapPresent = old.split('\n').some((l) => { try { const e = JSON.parse(l) as AnyEvent; return e.kind === 'coverage_gap' && e.reason === 'spool_full'; } catch { return false; } });
      if (!gapPresent) {
        const gap = canonicalJson(coverageGap(events[0]!, 'spool_full', dropped)) + '\n';
        if (bytes + Buffer.byteLength(gap) <= cap + GAP_RESERVE_BYTES) lines.push(gap);
      }
      this.warn('full', 'coverage gap: delivery spool full; events dropped (traffic unaffected)');
    }
    if (lines.length > 0) {
      const fd = await open(this.journal, 'a', 0o600);
      try { await fd.writeFile(lines.join('')); await fd.sync(); } finally { await fd.close(); }
      await syncDirectory(this.directory);
    }
    return dropped;
  }

  private async repairTail(): Promise<void> {
    let bytes: Buffer;
    try { bytes = await readFile(this.journal); } catch (err) { if (missing(err)) return; throw err; }
    if (bytes.length === 0 || bytes[bytes.length - 1] === 10) return;
    const cut = bytes.lastIndexOf(10) + 1;
    let intact = false;
    try { JSON.parse(bytes.subarray(cut).toString('utf8')); intact = true; } catch { /* torn frame */ }
    const fd = await open(this.journal, 'r+');
    try {
      if (intact) await fd.write(Buffer.from('\n'), 0, 1, bytes.length);
      else {
        await fd.truncate(cut);
        const gap = coverageGap(this.fallbackBase(), 'torn_spool', 1);
        const line = Buffer.from(canonicalJson(gap) + '\n');
        let offset = 0;
        while (offset < line.length) offset += (await fd.write(line, offset, line.length - offset, cut + offset)).bytesWritten;
      }
      await fd.sync();
    } finally { await fd.close(); }
  }

  private async replay(): Promise<number> {
    let text: string;
    try { text = await readFile(this.journal, 'utf8'); } catch (e) { if (missing(e)) return 0; throw e; }
    const lines = text.split('\n');
    const events: AnyEvent[] = [];
    for (let i = 0; i < lines.length; i++) {
      if (!lines[i]) continue;
      try { events.push(JSON.parse(lines[i]!) as AnyEvent); }
      catch { throw new Error('corrupt delivery journal; retained for inspection'); }
    }
    if (events.length === 0) return 0;
    this.store ??= this.opts.openStore();
    const sealed = this.store.appendEvents(events);
    this.signer ??= await Signer.load(this.opts.dataDir);
    const head = this.store.head();
    this.store.addSignature(await this.signer.sign(head.seq, head.hash));
    if (this.store.backend === 'jsonl') {
      for (const path of [this.store.path, join(this.opts.dataDir, 'signatures.jsonl')]) {
        const fd = await open(path, 'r+');
        try { await fd.sync(); } finally { await fd.close(); }
      }
    }
    await rm(this.journal);
    await syncDirectory(this.directory);
    this.warned.delete('full');
    return sealed.length;
  }

  private fallbackBase(): EventBase {
    return { schema: SCHEMA, kind: 'coverage_gap', event_id: randomUUID(),
      session_id: this.runId, timestamp: new Date().toISOString(),
      identity: { fingerprint: sha256Ref('unattributed-recovery') },
      server: { name: 'recorder', command: '', transport: 'stdio' }, attributes: {}, recorder_run_id: this.runId };
  }

  deliver(events: AnyEvent[]): Promise<DeliveryResult> {
    return this.serial(async () => {
      let dropped = 0;
      let persisted = false;
      try {
        return await this.withLock(async () => {
          await this.repairTail();
          // Repair/replay an old torn tail before appending to it. A healthy
          // journal is replayed first too, freeing its bounded capacity.
          let replayed = 0;
          try { replayed = await this.replay(); } catch { /* a down store retains the backlog */ }
          if (this.lostGap) {
            const gap = this.lostGap;
            if (await this.append([gap]) === 0) this.lostGap = undefined;
          }
          dropped = await this.append(events);
          persisted = true;
          try { return { written: replayed + await this.replay(), dropped, pending: false }; }
          catch {
            this.warn('store', 'store unavailable; evidence retained in durable delivery spool');
            return { written: replayed, dropped, pending: true };
          }
        });
      } catch {
        if (!persisted && events.length > 0) {
          this.lostGap ??= coverageGap(events[0]!, 'spool_unavailable', 0);
          // Some frames may already have reached disk: the loss count is unknown.
        }
        this.warn('spool', 'coverage gap: delivery spool unavailable; traffic continues, evidence may be lost');
        return { written: 0, dropped: persisted ? dropped : events.length, pending: true };
      }
    });
  }

  async start(): Promise<void> {
    await this.deliver([]);
    await this.recover();
  }

  /** Recover only known-dead process incarnations, or explicitly ended hook
   * sessions. PID reuse/permission errors are conservatively left unresolved.
   * Deterministic recovery IDs and timestamps make a kill during recovery safe. */
  async recover(): Promise<void> {
    await this.serial(async () => {
      try {
        await this.withLock(async () => {
          await this.repairTail();
          await this.replay();
          this.store ??= this.opts.openStore();
          const events = [...this.store.iterate()].map((r) => r.event);
          const dead: Lease[] = [];
          for (const name of await readdir(this.runs)) {
            if (!name.endsWith('.json') || name === this.runId + '.json') continue;
            try {
              const lease = JSON.parse(await readFile(join(this.runs, name), 'utf8')) as Lease;
              if (Number.isInteger(lease.pid) && lease.pid > 0 && !alive(lease.pid) && name === lease.run_id + '.json') dead.push(lease);
            } catch { this.warn('lease', 'coverage gap: unreadable recorder lease; recovery needs inspection'); }
          }
          const deadRuns = new Set(dead.map((l) => l.run_id));
          const ended = new Set(events.filter((e) => e.kind === 'session_end' && e.source === 'hook').map((e) => e.session_id));
          const outcomes = new Set(events.filter((e) => e.kind === 'action_lifecycle' && e.phase === 'outcome').map((e) => JSON.stringify([e.action_id, e.attempt_id])));
          const attempts = new Map<string, ActionLifecycleEvent>();
          for (const e of events) {
            if (e.kind === 'action_lifecycle' && e.phase !== 'outcome') attempts.set(JSON.stringify([e.action_id, e.attempt_id]), e);
          }
          const recovered: AnyEvent[] = [];
          for (const [key, e] of attempts) {
            if (outcomes.has(key) || !(deadRuns.has(e.recorder_run_id ?? '') || (e.source === 'hook' && ended.has(e.session_id)))) continue;
            recovered.push({ ...e, event_id: sha256Ref(e.event_id + ':recovered-outcome'),
              phase: 'outcome', outcome: e.decision === 'deny' ? 'denied' : 'unknown', reason: 'recorder_exit' });
          }
          const eventIds = new Set(events.map((e) => e.event_id));
          for (const lease of dead) {
            const base = events.find((e) => e.recorder_run_id === lease.run_id) ?? this.fallbackBase();
            const gap = coverageGap(base, 'recorder_exit', 0);
            gap.event_id = sha256Ref(lease.run_id + ':coverage-gap');
            gap.recorder_run_id = lease.run_id;
            gap.timestamp = lease.started_at;
            gap.session_id = base.session_id;
            if (!eventIds.has(gap.event_id)) recovered.push(gap);
          }
          if (recovered.length && await this.append(recovered) > 0) return; // bounded journal; retain leases until recoverable
          await this.replay();
          for (const lease of dead) await rm(join(this.runs, lease.run_id + '.json'), { force: true });
        });
      } catch { this.warn('recovery', 'coverage recovery pending; journal and recorder leases retained'); }
    });
  }

  async sweep(): Promise<Reconciliation | undefined> {
    try { this.store ??= this.opts.openStore(); return reconcileStore(this.store); }
    catch { this.warn('sweep', 'coverage reconciliation unavailable'); return undefined; }
  }

  async close(): Promise<void> {
    const final = await this.deliver([]);
    await this.recover();
    const report = await this.sweep();
    if (report && (report.missing_outcomes.length || report.missing_companion_records.length || report.gaps.length)) {
      this.warn('coverage', `coverage incomplete: ${report.missing_outcomes.length} allowed decisions without outcomes; ${report.missing_companion_records.length} missing companion records; ${report.gaps.length} gap records`);
    }
    if (this.ready && !final.pending && !this.lostGap) await rm(this.leasePath, { force: true }).catch(() => undefined);
    try { this.store?.close(); } catch { /* recording stays fail-open */ }
  }
}

/** Read-only snapshot, including durable evidence not yet in the chain. Active
 * runs may append after this snapshot; zero findings is not global completeness. */
export async function inspectDelivery(dataDir: string): Promise<{
  events: AnyEvent[]; pending_events: number; active_runs: number; abandoned_runs: number; errors: string[];
}> {
  const result = { events: [] as AnyEvent[], pending_events: 0, active_runs: 0, abandoned_runs: 0, errors: [] as string[] };
  const directory = join(dataDir, 'delivery');
  try {
    const text = await readFile(join(directory, 'pending.jsonl'), 'utf8');
    for (const line of text.split('\n')) {
      if (!line) continue;
      try {
        const event = JSON.parse(line) as AnyEvent;
        if (!event || typeof event.event_id !== 'string') throw new Error('invalid frame');
        result.events.push(event); result.pending_events++;
      } catch { result.errors.push('unreadable delivery frame'); }
    }
  } catch (err) { if (!missing(err)) result.errors.push('delivery journal unavailable'); }
  try {
    for (const name of await readdir(join(directory, 'runs'))) {
      try {
        const lease = JSON.parse(await readFile(join(directory, 'runs', name), 'utf8')) as Lease;
        if (!Number.isInteger(lease.pid) || lease.pid <= 0) throw new Error('invalid lease');
        if (alive(lease.pid)) result.active_runs++; else result.abandoned_runs++;
      } catch { result.errors.push('unreadable recorder lease'); }
    }
  } catch (err) { if (!missing(err)) result.errors.push('recorder leases unavailable'); }
  return result;
}
