/**
 * Async, fail-open capture sink (M1). `record()` is synchronous, O(1) and
 * never throws; events are sealed into chain records and batched to the
 * store off the hot path via setImmediate. A store failure flips the
 * recorder into drop mode: traffic is never affected, drops are counted,
 * and exactly one diagnostic line goes to stderr.
 */

import { makeRecord } from '../chain/hash.js';
import type { AnyEvent, ChainRecord } from '../schema/events.js';
import type {
  ChainHead,
  EvidenceStore,
  RecorderLike,
  RecorderStats,
  SignerLike,
} from '../types.js';

export interface RecorderOpts {
  store: EvidenceStore | null;
  signer: SignerLike | null;
  /** Sign the chain head after every flush (default true). */
  signEveryFlush?: boolean;
}

function logOnce(loggedRef: { v: boolean }, msg: string, err?: unknown): void {
  if (loggedRef.v) return;
  loggedRef.v = true;
  const detail = err instanceof Error ? err.message : err !== undefined ? String(err) : '';
  process.stderr.write(`[mcp-recorder] ${msg}${detail ? `: ${detail}` : ''}\n`);
}

export class Recorder implements RecorderLike {
  private readonly store: EvidenceStore | null;
  private readonly signer: SignerLike | null;
  private readonly signEveryFlush: boolean;

  private queue: AnyEvent[] = [];
  private flushScheduled = false;
  /** In-flight flush, so flush()/close() can await the active drain. */
  private flushing: Promise<void> = Promise.resolve();

  private enqueued = 0;
  private written = 0;
  private dropped = 0;
  private storeFailed = false;
  private closed = false;
  private closePromise: Promise<void> | null = null;

  private readonly storeErrorLogged = { v: false };
  private readonly signerErrorLogged = { v: false };

  constructor(opts: RecorderOpts) {
    this.store = opts.store;
    this.signer = opts.signer;
    this.signEveryFlush = opts.signEveryFlush ?? true;
  }

  /** Hot path: O(1), never throws. */
  record(event: AnyEvent): void {
    try {
      this.enqueued++;
      if (this.store === null || this.storeFailed || this.closed) {
        this.dropped++;
        return;
      }
      this.queue.push(event);
      if (!this.flushScheduled) {
        this.flushScheduled = true;
        setImmediate(() => {
          this.flushScheduled = false;
          void this.flush();
        });
      }
    } catch (err) {
      // Defensive: nothing above should throw, but fail-open regardless.
      this.dropped++;
      logOnce(this.storeErrorLogged, 'record() failed; dropping events', err);
    }
  }

  /** Drain the queue in one batch. Never rejects. */
  flush(): Promise<void> {
    const run = this.flushing.then(() => this.drainOnce());
    // Keep the chain alive even though drainOnce never rejects.
    this.flushing = run.catch(() => undefined);
    return this.flushing;
  }

  private async drainOnce(): Promise<void> {
    if (this.queue.length === 0) return;
    const events = this.queue;
    this.queue = [];

    if (this.store === null || this.storeFailed) {
      this.dropped += events.length;
      return;
    }
    const store = this.store;

    let batch: ChainRecord[];
    try {
      let head: ChainHead = store.head();
      batch = [];
      for (const event of events) {
        const rec = makeRecord(head, event);
        batch.push(rec);
        head = { seq: rec.seq, hash: rec.hash };
      }
      store.append(batch);
      this.written += batch.length;
    } catch (err) {
      this.storeFailed = true;
      this.dropped += events.length;
      logOnce(this.storeErrorLogged, 'store append failed; recording disabled, dropping events', err);
      return;
    }

    if (this.signer && this.signEveryFlush && batch.length > 0) {
      const tip = batch[batch.length - 1];
      try {
        const sig = await this.signer.sign(tip.seq, tip.hash);
        store.addSignature(sig);
      } catch (err) {
        // Signature failure does not invalidate stored events; warn once.
        logOnce(this.signerErrorLogged, 'head signing failed', err);
      }
    }
  }

  /** Flush, then release the store. Idempotent. */
  close(): Promise<void> {
    if (this.closePromise) return this.closePromise;
    this.closePromise = (async () => {
      await this.flush();
      this.closed = true;
      if (this.store && !this.storeFailed) {
        try {
          this.store.close();
        } catch (err) {
          logOnce(this.storeErrorLogged, 'store close failed', err);
        }
      }
    })();
    return this.closePromise;
  }

  stats(): RecorderStats {
    return {
      enqueued: this.enqueued,
      written: this.written,
      dropped: this.dropped,
      storeFailed: this.storeFailed,
    };
  }
}
