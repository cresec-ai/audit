/**
 * THE SHIPPER — a reader of the chain, and nothing else.
 *
 * It runs in its OWN process (`mcp-recorder ship`), never on the forwarding
 * path. It does not call `record()`, never holds the store's write lock
 * while doing I/O, and in the default deployment does not run inside the
 * proxy at all. That is not a preference: `hook` is a SHORT-LIVED PROCESS
 * PER HOOK INVOCATION (src/hook/state.ts), so there is no long-lived event
 * loop to put an in-process shipper into, and blocking a hook on a POST
 * would put sink latency directly in front of every tool call.
 *
 * THE SPOOL IS THE CHAIN. There is no second queue and no separate spool
 * file: the shipper reads with `store.iterate({fromSeq, toSeq})`. The jsonl
 * backend's read methods do not take the advisory write lock (they
 * incrementally parse only the bytes another process appended), and sqlite
 * reads under WAL, so a shipper never contends with a recording process.
 * Nothing is ever dropped from the local store because of the sink; the
 * backlog is bounded only by disk.
 *
 * THE SHIPPER NEVER APPENDS TO THE CHAIN. Writing a "shipped" event would
 * change the chain it is trying to ship. All sink state lives in
 * <data-dir>/sink-cursor.json (a cache) and <data-dir>/ship-status.json
 * (what an operator reads).
 *
 * Crash-only by construction: there are no "unsent events" to drain, because
 * everything `record()` sealed is already in the store. The next shipper
 * start reads the receiver's cursor and ships the backlog. If the machine
 * never comes back, the receiver holds everything up to the last 202 PLUS a
 * signed head proving how much more existed.
 *
 * Every terminal condition here STALLS LOUDLY rather than degrading quietly.
 * The sender must NEVER skip a seq: a gap at the receiver makes everything
 * after it unverifiable forever, which is far worse than a visible stall.
 */

import { GENESIS_HASH } from '../chain/hash.js';
import type { ChainRecord, HeadSignature } from '../schema/events.js';
import type { EvidenceStore, SignerLike } from '../types.js';
import { SinkClient } from './client.js';
import type { SinkOutcome, SinkSigner } from './client.js';
import type { SinkConfig } from './config.js';
import {
  AUTH_BACKOFF_BASE_MS,
  AUTH_BACKOFF_CAP_MS,
  HEARTBEAT_INTERVAL_S,
  SENDER_MAX_BYTES,
  SENDER_MAX_RECORDS,
  backoffMs,
  chainIdFromGenesisRecord,
} from './protocol.js';
import type { SinkCursor, SinkHead, SinkSurface } from './protocol.js';
import { readCursorCache, writeCursorCache, writeShipStatus } from './state.js';
import type { ShipState, ShipStatus } from './state.js';

/** Both halves of the signing surface: request signatures and head signatures. */
export type ShipSigner = SinkSigner & SignerLike;

export interface ShipperOpts {
  dataDir: string;
  sink: SinkConfig;
  store: EvidenceStore;
  signer: ShipSigner;
  toolVersion: string;
  surface: SinkSurface;
  env?: NodeJS.ProcessEnv;
  /** One stderr line per distinct condition; see `logOnce` below. */
  log?: (msg: string) => void;
  now?: () => number;
  sleep?: (ms: number) => Promise<void>;
  random?: () => number;
  /** Refresh the single-instance lock so peers can tell it from a corpse. */
  touchLock?: () => void;
  heartbeatIntervalMs?: number;
  /** Ship the backlog and exit — the CI mode (`ship --drain`). */
  drain?: boolean;
  /** Wall-clock ceiling for drain mode. */
  drainTimeoutMs?: number;
  /** Exit after this long with neither local growth nor a delivery. 0 = never. */
  idleExitMs?: number;
  /** How often to look for new records while caught up. */
  pollIntervalMs?: number;
  connectTimeoutMs?: number;
  totalTimeoutMs?: number;
  gzipThresholdBytes?: number;
  /** Test seam: stop after this many POST attempts. */
  maxPosts?: number;
}

export interface ShipperResult {
  state: ShipState;
  chainId?: string;
  /** Records this run got a 202 for. */
  delivered: number;
  /** Receiver's resume point as last reported. */
  nextSeq: number;
  localHeadSeq: number;
  /** localHeadSeq - (nextSeq - 1): sealed records the receiver does not have. */
  lag: number;
  lastError?: string;
  posts: number;
}

const DEFAULT_POLL_MS = 1_000;
/** No local growth and no delivery for this long: exit, and let the next
 *  `record`/`hook` respawn us. Supervised fleets pass 0 and run forever. */
export const DEFAULT_IDLE_EXIT_MS = 15 * 60_000;

/**
 * Deliberately NOT unref'd. Between iterations this timer is the shipper
 * process's only pending handle, and node does not keep the event loop alive
 * for an unref'd one — nor for a `process.on('SIGTERM')` handler, which is
 * unref'd too. An unref'd sleep here therefore made the daemon exit silently
 * after its very first pass: it shipped the backlog once, then died without
 * picking up later records and without ever heartbeating, which reads at the
 * receiver exactly like a killed machine. Nothing else in the loop keeps the
 * process alive, so this is what does.
 *
 * It does not keep the process alive past the run: once `runShipper`
 * resolves, no timer is pending.
 */
function defaultSleep(ms: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

/**
 * Pick the next batch: contiguous, ascending, from `fromSeq`, bounded by
 * whichever cap binds first — but ALWAYS at least one record, even when that
 * record alone blows the byte cap. Skipping is not an option.
 */
export function collectBatch(
  store: EvidenceStore,
  fromSeq: number,
  maxRecords: number,
  maxBytes: number,
): ChainRecord[] {
  const records: ChainRecord[] = [];
  let bytes = 0;
  for (const record of store.iterate({ fromSeq })) {
    // Contiguity is a property of the store, but a torn tail or a hand-edited
    // jsonl could break it; shipping across a hole would hand the receiver a
    // batch it can only reject, so stop at the first discontinuity instead.
    if (records.length > 0 && record.seq !== records[records.length - 1]!.seq + 1) break;
    const size = JSON.stringify(record).length;
    if (records.length > 0 && (records.length >= maxRecords || bytes + size > maxBytes)) break;
    records.push(record);
    bytes += size;
    if (records.length >= maxRecords) break;
  }
  return records;
}

/** Signatures whose seq falls inside [fromSeq, toSeq] — every one we hold. */
export function signaturesInRange(
  store: EvidenceStore,
  fromSeq: number,
  toSeq: number,
): HeadSignature[] {
  return store.signatures().filter((sig) => sig.seq >= fromSeq && sig.seq <= toSeq);
}

/** The local record at `seq`, or undefined when the store no longer holds it. */
function recordAt(store: EvidenceStore, seq: number): ChainRecord | undefined {
  for (const record of store.iterate({ fromSeq: seq, toSeq: seq })) return record;
  return undefined;
}

/**
 * One shipping run. Resolves when the loop ends: drained, idle-exited,
 * post-capped, or parked in a terminal state. Never throws for a sink
 * condition — every one of them is a state plus a diagnostic.
 */
export async function runShipper(opts: ShipperOpts): Promise<ShipperResult> {
  const now = opts.now ?? Date.now;
  const sleep = opts.sleep ?? defaultSleep;
  const random = opts.random ?? Math.random;
  const pollMs = opts.pollIntervalMs ?? DEFAULT_POLL_MS;
  const idleExitMs = opts.idleExitMs ?? DEFAULT_IDLE_EXIT_MS;
  const drainDeadline =
    opts.drain === true && opts.drainTimeoutMs !== undefined
      ? now() + opts.drainTimeoutMs
      : undefined;

  /**
   * Parked = shipping records is off, on purpose and visibly. Written as
   * functions over the state rather than inline comparisons so the control
   * flow stays readable — and so adding a state forces a decision here.
   */
  const isParked = (s: ShipState): boolean => s === 'forked' || s === 'stalled' || s === 'refused';
  const isHealthy = (s: ShipState): boolean =>
    s === 'idle' || s === 'shipping' || s === 'retrying';

  const logged = new Set<string>();
  const logOnce = (key: string, msg: string): void => {
    if (logged.has(key)) return;
    logged.add(key);
    try {
      opts.log?.(msg);
    } catch {
      /* even diagnostics are fail-open */
    }
  };

  let state: ShipState = 'idle';
  let chainId: string | undefined;
  let client: SinkClient | undefined;
  let cursor: SinkCursor | undefined;
  let nextSeq = 1;
  let delivered = 0;
  let posts = 0;
  let attempt = 0;
  let authAttempt = 0;
  let lastError: string | undefined;
  let lastSuccessAt: string | undefined;
  let lastErrorAt: string | undefined;
  let lastPostAt = 0;
  let lastActivityAt = now();
  let lastLocalHeadSeq = -1;
  let maxRecords = SENDER_MAX_RECORDS;
  let maxBytes = SENDER_MAX_BYTES;
  let heartbeatMs = opts.heartbeatIntervalMs ?? HEARTBEAT_INTERVAL_S * 1000;
  let badRequestRange: string | undefined;

  const writeStatus = (localHeadSeq: number): void => {
    const status: ShipStatus = {
      sink: opts.sink.url,
      key: opts.signer.publicKeyHex,
      state,
      local_head_seq: localHeadSeq,
      next_seq: nextSeq,
      lag: Math.max(0, localHeadSeq - (nextSeq - 1)),
      updated_at: new Date().toISOString(),
      pid: process.pid,
    };
    if (chainId !== undefined) status.chain_id = chainId;
    if (cursor?.attested_seq !== undefined) status.attested_seq = cursor.attested_seq;
    if (lastError !== undefined) status.last_error = lastError;
    if (lastErrorAt !== undefined) status.last_error_at = lastErrorAt;
    if (lastSuccessAt !== undefined) status.last_success_at = lastSuccessAt;
    writeShipStatus(opts.dataDir, status);
  };

  const noteError = (msg: string): void => {
    lastError = msg;
    lastErrorAt = new Date().toISOString();
  };

  const applyCursor = (next: SinkCursor): void => {
    cursor = next;
    nextSeq = next.next_seq;
    if (next.max_records !== undefined) maxRecords = Math.min(SENDER_MAX_RECORDS, next.max_records);
    if (next.max_bytes !== undefined) maxBytes = Math.min(SENDER_MAX_BYTES, next.max_bytes);
    if (next.heartbeat_interval_s !== undefined) heartbeatMs = next.heartbeat_interval_s * 1000;
    writeCursorCache(opts.dataDir, opts.sink.url, next);
  };

  /** Sign the CURRENT local head — the anti-withholding device. */
  const signHead = async (seq: number, hash: string): Promise<SinkHead | undefined> => {
    try {
      const signature = await opts.signer.sign(seq, hash);
      return { seq, hash, signature };
    } catch (cause) {
      noteError(`head signing failed: ${cause instanceof Error ? cause.message : String(cause)}`);
      return undefined;
    }
  };

  const result = (localHeadSeq: number): ShipperResult => {
    const out: ShipperResult = {
      state,
      delivered,
      nextSeq,
      localHeadSeq,
      lag: Math.max(0, localHeadSeq - (nextSeq - 1)),
      posts,
    };
    if (chainId !== undefined) out.chainId = chainId;
    if (lastError !== undefined) out.lastError = lastError;
    return out;
  };

  for (;;) {
    opts.touchLock?.();
    const localHead = opts.store.head();
    if (localHead.seq !== lastLocalHeadSeq) {
      lastLocalHeadSeq = localHead.seq;
      lastActivityAt = now();
    }

    if (drainDeadline !== undefined && now() >= drainDeadline) {
      writeStatus(localHead.seq);
      return result(localHead.seq);
    }

    /* ---- nothing sealed yet: there is no chain, so no chain_id ---- */
    if (localHead.seq === 0) {
      writeStatus(0);
      if (opts.drain === true) return result(0);
      if (idleExitMs > 0 && now() - lastActivityAt >= idleExitMs) return result(0);
      await sleep(pollMs);
      continue;
    }

    /* ---- resolve chain_id from the seq 1 record, once ---- */
    if (chainId === undefined) {
      const genesis = recordAt(opts.store, 1);
      if (genesis === undefined) {
        // A store whose seq 1 is gone cannot name its own chain. Stall: the
        // alternative is inventing an identifier, which would address the
        // wrong chain at the receiver.
        state = 'stalled';
        noteError('local store does not hold seq 1; cannot derive chain_id');
        logOnce('no-genesis', `[mcp-recorder] sink stalled: ${lastError ?? ''}`);
        writeStatus(localHead.seq);
        if (opts.drain === true) return result(localHead.seq);
        await sleep(pollMs);
        continue;
      }
      try {
        chainId = chainIdFromGenesisRecord(genesis);
      } catch (cause) {
        state = 'stalled';
        noteError(cause instanceof Error ? cause.message : String(cause));
        logOnce('bad-genesis', `[mcp-recorder] sink stalled: ${lastError ?? ''}`);
        writeStatus(localHead.seq);
        if (opts.drain === true) return result(localHead.seq);
        await sleep(pollMs);
        continue;
      }
      client = new SinkClient({
        sink: opts.sink,
        signer: opts.signer,
        chainId,
        sender: {
          tool_version: opts.toolVersion,
          surface: opts.surface,
          backend: opts.store.backend,
        },
        ...(opts.env !== undefined ? { env: opts.env } : {}),
        ...(opts.connectTimeoutMs !== undefined ? { connectTimeoutMs: opts.connectTimeoutMs } : {}),
        ...(opts.totalTimeoutMs !== undefined ? { totalTimeoutMs: opts.totalTimeoutMs } : {}),
        ...(opts.gzipThresholdBytes !== undefined
          ? { gzipThresholdBytes: opts.gzipThresholdBytes }
          : {}),
      });

      // Cache first (avoids a round trip), then ask the receiver, which is
      // the only authority on what it holds. A failed ask leaves us on the
      // cache — or at seq 1 — and the receiver's own 409 corrects us.
      const cached = readCursorCache(opts.dataDir, opts.sink.url);
      if (cached !== undefined && cached.chain_id === chainId) {
        nextSeq = cached.next_seq;
        cursor = cached;
      }
      const fetched = await client.fetchCursor();
      if (fetched.kind === 'ok' && fetched.cursor !== undefined) {
        applyCursor(fetched.cursor);
      } else if (fetched.kind === 'unauthorized') {
        noteError(fetched.detail);
      }
    }

    const activeClient = client;
    if (activeClient === undefined) {
      await sleep(pollMs);
      continue;
    }

    /* ---- a cursor that is not about OUR chain means a hostile or
           misdirected sink; shipping into it would corrupt one of the two ---- */
    if (cursor !== undefined && (cursor.chain_id !== chainId || cursor.key !== opts.signer.publicKeyHex)) {
      state = 'refused';
      noteError(
        `sink answered for chain ${cursor.chain_id.slice(0, 12)}/key ${cursor.key.slice(0, 12)}, ` +
          'which is not this install — refusing to ship',
      );
      logOnce('wrong-chain', `[mcp-recorder] sink REFUSED: ${lastError ?? ''}`);
      writeStatus(localHead.seq);
      return result(localHead.seq);
    }

    /* ---- head-hash guard: the receiver's view must BE this chain ---- */
    if (state !== 'forked' && cursor !== undefined && nextSeq >= 1) {
      const expected =
        nextSeq === 1 ? GENESIS_HASH : (recordAt(opts.store, nextSeq - 1)?.hash ?? undefined);
      if (expected === undefined) {
        // The receiver is ahead of, or diverged from, what we still hold.
        // Never jump the gap; stall and surface it.
        if (nextSeq - 1 > localHead.seq) {
          state = 'stalled';
          noteError(
            `receiver is at seq ${String(nextSeq - 1)} but the local head is ${String(localHead.seq)}`,
          );
          logOnce('receiver-ahead', `[mcp-recorder] sink stalled: ${lastError ?? ''}`);
          writeStatus(localHead.seq);
          if (opts.drain === true) return result(localHead.seq);
          await sleep(pollMs);
          continue;
        }
        state = 'stalled';
        noteError(`local store no longer holds seq ${String(nextSeq - 1)}; cannot resume without a gap`);
        logOnce('local-gap', `[mcp-recorder] sink stalled: ${lastError ?? ''}`);
        writeStatus(localHead.seq);
        if (opts.drain === true) return result(localHead.seq);
        await sleep(pollMs);
        continue;
      }
      if (expected !== cursor.head_hash) {
        state = 'forked';
        noteError(
          `receiver's hash at seq ${String(nextSeq - 1)} does not match the local chain — ` +
            'fork or MITM; refusing to ship',
        );
        logOnce(
          'fork-headhash',
          `[mcp-recorder] sink FORK DETECTED (terminal for this chain): ${lastError ?? ''}`,
        );
      }
    }

    const canShipRecords = !isParked(state);
    const backlog = canShipRecords && nextSeq <= localHead.seq;

    /* ---- caught up (or parked): heartbeat, then wait ---- */
    if (!backlog) {
      const heartbeatDue = now() - lastPostAt >= heartbeatMs;
      if (opts.drain !== true && heartbeatDue) {
        const head = await signHead(localHead.seq, localHead.hash);
        if (head !== undefined) {
          posts++;
          lastPostAt = now();
          const outcome = await activeClient.postBatch(
            activeClient.buildBody({
              fromSeq: 0,
              toSeq: 0,
              baseHash: GENESIS_HASH,
              records: [],
              signatures: [],
              head,
            }),
          );
          if (outcome.kind === 'ok') {
            lastSuccessAt = new Date().toISOString();
            if (outcome.cursor !== undefined) applyCursor(outcome.cursor);
          } else if (outcome.kind === 'unauthorized') {
            if (state !== 'forked') state = 'unauthorized';
            noteError(outcome.detail);
          } else {
            noteError(outcome.detail);
          }
        }
      }
      if (isHealthy(state)) state = 'idle';
      writeStatus(localHead.seq);
      if (opts.drain === true) return result(localHead.seq);
      if (opts.maxPosts !== undefined && posts >= opts.maxPosts) return result(localHead.seq);
      if (idleExitMs > 0 && now() - lastActivityAt >= idleExitMs) return result(localHead.seq);
      await sleep(state === 'unauthorized' ? Math.min(heartbeatMs, pollMs * 10) : pollMs);
      continue;
    }

    /* ---- ship one batch. Strictly one in-flight POST per chain: there is
           no pipelining here, and a chain's throughput is bounded by the
           tool-call rate, not by RTT. ---- */
    const records = collectBatch(opts.store, nextSeq, maxRecords, maxBytes);
    if (records.length === 0 || records[0]!.seq !== nextSeq) {
      state = 'stalled';
      noteError(`local store cannot produce a batch starting at seq ${String(nextSeq)}`);
      logOnce('rebuild-failed', `[mcp-recorder] sink stalled: ${lastError ?? ''}`);
      writeStatus(localHead.seq);
      if (opts.drain === true) return result(localHead.seq);
      await sleep(pollMs);
      continue;
    }
    const fromSeq = records[0]!.seq;
    const toSeq = records[records.length - 1]!.seq;
    const head = await signHead(localHead.seq, localHead.hash);
    if (head === undefined) {
      state = 'retrying';
      writeStatus(localHead.seq);
      if (opts.drain === true) return result(localHead.seq);
      await sleep(pollMs);
      continue;
    }

    state = 'shipping';
    posts++;
    lastPostAt = now();
    const outcome: SinkOutcome = await activeClient.postBatch(
      activeClient.buildBody({
        fromSeq,
        toSeq,
        baseHash: records[0]!.prev_hash,
        records,
        signatures: signaturesInRange(opts.store, fromSeq, toSeq),
        head,
      }),
    );

    switch (outcome.kind) {
      case 'ok': {
        attempt = 0;
        authAttempt = 0;
        badRequestRange = undefined;
        delivered += records.length;
        lastSuccessAt = new Date().toISOString();
        lastActivityAt = now();
        if (outcome.cursor !== undefined) {
          applyCursor(outcome.cursor);
        } else {
          // A receiver that answered 202 without a cursor is still telling
          // us it committed; advance optimistically and let its next cursor
          // (or a 409) correct us.
          nextSeq = toSeq + 1;
        }
        state = 'idle';
        break;
      }
      case 'gap': {
        // The receiver cannot link this batch. Rewind to ITS next_seq — never
        // forward, never across a hole.
        if (outcome.cursor !== undefined) applyCursor(outcome.cursor);
        else {
          const refetched = await activeClient.fetchCursor();
          if (refetched.kind === 'ok' && refetched.cursor !== undefined) applyCursor(refetched.cursor);
        }
        noteError(outcome.detail);
        state = 'retrying';
        break;
      }
      case 'fork': {
        state = 'forked';
        if (outcome.cursor !== undefined) cursor = outcome.cursor;
        noteError(outcome.detail);
        logOnce(
          'fork',
          '[mcp-recorder] sink FORK DETECTED (terminal for this chain, recording continues locally): ' +
            outcome.detail,
        );
        break;
      }
      case 'bad_request': {
        const range = `${String(fromSeq)}-${String(toSeq)}`;
        if (badRequestRange === range) {
          // Rebuilt once from the store and rejected again: stall rather than
          // skip. A skipped record makes every later one unverifiable at the
          // receiver, forever.
          state = 'stalled';
          noteError(`sink rejected seq ${range} twice: ${outcome.detail}`);
          logOnce('bad-request', `[mcp-recorder] sink stalled on seq ${range}: ${outcome.detail}`);
        } else {
          badRequestRange = range;
          noteError(outcome.detail);
          state = 'retrying';
        }
        break;
      }
      case 'unauthorized': {
        state = 'unauthorized';
        noteError(outcome.detail);
        logOnce(
          'unauthorized',
          `[mcp-recorder] sink refused this install's credential (${String(outcome.status)}): ${outcome.detail}`,
        );
        break;
      }
      case 'too_large': {
        if (records.length === 1) {
          state = 'stalled';
          noteError(`sink rejected a single record as too large: ${outcome.detail}`);
          logOnce('too-large-single', `[mcp-recorder] sink stalled: ${lastError ?? ''}`);
        } else {
          maxRecords = Math.max(1, Math.floor(records.length / 2));
          if (outcome.maxRecords !== undefined) {
            maxRecords = Math.max(1, Math.min(maxRecords, outcome.maxRecords));
          }
          if (outcome.maxBytes !== undefined) maxBytes = Math.max(1, outcome.maxBytes);
          noteError(outcome.detail);
          state = 'retrying';
        }
        break;
      }
      case 'rate_limited':
      case 'transient': {
        noteError(outcome.detail);
        state = 'retrying';
        break;
      }
    }

    writeStatus(localHead.seq);

    if (isParked(state)) {
      if (opts.drain === true) return result(localHead.seq);
      // Parked: keep heartbeating so the receiver can tell a stall (cursor
      // frozen while the signed head climbs — an explicit withholding
      // condition) from silence (nothing at all).
      if (opts.maxPosts !== undefined && posts >= opts.maxPosts) return result(localHead.seq);
      await sleep(pollMs);
      continue;
    }

    if (opts.maxPosts !== undefined && posts >= opts.maxPosts) return result(localHead.seq);

    if (state === 'retrying' || state === 'unauthorized') {
      if (opts.drain === true && outcome.kind === 'unauthorized') return result(localHead.seq);
      let delay: number;
      if (state === 'unauthorized') {
        delay = backoffMs(authAttempt++, random, AUTH_BACKOFF_BASE_MS, AUTH_BACKOFF_CAP_MS);
      } else if (outcome.kind === 'rate_limited' && outcome.retryAfterMs !== undefined) {
        delay = outcome.retryAfterMs;
      } else {
        delay = backoffMs(attempt++, random);
      }
      if (drainDeadline !== undefined && now() + delay >= drainDeadline) {
        return result(localHead.seq);
      }
      await sleep(delay);
    }
  }
}
