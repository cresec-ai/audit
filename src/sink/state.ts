/**
 * The shipper's only durable state, all of it outside the chain.
 *
 * THE SHIPPER NEVER APPENDS TO THE CHAIN. It is a reader: writing a
 * "shipped" event would change the very chain it is trying to ship, a
 * self-referential moving target. So everything it needs to remember lives
 * in two small files beside the store:
 *
 *   <data-dir>/sink-cursor.json — a CACHE of the receiver's cursor, consulted
 *       only to avoid a round trip. NEVER authoritative: the shipper re-reads
 *       the receiver's cursor on startup, on any 409 and on any 4xx, and a
 *       stale cache is harmless because the receiver hash-checks the
 *       overlapping prefix and commits only the suffix.
 *   <data-dir>/ship-status.json — what `mcp-recorder ship --status` prints.
 *       This is the file that turns a stall from an invisible condition into
 *       a human-legible one.
 *
 * Both are written tmp+rename, and a failed write is non-fatal — the local
 * store is the source of truth and the receiver is the authority on what it
 * holds.
 *
 * Single instance is a `<data-dir>/ship.lock` DIRECTORY created with
 * `mkdirSync`: the same atomic-create mutex the jsonl store, the hook's
 * session markers and `identity.key` already use, and the only one that is
 * atomic on every platform node supports.
 */

import {
  mkdirSync,
  readFileSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { join } from 'node:path';
import { FILES } from '../types.js';
import type { SinkCursor } from './protocol.js';

/* ------------------------------ cursor cache ---------------------------- */

export interface CursorCache extends SinkCursor {
  /** The sink this cursor came from — a different sink invalidates it. */
  sink: string;
  updated_at: string;
}

export function cursorCachePath(dataDir: string): string {
  return join(dataDir, FILES.SINK_CURSOR);
}

/** Read the cached cursor, or undefined for missing/corrupt/other-sink. */
export function readCursorCache(dataDir: string, sinkUrl: string): CursorCache | undefined {
  let text: string;
  try {
    text = readFileSync(cursorCachePath(dataDir), 'utf8');
  } catch {
    return undefined;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return undefined;
  }
  if (typeof parsed !== 'object' || parsed === null) return undefined;
  const raw = parsed as Record<string, unknown>;
  if (raw.sink !== sinkUrl) return undefined;
  const cursor = importCursor(raw);
  if (cursor === undefined) return undefined;
  return {
    ...cursor,
    sink: sinkUrl,
    updated_at: typeof raw.updated_at === 'string' ? raw.updated_at : '',
  };
}

function importCursor(raw: Record<string, unknown>): SinkCursor | undefined {
  const nextSeq = raw.next_seq;
  if (typeof nextSeq !== 'number' || !Number.isInteger(nextSeq) || nextSeq < 1) return undefined;
  if (typeof raw.head_hash !== 'string') return undefined;
  if (typeof raw.chain_id !== 'string') return undefined;
  if (typeof raw.key !== 'string') return undefined;
  const cursor: SinkCursor = {
    chain_id: raw.chain_id,
    key: raw.key,
    next_seq: nextSeq,
    head_hash: raw.head_hash,
  };
  if (typeof raw.attested_seq === 'number') cursor.attested_seq = raw.attested_seq;
  if (typeof raw.attested_at === 'string') cursor.attested_at = raw.attested_at;
  if (typeof raw.max_records === 'number') cursor.max_records = raw.max_records;
  if (typeof raw.max_bytes === 'number') cursor.max_bytes = raw.max_bytes;
  if (typeof raw.heartbeat_interval_s === 'number') {
    cursor.heartbeat_interval_s = raw.heartbeat_interval_s;
  }
  return cursor;
}

/** Best effort; a failed cursor write is never fatal. */
export function writeCursorCache(dataDir: string, sinkUrl: string, cursor: SinkCursor): void {
  const payload: CursorCache = { ...cursor, sink: sinkUrl, updated_at: new Date().toISOString() };
  writeJsonAtomicQuiet(cursorCachePath(dataDir), payload);
}

/* ------------------------------ status file ----------------------------- */

/**
 * `idle` and `shipping` are healthy. Everything else is a condition an
 * operator has to see, which is exactly why it is written down rather than
 * only logged: a stall that nobody can observe is the failure mode this
 * whole design exists to avoid.
 */
export type ShipState =
  | 'idle'
  | 'shipping'
  | 'retrying'
  | 'stalled'
  | 'forked'
  | 'unauthorized'
  | 'refused';

export interface ShipStatus {
  sink: string;
  key?: string;
  chain_id?: string;
  state: ShipState;
  /** Sender's local head seq at the last loop iteration. */
  local_head_seq: number;
  /** Receiver's resume point, as the receiver last reported it. */
  next_seq?: number;
  attested_seq?: number;
  /** local_head_seq - (next_seq - 1): sealed records the receiver lacks. */
  lag: number;
  last_error?: string;
  last_error_at?: string;
  last_success_at?: string;
  /** Records dropped by the STORE (disk full, ...) as counted by the
   *  recorder — surfaced here because a dropped record is the one gap the
   *  chain itself cannot show, and it must never be silent. */
  updated_at: string;
  pid: number;
}

export function statusPath(dataDir: string): string {
  return join(dataDir, FILES.SHIP_STATUS);
}

export function readShipStatus(dataDir: string): ShipStatus | undefined {
  try {
    const parsed: unknown = JSON.parse(readFileSync(statusPath(dataDir), 'utf8'));
    if (typeof parsed !== 'object' || parsed === null) return undefined;
    return parsed as ShipStatus;
  } catch {
    return undefined;
  }
}

export function writeShipStatus(dataDir: string, status: ShipStatus): void {
  writeJsonAtomicQuiet(statusPath(dataDir), status);
}

function writeJsonAtomicQuiet(path: string, value: unknown): void {
  const tmp = `${path}.${String(process.pid)}.tmp`;
  try {
    writeFileSync(tmp, JSON.stringify(value, null, 2) + '\n', { mode: 0o600 });
    renameSync(tmp, path);
  } catch {
    try {
      rmSync(tmp, { force: true });
    } catch {
      /* fail-open: state files are a convenience, never the evidence */
    }
  }
}

/* ------------------------------ ship.lock ------------------------------- */

/**
 * A shipper that has not touched its lock in this long is assumed dead (the
 * container was reclaimed, the laptop lid closed, SIGKILL). Deliberately
 * several heartbeats wide so a slow POST never looks like a corpse.
 */
export const SHIP_LOCK_STALE_MS = 5 * 60_000;

export function shipLockPath(dataDir: string): string {
  return join(dataDir, FILES.SHIP_LOCK);
}

export interface ShipLock {
  /** Refresh the lock's mtime so peers can tell it from an abandoned one. */
  touch(): void;
  release(): void;
  readonly path: string;
}

/**
 * True when some other process looks like it is already shipping for this
 * data dir. Cheap (one statSync) because `record`/`hook`/`http` call it on
 * their way past, and `hook` is a fresh process per tool call.
 */
export function shipperLooksAlive(dataDir: string): boolean {
  const owner = join(shipLockPath(dataDir), 'owner');
  try {
    return Date.now() - statSync(owner).mtimeMs <= SHIP_LOCK_STALE_MS;
  } catch {
    /* no owner file: fall back to the directory itself (crash between
     * mkdir and write), and treat a missing directory as "not running". */
  }
  try {
    return Date.now() - statSync(shipLockPath(dataDir)).mtimeMs <= SHIP_LOCK_STALE_MS;
  } catch {
    return false;
  }
}

/**
 * Take the single-instance lock, reclaiming one that looks abandoned.
 * Returns undefined when another live shipper holds it — the caller then
 * simply exits, because one shipper per data dir is the whole rule.
 */
export function acquireShipLock(dataDir: string): ShipLock | undefined {
  const dir = shipLockPath(dataDir);
  const ownerPath = join(dir, 'owner');
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      mkdirSync(dir, { mode: 0o700 });
    } catch (cause) {
      if ((cause as NodeJS.ErrnoException).code !== 'EEXIST') return undefined;
      if (attempt === 0 && !shipperLooksAlive(dataDir)) {
        try {
          rmSync(dir, { recursive: true, force: true });
        } catch {
          return undefined;
        }
        continue;
      }
      return undefined;
    }
    const touch = (): void => {
      try {
        writeFileSync(ownerPath, `${String(process.pid)} ${String(Date.now())}\n`, { mode: 0o600 });
      } catch {
        /* best-effort provenance only — the lock itself is already held */
      }
    };
    touch();
    return {
      path: dir,
      touch,
      release: (): void => {
        try {
          rmSync(dir, { recursive: true, force: true });
        } catch {
          /* a leftover lock is reclaimed by the next acquirer's staleness check */
        }
      },
    };
  }
  return undefined;
}
