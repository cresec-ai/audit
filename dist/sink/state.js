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
import { mkdirSync, readFileSync, renameSync, rmSync, statSync, writeFileSync, } from 'node:fs';
import { join } from 'node:path';
import { FILES } from '../types.js';
export function cursorCachePath(dataDir) {
    return join(dataDir, FILES.SINK_CURSOR);
}
/** Read the cached cursor, or undefined for missing/corrupt/other-sink. */
export function readCursorCache(dataDir, sinkUrl) {
    let text;
    try {
        text = readFileSync(cursorCachePath(dataDir), 'utf8');
    }
    catch {
        return undefined;
    }
    let parsed;
    try {
        parsed = JSON.parse(text);
    }
    catch {
        return undefined;
    }
    if (typeof parsed !== 'object' || parsed === null)
        return undefined;
    const raw = parsed;
    if (raw.sink !== sinkUrl)
        return undefined;
    const cursor = importCursor(raw);
    if (cursor === undefined)
        return undefined;
    return {
        ...cursor,
        sink: sinkUrl,
        updated_at: typeof raw.updated_at === 'string' ? raw.updated_at : '',
    };
}
function importCursor(raw) {
    const nextSeq = raw.next_seq;
    if (typeof nextSeq !== 'number' || !Number.isInteger(nextSeq) || nextSeq < 1)
        return undefined;
    if (typeof raw.head_hash !== 'string')
        return undefined;
    if (typeof raw.chain_id !== 'string')
        return undefined;
    if (typeof raw.key !== 'string')
        return undefined;
    const cursor = {
        chain_id: raw.chain_id,
        key: raw.key,
        next_seq: nextSeq,
        head_hash: raw.head_hash,
    };
    if (typeof raw.attested_seq === 'number')
        cursor.attested_seq = raw.attested_seq;
    if (typeof raw.attested_at === 'string')
        cursor.attested_at = raw.attested_at;
    if (typeof raw.max_records === 'number')
        cursor.max_records = raw.max_records;
    if (typeof raw.max_bytes === 'number')
        cursor.max_bytes = raw.max_bytes;
    if (typeof raw.heartbeat_interval_s === 'number') {
        cursor.heartbeat_interval_s = raw.heartbeat_interval_s;
    }
    return cursor;
}
/** Best effort; a failed cursor write is never fatal. */
export function writeCursorCache(dataDir, sinkUrl, cursor) {
    const payload = { ...cursor, sink: sinkUrl, updated_at: new Date().toISOString() };
    writeJsonAtomicQuiet(cursorCachePath(dataDir), payload);
}
export function statusPath(dataDir) {
    return join(dataDir, FILES.SHIP_STATUS);
}
export function readShipStatus(dataDir) {
    try {
        const parsed = JSON.parse(readFileSync(statusPath(dataDir), 'utf8'));
        if (typeof parsed !== 'object' || parsed === null)
            return undefined;
        return parsed;
    }
    catch {
        return undefined;
    }
}
export function writeShipStatus(dataDir, status) {
    writeJsonAtomicQuiet(statusPath(dataDir), status);
}
function writeJsonAtomicQuiet(path, value) {
    const tmp = `${path}.${String(process.pid)}.tmp`;
    try {
        writeFileSync(tmp, JSON.stringify(value, null, 2) + '\n', { mode: 0o600 });
        renameSync(tmp, path);
    }
    catch {
        try {
            rmSync(tmp, { force: true });
        }
        catch {
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
export function shipLockPath(dataDir) {
    return join(dataDir, FILES.SHIP_LOCK);
}
/**
 * True when some other process looks like it is already shipping for this
 * data dir. Cheap (one statSync) because `record`/`hook`/`http` call it on
 * their way past, and `hook` is a fresh process per tool call.
 */
export function shipperLooksAlive(dataDir) {
    const owner = join(shipLockPath(dataDir), 'owner');
    try {
        return Date.now() - statSync(owner).mtimeMs <= SHIP_LOCK_STALE_MS;
    }
    catch {
        /* no owner file: fall back to the directory itself (crash between
         * mkdir and write), and treat a missing directory as "not running". */
    }
    try {
        return Date.now() - statSync(shipLockPath(dataDir)).mtimeMs <= SHIP_LOCK_STALE_MS;
    }
    catch {
        return false;
    }
}
/**
 * Take the single-instance lock, reclaiming one that looks abandoned.
 * Returns undefined when another live shipper holds it — the caller then
 * simply exits, because one shipper per data dir is the whole rule.
 */
export function acquireShipLock(dataDir) {
    const dir = shipLockPath(dataDir);
    const ownerPath = join(dir, 'owner');
    for (let attempt = 0; attempt < 2; attempt++) {
        try {
            mkdirSync(dir, { mode: 0o700 });
        }
        catch (cause) {
            if (cause.code !== 'EEXIST')
                return undefined;
            if (attempt === 0 && !shipperLooksAlive(dataDir)) {
                try {
                    rmSync(dir, { recursive: true, force: true });
                }
                catch {
                    return undefined;
                }
                continue;
            }
            return undefined;
        }
        const touch = () => {
            try {
                writeFileSync(ownerPath, `${String(process.pid)} ${String(Date.now())}\n`, { mode: 0o600 });
            }
            catch {
                /* best-effort provenance only — the lock itself is already held */
            }
        };
        touch();
        return {
            path: dir,
            touch,
            release: () => {
                try {
                    rmSync(dir, { recursive: true, force: true });
                }
                catch {
                    /* a leftover lock is reclaimed by the next acquirer's staleness check */
                }
            },
        };
    }
    return undefined;
}
//# sourceMappingURL=state.js.map