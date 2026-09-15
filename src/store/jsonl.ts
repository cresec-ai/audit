/**
 * JSONL evidence store (fallback backend).
 *
 * Two append-only files in the data dir:
 *   FILES.JSONL_LOG  — one ChainRecord JSON per line
 *   FILES.JSONL_SIGS — one HeadSignature JSON per line
 *
 * Several `mcp-recorder record` processes normally share one data dir (one
 * wrapper per MCP server), so writes go through a cross-process advisory
 * lock (a `<log>.lock` directory — `mkdirSync` is atomic on every platform,
 * so "the dir didn't exist and now it does" is an uncontestable mutex). The
 * lock guards BOTH files: appends validate chain continuity against the
 * TRUE on-disk head (read fresh, under the lock — never a stale in-memory
 * copy), then appendFileSync the lines.
 *
 * Read methods (`head`/`count`/`iterate`/`sessions`/`latestSignature`/
 * `signatures`) reflect on-disk state written by other processes: each one
 * first checks whether the file's size changed since this instance last
 * loaded it and reloads when it has. Simple and correct beats clever here —
 * this is the no-native-deps path.
 */

import {
  appendFileSync,
  closeSync,
  existsSync,
  fstatSync,
  ftruncateSync,
  mkdirSync,
  openSync,
  readFileSync,
  readSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { join } from 'node:path';
import { Buffer } from 'node:buffer';
import type { AnyEvent, ChainRecord, HeadSignature } from '../schema/events.js';
import { GENESIS_HASH, makeRecord } from '../chain/hash.js';
import { validateExtendsHead } from './sqlite.js';
import { FILES } from '../types.js';
import type { ChainHead, EvidenceStore, IterateOpts, SessionSummary } from '../types.js';

/**
 * Read a JSONL file into objects. A trailing partial line (e.g. from a crash
 * mid-write) is tolerated with a stderr warning; corruption anywhere else is
 * an error — silent data loss in an evidence store is never acceptable.
 */
function loadJsonlFile<T>(path: string): T[] {
  if (!existsSync(path)) return [];
  const lines = readFileSync(path, 'utf8').split('\n');
  const out: T[] = [];
  for (let i = 0; i < lines.length; i++) {
    const line = (lines[i] ?? '').trim();
    if (line === '') continue;
    try {
      out.push(JSON.parse(line) as T);
    } catch (err) {
      const isLastContent = lines.slice(i + 1).every((rest) => rest.trim() === '');
      if (isLastContent) {
        process.stderr.write(
          `[mcp-recorder] ignoring trailing partial line ${i + 1} in ${path}\n`,
        );
        break;
      }
      throw new Error(
        `mcp-recorder: corrupt JSONL line ${i + 1} in ${path}: ${(err as Error).message}`,
      );
    }
  }
  return out;
}

/** Current size of `path`, or 0 when it does not exist (yet). */
function sizeOf(path: string): number {
  try {
    return statSync(path).size;
  } catch {
    return 0;
  }
}

/** Last KiB window read from the tail of a file, to cheaply find its last line. */
const TAIL_WINDOW_BYTES = 64 * 1024;

/**
 * The last non-empty line of `path`, read efficiently: only the last
 * `TAIL_WINDOW_BYTES` are pulled from disk in the common case. Falls back to
 * a full read when the window doesn't contain a full line (a single line
 * longer than the window, or the file itself is smaller than the window but
 * we still need to double-check — handled below).
 */
function readLastLine(path: string): string | undefined {
  let fd: number;
  try {
    fd = openSync(path, 'r');
  } catch {
    return undefined; // no file yet — empty store
  }
  try {
    const size = fstatSync(fd).size;
    if (size === 0) return undefined;
    const windowSize = Math.min(size, TAIL_WINDOW_BYTES);
    const start = size - windowSize;
    const buf = Buffer.alloc(windowSize);
    readSync(fd, buf, 0, windowSize, start);
    const text = buf.toString('utf8').replace(/\n+$/, '');
    const nl = text.lastIndexOf('\n');
    // If we read from the very start of the file, `text` IS the whole file,
    // so even a single line with no newline in it is the correct last line.
    // Otherwise, no newline in the window means the last line is longer
    // than the window — fall back to a full read below rather than return a
    // truncated suffix of it.
    if (start === 0 || nl !== -1) {
      const candidate = nl === -1 ? text : text.slice(nl + 1);
      if (candidate.trim() !== '') return candidate;
    }
  } finally {
    closeSync(fd);
  }
  // Fallback: full read (rare — a single trailing line wider than the tail
  // window, or some other edge case the fast path didn't like the look of).
  const all = readFileSync(path, 'utf8').split('\n');
  for (let i = all.length - 1; i >= 0; i--) {
    const line = all[i]!.trim();
    if (line !== '') return line;
  }
  return undefined;
}

/**
 * Crash recovery, run by a writer that holds the lock: when the log does not
 * end in a newline, a process died mid-write and left a torn final line.
 * Appending straight after it would glue the first new record onto the
 * garbage (losing that record, and turning the garbage into mid-file
 * corruption that makes the next open fail), so the torn bytes are trimmed
 * back to the last complete line first. Nothing sealed is removed — the
 * chain never extended over those bytes, and the tolerant loader already
 * ignores them at read time; this just makes that policy durable. Returns
 * the number of bytes discarded (0 when the tail was intact).
 */
function repairTornTail(path: string): number {
  let fd: number;
  try {
    fd = openSync(path, 'r+');
  } catch {
    return 0; // no file yet — nothing to repair
  }
  try {
    const size = fstatSync(fd).size;
    if (size === 0) return 0;
    const last = Buffer.alloc(1);
    readSync(fd, last, 0, 1, size - 1);
    if (last[0] === 0x0a) return 0;
    // Find the last newline: scan a tail window first, then the whole file.
    let keep = -1;
    let tail: Buffer | undefined;
    for (const windowSize of [Math.min(size, TAIL_WINDOW_BYTES), size]) {
      const start = size - windowSize;
      const buf = Buffer.alloc(windowSize);
      readSync(fd, buf, 0, windowSize, start);
      const nl = buf.lastIndexOf(0x0a);
      if (nl !== -1) {
        keep = start + nl + 1;
        tail = buf.subarray(nl + 1);
        break;
      }
      if (start === 0) {
        tail = buf;
        break;
      }
    }
    // A complete record that merely lost its newline (the write was cut at
    // its very last byte) is intact evidence, possibly already covered by a
    // head signature: finish the line instead of discarding it.
    if (tail !== undefined && tail.length > 0) {
      try {
        JSON.parse(tail.toString('utf8'));
        appendFileSync(path, '\n');
        return 0;
      } catch {
        /* genuinely torn — fall through and trim it */
      }
    }
    const cut = keep === -1 ? 0 : keep;
    ftruncateSync(fd, cut);
    process.stderr.write(
      `[mcp-recorder] discarded a torn trailing line (${size - cut} bytes) in ${path} left by an interrupted write\n`,
    );
    return size - cut;
  } finally {
    closeSync(fd);
  }
}

/* --------------------------- cross-process lock -------------------------- */

/**
 * Lock waits are SYNCHRONOUS (they block the event loop, and with it the
 * proxy's forwarding), so the budget per attempt is short: the critical
 * section is a tail read plus one appendFileSync, and the recorder retries
 * a batch that could not get the lock asynchronously.
 */
const LOCK_BUDGET_MS = 100;
const LOCK_RETRY_BASE_MS = 2;
const LOCK_RETRY_MAX_MS = 20;
/**
 * A lock dir older than this is assumed abandoned by a process that died
 * inside the critical section. That section takes milliseconds, so 5s is
 * generous, and it is short enough that a recorder's retry run (~1s of
 * backoff plus up to 7 lock waits) reaches the reclaim instead of dropping.
 */
const STALE_LOCK_MS = 5_000;

/** A real synchronous sleep, without a native dependency. */
function sleepSync(ms: number): void {
  if (ms <= 0) return;
  const sab = new SharedArrayBuffer(4);
  Atomics.wait(new Int32Array(sab), 0, 0, ms);
}

/** True when `dir`'s lock looks abandoned (missing/unreadable owner info). */
function lockLooksStale(lockDir: string): boolean {
  const ownerPath = join(lockDir, 'owner');
  try {
    return Date.now() - statSync(ownerPath).mtimeMs > STALE_LOCK_MS;
  } catch {
    // No owner file (crash between mkdir and write) — fall back to the lock
    // directory's own age.
    try {
      return Date.now() - statSync(lockDir).mtimeMs > STALE_LOCK_MS;
    } catch {
      return false; // vanished under us; the mkdir retry will sort it out
    }
  }
}

/**
 * Acquire the advisory lock at `lockDir`, retrying with backoff for up to
 * ~10s and reclaiming a lock that looks abandoned. `mkdirSync` either
 * succeeds or throws EEXIST atomically, so this is a real mutex across
 * processes despite being built from plain filesystem calls.
 */
function acquireLock(lockDir: string): void {
  const deadline = Date.now() + LOCK_BUDGET_MS;
  let attempt = 0;
  for (;;) {
    try {
      mkdirSync(lockDir);
      try {
        writeFileSync(join(lockDir, 'owner'), `${process.pid} ${Date.now()}\n`);
      } catch {
        /* best-effort provenance only — the lock itself is already held */
      }
      return;
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== 'EEXIST') throw err;
      if (lockLooksStale(lockDir)) {
        try {
          rmSync(lockDir, { recursive: true, force: true });
        } catch {
          /* another process may have reclaimed it first; just retry */
        }
        continue;
      }
      if (Date.now() >= deadline) {
        throw new Error(`mcp-recorder: timed out waiting for jsonl store lock at ${lockDir}`);
      }
      const backoff =
        Math.min(LOCK_RETRY_MAX_MS, LOCK_RETRY_BASE_MS * 2 ** attempt) + Math.random() * 5;
      attempt++;
      sleepSync(backoff);
    }
  }
}

function releaseLock(lockDir: string): void {
  try {
    rmSync(lockDir, { recursive: true, force: true });
  } catch {
    /* best effort — a crash here just leaves a lock for the next acquirer's
       staleness check to reclaim */
  }
}

export class JsonlStore implements EvidenceStore {
  readonly backend = 'jsonl' as const;
  /** Path of the record log (the store's primary file). */
  readonly path: string;
  private readonly sigsPath: string;
  private readonly lockDir: string;
  private records: ChainRecord[];
  private sigs: HeadSignature[];
  /** File size as of the last time `records`/`sigs` were loaded from disk. */
  private recordsLoadedSize: number;
  private sigsLoadedSize: number;

  constructor(dataDir: string) {
    mkdirSync(dataDir, { recursive: true, mode: 0o700 });
    this.path = join(dataDir, FILES.JSONL_LOG);
    this.sigsPath = join(dataDir, FILES.JSONL_SIGS);
    this.lockDir = `${this.path}.lock`;
    this.records = loadJsonlFile<ChainRecord>(this.path);
    this.sigs = loadJsonlFile<HeadSignature>(this.sigsPath);
    this.recordsLoadedSize = sizeOf(this.path);
    this.sigsLoadedSize = sizeOf(this.sigsPath);
  }

  /** Re-read the record log from disk iff another process has grown it. */
  private syncRecords(): void {
    const size = sizeOf(this.path);
    if (size !== this.recordsLoadedSize) {
      this.records = loadJsonlFile<ChainRecord>(this.path);
      this.recordsLoadedSize = size;
    }
  }

  /** Re-read the signatures log from disk iff another process has grown it. */
  private syncSigs(): void {
    const size = sizeOf(this.sigsPath);
    if (size !== this.sigsLoadedSize) {
      this.sigs = loadJsonlFile<HeadSignature>(this.sigsPath);
      this.sigsLoadedSize = size;
    }
  }

  private withLock<T>(fn: () => T): T {
    acquireLock(this.lockDir);
    try {
      return fn();
    } finally {
      releaseLock(this.lockDir);
    }
  }

  /** The head implied by the in-memory cache, with no disk access. */
  private cachedHead(): ChainHead {
    const last = this.records[this.records.length - 1];
    return last === undefined ? { seq: 0, hash: GENESIS_HASH } : { seq: last.seq, hash: last.hash };
  }

  /** The TRUE current head, read fresh from disk (cheap: tail-only read). */
  private readHeadFromDisk(): ChainHead {
    const line = readLastLine(this.path);
    if (line === undefined) return { seq: 0, hash: GENESIS_HASH };
    try {
      const record = JSON.parse(line) as ChainRecord;
      return { seq: record.seq, hash: record.hash };
    } catch {
      // Unexpected: a corrupt trailing line while holding the lock. Fall
      // back to the tolerant full loader rather than propagate a parse
      // error out of a head lookup.
      const records = loadJsonlFile<ChainRecord>(this.path);
      const last = records[records.length - 1];
      return last === undefined ? { seq: 0, hash: GENESIS_HASH } : { seq: last.seq, hash: last.hash };
    }
  }

  /**
   * Bring `this.records` in line with `diskHead` when the cache is behind
   * (another process wrote since this instance last loaded). A full reload
   * only when actually needed keeps the common single-writer case cheap,
   * and — unlike an unconditional reload after every write — never makes a
   * write re-parse the log purely because IT just grew it.
   */
  private catchUpTo(diskHead: ChainHead): void {
    const cached = this.cachedHead();
    if (cached.seq !== diskHead.seq || cached.hash !== diskHead.hash) {
      this.records = loadJsonlFile<ChainRecord>(this.path);
      this.recordsLoadedSize = sizeOf(this.path);
    }
  }

  head(): ChainHead {
    this.syncRecords();
    return this.cachedHead();
  }

  append(records: ChainRecord[]): void {
    if (records.length === 0) return;
    this.withLock(() => {
      repairTornTail(this.path);
      const diskHead = this.readHeadFromDisk();
      this.catchUpTo(diskHead);
      let head = diskHead;
      for (const record of records) {
        validateExtendsHead(head, record);
        head = { seq: record.seq, hash: record.hash };
      }
      const chunk = records.map((record) => JSON.stringify(record)).join('\n') + '\n';
      appendFileSync(this.path, chunk);
      this.records.push(...records);
      this.recordsLoadedSize = sizeOf(this.path);
    });
  }

  /**
   * Seal events into chain records under the lock, with the head read
   * inside it — safe when other `mcp-recorder record` processes are writing
   * the same log at the same time.
   */
  appendEvents(events: AnyEvent[]): ChainRecord[] {
    if (events.length === 0) return [];
    return this.withLock(() => {
      repairTornTail(this.path);
      const diskHead = this.readHeadFromDisk();
      this.catchUpTo(diskHead);
      let head = diskHead;
      const sealed: ChainRecord[] = [];
      for (const event of events) {
        const record = makeRecord(head, event);
        sealed.push(record);
        head = { seq: record.seq, hash: record.hash };
      }
      const chunk = sealed.map((record) => JSON.stringify(record)).join('\n') + '\n';
      appendFileSync(this.path, chunk);
      this.records.push(...sealed);
      this.recordsLoadedSize = sizeOf(this.path);
      return sealed;
    });
  }

  addSignature(sig: HeadSignature): void {
    this.withLock(() => {
      appendFileSync(this.sigsPath, JSON.stringify(sig) + '\n');
    });
  }

  latestSignature(): HeadSignature | null {
    this.syncSigs();
    return this.sigs.length > 0 ? this.sigs[this.sigs.length - 1]! : null;
  }

  signatures(): HeadSignature[] {
    this.syncSigs();
    return [...this.sigs];
  }

  *iterate(opts: IterateOpts = {}): Iterable<ChainRecord> {
    this.syncRecords();
    for (const record of this.records) {
      if (opts.fromSeq !== undefined && record.seq < opts.fromSeq) continue;
      if (opts.toSeq !== undefined && record.seq > opts.toSeq) continue;
      if (opts.sessionId !== undefined && record.event.session_id !== opts.sessionId) continue;
      yield record;
    }
  }

  count(): number {
    this.syncRecords();
    return this.records.length;
  }

  sessions(): SessionSummary[] {
    this.syncRecords();
    const byId = new Map<string, SessionSummary>();
    for (const record of this.records) {
      const ev = record.event;
      let summary = byId.get(ev.session_id);
      if (summary === undefined) {
        // First record of the session in seq order — same semantics as the
        // sqlite backend's "first event JSON of the session" subquery.
        summary = {
          session_id: ev.session_id,
          started_at: ev.timestamp,
          server_name: ev.server?.name ?? '',
          identity_fingerprint: ev.identity?.fingerprint ?? '',
          event_count: 0,
          tool_call_count: 0,
          error_count: 0,
        };
        byId.set(ev.session_id, summary);
      }
      if (ev.timestamp < summary.started_at) summary.started_at = ev.timestamp;
      summary.event_count += 1;
      if (ev.kind === 'tool_call') summary.tool_call_count += 1;
      if ((ev.kind === 'tool_call' || ev.kind === 'rpc') && ev.is_error) {
        summary.error_count += 1;
      }
      if (ev.kind === 'session_end') {
        if (summary.ended_at === undefined || ev.timestamp > summary.ended_at) {
          summary.ended_at = ev.timestamp;
        }
      }
    }
    return [...byId.values()];
  }

  close(): void {
    // Nothing to release: writes are flushed synchronously per append, and
    // the advisory lock is always released within the write that took it.
  }
}
