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
 * loaded it, and — since the log is append-only — reads and parses just the
 * bytes another process added since our last read, rather than re-parsing
 * the whole file (see `syncJsonlArray` / `readJsonlFrom` below). A shrink or
 * a replace/rotate falls back to a full reload, same as before this file
 * kept a byte offset at all.
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
import { sleepSync } from '../util/sleep-sync.js';

/**
 * Test-only I/O counters (bytes and call counts), so a test can prove a
 * sync did an incremental catch-up rather than a full reload without
 * intercepting `node:fs` itself: spying on a *named* import's call site
 * (`import { readFileSync } from 'node:fs'` used bare, as this file does)
 * isn't reliably interceptable via `vi.spyOn` under every ESM/bundler
 * transform — some bind the local name once at import time rather than
 * reading the exporting module live. Nothing in this module reads these;
 * they are not part of the `EvidenceStore` contract.
 */
export const jsonlIoStats = {
  /** Bytes read via a full reload (`loadJsonlFile` — the whole file). */
  fullReloadBytes: 0,
  fullReloadCalls: 0,
  /** Bytes read via an incremental catch-up (`readJsonlFrom` — from an offset). */
  incrementalReadBytes: 0,
  incrementalReadCalls: 0,
};

/**
 * Read a JSONL file into objects. A trailing partial line (e.g. from a crash
 * mid-write) is tolerated with a stderr warning; corruption anywhere else is
 * an error — silent data loss in an evidence store is never acceptable.
 */
function loadJsonlFile<T>(path: string): T[] {
  if (!existsSync(path)) return [];
  const text = readFileSync(path, 'utf8');
  jsonlIoStats.fullReloadBytes += Buffer.byteLength(text, 'utf8');
  jsonlIoStats.fullReloadCalls += 1;
  const lines = text.split('\n');
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

/**
 * True when `offset` is the start of a line in `path`: either 0, or the
 * byte immediately before it is `\n`. This is how a genuine append (the
 * file still begins with exactly what we last read, merely extended) is
 * told apart from a replace/rotate that happens to leave the file no
 * smaller — where reading on from the old offset would parse garbage.
 * Cheap: a single 1-byte read, and only ever called once the size has
 * already been seen to change.
 */
function isLineStart(path: string, offset: number): boolean {
  if (offset <= 0) return true;
  let fd: number;
  try {
    fd = openSync(path, 'r');
  } catch {
    return false;
  }
  try {
    const buf = Buffer.alloc(1);
    const n = readSync(fd, buf, 0, 1, offset - 1);
    return n === 1 && buf[0] === 0x0a;
  } finally {
    closeSync(fd);
  }
}

/**
 * Parse only the *complete* lines found in `path` at or after `fromOffset`
 * — the incremental counterpart to `loadJsonlFile`, used to catch a cached
 * copy up to disk without re-reading bytes already parsed. Byte offsets
 * (not string indices) are used throughout so a record containing
 * multi-byte UTF-8 text is never split mid-character: `\n` (0x0a) is a
 * single-byte code point that can never occur inside a multi-byte UTF-8
 * sequence, so scanning a raw `Buffer` for it is always safe.
 *
 * A trailing run of bytes with no closing newline yet is left unconsumed
 * (excluded from `nextOffset`) rather than guessed at. Unlike
 * `loadJsonlFile`'s tolerance for a torn final line, this is not even an
 * error case here: a reader that does not hold the lock can simply observe
 * another process's write still landing, and pick the bytes up on its next
 * sync once the newline arrives. A `JSON.parse` failure on a line that DOES
 * have its closing newline is real corruption (mirrors `loadJsonlFile`'s
 * handling of a non-trailing bad line) and throws.
 */
function readJsonlFrom<T>(path: string, fromOffset: number): { items: T[]; nextOffset: number } {
  let fd: number;
  try {
    fd = openSync(path, 'r');
  } catch {
    return { items: [], nextOffset: fromOffset };
  }
  try {
    const size = fstatSync(fd).size;
    if (size <= fromOffset) return { items: [], nextOffset: fromOffset };
    const length = size - fromOffset;
    const buf = Buffer.alloc(length);
    const n = readSync(fd, buf, 0, length, fromOffset);
    const bytes = n === length ? buf : buf.subarray(0, n);
    jsonlIoStats.incrementalReadBytes += bytes.length;
    jsonlIoStats.incrementalReadCalls += 1;
    const items: T[] = [];
    let lineStart = 0;
    let consumed = 0;
    for (let i = 0; i < bytes.length; i++) {
      if (bytes[i] !== 0x0a) continue;
      const line = bytes.subarray(lineStart, i).toString('utf8').trim();
      lineStart = i + 1;
      consumed = lineStart;
      if (line === '') continue;
      try {
        items.push(JSON.parse(line) as T);
      } catch (err) {
        throw new Error(
          `mcp-recorder: corrupt JSONL record at byte offset ${fromOffset + lineStart - line.length - 1} in ${path}: ${(err as Error).message}`,
        );
      }
    }
    return { items, nextOffset: fromOffset + consumed };
  } finally {
    closeSync(fd);
  }
}

/**
 * Bring an in-memory JSONL array in line with what is on disk right now.
 * When the file has simply grown past `loadedSize` — and the boundary check
 * above confirms it is still the same file, merely extended — only the new
 * bytes are read and parsed: the expensive full re-parse this scheme exists
 * to avoid, on what is normally a cross-process catch-up done under the
 * advisory lock on every append. A shrink, or a grow that fails that
 * boundary check (replaced/rotated from under us), falls back to a full
 * reload exactly as this store always has.
 */
function syncJsonlArray<T>(
  path: string,
  current: T[],
  loadedSize: number,
): { items: T[]; loadedSize: number } {
  const size = sizeOf(path);
  if (size === loadedSize) return { items: current, loadedSize };
  if (size < loadedSize || !isLineStart(path, loadedSize)) {
    return { items: loadJsonlFile<T>(path), loadedSize: sizeOf(path) };
  }
  const { items: added, nextOffset } = readJsonlFrom<T>(path, loadedSize);
  return {
    items: added.length > 0 ? current.concat(added) : current,
    loadedSize: nextOffset,
  };
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
 * generous, and it is short enough that a recorder's retry run (~6s of
 * asynchronous backoff plus a short synchronous lock wait per attempt — see
 * RETRY_DELAYS_MS in src/capture/recorder.ts) reaches the reclaim instead
 * of dropping the batch.
 */
const STALE_LOCK_MS = 5_000;

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

  /**
   * Catch the record log up with disk iff another process has grown it,
   * reading only the bytes added since we last looked (see
   * `syncJsonlArray`) rather than re-parsing the whole file.
   */
  private syncRecords(): void {
    const { items, loadedSize } = syncJsonlArray(this.path, this.records, this.recordsLoadedSize);
    this.records = items;
    this.recordsLoadedSize = loadedSize;
  }

  /** Same as `syncRecords`, for the signatures log. */
  private syncSigs(): void {
    const { items, loadedSize } = syncJsonlArray(this.sigsPath, this.sigs, this.sigsLoadedSize);
    this.sigs = items;
    this.sigsLoadedSize = loadedSize;
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
   * (another process wrote since this instance last loaded). Checking the
   * head first — rather than syncing unconditionally — keeps the common
   * single-writer case cheap: a write never re-parses the log purely
   * because IT just grew it. When a catch-up IS needed, `syncRecords`
   * reads only the bytes another process added (not the whole log) unless
   * the file was shrunk or replaced out from under us, in which case it
   * falls back to a full reload on its own. The head is re-checked
   * afterwards as a safety net: if it still doesn't match `diskHead` (e.g.
   * a stat raced a concurrent write elsewhere), a full reload is forced
   * rather than validating new appends against a chain we're not sure is
   * current.
   */
  private catchUpTo(diskHead: ChainHead): void {
    const cached = this.cachedHead();
    if (cached.seq === diskHead.seq && cached.hash === diskHead.hash) return;
    this.syncRecords();
    const after = this.cachedHead();
    if (after.seq !== diskHead.seq || after.hash !== diskHead.hash) {
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

  /**
   * Per-session aggregate. Must stay in step with SqliteStore's SESSIONS_SQL
   * — test/store.test.ts runs the same fixtures through both backends; the
   * counting rules are spelled out on SessionSummary (src/types.ts).
   */
  sessions(): SessionSummary[] {
    this.syncRecords();
    // policy_decision_count is optional on the contract but always set
    // here, so the accumulator spells it out as required — `+= 1` on an
    // optional number would not type-check.
    type Accumulator = SessionSummary & { policy_decision_count: number };
    const byId = new Map<string, { summary: Accumulator; servers: Set<string> }>();
    for (const record of this.records) {
      const ev = record.event;
      let entry = byId.get(ev.session_id);
      if (entry === undefined) {
        // First record of the session in seq order — same semantics as the
        // sqlite backend's "first event JSON of the session" subquery.
        entry = {
          summary: {
            session_id: ev.session_id,
            started_at: ev.timestamp,
            server_name: ev.server?.name ?? '',
            identity_fingerprint: ev.identity?.fingerprint ?? '',
            event_count: 0,
            tool_call_count: 0,
            error_count: 0,
            server_count: 0,
            policy_decision_count: 0,
          },
          servers: new Set<string>(),
        };
        byId.set(ev.session_id, entry);
      }
      const { summary, servers } = entry;
      if (ev.timestamp < summary.started_at) summary.started_at = ev.timestamp;
      summary.event_count += 1;
      // One per CALL: a proxy event (no phase) or a hook 'pre' event; the
      // hook 'post' twin (same request_id) is the same call, and a lone pre
      // (the call never completed) still counts once. An explicit
      // `phase: null` reads as "no phase", exactly as SQL's `IS NULL` does.
      if (
        ev.kind === 'tool_call' &&
        (ev.phase === undefined || ev.phase === null || ev.phase === 'pre')
      ) {
        summary.tool_call_count += 1;
      }
      // is_error on any phase: a failed hook call carries exactly one such
      // event (a denied pre, or a failing post). A post whose pre was never
      // recorded is an error here but not a call above.
      if ((ev.kind === 'tool_call' || ev.kind === 'rpc') && ev.is_error === true) {
        summary.error_count += 1;
      }
      // Distinct servers actually CALLED: tool_call events only, so a proxy
      // session recorded without --name (argv basename before the initialize
      // handshake, learned serverInfo.name after) reads 1, not 2, and a hook
      // session does not count its own claude-code session-level events.
      if (ev.kind === 'tool_call' && typeof ev.server?.name === 'string') {
        servers.add(ev.server.name);
        summary.server_count = servers.size;
      }
      // Gateway mode's enforcement: one per deny, one per resolved hold
      // (an approved hold included). Counted off the kind alone, like
      // event_count — the synthetic tool_call that carries a refusal back
      // to the client is counted as a call and an error above, not here,
      // and a policy_decision with missing or off-shape decision/outcome
      // fields still counts because nothing below the kind is read.
      // A refused `tools/call` NOTIFICATION is a decision with no request
      // id, so it carries its outcome on the notification event rather than
      // as a `policy_decision`. It counts here all the same, or the column
      // reports 0 for a session where enforcement happened. Must stay in
      // step with the sqlite backend's SQL.
      if (ev.kind === 'notification' && (ev as { gateway?: { decision?: string } }).gateway?.decision !== undefined) {
        summary.policy_decision_count += 1;
      }
      if (ev.kind === 'policy_decision') {
        summary.policy_decision_count += 1;
      }
      if (ev.kind === 'session_end') {
        if (summary.ended_at === undefined || ev.timestamp > summary.ended_at) {
          summary.ended_at = ev.timestamp;
        }
      }
    }
    return [...byId.values()].map((entry) => entry.summary);
  }

  close(): void {
    // Nothing to release: writes are flushed synchronously per append, and
    // the advisory lock is always released within the write that took it.
  }
}
