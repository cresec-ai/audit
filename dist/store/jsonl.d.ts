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
import type { AnyEvent, ChainRecord, HeadSignature } from '../schema/events.js';
import type { ChainHead, EvidenceStore, IterateOpts, SessionSummary } from '../types.js';
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
export declare const jsonlIoStats: {
    /** Bytes read via a full reload (`loadJsonlFile` — the whole file). */
    fullReloadBytes: number;
    fullReloadCalls: number;
    /** Bytes read via an incremental catch-up (`readJsonlFrom` — from an offset). */
    incrementalReadBytes: number;
    incrementalReadCalls: number;
};
export declare class JsonlStore implements EvidenceStore {
    readonly backend: "jsonl";
    /** Path of the record log (the store's primary file). */
    readonly path: string;
    private readonly sigsPath;
    private readonly lockDir;
    private records;
    private sigs;
    /** File size as of the last time `records`/`sigs` were loaded from disk. */
    private recordsLoadedSize;
    private sigsLoadedSize;
    constructor(dataDir: string);
    /**
     * Catch the record log up with disk iff another process has grown it,
     * reading only the bytes added since we last looked (see
     * `syncJsonlArray`) rather than re-parsing the whole file.
     */
    private syncRecords;
    /** Same as `syncRecords`, for the signatures log. */
    private syncSigs;
    private withLock;
    /** The head implied by the in-memory cache, with no disk access. */
    private cachedHead;
    /** The TRUE current head, read fresh from disk (cheap: tail-only read). */
    private readHeadFromDisk;
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
    private catchUpTo;
    head(): ChainHead;
    append(records: ChainRecord[]): void;
    /**
     * Seal events into chain records under the lock, with the head read
     * inside it — safe when other `mcp-recorder record` processes are writing
     * the same log at the same time.
     */
    appendEvents(events: AnyEvent[]): ChainRecord[];
    addSignature(sig: HeadSignature): void;
    latestSignature(): HeadSignature | null;
    signatures(): HeadSignature[];
    iterate(opts?: IterateOpts): Iterable<ChainRecord>;
    count(): number;
    /**
     * Per-session aggregate. Must stay in step with SqliteStore's SESSIONS_SQL
     * — test/store.test.ts runs the same fixtures through both backends; the
     * counting rules are spelled out on SessionSummary (src/types.ts).
     */
    sessions(): SessionSummary[];
    close(): void;
}
