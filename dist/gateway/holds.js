/**
 * Gateway hold store — `<dataDir>/holds/<approval_id>.json`.
 *
 * A `hold` policy action parks a tools/call until a human runs
 * `mcp-recorder approve|deny <id>` (or it times out / is cancelled). The
 * proxy and the CLI share nothing but the filesystem, so a hold is one
 * small JSON file, written atomically (temp + rename) and re-read by
 * polling: `fs.watch` is unreliable across platforms and the proxy must
 * never block on it.
 *
 * Invariants:
 *  - Hold files never contain readable payloads: `args` is the SCRUBBED
 *    tree (hashed unconditionally, like `tool_call.args`) and `args_hash`
 *    the canonical hash. This module stores what it is given; the caller
 *    scrubs.
 *  - The directory is created 0700 and files 0600 (best effort on Windows).
 *  - `waitForDecision()` never throws and never keeps the process alive:
 *    every timer is `unref()`'d, a corrupt or missing file is just "still
 *    pending" until the deadline.
 *  - Ids are uuid v4 (`randomUUID`) and are validated before they touch a
 *    path, so a CLI argument can never escape the holds directory.
 *  - The pending -> final transition happens EXACTLY ONCE, across processes.
 *    Reading the file and writing it back is not enough: two
 *    `mcp-recorder approve|deny` runs (or an approval racing the proxy's own
 *    timeout) both saw `pending`, both wrote, and the last rename won. Every
 *    writer therefore first creates `<id>.decided` with `openSync(..., 'wx')`
 *    — an atomic, Windows-safe create-if-absent — and only the process that
 *    wins that CAS writes the record: `decide()` throws `not_pending` when it
 *    loses, `finalize()` (timeout / cancelled / session_end) returns without
 *    touching a decision that got there first.
 *  - A `pending` hold whose `timeout_at` has passed is reported and treated
 *    as `timeout` even if nothing ever rewrote it: the proxy that parked it
 *    may have died, and a stale hold must not stay approvable forever.
 */
import { randomBytes, randomUUID } from 'node:crypto';
import { chmodSync, closeSync, mkdirSync, openSync, readdirSync, readFileSync, renameSync, rmSync, writeFileSync, } from 'node:fs';
import { userInfo } from 'node:os';
import { join } from 'node:path';
import { sleepSync } from '../util/sleep-sync.js';
export class HoldError extends Error {
    code;
    constructor(code, message) {
        super(message);
        this.name = 'HoldError';
        this.code = code;
    }
}
/** Default poll interval for `waitForDecision`. */
export const DEFAULT_POLL_MS = 200;
/** Name suffix of the exclusive sentinel that makes a decision a cross-process CAS. */
const SENTINEL_SUFFIX = '.decided';
const ID_RE = /^[A-Za-z0-9-]{1,64}$/;
const STATUSES = new Set([
    'pending',
    'approved',
    'denied',
    'timeout',
    'cancelled',
    'session_end',
]);
function isRecord(v) {
    return typeof v === 'object' && v !== null && !Array.isArray(v);
}
/** Structural check of a parsed hold file; undefined when it is not one. */
function asHoldRecord(v) {
    if (!isRecord(v))
        return undefined;
    if (v['version'] !== 1)
        return undefined;
    const str = (k) => typeof v[k] === 'string';
    if (!str('approval_id') || !str('created_at') || !str('session_id') || !str('server'))
        return undefined;
    if (!str('tool') || !str('args_hash') || !str('timeout_at') || !str('status'))
        return undefined;
    if (!STATUSES.has(v['status']))
        return undefined;
    if (!('args' in v))
        return undefined;
    return v;
}
/**
 * The record as it should be READ: a `pending` hold whose `timeout_at` has
 * passed is a `timeout`, whoever (if anyone) is still around to write that
 * down. An unparseable `timeout_at` is left alone — the clock is the only
 * thing that could be wrong, and a hold is never silently invalidated by it.
 */
function withExpiry(rec, now) {
    if (rec.status !== 'pending')
        return rec;
    const deadline = Date.parse(rec.timeout_at);
    if (Number.isNaN(deadline) || deadline > now)
        return rec;
    return { ...rec, status: 'timeout' };
}
/**
 * Rename errors Windows reports while ANOTHER process momentarily has the
 * target open: Node opens files without FILE_SHARE_DELETE there, so a
 * rename-over fails with EPERM (sometimes EACCES/EBUSY) for exactly as long
 * as a concurrent `readFileSync` of the record is in flight — the proxy
 * polling its hold, `mcp-recorder holds` listing, or the loser of a decide()
 * race reading the status it lost to. Readers hold the file for
 * microseconds, so a short bounded retry is the whole fix. POSIX never
 * returns these for a rename inside our own 0700 directory, so a genuine
 * permission problem still surfaces — after the budget, unchanged.
 */
const TRANSIENT_RENAME_CODES = new Set(['EPERM', 'EACCES', 'EBUSY']);
/** Total wall-clock budget for {@link renameRetrying} before the error propagates. */
export const RENAME_RETRY_BUDGET_MS = 1_000;
const REAL_RENAME_DEPS = { rename: renameSync, sleep: sleepSync, now: Date.now };
/**
 * `renameSync(from, to)` that retries the transient Windows sharing errors
 * above with exponential backoff (2, 4, 8, … 50 ms) for at most
 * {@link RENAME_RETRY_BUDGET_MS}. Every other error, and a transient one
 * that outlives the budget, is thrown unchanged.
 */
export function renameRetrying(from, to, deps = REAL_RENAME_DEPS) {
    const deadline = deps.now() + RENAME_RETRY_BUDGET_MS;
    let delay = 2;
    for (;;) {
        try {
            deps.rename(from, to);
            return;
        }
        catch (err) {
            const code = err.code;
            if (code === undefined || !TRANSIENT_RENAME_CODES.has(code) || deps.now() >= deadline)
                throw err;
            deps.sleep(delay);
            delay = Math.min(delay * 2, 50);
        }
    }
}
/** Atomic 0600 write: temp file in the same directory, then rename (Windows-safe, see above). */
function writeFileAtomic0600(path, content) {
    const tmp = `${path}.tmp-${randomBytes(6).toString('hex')}`;
    try {
        writeFileSync(tmp, content, { encoding: 'utf8', mode: 0o600 });
        renameRetrying(tmp, path);
    }
    catch (err) {
        rmSync(tmp, { force: true });
        throw err;
    }
}
function bestEffortUser() {
    try {
        const name = userInfo().username;
        return name === '' ? undefined : name;
    }
    catch {
        return undefined;
    }
}
export class HoldStore {
    /** `<dataDir>/holds` */
    dir;
    constructor(dataDir) {
        this.dir = join(dataDir, 'holds');
    }
    pathOf(id, suffix = '.json') {
        if (!ID_RE.test(id))
            throw new HoldError('invalid_id', `invalid hold id: ${JSON.stringify(id)}`);
        return join(this.dir, `${id}${suffix}`);
    }
    /**
     * Win the pending -> final transition, atomically and across processes.
     * `wx` fails with EEXIST when the file is already there — the one syscall
     * POSIX and Windows both make exclusive — so exactly one caller can ever
     * see `true` for a given hold.
     */
    claim(id) {
        this.ensureDir();
        let fd;
        try {
            fd = openSync(this.pathOf(id, SENTINEL_SUFFIX), 'wx', 0o600);
        }
        catch (err) {
            if (err.code === 'EEXIST')
                return false;
            throw err;
        }
        try {
            closeSync(fd);
        }
        catch {
            /* the file exists; that is all the claim needs */
        }
        return true;
    }
    /** Give a claim back when the record it was taken for could not be written. */
    releaseClaim(id) {
        try {
            rmSync(this.pathOf(id, SENTINEL_SUFFIX), { force: true });
        }
        catch {
            /* best effort */
        }
    }
    ensureDir() {
        mkdirSync(this.dir, { recursive: true, mode: 0o700 });
    }
    write(rec) {
        this.ensureDir();
        writeFileAtomic0600(this.pathOf(rec.approval_id), JSON.stringify(rec, null, 2) + '\n');
        try {
            chmodSync(this.pathOf(rec.approval_id), 0o600);
        }
        catch {
            /* best effort (Windows) */
        }
    }
    /** Write a new pending hold. Throws on I/O failure (caller denies: "hold unavailable"). */
    create(input) {
        const rec = {
            version: 1,
            approval_id: input.approval_id ?? randomUUID(),
            created_at: input.created_at ?? new Date().toISOString(),
            session_id: input.session_id,
            server: input.server,
            tool: input.tool,
            args: input.args,
            args_hash: input.args_hash,
            status: 'pending',
            timeout_at: input.timeout_at,
        };
        if (input.rule_id !== undefined)
            rec.rule_id = input.rule_id;
        if (input.reason !== undefined)
            rec.reason = input.reason;
        this.write(rec);
        return rec;
    }
    /** The record, or undefined when missing, unreadable, corrupt or oddly shaped. Never throws. */
    read(id) {
        try {
            const raw = readFileSync(this.pathOf(id), 'utf8');
            return asHoldRecord(JSON.parse(raw));
        }
        catch {
            return undefined;
        }
    }
    /** Ids of every well-formed hold file name in the directory (unsorted). */
    ids() {
        let names;
        try {
            names = readdirSync(this.dir);
        }
        catch {
            return [];
        }
        const out = [];
        for (const n of names) {
            if (!n.endsWith('.json'))
                continue;
            const id = n.slice(0, -'.json'.length);
            if (ID_RE.test(id))
                out.push(id);
        }
        return out;
    }
    /**
     * Pending holds (default) or every hold with `all`, oldest first. Corrupt
     * files are skipped. A hold still marked `pending` on disk whose
     * `timeout_at` has passed is reported as `timeout` (and is therefore NOT in
     * the default, actionable listing) — the proxy that would have written that
     * status may be long gone.
     */
    list(opts = {}) {
        const out = [];
        const now = Date.now();
        for (const id of this.ids()) {
            const raw = this.read(id);
            if (raw === undefined)
                continue;
            const rec = withExpiry(raw, now);
            if (opts.all === true || rec.status === 'pending')
                out.push(rec);
        }
        return out.sort((a, b) => a.created_at.localeCompare(b.created_at) || a.approval_id.localeCompare(b.approval_id));
    }
    /** Resolve a full id or a unique prefix of one against the files on disk. */
    resolveId(prefix) {
        if (typeof prefix !== 'string' || prefix === '')
            return { ok: false, reason: 'not_found' };
        const ids = this.ids();
        if (ids.includes(prefix))
            return { ok: true, id: prefix };
        const matches = ids.filter((id) => id.startsWith(prefix));
        if (matches.length === 1)
            return { ok: true, id: matches[0] };
        return { ok: false, reason: matches.length === 0 ? 'not_found' : 'ambiguous' };
    }
    /**
     * Approve or deny a PENDING hold (the CLI path). Throws HoldError
     * otherwise — including when another process (a second `approve`, or the
     * proxy's own timeout) won the transition between the read and the write:
     * the sentinel makes that race a clean `not_pending`, never two "success"
     * lines for one hold.
     */
    decide(id, status, by) {
        const rec = this.read(id);
        if (rec === undefined)
            throw new HoldError('not_found', `hold not found: ${id}`);
        const current = withExpiry(rec, Date.now());
        if (current.status !== 'pending') {
            throw new HoldError('not_pending', `hold ${id} is not pending (status: ${current.status})`);
        }
        if (!this.claim(id)) {
            throw new HoldError('not_pending', `hold ${id} is not pending (another process decided it first)`);
        }
        const decided = { ...rec, status, decided_at: new Date().toISOString() };
        const who = by ?? bestEffortUser();
        if (who !== undefined)
            decided.decided_by = who;
        try {
            this.write(decided);
        }
        catch (err) {
            this.releaseClaim(id); // nothing was decided after all: let the next writer try
            throw err;
        }
        return decided;
    }
    /**
     * Record the final status of a hold the proxy stopped waiting on
     * (timeout / cancelled / session_end, or an approval it acted on). Best
     * effort: a missing or unreadable file, or an I/O failure, is ignored —
     * this runs on the proxy's fail-open path.
     *
     * It takes the same sentinel as `decide()`: a human decision that got there
     * first is NEVER overwritten (the call simply returns, leaving the approver,
     * their timestamp and the status a concurrent `waitForDecision` is about to
     * read), and a timeout that got there first cannot be undone by a late
     * approval either.
     */
    finalize(id, status) {
        try {
            const rec = this.read(id);
            if (rec === undefined)
                return;
            if (!this.claim(id))
                return; // somebody already settled this hold
            const final = { ...rec, status };
            if (final.decided_at === undefined)
                final.decided_at = new Date().toISOString();
            this.write(final);
        }
        catch {
            /* fail-open */
        }
    }
    /**
     * Poll the hold file until it is approved/denied, the deadline passes, or
     * `signal` aborts. Timers are unref()'d; never rejects.
     */
    waitForDecision(id, opts) {
        const pollMs = Math.max(1, opts.pollMs ?? DEFAULT_POLL_MS);
        const timeoutMs = Math.max(0, opts.timeoutMs);
        const signal = opts.signal;
        return new Promise((resolve) => {
            const start = Date.now();
            let timer;
            let done = false;
            let last;
            const finish = (status, record) => {
                if (done)
                    return;
                done = true;
                if (timer !== undefined)
                    clearTimeout(timer);
                signal?.removeEventListener('abort', onAbort);
                const out = { status, waitedMs: Date.now() - start };
                if (record !== undefined)
                    out.record = record;
                resolve(out);
            };
            const onAbort = () => finish('cancelled', last);
            if (signal?.aborted === true) {
                finish('cancelled');
                return;
            }
            signal?.addEventListener('abort', onAbort, { once: true });
            const tick = () => {
                if (done)
                    return;
                const rec = this.read(id);
                if (rec !== undefined)
                    last = rec;
                if (rec !== undefined && (rec.status === 'approved' || rec.status === 'denied')) {
                    finish(rec.status, rec);
                    return;
                }
                const elapsed = Date.now() - start;
                if (elapsed >= timeoutMs) {
                    finish('timeout', last);
                    return;
                }
                timer = setTimeout(tick, Math.min(pollMs, timeoutMs - elapsed));
                timer.unref();
            };
            tick();
        });
    }
}
//# sourceMappingURL=holds.js.map