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
 */

import { randomBytes, randomUUID } from 'node:crypto';
import {
  chmodSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  renameSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { userInfo } from 'node:os';
import { join } from 'node:path';

export type HoldStatus = 'pending' | 'approved' | 'denied' | 'timeout' | 'cancelled' | 'session_end';

export interface HoldRecord {
  version: 1;
  approval_id: string;
  created_at: string;
  session_id: string;
  server: string;
  tool: string;
  /** Scrubbed tree — never readable. */
  args: unknown;
  args_hash: string;
  rule_id?: string;
  reason?: string;
  status: HoldStatus;
  timeout_at: string;
  decided_at?: string;
  decided_by?: string;
}

/** What `create()` needs; the store fills in version/status/created_at and
 * (when absent) the approval id. */
export type HoldCreateInput = Omit<HoldRecord, 'version' | 'status' | 'created_at' | 'approval_id'> & {
  created_at?: string;
  approval_id?: string;
};

export type HoldDecision = 'approved' | 'denied';

export interface HoldWaitOptions {
  timeoutMs: number;
  /** Poll interval; default 200 ms. */
  pollMs?: number;
  /** Aborting resolves `cancelled` immediately. */
  signal?: AbortSignal;
}

export interface HoldWaitResult {
  status: 'approved' | 'denied' | 'timeout' | 'cancelled';
  /** The last record read, when one could be read. */
  record?: HoldRecord;
  waitedMs: number;
}

export type HoldErrorCode = 'not_found' | 'not_pending' | 'invalid_id';

export class HoldError extends Error {
  readonly code: HoldErrorCode;
  constructor(code: HoldErrorCode, message: string) {
    super(message);
    this.name = 'HoldError';
    this.code = code;
  }
}

/** Default poll interval for `waitForDecision`. */
export const DEFAULT_POLL_MS = 200;
const ID_RE = /^[A-Za-z0-9-]{1,64}$/;
const STATUSES: ReadonlySet<string> = new Set<HoldStatus>([
  'pending',
  'approved',
  'denied',
  'timeout',
  'cancelled',
  'session_end',
]);

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/** Structural check of a parsed hold file; undefined when it is not one. */
function asHoldRecord(v: unknown): HoldRecord | undefined {
  if (!isRecord(v)) return undefined;
  if (v['version'] !== 1) return undefined;
  const str = (k: string): boolean => typeof v[k] === 'string';
  if (!str('approval_id') || !str('created_at') || !str('session_id') || !str('server')) return undefined;
  if (!str('tool') || !str('args_hash') || !str('timeout_at') || !str('status')) return undefined;
  if (!STATUSES.has(v['status'] as string)) return undefined;
  if (!('args' in v)) return undefined;
  return v as unknown as HoldRecord;
}

/** Atomic 0600 write: temp file in the same directory, then rename. */
function writeFileAtomic0600(path: string, content: string): void {
  const tmp = `${path}.tmp-${randomBytes(6).toString('hex')}`;
  try {
    writeFileSync(tmp, content, { encoding: 'utf8', mode: 0o600 });
    renameSync(tmp, path);
  } catch (err) {
    rmSync(tmp, { force: true });
    throw err;
  }
}

function bestEffortUser(): string | undefined {
  try {
    const name = userInfo().username;
    return name === '' ? undefined : name;
  } catch {
    return undefined;
  }
}

export class HoldStore {
  /** `<dataDir>/holds` */
  readonly dir: string;

  constructor(dataDir: string) {
    this.dir = join(dataDir, 'holds');
  }

  private pathOf(id: string): string {
    if (!ID_RE.test(id)) throw new HoldError('invalid_id', `invalid hold id: ${JSON.stringify(id)}`);
    return join(this.dir, `${id}.json`);
  }

  private ensureDir(): void {
    mkdirSync(this.dir, { recursive: true, mode: 0o700 });
  }

  private write(rec: HoldRecord): void {
    this.ensureDir();
    writeFileAtomic0600(this.pathOf(rec.approval_id), JSON.stringify(rec, null, 2) + '\n');
    try {
      chmodSync(this.pathOf(rec.approval_id), 0o600);
    } catch {
      /* best effort (Windows) */
    }
  }

  /** Write a new pending hold. Throws on I/O failure (caller denies: "hold unavailable"). */
  create(input: HoldCreateInput): HoldRecord {
    const rec: HoldRecord = {
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
    if (input.rule_id !== undefined) rec.rule_id = input.rule_id;
    if (input.reason !== undefined) rec.reason = input.reason;
    this.write(rec);
    return rec;
  }

  /** The record, or undefined when missing, unreadable, corrupt or oddly shaped. Never throws. */
  read(id: string): HoldRecord | undefined {
    try {
      const raw = readFileSync(this.pathOf(id), 'utf8');
      return asHoldRecord(JSON.parse(raw));
    } catch {
      return undefined;
    }
  }

  /** Ids of every well-formed hold file name in the directory (unsorted). */
  private ids(): string[] {
    let names: string[];
    try {
      names = readdirSync(this.dir);
    } catch {
      return [];
    }
    const out: string[] = [];
    for (const n of names) {
      if (!n.endsWith('.json')) continue;
      const id = n.slice(0, -'.json'.length);
      if (ID_RE.test(id)) out.push(id);
    }
    return out;
  }

  /** Pending holds (default) or every hold with `all`, oldest first. Corrupt files are skipped. */
  list(opts: { all?: boolean } = {}): HoldRecord[] {
    const out: HoldRecord[] = [];
    for (const id of this.ids()) {
      const rec = this.read(id);
      if (rec === undefined) continue;
      if (opts.all === true || rec.status === 'pending') out.push(rec);
    }
    return out.sort(
      (a, b) => a.created_at.localeCompare(b.created_at) || a.approval_id.localeCompare(b.approval_id),
    );
  }

  /** Resolve a full id or a unique prefix of one against the files on disk. */
  resolveId(prefix: string): { ok: true; id: string } | { ok: false; reason: 'not_found' | 'ambiguous' } {
    if (typeof prefix !== 'string' || prefix === '') return { ok: false, reason: 'not_found' };
    const ids = this.ids();
    if (ids.includes(prefix)) return { ok: true, id: prefix };
    const matches = ids.filter((id) => id.startsWith(prefix));
    if (matches.length === 1) return { ok: true, id: matches[0]! };
    return { ok: false, reason: matches.length === 0 ? 'not_found' : 'ambiguous' };
  }

  /** Approve or deny a PENDING hold (the CLI path). Throws HoldError otherwise. */
  decide(id: string, status: HoldDecision, by?: string): HoldRecord {
    const rec = this.read(id);
    if (rec === undefined) throw new HoldError('not_found', `hold not found: ${id}`);
    if (rec.status !== 'pending') {
      throw new HoldError('not_pending', `hold ${id} is not pending (status: ${rec.status})`);
    }
    const decided: HoldRecord = { ...rec, status, decided_at: new Date().toISOString() };
    const who = by ?? bestEffortUser();
    if (who !== undefined) decided.decided_by = who;
    this.write(decided);
    return decided;
  }

  /**
   * Record the final status of a hold the proxy stopped waiting on
   * (timeout / cancelled / session_end, or an approval it acted on). Best
   * effort: a missing or unreadable file, or an I/O failure, is ignored —
   * this runs on the proxy's fail-open path.
   */
  finalize(id: string, status: HoldStatus): void {
    try {
      const rec = this.read(id);
      if (rec === undefined) return;
      const final: HoldRecord = { ...rec, status };
      if (final.decided_at === undefined) final.decided_at = new Date().toISOString();
      this.write(final);
    } catch {
      /* fail-open */
    }
  }

  /**
   * Poll the hold file until it is approved/denied, the deadline passes, or
   * `signal` aborts. Timers are unref()'d; never rejects.
   */
  waitForDecision(id: string, opts: HoldWaitOptions): Promise<HoldWaitResult> {
    const pollMs = Math.max(1, opts.pollMs ?? DEFAULT_POLL_MS);
    const timeoutMs = Math.max(0, opts.timeoutMs);
    const signal = opts.signal;
    return new Promise<HoldWaitResult>((resolve) => {
      const start = Date.now();
      let timer: NodeJS.Timeout | undefined;
      let done = false;
      let last: HoldRecord | undefined;

      const finish = (status: HoldWaitResult['status'], record?: HoldRecord): void => {
        if (done) return;
        done = true;
        if (timer !== undefined) clearTimeout(timer);
        signal?.removeEventListener('abort', onAbort);
        const out: HoldWaitResult = { status, waitedMs: Date.now() - start };
        if (record !== undefined) out.record = record;
        resolve(out);
      };
      const onAbort = (): void => finish('cancelled', last);

      if (signal?.aborted === true) {
        finish('cancelled');
        return;
      }
      signal?.addEventListener('abort', onAbort, { once: true });

      const tick = (): void => {
        if (done) return;
        const rec = this.read(id);
        if (rec !== undefined) last = rec;
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
