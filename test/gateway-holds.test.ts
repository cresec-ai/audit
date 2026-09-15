import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { existsSync, mkdtempSync, openSync, closeSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { DEFAULT_POLL_MS, HoldError, HoldStore, type HoldCreateInput } from '../src/gateway/index.js';
import { RENAME_RETRY_BUDGET_MS, renameRetrying } from '../src/gateway/holds.js';
import { spawnTsx } from './helpers/tsx.js';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
/** The module under test, as a specifier a spawned child can import. */
const HOLDS_MODULE = pathToFileURL(join(ROOT, 'src', 'gateway', 'holds.ts')).href;
/** `<id>.decided`: the exclusive sentinel that makes a decision a cross-process CAS. */
const sentinel = (store: HoldStore, id: string): string => join(store.dir, `${id}.decided`);

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

function input(over: Partial<HoldCreateInput> = {}): HoldCreateInput {
  return {
    session_id: 'sess-1',
    server: 'corp-notes',
    tool: 'http_post',
    args: { url: { redacted: true, ref: 'sha256:aa', len: 3 } },
    args_hash: 'sha256:bb',
    rule_id: 'no-exfil',
    reason: 'needs a human',
    timeout_at: new Date(Date.now() + 60_000).toISOString(),
    ...over,
  };
}

let dataDir: string;
let store: HoldStore;

beforeEach(() => {
  dataDir = mkdtempSync(join(tmpdir(), 'mcp-recorder-holds-'));
  store = new HoldStore(dataDir);
});

afterEach(() => {
  rmSync(dataDir, { recursive: true, force: true });
});

describe('HoldStore.create / read', () => {
  it('writes <dataDir>/holds/<uuid>.json with the full record', () => {
    expect(store.dir).toBe(join(dataDir, 'holds'));
    const rec = store.create(input());
    expect(rec.approval_id).toMatch(UUID_RE);
    expect(rec.version).toBe(1);
    expect(rec.status).toBe('pending');
    expect(Date.parse(rec.created_at)).not.toBeNaN();
    expect(rec).toMatchObject({ session_id: 'sess-1', server: 'corp-notes', tool: 'http_post', rule_id: 'no-exfil', reason: 'needs a human' });
    const path = join(store.dir, `${rec.approval_id}.json`);
    expect(existsSync(path)).toBe(true);
    expect(JSON.parse(readFileSync(path, 'utf8'))).toEqual(rec);
    expect(store.read(rec.approval_id)).toEqual(rec);
    // No temp files left behind.
    expect(readdirSync(store.dir)).toEqual([`${rec.approval_id}.json`]);
  });

  it('honours a caller-supplied created_at and approval_id and omits absent optionals', () => {
    const rec = store.create({ ...input({ rule_id: undefined, reason: undefined }), created_at: '2026-01-02T03:04:05.000Z', approval_id: 'custom-id-1' });
    expect(rec.created_at).toBe('2026-01-02T03:04:05.000Z');
    expect(rec.approval_id).toBe('custom-id-1');
    expect('rule_id' in rec).toBe(false);
    expect('reason' in rec).toBe(false);
  });

  it('generates distinct ids', () => {
    const ids = new Set(Array.from({ length: 5 }, () => store.create(input()).approval_id));
    expect(ids.size).toBe(5);
  });

  it('read returns undefined for missing, corrupt, wrong-shaped and path-escaping ids', () => {
    expect(store.read('does-not-exist')).toBeUndefined();
    store.create(input({ approval_id: 'seed' }));
    writeFileSync(join(store.dir, 'corrupt.json'), '{not json', 'utf8');
    expect(store.read('corrupt')).toBeUndefined();
    writeFileSync(join(store.dir, 'shape.json'), JSON.stringify({ version: 2, approval_id: 'shape' }), 'utf8');
    expect(store.read('shape')).toBeUndefined();
    writeFileSync(join(store.dir, 'status.json'), JSON.stringify({ ...store.read('seed'), approval_id: 'status', status: 'weird' }), 'utf8');
    expect(store.read('status')).toBeUndefined();
    expect(store.read('../seed')).toBeUndefined();
    expect(store.read('')).toBeUndefined();
  });

  it.runIf(process.platform !== 'win32')('creates the directory 0700 and files 0600', () => {
    const rec = store.create(input());
    expect(statSync(store.dir).mode & 0o777).toBe(0o700);
    expect(statSync(join(store.dir, `${rec.approval_id}.json`)).mode & 0o777).toBe(0o600);
    const decided = store.decide(rec.approval_id, 'approved', 'alice');
    expect(statSync(join(store.dir, `${decided.approval_id}.json`)).mode & 0o777).toBe(0o600);
  });
});

describe('HoldStore.list / resolveId', () => {
  it('lists pending only by default, all with { all: true }, oldest first, skipping corrupt files', () => {
    expect(store.list()).toEqual([]); // directory does not exist yet
    const a = store.create({ ...input(), created_at: '2026-01-01T00:00:00.000Z', approval_id: 'aaaa-1' });
    const b = store.create({ ...input(), created_at: '2026-01-01T00:00:01.000Z', approval_id: 'aaab-2' });
    const c = store.create({ ...input(), created_at: '2025-12-31T00:00:00.000Z', approval_id: 'bbbb-3' });
    store.decide(b.approval_id, 'denied', 'bob');
    writeFileSync(join(store.dir, 'junk.json'), 'nope', 'utf8');
    writeFileSync(join(store.dir, 'notes.txt'), '{}', 'utf8');
    expect(store.list().map((r) => r.approval_id)).toEqual([c.approval_id, a.approval_id]);
    expect(store.list({ all: true }).map((r) => r.approval_id)).toEqual([c.approval_id, a.approval_id, b.approval_id]);
    expect(store.list({ all: true }).find((r) => r.approval_id === b.approval_id)?.status).toBe('denied');
  });

  it('resolves exact ids, unique prefixes, and reports ambiguous / not_found', () => {
    expect(store.resolveId('aaaa')).toEqual({ ok: false, reason: 'not_found' });
    store.create({ ...input(), approval_id: 'aaaa-1' });
    store.create({ ...input(), approval_id: 'aaab-2' });
    store.create({ ...input(), approval_id: 'aaaa-1x' });
    expect(store.resolveId('aaaa-1')).toEqual({ ok: true, id: 'aaaa-1' }); // exact beats prefix
    expect(store.resolveId('aaaa-1x')).toEqual({ ok: true, id: 'aaaa-1x' });
    expect(store.resolveId('aaab')).toEqual({ ok: true, id: 'aaab-2' });
    expect(store.resolveId('aaa')).toEqual({ ok: false, reason: 'ambiguous' });
    expect(store.resolveId('zzz')).toEqual({ ok: false, reason: 'not_found' });
    expect(store.resolveId('')).toEqual({ ok: false, reason: 'not_found' });
  });
});

describe('HoldStore.decide / finalize', () => {
  it('approves a pending hold, stamping decided_at / decided_by, and persists it', () => {
    const rec = store.create(input());
    const before = Date.now();
    const decided = store.decide(rec.approval_id, 'approved', 'alice');
    expect(decided.status).toBe('approved');
    expect(decided.decided_by).toBe('alice');
    expect(Date.parse(decided.decided_at!)).toBeGreaterThanOrEqual(before - 1);
    expect(store.read(rec.approval_id)).toEqual(decided);
    expect(decided).toMatchObject({ approval_id: rec.approval_id, args: rec.args, args_hash: rec.args_hash });
  });

  it('denies with a best-effort OS user when `by` is omitted', () => {
    const rec = store.create(input());
    const decided = store.decide(rec.approval_id, 'denied');
    expect(decided.status).toBe('denied');
    if (decided.decided_by !== undefined) expect(decided.decided_by.length).toBeGreaterThan(0);
  });

  it('throws HoldError not_pending on a decided hold and not_found on a missing one', () => {
    const rec = store.create(input());
    store.decide(rec.approval_id, 'approved', 'alice');
    let err: unknown;
    try {
      store.decide(rec.approval_id, 'denied', 'bob');
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(HoldError);
    expect((err as HoldError).code).toBe('not_pending');
    expect(store.read(rec.approval_id)?.status).toBe('approved'); // unchanged
    expect(() => store.decide('missing', 'approved')).toThrow(HoldError);
    try {
      store.decide('missing', 'approved');
    } catch (e) {
      expect((e as HoldError).code).toBe('not_found');
    }
    try {
      store.decide('../escape', 'approved');
    } catch (e) {
      expect((e as HoldError).code).toBe('not_found');
    }
  });

  it('finalize rewrites the status and never throws', () => {
    const rec = store.create(input());
    store.finalize(rec.approval_id, 'timeout');
    const after = store.read(rec.approval_id)!;
    expect(after.status).toBe('timeout');
    expect(after.decided_at).toBeDefined();
    expect(store.list()).toEqual([]);
    expect(store.list({ all: true })).toHaveLength(1);
    expect(() => store.finalize('missing', 'session_end')).not.toThrow();
    expect(() => store.finalize('../x', 'session_end')).not.toThrow();
    // finalize after an approve keeps the approver's decided_at.
    const rec2 = store.create(input());
    const decided = store.decide(rec2.approval_id, 'approved', 'alice');
    store.finalize(rec2.approval_id, 'approved');
    expect(store.read(rec2.approval_id)).toEqual(decided);
  });
});

describe('HoldStore.waitForDecision', () => {
  it('resolves approved promptly after a concurrent decide', async () => {
    const rec = store.create(input());
    const t0 = Date.now();
    const wait = store.waitForDecision(rec.approval_id, { timeoutMs: 10_000, pollMs: 20 });
    setTimeout(() => store.decide(rec.approval_id, 'approved', 'alice'), 60);
    const res = await wait;
    expect(res.status).toBe('approved');
    expect(res.record?.decided_by).toBe('alice');
    expect(res.waitedMs).toBeGreaterThanOrEqual(50);
    expect(res.waitedMs).toBeLessThan(2_000);
    expect(Date.now() - t0).toBeLessThan(2_000); // timers do not hold us to the deadline
  });

  it('resolves denied', async () => {
    const rec = store.create(input());
    const wait = store.waitForDecision(rec.approval_id, { timeoutMs: 10_000, pollMs: 10 });
    store.decide(rec.approval_id, 'denied', 'bob');
    const res = await wait;
    expect(res.status).toBe('denied');
    expect(res.record?.status).toBe('denied');
  });

  it('returns immediately when already decided', async () => {
    const rec = store.create(input());
    store.decide(rec.approval_id, 'approved');
    const res = await store.waitForDecision(rec.approval_id, { timeoutMs: 10_000 });
    expect(res.status).toBe('approved');
    expect(res.waitedMs).toBeLessThan(500);
  });

  it('times out with the last-read record', async () => {
    const rec = store.create(input());
    const t0 = Date.now();
    const res = await store.waitForDecision(rec.approval_id, { timeoutMs: 150, pollMs: 20 });
    expect(res.status).toBe('timeout');
    expect(res.record?.approval_id).toBe(rec.approval_id);
    expect(res.record?.status).toBe('pending');
    expect(res.waitedMs).toBeGreaterThanOrEqual(140);
    expect(Date.now() - t0).toBeLessThan(2_000);
  });

  it('times out on a missing file without throwing', async () => {
    const res = await store.waitForDecision('never-written', { timeoutMs: 50, pollMs: 10 });
    expect(res.status).toBe('timeout');
    expect(res.record).toBeUndefined();
  });

  it('keeps polling through a corrupt file until it becomes readable', async () => {
    const rec = store.create(input());
    const path = join(store.dir, `${rec.approval_id}.json`);
    const good = readFileSync(path, 'utf8');
    writeFileSync(path, '{"half": ', 'utf8');
    const wait = store.waitForDecision(rec.approval_id, { timeoutMs: 10_000, pollMs: 10 });
    setTimeout(() => {
      writeFileSync(path, good, 'utf8');
      store.decide(rec.approval_id, 'approved', 'carol');
    }, 60);
    const res = await wait;
    expect(res.status).toBe('approved');
    expect(res.record?.decided_by).toBe('carol');
  });

  it('ignores non-terminal statuses until the deadline', async () => {
    const rec = store.create(input());
    store.finalize(rec.approval_id, 'cancelled');
    const res = await store.waitForDecision(rec.approval_id, { timeoutMs: 60, pollMs: 10 });
    expect(res.status).toBe('timeout');
    expect(res.record?.status).toBe('cancelled');
  });

  it('resolves cancelled on abort, and immediately when already aborted', async () => {
    const rec = store.create(input());
    const ac = new AbortController();
    const wait = store.waitForDecision(rec.approval_id, { timeoutMs: 10_000, pollMs: 10, signal: ac.signal });
    setTimeout(() => ac.abort(), 30);
    const res = await wait;
    expect(res.status).toBe('cancelled');
    expect(res.record?.status).toBe('pending');
    expect(res.waitedMs).toBeLessThan(2_000);

    const pre = new AbortController();
    pre.abort();
    const res2 = await store.waitForDecision(rec.approval_id, { timeoutMs: 10_000, signal: pre.signal });
    expect(res2.status).toBe('cancelled');
    expect(res2.waitedMs).toBeLessThan(100);
    // A late decide does not flip an already-settled wait.
    store.decide(rec.approval_id, 'approved');
    expect(res.status).toBe('cancelled');
  });

  it('uses unref()d timers so a pending wait never keeps the event loop alive', async () => {
    const rec = store.create(input());
    const seen: { unref: boolean }[] = [];
    const original = globalThis.setTimeout;
    const patched = ((fn: () => void, ms?: number) => {
      const t = original(fn, ms);
      const entry = { unref: false };
      seen.push(entry);
      const realUnref = t.unref.bind(t);
      t.unref = () => {
        entry.unref = true;
        return realUnref();
      };
      return t;
    }) as unknown as typeof setTimeout;
    globalThis.setTimeout = patched;
    try {
      const res = await store.waitForDecision(rec.approval_id, { timeoutMs: 80, pollMs: 10 });
      expect(res.status).toBe('timeout');
    } finally {
      globalThis.setTimeout = original;
    }
    expect(seen.length).toBeGreaterThan(1);
    expect(seen.every((e) => e.unref)).toBe(true);
    expect(DEFAULT_POLL_MS).toBe(200);
  });
});

/* ------------------- Windows-safe rename in the atomic write ------------------- */

describe('renameRetrying (the atomic write on Windows)', () => {
  const errnoError = (code: string): NodeJS.ErrnoException => Object.assign(new Error(`${code}: rename`), { code });

  function harness(failures: string[], opts: { advancePerSleep?: number } = {}) {
    const calls: Array<[string, string]> = [];
    const sleeps: number[] = [];
    let clock = 1_000;
    const deps = {
      rename: (from: string, to: string): void => {
        calls.push([from, to]);
        const code = failures.shift();
        if (code !== undefined) throw errnoError(code);
      },
      sleep: (ms: number): void => {
        sleeps.push(ms);
        clock += opts.advancePerSleep ?? ms;
      },
      now: (): number => clock,
    };
    return { calls, sleeps, deps };
  }

  it('retries EPERM (a reader still has the target open) and succeeds once it clears', () => {
    // The Windows CI failure: two racing decide() processes, the winner's
    // rename-over hit EPERM because the loser was reading the record.
    const h = harness(['EPERM', 'EPERM']);
    expect(() => renameRetrying('a.tmp', 'a', h.deps)).not.toThrow();
    expect(h.calls).toHaveLength(3);
    expect(h.sleeps).toEqual([2, 4]); // exponential backoff, starting small
  });

  it('EACCES and EBUSY are retried the same way', () => {
    for (const code of ['EACCES', 'EBUSY']) {
      const h = harness([code]);
      expect(() => renameRetrying('a.tmp', 'a', h.deps)).not.toThrow();
      expect(h.calls).toHaveLength(2);
    }
  });

  it('a transient error that outlives the budget is thrown unchanged (never a silent success)', () => {
    const forever = new Proxy([] as string[], { get: (arr, k) => (k === 'shift' ? () => 'EPERM' : Reflect.get(arr, k)) });
    const h = harness(forever, { advancePerSleep: 100 });
    expect(() => renameRetrying('a.tmp', 'a', h.deps)).toThrow(/EPERM/);
    const slept = h.sleeps.reduce((a, b) => a + b, 0);
    expect(h.sleeps.length).toBeGreaterThan(1);
    expect(h.sleeps.every((ms) => ms <= 50)).toBe(true); // backoff is capped
    expect(slept).toBeLessThanOrEqual(RENAME_RETRY_BUDGET_MS); // the deadline, not the sleeps, ends it
  });

  it('any other error is thrown immediately, without a retry', () => {
    for (const code of ['ENOENT', 'EXDEV', 'EIO']) {
      const h = harness([code]);
      expect(() => renameRetrying('a.tmp', 'a', h.deps)).toThrow(new RegExp(code));
      expect(h.calls).toHaveLength(1);
      expect(h.sleeps).toEqual([]);
    }
    const noCode = { rename: (): void => { throw new Error('plain'); }, sleep: (): void => {}, now: (): number => 0 };
    expect(() => renameRetrying('a.tmp', 'a', noCode)).toThrow('plain');
  });
});

/* ------------------- the pending -> decided transition is a CAS ------------------- */

describe('HoldStore: the pending -> final transition is exclusive', () => {
  it('decide() takes the <id>.decided sentinel and a caller that loses it gets not_pending', () => {
    const rec = store.create(input());
    const decided = store.decide(rec.approval_id, 'approved', 'alice');
    expect(existsSync(sentinel(store, rec.approval_id))).toBe(true);
    expect(store.read(rec.approval_id)).toEqual(decided);
    // Sentinel files are not hold files: they never show up as holds.
    expect(store.list({ all: true }).map((r) => r.approval_id)).toEqual([rec.approval_id]);

    // A hold whose sentinel exists is decided, whatever the record still says:
    // this is exactly the state the loser of a real race observes.
    const other = store.create(input({ approval_id: 'raced-1' }));
    closeSync(openSync(sentinel(store, other.approval_id), 'wx', 0o600));
    let err: unknown;
    try {
      store.decide(other.approval_id, 'denied', 'bob');
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(HoldError);
    expect((err as HoldError).code).toBe('not_pending');
    expect((err as HoldError).message).toMatch(/another process decided it first/);
    expect(store.read(other.approval_id)?.status).toBe('pending'); // untouched by the loser
  });

  it('finalize() never overwrites a decision that got there first, and the decision is what a waiter sees', async () => {
    const rec = store.create(input());
    const wait = store.waitForDecision(rec.approval_id, { timeoutMs: 10_000, pollMs: 10 });
    const decided = store.decide(rec.approval_id, 'approved', 'alice');
    store.finalize(rec.approval_id, 'timeout'); // the proxy gave up at the same moment
    expect(store.read(rec.approval_id)).toEqual(decided);
    const res = await wait;
    expect(res.status).toBe('approved');
    expect(res.record?.decided_by).toBe('alice');
  });

  it('finalize() that wins first cannot be undone by a late decide()', () => {
    const rec = store.create(input());
    store.finalize(rec.approval_id, 'timeout');
    expect(store.read(rec.approval_id)?.status).toBe('timeout');
    expect(() => store.decide(rec.approval_id, 'approved', 'alice')).toThrow(HoldError);
    expect(store.read(rec.approval_id)?.status).toBe('timeout');
    // A second finalize is a no-op too: the first final status stands.
    store.finalize(rec.approval_id, 'session_end');
    expect(store.read(rec.approval_id)?.status).toBe('timeout');
  });

  it('a pending hold past its timeout_at is reported and treated as timeout', () => {
    const stale = store.create(input({ approval_id: 'stale-1', timeout_at: new Date(Date.now() - 1_000).toISOString() }));
    const live = store.create(input({ approval_id: 'live-1' }));
    // Nothing rewrote the file: the proxy that parked it may be gone.
    expect(store.read(stale.approval_id)?.status).toBe('pending');
    expect(store.list().map((r) => r.approval_id)).toEqual([live.approval_id]);
    const all = store.list({ all: true });
    expect(all.find((r) => r.approval_id === stale.approval_id)?.status).toBe('timeout');
    expect(all.find((r) => r.approval_id === live.approval_id)?.status).toBe('pending');

    let err: unknown;
    try {
      store.decide(stale.approval_id, 'approved', 'alice');
    } catch (e) {
      err = e;
    }
    expect((err as HoldError).code).toBe('not_pending');
    expect((err as HoldError).message).toMatch(/status: timeout/);
    expect(existsSync(sentinel(store, stale.approval_id))).toBe(false); // no claim was taken
    // An unparseable timeout_at is never treated as expired.
    const odd = store.create(input({ approval_id: 'odd-1', timeout_at: 'not-a-date' }));
    expect(store.list().map((r) => r.approval_id)).toContain(odd.approval_id);
    expect(store.decide(odd.approval_id, 'approved', 'alice').status).toBe('approved');
  });

  it('two racing processes: exactly one decide() wins every time', async () => {
    const trials = 20;
    const ids = Array.from({ length: trials }, (_, i) => `race-${i}`);
    for (const id of ids) store.create(input({ approval_id: id }));

    const child = join(dataDir, 'decide-child.ts');
    writeFileSync(
      child,
      [
        `import { HoldError, HoldStore } from ${JSON.stringify(HOLDS_MODULE)};`,
        'const [dir, startAt, gap, count, who] = process.argv.slice(2);',
        'const store = new HoldStore(dir);',
        'const out: string[] = [];',
        'for (let i = 0; i < Number(count); i++) {',
        '  const at = Number(startAt) + i * Number(gap);',
        '  while (Date.now() < at) { /* spin onto the shared instant */ }',
        '  try {',
        "    store.decide(`race-${i}`, 'approved', who);",
        "    out.push('won');",
        '  } catch (e) {',
        "    out.push(e instanceof HoldError ? e.code : `threw:${String(e)}`);",
        '  }',
        '}',
        'process.stdout.write(JSON.stringify(out));',
      ].join('\n'),
      'utf8',
    );

    const startAt = Date.now() + 3_000; // enough for both tsx processes to be up
    const runChild = (who: string): Promise<string[]> =>
      new Promise((resolve, reject) => {
        const proc = spawnTsx([child, dataDir, String(startAt), '25', String(trials), who], { cwd: ROOT });
        let stdout = '';
        let stderr = '';
        proc.stdout.on('data', (b: Buffer) => (stdout += b.toString('utf8')));
        proc.stderr.on('data', (b: Buffer) => (stderr += b.toString('utf8')));
        proc.on('error', reject);
        proc.on('close', (code) => {
          if (code !== 0) {
            reject(new Error(`child ${who} exited ${code}: ${stderr}`));
            return;
          }
          resolve(JSON.parse(stdout) as string[]);
        });
      });

    const [alice, bob] = await Promise.all([runChild('alice'), runChild('bob')]);
    expect(alice).toHaveLength(trials);
    expect(bob).toHaveLength(trials);
    for (let i = 0; i < trials; i++) {
      const pair = [alice[i], bob[i]];
      // Before the sentinel both processes could read `pending`, both write and
      // both report success (the reviewer saw it in 7 of 40 trials).
      expect(pair.filter((r) => r === 'won'), `trial ${i}: ${JSON.stringify(pair)}`).toHaveLength(1);
      expect(pair.filter((r) => r === 'not_pending'), `trial ${i}: ${JSON.stringify(pair)}`).toHaveLength(1);
      const rec = store.read(ids[i]!)!;
      expect(rec.status).toBe('approved');
      expect(rec.decided_by).toBe(alice[i] === 'won' ? 'alice' : 'bob');
    }
    // Exactly `trials` successes in total across both processes — never two for
    // one hold, never zero (which is what a lock that is too eager would give).
    const won = [...alice, ...bob].filter((r) => r === 'won').length;
    expect(won).toBe(trials);
  }, 60_000);
});
