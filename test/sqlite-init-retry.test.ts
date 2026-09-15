/**
 * The one-time sqlite open/schema step retries SQLITE_BUSY (see the
 * constructor comment in src/store/sqlite.ts for why busy_timeout alone is
 * not enough when several recorders open a fresh store at once). The race
 * itself is exercised cross-process by test/concurrency.test.ts; this pins
 * the retry helper's contract with injected time and sleep.
 */
import { describe, expect, it } from 'vitest';

import { isSqliteBusy, retryWhileBusy } from '../src/store/sqlite.js';

function busyError(code = 'SQLITE_BUSY'): Error {
  const err = new Error('database is locked') as Error & { code: string };
  err.code = code;
  return err;
}

describe('isSqliteBusy', () => {
  it('recognises better-sqlite3 busy codes and the bare message', () => {
    expect(isSqliteBusy(busyError())).toBe(true);
    expect(isSqliteBusy(busyError('SQLITE_BUSY_SNAPSHOT'))).toBe(true);
    expect(isSqliteBusy(new Error('database is locked'))).toBe(true);
    expect(isSqliteBusy(new Error('SQLITE_CONSTRAINT: append-only'))).toBe(false);
    expect(isSqliteBusy('database is locked')).toBe(false);
    expect(isSqliteBusy(undefined)).toBe(false);
  });
});

describe('retryWhileBusy', () => {
  it('returns the value on first success without sleeping', () => {
    const sleeps: number[] = [];
    const out = retryWhileBusy(() => 42, { deadlineMs: 1000, sleep: (ms) => sleeps.push(ms) });
    expect(out).toBe(42);
    expect(sleeps).toEqual([]);
  });

  it('retries busy errors with a doubling backoff capped at 100 ms, then succeeds', () => {
    const sleeps: number[] = [];
    let clock = 0;
    let attempts = 0;
    const out = retryWhileBusy(
      () => {
        attempts += 1;
        if (attempts <= 7) throw busyError();
        return 'ok';
      },
      { deadlineMs: 10_000, sleep: (ms) => { sleeps.push(ms); clock += ms; }, now: () => clock },
    );
    expect(out).toBe('ok');
    expect(attempts).toBe(8);
    expect(sleeps).toEqual([5, 10, 20, 40, 80, 100, 100]);
  });

  it('gives up with the busy error once the deadline has passed', () => {
    let clock = 0;
    let attempts = 0;
    expect(() =>
      retryWhileBusy(
        () => {
          attempts += 1;
          throw busyError();
        },
        { deadlineMs: 50, sleep: (ms) => { clock += ms; }, now: () => clock },
      ),
    ).toThrow(/database is locked/);
    // 5 + 10 + 20 + 40 = 75 ms elapsed after the 4th failure >= 50 ms deadline.
    expect(attempts).toBe(5);
  });

  it('propagates non-busy errors immediately', () => {
    const sleeps: number[] = [];
    let attempts = 0;
    expect(() =>
      retryWhileBusy(
        () => {
          attempts += 1;
          throw new Error('SQLITE_CORRUPT: malformed');
        },
        { deadlineMs: 10_000, sleep: (ms) => sleeps.push(ms) },
      ),
    ).toThrow(/SQLITE_CORRUPT/);
    expect(attempts).toBe(1);
    expect(sleeps).toEqual([]);
  });
});
