/**
 * Block the calling thread for `ms` milliseconds without spinning.
 *
 * `Atomics.wait` on a private SharedArrayBuffer is the one portable way to
 * sleep synchronously in Node (it is allowed on the main thread there, unlike
 * in browsers). Used by the synchronous retry loops — key-file creation, the
 * JSONL and SQLite stores' lock/busy handling, the hold store's Windows-safe
 * rename — which cannot yield to the event loop.
 */
const cell = new Int32Array(new SharedArrayBuffer(4));

export function sleepSync(ms: number): void {
  if (ms <= 0) return;
  Atomics.wait(cell, 0, 0, ms);
}
