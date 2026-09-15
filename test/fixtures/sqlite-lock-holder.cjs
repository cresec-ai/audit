/**
 * Test helper: create `<dbPath>` in rollback (DELETE) journal mode, then hold
 * a RESERVED write lock on it (BEGIN IMMEDIATE) for `<holdMs>` milliseconds.
 * Prints "locked" once the lock is held and "released" after COMMIT.
 *
 *   node sqlite-lock-holder.cjs <dbPath> <holdMs>
 *
 * This is the exact situation a second `mcp-recorder record` process meets
 * when it opens a data dir another recorder is just creating: the file is
 * still in rollback mode, and switching it to WAL needs a write lock the
 * other process holds. stdout is written with writeSync so the "locked"
 * line reaches the parent before this process blocks (pipe writes are
 * asynchronous on Windows).
 */
'use strict';
const { writeSync } = require('node:fs');
const Database = require('better-sqlite3');

const [dbPath, holdMsArg] = process.argv.slice(2);
const holdMs = Number(holdMsArg);
if (!dbPath || !Number.isFinite(holdMs)) {
  writeSync(2, 'usage: sqlite-lock-holder.cjs <dbPath> <holdMs>\n');
  process.exit(2);
}

const db = new Database(dbPath);
db.pragma('journal_mode = DELETE');
db.exec('CREATE TABLE IF NOT EXISTS lock_holder (x INTEGER)');
db.exec('BEGIN IMMEDIATE');
db.exec('INSERT INTO lock_holder (x) VALUES (1)');
writeSync(1, 'locked\n');
Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, holdMs);
db.exec('COMMIT');
db.close();
writeSync(1, 'released\n');
