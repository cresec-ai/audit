/**
 * Multiple `mcp-recorder record` processes sharing one data dir is the
 * README's normal setup (one wrapper per MCP server). This spawns several
 * REAL `record` CLI child processes against a single temp data dir — the
 * only way to exercise the true cross-process races (sqlite SQLITE_BUSY /
 * stale head, jsonl's advisory lock, the key-file creation race) that an
 * in-process test cannot reproduce.
 */
import type { ChildProcess } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, describe, expect, it } from 'vitest';
import { spawnTsx } from './helpers/tsx.js';

import { openStore } from '../src/store/index.js';
import { verifyStore } from '../src/verify/verify.js';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const ECHO_SERVER = fileURLToPath(new URL('./fixtures/echo-server.cjs', import.meta.url));

const NPROC = 3;
const NCALLS = 40;
/** session_start + initialize + the server's post-init notification + N tool_call + session_end. */
const EVENTS_PER_SESSION = NCALLS + 4;

const cleanups: Array<() => void> = [];
afterEach(() => {
  while (cleanups.length > 0) {
    try {
      cleanups.pop()!();
    } catch {
      /* best-effort teardown */
    }
  }
});

function tmpDataDir(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  cleanups.push(() => rmSync(dir, { recursive: true, force: true }));
  return dir;
}

interface ProcResult {
  code: number | null;
  stderr: string;
}

/** Drive one `record` CLI child through initialize + `calls` tools/call requests. */
function runRecordProcess(
  dataDir: string,
  backend: 'sqlite' | 'jsonl',
  tag: string,
  calls: number,
): Promise<ProcResult> {
  return new Promise((resolve) => {
    const child: ChildProcess = spawnTsx(
      [
        'src/cli.ts',
        'record',
        '--data-dir',
        dataDir,
        '--store',
        backend,
        '--name',
        tag,
        '--',
        'node',
        ECHO_SERVER,
      ],
      { cwd: ROOT, stdio: ['pipe', 'ignore', 'pipe'] },
    );

    let stderr = '';
    child.stderr!.setEncoding('utf8');
    child.stderr!.on('data', (chunk: string) => {
      stderr += chunk;
    });
    child.on('close', (code) => resolve({ code, stderr }));

    child.stdin!.write(
      JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: 'initialize',
        params: {
          protocolVersion: '2024-11-05',
          clientInfo: { name: 'concurrency-test', version: '1.0.0' },
          capabilities: {},
        },
      }) + '\n',
    );

    let i = 0;
    const tick = (): void => {
      if (i >= calls) {
        // Give the last in-flight response a moment to land before closing.
        setTimeout(() => child.stdin!.end(), 300);
        return;
      }
      child.stdin!.write(
        JSON.stringify({
          jsonrpc: '2.0',
          id: 10 + i,
          method: 'tools/call',
          params: { name: 'echo', arguments: { tag, i } },
        }) + '\n',
      );
      i++;
      setTimeout(tick, 2);
    };
    // Give tsx a moment to boot so the bursts genuinely overlap across
    // processes instead of running back-to-back.
    setTimeout(tick, 1000);
  });
}

async function runConcurrencyCase(backend: 'sqlite' | 'jsonl'): Promise<void> {
  const dataDir = tmpDataDir(`mcp-rec-conc-${backend}-`);

  const results = await Promise.all(
    Array.from({ length: NPROC }, (_, i) => runRecordProcess(dataDir, backend, `S${i}`, NCALLS)),
  );

  for (const [i, r] of results.entries()) {
    expect(r.code, `process S${i} exited nonzero; stderr:\n${r.stderr}`).toBe(0);
    expect(r.stderr, `process S${i} stderr:\n${r.stderr}`).toMatch(/\(0 dropped\)/);
  }

  const store = openStore({ dataDir, backend });
  try {
    const verify = await verifyStore(store);
    const hardProblems = verify.problems.filter((p) => p.warning !== true);
    expect(hardProblems, JSON.stringify(hardProblems, null, 2)).toEqual([]);
    expect(verify.ok).toBe(true);

    expect(store.count()).toBe(NPROC * EVENTS_PER_SESSION);

    const sessions = store.sessions();
    expect(sessions).toHaveLength(NPROC);
    for (const s of sessions) {
      expect(s.ended_at, `session ${s.session_id} has no session_end (open)`).toBeDefined();
      expect(s.event_count).toBe(EVENTS_PER_SESSION);
      expect(s.tool_call_count).toBe(NCALLS);
    }

    const seqs = [...store.iterate()].map((r) => r.seq);
    expect(seqs).toEqual(
      Array.from({ length: NPROC * EVENTS_PER_SESSION }, (_, idx) => idx + 1),
    );
  } finally {
    store.close();
  }
}

describe('concurrent record processes sharing one data dir', () => {
  it(
    `sqlite: ${NPROC} processes x ${NCALLS} calls lose nothing and verify PASS`,
    () => runConcurrencyCase('sqlite'),
    25_000,
  );

  it(
    `jsonl: ${NPROC} processes x ${NCALLS} calls lose nothing and verify PASS`,
    () => runConcurrencyCase('jsonl'),
    25_000,
  );
});
