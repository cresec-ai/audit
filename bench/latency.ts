/**
 * bench/latency.ts — the M1 definition-of-done gate.
 *
 *   npx tsx bench/latency.ts            # K=300 round-trips, gate at p50 < 5ms
 *   npx tsx bench/latency.ts --smoke    # K=60 (fast CI sanity check)
 *   npx tsx bench/latency.ts --no-gate  # measure & print, never exit nonzero
 *
 * Method: drive the echo-server fixture with raw newline-delimited JSON-RPC.
 * First DIRECT (node child, no proxy), then WRAPPED (the recorder CLI proxying
 * the same fixture). For each, after an initialize handshake and a discarded
 * warmup, time K sequential tools/call echo round-trips with performance.now().
 * Report p50/p95/p99 of each series and the added-latency deltas. Exit 1 if the
 * p50 delta exceeds 5ms (DoD: <5ms p50 added latency), unless --no-gate.
 *
 * Everything prints to stderr — stdout is reserved for the wire and stays
 * clean so this never interferes with anything reading it.
 */

import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { performance } from 'node:perf_hooks';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(fileURLToPath(new URL('..', import.meta.url)));
const ECHO_SERVER = join(ROOT, 'test', 'fixtures', 'echo-server.cjs');

const SMOKE = process.argv.includes('--smoke');
const NO_GATE = process.argv.includes('--no-gate');
const K = SMOKE ? 60 : 300;
const WARMUP = 20;
const P50_GATE_MS = 5;

/** A live child driven over stdio with one JSON message per line. */
class Harness {
  private buf = '';
  /** Resolvers keyed by the JSON-RPC id we are waiting on. */
  private readonly waiters = new Map<number, () => void>();

  constructor(private readonly child: ChildProcessWithoutNullStreams) {
    child.stdout.setEncoding('utf8');
    child.stdout.on('data', (chunk: string) => this.onData(chunk));
    // Keep the child's stderr from polluting our table, but don't lose it on error.
    child.stderr.on('data', () => {
      /* swallowed; recorder diagnostics handled separately by the caller */
    });
  }

  private onData(chunk: string): void {
    this.buf += chunk;
    let nl: number;
    while ((nl = this.buf.indexOf('\n')) !== -1) {
      const line = this.buf.slice(0, nl).replace(/\r$/, '');
      this.buf = this.buf.slice(nl + 1);
      if (line.trim() === '') continue;
      let msg: { id?: unknown };
      try {
        msg = JSON.parse(line);
      } catch {
        continue;
      }
      if (typeof msg.id === 'number') {
        const w = this.waiters.get(msg.id);
        if (w) {
          this.waiters.delete(msg.id);
          w();
        }
      }
    }
  }

  /** Send a request and resolve when the response with the same id arrives. */
  request(id: number, method: string, params?: unknown): Promise<void> {
    return new Promise((res) => {
      this.waiters.set(id, res);
      this.child.stdin.write(JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n');
    });
  }

  end(): void {
    try {
      this.child.stdin.end();
    } catch {
      /* ignore */
    }
  }
}

interface Stats {
  p50: number;
  p95: number;
  p99: number;
}

function percentile(sorted: number[], p: number): number {
  if (sorted.length === 0) return 0;
  const idx = Math.min(sorted.length - 1, Math.max(0, Math.ceil((p / 100) * sorted.length) - 1));
  return sorted[idx];
}

function summarize(samples: number[]): Stats {
  const sorted = [...samples].sort((a, b) => a - b);
  return {
    p50: percentile(sorted, 50),
    p95: percentile(sorted, 95),
    p99: percentile(sorted, 99),
  };
}

/** Run the handshake + warmup + K timed echo round-trips against one child. */
async function measure(child: ChildProcessWithoutNullStreams): Promise<number[]> {
  const h = new Harness(child);
  let id = 1;

  await h.request(id++, 'initialize', {
    protocolVersion: '2024-11-05',
    clientInfo: { name: 'bench', version: '1.0.0' },
    capabilities: {},
  });

  const call = (n: number): Promise<void> =>
    h.request(id++, 'tools/call', { name: 'echo', arguments: { n } });

  for (let i = 0; i < WARMUP; i++) await call(i);

  const samples: number[] = [];
  for (let i = 0; i < K; i++) {
    const t0 = performance.now();
    await call(i);
    samples.push(performance.now() - t0);
  }

  h.end();
  return samples;
}

/** Spawn the fixture directly (no proxy). */
function spawnDirect(): ChildProcessWithoutNullStreams {
  return spawn(process.execPath, [ECHO_SERVER], { cwd: ROOT, stdio: ['pipe', 'pipe', 'pipe'] });
}

/** Spawn the fixture WRAPPED by the recorder CLI; capture its stderr summary. */
function spawnWrapped(dataDir: string): { child: ChildProcessWithoutNullStreams; stderr: () => string } {
  const child = spawn(
    'npx',
    ['tsx', 'src/cli.ts', '--data-dir', dataDir, '--', 'node', ECHO_SERVER],
    { cwd: ROOT, stdio: ['pipe', 'pipe', 'pipe'] },
  );
  let stderr = '';
  child.stderr.setEncoding('utf8');
  child.stderr.on('data', (c: string) => {
    stderr += c;
  });
  return { child, stderr: () => stderr };
}

function waitClose(child: ChildProcessWithoutNullStreams): Promise<void> {
  return new Promise((res) => {
    let done = false;
    const finish = (): void => {
      if (done) return;
      done = true;
      res();
    };
    child.on('close', finish);
    child.on('error', finish);
    // Don't hang the bench forever if a child refuses to die.
    setTimeout(finish, 5000).unref();
  });
}

function pad(s: string, n: number): string {
  return s.length >= n ? s : s + ' '.repeat(n - s.length);
}

function fmt(n: number): string {
  return n.toFixed(3) + 'ms';
}

async function main(): Promise<void> {
  const log = (m: string): void => {
    process.stderr.write(m + '\n');
  };

  log(`[mcp-recorder] latency bench — K=${K} timed round-trips, ${WARMUP} warmup discarded${SMOKE ? ' (smoke)' : ''}`);

  // ---- DIRECT baseline ----
  const direct = spawnDirect();
  const directSamples = await measure(direct);
  await waitClose(direct);

  // ---- WRAPPED through the recorder ----
  const tmp = mkdtempSync(join(tmpdir(), 'mcp-rec-bench-'));
  let wrappedSamples: number[];
  let recorderStderr = '';
  try {
    const wrapped = spawnWrapped(tmp);
    wrappedSamples = await measure(wrapped.child);
    await waitClose(wrapped.child);
    recorderStderr = wrapped.stderr();
  } finally {
    try {
      rmSync(tmp, { recursive: true, force: true });
    } catch {
      /* best effort */
    }
  }

  const d = summarize(directSamples);
  const w = summarize(wrappedSamples);
  const delta: Stats = {
    p50: w.p50 - d.p50,
    p95: w.p95 - d.p95,
    p99: w.p99 - d.p99,
  };

  log('');
  log(`  ${pad('series', 10)}${pad('p50', 12)}${pad('p95', 12)}${pad('p99', 12)}`);
  log(`  ${pad('direct', 10)}${pad(fmt(d.p50), 12)}${pad(fmt(d.p95), 12)}${pad(fmt(d.p99), 12)}`);
  log(`  ${pad('wrapped', 10)}${pad(fmt(w.p50), 12)}${pad(fmt(w.p95), 12)}${pad(fmt(w.p99), 12)}`);
  log(`  ${pad('added', 10)}${pad(fmt(delta.p50), 12)}${pad(fmt(delta.p95), 12)}${pad(fmt(delta.p99), 12)}`);
  log('');

  // Surface the recorder's own session-end summary so the event count is visible.
  const summaryLine = recorderStderr
    .split('\n')
    .find((l) => /\[mcp-recorder\]/.test(l) && /(event|record|session|wrote|written)/i.test(l));
  if (summaryLine) {
    log(`  recorder: ${summaryLine.trim()}`);
  } else if (recorderStderr.trim()) {
    // Fall back to the last non-empty recorder stderr line.
    const lines = recorderStderr.split('\n').filter((l) => l.trim().length > 0);
    if (lines.length > 0) log(`  recorder: ${lines[lines.length - 1].trim()}`);
  }

  const gateMsg = `p50 added latency = ${fmt(delta.p50)} (gate: < ${P50_GATE_MS}ms)`;
  if (delta.p50 > P50_GATE_MS && !NO_GATE) {
    log(`  ✗ FAIL — ${gateMsg}`);
    process.exit(1);
  }
  log(`  ✓ PASS — ${gateMsg}${NO_GATE ? ' [gate disabled]' : ''}`);
}

main().catch((err) => {
  process.stderr.write(`[mcp-recorder] bench crashed: ${err instanceof Error ? err.stack ?? err.message : String(err)}\n`);
  process.exit(1);
});
