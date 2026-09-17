/**
 * bench/latency.ts — the M1 definition-of-done gate.
 *
 *   npx tsx bench/latency.ts            # K=300 round-trips, gate at p50 < 5ms
 *   npx tsx bench/latency.ts --smoke    # K=60 (fast CI sanity check)
 *   npx tsx bench/latency.ts --no-gate  # measure & print, never exit nonzero
 *   npx tsx bench/latency.ts --gateway  # also measure GATEWAY mode (--policy)
 *
 * Method: drive the echo-server fixture with raw newline-delimited JSON-RPC.
 * First DIRECT (node child, no proxy), then WRAPPED (the recorder CLI proxying
 * the same fixture). For each, after an initialize handshake and a discarded
 * warmup, time K sequential tools/call echo round-trips with performance.now().
 * Report p50/p95/p99 of each series and the added-latency deltas. Exit 1 if the
 * p50 delta exceeds 5ms (DoD: <5ms p50 added latency), unless --no-gate.
 *
 * --gateway adds a THIRD series: the same round-trips through the same CLI
 * with `--policy` in force, so every tools/call is evaluated against a policy
 * and every result goes through the boundary filter. It is opt-in and NOT
 * gated: the 5ms DoD is about record mode, and gateway mode is an explicit
 * trade of latency for enforcement. The echo fixture answers with a few dozen
 * bytes, so the gateway row prices the per-call FIXED cost — policy evaluation,
 * the gateway's correlation bookkeeping, a boundary pass over a tiny result —
 * and not the boundary scan itself, which scales with result size and is what
 * bench/boundary.ts measures. Every call here is ALLOWED, which is also the
 * only path that costs on the forwarding side: a deny or a hold is answered
 * by the gateway and never reaches the server at all.
 *
 * --gateway also runs a FOURTH series, a CONTROL: a second wrapped run with
 * no policy, identical to the first. `gw added` (vs direct) answers "what
 * does turning the proxy on cost", but the gateway's own trade-off is `gw vs
 * rec` — enforcement on top of recording — and at this K that delta is small
 * enough that reading it against zero is meaningless: it has come out
 * NEGATIVE on runs where nothing changed. The control measures what two
 * identical runs differ by on this machine, and the bench then says outright
 * whether `gw vs rec` clears that floor instead of leaving the reader to
 * assume it does.
 *
 * Everything prints to stderr — stdout is reserved for the wire and stays
 * clean so this never interferes with anything reading it.
 */

import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { performance } from 'node:perf_hooks';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(fileURLToPath(new URL('..', import.meta.url)));
const ECHO_SERVER = join(ROOT, 'test', 'fixtures', 'echo-server.cjs');

const SMOKE = process.argv.includes('--smoke');
const NO_GATE = process.argv.includes('--no-gate');
const GATEWAY = process.argv.includes('--gateway');
const K = SMOKE ? 60 : 300;
const WARMUP = 20;
const P50_GATE_MS = 5;

/**
 * The policy the --gateway series enforces. `echo` matches none of the rules,
 * so every call walks the whole rule list and lands on `default: allow` —
 * the shape a real deployment has, and the one that prices the rule walk
 * rather than an empty-policy short circuit. Boundary settings are left
 * unset so the series runs the shipped defaults.
 */
const GATEWAY_POLICY = [
  'version: 1',
  'name: bench-gateway',
  'mcp:',
  '  default: allow',
  '  rules:',
  '    - id: no-exfil',
  '      match: { tool: [http_post, "send_*"] }',
  '      action: deny',
  '      reason: no outbound HTTP',
  '    - id: careful-writes',
  '      match: { tool: ["delete_*", "write_*"] }',
  '      action: hold',
  '    - id: no-secrets-dir',
  '      match: { tool: "read_*", args: { path: "^/etc/" } }',
  '      action: deny',
  '      reason: not readable through the gateway',
  '',
].join('\n');

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

/**
 * Spawn the fixture WRAPPED by the recorder CLI; capture its stderr summary.
 * `extraArgs` go before the `--` separator (the --gateway series passes
 * `--policy <file>` there).
 */
function spawnWrapped(
  dataDir: string,
  extraArgs: readonly string[] = [],
): { child: ChildProcessWithoutNullStreams; stderr: () => string } {
  const child = spawn(
    'npx',
    ['tsx', 'src/cli.ts', '--data-dir', dataDir, ...extraArgs, '--', 'node', ECHO_SERVER],
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

/**
 * Half-width of a distribution-free ~95% confidence interval for the MEDIAN,
 * from order statistics (the normal approximation to the binomial: the true
 * median lies between the samples at rank n/2 +/- 1.96*sqrt(n)/2 about 95% of
 * the time). Used instead of a stddev because these samples are heavy-tailed
 * — a handful of multi-millisecond round-trips would dominate a stddev and
 * say nothing about how well the median is pinned down.
 */
function medianHalfWidth(samples: readonly number[]): number {
  const sorted = [...samples].sort((a, b) => a - b);
  const n = sorted.length;
  if (n < 2) return Infinity;
  const half = (1.96 * Math.sqrt(n)) / 2;
  const lo = sorted[Math.max(0, Math.floor(n / 2 - half))];
  const hi = sorted[Math.min(n - 1, Math.ceil(n / 2 + half))];
  return (hi - lo) / 2;
}

function pad(s: string, n: number): string {
  return s.length >= n ? s : s + ' '.repeat(n - s.length);
}

function fmt(n: number): string {
  return n.toFixed(3) + 'ms';
}

function deltaOf(series: Stats, baseline: Stats): Stats {
  return {
    p50: series.p50 - baseline.p50,
    p95: series.p95 - baseline.p95,
    p99: series.p99 - baseline.p99,
  };
}

/** One measured run of the recorder CLI. */
interface RecorderRun {
  samples: number[];
  stderr: string;
}

/** Measure one recorder series in a throwaway data dir, then clean it up. */
async function runRecorder(extraArgs: readonly string[] = []): Promise<RecorderRun> {
  const tmp = mkdtempSync(join(tmpdir(), 'mcp-rec-bench-'));
  try {
    const wrapped = spawnWrapped(tmp, extraArgs);
    const samples = await measure(wrapped.child);
    await waitClose(wrapped.child);
    return { samples, stderr: wrapped.stderr() };
  } finally {
    try {
      rmSync(tmp, { recursive: true, force: true });
    } catch {
      /* best effort */
    }
  }
}

/**
 * The recorder's session-end summary line, else its last stderr line.
 *
 * The event count is matched first and explicitly: gateway mode prints its
 * own startup line, and every recorder line contains "mcp-recorder", so the
 * looser diagnostic match below would otherwise return whichever line came
 * first rather than the summary this bench wants to show.
 */
function summaryLine(stderr: string): string | undefined {
  const lines = stderr.split('\n').filter((l) => l.trim().length > 0);
  const summary =
    lines.find((l) => /recorded \d+ events?/.test(l)) ??
    lines.find((l) => /\[mcp-recorder\]/.test(l) && /(event|record|session|wrote|written)/i.test(l));
  if (summary !== undefined) return summary.trim();
  return lines.length > 0 ? lines[lines.length - 1].trim() : undefined;
}

async function main(): Promise<void> {
  const log = (m: string): void => {
    process.stderr.write(m + '\n');
  };

  log(
    `[mcp-recorder] latency bench — K=${K} timed round-trips, ${WARMUP} warmup discarded` +
      `${GATEWAY ? ', + gateway series' : ''}${SMOKE ? ' (smoke)' : ''}`,
  );

  // ---- DIRECT baseline ----
  const direct = spawnDirect();
  const directSamples = await measure(direct);
  await waitClose(direct);

  // ---- WRAPPED through the recorder ----
  const wrapped = await runRecorder();

  // ---- GATEWAY: the same recorder, same fixture, --policy in force ----
  // Followed by a CONTROL: a second wrapped series with no policy at all,
  // identical to the first in every way. Its p50 gap from the first wrapped
  // series is this machine's run-to-run noise for a recorder series, measured
  // rather than assumed, and it brackets the gateway series so process drift
  // shows up in the control instead of being attributed to the gateway.
  // Without it the gateway row can only be read against zero, and the
  // per-call fixed cost at this K is small enough that the sign of that
  // comparison flips between runs.
  let gatewaySeries: RecorderRun | undefined;
  let controlSeries: RecorderRun | undefined;
  if (GATEWAY) {
    const policyDir = mkdtempSync(join(tmpdir(), 'mcp-rec-bench-policy-'));
    const policyPath = join(policyDir, 'policy.yaml');
    writeFileSync(policyPath, GATEWAY_POLICY);
    try {
      gatewaySeries = await runRecorder(['--policy', policyPath]);
    } finally {
      try {
        rmSync(policyDir, { recursive: true, force: true });
      } catch {
        /* best effort */
      }
    }
    controlSeries = await runRecorder();
  }

  const d = summarize(directSamples);
  const w = summarize(wrapped.samples);
  const delta = deltaOf(w, d);

  const row = (name: string, s: Stats): string =>
    `  ${pad(name, 10)}${pad(fmt(s.p50), 12)}${pad(fmt(s.p95), 12)}${pad(fmt(s.p99), 12)}`;

  log('');
  log(`  ${pad('series', 10)}${pad('p50', 12)}${pad('p95', 12)}${pad('p99', 12)}`);
  log(row('direct', d));
  log(row('wrapped', w));
  log(row('added', delta));
  if (gatewaySeries !== undefined && controlSeries !== undefined) {
    const g = summarize(gatewaySeries.samples);
    const c = summarize(controlSeries.samples);
    log(row('gateway', g));
    // Added vs DIRECT: what enabling the gateway costs against no proxy at
    // all. Then vs WRAPPED: what ENFORCEMENT alone costs on top of recording,
    // which is the number the gateway's own trade-off is about and the one
    // this series used to leave the reader to subtract. Then the control:
    // the same wrapped configuration run twice, whose gap is the noise floor
    // the `gw vs rec` row has to clear to mean anything.
    log(row('gw added', deltaOf(g, d)));
    log(row('gw vs rec', deltaOf(g, w)));
    log(row('control', deltaOf(c, w)));
    log('');
    const fixed = g.p50 - w.p50;
    const gw = medianHalfWidth(gatewaySeries.samples);
    const ww = medianHalfWidth(wrapped.samples);
    const cw = medianHalfWidth(controlSeries.samples);
    // Conservative: add the two half-widths rather than combining them in
    // quadrature. The delta has to clear BOTH medians' own uncertainty.
    const uncertainty = gw + ww;
    const controlDelta = c.p50 - w.p50;
    const controlUncertainty = cw + ww;
    log(
      `  enforcement cost at K=${K}: gateway p50 - wrapped p50 = ${fmt(fixed)} ` +
        `(+/- ${fmt(uncertainty)}, 95% CI on the two medians)`,
    );
    log(
      `    control: a second identical wrapped run differs by ${fmt(controlDelta)} ` +
        `(+/- ${fmt(controlUncertainty)})`,
    );
    if (Math.abs(controlDelta) > controlUncertainty) {
      log(
        `    -> the CONTROL itself moved more than its own uncertainty, so this run is too noisy ` +
          `to read: two identical configurations did not come out the same. Nothing should be ` +
          `concluded about the gateway from it.`,
      );
    } else if (Math.abs(fixed) > uncertainty) {
      log(
        `    -> clears its own uncertainty, so it is a real cost. The echo fixture answers with a ` +
          `few dozen bytes, so this is the per-call FIXED cost (rule walk + correlation ` +
          `bookkeeping + a boundary pass over a tiny result), not the boundary scan — that ` +
          `scales with result size (bench/boundary.ts).`,
      );
    } else {
      log(
        `    -> does NOT clear it: at K=${K} the per-call fixed cost of enforcement is inside the ` +
          `measurement noise, and the sign of this delta is not meaningful (it comes out NEGATIVE ` +
          `on some runs). Raise K before reading anything into it; the gateway cost that does ` +
          `resolve at this scale is the size-dependent boundary scan (bench/boundary.ts).`,
      );
    }
  }
  log('');

  // Surface the recorder's own session-end summary so the event count is visible.
  const wrappedSummary = summaryLine(wrapped.stderr);
  if (wrappedSummary !== undefined) log(`  recorder: ${wrappedSummary}`);
  if (gatewaySeries !== undefined) {
    const gatewaySummary = summaryLine(gatewaySeries.stderr);
    if (gatewaySummary !== undefined) log(`  gateway:  ${gatewaySummary}`);
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
