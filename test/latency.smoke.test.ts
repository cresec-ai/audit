import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { spawnTsx } from './helpers/tsx.js';

const ROOT = resolve(fileURLToPath(new URL('..', import.meta.url)));

/**
 * The benches are the project's timing gates: `npm run bench` is the M1 DoD
 * gate (p50 added latency < 5ms) and `npm run bench:boundary` prices the
 * gateway's tool-result scan. These smoke tests prove both run end to end
 * inside the suite without enforcing their gates: the unit suite runs
 * alongside tests that spawn dozens of child processes, so a hard timing gate
 * here would fail on loaded CI runners for reasons unrelated to the proxy.
 */
describe('latency bench (smoke)', () => {
  // bench/latency.ts itself shells out via `spawn('npx', ['tsx', ...])` to
  // launch the wrapped harness — that's outside this unit's file scope
  // (bench/**), and unlike the test-side spawns above it isn't portable to
  // Windows as-is (npx is a .cmd shim there). Skip until bench/latency.ts
  // gets the same process.execPath + resolved-tsx-CLI treatment.
  it.skipIf(process.platform === 'win32')(
    'runs --smoke --no-gate end to end and reports the added p50 latency',
    async () => {
      let stderr = '';
      const code = await new Promise<number>((resolveCode) => {
        const child = spawnTsx(['bench/latency.ts', '--smoke', '--no-gate'], {
          cwd: ROOT,
          stdio: ['ignore', 'ignore', 'pipe'],
        });
        child.stderr!.setEncoding('utf8');
        child.stderr!.on('data', (chunk: string) => {
          stderr += chunk;
        });
        child.on('error', () => resolveCode(1));
        child.on('close', (c) => resolveCode(c ?? 1));
      });
      process.stderr.write(stderr);
      expect(code).toBe(0);
      expect(stderr).toMatch(/p50 added latency = [0-9.]+ms/);
      expect(stderr).toMatch(/recorded \d+ events \(0 dropped\)/);
    },
  );
});

/**
 * bench/boundary.ts runs applyBoundary in-process, so this adds no spawned
 * servers to the suite — but its fixtures assert themselves (a clean payload
 * must come back untouched, a dirty one must be rewritten every iteration,
 * every cell must actually be scanned under the max_scan_bytes default),
 * which is what makes it worth running here: a corpus line that starts
 * matching, or a boundary pattern that stops, fails the bench rather than
 * quietly changing the numbers the max_scan_bytes default is chosen from.
 *
 * Unlike the latency bench above, the GATE IS ENABLED here. P99_GATE_MS is a
 * ReDoS alarm, not a performance target: it sits ~3x over the worst cell
 * measured (~35ms total, scan plus re-serialize), so catastrophic
 * backtracking — which costs orders of magnitude — trips it while a loaded
 * runner does not. With --no-gate nothing in the repo ever exercised it.
 */
describe('boundary bench (smoke)', () => {
  // No skipIf here: unlike bench/latency.ts this bench spawns nothing of its
  // own, and spawnTsx is portable, so it runs on Windows like any other test.
  it(
    'runs --smoke end to end, passes its own p99 gate, and reports every cell',
    async () => {
      let stderr = '';
      const code = await new Promise<number>((resolveCode) => {
        const child = spawnTsx(['bench/boundary.ts', '--smoke'], {
          cwd: ROOT,
          stdio: ['ignore', 'ignore', 'pipe'],
        });
        child.stderr!.setEncoding('utf8');
        child.stderr!.on('data', (chunk: string) => {
          stderr += chunk;
        });
        child.on('error', () => resolveCode(1));
        child.on('close', (c) => resolveCode(c ?? 1));
      });
      process.stderr.write(stderr);
      // Exit 0 is the gate: the bench exits 1 if the worst p99 is over
      // P99_GATE_MS, and throws (also exit 1) if any cell failed to match
      // what it claims or landed over max_scan_bytes.
      expect(code).toBe(0);
      // One row per cell: 4 sizes x 2 shapes x 2 contents. The largest size is
      // FITTED to max_scan_bytes rather than round, so it is not a whole KiB.
      expect(stderr.match(/^ {2}[\d.]+(?:KiB|MiB)\s+\S+\s+(?:clean|dirty)\s.*ms/gm)).toHaveLength(16);
      expect(stderr).toMatch(/worst p99 = [0-9.]+ms/);
      expect(stderr).toMatch(/\u2713 PASS/);
      // Every `dirty` cell must price BOTH steps the proxy pays only on a
      // CHANGED result — the evidence hash and the re-serialize. They are the
      // whole difference between a hit and a miss on the forwarding path, so
      // leaving either out makes clean-vs-dirty not like-for-like and turns
      // "a hit costs what a miss costs" into an artifact of the measurement.
      expect(stderr).toMatch(/the evidence hash [0-9.]+ms plus the/);
      expect(stderr).toMatch(/re-serialize [0-9.]+ms, [0-9.]+ms together at this size/);
      expect(stderr).toMatch(/evidence hash [0-9.]+ms \+ re-serialize [0-9.]+ms/);
      // The cap row must be sized from the shipped default, not hardcoded.
      expect(stderr).toMatch(/max_scan_bytes default — largest row that fits/);
    },
    60_000,
  );
});
