import { spawn } from 'node:child_process';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

const ROOT = resolve(fileURLToPath(new URL('..', import.meta.url)));

/**
 * The latency bench is the M1 DoD gate. In smoke mode it runs K=60 round-trips
 * direct vs. wrapped and exits 0 only if the p50 added latency is under 5ms.
 * Asserting exit 0 here ties the DoD bar into the test suite (the global 30s
 * timeout applies — the bench is built to finish well inside it).
 */
describe('latency bench (smoke)', () => {
  it('runs --smoke and exits 0 (p50 added latency under the 5ms gate)', async () => {
    const code = await new Promise<number>((resolveCode) => {
      const child = spawn('npx', ['tsx', 'bench/latency.ts', '--smoke'], {
        cwd: ROOT,
        stdio: ['ignore', 'ignore', 'inherit'],
      });
      child.on('error', () => resolveCode(1));
      child.on('close', (c) => resolveCode(c ?? 1));
    });
    expect(code).toBe(0);
  });
});
