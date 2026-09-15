import { spawn } from 'node:child_process';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

const ROOT = resolve(fileURLToPath(new URL('..', import.meta.url)));

/**
 * The latency bench is the M1 DoD gate (p50 added latency < 5ms), enforced by
 * `npm run bench`. This smoke test proves the bench runs end to end inside
 * the suite without enforcing the gate: the unit suite runs alongside tests
 * that spawn dozens of child processes, so a hard timing gate here would fail
 * on loaded CI runners for reasons unrelated to the proxy.
 */
describe('latency bench (smoke)', () => {
  it('runs --smoke --no-gate end to end and reports the added p50 latency', async () => {
    let stderr = '';
    const code = await new Promise<number>((resolveCode) => {
      const child = spawn('npx', ['tsx', 'bench/latency.ts', '--smoke', '--no-gate'], {
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
  });
});
