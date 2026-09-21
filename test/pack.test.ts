/**
 * What `npm pack` ships. Cheap (a dry run, no network) and worth pinning:
 * `receiver/` was absent from `files` for months, so a receiver operator
 * needed a repository clone, and the Dockerfile that runs it could not have
 * been built from the published tarball either.
 */

import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

const ROOT = fileURLToPath(new URL('..', import.meta.url));

interface PackEntry {
  path: string;
}
interface PackReport {
  files: PackEntry[];
}

function packedFiles(): string[] {
  const res = spawnSync(process.platform === 'win32' ? 'npm.cmd' : 'npm', ['pack', '--dry-run', '--json', '--ignore-scripts'], {
    cwd: ROOT,
    encoding: 'utf8',
    shell: process.platform === 'win32',
    env: { ...process.env, npm_config_loglevel: 'silent' },
  });
  expect(res.status, res.stderr).toBe(0);
  // npm prints the report on stdout; some versions prefix it with notices on stderr only.
  const start = res.stdout.indexOf('[');
  const report = JSON.parse(res.stdout.slice(start)) as PackReport[];
  return (report[0]?.files ?? []).map((f) => f.path.split('\\').join('/'));
}

describe('npm pack --dry-run', () => {
  const files = packedFiles();

  it('ships receiver/ (the reference receiver and its Dockerfile)', () => {
    expect(files).toContain('receiver/main.ts');
    expect(files).toContain('receiver/Dockerfile');
    expect(files).toContain('receiver/README.md');
    // The receiver imports ../src/*.ts and runs through tsx, so src/ ships with it.
    expect(files).toContain('src/chain/hash.ts');
  });

  it('ships the built CLI and the frozen schema docs', () => {
    expect(files).toContain('dist/cli.js');
    expect(files).toContain('docs/event-schema.md');
    expect(files).toContain('docs/policy-schema.json');
  });

  it('never ships evidence, tests or the dogfood store', () => {
    // NEGATIVE CONTROL: add "test" to package.json `files` and this fails.
    expect(files.some((f) => f.startsWith('test/'))).toBe(false);
    expect(files.some((f) => f.startsWith('.mcp-recorder/'))).toBe(false);
    expect(files.some((f) => f.endsWith('evidence.jsonl') || f.endsWith('evidence.db'))).toBe(false);
  });
});
