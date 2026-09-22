/**
 * What `npm pack` ships. Cheap (a dry run, no network) and worth pinning:
 * `receiver/` was absent from `files` for months, so a receiver operator
 * needed a repository clone, and the Dockerfile that runs it could not have
 * been built from the published tarball either.
 */

import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
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
    // The enforcement-first entry points, and the doc README and
    // docs/gateway.md both link to.
    expect(files).toContain('dist/doctor/run.js');
    expect(files).toContain('dist/policy/starter.js');
    expect(files).toContain('docs/first-run.md');
  });

  it('is publishable so a STRANGER can npx it', () => {
    const pkg = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8')) as {
      name: string;
      bin: Record<string, string>;
      publishConfig?: { access?: string };
      scripts: Record<string, string>;
    };
    // `@edut/...` is SCOPED, and npm defaults a scoped package to
    // `restricted` — which a stranger cannot install at all, and which a free
    // account cannot publish. `npx @edut/mcp-recorder` working for someone
    // who has never heard of us is the whole pitch, so pin it.
    expect(pkg.name.startsWith('@')).toBe(true);
    expect(pkg.publishConfig?.access).toBe('public');
    // The bin npx resolves, present in the tarball, with a shebang.
    expect(files).toContain(pkg.bin['mcp-recorder']);
    expect(readFileSync(join(ROOT, pkg.bin['mcp-recorder'] as string), 'utf8').startsWith('#!/usr/bin/env node')).toBe(true);
    // AGENTS.md's first rule: none of these script names may exist, or npm
    // runs a nested install inside a git clone and the documented
    // `npm install -g github:cresec-ai/audit#main` fails in global mode.
    for (const banned of ['build', 'prepare', 'prepack', 'install', 'postinstall']) {
      expect(banned in pkg.scripts, banned).toBe(false);
    }
  });

  it('never ships evidence, tests or the dogfood store', () => {
    // NEGATIVE CONTROL: add "test" to package.json `files` and this fails.
    expect(files.some((f) => f.startsWith('test/'))).toBe(false);
    expect(files.some((f) => f.startsWith('.mcp-recorder/'))).toBe(false);
    expect(files.some((f) => f.endsWith('evidence.jsonl') || f.endsWith('evidence.db'))).toBe(false);
  });
});
