import { mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync, spawnSync } from 'node:child_process';
import { afterEach, describe, expect, it } from 'vitest';
import { generatePublicEvidence, sampleEvents, SAMPLE_LIMITATIONS, sourceProvenance } from '../demo/public-evidence.js';
import { BUNDLE_FILES } from '../src/export/bundle.js';
import { sha256Hex } from '../src/chain/hash.js';
import type { ChainRecord } from '../src/schema/events.js';

const temporary: string[] = [];
const published = fileURLToPath(new URL('../demo/fixtures/public-evidence/v1/', import.meta.url));

afterEach(() => {
  for (const path of temporary.splice(0)) rmSync(path, { recursive: true, force: true });
});

function assertArtifact(directory: string) {
  const metadata = JSON.parse(readFileSync(join(directory, 'display.json'), 'utf8')) as Awaited<ReturnType<typeof generatePublicEvidence>>;
  expect(metadata.sample).toBe(true);
  expect(metadata.mode).toBe('synthetic-observation');
  expect(metadata.actor_status).toBe('unattributed');
  expect(metadata.signer.independently_trusted).toBe(false);
  expect(metadata.verification.kind).toBe('precomputed');
  expect(metadata.generator.source_state).toMatch(/^(clean|dirty)$/);
  expect(metadata.generator.source_changes).toBeInstanceOf(Array);
  expect(metadata.generator.source_note).toContain('installed dependencies and the environment are not attested');
  expect(metadata.limitations).toEqual(SAMPLE_LIMITATIONS);
  expect(readdirSync(directory).sort()).toEqual(['display.json', 'intact', 'tampered']);
  for (const kind of ['intact', 'tampered'] as const) {
    const bundle = join(directory, kind);
    expect(readdirSync(bundle).sort()).toEqual(Object.values(BUNDLE_FILES).sort());
    for (const filename of Object.values(BUNDLE_FILES)) {
      const contents = readFileSync(join(bundle, filename), 'utf8');
      expect(sha256Hex(contents)).toBe(metadata.artifact_sha256[`${kind}/${filename}`]);
      expect(contents).not.toMatch(/SYNTHETIC_(?:ARGUMENT|RESULT)_|BEGIN PRIVATE KEY|identity\.key/);
    }
    const result = spawnSync(process.execPath, ['verify.cjs'], { cwd: bundle, encoding: 'utf8' });
    expect(result.error).toBeUndefined();
    expect(result.status).toBe(kind === 'intact' ? 0 : 1);
    expect(result.stdout).toBe(metadata.verification[kind].stdout);
    expect(result.stderr).toBe(metadata.verification[kind].stderr);
  }
  const records = readFileSync(join(directory, 'intact/events.jsonl'), 'utf8').trim().split('\n')
    .map((line) => JSON.parse(line) as ChainRecord);
  expect(records.map(({ event }) => event)).toEqual(sampleEvents());
  for (const { event } of records) {
    expect(event.identity.actor).toBeUndefined();
    expect(event.identity.actor_verified).toBeUndefined();
    expect(event.identity.os_user).toBeUndefined();
    expect(event.identity.hostname).toBeUndefined();
  }
  const readme = readFileSync(join(directory, 'intact/README.txt'), 'utf8');
  expect(readme).toContain('does not prove all real activity was recorded');
  expect(readme).toContain('unsigned informational metadata');
  // This sample ships the exporter's verifier, not a website-specific fork.
  expect(readFileSync(join(directory, 'intact/verify.cjs'), 'utf8'))
    .toBe(readFileSync(join(directory, 'tampered/verify.cjs'), 'utf8'));
  return metadata;
}

describe('public synthetic evidence sample', () => {
  it('fresh generation proves intact acceptance and deliberate-tamper rejection without payloads or private keys', async () => {
    const parent = mkdtempSync(join(tmpdir(), 'public-evidence-test-'));
    temporary.push(parent);
    const out = join(parent, 'sample');
    await generatePublicEvidence(out);
    const fresh = assertArtifact(out);
    expect(readFileSync(join(out, 'intact/verify.cjs'), 'utf8'))
      .toBe(readFileSync(join(published, 'intact/verify.cjs'), 'utf8'));
    for (const [path, hash] of Object.entries(fresh.generator.source_sha256)) {
      expect(sha256Hex(readFileSync(fileURLToPath(new URL(`../${path}`, import.meta.url))))).toBe(hash);
    }
    await expect(generatePublicEvidence(out)).rejects.toThrow();
  });

  it('published fixture remains reproducibly verifiable with hashes matching the display contract', () => {
    assertArtifact(published);
  });

  it('records omitted runtime files, staged-then-edited bytes, deletions and new source relative to the same base', () => {
    const root = mkdtempSync(join(tmpdir(), 'public-evidence-provenance-'));
    temporary.push(root);
    const git = (args: string[]) => execFileSync('git', args, { cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
    git(['init']);
    mkdirSync(join(root, 'src/store'), { recursive: true });
    mkdirSync(join(root, 'src/schema'), { recursive: true });
    writeFileSync(join(root, '.gitignore'), 'ignored.cache\n');
    writeFileSync(join(root, 'src/store/jsonl.ts'), 'original store\n');
    writeFileSync(join(root, 'src/schema/events.ts'), 'original schema\n');
    writeFileSync(join(root, 'deleted.ts'), 'original helper\n');
    git(['add', '.']);
    git(['-c', 'user.name=Fixture Test', '-c', 'user.email=fixture@example.invalid',
      '-c', 'commit.gpgsign=false', 'commit', '-m', 'Base source']);
    const clean = sourceProvenance(root);
    expect(clean.source_state).toBe('clean');
    expect(clean.source_changes).toEqual([]);

    writeFileSync(join(root, 'src/store/jsonl.ts'), 'changed store\n');
    writeFileSync(join(root, 'src/schema/events.ts'), 'staged schema\n');
    git(['add', 'src/schema/events.ts']);
    writeFileSync(join(root, 'src/schema/events.ts'), 'actual working-tree schema\n');
    writeFileSync(join(root, 'new helper.ts'), 'new local dependency\n');
    writeFileSync(join(root, 'ignored.cache'), 'installation state is outside the snapshot\n');
    rmSync(join(root, 'deleted.ts'));
    const dirty = sourceProvenance(root);
    expect(dirty.source_base_commit).toBe(clean.source_base_commit);
    expect(dirty.source_state).toBe('dirty');
    expect(dirty.source_changes.map(({ path }) => path)).toEqual([
      'deleted.ts', 'new helper.ts', 'src/schema/events.ts', 'src/store/jsonl.ts',
    ]);
    expect(dirty.source_changes[0]).toEqual({ path: 'deleted.ts', kind: 'deleted', sha256: null, mode: null });
    expect(dirty.source_sha256['src/store/jsonl.ts']).toBe(sha256Hex('changed store\n'));
    expect(dirty.source_sha256['src/schema/events.ts']).toBe(sha256Hex('actual working-tree schema\n'));
    expect(dirty.source_sha256['new helper.ts']).toBe(sha256Hex('new local dependency\n'));
    expect(dirty.source_note).toContain('Ignored files, installed dependencies and the environment are not attested');

    // A second mutation to the formerly omitted store changes provenance while
    // the base commit, entrypoint and every other source file stay unchanged.
    writeFileSync(join(root, 'src/store/jsonl.ts'), 'another store implementation\n');
    const changedAgain = sourceProvenance(root);
    expect(changedAgain.source_base_commit).toBe(dirty.source_base_commit);
    expect(changedAgain.source_sha256['src/store/jsonl.ts']).not.toBe(dirty.source_sha256['src/store/jsonl.ts']);
  });

  it.skipIf(process.platform === 'win32')('records symlink targets without following them outside the source tree', () => {
    const root = mkdtempSync(join(tmpdir(), 'public-evidence-provenance-link-'));
    temporary.push(root);
    const git = (args: string[]) => execFileSync('git', args, { cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
    git(['init']);
    git(['-c', 'user.name=Fixture Test', '-c', 'user.email=fixture@example.invalid',
      '-c', 'commit.gpgsign=false', 'commit', '--allow-empty', '-m', 'Base source']);
    symlinkSync('missing-target', join(root, 'helper.ts'));
    expect(sourceProvenance(root).source_changes).toEqual([
      expect.objectContaining({ path: 'helper.ts', kind: 'symlink', sha256: sha256Hex('missing-target') }),
    ]);
  });
});
