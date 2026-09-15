import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdirSync, mkdtempSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ensureDataDir } from '../src/config.js';

describe('ensureDataDir', () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'mcp-recorder-config-'));
  });
  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it.skipIf(process.platform === 'win32')('creates a missing data dir with mode 0700', () => {
    const dataDir = join(dir, 'a', 'b');
    ensureDataDir(dataDir);
    expect(statSync(dataDir).mode & 0o777).toBe(0o700);
  });

  it.skipIf(process.platform === 'win32')(
    'tightens a data dir that already exists with a wider mode (it holds the signing key)',
    () => {
      const dataDir = join(dir, 'loose');
      mkdirSync(dataDir, { mode: 0o755 });
      expect(statSync(dataDir).mode & 0o777).toBe(0o755);
      ensureDataDir(dataDir);
      expect(statSync(dataDir).mode & 0o777).toBe(0o700);
    },
  );
});
