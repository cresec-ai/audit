import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
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
    'leaves a pre-existing wider-mode dir alone but warns once (it may be shared on purpose)',
    () => {
      const dataDir = join(dir, 'shared');
      mkdirSync(dataDir, { mode: 0o755 });
      const stderrSpy = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
      try {
        ensureDataDir(dataDir);
        expect(statSync(dataDir).mode & 0o777).toBe(0o755);
        expect(
          stderrSpy.mock.calls.some((call) => /group\/world accessible \(mode 755\)/.test(String(call[0]))),
        ).toBe(true);
      } finally {
        stderrSpy.mockRestore();
      }
    },
  );

  it.skipIf(process.platform === 'win32')('does not warn about a pre-existing private dir', () => {
    const dataDir = join(dir, 'private');
    mkdirSync(dataDir, { mode: 0o700 });
    const stderrSpy = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
    try {
      ensureDataDir(dataDir);
      expect(stderrSpy).not.toHaveBeenCalled();
    } finally {
      stderrSpy.mockRestore();
    }
  });
});
