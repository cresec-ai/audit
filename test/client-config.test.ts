/**
 * `src/setup/client-config.ts` — Claude Desktop config path resolution,
 * focused on the win32 MSIX (Microsoft Store) fallback. `claudeDesktopConfigPath`
 * takes `fileExists`/`listDir`/`platform`/`env` as injectable parameters (the
 * same pattern `src/proxy/spawn.ts` uses), so the win32 branch is fully
 * testable on any host by simulating `platform: 'win32'` — no real Windows
 * machine, and no `describe.skipIf`, required.
 */
import { describe, expect, it } from 'vitest';
import { claudeDesktopConfigPath, resolveClientConfigPath } from '../src/setup/client-config.js';

const WIN_ENV = { APPDATA: 'C:\\Users\\joni\\AppData\\Roaming', LOCALAPPDATA: 'C:\\Users\\joni\\AppData\\Local' };
const APPDATA_PRIMARY = 'C:\\Users\\joni\\AppData\\Roaming\\Claude\\claude_desktop_config.json';
const PACKAGES_DIR = 'C:\\Users\\joni\\AppData\\Local\\Packages';

function msixPath(pkg: string): string {
  return `${PACKAGES_DIR}\\${pkg}\\LocalCache\\Roaming\\Claude\\claude_desktop_config.json`;
}

function existsAmong(paths: readonly string[]): (p: string) => boolean {
  const set = new Set(paths);
  return (p) => set.has(p);
}

describe('claudeDesktopConfigPath — win32 MSIX fallback', () => {
  it('darwin: unaffected by any of this, ignores fileExists/listDir entirely', () => {
    const resolved = claudeDesktopConfigPath(
      () => {
        throw new Error('must not be called on darwin');
      },
      () => {
        throw new Error('must not be called on darwin');
      },
      'darwin',
      {},
    );
    expect(resolved.path).toMatch(/Library\/Application Support\/Claude\/claude_desktop_config\.json$/);
    expect(resolved.note).toBeUndefined();
  });

  it('win32: %APPDATA%\\Claude\\... is preferred outright when it exists — MSIX never even looked up', () => {
    const readdir = (): string[] => {
      throw new Error('must not be called when the primary config already exists');
    };
    const resolved = claudeDesktopConfigPath(existsAmong([APPDATA_PRIMARY]), readdir, 'win32', WIN_ENV);
    expect(resolved).toEqual({ path: APPDATA_PRIMARY });
  });

  it('win32: primary missing, exactly one Claude_* MSIX package with a config — uses it, with a note', () => {
    const pkg = msixPath('Claude_pzs8sxrjxfjjc');
    const readdir = (p: string): string[] => {
      expect(p).toBe(PACKAGES_DIR);
      return ['Claude_pzs8sxrjxfjjc'];
    };
    const resolved = claudeDesktopConfigPath(existsAmong([pkg]), readdir, 'win32', WIN_ENV);
    expect(resolved.path).toBe(pkg);
    expect(resolved.note).toContain(pkg);
    expect(resolved.note).toMatch(/MSIX|Microsoft Store/);
  });

  it('win32: primary missing, several Claude_* MSIX matches exist — throws naming them, tells to use --config', () => {
    const pkg1 = msixPath('Claude_aaaa');
    const pkg2 = msixPath('Claude_bbbb');
    const readdir = (): string[] => ['Claude_aaaa', 'Claude_bbbb'];
    expect(() => claudeDesktopConfigPath(existsAmong([pkg1, pkg2]), readdir, 'win32', WIN_ENV)).toThrow(/--config/);
    try {
      claudeDesktopConfigPath(existsAmong([pkg1, pkg2]), readdir, 'win32', WIN_ENV);
      expect.unreachable();
    } catch (cause) {
      const msg = cause instanceof Error ? cause.message : String(cause);
      expect(msg).toContain(pkg1);
      expect(msg).toContain(pkg2);
    }
  });

  it('win32: neither the primary nor any Claude_* MSIX package exists — falls back to the primary path, with a note', () => {
    const readdir = (): string[] => ['Claude_pzs8sxrjxfjjc']; // dir matches, but its config file doesn't exist
    const resolved = claudeDesktopConfigPath(() => false, readdir, 'win32', WIN_ENV);
    expect(resolved.path).toBe(APPDATA_PRIMARY);
    expect(resolved.note).toContain(msixPath('Claude_pzs8sxrjxfjjc'));
  });

  it('win32: no Packages dir at all (readdir throws) — falls back to the primary path, with a note, no crash', () => {
    const readdir = (): string[] => {
      throw new Error('ENOENT');
    };
    const resolved = claudeDesktopConfigPath(() => false, readdir, 'win32', WIN_ENV);
    expect(resolved.path).toBe(APPDATA_PRIMARY);
    expect(resolved.note).toBeDefined();
  });

  it('win32: only non-Claude_ package directories present — treated the same as none found', () => {
    const readdir = (): string[] => ['SomeOtherVendor_abc123', 'Claude'];
    const resolved = claudeDesktopConfigPath(() => false, readdir, 'win32', WIN_ENV);
    expect(resolved.path).toBe(APPDATA_PRIMARY);
  });

  it('win32: falls back to homedir()-derived defaults when APPDATA/LOCALAPPDATA are unset', () => {
    const resolved = claudeDesktopConfigPath(() => false, () => [], 'win32', {});
    expect(resolved.path).toMatch(/AppData[\\/]Roaming[\\/]Claude[\\/]claude_desktop_config\.json$/);
  });
});

/* --------------------- resolveClientConfigPath — win32 -------------------- */

// resolveClientConfigPath calls the *real* claudeDesktopConfigPath()
// internally (platform defaults to process.platform, not injectable through
// resolveClientConfigPath's own signature — only fileExists is), so this
// only makes sense to run on an actual win32 host; see the platform-injected
// assertions above for the portable coverage of the same MSIX logic.
describe.skipIf(process.platform !== 'win32')('resolveClientConfigPath — win32 (not WSL)', () => {
  // On native win32, detectWsl() always returns inWsl: false (it only ever
  // returns true on linux), so resolveClientConfigPath's WSL fallback is a
  // no-op there and claudeDesktopConfigPath's own MSIX resolution decides
  // the path outright — including its note, which must survive the pass
  // through resolveWithWslFallback's early-return branch.
  it('propagates the MSIX note through when running natively on win32 (inWsl: false)', () => {
    // Only fileExists is injectable here, so the primary path and the
    // Packages listing come from the runner's real environment: with nothing
    // "existing", the result is the real %APPDATA% primary plus the note that
    // the MSIX location was checked — which is exactly what must survive
    // resolveWithWslFallback's early return.
    const resolved = resolveClientConfigPath(
      'claude-desktop',
      undefined,
      '/cwd',
      { inWsl: false, homeCandidates: () => [] },
      () => false,
    );
    expect(resolved.path).toMatch(/AppData[\\/]Roaming[\\/]Claude[\\/]claude_desktop_config\.json$/);
    expect(resolved.note).toMatch(/MSIX|Microsoft Store/);
  });
});
