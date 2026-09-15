import { homedir } from 'node:os';
import { describe, expect, it } from 'vitest';
import type { ClientKind } from '../src/setup/client-config.js';
import { resolveClientConfigPath } from '../src/setup/client-config.js';
import {
  chooseWrapper,
  detectWsl,
  isWindowsMountPath,
  windowsClientConfigCandidates,
  windowsHomeCandidates,
} from '../src/setup/wsl.js';
import type { SpawnSyncFn, SpawnSyncResult } from '../src/setup/wsl.js';

/* ------------------------------- detectWsl -------------------------------- */

describe('detectWsl', () => {
  const noProcVersion = (): string => {
    throw new Error('ENOENT');
  };

  it('false outright on a non-linux platform, even with every WSL marker set', () => {
    const result = detectWsl(
      { WSL_DISTRO_NAME: 'Ubuntu', WSL_INTEROP: '/run/WSL/1_interop' },
      () => 'Linux version 5.15.90.1-microsoft-standard-WSL2',
      'darwin',
    );
    expect(result).toEqual({ inWsl: false });
  });

  it('false on linux with none of the WSL markers present', () => {
    const result = detectWsl({}, noProcVersion, 'linux');
    expect(result).toEqual({ inWsl: false });
  });

  it('true via WSL_DISTRO_NAME, and carries the distro name', () => {
    const result = detectWsl({ WSL_DISTRO_NAME: 'Ubuntu-22.04' }, noProcVersion, 'linux');
    expect(result).toEqual({ inWsl: true, distro: 'Ubuntu-22.04' });
  });

  it('true via /proc/version mentioning "microsoft" case-insensitively, no distro', () => {
    const result = detectWsl({}, () => 'Linux version 5.15.0 (MICROSOFT@buildhost)', 'linux', () => false);
    expect(result).toEqual({ inWsl: true });
  });

  it('a container on a Microsoft kernel (Docker Desktop WSL2 backend) is NOT WSL', () => {
    // /proc/version matches, but /.dockerenv exists and no WSL env marker is set.
    const kernel = (): string => 'Linux version 5.15.153.1-microsoft-standard-WSL2';
    const dockerenv = (p: string): boolean => p === '/.dockerenv';
    expect(detectWsl({}, kernel, 'linux', dockerenv)).toEqual({ inWsl: false });
    const podman = (p: string): boolean => p === '/run/.containerenv';
    expect(detectWsl({}, kernel, 'linux', podman)).toEqual({ inWsl: false });
  });

  it('the env markers still win inside a container (a real WSL session that happens to run in one)', () => {
    const kernel = (): string => 'Linux version 5.15.153.1-microsoft-standard-WSL2';
    const dockerenv = (p: string): boolean => p === '/.dockerenv';
    expect(detectWsl({ WSL_DISTRO_NAME: 'Ubuntu' }, kernel, 'linux', dockerenv)).toEqual({
      inWsl: true,
      distro: 'Ubuntu',
    });
    expect(detectWsl({ WSL_INTEROP: '/run/WSL/1_interop' }, kernel, 'linux', dockerenv)).toEqual({ inWsl: true });
  });

  it('an exists() probe that throws is treated as "no marker"', () => {
    const kernel = (): string => 'Linux version 5.15.0-microsoft-standard';
    const boom = (): boolean => {
      throw new Error('EACCES');
    };
    expect(detectWsl({}, kernel, 'linux', boom)).toEqual({ inWsl: true });
  });

  it('true via WSL_INTEROP alone', () => {
    const result = detectWsl({ WSL_INTEROP: '/run/WSL/8_interop' }, noProcVersion, 'linux');
    expect(result).toEqual({ inWsl: true });
  });

  it('a /proc/version read that throws (e.g. file missing) is treated as no match, not an error', () => {
    expect(() => detectWsl({}, noProcVersion, 'linux')).not.toThrow();
  });

  it('an empty WSL_DISTRO_NAME does not count as set', () => {
    const result = detectWsl({ WSL_DISTRO_NAME: '' }, noProcVersion, 'linux');
    expect(result).toEqual({ inWsl: false });
  });
});

/* --------------------------- windowsHomeCandidates ------------------------ */

function ok(stdout: string): SpawnSyncResult {
  return { status: 0, stdout, stderr: '' };
}
function fail(): SpawnSyncResult {
  return { status: 1, stdout: '', stderr: 'boom' };
}
function notFound(): SpawnSyncResult {
  return { status: null, stdout: '', stderr: '', error: new Error('ENOENT') };
}

describe('windowsHomeCandidates', () => {
  it('cmd.exe + wslpath path: asks %USERPROFILE% then converts it with wslpath -u', () => {
    const calls: Array<{ command: string; args: string[] }> = [];
    const spawnSync: SpawnSyncFn = (command, args) => {
      calls.push({ command, args });
      if (command === 'cmd.exe') return ok('C:\\Users\\joni\r\n');
      if (command === 'wslpath') return ok('/mnt/c/Users/joni\n');
      throw new Error(`unexpected command ${command}`);
    };
    const homes = windowsHomeCandidates({ spawnSync, existsSync: () => false, readdirSync: () => [] });
    expect(homes).toEqual(['/mnt/c/Users/joni']);
    expect(calls[0]).toEqual({ command: 'cmd.exe', args: ['/c', 'echo %USERPROFILE%'] });
    expect(calls[1]!.command).toBe('wslpath');
  });

  it('falls back to /mnt/<drive>/... when cmd.exe works but wslpath is unavailable', () => {
    const spawnSync: SpawnSyncFn = (command) => {
      if (command === 'cmd.exe') return ok('C:\\Users\\joni\n');
      if (command === 'wslpath') return notFound();
      throw new Error(`unexpected command ${command}`);
    };
    const homes = windowsHomeCandidates({ spawnSync, existsSync: () => false, readdirSync: () => [] });
    expect(homes).toEqual(['/mnt/c/Users/joni']);
  });

  it('falls back to the absolute cmd.exe path under /mnt/c when "cmd.exe" alone is not on PATH', () => {
    const calls: string[] = [];
    const spawnSync: SpawnSyncFn = (command) => {
      calls.push(command);
      if (command === 'cmd.exe') return notFound();
      if (command === '/mnt/c/Windows/System32/cmd.exe') return ok('C:\\Users\\joni\n');
      if (command === 'wslpath') return ok('/mnt/c/Users/joni\n');
      throw new Error(`unexpected command ${command}`);
    };
    const exists = (p: string): boolean => p === '/mnt/c/Windows/System32/cmd.exe';
    const homes = windowsHomeCandidates({ spawnSync, existsSync: exists, readdirSync: () => [] });
    expect(homes).toEqual(['/mnt/c/Users/joni']);
    expect(calls).toContain('/mnt/c/Windows/System32/cmd.exe');
  });

  it('glob fallback: lists /mnt/c/Users when cmd.exe cannot be run at all, excluding non-user dirs', () => {
    const spawnSync: SpawnSyncFn = () => notFound();
    const exists = (p: string): boolean => p === '/mnt/c/Users';
    const readdir = (p: string): string[] => {
      expect(p).toBe('/mnt/c/Users');
      return ['joni', 'Default', 'Default User', 'Public', 'All Users', '.dotdir'];
    };
    const homes = windowsHomeCandidates({ spawnSync, existsSync: exists, readdirSync: readdir });
    expect(homes).toEqual(['/mnt/c/Users/joni']);
  });

  it('glob fallback returns nothing when /mnt/c/Users itself does not exist', () => {
    const spawnSync: SpawnSyncFn = () => notFound();
    const homes = windowsHomeCandidates({ spawnSync, existsSync: () => false, readdirSync: () => [] });
    expect(homes).toEqual([]);
  });

  it('a non-zero cmd.exe exit or an unexpanded %USERPROFILE% is treated as failure, falls through to glob', () => {
    const spawnSync: SpawnSyncFn = (command) => {
      if (command === 'cmd.exe') return fail();
      return notFound();
    };
    const exists = (p: string): boolean => p === '/mnt/c/Users';
    const readdir = (): string[] => ['joni'];
    const homes = windowsHomeCandidates({ spawnSync, existsSync: exists, readdirSync: readdir });
    expect(homes).toEqual(['/mnt/c/Users/joni']);
  });

  it('when Windows answers, /mnt/c/Users is never listed: another account is not a candidate', () => {
    // If it were, an operator whose own client config does not exist yet
    // would have setup silently edit the other account's config.
    const spawnSync: SpawnSyncFn = (command) => {
      if (command === 'cmd.exe') return ok('C:\\Users\\joni\n');
      if (command === 'wslpath') return ok('/mnt/c/Users/joni\n');
      return notFound();
    };
    const exists = (p: string): boolean => p === '/mnt/c/Users';
    let listed = false;
    const readdir = (): string[] => {
      listed = true;
      return ['joni', 'other'];
    };
    const homes = windowsHomeCandidates({ spawnSync, existsSync: exists, readdirSync: readdir });
    expect(homes).toEqual(['/mnt/c/Users/joni']);
    expect(listed).toBe(false);
  });

  it('the glob fallback de-duplicates its own listing', () => {
    const spawnSync: SpawnSyncFn = () => notFound();
    const exists = (p: string): boolean => p === '/mnt/c/Users';
    const readdir = (): string[] => ['joni', 'other', 'joni'];
    const homes = windowsHomeCandidates({ spawnSync, existsSync: exists, readdirSync: readdir });
    expect(homes).toEqual(['/mnt/c/Users/joni', '/mnt/c/Users/other']);
  });

  it('never touches the real filesystem or spawns a real process when deps are fully injected', () => {
    // Regression guard: if this test ever calls the real cmd.exe/wslpath it
    // will hang or fail in CI; asserting deterministic output from fakes is
    // the point.
    const homes = windowsHomeCandidates({
      spawnSync: () => notFound(),
      existsSync: () => false,
      readdirSync: () => {
        throw new Error('should not be called when /mnt/c/Users does not "exist"');
      },
    });
    expect(homes).toEqual([]);
  });
});

/* ----------------------- windowsClientConfigCandidates -------------------- */

describe('windowsClientConfigCandidates', () => {
  it('claude-desktop: <home>/AppData/Roaming/Claude/claude_desktop_config.json', () => {
    const out = windowsClientConfigCandidates('claude-desktop', ['/mnt/c/Users/joni']);
    expect(out).toEqual(['/mnt/c/Users/joni/AppData/Roaming/Claude/claude_desktop_config.json']);
  });

  it('cursor: <home>/.cursor/mcp.json', () => {
    const out = windowsClientConfigCandidates('cursor', ['/mnt/c/Users/joni', '/mnt/c/Users/bob']);
    expect(out).toEqual(['/mnt/c/Users/joni/.cursor/mcp.json', '/mnt/c/Users/bob/.cursor/mcp.json']);
  });

  it('claude-code: no Windows-side config, always empty', () => {
    const out = windowsClientConfigCandidates('claude-code', ['/mnt/c/Users/joni']);
    expect(out).toEqual([]);
  });

  it('claude-desktop: no readdirFn given defaults to the real fs and never throws when the Packages dir is absent', () => {
    // Regression guard: on a real (non-Windows) test machine
    // /mnt/c/Users/joni/AppData/Local/Packages doesn't exist — the default
    // readdirSync throws ENOENT, which must be swallowed, not propagated.
    const out = windowsClientConfigCandidates('claude-desktop', ['/mnt/c/Users/joni']);
    expect(out).toEqual(['/mnt/c/Users/joni/AppData/Roaming/Claude/claude_desktop_config.json']);
  });

  it('claude-desktop: appends every Claude_* MSIX package match after the ordinary Roaming path', () => {
    const readdir = (p: string): string[] => {
      expect(p).toBe('/mnt/c/Users/joni/AppData/Local/Packages');
      return ['Claude_pzs8sxrjxfjjc', 'SomeOtherVendor_abc123', 'Claude_anotherhash'];
    };
    const out = windowsClientConfigCandidates('claude-desktop', ['/mnt/c/Users/joni'], readdir);
    expect(out).toEqual([
      '/mnt/c/Users/joni/AppData/Roaming/Claude/claude_desktop_config.json',
      '/mnt/c/Users/joni/AppData/Local/Packages/Claude_anotherhash/LocalCache/Roaming/Claude/claude_desktop_config.json',
      '/mnt/c/Users/joni/AppData/Local/Packages/Claude_pzs8sxrjxfjjc/LocalCache/Roaming/Claude/claude_desktop_config.json',
    ]);
  });

  it('claude-desktop: per home directory, both the Roaming path and that home\'s own MSIX matches', () => {
    const readdir = (p: string): string[] =>
      p === '/mnt/c/Users/joni/AppData/Local/Packages' ? ['Claude_joniHash'] : [];
    const out = windowsClientConfigCandidates('claude-desktop', ['/mnt/c/Users/joni', '/mnt/c/Users/bob'], readdir);
    expect(out).toEqual([
      '/mnt/c/Users/joni/AppData/Roaming/Claude/claude_desktop_config.json',
      '/mnt/c/Users/joni/AppData/Local/Packages/Claude_joniHash/LocalCache/Roaming/Claude/claude_desktop_config.json',
      '/mnt/c/Users/bob/AppData/Roaming/Claude/claude_desktop_config.json',
    ]);
  });

  it('claude-desktop: a readdir that throws (missing Packages dir) yields no MSIX candidates, not an error', () => {
    const readdir = (): string[] => {
      throw new Error('ENOENT');
    };
    const out = windowsClientConfigCandidates('claude-desktop', ['/mnt/c/Users/joni'], readdir);
    expect(out).toEqual(['/mnt/c/Users/joni/AppData/Roaming/Claude/claude_desktop_config.json']);
  });

  it('cursor and claude-code ignore the readdirFn parameter entirely', () => {
    const readdir = (): string[] => {
      throw new Error('must not be called for cursor/claude-code');
    };
    expect(windowsClientConfigCandidates('cursor', ['/mnt/c/Users/joni'], readdir)).toEqual([
      '/mnt/c/Users/joni/.cursor/mcp.json',
    ]);
    expect(windowsClientConfigCandidates('claude-code', ['/mnt/c/Users/joni'], readdir)).toEqual([]);
  });
});

/* ------------------------------ isWindowsMountPath ------------------------- */

describe('isWindowsMountPath', () => {
  it.each([
    ['/mnt/c/Users/joni/AppData/Roaming/Claude/claude_desktop_config.json', true],
    ['/mnt/d/stuff', true],
    ['/mnt/c', true],
    ['/home/joni/.config/Claude/claude_desktop_config.json', false],
    ['/mnt/cool/not-a-drive', false],
    ['/mnt', false],
    ['relative/mnt/c/x', false],
  ])('%s -> %s', (p, expected) => {
    expect(isWindowsMountPath(p)).toBe(expected);
  });
});

/* -------------------------------- chooseWrapper ---------------------------- */

describe('chooseWrapper', () => {
  it('an explicit choice always wins, regardless of WSL/path', () => {
    expect(chooseWrapper('local', true, '/mnt/c/Users/joni/AppData/Roaming/Claude/claude_desktop_config.json')).toBe(
      'local',
    );
    expect(chooseWrapper('npx', false, '/home/joni/.claude.json')).toBe('npx');
    expect(chooseWrapper('wsl', false, '/home/joni/.claude.json')).toBe('wsl');
  });

  it('auto-selects wsl only when inWsl AND the config is on a Windows mount', () => {
    expect(
      chooseWrapper(undefined, true, '/mnt/c/Users/joni/AppData/Roaming/Claude/claude_desktop_config.json'),
    ).toBe('wsl');
  });

  it('defaults to local when not in WSL, even for a /mnt path', () => {
    expect(chooseWrapper(undefined, false, '/mnt/c/Users/joni/AppData/Roaming/Claude/claude_desktop_config.json')).toBe(
      'local',
    );
  });

  it('defaults to local when in WSL but the config is a Linux-side path', () => {
    expect(chooseWrapper(undefined, true, '/home/joni/.claude.json')).toBe('local');
  });
});

/* ---------------------- resolveClientConfigPath (WSL) ---------------------- */

// "In WSL" is inherently a Linux-only concept (detectWsl itself never
// returns true off Linux) and the expected Linux-side paths below assume
// the Linux/else branch of claudeDesktopConfigPath()'s own platform switch
// (unmockable — it reads process.platform directly), so these only make
// sense to run on Linux.
describe.skipIf(process.platform !== 'linux')('resolveClientConfigPath — WSL fallback', () => {
  // Real homedir() — resolveClientConfigPath calls the real os.homedir()
  // internally (it's not injectable, only fileExists/homeCandidates are),
  // so the Linux-side paths this test asserts against must match it too.
  const HOME = homedir();
  const linuxDesktopPath = `${HOME}/.config/Claude/claude_desktop_config.json`;
  const winHome1 = '/mnt/c/Users/joni';
  const winHome2 = '/mnt/c/Users/jwork';
  const winDesktop1 = `${winHome1}/AppData/Roaming/Claude/claude_desktop_config.json`;
  const winDesktop2 = `${winHome2}/AppData/Roaming/Claude/claude_desktop_config.json`;

  function existsAmong(paths: readonly string[]): (p: string) => boolean {
    const set = new Set(paths);
    return (p) => set.has(p);
  }

  it('not in WSL: returns the Linux path even though it does not exist (no fallback attempted)', () => {
    const called: string[] = [];
    const resolved = resolveClientConfigPath(
      'claude-desktop',
      undefined,
      '/cwd',
      { inWsl: false, homeCandidates: () => (called.push('called'), [winHome1]) },
      existsAmong([winDesktop1]),
    );
    expect(resolved).toEqual({ path: linuxDesktopPath });
    expect(called).toEqual([]); // never even asked for Windows homes
  });

  it('in WSL, Linux-side path already exists: uses it, never calls homeCandidates', () => {
    const called: string[] = [];
    const resolved = resolveClientConfigPath(
      'claude-desktop',
      undefined,
      '/cwd',
      { inWsl: true, homeCandidates: () => (called.push('called'), [winHome1]) },
      existsAmong([linuxDesktopPath]),
    );
    expect(resolved).toEqual({ path: linuxDesktopPath });
    expect(called).toEqual([]);
  });

  it('in WSL, Linux-side missing, exactly one Windows candidate exists: uses it with a note', () => {
    const resolved = resolveClientConfigPath(
      'claude-desktop',
      undefined,
      '/cwd',
      { inWsl: true, homeCandidates: () => [winHome1] },
      existsAmong([winDesktop1]),
    );
    expect(resolved.path).toBe(winDesktop1);
    expect(resolved.note).toMatch(/Claude Desktop/);
    expect(resolved.note).toContain(winDesktop1);
  });

  it('in WSL, Linux-side missing, several Windows candidates exist: throws listing them, tells to use --config', () => {
    expect(() =>
      resolveClientConfigPath(
        'claude-desktop',
        undefined,
        '/cwd',
        { inWsl: true, homeCandidates: () => [winHome1, winHome2] },
        existsAmong([winDesktop1, winDesktop2]),
      ),
    ).toThrow(/--config/);
    try {
      resolveClientConfigPath(
        'claude-desktop',
        undefined,
        '/cwd',
        { inWsl: true, homeCandidates: () => [winHome1, winHome2] },
        existsAmong([winDesktop1, winDesktop2]),
      );
      expect.unreachable();
    } catch (cause) {
      const msg = cause instanceof Error ? cause.message : String(cause);
      expect(msg).toContain(winDesktop1);
      expect(msg).toContain(winDesktop2);
    }
  });

  it('in WSL, Linux-side missing, no Windows candidate exists: keeps the Linux path, notes what was checked', () => {
    const resolved = resolveClientConfigPath(
      'claude-desktop',
      undefined,
      '/cwd',
      { inWsl: true, homeCandidates: () => [winHome1] },
      existsAmong([]),
    );
    expect(resolved.path).toBe(linuxDesktopPath);
    expect(resolved.note).toContain(winDesktop1);
  });

  it('cursor gets the same treatment (~/.cursor/mcp.json on each side)', () => {
    const winCursor = `${winHome1}/.cursor/mcp.json`;
    const resolved = resolveClientConfigPath(
      'cursor',
      undefined,
      '/cwd',
      { inWsl: true, homeCandidates: () => [winHome1] },
      existsAmong([winCursor]),
    );
    expect(resolved.path).toBe(winCursor);
    expect(resolved.note).toMatch(/Cursor/);
  });

  it('claude-code never falls back to a Windows-side path (there is none)', () => {
    const resolved = resolveClientConfigPath(
      'claude-code' as ClientKind,
      undefined,
      '/no/mcp/json/here',
      { inWsl: true, homeCandidates: () => [winHome1] },
      () => false,
    );
    expect(resolved.path).toBe(`${HOME}/.claude.json`);
    expect(resolved.note).toBeUndefined();
  });

  it('--config always wins outright, WSL context ignored entirely', () => {
    const resolved = resolveClientConfigPath(
      'claude-desktop',
      '/explicit/path.json',
      '/cwd',
      {
        inWsl: true,
        homeCandidates: () => {
          throw new Error('should never be called when --config is given');
        },
      },
      () => false,
    );
    expect(resolved.path).toBe('/explicit/path.json');
  });
});
