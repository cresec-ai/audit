/**
 * `mcp-recorder setup` — WSL awareness.
 *
 * When the MCP client (Claude Desktop, Cursor) runs on Windows but `setup`
 * itself runs inside WSL, the client's config lives on the Windows side of
 * the filesystem (under `/mnt/c/...`) and the servers it launches have to be
 * runnable by *Windows*, not Linux. This module supplies the pure decision
 * functions plus the (injectable) Windows-side discovery `setup`'s wrapper
 * commands need: detecting WSL itself, finding Windows user profile
 * directories from inside WSL, and turning those into candidate client
 * config paths. No filesystem/process access happens at import time — every
 * function here either takes its inputs directly or accepts injectable deps
 * with real defaults, so tests never need to shell out to a real `cmd.exe`.
 */

import { spawnSync as nodeSpawnSync } from 'node:child_process';
import { existsSync as nodeExistsSync, readdirSync as nodeReaddirSync } from 'node:fs';
import { join } from 'node:path';
import type { ClientKind } from './client-config.js';

/* ------------------------------ detectWsl -------------------------------- */

export interface WslDetection {
  inWsl: boolean;
  /** Present only when WSL_DISTRO_NAME is set (the normal case for an
   * interactive WSL shell). Used to pass `-d <distro>` to wsl.exe so the
   * wrapped command launches in the same distro `setup` ran from, rather
   * than whichever one wsl.exe treats as default. */
  distro?: string;
}

/**
 * True when running inside WSL: platform is linux AND at least one of
 * WSL_DISTRO_NAME, `/proc/version` mentioning "microsoft" (case-insensitive
 * — WSL1 and WSL2 kernels both self-identify this way), or WSL_INTEROP is
 * set. `env` and `readFile` are injected so tests never touch the real
 * environment or filesystem; `readFile` may throw (e.g. `/proc/version`
 * doesn't exist on a non-Linux test double) and that's treated the same as
 * "no match".
 */
export function detectWsl(
  env: Readonly<Record<string, string | undefined>>,
  readFile: (path: string) => string,
  platform: NodeJS.Platform = process.platform,
): WslDetection {
  if (platform !== 'linux') return { inWsl: false };

  const distroEnv = env.WSL_DISTRO_NAME;
  const distro = distroEnv !== undefined && distroEnv.length > 0 ? distroEnv : undefined;

  let procVersionMentionsMicrosoft = false;
  try {
    procVersionMentionsMicrosoft = /microsoft/i.test(readFile('/proc/version'));
  } catch {
    procVersionMentionsMicrosoft = false;
  }

  const interop = env.WSL_INTEROP;
  const hasInterop = interop !== undefined && interop.length > 0;

  const inWsl = distro !== undefined || procVersionMentionsMicrosoft || hasInterop;
  return distro !== undefined ? { inWsl, distro } : { inWsl };
}

/* -------------------------- windowsHomeCandidates ------------------------- */

/** Minimal, easily-mocked spawnSync shape — narrower than node:child_process's
 * real (overloaded) signature so tests can supply a plain function without
 * fighting its types. The default implementation adapts the real thing. */
export interface SpawnSyncOptions {
  cwd?: string;
  timeout?: number;
  windowsHide?: boolean;
}

export interface SpawnSyncResult {
  status: number | null;
  stdout: string;
  stderr: string;
  error?: Error;
}

export type SpawnSyncFn = (command: string, args: string[], options?: SpawnSyncOptions) => SpawnSyncResult;

const defaultSpawnSync: SpawnSyncFn = (command, args, options) => {
  const res = nodeSpawnSync(command, args, { encoding: 'utf8', ...options });
  const result: SpawnSyncResult = { status: res.status, stdout: res.stdout ?? '', stderr: res.stderr ?? '' };
  if (res.error !== undefined) result.error = res.error;
  return result;
};

export interface WindowsHomeDeps {
  spawnSync: SpawnSyncFn;
  existsSync: (path: string) => boolean;
  readdirSync: (path: string) => string[];
}

const CMD_EXE_CANDIDATES = ['cmd.exe', '/mnt/c/Windows/System32/cmd.exe'];

/** Ask Windows for %USERPROFILE% via cmd.exe, trying `cmd.exe` resolved off
 * PATH first (works when the Windows PATH is appended into WSL's, the WSL
 * default) and falling back to its well-known absolute mount path. Run from
 * `/mnt/c` — running it from a UNC-style WSL path (`\\wsl$\...`) is what
 * triggers cmd.exe's "CMD.EXE was started with the above path as the
 * current directory" warning on stderr, which this avoids entirely. Returns
 * undefined on any failure (missing binary, timeout, non-zero exit, or the
 * echo not expanding — e.g. under a shell where %USERPROFILE% isn't set). */
function windowsUserProfileVia(spawn: SpawnSyncFn, exists: (p: string) => boolean): string | undefined {
  for (const cmd of CMD_EXE_CANDIDATES) {
    if (cmd.startsWith('/') && !exists(cmd)) continue;
    const res = spawn(cmd, ['/c', 'echo %USERPROFILE%'], {
      cwd: '/mnt/c',
      timeout: 5_000,
      windowsHide: true,
    });
    if (res.error !== undefined || res.status !== 0) continue;
    const line = res.stdout.trim();
    if (line.length === 0 || line.includes('%USERPROFILE%')) continue; // didn't expand
    return line;
  }
  return undefined;
}

/** `C:\Users\me` -> `/mnt/c/users/me` as a manual fallback when `wslpath` is
 * unavailable. Case-preserving for the path components (WSL's own mount is
 * case-sensitive on a case-sensitive Linux filesystem, but the drive
 * mountpoint itself is always lowercased). */
function manualWinToWslPath(winPath: string): string | undefined {
  const m = /^([A-Za-z]):\\(.*)$/.exec(winPath);
  if (m === null) return undefined;
  const drive = m[1]!.toLowerCase();
  const rest = m[2]!.replace(/\\/g, '/');
  return `/mnt/${drive}/${rest}`;
}

/** Convert a Windows path to its WSL mount equivalent, preferring the real
 * `wslpath -u` (handles drive remaps, WSL-specific mounts, etc.) and falling
 * back to the manual `C:\...` -> `/mnt/<drive>/...` rule above. */
function convertWindowsPath(winPath: string, spawn: SpawnSyncFn): string | undefined {
  const res = spawn('wslpath', ['-u', winPath], { timeout: 5_000 });
  if (res.error === undefined && res.status === 0) {
    const out = res.stdout.trim();
    if (out.length > 0) return out;
  }
  return manualWinToWslPath(winPath);
}

const EXCLUDED_USER_DIRS = new Set(['Default', 'Default User', 'Public', 'All Users']);
const WINDOWS_USERS_DIR = '/mnt/c/Users';

/** Fallback when cmd.exe isn't reachable at all: every subdirectory of
 * `/mnt/c/Users` except the well-known non-user profile directories Windows
 * always creates there. */
function globWindowsUsersDir(readdir: (p: string) => string[], exists: (p: string) => boolean): string[] {
  if (!exists(WINDOWS_USERS_DIR)) return [];
  let entries: string[];
  try {
    entries = readdir(WINDOWS_USERS_DIR);
  } catch {
    return [];
  }
  return entries
    .filter((name) => !EXCLUDED_USER_DIRS.has(name) && !name.startsWith('.'))
    .map((name) => join(WINDOWS_USERS_DIR, name));
}

/**
 * Discover Windows user profile directories, as seen from inside WSL.
 * Prefers asking Windows directly (cmd.exe's %USERPROFILE%, converted to a
 * WSL path), which reliably finds the *current* Windows user even when
 * several profiles exist; falls back to listing `/mnt/c/Users` when cmd.exe
 * can't be run at all (e.g. interop disabled). Always returns an ordered,
 * de-duplicated list — deps are injectable so no test ever shells out to a
 * real `cmd.exe`/`wslpath` or touches the real filesystem.
 */
export function windowsHomeCandidates(deps: Partial<WindowsHomeDeps> = {}): string[] {
  const spawn = deps.spawnSync ?? defaultSpawnSync;
  const exists = deps.existsSync ?? nodeExistsSync;
  const readdir = deps.readdirSync ?? nodeReaddirSync;

  const candidates: string[] = [];

  const winProfile = windowsUserProfileVia(spawn, exists);
  if (winProfile !== undefined) {
    const converted = convertWindowsPath(winProfile, spawn);
    if (converted !== undefined) candidates.push(converted);
  }

  for (const dir of globWindowsUsersDir(readdir, exists)) candidates.push(dir);

  return [...new Set(candidates)];
}

/* --------------------------- config candidates ---------------------------- */

/**
 * The Windows-side config path(s) a given client would use, for each
 * candidate home directory. `claude-code` has none: Claude Code running
 * inside WSL is a plain Linux install using `~/.claude.json` there —
 * there's no separate Windows-side config for it to fall back to.
 */
export function windowsClientConfigCandidates(client: ClientKind, homes: readonly string[]): string[] {
  switch (client) {
    case 'claude-desktop':
      return homes.map((home) => join(home, 'AppData', 'Roaming', 'Claude', 'claude_desktop_config.json'));
    case 'cursor':
      return homes.map((home) => join(home, '.cursor', 'mcp.json'));
    case 'claude-code':
      return [];
  }
}

/* ------------------------------ mount paths -------------------------------- */

/** True for a WSL Windows-drive mount path, e.g. `/mnt/c/Users/me/...`. */
export function isWindowsMountPath(p: string): boolean {
  return /^\/mnt\/[a-zA-Z](\/|$)/.test(p);
}

/* ----------------------------- wrapper choice ------------------------------ */

export type WrapperChoice = 'local' | 'npx' | 'wsl';

/**
 * Decide which `--wrapper` form `setup` uses. An explicit flag always wins.
 * Otherwise, auto-select `wsl` only when `setup` itself is running inside
 * WSL AND the config file it resolved to lives on the Windows side
 * (`/mnt/<drive>/...`) — that combination means the client reading this
 * config is a Windows program, so a Linux `node` path written into
 * `command` would never be runnable by it. Every other combination (not in
 * WSL at all, or editing a genuinely Linux-side config while inside WSL)
 * keeps the ordinary default of `local`.
 */
export function chooseWrapper(
  explicit: WrapperChoice | undefined,
  inWsl: boolean,
  configPath: string,
): WrapperChoice {
  if (explicit !== undefined) return explicit;
  if (inWsl && isWindowsMountPath(configPath)) return 'wsl';
  return 'local';
}
