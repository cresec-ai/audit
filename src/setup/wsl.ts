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
import { posix } from 'node:path';

// Every path built here is a WSL (Linux) path — `/mnt/c/...` — regardless of
// the platform this code happens to execute on (the unit tests also run on
// windows-latest), so path.posix is used deliberately, never the
// platform-dependent `path.join`.
const { join } = posix;
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

/** Files that exist inside a Docker / Podman container and nowhere else. */
const CONTAINER_MARKERS = ['/.dockerenv', '/run/.containerenv'];

/**
 * True when running inside WSL: platform is linux AND at least one of
 * WSL_DISTRO_NAME or WSL_INTEROP is set, or `/proc/version` mentions
 * "microsoft" (case-insensitive — WSL1 and WSL2 kernels both self-identify
 * this way) while no container marker file is present. `env` and `readFile` are injected so tests never touch the real
 * environment or filesystem; `readFile` may throw (e.g. `/proc/version`
 * doesn't exist on a non-Linux test double) and that's treated the same as
 * "no match".
 */
export function detectWsl(
  env: Readonly<Record<string, string | undefined>>,
  readFile: (path: string) => string,
  platform: NodeJS.Platform = process.platform,
  exists: (path: string) => boolean = nodeExistsSync,
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

  // Docker Desktop's WSL2 backend runs every container on the same
  // Microsoft kernel, so /proc/version alone also matches inside an ordinary
  // Linux container that has no interop bridge to Windows at all. The env
  // markers are per-session and never leak into such a container; the
  // kernel string is only trusted when no container marker is present.
  const inContainer = CONTAINER_MARKERS.some((p) => {
    try {
      return exists(p);
    } catch {
      return false;
    }
  });

  const inWsl = distro !== undefined || hasInterop || (procVersionMentionsMicrosoft && !inContainer);
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
 * several profiles exist; ONLY when cmd.exe can't be run at all (e.g.
 * interop disabled) does it fall back to listing `/mnt/c/Users`. Always
 * returns a de-duplicated list — deps are injectable so no test ever shells out to a
 * real `cmd.exe`/`wslpath` or touches the real filesystem.
 */
export function windowsHomeCandidates(deps: Partial<WindowsHomeDeps> = {}): string[] {
  const spawn = deps.spawnSync ?? defaultSpawnSync;
  const exists = deps.existsSync ?? nodeExistsSync;
  const readdir = deps.readdirSync ?? nodeReaddirSync;

  // When Windows itself answers, that answer is the whole list: listing
  // /mnt/c/Users as well would put every OTHER account's profile on the
  // candidate list, and an operator whose own client config does not exist
  // yet would have setup silently edit another user's. The listing is a
  // fallback for when cmd.exe cannot be run at all, nothing more.
  const winProfile = windowsUserProfileVia(spawn, exists);
  if (winProfile !== undefined) {
    const converted = convertWindowsPath(winProfile, spawn);
    if (converted !== undefined) return [converted];
  }

  return [...new Set(globWindowsUsersDir(readdir, exists))];
}

/* --------------------------- config candidates ---------------------------- */

/**
 * A home directory's Windows-side MSIX (Microsoft Store) Claude Desktop
 * config candidates: every `Claude_*` package directory under
 * `<home>/AppData/Local/Packages`, each turned into its
 * `LocalCache/Roaming/Claude/claude_desktop_config.json`. `readdirFn` reads
 * the Packages directory (wrapped in try/catch — a missing/unreadable
 * directory is just "no MSIX install", not an error) and defaults to the
 * real `fs.readdirSync`, injectable so tests never touch the real
 * filesystem.
 */
function msixClaudeDesktopCandidates(home: string, readdirFn: (p: string) => string[]): string[] {
  const packagesDir = join(home, 'AppData', 'Local', 'Packages');
  let entries: string[] = [];
  try {
    entries = readdirFn(packagesDir);
  } catch {
    entries = [];
  }
  return entries
    .filter((name) => name.startsWith('Claude_'))
    .sort()
    .map((name) => join(packagesDir, name, 'LocalCache', 'Roaming', 'Claude', 'claude_desktop_config.json'));
}

/**
 * The Windows-side config path(s) a given client would use, for each
 * candidate home directory. `claude-code` has none: Claude Code running
 * inside WSL is a plain Linux install using `~/.claude.json` there —
 * there's no separate Windows-side config for it to fall back to.
 *
 * `claude-desktop` yields, per home, the ordinary installer path
 * (`AppData/Roaming/Claude/...`) followed by every MSIX / Microsoft Store
 * package match under `AppData/Local/Packages` (see
 * {@link msixClaudeDesktopCandidates}), since a Windows install can be
 * either shape. `readdirFn` is only used for that MSIX lookup and defaults
 * to the real `fs.readdirSync`.
 */
export function windowsClientConfigCandidates(
  client: ClientKind,
  homes: readonly string[],
  readdirFn: (p: string) => string[] = nodeReaddirSync,
): string[] {
  switch (client) {
    case 'claude-desktop':
      return homes.flatMap((home) => [
        join(home, 'AppData', 'Roaming', 'Claude', 'claude_desktop_config.json'),
        ...msixClaudeDesktopCandidates(home, readdirFn),
      ]);
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
