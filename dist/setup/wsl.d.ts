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
import type { ClientKind } from './client-config.js';
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
 * WSL_DISTRO_NAME or WSL_INTEROP is set, or `/proc/version` mentions
 * "microsoft" (case-insensitive — WSL1 and WSL2 kernels both self-identify
 * this way) while no container marker file is present. `env` and `readFile` are injected so tests never touch the real
 * environment or filesystem; `readFile` may throw (e.g. `/proc/version`
 * doesn't exist on a non-Linux test double) and that's treated the same as
 * "no match".
 */
export declare function detectWsl(env: Readonly<Record<string, string | undefined>>, readFile: (path: string) => string, platform?: NodeJS.Platform, exists?: (path: string) => boolean): WslDetection;
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
export interface WindowsHomeDeps {
    spawnSync: SpawnSyncFn;
    existsSync: (path: string) => boolean;
    readdirSync: (path: string) => string[];
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
export declare function windowsHomeCandidates(deps?: Partial<WindowsHomeDeps>): string[];
/**
 * The Windows-side config path(s) a given client would use, for each
 * candidate home directory. `claude-code` has none: Claude Code running
 * inside WSL is a plain Linux install using `~/.claude.json` there —
 * there's no separate Windows-side config for it to fall back to.
 */
export declare function windowsClientConfigCandidates(client: ClientKind, homes: readonly string[]): string[];
/** True for a WSL Windows-drive mount path, e.g. `/mnt/c/Users/me/...`. */
export declare function isWindowsMountPath(p: string): boolean;
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
export declare function chooseWrapper(explicit: WrapperChoice | undefined, inWsl: boolean, configPath: string): WrapperChoice;
