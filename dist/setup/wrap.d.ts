/**
 * `mcp-recorder setup` — the wrap/unwrap decisions, as pure functions over
 * parsed JSON. No filesystem or process access here: cli.ts owns all I/O and
 * exit codes, this module just decides what the new `mcpServers` map (and
 * the sidecar recording it) should look like.
 */
/** A client config's per-server entry. Loosely typed on purpose — clients
 * carry keys this tool doesn't know about (and must preserve untouched). */
export interface ServerEntry {
    command?: string;
    args?: string[];
    url?: string;
    type?: string;
    env?: Record<string, string>;
    cwd?: string;
    [key: string]: unknown;
}
export type McpServersMap = Record<string, ServerEntry>;
export interface WrapOpts {
    wrapper: 'local' | 'npx' | 'wsl';
    /** Absolute path to dist/cli.js for the install running `setup` — used
     * for wrapper: 'local' and 'wsl' (which both invoke it with `node`
     * directly), and to recognize an entry this exact install already
     * wrapped. */
    localWrapperPath: string;
    dataDir?: string;
    /** --only NAME[,NAME...]: wrap nothing outside this set. */
    only?: ReadonlySet<string>;
    /** --except NAME[,NAME...]: wrap everything except this set. */
    except?: ReadonlySet<string>;
    /** wrapper: 'wsl' only — passed to `wsl.exe -d <distro>` so the wrapped
     * command launches in the same distro `setup` ran from, instead of
     * whichever one wsl.exe treats as default. Omitted entirely (no `-d`
     * pair) when unknown. */
    wslDistro?: string;
}
export interface SkipEntry {
    name: string;
    reason: string;
}
export interface WrapPlan {
    /** The full mcpServers map after wrapping (unwrapped/skipped entries
     * carried over unchanged). */
    next: McpServersMap;
    /** Names wrapped this run. */
    wrapped: string[];
    skipped: SkipEntry[];
    /** Names left alone because they already referenced the recorder. */
    alreadyWrapped: string[];
    /** Original entries for names wrapped this run — what the sidecar stores. */
    originals: Record<string, ServerEntry>;
    /** Free-text notices worth surfacing in the human/dry-run output but that
     * aren't a skip — e.g. explaining which env vars got forwarded via
     * WSLENV for a `wrapper: 'wsl'` entry. */
    notes: string[];
}
/** True when `entry` already runs through this recorder — either form
 * (`npx @edut/mcp-recorder ...`, a global `mcp-recorder` binary, or this
 * exact install's local wrapper path — including that path appearing after
 * a `wsl.exe -d <distro> -e ...` prefix, since this scans every string part
 * of the entry, command and args alike, not just the first one). Wrapping
 * it again would nest proxies. */
export declare function isAlreadyWrapped(entry: ServerEntry, localWrapperPath: string): boolean;
/**
 * Merge `keys` into an existing `WSLENV` value (colon-separated), without
 * duplicating a key that's already listed — comparing by the bare name
 * before any `/flags` suffix, and preserving those flags and the existing
 * entries' order. `WSLENV` is how wsl.exe decides which Windows-side
 * environment variables get forwarded into the WSL process at all: a
 * variable merely being present in `env` is not enough on its own.
 */
export declare function mergeWslEnv(existing: string | undefined, keys: readonly string[]): string;
/** Build the wrapped replacement for one entry. `env`, `cwd`, and any other
 * keys are carried over untouched (`wrapper: 'wsl'` extends `env.WSLENV`,
 * see {@link buildWslWrappedEntry}); otherwise only `command`/`args` change. */
export declare function buildWrappedEntry(name: string, original: ServerEntry, opts: WrapOpts): ServerEntry;
/** Decide, for every entry in `servers`, whether it gets wrapped, skipped, or
 * is already wrapped — and build the replacement map. Order of entries in
 * `next` follows `servers`' own key order. */
export declare function planWrap(servers: McpServersMap, opts: WrapOpts): WrapPlan;
/**
 * `setup --undo` fallback when the sidecar file is missing: strip a
 * recognizable recorder-wrapper prefix back off to recover the original
 * command/args. Returns undefined when `entry` doesn't look like one of ours
 * (left alone by the caller). Only `command`/`args` are reconstructed — any
 * other keys (env, cwd, ...) were never touched by wrapping, so they're
 * already correct on `entry` EXCEPT for a `wrapper: 'wsl'` entry's `env`:
 * wrapping extended `WSLENV` there (see {@link mergeWslEnv}), and this
 * structural fallback doesn't know which keys it added, so any such
 * addition lingers in the restored entry's `env` (harmless — WSLENV without
 * a WSLENV-aware host such as a Windows client, wsl.exe just does nothing
 * with it — but not byte-for-byte identical to the original). The sidecar
 * path (used whenever it's available) always restores exactly, this
 * caveat only applies to a config that lost its sidecar.
 */
export declare function structuralUnwrap(entry: ServerEntry): ServerEntry | undefined;
