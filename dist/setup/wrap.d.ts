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
    /** `setup --policy FILE`: ABSOLUTE path (cli.ts resolves it) baked into
     * every wrapped entry as `--policy <path>` right after `--data-dir`, so
     * those servers run in gateway mode (record --policy). Absolute because
     * MCP clients launch servers from their own working directory. Entries an
     * earlier run already wrapped get it too — see {@link WrapPlan.updated}. */
    policyPath?: string;
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
    /** Names left alone because they already referenced the recorder (and,
     * with `--policy`, already carried exactly that policy). */
    alreadyWrapped: string[];
    /** Names that were ALREADY wrapped and whose recorder arguments this run
     * rewrote to carry `opts.policyPath` (inserted, or replacing the policy
     * they pointed at before). Only ever non-empty when `opts.policyPath` is
     * set; the entries' originals are NOT re-recorded in the sidecar, which
     * already holds them from the run that wrapped them. */
    updated: string[];
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
/**
 * Rewrite an ALREADY-wrapped entry so its recorder arguments carry
 * `--policy <policyPath>`: replacing the value of an existing `--policy`
 * (both the `--policy X` pair and the `--policy=X` spelling a hand edit may
 * use) or, when there is none, inserting the pair immediately before the
 * `--` that closes the recorder's own arguments. Everything else — the
 * wrapper form, `--name`, `--data-dir`, the wrapped server's argv, `env`,
 * `cwd` — is left exactly as it was.
 *
 * Returns undefined when the entry has no readable recorder-args segment
 * (no `args` array, or no `--` separator), so the caller can leave such an
 * entry untouched rather than guess at its shape.
 */
export declare function withPolicyArg(entry: ServerEntry, policyPath: string): ServerEntry | undefined;
export interface BridgeSpec {
    name: string;
    url: string;
}
/**
 * Parse `--bridge NAME=URL[,NAME=URL...]` values into `{name, url}` specs.
 * `values` is every raw `--bridge` occurrence (cli.ts collects a repeatable
 * flag into an array); each one may itself be a comma-separated list, so
 * both `--bridge a=X --bridge b=Y` and `--bridge a=X,b=Y` work. Throws a
 * usage-shaped `Error` (cli.ts turns any thrown error from `setup` into exit
 * code 2) on a malformed spec — a bad name or a URL that doesn't parse as
 * http(s) — naming the offending piece so the message is actionable.
 */
export declare function parseBridgeSpecs(values: readonly string[]): BridgeSpec[];
/**
 * The unwrapped stdio entry that bridges a *remote* MCP server — an OAuth
 * "connector" Claude Desktop would otherwise reach directly from Anthropic's
 * own infrastructure, never touching this machine — into a local process
 * the recorder can wrap like any other. `mcp-remote`
 * (https://www.npmjs.com/package/mcp-remote) speaks the remote server's
 * HTTP/SSE transport on one side and plain stdio on the other; `npx -y`
 * fetches it at run time, so it's never a dependency of this package (same
 * as `--wrapper npx` already does for the recorder itself). This entry is
 * what the sidecar stores as the "original" for a bridged server — `--undo`
 * restores exactly this, not a further-unwrapped remote connector, since
 * this recorder cannot make Claude Desktop reach a remote MCP server any
 * other way.
 */
export declare function bridgeEntry(url: string): ServerEntry;
/**
 * True when `entry` is exactly the bridge entry {@link bridgeEntry} would
 * build for `url` — same keys, same values — so a second `setup --bridge`
 * run for a name that's already bridged is idempotent instead of erroring.
 * Any other entry under that name (a real server, or a bridge to a
 * different URL, or one the operator customized) is NOT identical, and the
 * caller must refuse to silently replace it.
 */
export declare function isSameBridgeEntry(entry: ServerEntry, url: string): boolean;
/** Decide, for every entry in `servers`, whether it gets wrapped, skipped,
 * policy-updated, or is already wrapped — and build the replacement map.
 * Order of entries in `next` follows `servers`' own key order. */
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
