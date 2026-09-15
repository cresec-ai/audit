/**
 * `mcp-recorder setup` — resolving which client config file to edit.
 *
 * `--config PATH` always wins outright (this is also how tests exercise the
 * command, against a temp file, without needing a real client installed).
 * Otherwise `--client` picks a per-platform default location; `claude-code`
 * additionally prefers a `.mcp.json` in the current directory over
 * `~/.claude.json` when one exists, since that project-scoped config is
 * almost always what someone running `setup` from inside a project means.
 */
export type ClientKind = 'claude-desktop' | 'claude-code' | 'cursor';
export declare const CLIENT_KINDS: readonly ClientKind[];
export declare function isClientKind(value: string): value is ClientKind;
export interface ResolvedConfigPath {
    path: string;
    /** Set when the resolution made a choice worth telling the operator about
     * (e.g. preferring a project-local .mcp.json). Printed as a diagnostic. */
    note?: string;
}
/**
 * WSL context for {@link resolveClientConfigPath}: whether `setup` is
 * running inside WSL, plus a *lazy* way to discover Windows-side home
 * directories. `homeCandidates` is only invoked when actually needed (the
 * Linux-side config is missing and we are in WSL) since the real
 * implementation (`windowsHomeCandidates`) may shell out to `cmd.exe` —
 * callers pass `() => windowsHomeCandidates()` rather than a precomputed
 * list so that cost is never paid unnecessarily.
 */
export interface WslContext {
    inWsl: boolean;
    homeCandidates: () => string[];
}
/**
 * Resolve the client config file `setup` should edit. Only the top-level
 * `mcpServers` object is ever read or written — for `claude-code`'s
 * `~/.claude.json` that means the user-scope servers, not any per-project
 * overrides nested under a `projects` key.
 *
 * `wsl` (optional) enables the WSL-side fallback for `claude-desktop` and
 * `cursor` described on {@link resolveWithWslFallback}; `fileExists`
 * defaults to the real `fs.existsSync` and is only overridable for tests.
 */
export declare function resolveClientConfigPath(client: ClientKind | undefined, configFlag: string | undefined, cwd: string, wsl?: WslContext, fileExists?: (p: string) => boolean): ResolvedConfigPath;
