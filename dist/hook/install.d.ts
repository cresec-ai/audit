/**
 * `mcp-recorder hook install` — merge the `hook` subcommand into a Claude
 * Code settings file's `hooks` block: PreToolUse/PostToolUse/
 * PostToolUseFailure matched on `mcp__.*` (or `.*` with --all-tools), plus
 * SessionEnd (a session_end event) and Stop (a 'claude-code/stop'
 * turn-boundary notification) with no matcher — see docs/hooks.md and
 * https://code.claude.com/docs/en/hooks. PostToolUseFailure gets exactly the
 * same matcher and command as PostToolUse: Claude Code fires one OR the
 * other per tool call (success vs failure), so without it every failed call
 * would be recorded as a lone `pre` event (cloud dogfood 3). SessionStart is
 * left alone: it is for environment setup, not evidence.
 *
 * Pure functions over parsed JSON, mirroring src/setup/wrap.ts: cli.ts owns
 * every filesystem side effect and exit code, this module just decides what
 * the new `hooks` object should look like. Idempotent by EXACT command
 * string match (never adds a second entry for the same command), and
 * `planHookUndo` removes exactly the entries whose command matches —
 * nothing else in the settings file is ever touched.
 */
declare const MANAGED_EVENTS: readonly ["PreToolUse", "PostToolUse", "PostToolUseFailure", "SessionEnd", "Stop"];
export type ManagedEvent = (typeof MANAGED_EVENTS)[number];
export interface HookCommandEntry {
    type: 'command';
    command: string;
}
export interface HookMatcherEntry {
    matcher?: string;
    hooks: HookCommandEntry[];
}
export interface BuildHookCommandOpts {
    /** Absolute path to node (process.execPath). */
    execPath: string;
    /** Absolute path to this install's dist/cli.js. */
    cliPath: string;
    /** Absolute --data-dir. */
    dataDir: string;
    policyPath?: string;
    clientName?: string;
    allTools: boolean;
}
/** Build the settings.json hook `command` string for this install. Mirrors
 *  src/setup/wrap.ts's `buildWrappedEntry` for `--wrapper local`: absolute
 *  node + absolute dist/cli.js, so the hook works regardless of the shell's
 *  cwd or PATH. */
export declare function buildHookCommand(opts: BuildHookCommandOpts): string;
export interface HookInstallOpts {
    /** The exact shell command line this install writes/looks for. */
    command: string;
    /** Matcher for PreToolUse/PostToolUse/PostToolUseFailure: 'mcp__.*' by default, '.*' with --all-tools. */
    matcher: string;
}
export interface HookInstallPlan {
    root: Record<string, unknown>;
    /** Event types a new entry was added to this run. */
    added: ManagedEvent[];
    /** Event types that already had this exact command installed. */
    alreadyInstalled: ManagedEvent[];
}
/** Build the plan: which of PreToolUse/PostToolUse/PostToolUseFailure/SessionEnd/Stop need our
 *  entry added, preserving every other key and every other entry untouched
 *  (even entries this module can't fully type, e.g. a non-`command` hook
 *  type such as `http`/`mcp_tool`/`prompt` — those are passed through as-is). */
export declare function planHookInstall(root: Record<string, unknown>, opts: HookInstallOpts): HookInstallPlan;
export interface HookUndoPlan {
    root: Record<string, unknown>;
    /** Event types an entry was removed from this run. */
    removed: ManagedEvent[];
}
/** Remove exactly the entries `planHookInstall` would add for `opts.command`
 *  (matched by exact command string) — an entry with other hooks alongside
 *  ours keeps those; an entry left with zero hooks is dropped entirely.
 *  Nothing else in `root` (or in `root.hooks` for an event this module
 *  doesn't manage) is ever touched. */
export declare function planHookUndo(root: Record<string, unknown>, opts: Pick<HookInstallOpts, 'command'>): HookUndoPlan;
export {};
