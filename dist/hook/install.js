/**
 * `mcp-recorder hook install` — merge the `hook` subcommand into a Claude
 * Code settings file's `hooks` block: PreToolUse/PostToolUse matched on
 * `mcp__.*` (or `.*` with --all-tools), plus SessionEnd (a session_end
 * event) and Stop (a 'claude-code/stop' turn-boundary notification) with no
 * matcher — see docs/hooks.md and https://code.claude.com/docs/en/hooks.
 * SessionStart is left alone: it is for environment setup, not evidence.
 *
 * Pure functions over parsed JSON, mirroring src/setup/wrap.ts: cli.ts owns
 * every filesystem side effect and exit code, this module just decides what
 * the new `hooks` object should look like. Idempotent by EXACT command
 * string match (never adds a second entry for the same command), and
 * `planHookUndo` removes exactly the entries whose command matches —
 * nothing else in the settings file is ever touched.
 */
const TOOL_EVENTS = ['PreToolUse', 'PostToolUse'];
const END_EVENTS = ['SessionEnd', 'Stop'];
const MANAGED_EVENTS = [...TOOL_EVENTS, ...END_EVENTS];
function isPlainObject(v) {
    return typeof v === 'object' && v !== null && !Array.isArray(v);
}
function isHookCommandEntry(v) {
    return isPlainObject(v) && v.type === 'command' && typeof v.command === 'string';
}
function isMatcherEntry(v) {
    return (isPlainObject(v) &&
        Array.isArray(v.hooks) &&
        v.hooks.every(isHookCommandEntry) &&
        (v.matcher === undefined || typeof v.matcher === 'string'));
}
function isToolEvent(event) {
    return TOOL_EVENTS.includes(event);
}
/** Quote one shell word: settings.json hook commands run through a shell
 *  (see the docs' own `${CLAUDE_PROJECT_DIR}/.claude/hooks/script.sh`
 *  example), so any path containing a space must be quoted. */
function shellQuote(s) {
    return `"${s.replace(/(["\\$`])/g, '\\$1')}"`;
}
/** Build the settings.json hook `command` string for this install. Mirrors
 *  src/setup/wrap.ts's `buildWrappedEntry` for `--wrapper local`: absolute
 *  node + absolute dist/cli.js, so the hook works regardless of the shell's
 *  cwd or PATH. */
export function buildHookCommand(opts) {
    const parts = [
        shellQuote(opts.execPath),
        shellQuote(opts.cliPath),
        'hook',
        '--data-dir',
        shellQuote(opts.dataDir),
    ];
    if (opts.policyPath !== undefined)
        parts.push('--policy', shellQuote(opts.policyPath));
    if (opts.clientName !== undefined)
        parts.push('--client', shellQuote(opts.clientName));
    if (opts.allTools)
        parts.push('--all-tools');
    return parts.join(' ');
}
function hooksArrayOf(root, event) {
    if (!isPlainObject(root.hooks))
        return [];
    const arr = root.hooks[event];
    return Array.isArray(arr) ? arr : [];
}
function hasOurCommand(entries, command) {
    return entries.some((e) => isMatcherEntry(e) && e.hooks.some((h) => h.command === command));
}
/** Build the plan: which of PreToolUse/PostToolUse/SessionEnd/Stop need our
 *  entry added, preserving every other key and every other entry untouched
 *  (even entries this module can't fully type, e.g. a non-`command` hook
 *  type such as `http`/`mcp_tool`/`prompt` — those are passed through as-is). */
export function planHookInstall(root, opts) {
    const nextHooks = isPlainObject(root.hooks) ? { ...root.hooks } : {};
    const added = [];
    const alreadyInstalled = [];
    for (const event of MANAGED_EVENTS) {
        const existing = hooksArrayOf(root, event);
        if (hasOurCommand(existing, opts.command)) {
            alreadyInstalled.push(event);
            continue;
        }
        const entry = isToolEvent(event)
            ? { matcher: opts.matcher, hooks: [{ type: 'command', command: opts.command }] }
            : { hooks: [{ type: 'command', command: opts.command }] };
        nextHooks[event] = [...existing, entry];
        added.push(event);
    }
    return { root: { ...root, hooks: nextHooks }, added, alreadyInstalled };
}
/** Remove exactly the entries `planHookInstall` would add for `opts.command`
 *  (matched by exact command string) — an entry with other hooks alongside
 *  ours keeps those; an entry left with zero hooks is dropped entirely.
 *  Nothing else in `root` (or in `root.hooks` for an event this module
 *  doesn't manage) is ever touched. */
export function planHookUndo(root, opts) {
    if (!isPlainObject(root.hooks))
        return { root, removed: [] };
    const nextHooks = { ...root.hooks };
    const removed = [];
    for (const event of MANAGED_EVENTS) {
        const existing = hooksArrayOf(root, event);
        if (existing.length === 0)
            continue;
        let touched = false;
        const filtered = [];
        for (const entryRaw of existing) {
            if (!isMatcherEntry(entryRaw)) {
                filtered.push(entryRaw); // not ours to understand — leave it alone
                continue;
            }
            const keptHooks = entryRaw.hooks.filter((h) => h.command !== opts.command);
            if (keptHooks.length !== entryRaw.hooks.length)
                touched = true;
            if (keptHooks.length > 0) {
                filtered.push(keptHooks.length === entryRaw.hooks.length ? entryRaw : { ...entryRaw, hooks: keptHooks });
            }
        }
        if (touched) {
            removed.push(event);
            if (filtered.length > 0)
                nextHooks[event] = filtered;
            else
                delete nextHooks[event]; // no entries left for this event: drop the key entirely
        }
    }
    return { root: { ...root, hooks: nextHooks }, removed };
}
//# sourceMappingURL=install.js.map