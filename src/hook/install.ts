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

const TOOL_EVENTS = ['PreToolUse', 'PostToolUse', 'PostToolUseFailure'] as const;
const END_EVENTS = ['SessionEnd', 'Stop'] as const;
const MANAGED_EVENTS = [...TOOL_EVENTS, ...END_EVENTS] as const;
export type ManagedEvent = (typeof MANAGED_EVENTS)[number];

export interface HookCommandEntry {
  type: 'command';
  command: string;
}

export interface HookMatcherEntry {
  matcher?: string;
  hooks: HookCommandEntry[];
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function isHookCommandEntry(v: unknown): v is HookCommandEntry {
  return isPlainObject(v) && v.type === 'command' && typeof v.command === 'string';
}

function isMatcherEntry(v: unknown): v is HookMatcherEntry {
  return (
    isPlainObject(v) &&
    Array.isArray(v.hooks) &&
    v.hooks.every(isHookCommandEntry) &&
    (v.matcher === undefined || typeof v.matcher === 'string')
  );
}

function isToolEvent(event: string): event is (typeof TOOL_EVENTS)[number] {
  return (TOOL_EVENTS as readonly string[]).includes(event);
}

/* ------------------------------- command ------------------------------- */

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

/** Quote one shell word: settings.json hook commands run through a shell
 *  (see the docs' own `${CLAUDE_PROJECT_DIR}/.claude/hooks/script.sh`
 *  example), so any path containing a space must be quoted. */
function shellQuote(s: string): string {
  return `"${s.replace(/(["\\$`])/g, '\\$1')}"`;
}

/** Build the settings.json hook `command` string for this install. Mirrors
 *  src/setup/wrap.ts's `buildWrappedEntry` for `--wrapper local`: absolute
 *  node + absolute dist/cli.js, so the hook works regardless of the shell's
 *  cwd or PATH. */
export function buildHookCommand(opts: BuildHookCommandOpts): string {
  const parts = [
    shellQuote(opts.execPath),
    shellQuote(opts.cliPath),
    'hook',
    '--data-dir',
    shellQuote(opts.dataDir),
  ];
  if (opts.policyPath !== undefined) parts.push('--policy', shellQuote(opts.policyPath));
  if (opts.clientName !== undefined) parts.push('--client', shellQuote(opts.clientName));
  if (opts.allTools) parts.push('--all-tools');
  return parts.join(' ');
}

/* -------------------------------- plan --------------------------------- */

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

function hooksArrayOf(root: Record<string, unknown>, event: string): unknown[] {
  if (!isPlainObject(root.hooks)) return [];
  const arr = root.hooks[event];
  return Array.isArray(arr) ? arr : [];
}

function hasOurCommand(entries: unknown[], command: string): boolean {
  return entries.some((e) => isMatcherEntry(e) && e.hooks.some((h) => h.command === command));
}

/** Build the plan: which of PreToolUse/PostToolUse/PostToolUseFailure/SessionEnd/Stop need our
 *  entry added, preserving every other key and every other entry untouched
 *  (even entries this module can't fully type, e.g. a non-`command` hook
 *  type such as `http`/`mcp_tool`/`prompt` — those are passed through as-is). */
export function planHookInstall(root: Record<string, unknown>, opts: HookInstallOpts): HookInstallPlan {
  const nextHooks: Record<string, unknown> = isPlainObject(root.hooks) ? { ...root.hooks } : {};
  const added: ManagedEvent[] = [];
  const alreadyInstalled: ManagedEvent[] = [];

  for (const event of MANAGED_EVENTS) {
    const existing = hooksArrayOf(root, event);
    if (hasOurCommand(existing, opts.command)) {
      alreadyInstalled.push(event);
      continue;
    }
    const entry: HookMatcherEntry = isToolEvent(event)
      ? { matcher: opts.matcher, hooks: [{ type: 'command', command: opts.command }] }
      : { hooks: [{ type: 'command', command: opts.command }] };
    nextHooks[event] = [...existing, entry];
    added.push(event);
  }

  return { root: { ...root, hooks: nextHooks }, added, alreadyInstalled };
}

/* -------------------------------- undo ---------------------------------- */

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
export function planHookUndo(
  root: Record<string, unknown>,
  opts: Pick<HookInstallOpts, 'command'>,
): HookUndoPlan {
  if (!isPlainObject(root.hooks)) return { root, removed: [] };
  const nextHooks: Record<string, unknown> = { ...root.hooks };
  const removed: ManagedEvent[] = [];

  for (const event of MANAGED_EVENTS) {
    const existing = hooksArrayOf(root, event);
    if (existing.length === 0) continue;
    let touched = false;
    const filtered: unknown[] = [];
    for (const entryRaw of existing) {
      if (!isMatcherEntry(entryRaw)) {
        filtered.push(entryRaw); // not ours to understand — leave it alone
        continue;
      }
      const keptHooks = entryRaw.hooks.filter((h) => h.command !== opts.command);
      if (keptHooks.length !== entryRaw.hooks.length) touched = true;
      if (keptHooks.length > 0) {
        filtered.push(keptHooks.length === entryRaw.hooks.length ? entryRaw : { ...entryRaw, hooks: keptHooks });
      }
    }
    if (touched) {
      removed.push(event);
      if (filtered.length > 0) nextHooks[event] = filtered;
      else delete nextHooks[event]; // no entries left for this event: drop the key entirely
    }
  }

  return { root: { ...root, hooks: nextHooks }, removed };
}
