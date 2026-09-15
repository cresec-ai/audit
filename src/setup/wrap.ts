/**
 * `mcp-recorder setup` — the wrap/unwrap decisions, as pure functions over
 * parsed JSON. No filesystem or process access here: cli.ts owns all I/O and
 * exit codes, this module just decides what the new `mcpServers` map (and
 * the sidecar recording it) should look like.
 */

import { homedir } from 'node:os';
import { join } from 'node:path';

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
   * MCP clients launch servers from their own working directory. */
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
  /** Names left alone because they already referenced the recorder. */
  alreadyWrapped: string[];
  /** Original entries for names wrapped this run — what the sidecar stores. */
  originals: Record<string, ServerEntry>;
  /** Free-text notices worth surfacing in the human/dry-run output but that
   * aren't a skip — e.g. explaining which env vars got forwarded via
   * WSLENV for a `wrapper: 'wsl'` entry. */
  notes: string[];
}

const RECORDER_MARKERS = ['@edut/mcp-recorder', 'mcp-recorder'];

function stringPartsOf(entry: ServerEntry): string[] {
  const parts: string[] = [];
  if (typeof entry.command === 'string') parts.push(entry.command);
  if (Array.isArray(entry.args)) {
    for (const a of entry.args) if (typeof a === 'string') parts.push(a);
  }
  return parts;
}

/** True when `entry` already runs through this recorder — either form
 * (`npx @edut/mcp-recorder ...`, a global `mcp-recorder` binary, or this
 * exact install's local wrapper path — including that path appearing after
 * a `wsl.exe -d <distro> -e ...` prefix, since this scans every string part
 * of the entry, command and args alike, not just the first one). Wrapping
 * it again would nest proxies. */
export function isAlreadyWrapped(entry: ServerEntry, localWrapperPath: string): boolean {
  return stringPartsOf(entry).some(
    (p) => p === localWrapperPath || RECORDER_MARKERS.some((marker) => p.includes(marker)),
  );
}

function isStdioEntry(entry: ServerEntry): boolean {
  return typeof entry.command === 'string' && entry.command.length > 0;
}

/** Why an entry isn't a wrappable stdio server, or undefined if it is one. */
function transportSkipReason(entry: ServerEntry): string | undefined {
  if (isStdioEntry(entry)) return undefined;
  if (typeof entry.url === 'string') {
    return 'remote transport (url) — not a stdio server, skipped';
  }
  if (entry.type === 'http' || entry.type === 'sse') {
    return `remote transport (type: ${entry.type}) — not a stdio server, skipped`;
  }
  return 'no "command" field — not a recognized stdio server, skipped';
}

/**
 * Merge `keys` into an existing `WSLENV` value (colon-separated), without
 * duplicating a key that's already listed — comparing by the bare name
 * before any `/flags` suffix, and preserving those flags and the existing
 * entries' order. `WSLENV` is how wsl.exe decides which Windows-side
 * environment variables get forwarded into the WSL process at all: a
 * variable merely being present in `env` is not enough on its own.
 */
export function mergeWslEnv(existing: string | undefined, keys: readonly string[]): string {
  const entries = existing !== undefined && existing.length > 0 ? existing.split(':') : [];
  const seen = new Set(entries.map((e) => e.split('/')[0]!));
  for (const key of keys) {
    if (seen.has(key)) continue;
    entries.push(key);
    seen.add(key);
  }
  return entries.join(':');
}

/** Build the `wrapper: 'wsl'` replacement: `wsl.exe -d <distro> -e <node>
 * <localWrapperPath> record ... -- <originalArgv>`. `-d <distro>` is
 * omitted entirely when the distro is unknown. `--data-dir` is always
 * included (unlike the other wrapper forms, where it's optional and falls
 * back to `~` at runtime) because `wsl.exe -e` launches the target directly,
 * with no shell in the loop to expand `~`. */
function buildWslWrappedEntry(name: string, original: ServerEntry, originalArgv: string[], opts: WrapOpts): ServerEntry {
  const dataDir = opts.dataDir ?? join(homedir(), '.mcp-recorder');

  const args: string[] = [];
  if (opts.wslDistro !== undefined) args.push('-d', opts.wslDistro);
  args.push(
    '-e',
    process.execPath,
    opts.localWrapperPath,
    'record',
    '--name',
    name,
    '--data-dir',
    dataDir,
  );
  // Same treatment as --data-dir: the path is used verbatim (wsl.exe -e
  // launches the recorder inside the distro, where a Linux path is right).
  if (opts.policyPath !== undefined) args.push('--policy', opts.policyPath);
  args.push('--', ...originalArgv);

  const entry: ServerEntry = { ...original, command: 'wsl.exe', args };

  // Windows env vars only cross the WSL boundary when their names are
  // listed in WSLENV (colon-separated) — being present in `env` alone does
  // nothing. Carry the original env object over unchanged (wsl.exe itself
  // still needs these set on its OWN process environment to have anything
  // to forward) and extend WSLENV with each of its keys so they actually
  // reach the recorded server running inside WSL.
  const originalEnv = original.env;
  if (originalEnv !== undefined && Object.keys(originalEnv).length > 0) {
    const forwardKeys = Object.keys(originalEnv).filter((k) => k !== 'WSLENV');
    const wslenv = mergeWslEnv(originalEnv.WSLENV, forwardKeys);
    entry.env = wslenv.length > 0 ? { ...originalEnv, WSLENV: wslenv } : { ...originalEnv };
  }

  return entry;
}

/** Build the wrapped replacement for one entry. `env`, `cwd`, and any other
 * keys are carried over untouched (`wrapper: 'wsl'` extends `env.WSLENV`,
 * see {@link buildWslWrappedEntry}); otherwise only `command`/`args` change. */
export function buildWrappedEntry(name: string, original: ServerEntry, opts: WrapOpts): ServerEntry {
  const originalArgv = [original.command as string, ...(original.args ?? [])];

  if (opts.wrapper === 'wsl') return buildWslWrappedEntry(name, original, originalArgv, opts);

  const recorderArgs: string[] = [];
  if (opts.wrapper === 'npx') recorderArgs.push('-y', '@edut/mcp-recorder');
  recorderArgs.push('record', '--name', name);
  if (opts.dataDir !== undefined) recorderArgs.push('--data-dir', opts.dataDir);
  if (opts.policyPath !== undefined) recorderArgs.push('--policy', opts.policyPath);
  recorderArgs.push('--', ...originalArgv);

  const command = opts.wrapper === 'npx' ? 'npx' : process.execPath;
  const args = opts.wrapper === 'npx' ? recorderArgs : [opts.localWrapperPath, ...recorderArgs];

  return { ...original, command, args };
}

/** Decide, for every entry in `servers`, whether it gets wrapped, skipped, or
 * is already wrapped — and build the replacement map. Order of entries in
 * `next` follows `servers`' own key order. */
export function planWrap(servers: McpServersMap, opts: WrapOpts): WrapPlan {
  const next: McpServersMap = { ...servers };
  const wrapped: string[] = [];
  const skipped: SkipEntry[] = [];
  const alreadyWrapped: string[] = [];
  const originals: Record<string, ServerEntry> = {};
  const notes: string[] = [];

  for (const [name, entry] of Object.entries(servers)) {
    if (opts.only !== undefined && !opts.only.has(name)) {
      skipped.push({ name, reason: 'not selected by --only' });
      continue;
    }
    if (opts.except !== undefined && opts.except.has(name)) {
      skipped.push({ name, reason: 'excluded by --except' });
      continue;
    }
    const transportReason = transportSkipReason(entry);
    if (transportReason !== undefined) {
      skipped.push({ name, reason: transportReason });
      continue;
    }
    if (isAlreadyWrapped(entry, opts.localWrapperPath)) {
      alreadyWrapped.push(name);
      continue;
    }
    const wrappedEntry = buildWrappedEntry(name, entry, opts);
    next[name] = wrappedEntry;
    originals[name] = entry;
    wrapped.push(name);
    if (opts.wrapper === 'wsl' && wrappedEntry.env?.WSLENV !== undefined) {
      notes.push(
        `${name}: env forwarded into WSL via WSLENV=${wrappedEntry.env.WSLENV} ` +
          '(wsl.exe only forwards Windows env vars listed there)',
      );
    }
  }

  return { next, wrapped, skipped, alreadyWrapped, originals, notes };
}

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
export function structuralUnwrap(entry: ServerEntry): ServerEntry | undefined {
  const args = entry.args;
  if (!Array.isArray(args)) return undefined;

  // Search for the "--" that closes the recorder's OWN args starting from
  // the "record" marker, not blindly the array's first "--": a prefix with
  // extra leading flags (wsl.exe's "-d <distro> -e ...") still parses
  // correctly this way, and — more importantly — a "--" that happens to
  // appear inside the wrapped server's OWN argv can never be mistaken for
  // the recorder's separator (it always comes after "record", never before).
  const recordIdx = args.indexOf('record');
  const sepIdx = args.indexOf('--', recordIdx === -1 ? 0 : recordIdx);
  if (sepIdx === -1) return undefined;

  const prefix = [entry.command, ...args.slice(0, sepIdx)].filter(
    (p): p is string => typeof p === 'string',
  );
  const looksLikeOurWrapper =
    prefix.includes('record') &&
    prefix.some(
      (p) => p.includes('@edut/mcp-recorder') || p.includes('mcp-recorder') || p.endsWith('cli.js'),
    );
  if (!looksLikeOurWrapper) return undefined;

  const originalArgv = args.slice(sepIdx + 1);
  if (originalArgv.length === 0) return undefined;
  const [command, ...rest] = originalArgv;
  return { ...entry, command, args: rest };
}
