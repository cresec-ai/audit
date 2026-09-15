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
  wrapper: 'local' | 'npx';
  /** Absolute path to dist/cli.js for the install running `setup` — only
   * used for wrapper: 'local', and to recognize an entry this exact install
   * already wrapped. */
  localWrapperPath: string;
  dataDir?: string;
  /** --only NAME[,NAME...]: wrap nothing outside this set. */
  only?: ReadonlySet<string>;
  /** --except NAME[,NAME...]: wrap everything except this set. */
  except?: ReadonlySet<string>;
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
 * exact install's local wrapper path). Wrapping it again would nest proxies. */
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

/** Build the wrapped replacement for one entry. `env`, `cwd`, and any other
 * keys are carried over untouched; only `command`/`args` change. */
export function buildWrappedEntry(name: string, original: ServerEntry, opts: WrapOpts): ServerEntry {
  const originalArgv = [original.command as string, ...(original.args ?? [])];
  const recorderArgs: string[] = [];
  if (opts.wrapper === 'npx') recorderArgs.push('-y', '@edut/mcp-recorder');
  recorderArgs.push('record', '--name', name);
  if (opts.dataDir !== undefined) recorderArgs.push('--data-dir', opts.dataDir);
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
    next[name] = buildWrappedEntry(name, entry, opts);
    originals[name] = entry;
    wrapped.push(name);
  }

  return { next, wrapped, skipped, alreadyWrapped, originals };
}

/**
 * `setup --undo` fallback when the sidecar file is missing: strip a
 * recognizable recorder-wrapper prefix back off to recover the original
 * command/args. Returns undefined when `entry` doesn't look like one of ours
 * (left alone by the caller). Only `command`/`args` are reconstructed — any
 * other keys (env, cwd, ...) were never touched by wrapping, so they're
 * already correct on `entry`.
 */
export function structuralUnwrap(entry: ServerEntry): ServerEntry | undefined {
  const args = entry.args;
  if (!Array.isArray(args)) return undefined;
  const sepIdx = args.indexOf('--');
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
