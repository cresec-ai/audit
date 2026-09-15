/**
 * Cross-platform child spawning for the wrapped MCP server, without a new
 * runtime dependency (no `cross-spawn`).
 *
 * The problem this solves: on win32, Node's `child_process.spawn()` refuses
 * to launch a `.cmd`/`.bat` file directly without `shell: true` (Node's
 * CVE-2024-27980 hardening throws EINVAL instead), and a bare command name
 * like `npx` is not itself an executable Windows knows how to run — the real
 * binary on disk is `npx.cmd` (a batch shim installed by npm), which must be
 * found on PATH first. `resolveCommand` does that lookup; `planSpawn`
 * decides, from the resolved file's extension, whether the child needs to be
 * launched through `cmd.exe` and (if so) builds the escaped command line;
 * `spawnWrapped` is the thin wrapper the proxy actually calls.
 *
 * Everything here is a pure function of its inputs (command/env/platform,
 * plus an injectable fs probe) so it is fully testable on Linux by
 * simulating `platform: 'win32'` — see test/spawn.test.ts.
 */

import { spawn, spawnSync, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { existsSync, statSync } from 'node:fs';
import { posix as pathPosix, win32 as pathWin32 } from 'node:path';

/** The bits of `node:fs` resolveCommand needs, injectable for tests. */
export interface FsProbe {
  existsSync: (path: string) => boolean;
  statSync: (path: string) => { isFile(): boolean };
}

const defaultFs: FsProbe = { existsSync, statSync };

/** Default Windows executable extension search order (matches cmd.exe's own default). */
const DEFAULT_PATHEXT = '.COM;.EXE;.BAT;.CMD';

function isFile(fs: FsProbe, path: string): boolean {
  if (!fs.existsSync(path)) return false;
  try {
    return fs.statSync(path).isFile();
  } catch {
    return false;
  }
}

/** Case-insensitive env lookup: Windows env var casing (PATH/Path/path) is not reliable. */
function envLookup(env: NodeJS.ProcessEnv, name: string): string | undefined {
  const key = Object.keys(env).find((k) => k.toUpperCase() === name.toUpperCase());
  return key ? env[key] : undefined;
}

function pathExtList(env: NodeJS.ProcessEnv): string[] {
  const raw = envLookup(env, 'PATHEXT') || DEFAULT_PATHEXT;
  return raw.split(';').filter((ext) => ext.length > 0);
}

function pathDirs(env: NodeJS.ProcessEnv): string[] {
  const raw = envLookup(env, 'PATH') || '';
  return raw.split(';').filter((dir) => dir.length > 0);
}

/**
 * Resolves `command` to an absolute path on win32 the same way cmd.exe /
 * CreateProcess would: if it has no directory component, search each PATH
 * entry (';'-delimited) trying each PATHEXT extension in order (honouring an
 * extension the command already has, e.g. `npx.cmd`, instead of appending
 * more); if it has a directory component, resolve extensions against that
 * path directly without touching PATH. Falls back to returning `command`
 * unchanged when nothing on disk matches (or on any non-win32 platform,
 * where Node's own exec semantics already do the right thing) — a doomed
 * spawn then surfaces as the usual ENOENT rather than being silently altered
 * here.
 */
export function resolveCommand(
  command: string,
  env: NodeJS.ProcessEnv,
  platform: NodeJS.Platform,
  fs: FsProbe = defaultFs,
): string {
  if (platform !== 'win32' || command === '') return command;

  const exts = pathExtList(env);
  const lowerCommand = command.toLowerCase();
  const hasKnownExt = exts.some((ext) => lowerCommand.endsWith(ext.toLowerCase()));
  const candidates = (base: string): string[] => (hasKnownExt ? [base] : exts.map((ext) => base + ext));

  const hasDirComponent = command.includes('/') || command.includes('\\');
  if (hasDirComponent) {
    for (const candidate of candidates(command)) {
      if (isFile(fs, candidate)) return candidate;
    }
    return command;
  }

  for (const dir of pathDirs(env)) {
    for (const candidate of candidates(pathWin32.join(dir, command))) {
      if (isFile(fs, candidate)) return candidate;
    }
  }
  return command;
}

export interface SpawnPlan {
  file: string;
  args: string[];
  options: {
    windowsVerbatimArguments?: boolean;
    windowsHide?: boolean;
  };
}

/**
 * cmd.exe metacharacters, cross-spawn's set: everything cmd.exe's own lexer
 * would otherwise act on, INCLUDING the space — that is what lets an
 * unquoted command path such as `C:\Program Files\nodejs\npx.cmd` stay
 * one token once each space is caret-escaped.
 */
const CMD_META_CHARS_RE = /([()\][%!^"`<>&|;, *?])/g;
const LINE_BREAK_RE = /[\r\n]/;

/**
 * Escapes the command itself (the resolved `.cmd`/`.bat` path) for a
 * `cmd.exe /d /s /c "<line>"` invocation: normalize the path, then
 * caret-escape its metacharacters. It is deliberately NOT quoted — a `^ `
 * escaped space keeps the path one token in cmd.exe's command-name lexer,
 * which is how cross-spawn launches `C:\Program Files\nodejs\npm.cmd`.
 */
export function escapeCmdCommand(command: string): string {
  return pathWin32.normalize(command).replace(CMD_META_CHARS_RE, '^$1');
}

/**
 * Escapes one argument for the same invocation. This is cross-spawn's
 * well-established algorithm (https://github.com/moxystudio/node-cross-spawn),
 * reproduced here to avoid taking on the dependency:
 *
 *   1. double every backslash run that immediately precedes a double quote,
 *      then escape that quote with a backslash (the MSVCRT argv rules the
 *      target program will apply);
 *   2. double a trailing backslash run for the same reason (a closing quote
 *      is about to follow it);
 *   3. wrap the whole token in double quotes, so a space inside it does not
 *      split the argument;
 *   4. caret-escape every cmd.exe metacharacter (this also escapes the quotes
 *      just added, which is intentional: cmd.exe's lexer consumes the carets
 *      and hands the target the quoted form).
 *
 * Every target that reaches this code path is a batch file, and a batch
 * file re-parses its own parameters: the `%*` / `%1` substitution inside
 * `npx.cmd` runs the text through cmd.exe's lexer a SECOND time. So step 4
 * is applied twice — the first pass turns `^^^"` back into `^"`, the batch
 * file's own pass turns that into a literal `"`. With a single pass, an
 * argument containing a double quote reaches the batch file as a bare `"`,
 * toggles cmd.exe's quote mode mid-line and swallows everything after it.
 * (cross-spawn applies the second pass only to npm's `node_modules/.bin`
 * shims because it cannot tell what else it is launching; here the branch is
 * taken only for `.cmd`/`.bat` files, so it always applies.)
 *
 * NOTE (same limitation as cross-spawn): `%VAR%` expansion by cmd.exe cannot
 * be made fully safe — cmd.exe expands `%...%` in phase 1, before any caret
 * is honoured, quoted or not. argv here comes from the operator's own
 * trusted client config (the same JSON that already names the binary to
 * run), not from anything a remote MCP peer controls, so this is an
 * accepted, documented gap rather than a hardened boundary. Line breaks are
 * the one control character that cannot be tolerated even so, and planSpawn
 * refuses them (see LINE_BREAK_RE there).
 */
export function escapeCmdArg(arg: string, doubleEscapeMetaChars: boolean): string {
  let out = `"${escapeBackslashRuns(String(arg))}"`;
  out = out.replace(CMD_META_CHARS_RE, '^$1');
  if (doubleEscapeMetaChars) out = out.replace(CMD_META_CHARS_RE, '^$1');
  return out;
}

/**
 * Steps 1 and 2 of escapeCmdArg as a single linear scan: a run of
 * backslashes directly before a double quote is doubled and the quote
 * escaped (`\\\"` for one backslash + quote); a run at the very end is
 * doubled too, because the caller appends a closing quote right after it;
 * every other backslash is literal. Written as a loop on purpose — the
 * regex form of this rule, `/(\\*)"/g`, backtracks quadratically on a long
 * run of backslashes with no quote after it (cross-spawn's CVE-2024-21538).
 */
function escapeBackslashRuns(arg: string): string {
  let out = '';
  let run = 0;
  for (let i = 0; i < arg.length; i++) {
    const ch = arg[i]!;
    if (ch === '\\') {
      run++;
      continue;
    }
    if (ch === '"') {
      out += '\\'.repeat(run * 2) + '\\"';
    } else {
      out += '\\'.repeat(run) + ch;
    }
    run = 0;
  }
  return out + '\\'.repeat(run * 2);
}

function comspec(env: NodeJS.ProcessEnv): string {
  return envLookup(env, 'COMSPEC') || 'cmd.exe';
}

/**
 * Builds the actual spawn plan for `argv` (argv[0] is the command, the rest
 * its arguments). On non-win32 this is the identity plan — spawn argv[0]
 * directly, no options. On win32: `argv[0]` is resolved against PATH/PATHEXT
 * first; if the resolved file is a `.cmd`/`.bat` shim (npx, npm, uvx, ...
 * installed as such), it cannot be exec'd directly (Node throws EINVAL), so
 * the plan routes it through `cmd.exe /d /s /c "<escaped line>"` with
 * `windowsVerbatimArguments: true` (Node must not re-quote arguments we
 * already escaped ourselves). Any other resolved file (an actual `.exe`/
 * `.com`, or a script Windows can exec directly) is spawned as-is, no shell.
 * Throws when a token bound for cmd.exe contains a line break (unescapable).
 */
export function planSpawn(
  argv: string[],
  env: NodeJS.ProcessEnv,
  platform: NodeJS.Platform,
  fs: FsProbe = defaultFs,
): SpawnPlan {
  const command = argv[0] ?? '';
  const args = argv.slice(1);

  if (platform !== 'win32') {
    return { file: command, args, options: {} };
  }

  const resolved = resolveCommand(command, env, platform, fs);
  const isCmdOrBat = /\.(cmd|bat)$/i.test(resolved);
  if (!isCmdOrBat) {
    return { file: resolved, args, options: { windowsHide: true } };
  }

  // A line break cannot be escaped for cmd.exe at all: the lexer ends the
  // command there and runs whatever follows as a second command. Refuse the
  // launch outright (this throws before anything is spawned or recorded;
  // the CLI reports it as a plain error) rather than risk it.
  const tokens = [resolved, ...args];
  const broken = tokens.findIndex((t) => LINE_BREAK_RE.test(t));
  if (broken !== -1) {
    throw new Error(
      `refusing to launch ${command} through cmd.exe: argument ${broken} contains a line break ` +
        '(cmd.exe would run the text after it as a separate command)',
    );
  }

  const escapedLine = [escapeCmdCommand(resolved), ...args.map((a) => escapeCmdArg(a, true))].join(' ');
  return {
    file: comspec(env),
    args: ['/d', '/s', '/c', `"${escapedLine}"`],
    options: { windowsVerbatimArguments: true, windowsHide: true },
  };
}

/**
 * Spawns the wrapped MCP server per `planSpawn`, with the same stdio shape
 * the proxy has always used (three pipes). The RECORDED argv/server name is
 * never derived from this: callers keep using the operator's original
 * `argv` for that, since a `.cmd` shim being routed through `cmd.exe` here
 * is an implementation detail of how the process gets started, not a change
 * to what was actually configured.
 */
export function spawnWrapped(
  argv: string[],
  env: NodeJS.ProcessEnv,
  plan: SpawnPlan = planSpawn(argv, env, process.platform),
): ChildProcessWithoutNullStreams {
  return spawn(plan.file, plan.args, {
    stdio: ['pipe', 'pipe', 'pipe'] as const,
    env,
    ...plan.options,
  });
}

/**
 * Appends (never prepends) the directory containing the currently running
 * Node binary to `env`'s PATH, when it is not already present. This is what
 * lets a wrapped command like `npx` resolve when the recorder process itself
 * was launched by an absolute path to a specific Node binary with a minimal
 * PATH (nvm/fnm shims, a WSL bridge invoking a Windows Node, or a Windows
 * MCP client launching `node.exe` directly with `PATH` trimmed down) —
 * `npx`/`npm`/`corepack` are installed next to that same Node binary.
 * Appending (not prepending) means it can never shadow a binary the operator
 * put earlier on their own PATH on purpose. Applies on every platform, not
 * just win32 — the same failure mode (absolute node path, thin PATH) shows
 * up on POSIX launchers too.
 */
export function withNodeDirOnPath(
  env: NodeJS.ProcessEnv,
  execPath: string,
  platform: NodeJS.Platform = process.platform,
): NodeJS.ProcessEnv {
  const dir = platform === 'win32' ? pathWin32.dirname(execPath) : pathPosix.dirname(execPath);
  const delimiter = platform === 'win32' ? ';' : ':';
  const pathKey = Object.keys(env).find((k) => k.toUpperCase() === 'PATH') ?? 'PATH';
  const current = env[pathKey] ?? '';
  const segments = current.length > 0 ? current.split(delimiter) : [];
  const alreadyPresent = segments.some((seg) =>
    platform === 'win32' ? seg.toLowerCase() === dir.toLowerCase() : seg === dir,
  );
  if (alreadyPresent || dir.length === 0) return env;
  return {
    ...env,
    [pathKey]: current.length > 0 ? `${current}${delimiter}${dir}` : dir,
  };
}

/** Kill the process tree rooted at `pid` with `taskkill /T /F`. True only
 * when taskkill ran AND reported success — `spawnSync` does not throw when
 * the binary is missing or exits non-zero, it reports that in its result. */
function defaultTaskkill(pid: number): boolean {
  try {
    const res = spawnSync('taskkill', ['/pid', String(pid), '/T', '/F'], {
      stdio: 'ignore',
      windowsHide: true,
    });
    return res.error === undefined && res.status === 0;
  } catch {
    return false;
  }
}

/**
 * Terminates the wrapped child. On win32, `child.kill(signal)` doesn't
 * honour the signal (Windows has no POSIX signals) and, critically, doesn't
 * reach the child's own descendants — for a `.cmd`/`.bat` shim spawned
 * through `cmd.exe` (see `planSpawn`), the process the MCP client actually
 * cares about is a *grandchild* of the child we hold a handle to, and it
 * survives a plain `child.kill()`. `taskkill /T /F` kills the whole process
 * tree rooted at the child's pid instead. Falls back to `child.kill()`
 * whenever taskkill did not succeed (missing binary, non-zero exit, no pid
 * because the spawn itself failed) — termination must never throw. POSIX
 * behaviour is unchanged: a real signal, no subprocess. `taskkill` is
 * injectable for tests.
 */
export function terminateChild(
  child: { pid?: number; kill: (signal?: NodeJS.Signals | number) => boolean },
  signal: NodeJS.Signals,
  platform: NodeJS.Platform = process.platform,
  taskkill: (pid: number) => boolean = defaultTaskkill,
): void {
  if (platform === 'win32' && child.pid !== undefined && taskkill(child.pid)) return;
  try {
    child.kill(signal);
  } catch {
    /* child already gone */
  }
}
