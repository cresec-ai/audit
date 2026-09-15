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
 * Escapes one command-line token for a `cmd.exe /d /s /c "<line>"` verbatim
 * invocation. This is cross-spawn's well-established algorithm
 * (https://github.com/moxystudio/node-cross-spawn), reproduced here to avoid
 * taking on the dependency: double any backslashes that immediately precede
 * a double quote (so they don't escape it once we add our own closing
 * quote), then escape the quote itself with a backslash; double any
 * backslashes that fall right at the end of the string for the same reason;
 * wrap the whole token in double quotes (so cmd.exe's tokenizer treats it as
 * one argument even when it contains spaces); then caret-escape the cmd.exe
 * metacharacters `()%!^"<>&|` (this also re-escapes the quotes just added,
 * which is intentional and matches cross-spawn — the token is parsed once by
 * cmd.exe's own command-line lexer and needs to survive that before the
 * quotes it wraps mean anything to the target program).
 *
 * NOTE (same limitation as cross-spawn): this cannot make `%VAR%` expansion
 * by cmd.exe fully safe — cmd.exe expands `%...%` sequences in an argument
 * even when it's quoted, before the target program ever sees it. argv here
 * comes from the operator's own trusted client config (the same JSON that
 * already names the binary to run), not from anything a remote MCP peer
 * controls, so this is an accepted, documented gap rather than a hardened
 * boundary.
 */
function escapeCmdArg(arg: string): string {
  let out = String(arg);
  out = out.replace(/(\\*)"/g, '$1$1\\"');
  out = out.replace(/(\\*)$/, '$1$1');
  out = `"${out}"`;
  out = out.replace(/([()%!^"<>&|])/g, '^$1');
  return out;
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

  const escapedLine = [resolved, ...args].map(escapeCmdArg).join(' ');
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
export function spawnWrapped(argv: string[], env: NodeJS.ProcessEnv): ChildProcessWithoutNullStreams {
  const plan = planSpawn(argv, env, process.platform);
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

/**
 * Terminates the wrapped child. On win32, `child.kill(signal)` doesn't
 * honour the signal (Windows has no POSIX signals) and, critically, doesn't
 * reach the child's own descendants — for a `.cmd`/`.bat` shim spawned
 * through `cmd.exe` (see `planSpawn`), the process the MCP client actually
 * cares about is a *grandchild* of the child we hold a handle to, and it
 * survives a plain `child.kill()`. `taskkill /T /F` kills the whole process
 * tree rooted at the child's pid instead. Falls back to `child.kill()` if
 * `taskkill` itself is unavailable or errors (fail-open: termination must
 * never throw). POSIX behaviour is unchanged — a real signal, no subprocess.
 */
export function terminateChild(
  child: { pid?: number; kill: (signal?: NodeJS.Signals | number) => boolean },
  signal: NodeJS.Signals,
  platform: NodeJS.Platform = process.platform,
): void {
  if (platform === 'win32' && child.pid !== undefined) {
    try {
      spawnSync('taskkill', ['/pid', String(child.pid), '/T', '/F'], { stdio: 'ignore' });
      return;
    } catch {
      /* fall through to child.kill() below */
    }
  }
  try {
    child.kill(signal);
  } catch {
    /* child already gone */
  }
}
