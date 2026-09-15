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
import { type ChildProcessWithoutNullStreams } from 'node:child_process';
/** The bits of `node:fs` resolveCommand needs, injectable for tests. */
export interface FsProbe {
    existsSync: (path: string) => boolean;
    statSync: (path: string) => {
        isFile(): boolean;
    };
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
export declare function resolveCommand(command: string, env: NodeJS.ProcessEnv, platform: NodeJS.Platform, fs?: FsProbe): string;
export interface SpawnPlan {
    file: string;
    args: string[];
    options: {
        windowsVerbatimArguments?: boolean;
        windowsHide?: boolean;
    };
}
/**
 * Escapes the command itself (the resolved `.cmd`/`.bat` path) for a
 * `cmd.exe /d /s /c "<line>"` invocation: normalize the path, then
 * caret-escape its metacharacters. It is deliberately NOT quoted — a `^ `
 * escaped space keeps the path one token in cmd.exe's command-name lexer,
 * which is how cross-spawn launches `C:\Program Files\nodejs\npm.cmd`.
 */
export declare function escapeCmdCommand(command: string): string;
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
export declare function escapeCmdArg(arg: string, doubleEscapeMetaChars: boolean): string;
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
export declare function planSpawn(argv: string[], env: NodeJS.ProcessEnv, platform: NodeJS.Platform, fs?: FsProbe): SpawnPlan;
/**
 * Spawns the wrapped MCP server per `planSpawn`, with the same stdio shape
 * the proxy has always used (three pipes). The RECORDED argv/server name is
 * never derived from this: callers keep using the operator's original
 * `argv` for that, since a `.cmd` shim being routed through `cmd.exe` here
 * is an implementation detail of how the process gets started, not a change
 * to what was actually configured.
 */
export declare function spawnWrapped(argv: string[], env: NodeJS.ProcessEnv, plan?: SpawnPlan): ChildProcessWithoutNullStreams;
/**
 * Adds the directory containing the currently running Node binary to
 * `env`'s PATH when it is not already present — appended, except that on
 * WSL it goes ahead of the Windows interop entries (see below). This is what
 * lets a wrapped command like `npx` resolve when the recorder process itself
 * was launched by an absolute path to a specific Node binary with a minimal
 * PATH (nvm/fnm shims, a WSL bridge invoking a Windows Node, or a Windows
 * MCP client launching `node.exe` directly with `PATH` trimmed down) —
 * `npx`/`npm`/`corepack` are installed next to that same Node binary.
 * Appending (not prepending) means it can never shadow a binary the operator
 * put earlier on their own PATH on purpose; the Windows interop entries WSL
 * adds are the one exception, since nothing there is an operator choice.
 * Applies on every platform, not just win32 — the same failure mode
 * (absolute node path, thin PATH) shows up on POSIX launchers too.
 */
export declare function withNodeDirOnPath(env: NodeJS.ProcessEnv, execPath: string, platform?: NodeJS.Platform): NodeJS.ProcessEnv;
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
export declare function terminateChild(child: {
    pid?: number;
    kill: (signal?: NodeJS.Signals | number) => boolean;
}, signal: NodeJS.Signals, platform?: NodeJS.Platform, taskkill?: (pid: number) => boolean): void;
