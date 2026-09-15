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
import { existsSync, readdirSync } from 'node:fs';
import { homedir } from 'node:os';
import { join, posix, resolve, win32 } from 'node:path';
import { windowsClientConfigCandidates } from './wsl.js';
// The win32 branch of claudeDesktopConfigPath() below builds Windows paths
// regardless of the host platform it happens to execute on (tests simulate
// `platform: 'win32'` from any OS — see test/client-config.test.ts), so it
// deliberately uses path.win32 rather than the ambient, host-dependent
// `join`. On a real Windows host the two are identical; this only changes
// output on a non-Windows host, where it's what makes the simulation
// meaningful.
const joinWin32 = win32.join;
// Same reasoning for the darwin/linux branches: with `platform` injected as
// 'darwin' on a Windows host, the ambient `join` would produce backslashes.
const joinPosix = posix.join;
export const CLIENT_KINDS = ['claude-desktop', 'claude-code', 'cursor'];
export function isClientKind(value) {
    return CLIENT_KINDS.includes(value);
}
/**
 * Where Claude Desktop's config lives, per platform. On win32 there are two
 * install shapes: an ordinary installer, which uses `%APPDATA%\Claude\...`
 * (the primary, tried first and always preferred when it exists), and an
 * MSIX / Microsoft Store install, which is sandboxed into a
 * per-package-identity `LocalCache` under
 * `%LOCALAPPDATA%\Packages\Claude_<publisher-hash>\LocalCache\Roaming\Claude\...`
 * — `Claude_` plus an opaque hash that differs per machine, hence the
 * `Claude_*` glob. `fileExists`/`listDir` are injectable (real `fs` by
 * default) so this is testable by simulating `platform: 'win32'` on any
 * host, the same pattern `src/proxy/spawn.ts` uses.
 */
export function claudeDesktopConfigPath(fileExists = existsSync, listDir = readdirSync, platform = process.platform, env = process.env) {
    if (platform === 'darwin') {
        return { path: joinPosix(homedir(), 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json') };
    }
    if (platform === 'win32') {
        const appData = env.APPDATA ?? joinWin32(homedir(), 'AppData', 'Roaming');
        const primary = joinWin32(appData, 'Claude', 'claude_desktop_config.json');
        if (fileExists(primary))
            return { path: primary };
        const localAppData = env.LOCALAPPDATA ?? joinWin32(homedir(), 'AppData', 'Local');
        const packagesDir = joinWin32(localAppData, 'Packages');
        let entries = [];
        try {
            entries = listDir(packagesDir);
        }
        catch {
            entries = [];
        }
        const msixCandidates = entries
            .filter((name) => name.startsWith('Claude_'))
            .sort()
            .map((name) => joinWin32(packagesDir, name, 'LocalCache', 'Roaming', 'Claude', 'claude_desktop_config.json'));
        const existingMsix = msixCandidates.filter((p) => fileExists(p));
        if (existingMsix.length === 1) {
            return {
                path: existingMsix[0],
                note: `Claude Desktop config found at its Microsoft Store (MSIX) install location ${existingMsix[0]} (no config at ${primary})`,
            };
        }
        if (existingMsix.length > 1) {
            throw new Error('setup: multiple Microsoft Store (MSIX) Claude Desktop config candidates found — pass --config PATH to pick one:\n' +
                existingMsix.map((p) => `  ${p}`).join('\n'));
        }
        return {
            path: primary,
            note: msixCandidates.length > 0
                ? `also checked for a Microsoft Store (MSIX) install (none found): ${msixCandidates.join(', ')}`
                : `also checked for a Microsoft Store (MSIX) install under ${packagesDir} (no Claude_* package found)`,
        };
    }
    return { path: joinPosix(homedir(), '.config', 'Claude', 'claude_desktop_config.json') };
}
const CLIENT_LABELS = {
    'claude-desktop': 'Claude Desktop',
    'claude-code': 'Claude Code',
    cursor: 'Cursor',
};
/**
 * When the Linux-side config for `client` doesn't exist and we're running
 * inside WSL, look for it on the Windows side instead (Claude Desktop is a
 * Windows program; its config never lives under Linux paths there).
 * Exactly one existing Windows-side candidate is used, with a note; several
 * is an error naming them all (ambiguous — the operator must pass
 * `--config`); none found falls back to the original Linux path, noting the
 * Windows path(s) that were checked so the eventual "config file not found"
 * message isn't a mystery.
 */
function resolveWithWslFallback(client, linuxPath, wsl, fileExists, 
/** A note already attached to `linuxPath` by its caller (e.g. the win32
 * MSIX note from {@link claudeDesktopConfigPath}) — carried through
 * whenever this function takes its own early-return path, since that path
 * doesn't otherwise produce a note of its own. The two never coexist:
 * `wsl.inWsl` is only ever true on Linux, where `claudeDesktopConfigPath`
 * never takes the win32 branch that produces this note in the first
 * place. */
primaryNote) {
    if (fileExists(linuxPath) || wsl === undefined || !wsl.inWsl) {
        return primaryNote !== undefined ? { path: linuxPath, note: primaryNote } : { path: linuxPath };
    }
    const windowsCandidates = windowsClientConfigCandidates(client, wsl.homeCandidates());
    const existing = windowsCandidates.filter((p) => fileExists(p));
    if (existing.length === 1) {
        return {
            path: existing[0],
            note: `${CLIENT_LABELS[client]} config found on the Windows side at ${existing[0]} (no config at ${linuxPath})`,
        };
    }
    if (existing.length > 1) {
        throw new Error(`setup: multiple Windows-side ${CLIENT_LABELS[client]} config candidates found — pass --config PATH to pick one:\n` +
            existing.map((p) => `  ${p}`).join('\n'));
    }
    if (windowsCandidates.length === 0)
        return { path: linuxPath };
    return {
        path: linuxPath,
        note: `also checked for a Windows-side config (none found): ${windowsCandidates.join(', ')}`,
    };
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
export function resolveClientConfigPath(client, configFlag, cwd, wsl, fileExists = existsSync) {
    if (configFlag !== undefined)
        return { path: resolve(cwd, configFlag) };
    if (client === undefined) {
        throw new Error('setup: --client <claude-desktop|claude-code|cursor> is required (or pass --config PATH)');
    }
    switch (client) {
        case 'claude-desktop': {
            const desktop = claudeDesktopConfigPath(fileExists);
            return resolveWithWslFallback(client, desktop.path, wsl, fileExists, desktop.note);
        }
        case 'claude-code': {
            const projectConfig = resolve(cwd, '.mcp.json');
            if (fileExists(projectConfig)) {
                return {
                    path: projectConfig,
                    note: 'found .mcp.json in the current directory — using it instead of ~/.claude.json ' +
                        '(pass --config to override)',
                };
            }
            return { path: join(homedir(), '.claude.json') };
        }
        case 'cursor':
            return resolveWithWslFallback(client, join(homedir(), '.cursor', 'mcp.json'), wsl, fileExists);
    }
}
//# sourceMappingURL=client-config.js.map