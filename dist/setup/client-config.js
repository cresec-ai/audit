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
import { existsSync } from 'node:fs';
import { homedir } from 'node:os';
import { join, resolve } from 'node:path';
import { windowsClientConfigCandidates } from './wsl.js';
export const CLIENT_KINDS = ['claude-desktop', 'claude-code', 'cursor'];
export function isClientKind(value) {
    return CLIENT_KINDS.includes(value);
}
function claudeDesktopConfigPath() {
    if (process.platform === 'darwin') {
        return join(homedir(), 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json');
    }
    if (process.platform === 'win32') {
        const appData = process.env.APPDATA ?? join(homedir(), 'AppData', 'Roaming');
        return join(appData, 'Claude', 'claude_desktop_config.json');
    }
    return join(homedir(), '.config', 'Claude', 'claude_desktop_config.json');
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
function resolveWithWslFallback(client, linuxPath, wsl, fileExists) {
    if (fileExists(linuxPath) || wsl === undefined || !wsl.inWsl)
        return { path: linuxPath };
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
        case 'claude-desktop':
            return resolveWithWslFallback(client, claudeDesktopConfigPath(), wsl, fileExists);
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