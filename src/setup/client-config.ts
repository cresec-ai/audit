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

export type ClientKind = 'claude-desktop' | 'claude-code' | 'cursor';

export const CLIENT_KINDS: readonly ClientKind[] = ['claude-desktop', 'claude-code', 'cursor'];

export function isClientKind(value: string): value is ClientKind {
  return (CLIENT_KINDS as readonly string[]).includes(value);
}

function claudeDesktopConfigPath(): string {
  if (process.platform === 'darwin') {
    return join(homedir(), 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json');
  }
  if (process.platform === 'win32') {
    const appData = process.env.APPDATA ?? join(homedir(), 'AppData', 'Roaming');
    return join(appData, 'Claude', 'claude_desktop_config.json');
  }
  return join(homedir(), '.config', 'Claude', 'claude_desktop_config.json');
}

export interface ResolvedConfigPath {
  path: string;
  /** Set when the resolution made a choice worth telling the operator about
   * (e.g. preferring a project-local .mcp.json). Printed as a diagnostic. */
  note?: string;
}

/**
 * Resolve the client config file `setup` should edit. Only the top-level
 * `mcpServers` object is ever read or written — for `claude-code`'s
 * `~/.claude.json` that means the user-scope servers, not any per-project
 * overrides nested under a `projects` key.
 */
export function resolveClientConfigPath(
  client: ClientKind | undefined,
  configFlag: string | undefined,
  cwd: string,
): ResolvedConfigPath {
  if (configFlag !== undefined) return { path: resolve(cwd, configFlag) };
  if (client === undefined) {
    throw new Error(
      'setup: --client <claude-desktop|claude-code|cursor> is required (or pass --config PATH)',
    );
  }
  switch (client) {
    case 'claude-desktop':
      return { path: claudeDesktopConfigPath() };
    case 'claude-code': {
      const projectConfig = resolve(cwd, '.mcp.json');
      if (existsSync(projectConfig)) {
        return {
          path: projectConfig,
          note:
            'found .mcp.json in the current directory — using it instead of ~/.claude.json ' +
            '(pass --config to override)',
        };
      }
      return { path: join(homedir(), '.claude.json') };
    }
    case 'cursor':
      return { path: join(homedir(), '.cursor', 'mcp.json') };
  }
}
