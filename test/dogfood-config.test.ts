import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

/**
 * The repo-root .mcp.json is the dogfood config: it wraps this repo's own MCP
 * servers through the recorder run from source, so `npm ci` + Claude Code is
 * enough to start recording with nothing built. This test only checks its
 * *shape* (it never spawns the servers) so a careless edit can't silently
 * rot it — e.g. dropping `--data-dir`, forgetting the `--` separator, or
 * pointing at a build artifact that doesn't exist until `npm run build` runs.
 */

const CONFIG_PATH = resolve(__dirname, '..', '.mcp.json');

interface McpServerEntry {
  command: string;
  args: string[];
  [key: string]: unknown;
}

interface McpConfig {
  mcpServers: Record<string, McpServerEntry>;
}

function loadConfig(): McpConfig {
  const raw = readFileSync(CONFIG_PATH, 'utf8');
  return JSON.parse(raw) as McpConfig;
}

describe('.mcp.json (repo-root dogfood config)', () => {
  it('parses as JSON with an mcpServers object', () => {
    const config = loadConfig();
    expect(config.mcpServers).toBeTypeOf('object');
    expect(Object.keys(config.mcpServers).length).toBeGreaterThan(0);
  });

  it('every entry has a string command and a string[] args', () => {
    const { mcpServers } = loadConfig();
    for (const [name, entry] of Object.entries(mcpServers)) {
      expect(entry.command, `${name}.command`).toBeTypeOf('string');
      expect(Array.isArray(entry.args), `${name}.args`).toBe(true);
      for (const arg of entry.args) {
        expect(arg, `${name}.args entry`).toBeTypeOf('string');
      }
    }
  });

  it('every entry runs the recorder from source (npx tsx src/cli.ts), not a build artifact', () => {
    const { mcpServers } = loadConfig();
    for (const [name, entry] of Object.entries(mcpServers)) {
      expect(entry.command, name).toBe('npx');
      expect(entry.args.slice(0, 2), name).toEqual(['tsx', 'src/cli.ts']);
      // Never point at dist/ here — the whole point is that `npm ci` alone
      // (no build) is enough for this config to work on a fresh clone.
      expect(entry.args.join(' '), name).not.toContain('dist/');
    }
  });

  it('every entry records into the gitignored .mcp-recorder data dir', () => {
    const { mcpServers } = loadConfig();
    for (const [name, entry] of Object.entries(mcpServers)) {
      const i = entry.args.indexOf('--data-dir');
      expect(i, `${name} missing --data-dir`).toBeGreaterThanOrEqual(0);
      expect(entry.args[i + 1], name).toBe('.mcp-recorder');
    }
  });

  it('every entry names itself with --name and separates the wrapped command with --', () => {
    const { mcpServers } = loadConfig();
    for (const [name, entry] of Object.entries(mcpServers)) {
      const nameFlag = entry.args.indexOf('--name');
      expect(nameFlag, `${name} missing --name`).toBeGreaterThanOrEqual(0);
      expect(entry.args[nameFlag + 1], name).toBe(name);

      const sep = entry.args.indexOf('--');
      expect(sep, `${name} missing -- separator`).toBeGreaterThan(nameFlag);
      // There must be an actual wrapped command after the separator.
      expect(entry.args.length, name).toBeGreaterThan(sep + 1);
    }
  });

  it('wraps the demo corp-notes server and the filesystem server scoped to the repo', () => {
    const { mcpServers } = loadConfig();
    expect(mcpServers['corp-notes'], 'corp-notes entry').toBeDefined();
    expect(mcpServers['corp-notes'].args.join(' ')).toContain('demo/server.ts');

    const fsEntry = Object.values(mcpServers).find((e) =>
      e.args.some((a) => a.includes('server-filesystem')),
    );
    expect(fsEntry, 'a @modelcontextprotocol/server-filesystem entry').toBeDefined();
    // Scoped to the repo directory (".") — never an absolute host path baked
    // into a config meant to work from any clone.
    expect(fsEntry!.args.at(-1)).toBe('.');
  });
});
