/**
 * The repo's own .mcp.json wraps its demo server and a filesystem server with
 * the recorder run from source, through scripts/dogfood-wrap.sh (which also
 * installs dependencies on a fresh clone or cloud container). These tests keep
 * that config from rotting silently, and drive the wrapper once end to end.
 */
import { spawn } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

import { openStoreReadOnly } from '../src/store/index.js';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const CONFIG_PATH = join(ROOT, '.mcp.json');
const ECHO_SERVER = join(ROOT, 'test', 'fixtures', 'echo-server.cjs');

interface Entry {
  command: string;
  args: string[];
}

function loadConfig(): Record<string, Entry> {
  const parsed = JSON.parse(readFileSync(CONFIG_PATH, 'utf8')) as { mcpServers: Record<string, Entry> };
  expect(parsed.mcpServers).toBeTypeOf('object');
  expect(Object.keys(parsed.mcpServers).length).toBeGreaterThan(0);
  return parsed.mcpServers;
}

describe('platform hooks call the shared bootstrap', () => {
  it('Copilot setup steps, Cursor environment and Codex config reference scripts/bootstrap.sh or the wrapper', () => {
    const copilot = readFileSync(join(ROOT, '.github', 'workflows', 'copilot-setup-steps.yml'), 'utf8');
    expect(copilot).toMatch(/^\s*copilot-setup-steps:/m);
    expect(copilot).toContain('sh scripts/bootstrap.sh');
    const cursorEnv = JSON.parse(readFileSync(join(ROOT, '.cursor', 'environment.json'), 'utf8')) as { install: string };
    expect(cursorEnv.install).toBe('sh scripts/bootstrap.sh');
    const cursorMcp = JSON.parse(readFileSync(join(ROOT, '.cursor', 'mcp.json'), 'utf8')) as { mcpServers: Record<string, Entry> };
    expect(cursorMcp.mcpServers['corp-notes']!.args[0]).toBe('scripts/dogfood-wrap.sh');
    const codex = readFileSync(join(ROOT, '.codex', 'config.toml'), 'utf8');
    expect(codex).toContain('[mcp_servers.corp_notes]');
    expect(codex).toContain('scripts/dogfood-wrap.sh');
    expect(readFileSync(join(ROOT, 'AGENTS.md'), 'utf8')).toContain('sh scripts/bootstrap.sh');
  });
});

describe('.mcp.json dogfood config', () => {
  it('runs every server through the dogfood wrapper with a matching --name and a wrapped command', () => {
    for (const [name, entry] of Object.entries(loadConfig())) {
      expect(entry.command, `${name}.command`).toBe('sh');
      expect(entry.args[0], `${name} wrapper`).toBe('scripts/dogfood-wrap.sh');
      const nameFlag = entry.args.indexOf('--name');
      expect(nameFlag, `${name} missing --name`).toBeGreaterThan(0);
      expect(entry.args[nameFlag + 1], name).toBe(name);
      const sep = entry.args.indexOf('--');
      expect(sep, `${name} missing -- separator`).toBeGreaterThan(nameFlag);
      expect(entry.args.length, `${name} has no wrapped command`).toBeGreaterThan(sep + 1);
      expect(entry.args.join(' '), name).not.toContain('dist/');
    }
  });

  it('wraps the demo corp-notes server and a filesystem server scoped to the repo', () => {
    const servers = loadConfig();
    expect(servers['corp-notes']).toBeDefined();
    expect(servers['corp-notes']!.args.join(' ')).toContain('demo/server.ts');
    const fsEntry = Object.values(servers).find((e) =>
      e.args.some((a) => a.includes('@modelcontextprotocol/server-filesystem')),
    );
    expect(fsEntry, 'a @modelcontextprotocol/server-filesystem entry').toBeDefined();
    expect(fsEntry!.args.at(-1)).toBe('.');
  });

  it('the wrapper records a session end to end (dependencies present, data dir from env)', async () => {
    const dataDir = mkdtempSync(join(tmpdir(), 'mcp-recorder-dogfood-'));
    try {
      const child = spawn(
        'sh',
        ['scripts/dogfood-wrap.sh', '--name', 'dogfood-test', '--', 'node', ECHO_SERVER],
        { cwd: ROOT, env: { ...process.env, MCP_RECORDER_DATA_DIR: dataDir }, stdio: ['pipe', 'pipe', 'pipe'] },
      );
      let stdout = '';
      let stderr = '';
      child.stdout.setEncoding('utf8');
      child.stderr.setEncoding('utf8');
      child.stdout.on('data', (c: string) => (stdout += c));
      child.stderr.on('data', (c: string) => (stderr += c));
      child.stdin.write(
        JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2024-11-05', clientInfo: { name: 'dogfood', version: '1' }, capabilities: {} } }) + '\n',
      );
      child.stdin.write(
        JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'echo', arguments: { hello: 'world' } } }) + '\n',
      );
      // Wait for both replies, then close the client side as a real client would.
      const deadline = Date.now() + 20_000;
      while (Date.now() < deadline && (stdout.match(/"id":2/g) ?? []).length === 0) {
        await new Promise((r) => setTimeout(r, 50));
      }
      child.stdin.end();
      const code = await new Promise<number | null>((resolve) => child.on('close', resolve));
      expect(code, stderr).toBe(0);
      expect(stdout).toContain('"id":1');
      expect(stdout).toContain('"id":2');
      expect(stderr).toContain('(0 dropped)');

      const store = openStoreReadOnly({ dataDir });
      const sessions = store.sessions();
      store.close();
      expect(sessions).toHaveLength(1);
      expect(sessions[0]!.server_name).toBe('dogfood-test');
      expect(sessions[0]!.tool_call_count).toBe(1);
    } finally {
      rmSync(dataDir, { recursive: true, force: true });
    }
  }, 60_000);
});
