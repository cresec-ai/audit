import { execFileSync, spawn } from 'node:child_process';
import type { ChildProcess } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { Readable } from 'node:stream';
import { fileURLToPath } from 'node:url';
import { afterEach, beforeAll, describe, expect, it } from 'vitest';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const ECHO_SERVER = fileURLToPath(new URL('./fixtures/echo-server.cjs', import.meta.url));
const SIDECAR_SUFFIX = '.mcp-recorder-setup.json';

/* ------------------------------- helpers --------------------------------
 * Mirrors the small spawn/collect/lineReader helpers test/cli.test.ts
 * defines for itself — `setup` is exercised the same way, via the real CLI,
 * always with --config pointed at a temp file.
 */

const cleanups: Array<() => void> = [];
afterEach(() => {
  while (cleanups.length > 0) {
    try {
      cleanups.pop()!();
    } catch {
      /* best-effort teardown */
    }
  }
});

function tmpDir(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  cleanups.push(() => rmSync(dir, { recursive: true, force: true }));
  return dir;
}

function writeConfig(dir: string, name: string, value: unknown, indent = 2): string {
  const path = join(dir, name);
  writeFileSync(path, JSON.stringify(value, null, indent) + '\n');
  return path;
}

function sidecarFor(configPath: string): string {
  return configPath + SIDECAR_SUFFIX;
}

interface CliResult {
  code: number | null;
  stdout: string;
  stderr: string;
}

function collect(stream: Readable | null): () => string {
  let text = '';
  stream?.setEncoding('utf8');
  stream?.on('data', (chunk: string) => {
    text += chunk;
  });
  return () => text;
}

function waitExit(child: ChildProcess): Promise<number | null> {
  return new Promise((resolve) => child.once('close', (code) => resolve(code)));
}

function spawnCli(args: string[]): ChildProcess {
  const child = spawn('npx', ['tsx', 'src/cli.ts', ...args], {
    cwd: ROOT,
    env: { ...process.env, MCP_RECORDER_DISABLE: undefined },
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  cleanups.push(() => {
    if (child.exitCode === null) child.kill('SIGKILL');
  });
  return child;
}

async function runCli(args: string[]): Promise<CliResult> {
  const child = spawnCli(args);
  const stdout = collect(child.stdout);
  const stderr = collect(child.stderr);
  child.stdin?.end();
  const code = await waitExit(child);
  return { code, stdout: stdout(), stderr: stderr() };
}

interface LineReader {
  next(timeoutMs?: number): Promise<string>;
}

function lineReader(stream: Readable): LineReader {
  const ready: string[] = [];
  const waiters: Array<(line: string) => void> = [];
  let buf = '';
  stream.setEncoding('utf8');
  stream.on('data', (chunk: string) => {
    buf += chunk;
    let nl: number;
    while ((nl = buf.indexOf('\n')) !== -1) {
      const line = buf.slice(0, nl).trim();
      buf = buf.slice(nl + 1);
      if (line === '') continue;
      const waiter = waiters.shift();
      if (waiter !== undefined) waiter(line);
      else ready.push(line);
    }
  });
  return {
    next(timeoutMs = 20_000): Promise<string> {
      const got = ready.shift();
      if (got !== undefined) return Promise.resolve(got);
      return new Promise((resolve, reject) => {
        const timer = setTimeout(
          () => reject(new Error('timed out waiting for a stdout line')),
          timeoutMs,
        );
        waiters.push((line) => {
          clearTimeout(timer);
          resolve(line);
        });
      });
    },
  };
}

interface RpcMsg {
  jsonrpc: string;
  id?: string | number;
  method?: string;
  result?: Record<string, unknown>;
  error?: unknown;
}

async function readResponse(reader: LineReader, id: number): Promise<RpcMsg> {
  for (let i = 0; i < 20; i++) {
    const line = await reader.next();
    let msg: RpcMsg;
    try {
      msg = JSON.parse(line) as RpcMsg;
    } catch {
      continue;
    }
    if (msg.id === id) return msg;
  }
  throw new Error(`no response with id ${id}`);
}

const PROBE = 'setup-e2e-probe-98765';

/** Drive initialize + one tools/call over a wrapped stdio server's stdin/stdout. */
async function driveEchoSession(child: ChildProcess): Promise<void> {
  const reader = lineReader(child.stdout!);
  const send = (msg: unknown): void => {
    child.stdin!.write(JSON.stringify(msg) + '\n');
  };

  send({
    jsonrpc: '2.0',
    id: 1,
    method: 'initialize',
    params: {
      protocolVersion: '2024-11-05',
      clientInfo: { name: 'setup-e2e-client', version: '0.0.1' },
      capabilities: {},
    },
  });
  const init = await readResponse(reader, 1);
  expect((init.result as { serverInfo: { name: string } }).serverInfo.name).toBe('echo-server');

  send({
    jsonrpc: '2.0',
    id: 2,
    method: 'tools/call',
    params: { name: 'echo', arguments: { note: PROBE } },
  });
  const call = await readResponse(reader, 2);
  expect(JSON.stringify(call.result)).toContain(PROBE);

  child.stdin!.end();
}

/* -------------------------------- fixtures -------------------------------- */

interface ServerEntry {
  command?: string;
  args?: string[];
  url?: string;
  type?: string;
  env?: Record<string, string>;
  cwd?: string;
}

/** A claude-desktop-shaped config: two stdio servers (one with env, one with
 * cwd) and one remote (url/http) server that must be skipped. */
function claudeDesktopFixture(): { mcpServers: Record<string, ServerEntry> } {
  return {
    mcpServers: {
      filesystem: {
        command: 'npx',
        args: ['-y', '@modelcontextprotocol/server-filesystem', '/tmp/projects'],
        env: { FOO: 'bar' },
      },
      custom: {
        command: 'node',
        args: ['./server.js'],
        cwd: '/some/dir',
      },
      remote: {
        url: 'https://example.com/mcp',
        type: 'http',
      },
    },
  };
}

/* ---------------------------------------------------------------------- */

describe('mcp-recorder setup', () => {
  it(
    'wraps both stdio servers, skips the url server, preserves env/cwd, ' +
      'stamps --name, and writes a backup + sidecar preserving indentation',
    async () => {
      const dir = tmpDir('mcp-rec-setup-');
      const configPath = writeConfig(dir, 'claude_desktop_config.json', claudeDesktopFixture(), 4);
      const original = readFileSync(configPath, 'utf8');
      const filesBefore = readdirSync(dir);

      const res = await runCli(['setup', '--config', configPath, '--data-dir', join(dir, 'data'), '--json']);
      expect(res.code).toBe(0);
      const result = JSON.parse(res.stdout) as {
        config: string;
        backup: string;
        wrapped: string[];
        skipped: Array<{ name: string; reason: string }>;
        already_wrapped: string[];
      };

      expect(result.config).toBe(configPath);
      expect([...result.wrapped].sort()).toEqual(['custom', 'filesystem']);
      expect(result.already_wrapped).toEqual([]);
      expect(result.skipped).toHaveLength(1);
      expect(result.skipped[0]!.name).toBe('remote');
      expect(result.skipped[0]!.reason).toMatch(/url|remote|http/i);

      // --- backup ------------------------------------------------------
      expect(filesBefore).not.toContain(result.backup.slice(dir.length + 1));
      expect(existsSync(result.backup)).toBe(true);
      expect(readFileSync(result.backup, 'utf8')).toBe(original);

      // --- sidecar -------------------------------------------------------
      const sidecarPath = sidecarFor(configPath);
      expect(existsSync(sidecarPath)).toBe(true);
      const sidecar = JSON.parse(readFileSync(sidecarPath, 'utf8')) as {
        version: number;
        wrapped: Record<string, ServerEntry>;
      };
      expect(sidecar.wrapped.filesystem).toEqual(claudeDesktopFixture().mcpServers.filesystem);
      expect(sidecar.wrapped.custom).toEqual(claudeDesktopFixture().mcpServers.custom);

      // --- rewritten config ------------------------------------------------
      const updatedRaw = readFileSync(configPath, 'utf8');
      const updated = JSON.parse(updatedRaw) as { mcpServers: Record<string, ServerEntry> };

      // env/cwd preserved untouched
      expect(updated.mcpServers.filesystem!.env).toEqual({ FOO: 'bar' });
      expect(updated.mcpServers.custom!.cwd).toBe('/some/dir');
      // remote entry untouched entirely
      expect(updated.mcpServers.remote).toEqual(claudeDesktopFixture().mcpServers.remote);

      // --name is stamped with the entry's own name
      for (const name of ['filesystem', 'custom']) {
        const args = updated.mcpServers[name]!.args!;
        const i = args.indexOf('--name');
        expect(i, `${name} --name`).toBeGreaterThanOrEqual(0);
        expect(args[i + 1]).toBe(name);
        expect(args).toContain('--');
      }
      // original argv still present after the '--' separator
      const fsArgs = updated.mcpServers.filesystem!.args!;
      const fsSep = fsArgs.indexOf('--');
      expect(fsArgs.slice(fsSep + 1)).toEqual([
        'npx',
        '-y',
        '@modelcontextprotocol/server-filesystem',
        '/tmp/projects',
      ]);

      // 4-space indentation preserved (the fixture was written with 4)
      const lines = updatedRaw.split('\n');
      expect(lines[1]).toMatch(/^ {4}"mcpServers"/);
    },
    30_000,
  );

  it('idempotent: a second run reports already_wrapped and writes nothing new', async () => {
    const dir = tmpDir('mcp-rec-setup-idempotent-');
    const configPath = writeConfig(dir, 'config.json', claudeDesktopFixture());

    const first = await runCli(['setup', '--config', configPath, '--json']);
    expect(first.code).toBe(0);
    const afterFirst = readFileSync(configPath, 'utf8');
    const filesAfterFirst = readdirSync(dir).sort();

    const second = await runCli(['setup', '--config', configPath, '--json']);
    expect(second.code).toBe(0);
    const result = JSON.parse(second.stdout) as {
      backup: string | null;
      wrapped: string[];
      already_wrapped: string[];
    };
    expect(result.wrapped).toEqual([]);
    expect([...result.already_wrapped].sort()).toEqual(['custom', 'filesystem']);
    expect(result.backup).toBeNull();

    // nothing rewritten, no new backup file created
    expect(readFileSync(configPath, 'utf8')).toBe(afterFirst);
    expect(readdirSync(dir).sort()).toEqual(filesAfterFirst);
  }, 30_000);

  it('--only wraps just the named server(s); everything else is reported skipped', async () => {
    const dir = tmpDir('mcp-rec-setup-only-');
    const configPath = writeConfig(dir, 'config.json', claudeDesktopFixture());

    const res = await runCli(['setup', '--config', configPath, '--only', 'filesystem', '--json']);
    expect(res.code).toBe(0);
    const result = JSON.parse(res.stdout) as {
      wrapped: string[];
      skipped: Array<{ name: string; reason: string }>;
    };
    expect(result.wrapped).toEqual(['filesystem']);
    expect([...result.skipped.map((s) => s.name)].sort()).toEqual(['custom', 'remote']);
    for (const s of result.skipped) expect(s.reason).toContain('--only');
  }, 30_000);

  it('--except wraps everything but the named server(s)', async () => {
    const dir = tmpDir('mcp-rec-setup-except-');
    const configPath = writeConfig(dir, 'config.json', claudeDesktopFixture());

    const res = await runCli(['setup', '--config', configPath, '--except', 'custom', '--json']);
    expect(res.code).toBe(0);
    const result = JSON.parse(res.stdout) as {
      wrapped: string[];
      skipped: Array<{ name: string; reason: string }>;
    };
    expect(result.wrapped).toEqual(['filesystem']);
    const custom = result.skipped.find((s) => s.name === 'custom');
    expect(custom?.reason).toContain('--except');
    const remote = result.skipped.find((s) => s.name === 'remote');
    expect(remote).toBeDefined();
  }, 30_000);

  it('--wrapper npx produces exactly the published-package form the README documents', async () => {
    const dir = tmpDir('mcp-rec-setup-npx-');
    const configPath = writeConfig(dir, 'config.json', {
      mcpServers: {
        filesystem: {
          command: 'npx',
          args: ['-y', '@modelcontextprotocol/server-filesystem', '/tmp'],
        },
      },
    });

    const res = await runCli(['setup', '--config', configPath, '--wrapper', 'npx', '--json']);
    expect(res.code).toBe(0);

    const updated = JSON.parse(readFileSync(configPath, 'utf8')) as { mcpServers: Record<string, ServerEntry> };
    expect(updated.mcpServers.filesystem).toEqual({
      command: 'npx',
      args: [
        '-y',
        '@edut/mcp-recorder',
        'record',
        '--name',
        'filesystem',
        '--',
        'npx',
        '-y',
        '@modelcontextprotocol/server-filesystem',
        '/tmp',
      ],
    });
  }, 30_000);

  it('--dry-run prints the plan and exits 0 without writing anything', async () => {
    const dir = tmpDir('mcp-rec-setup-dryrun-');
    const configPath = writeConfig(dir, 'config.json', claudeDesktopFixture());
    const before = readFileSync(configPath, 'utf8');

    const res = await runCli(['setup', '--config', configPath, '--dry-run', '--json']);
    expect(res.code).toBe(0);
    const result = JSON.parse(res.stdout) as { wrapped: string[]; backup: string | null };
    expect([...result.wrapped].sort()).toEqual(['custom', 'filesystem']);
    expect(result.backup).toBeNull();

    expect(readFileSync(configPath, 'utf8')).toBe(before);
    expect(existsSync(sidecarFor(configPath))).toBe(false);
    expect(readdirSync(dir)).toEqual(['config.json']);
  }, 30_000);

  it('--undo restores byte-for-byte from the sidecar, and removes it', async () => {
    const dir = tmpDir('mcp-rec-setup-undo-sidecar-');
    const configPath = writeConfig(dir, 'config.json', claudeDesktopFixture());
    const original = readFileSync(configPath, 'utf8');

    const wrap = await runCli(['setup', '--config', configPath]);
    expect(wrap.code).toBe(0);
    expect(readFileSync(configPath, 'utf8')).not.toBe(original);
    expect(existsSync(sidecarFor(configPath))).toBe(true);

    const undo = await runCli(['setup', '--config', configPath, '--undo', '--json']);
    expect(undo.code).toBe(0);
    const result = JSON.parse(undo.stdout) as { restored: string[]; used_sidecar: boolean };
    expect([...result.restored].sort()).toEqual(['custom', 'filesystem']);
    expect(result.used_sidecar).toBe(true);

    expect(readFileSync(configPath, 'utf8')).toBe(original);
    expect(existsSync(sidecarFor(configPath))).toBe(false);
  }, 30_000);

  it('--undo structurally unwraps (byte-for-byte) when the sidecar is missing', async () => {
    const dir = tmpDir('mcp-rec-setup-undo-nosidecar-');
    const configPath = writeConfig(dir, 'config.json', claudeDesktopFixture());
    const original = readFileSync(configPath, 'utf8');

    const wrap = await runCli(['setup', '--config', configPath]);
    expect(wrap.code).toBe(0);
    rmSync(sidecarFor(configPath));

    const undo = await runCli(['setup', '--config', configPath, '--undo', '--json']);
    expect(undo.code).toBe(0);
    const result = JSON.parse(undo.stdout) as { restored: string[]; used_sidecar: boolean };
    expect([...result.restored].sort()).toEqual(['custom', 'filesystem']);
    expect(result.used_sidecar).toBe(false);

    expect(readFileSync(configPath, 'utf8')).toBe(original);
  }, 30_000);

  it('invalid JSON exits 2 and leaves the file untouched', async () => {
    const dir = tmpDir('mcp-rec-setup-badjson-');
    const configPath = join(dir, 'config.json');
    writeFileSync(configPath, '{\n  "mcpServers": { // a comment\n    "x": {}\n  }\n}\n');
    const before = readFileSync(configPath, 'utf8');

    const res = await runCli(['setup', '--config', configPath]);
    expect(res.code).toBe(2);
    expect(res.stderr).toContain('[mcp-recorder] error:');

    expect(readFileSync(configPath, 'utf8')).toBe(before);
    expect(existsSync(sidecarFor(configPath))).toBe(false);
    expect(existsSync(`${configPath}.bak`)).toBe(false);
  }, 30_000);

  it('a missing config file exits 1 and names the resolved path', async () => {
    const dir = tmpDir('mcp-rec-setup-missing-');
    const configPath = join(dir, 'does-not-exist.json');

    const res = await runCli(['setup', '--config', configPath]);
    expect(res.code).toBe(1);
    expect(res.stderr).toContain(configPath);
  }, 30_000);

  it('--json prints the {config, backup, wrapped, skipped, already_wrapped} shape', async () => {
    const dir = tmpDir('mcp-rec-setup-jsonshape-');
    const configPath = writeConfig(dir, 'config.json', claudeDesktopFixture());

    const res = await runCli(['setup', '--config', configPath, '--json']);
    expect(res.code).toBe(0);
    const result = JSON.parse(res.stdout) as Record<string, unknown>;
    expect(Object.keys(result).sort()).toEqual(
      ['already_wrapped', 'backup', 'config', 'skipped', 'wrapped'].sort(),
    );
    expect(result.config).toBe(configPath);
    expect(typeof result.backup).toBe('string');
    expect(Array.isArray(result.wrapped)).toBe(true);
    expect(Array.isArray(result.skipped)).toBe(true);
    expect(Array.isArray(result.already_wrapped)).toBe(true);
  }, 30_000);

  describe('--wrapper local end-to-end', () => {
    // wrapper: 'local' points at THIS install's dist/cli.js (see cli.ts's
    // resolveLocalWrapperPath) — a real build has to exist on disk for the
    // wrapped entry to actually be spawnable, same as any real install.
    beforeAll(() => {
      const cliJs = join(ROOT, 'dist', 'cli.js');
      if (existsSync(cliJs)) return;
      execFileSync('npm', ['run', 'build'], { cwd: ROOT, stdio: 'ignore' });
    }, 120_000);

    it('wraps echo-server.cjs, spawns the wrapped entry exactly as a client would, and records a session', async () => {
      const dir = tmpDir('mcp-rec-setup-e2e-');
      const dataDir = join(dir, 'data');
      const configPath = writeConfig(dir, 'config.json', {
        mcpServers: {
          echo: { command: 'node', args: [ECHO_SERVER] },
        },
      });

      const setupRes = await runCli([
        'setup',
        '--config',
        configPath,
        '--wrapper',
        'local',
        '--data-dir',
        dataDir,
        '--json',
      ]);
      expect(setupRes.code).toBe(0);
      const setupResult = JSON.parse(setupRes.stdout) as { wrapped: string[] };
      expect(setupResult.wrapped).toEqual(['echo']);

      const updated = JSON.parse(readFileSync(configPath, 'utf8')) as {
        mcpServers: Record<string, { command: string; args: string[] }>;
      };
      const entry = updated.mcpServers.echo!;
      expect(entry.command).toBe(process.execPath);
      expect(entry.args[0]).toBe(join(ROOT, 'dist', 'cli.js'));

      // Spawn exactly what a client would: entry.command with entry.args.
      const child = spawn(entry.command, entry.args, { stdio: ['pipe', 'pipe', 'pipe'] });
      cleanups.push(() => {
        if (child.exitCode === null) child.kill('SIGKILL');
      });
      const stderrText = collect(child.stderr);
      await driveEchoSession(child);
      const code = await waitExit(child);
      expect(code).toBe(0);
      expect(stderrText()).toMatch(/\[mcp-recorder\] session [0-9a-f]{8} recorded \d+ events/);

      const sessions = await runCli(['sessions', '--data-dir', dataDir, '--json']);
      expect(sessions.code).toBe(0);
      const list = JSON.parse(sessions.stdout) as Array<{ server_name: string; tool_call_count: number }>;
      expect(list).toHaveLength(1);
      expect(list[0]!.server_name).toBe('echo');
      expect(list[0]!.tool_call_count).toBe(1);
    }, 60_000);
  });
});
