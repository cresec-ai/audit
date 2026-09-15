import { execFileSync, spawn } from 'node:child_process';
import type { ChildProcess } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { join } from 'node:path';
import type { Readable } from 'node:stream';
import { fileURLToPath } from 'node:url';
import { afterEach, beforeAll, describe, expect, it } from 'vitest';
import { spawnTsx } from './helpers/tsx.js';
import {
  bridgeEntry,
  buildWrappedEntry,
  isAlreadyWrapped,
  isSameBridgeEntry,
  mergeWslEnv,
  parseBridgeSpecs,
  structuralUnwrap,
} from '../src/setup/wrap.js';
import type { ServerEntry as WrapServerEntry } from '../src/setup/wrap.js';

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
  const child = spawnTsx(['src/cli.ts', ...args], {
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

  it('--json prints the {config, backup, wrapped, skipped, already_wrapped, bridged} shape', async () => {
    const dir = tmpDir('mcp-rec-setup-jsonshape-');
    const configPath = writeConfig(dir, 'config.json', claudeDesktopFixture());

    const res = await runCli(['setup', '--config', configPath, '--json']);
    expect(res.code).toBe(0);
    const result = JSON.parse(res.stdout) as Record<string, unknown>;
    expect(Object.keys(result).sort()).toEqual(
      ['already_wrapped', 'backup', 'bridged', 'config', 'notes', 'skipped', 'wrapped'].sort(),
    );
    expect(result.config).toBe(configPath);
    expect(typeof result.backup).toBe('string');
    expect(Array.isArray(result.wrapped)).toBe(true);
    expect(Array.isArray(result.skipped)).toBe(true);
    expect(Array.isArray(result.already_wrapped)).toBe(true);
    expect(result.bridged).toEqual([]);
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

/* ----------------------------- wrapper: 'wsl' ------------------------------
 * Pure-function coverage for the wsl.exe wrapper form (src/setup/wrap.ts) —
 * no client, no real wsl.exe/cmd.exe, direct imports like the rest of the
 * codebase's unit tests (see test/redact.test.ts, test/config.test.ts).
 */

describe('wrapper: wsl (buildWrappedEntry / mergeWslEnv)', () => {
  const LOCAL_WRAPPER = '/install/dist/cli.js';

  it('produces "wsl.exe -d <distro> -e <node> <wrapper> record --name N --data-dir D -- <original>"', () => {
    const original: WrapServerEntry = {
      command: 'npx',
      args: ['-y', '@modelcontextprotocol/server-filesystem', '/tmp'],
    };
    const entry = buildWrappedEntry('filesystem', original, {
      wrapper: 'wsl',
      localWrapperPath: LOCAL_WRAPPER,
      wslDistro: 'Ubuntu-22.04',
    });
    expect(entry.command).toBe('wsl.exe');
    expect(entry.args).toEqual([
      '-d',
      'Ubuntu-22.04',
      '-e',
      process.execPath,
      LOCAL_WRAPPER,
      'record',
      '--name',
      'filesystem',
      '--data-dir',
      join(homedir(), '.mcp-recorder'),
      '--',
      'npx',
      '-y',
      '@modelcontextprotocol/server-filesystem',
      '/tmp',
    ]);
    expect(entry.env).toBeUndefined();
  });

  it('omits the "-d" pair entirely when the distro is unknown', () => {
    const original: WrapServerEntry = { command: 'node', args: ['server.js'] };
    const entry = buildWrappedEntry('custom', original, { wrapper: 'wsl', localWrapperPath: LOCAL_WRAPPER });
    expect(entry.args!.slice(0, 2)).toEqual(['-e', process.execPath]);
    expect(entry.args).not.toContain('-d');
  });

  it('an explicit --data-dir is used verbatim instead of the ~/.mcp-recorder default', () => {
    const original: WrapServerEntry = { command: 'node', args: ['server.js'] };
    const entry = buildWrappedEntry('custom', original, {
      wrapper: 'wsl',
      localWrapperPath: LOCAL_WRAPPER,
      dataDir: '/custom/data',
    });
    const i = entry.args!.indexOf('--data-dir');
    expect(entry.args![i + 1]).toBe('/custom/data');
  });

  it('--data-dir is always present, even when nothing was requested (wsl.exe -e never expands ~)', () => {
    const original: WrapServerEntry = { command: 'node', args: ['server.js'] };
    const entry = buildWrappedEntry('custom', original, { wrapper: 'wsl', localWrapperPath: LOCAL_WRAPPER });
    expect(entry.args).toContain('--data-dir');
  });

  it('no env on the original entry -> no env on the wrapped entry', () => {
    const original: WrapServerEntry = { command: 'node', args: ['server.js'] };
    const entry = buildWrappedEntry('custom', original, { wrapper: 'wsl', localWrapperPath: LOCAL_WRAPPER });
    expect(entry.env).toBeUndefined();
  });

  it('carries env over unchanged and adds a fresh WSLENV listing every key', () => {
    const original: WrapServerEntry = { command: 'node', args: ['server.js'], env: { FOO: 'x', BAR: 'y' } };
    const entry = buildWrappedEntry('custom', original, { wrapper: 'wsl', localWrapperPath: LOCAL_WRAPPER });
    expect(entry.env).toEqual({ FOO: 'x', BAR: 'y', WSLENV: 'FOO:BAR' });
  });

  it('merges into an existing WSLENV without duplicating a key or losing its /flags', () => {
    const original: WrapServerEntry = {
      command: 'node',
      args: ['server.js'],
      env: { FOO: 'x', BAR: 'y', WSLENV: 'FOO/p:BAR' },
    };
    const entry = buildWrappedEntry('custom', original, { wrapper: 'wsl', localWrapperPath: LOCAL_WRAPPER });
    // FOO and BAR are both already listed (FOO with its /p flag preserved) —
    // nothing new to add, so WSLENV is unchanged.
    expect(entry.env).toEqual({ FOO: 'x', BAR: 'y', WSLENV: 'FOO/p:BAR' });
  });

  it('extends an existing WSLENV with only the genuinely new keys', () => {
    const original: WrapServerEntry = {
      command: 'node',
      args: ['server.js'],
      env: { FOO: 'x', BAZ: 'z', WSLENV: 'FOO/p' },
    };
    const entry = buildWrappedEntry('custom', original, { wrapper: 'wsl', localWrapperPath: LOCAL_WRAPPER });
    expect(entry.env).toEqual({ FOO: 'x', BAZ: 'z', WSLENV: 'FOO/p:BAZ' });
  });
});

describe('mergeWslEnv', () => {
  it('starts fresh (colon-joined) when there is no existing WSLENV', () => {
    expect(mergeWslEnv(undefined, ['FOO', 'BAR'])).toBe('FOO:BAR');
  });
  it('treats an empty existing value the same as undefined', () => {
    expect(mergeWslEnv('', ['FOO'])).toBe('FOO');
  });
  it('does not duplicate a key that is already listed, /flags and all', () => {
    expect(mergeWslEnv('FOO/p:BAR', ['FOO', 'BAR', 'BAZ'])).toBe('FOO/p:BAR:BAZ');
  });
  it('no new keys leaves the existing value untouched', () => {
    expect(mergeWslEnv('FOO:BAR', ['FOO'])).toBe('FOO:BAR');
  });
});

describe('isAlreadyWrapped — wsl.exe prefix', () => {
  it('recognizes localWrapperPath even behind a "wsl.exe -d <distro> -e ..." prefix', () => {
    const entry: WrapServerEntry = {
      command: 'wsl.exe',
      args: [
        '-d',
        'Ubuntu',
        '-e',
        '/usr/bin/node',
        '/install/dist/cli.js',
        'record',
        '--name',
        'x',
        '--data-dir',
        '/d',
        '--',
        'node',
        'server.js',
      ],
    };
    expect(isAlreadyWrapped(entry, '/install/dist/cli.js')).toBe(true);
  });

  it('a wsl.exe entry wrapping a DIFFERENT install is not "already wrapped" by this one', () => {
    const entry: WrapServerEntry = {
      command: 'wsl.exe',
      args: ['-e', '/usr/bin/node', '/other/install/dist/cli.js', 'record', '--name', 'x', '--', 'node', 'server.js'],
    };
    expect(isAlreadyWrapped(entry, '/install/dist/cli.js')).toBe(false);
  });
});

describe('structuralUnwrap — wsl.exe form', () => {
  it('restores command/args, stripping the full "wsl.exe -d ... -e ... record ... --" prefix', () => {
    const entry: WrapServerEntry = {
      command: 'wsl.exe',
      args: [
        '-d',
        'Ubuntu',
        '-e',
        '/usr/bin/node',
        '/install/dist/cli.js',
        'record',
        '--name',
        'custom',
        '--data-dir',
        '/home/joni/.mcp-recorder',
        '--',
        'node',
        'server.js',
        '--flag',
      ],
    };
    expect(structuralUnwrap(entry)).toEqual({ command: 'node', args: ['server.js', '--flag'] });
  });

  it('works without "-d" too (unknown distro)', () => {
    const entry: WrapServerEntry = {
      command: 'wsl.exe',
      args: [
        '-e',
        '/usr/bin/node',
        '/install/dist/cli.js',
        'record',
        '--name',
        'custom',
        '--data-dir',
        '/d',
        '--',
        'node',
        'server.js',
      ],
    };
    expect(structuralUnwrap(entry)).toEqual({ command: 'node', args: ['server.js'] });
  });

  it('is not confused by a "--" that appears inside the wrapped server\'s own argv', () => {
    const entry: WrapServerEntry = {
      command: 'wsl.exe',
      args: [
        '-e',
        '/usr/bin/node',
        '/install/dist/cli.js',
        'record',
        '--name',
        'custom',
        '--data-dir',
        '/d',
        '--',
        'node',
        'server.js',
        '--',
        'extra',
      ],
    };
    expect(structuralUnwrap(entry)).toEqual({ command: 'node', args: ['server.js', '--', 'extra'] });
  });

  it('leaves a WSLENV addition lingering in env (documented: only the sidecar restores exactly)', () => {
    const entry: WrapServerEntry = {
      command: 'wsl.exe',
      args: ['-e', '/usr/bin/node', '/install/dist/cli.js', 'record', '--name', 'custom', '--data-dir', '/d', '--', 'node', 'server.js'],
      env: { FOO: 'x', WSLENV: 'FOO' },
    };
    const restored = structuralUnwrap(entry);
    expect(restored).toBeDefined();
    expect(restored!.env).toEqual({ FOO: 'x', WSLENV: 'FOO' });
  });
});

/* ------------------------- CLI: --wrapper wsl / BOM ------------------------ */

describe('mcp-recorder setup — wsl wrapper & BOM handling (via the CLI)', () => {
  it('--wrapper wsl --dry-run produces the wsl.exe shape; needs no real wsl.exe or cmd.exe', async () => {
    const dir = tmpDir('mcp-rec-setup-wsl-dryrun-');
    const configPath = writeConfig(dir, 'config.json', {
      mcpServers: {
        filesystem: { command: 'npx', args: ['-y', '@modelcontextprotocol/server-filesystem', '/tmp'] },
      },
    });
    const before = readFileSync(configPath, 'utf8');

    const res = await runCli([
      'setup',
      '--config',
      configPath,
      '--wrapper',
      'wsl',
      '--data-dir',
      '/home/me/.mcp-recorder',
      '--dry-run',
    ]);
    expect(res.code).toBe(0);
    expect(res.stdout).toContain('wsl.exe');
    expect(res.stdout).toContain('"-e"');
    expect(res.stdout).toContain('"record"');
    expect(res.stdout).toContain('"--data-dir"');
    expect(res.stdout).toContain('"/home/me/.mcp-recorder"');

    // --dry-run never writes anything, wsl or not.
    expect(readFileSync(configPath, 'utf8')).toBe(before);
    expect(existsSync(sidecarFor(configPath))).toBe(false);
  }, 30_000);

  it('--wrapper wsl --json --dry-run reports the server as wrapped', async () => {
    const dir = tmpDir('mcp-rec-setup-wsl-json-');
    const configPath = writeConfig(dir, 'config.json', claudeDesktopFixture());

    const res = await runCli(['setup', '--config', configPath, '--wrapper', 'wsl', '--dry-run', '--json']);
    expect(res.code).toBe(0);
    const result = JSON.parse(res.stdout) as { wrapped: string[] };
    expect([...result.wrapped].sort()).toEqual(['custom', 'filesystem']);
  }, 30_000);

  it('a UTF-8 BOM at the start of the config is stripped before parsing and not written back', async () => {
    const dir = tmpDir('mcp-rec-setup-bom-');
    const configPath = join(dir, 'config.json');
    writeFileSync(configPath, '﻿' + JSON.stringify(claudeDesktopFixture(), null, 2) + '\n');

    const res = await runCli(['setup', '--config', configPath, '--json']);
    expect(res.code).toBe(0);
    expect(res.stderr).toMatch(/BOM/i);

    const result = JSON.parse(res.stdout) as { wrapped: string[] };
    expect([...result.wrapped].sort()).toEqual(['custom', 'filesystem']);

    const rewritten = readFileSync(configPath, 'utf8');
    expect(rewritten.charCodeAt(0)).not.toBe(0xfeff);
    const updated = JSON.parse(rewritten) as { mcpServers: Record<string, WrapServerEntry> };
    expect(updated.mcpServers.filesystem!.env).toEqual({ FOO: 'bar' });
  }, 30_000);

  it('a CRLF config (Windows-authored) is rewritten with CRLF, and --undo keeps it too', async () => {
    const dir = tmpDir('mcp-rec-setup-crlf-');
    const configPath = join(dir, 'config.json');
    const crlf = JSON.stringify(claudeDesktopFixture(), null, 2).replace(/\n/g, '\r\n') + '\r\n';
    writeFileSync(configPath, crlf);

    const wrap = await runCli(['setup', '--config', configPath]);
    expect(wrap.code).toBe(0);
    const rewritten = readFileSync(configPath, 'utf8');
    expect(rewritten).toContain('\r\n');
    // every newline is a CRLF one — no bare LF slipped in
    expect(rewritten.replace(/\r\n/g, '')).not.toContain('\n');
    expect(rewritten.endsWith('\r\n')).toBe(true);
    const updated = JSON.parse(rewritten) as { mcpServers: Record<string, WrapServerEntry> };
    expect(updated.mcpServers.filesystem!.command).not.toBe('npx');

    const undo = await runCli(['setup', '--config', configPath, '--undo']);
    expect(undo.code).toBe(0);
    expect(readFileSync(configPath, 'utf8')).toBe(crlf);
  }, 30_000);

  it('--undo works on a config that picked up a BOM after wrapping', async () => {
    const dir = tmpDir('mcp-rec-setup-bom-undo-');
    const configPath = writeConfig(dir, 'config.json', claudeDesktopFixture());
    const original = readFileSync(configPath, 'utf8');

    const wrap = await runCli(['setup', '--config', configPath]);
    expect(wrap.code).toBe(0);

    // Simulate a Windows tool re-saving the file with a BOM in between.
    writeFileSync(configPath, '﻿' + readFileSync(configPath, 'utf8'));

    const undo = await runCli(['setup', '--config', configPath, '--undo', '--json']);
    expect(undo.code).toBe(0);
    const result = JSON.parse(undo.stdout) as { restored: string[] };
    expect([...result.restored].sort()).toEqual(['custom', 'filesystem']);

    const rewritten = readFileSync(configPath, 'utf8');
    expect(rewritten.charCodeAt(0)).not.toBe(0xfeff);
    expect(JSON.parse(rewritten)).toEqual(JSON.parse(original));
  }, 30_000);
});

/* ------------------------------ --policy ----------------------------------
 * `setup --policy FILE` bakes `--policy <absolute path>` into every wrapped
 * entry (gateway mode). Pure-function coverage of src/setup/wrap.ts first,
 * then the CLI path (validation, dry-run, write, undo).
 */

describe('buildWrappedEntry / structuralUnwrap — policyPath (setup --policy)', () => {
  const LOCAL_WRAPPER = '/install/dist/cli.js';
  const original: WrapServerEntry = { command: 'npx', args: ['-y', '@modelcontextprotocol/server-filesystem', '/tmp'] };

  it('local: "--policy <path>" lands right after --data-dir, before the "--" separator', () => {
    const entry = buildWrappedEntry('filesystem', original, {
      wrapper: 'local',
      localWrapperPath: LOCAL_WRAPPER,
      dataDir: '/data',
      policyPath: '/abs/policy.yaml',
    });
    expect(entry.command).toBe(process.execPath);
    expect(entry.args).toEqual([
      LOCAL_WRAPPER,
      'record',
      '--name',
      'filesystem',
      '--data-dir',
      '/data',
      '--policy',
      '/abs/policy.yaml',
      '--',
      'npx',
      '-y',
      '@modelcontextprotocol/server-filesystem',
      '/tmp',
    ]);
  });

  it('npx: same position in the published-package form (no --data-dir given)', () => {
    const entry = buildWrappedEntry('filesystem', original, {
      wrapper: 'npx',
      localWrapperPath: LOCAL_WRAPPER,
      policyPath: '/abs/policy.yaml',
    });
    expect(entry).toEqual({
      command: 'npx',
      args: ['-y', '@edut/mcp-recorder', 'record', '--name', 'filesystem', '--policy', '/abs/policy.yaml', '--', 'npx', '-y', '@modelcontextprotocol/server-filesystem', '/tmp'],
    });
  });

  it('wsl: "--policy <path>" follows the always-present --data-dir, verbatim like it', () => {
    const entry = buildWrappedEntry('filesystem', original, {
      wrapper: 'wsl',
      localWrapperPath: LOCAL_WRAPPER,
      wslDistro: 'Ubuntu',
      dataDir: '/home/me/.mcp-recorder',
      policyPath: '/home/me/.mcp-recorder/policy.yaml',
    });
    expect(entry.command).toBe('wsl.exe');
    expect(entry.args).toEqual([
      '-d',
      'Ubuntu',
      '-e',
      process.execPath,
      LOCAL_WRAPPER,
      'record',
      '--name',
      'filesystem',
      '--data-dir',
      '/home/me/.mcp-recorder',
      '--policy',
      '/home/me/.mcp-recorder/policy.yaml',
      '--',
      'npx',
      '-y',
      '@modelcontextprotocol/server-filesystem',
      '/tmp',
    ]);
  });

  it('no policyPath -> no --policy anywhere (byte-identical to before)', () => {
    for (const wrapper of ['local', 'npx', 'wsl'] as const) {
      const entry = buildWrappedEntry('filesystem', original, { wrapper, localWrapperPath: LOCAL_WRAPPER });
      expect(entry.args).not.toContain('--policy');
    }
  });

  it('structuralUnwrap still recognises entries carrying --policy (local, npx and wsl forms)', () => {
    for (const wrapper of ['local', 'npx', 'wsl'] as const) {
      const wrapped = buildWrappedEntry('filesystem', original, {
        wrapper,
        localWrapperPath: LOCAL_WRAPPER,
        dataDir: '/data',
        policyPath: '/abs/policy.yaml',
        wslDistro: 'Ubuntu',
      });
      expect(structuralUnwrap(wrapped), wrapper).toEqual(original);
    }
  });

  it('an entry wrapped with --policy is recognised as already wrapped', () => {
    const wrapped = buildWrappedEntry('filesystem', original, {
      wrapper: 'local',
      localWrapperPath: LOCAL_WRAPPER,
      policyPath: '/abs/policy.yaml',
    });
    expect(isAlreadyWrapped(wrapped, LOCAL_WRAPPER)).toBe(true);
  });
});

describe('mcp-recorder setup --policy (via the CLI)', () => {
  const POLICY = 'version: 1\nmcp:\n  rules:\n    - id: no-exfil\n      match: { tool: http_post }\n      action: deny\n';

  it('bakes the ABSOLUTE policy path into every wrapped entry; --undo restores the originals', async () => {
    const dir = tmpDir('mcp-rec-setup-policy-');
    const configPath = writeConfig(dir, 'config.json', claudeDesktopFixture());
    const original = readFileSync(configPath, 'utf8');
    const policyPath = join(dir, 'policy.yaml');
    writeFileSync(policyPath, POLICY);

    // A relative --policy is resolved against the cwd (the repo root, where
    // the CLI is spawned) — so hand it the absolute path and check it is
    // written back verbatim as an absolute path.
    const res = await runCli(['setup', '--config', configPath, '--policy', policyPath, '--json']);
    expect(res.code).toBe(0);
    const result = JSON.parse(res.stdout) as { wrapped: string[] };
    expect([...result.wrapped].sort()).toEqual(['custom', 'filesystem']);

    const updated = JSON.parse(readFileSync(configPath, 'utf8')) as { mcpServers: Record<string, WrapServerEntry> };
    for (const name of ['filesystem', 'custom']) {
      const args = updated.mcpServers[name]!.args!;
      const i = args.indexOf('--policy');
      expect(i, `${name} --policy`).toBeGreaterThan(0);
      expect(args[i + 1]).toBe(policyPath);
      expect(i).toBeLessThan(args.indexOf('--'));
    }
    // the remote entry is untouched
    expect(updated.mcpServers.remote).toEqual(claudeDesktopFixture().mcpServers.remote);

    const undo = await runCli(['setup', '--config', configPath, '--undo']);
    expect(undo.code).toBe(0);
    expect(readFileSync(configPath, 'utf8')).toBe(original);
  }, 60_000);

  it('--dry-run shows the --policy argument and writes nothing', async () => {
    const dir = tmpDir('mcp-rec-setup-policy-');
    const configPath = writeConfig(dir, 'config.json', claudeDesktopFixture());
    const before = readFileSync(configPath, 'utf8');
    const policyPath = join(dir, 'policy.yaml');
    writeFileSync(policyPath, POLICY);

    const res = await runCli(['setup', '--config', configPath, '--policy', policyPath, '--dry-run']);
    expect(res.code).toBe(0);
    expect(res.stdout).toContain('dry run');
    expect(res.stdout).toContain('"--policy"');
    expect(res.stdout).toContain(JSON.stringify(policyPath));
    expect(readFileSync(configPath, 'utf8')).toBe(before);
    expect(existsSync(sidecarFor(configPath))).toBe(false);
  }, 30_000);

  it('a missing policy file exits 2 and leaves the config untouched', async () => {
    const dir = tmpDir('mcp-rec-setup-policy-');
    const configPath = writeConfig(dir, 'config.json', claudeDesktopFixture());
    const before = readFileSync(configPath, 'utf8');
    const res = await runCli(['setup', '--config', configPath, '--policy', join(dir, 'missing.yaml')]);
    expect(res.code).toBe(2);
    expect(res.stderr).toContain('cannot read policy file');
    expect(readFileSync(configPath, 'utf8')).toBe(before);
    expect(existsSync(sidecarFor(configPath))).toBe(false);
  }, 30_000);

  it('an invalid policy exits 2 (with the pointer lines) and leaves the config untouched', async () => {
    const dir = tmpDir('mcp-rec-setup-policy-');
    const configPath = writeConfig(dir, 'config.json', claudeDesktopFixture());
    const before = readFileSync(configPath, 'utf8');
    const policyPath = join(dir, 'policy.yaml');
    writeFileSync(policyPath, 'version: 1\nmcp:\n  rules:\n    - match: { tool: x }\n      action: nope\n');
    const res = await runCli(['setup', '--config', configPath, '--policy', policyPath, '--json']);
    expect(res.code).toBe(2);
    expect(res.stderr).toContain('invalid policy');
    expect(res.stderr).toContain('/mcp/rules/0/action');
    expect(res.stdout).toBe('');
    expect(readFileSync(configPath, 'utf8')).toBe(before);
  }, 30_000);

  it('a policy without an mcp section exits 2', async () => {
    const dir = tmpDir('mcp-rec-setup-policy-');
    const configPath = writeConfig(dir, 'config.json', claudeDesktopFixture());
    const policyPath = join(dir, 'policy.yaml');
    writeFileSync(policyPath, 'version: 1\negress:\n  default: deny\n');
    const res = await runCli(['setup', '--config', configPath, '--policy', policyPath]);
    expect(res.code).toBe(2);
    expect(res.stderr).toContain('no `mcp` section');
  }, 30_000);
});

/* ------------------ --bridge: remote MCP connectors via mcp-remote ------- */

describe('parseBridgeSpecs', () => {
  it('parses a single NAME=URL', () => {
    expect(parseBridgeSpecs(['clickup=https://mcp.clickup.com/mcp'])).toEqual([
      { name: 'clickup', url: 'https://mcp.clickup.com/mcp' },
    ]);
  });

  it('a repeatable flag (one element per --bridge) and comma-separated values within one element both work', () => {
    expect(
      parseBridgeSpecs(['a=https://a.example/mcp', 'b=https://b.example/mcp,c=https://c.example/mcp']),
    ).toEqual([
      { name: 'a', url: 'https://a.example/mcp' },
      { name: 'b', url: 'https://b.example/mcp' },
      { name: 'c', url: 'https://c.example/mcp' },
    ]);
  });

  it('accepts a name made only of letters, digits, "_", ".", "-"', () => {
    expect(parseBridgeSpecs(['my-server_v2.1=https://x.example/mcp'])).toEqual([
      { name: 'my-server_v2.1', url: 'https://x.example/mcp' },
    ]);
  });

  it('rejects a name with a character outside that set', () => {
    expect(() => parseBridgeSpecs(['cl ickup=https://mcp.clickup.com/mcp'])).toThrow(/--bridge/);
    expect(() => parseBridgeSpecs(['click@up=https://mcp.clickup.com/mcp'])).toThrow(/name/i);
  });

  it('rejects a spec with no "="', () => {
    expect(() => parseBridgeSpecs(['clickup'])).toThrow(/NAME=URL/);
  });

  it('rejects a URL that does not parse at all', () => {
    expect(() => parseBridgeSpecs(['clickup=not a url'])).toThrow(/URL/);
  });

  it('rejects a non-http(s) URL scheme', () => {
    expect(() => parseBridgeSpecs(['clickup=ftp://mcp.clickup.com/mcp'])).toThrow(/http/);
  });

  it('accepts plain http:// as well as https://', () => {
    expect(parseBridgeSpecs(['local=http://localhost:1234/mcp'])).toEqual([
      { name: 'local', url: 'http://localhost:1234/mcp' },
    ]);
  });

  it('ignores empty pieces (a trailing comma, blank --bridge)', () => {
    expect(parseBridgeSpecs(['a=https://a.example/mcp,'])).toEqual([{ name: 'a', url: 'https://a.example/mcp' }]);
    expect(parseBridgeSpecs([''])).toEqual([]);
  });
});

describe('bridgeEntry / isSameBridgeEntry', () => {
  const URL = 'https://mcp.clickup.com/mcp';

  it('bridgeEntry builds the "npx -y mcp-remote URL" unwrapped form', () => {
    expect(bridgeEntry(URL)).toEqual({ command: 'npx', args: ['-y', 'mcp-remote', URL] });
  });

  it('isSameBridgeEntry is true only for an exact match', () => {
    expect(isSameBridgeEntry(bridgeEntry(URL), URL)).toBe(true);
    expect(isSameBridgeEntry({ command: 'npx', args: ['-y', 'mcp-remote', URL] }, URL)).toBe(true);
  });

  it('isSameBridgeEntry is false for a different URL, command, argv, or extra keys', () => {
    expect(isSameBridgeEntry({ command: 'npx', args: ['-y', 'mcp-remote', 'https://other.example/mcp'] }, URL)).toBe(
      false,
    );
    expect(isSameBridgeEntry({ command: 'node', args: ['./server.js'] }, URL)).toBe(false);
    expect(isSameBridgeEntry({ command: 'npx', args: ['-y', 'mcp-remote'] }, URL)).toBe(false);
    expect(isSameBridgeEntry({ ...bridgeEntry(URL), env: { FOO: 'bar' } }, URL)).toBe(false);
  });
});

describe('mcp-recorder setup --bridge (via the CLI)', () => {
  const CLICKUP_URL = 'https://mcp.clickup.com/mcp';

  it('--bridge with a malformed name exits 2, config untouched', async () => {
    const dir = tmpDir('mcp-rec-setup-bridge-badname-');
    const configPath = writeConfig(dir, 'config.json', { mcpServers: {} });
    const before = readFileSync(configPath, 'utf8');

    const res = await runCli(['setup', '--config', configPath, '--bridge', `cl ickup=${CLICKUP_URL}`]);
    expect(res.code).toBe(2);
    expect(res.stderr).toMatch(/--bridge/);
    expect(readFileSync(configPath, 'utf8')).toBe(before);
  }, 30_000);

  it('--bridge with an invalid URL exits 2, config untouched', async () => {
    const dir = tmpDir('mcp-rec-setup-bridge-badurl-');
    const configPath = writeConfig(dir, 'config.json', { mcpServers: {} });
    const before = readFileSync(configPath, 'utf8');

    const res = await runCli(['setup', '--config', configPath, '--bridge', 'clickup=not-a-url']);
    expect(res.code).toBe(2);
    expect(res.stderr).toMatch(/--bridge/);
    expect(readFileSync(configPath, 'utf8')).toBe(before);
  }, 30_000);

  it('--dry-run prints the wrapped mcp-remote argv, and --json reports it under "bridged"', async () => {
    const dir = tmpDir('mcp-rec-setup-bridge-dryrun-');
    const configPath = writeConfig(dir, 'config.json', { mcpServers: {} });

    const human = await runCli([
      'setup',
      '--config',
      configPath,
      '--wrapper',
      'npx',
      '--bridge',
      `clickup=${CLICKUP_URL}`,
      '--dry-run',
    ]);
    expect(human.code).toBe(0);
    expect(human.stdout).toContain('clickup:');
    expect(human.stdout).toContain('"mcp-remote"');
    expect(human.stdout).toContain(`"${CLICKUP_URL}"`);
    expect(human.stdout).toMatch(/OAuth/);
    expect(human.stdout).toContain('npx -y mcp-remote');

    const json = await runCli([
      'setup',
      '--config',
      configPath,
      '--wrapper',
      'npx',
      '--bridge',
      `clickup=${CLICKUP_URL}`,
      '--dry-run',
      '--json',
    ]);
    expect(json.code).toBe(0);
    const result = JSON.parse(json.stdout) as { wrapped: string[]; bridged: string[]; notes: string[] };
    expect(result.wrapped).toEqual(['clickup']);
    expect(result.bridged).toEqual(['clickup']);
    expect(result.notes.some((n) => n.includes('clickup') && n.includes('OAuth'))).toBe(true);

    // --dry-run never writes, either time.
    const onDisk = JSON.parse(readFileSync(configPath, 'utf8')) as { mcpServers: Record<string, unknown> };
    expect(onDisk.mcpServers).toEqual({});
  }, 30_000);

  it('a real write wraps the bridge entry; --undo restores the unwrapped "npx -y mcp-remote URL" entry', async () => {
    const dir = tmpDir('mcp-rec-setup-bridge-write-');
    const configPath = writeConfig(dir, 'config.json', { mcpServers: {} });

    const wrap = await runCli([
      'setup',
      '--config',
      configPath,
      '--wrapper',
      'npx',
      '--bridge',
      `clickup=${CLICKUP_URL}`,
      '--json',
    ]);
    expect(wrap.code).toBe(0);
    const wrapResult = JSON.parse(wrap.stdout) as { wrapped: string[]; bridged: string[] };
    expect(wrapResult.wrapped).toEqual(['clickup']);
    expect(wrapResult.bridged).toEqual(['clickup']);

    const written = JSON.parse(readFileSync(configPath, 'utf8')) as {
      mcpServers: Record<string, WrapServerEntry>;
    };
    expect(written.mcpServers.clickup).toEqual({
      command: 'npx',
      args: [
        '-y',
        '@edut/mcp-recorder',
        'record',
        '--name',
        'clickup',
        '--',
        'npx',
        '-y',
        'mcp-remote',
        CLICKUP_URL,
      ],
    });

    // sidecar stores the unwrapped mcp-remote entry as the "original"
    const sidecar = JSON.parse(readFileSync(sidecarFor(configPath), 'utf8')) as {
      wrapped: Record<string, WrapServerEntry>;
    };
    expect(sidecar.wrapped.clickup).toEqual(bridgeEntry(CLICKUP_URL));

    const undo = await runCli(['setup', '--config', configPath, '--undo', '--json']);
    expect(undo.code).toBe(0);
    const undoResult = JSON.parse(undo.stdout) as { restored: string[]; used_sidecar: boolean };
    expect(undoResult.restored).toEqual(['clickup']);
    expect(undoResult.used_sidecar).toBe(true);

    const restored = JSON.parse(readFileSync(configPath, 'utf8')) as {
      mcpServers: Record<string, WrapServerEntry>;
    };
    expect(restored.mcpServers.clickup).toEqual(bridgeEntry(CLICKUP_URL));
  }, 30_000);

  it('an existing different entry under the bridge name is never silently replaced (exit 2)', async () => {
    const dir = tmpDir('mcp-rec-setup-bridge-conflict-');
    const configPath = writeConfig(dir, 'config.json', {
      mcpServers: { clickup: { command: 'node', args: ['./my-clickup-server.js'] } },
    });
    const before = readFileSync(configPath, 'utf8');

    const res = await runCli(['setup', '--config', configPath, '--bridge', `clickup=${CLICKUP_URL}`]);
    expect(res.code).toBe(2);
    expect(res.stderr).toContain('clickup');
    expect(res.stderr.toLowerCase()).toContain('already exists');
    expect(readFileSync(configPath, 'utf8')).toBe(before);
  }, 30_000);

  it('re-running --bridge on an already-bridged-and-wrapped name is idempotent, not a conflict', async () => {
    const dir = tmpDir('mcp-rec-setup-bridge-idempotent-');
    const configPath = writeConfig(dir, 'config.json', { mcpServers: {} });

    const first = await runCli(['setup', '--config', configPath, '--bridge', `clickup=${CLICKUP_URL}`, '--json']);
    expect(first.code).toBe(0);

    const second = await runCli(['setup', '--config', configPath, '--bridge', `clickup=${CLICKUP_URL}`, '--json']);
    expect(second.code).toBe(0);
    const result = JSON.parse(second.stdout) as { wrapped: string[]; already_wrapped: string[]; bridged: string[] };
    expect(result.wrapped).toEqual([]);
    expect(result.already_wrapped).toEqual(['clickup']);
    expect(result.bridged).toEqual(['clickup']);
  }, 30_000);

  it('--wrapper wsl --bridge produces the wsl.exe form, with the mcp-remote argv after "--"', async () => {
    const dir = tmpDir('mcp-rec-setup-bridge-wsl-');
    const configPath = writeConfig(dir, 'config.json', { mcpServers: {} });

    const res = await runCli([
      'setup',
      '--config',
      configPath,
      '--wrapper',
      'wsl',
      '--data-dir',
      '/home/me/.mcp-recorder',
      '--bridge',
      `clickup=${CLICKUP_URL}`,
      '--dry-run',
    ]);
    expect(res.code).toBe(0);
    expect(res.stdout).toContain('wsl.exe');
    expect(res.stdout).toContain('"-e"');
    expect(res.stdout).toContain('"record"');
    expect(res.stdout).toContain('"clickup"');
    expect(res.stdout).toContain('"--"');
    expect(res.stdout).toContain('"npx"');
    expect(res.stdout).toContain('"mcp-remote"');
    expect(res.stdout).toContain(`"${CLICKUP_URL}"`);
  }, 30_000);
});
