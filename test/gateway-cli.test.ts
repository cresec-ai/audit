/**
 * Gateway-mode CLI surface, end to end through the real CLI (spawned with
 * tsx, like test/cli.test.ts):
 *
 *   - `policy validate` / `policy compile` (exit codes, human + --json output,
 *     --out bundle contents, `opa check` when an opa binary is around);
 *   - `holds` / `approve` / `deny` against hold files written with HoldStore
 *     directly (prefix resolution, ambiguity, not found, not pending);
 *   - `record --policy` startup semantics that hold WITHOUT the proxy's
 *     gateway path: a missing / invalid / mcp-less policy exits 2 before the
 *     server is spawned, MCP_RECORDER_DISABLE=1 turns the gateway off,
 *     MCP_RECORDER_POLICY is honoured, `http --policy` is rejected;
 *   - the full `record --policy` run (deny + allow + boundary redaction, then
 *     verify / sessions / query / ui / export / verify --bundle) and a real
 *     hold approved from a second CLI process. These need the stdio proxy's
 *     gateway implementation (work package A) and are marked "[needs proxy
 *     gateway]" in their names.
 *
 * Helpers are copied from test/cli.test.ts on purpose (they are file-local
 * there) rather than importing that file's module-level state.
 */

import { spawn } from 'node:child_process';
import type { ChildProcess } from 'node:child_process';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import type { Readable } from 'node:stream';
import { fileURLToPath } from 'node:url';
import { afterEach, describe, expect, it } from 'vitest';
import { spawnTsx } from './helpers/tsx.js';
import { sha256Ref } from '../src/chain/hash.js';
import { HoldStore } from '../src/gateway/holds.js';
import type { HoldRecord } from '../src/gateway/holds.js';
import { loadPolicyFile } from '../src/policy/load.js';
import { compileToRego } from '../src/policy/rego.js';
import type { ChainRecord, PolicyDecisionEvent, ToolCallEvent } from '../src/schema/events.js';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const ECHO_SERVER = fileURLToPath(new URL('./fixtures/echo-server.cjs', import.meta.url));

/* ------------------------------- helpers -------------------------------- */

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

function spawnCli(args: string[], env: Record<string, string | undefined> = {}): ChildProcess {
  const child = spawnTsx(['src/cli.ts', ...args], {
    cwd: ROOT,
    env: { ...process.env, MCP_RECORDER_DISABLE: undefined, MCP_RECORDER_POLICY: undefined, ...env },
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  cleanups.push(() => {
    if (child.exitCode === null) child.kill('SIGKILL');
  });
  return child;
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
  return new Promise((resolveExit) => child.once('close', (code) => resolveExit(code)));
}

async function runCli(args: string[], env: Record<string, string | undefined> = {}): Promise<CliResult> {
  const child = spawnCli(args, env);
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
      return new Promise((resolveLine, reject) => {
        const timer = setTimeout(() => reject(new Error('timed out waiting for a stdout line')), timeoutMs);
        waiters.push((line) => {
          clearTimeout(timer);
          resolveLine(line);
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

async function readResponse(reader: LineReader, id: number, timeoutMs = 20_000): Promise<RpcMsg> {
  for (let i = 0; i < 20; i++) {
    const line = await reader.next(timeoutMs);
    let msg: RpcMsg;
    try {
      msg = JSON.parse(line) as RpcMsg;
    } catch {
      continue; // non-JSON noise is not ours to judge
    }
    if (msg.id === id) return msg;
  }
  throw new Error(`no response with id ${id}`);
}

/** Poll until `get()` contains `needle` (used for a long-running child's stderr). */
async function waitForText(get: () => string, needle: string, timeoutMs = 30_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (get().includes(needle)) return;
    await new Promise((r) => setTimeout(r, 50));
  }
  throw new Error(`timed out waiting for ${JSON.stringify(needle)}; saw: ${get()}`);
}

function writePolicy(dir: string, name: string, text: string): string {
  const path = join(dir, name);
  writeFileSync(path, text);
  return path;
}

function readJsonl(dataDir: string): ChainRecord[] {
  return readFileSync(join(dataDir, 'evidence.jsonl'), 'utf8')
    .trim()
    .split('\n')
    .map((l) => JSON.parse(l) as ChainRecord);
}

/** The initialize request every driven session starts with. */
const INITIALIZE = {
  jsonrpc: '2.0',
  id: 1,
  method: 'initialize',
  params: {
    protocolVersion: '2024-11-05',
    clientInfo: { name: 'gateway-cli-test', version: '0.0.1' },
    capabilities: {},
  },
};

/**
 * Where `opa` lives, if anywhere (same lookup as test/policy-rego.test.ts),
 * and the same CI guard: locally a missing binary is a skip, but CI sets
 * MCP_RECORDER_REQUIRE_OPA=1 (.github/workflows/ci.yml) so a broken
 * setup-opa step fails loudly instead of quietly dropping the check.
 */
function findOpa(): string | undefined {
  const candidates = [process.env.OPA_BIN, 'opa', '/home/user/go/bin/opa'].filter(
    (c): c is string => c !== undefined && c !== '',
  );
  for (const c of candidates) {
    try {
      const r = spawnSync(c, ['version'], { encoding: 'utf8' });
      if (r.status === 0) return c;
    } catch {
      /* not this one */
    }
  }
  return undefined;
}

/** The MCP module's key in a compiled bundle — located, never hard-coded (package C may rename it). */
function mcpModuleKey(files: Record<string, string>): string {
  const keys = Object.keys(files);
  const key =
    keys.find((p) => p.startsWith('cresec/mcp/')) ??
    keys.find((p) => p.endsWith('.rego') && /(^|\/)[^/]*mcp[^/]*\.rego$/.test(p));
  expect(key, `no MCP module among ${keys.join(', ')}`).toBeDefined();
  return key!;
}

const VALID_POLICY = [
  'version: 1',
  'name: cli-test',
  'mcp:',
  '  default: allow',
  '  rules:',
  '    - id: no-exfil',
  '      match: { tool: [http_post, "send_*"] }',
  '      action: deny',
  '      reason: no outbound HTTP',
  '    - id: careful',
  '      match: { tool: "delete_*" }',
  '      action: hold',
  'egress:',
  '  default: deny',
  '  rules:',
  '    - id: gh',
  '      match: { host: api.github.com, methods: [GET] }',
  '      action: allow',
  '',
].join('\n');

/** Valid (the top level requires one of `mcp`/`egress`), but nothing the
 * stdio gateway can enforce — `record --policy` / `setup --policy` exit 2. */
const EGRESS_ONLY_POLICY = [
  'version: 1',
  'name: egress-only',
  'egress:',
  '  default: deny',
  '  rules:',
  '    - id: gh',
  '      match: { host: api.github.com, methods: [GET] }',
  '      action: allow',
  '',
].join('\n');

const INVALID_POLICY = [
  'version: 1',
  'mcp:',
  '  rules:',
  '    - id: bad',
  '      match: { tool: echo, args: { path: "(?=x)" } }',
  '      action: maybe',
  '',
].join('\n');

/* ------------------------- policy validate / compile ----------------------- */

describe('mcp-recorder policy validate', () => {
  it('a valid policy prints "<path>: valid (n mcp rules, m egress rules)" and exits 0', async () => {
    const dir = tmpDir('mcp-rec-pol-');
    const path = writePolicy(dir, 'policy.yaml', VALID_POLICY);
    const res = await runCli(['policy', 'validate', path]);
    expect(res.code).toBe(0);
    expect(res.stdout.trim()).toBe(`${resolve(path)}: valid (2 mcp rules, 1 egress rules)`);
    expect(res.stderr).toBe('');
  }, 30_000);

  it('--json reports validity, rule counts, name and the file hash', async () => {
    const dir = tmpDir('mcp-rec-pol-');
    const path = writePolicy(dir, 'policy.yaml', VALID_POLICY);
    const res = await runCli(['policy', 'validate', path, '--json']);
    expect(res.code).toBe(0);
    const parsed = JSON.parse(res.stdout) as Record<string, unknown>;
    expect(parsed).toMatchObject({ path: resolve(path), valid: true, name: 'cli-test', mcp_rules: 2, egress_rules: 1, source: 'yaml' });
    expect(parsed.hash).toBe(loadPolicyFile(path).hash);
  }, 30_000);

  it('an invalid policy exits 1 and lists one "<pointer>: <message>" line per error', async () => {
    const dir = tmpDir('mcp-rec-pol-');
    const path = writePolicy(dir, 'policy.yaml', INVALID_POLICY);
    const res = await runCli(['policy', 'validate', path]);
    expect(res.code).toBe(1);
    const lines = res.stdout.trimEnd().split('\n');
    expect(lines[0]).toBe(`${resolve(path)}: invalid`);
    expect(lines.length).toBeGreaterThanOrEqual(2);
    for (const line of lines.slice(1)) expect(line).toMatch(/^ {2}\/[^:]*: .+/);
    expect(res.stdout).toContain('/mcp/rules/0/action');
    expect(res.stderr).toBe('');
  }, 30_000);

  it('an invalid policy with --json exits 1 and carries the error list', async () => {
    const dir = tmpDir('mcp-rec-pol-');
    const path = writePolicy(dir, 'policy.yaml', INVALID_POLICY);
    const res = await runCli(['policy', 'validate', path, '--json']);
    expect(res.code).toBe(1);
    const parsed = JSON.parse(res.stdout) as { path: string; valid: boolean; errors: Array<{ path: string; message: string }> };
    expect(parsed.valid).toBe(false);
    expect(parsed.path).toBe(resolve(path));
    expect(parsed.errors.length).toBeGreaterThanOrEqual(1);
    expect(parsed.errors.some((e) => e.path === '/mcp/rules/0/action')).toBe(true);
  }, 30_000);

  it('a lookaround regex (outside the RE2 subset) is invalid, with its pointer', async () => {
    const dir = tmpDir('mcp-rec-pol-');
    const path = writePolicy(
      dir,
      'policy.yaml',
      'version: 1\nmcp:\n  rules:\n    - match: { tool: echo, args: { path: "(?=x)" } }\n      action: deny\n',
    );
    const res = await runCli(['policy', 'validate', path]);
    expect(res.code).toBe(1);
    expect(res.stdout).toContain('/mcp/rules/0/match/args/path');
  }, 30_000);

  it('unparseable YAML is invalid (exit 1) with a root-pointer parse error, not a crash', async () => {
    const dir = tmpDir('mcp-rec-pol-');
    const path = writePolicy(dir, 'policy.yaml', 'version: 1\nmcp: [\n');
    const res = await runCli(['policy', 'validate', path]);
    expect(res.code).toBe(1);
    expect(res.stdout).toContain(`${resolve(path)}: invalid`);
    expect(res.stdout).toMatch(/^ {2}\/: .*YAML parse error/m);
  }, 30_000);

  it('a .json policy is accepted too', async () => {
    const dir = tmpDir('mcp-rec-pol-');
    const path = writePolicy(dir, 'policy.json', JSON.stringify({ version: 1, mcp: { default: 'deny' } }));
    const res = await runCli(['policy', 'validate', path, '--json']);
    expect(res.code).toBe(0);
    expect(JSON.parse(res.stdout)).toMatchObject({ valid: true, source: 'json', mcp_rules: 0, egress_rules: 0 });
  }, 30_000);

  it('a valid policy with no `mcp` section still exits 0, with a warning line after the valid line', async () => {
    const dir = tmpDir('mcp-rec-pol-');
    const path = writePolicy(dir, 'policy.yaml', EGRESS_ONLY_POLICY);
    const res = await runCli(['policy', 'validate', path]);
    expect(res.code).toBe(0);
    const lines = res.stdout.trimEnd().split('\n');
    expect(lines[0]).toBe(`${resolve(path)}: valid (0 mcp rules, 1 egress rules)`);
    expect(lines[1]).toBe(
      '  warning: no "mcp" section — nothing for the gateway to enforce ' +
        '(record --policy and setup --policy will refuse it)',
    );
    expect(lines).toHaveLength(2);
    expect(res.stderr).toBe('');

    // and the warning tells the truth: the same file is refused by record
    const server = markerServer(dir);
    const refused = await runCli(['record', '--data-dir', join(dir, 'data'), '--policy', path, '--', ...server.command]);
    expect(refused.code).toBe(2);
    expect(refused.stderr).toContain('no `mcp` section');
  }, 60_000);

  it('--json carries the same warning in "warnings" (an empty array when there is nothing to say)', async () => {
    const dir = tmpDir('mcp-rec-pol-');
    const egressOnly = writePolicy(dir, 'egress-only.yaml', EGRESS_ONLY_POLICY);
    const res = await runCli(['policy', 'validate', egressOnly, '--json']);
    expect(res.code).toBe(0);
    const parsed = JSON.parse(res.stdout) as { valid: boolean; mcp_rules: number; warnings: string[] };
    expect(parsed).toMatchObject({ valid: true, mcp_rules: 0, egress_rules: 1 });
    expect(parsed.warnings).toEqual([
      'no "mcp" section — nothing for the gateway to enforce ' +
        '(record --policy and setup --policy will refuse it)',
    ]);

    const ok = writePolicy(dir, 'policy.yaml', VALID_POLICY);
    const clean = await runCli(['policy', 'validate', ok, '--json']);
    expect(clean.code).toBe(0);
    expect((JSON.parse(clean.stdout) as { warnings: string[] }).warnings).toEqual([]);
    expect((await runCli(['policy', 'validate', ok])).stdout).not.toContain('warning');
  }, 60_000);

  it('an unreadable file exits 2 with the usual "[mcp-recorder] error:" line', async () => {
    const dir = tmpDir('mcp-rec-pol-');
    const res = await runCli(['policy', 'validate', join(dir, 'missing.yaml')]);
    expect(res.code).toBe(2);
    expect(res.stdout).toBe('');
    expect(res.stderr).toContain('[mcp-recorder] error:');
    expect(res.stderr).toContain('cannot read policy file');
  }, 30_000);

  it('usage errors exit 2: no verb, unknown verb, missing file, extra argument', async () => {
    const dir = tmpDir('mcp-rec-pol-');
    const path = writePolicy(dir, 'policy.yaml', VALID_POLICY);
    const noVerb = await runCli(['policy']);
    expect(noVerb.code).toBe(2);
    expect(noVerb.stderr).toContain('missing <validate|compile>');
    const unknown = await runCli(['policy', 'frobnicate', path]);
    expect(unknown.code).toBe(2);
    expect(unknown.stderr).toContain("unknown verb 'frobnicate'");
    const noFile = await runCli(['policy', 'validate']);
    expect(noFile.code).toBe(2);
    expect(noFile.stderr).toContain('missing <file>');
    const extra = await runCli(['policy', 'validate', path, 'extra']);
    expect(extra.code).toBe(2);
    expect(extra.stderr).toContain("unexpected argument 'extra'");
  }, 60_000);
});

describe('mcp-recorder policy compile', () => {
  it('without --out prints exactly the MCP module compileToRego produces', async () => {
    const dir = tmpDir('mcp-rec-pol-');
    const path = writePolicy(dir, 'policy.yaml', VALID_POLICY);
    const loaded = loadPolicyFile(path);
    const expected = compileToRego(loaded.policy, { policyHash: loaded.hash, policyName: 'cli-test', toolVersion: '0.1.0' });
    const key = mcpModuleKey(expected.files);

    const res = await runCli(['policy', 'compile', path]);
    expect(res.code).toBe(0);
    expect(res.stdout).toBe(expected.files[key]);
    expect(res.stdout).toContain('import rego.v1');
    expect(res.stdout).toContain('"no-exfil"');
    expect(res.stderr).toBe('');
  }, 30_000);

  it('--target rego is accepted; any other target is a usage error (exit 2)', async () => {
    const dir = tmpDir('mcp-rec-pol-');
    const path = writePolicy(dir, 'policy.yaml', VALID_POLICY);
    const ok = await runCli(['policy', 'compile', path, '--target', 'rego']);
    expect(ok.code).toBe(0);
    expect(ok.stdout).toContain('import rego.v1');
    const bad = await runCli(['policy', 'compile', path, '--target', 'cedar']);
    expect(bad.code).toBe(2);
    expect(bad.stdout).toBe('');
    expect(bad.stderr).toContain("invalid --target 'cedar'");
  }, 60_000);

  it('--out DIR writes every bundle file (subdirs created) and prints the list', async () => {
    const dir = tmpDir('mcp-rec-pol-');
    const path = writePolicy(dir, 'policy.yaml', VALID_POLICY);
    const outDir = join(dir, 'out', 'bundle');
    const loaded = loadPolicyFile(path);
    const expected = compileToRego(loaded.policy, { policyHash: loaded.hash, policyName: 'cli-test', toolVersion: '0.1.0' });

    const res = await runCli(['policy', 'compile', path, '--out', outDir]);
    expect(res.code).toBe(0);
    expect(res.stdout).toContain(`wrote ${Object.keys(expected.files).length} file(s) to ${outDir}`);
    for (const [rel, content] of Object.entries(expected.files)) {
      expect(res.stdout).toContain(`  ${rel}`);
      expect(readFileSync(join(outDir, ...rel.split('/')), 'utf8')).toBe(content);
    }
    // Both modules are there: the policy has an egress section.
    const rego = Object.keys(expected.files).filter((p) => p.endsWith('.rego'));
    expect(rego.length).toBe(2);
    expect(existsSync(join(outDir, '.manifest'))).toBe(true);

    const opa = findOpa();
    if (opa === undefined) {
      if (process.env.MCP_RECORDER_REQUIRE_OPA === '1') {
        throw new Error('opa required by CI (MCP_RECORDER_REQUIRE_OPA=1) but not found');
      }
      console.warn('[gateway-cli.test] no opa binary (OPA_BIN / PATH / /home/user/go/bin/opa); skipping opa check');
      return;
    }
    const check = spawnSync(opa, ['check', '--strict', '-b', outDir], { encoding: 'utf8' });
    expect(check.status, `opa check failed: ${check.stdout}${check.stderr}`).toBe(0);
  }, 60_000);

  it('an invalid policy exits 1 with the validate-style error list and writes nothing', async () => {
    const dir = tmpDir('mcp-rec-pol-');
    const path = writePolicy(dir, 'policy.yaml', INVALID_POLICY);
    const outDir = join(dir, 'bundle');
    const res = await runCli(['policy', 'compile', path, '--out', outDir]);
    expect(res.code).toBe(1);
    expect(res.stdout).toContain(`${resolve(path)}: invalid`);
    expect(existsSync(outDir)).toBe(false);
  }, 30_000);
});

/* --------------------------- holds / approve / deny ------------------------ */

function seedHold(store: HoldStore, id: string, tool: string, over: Partial<HoldRecord> = {}): HoldRecord {
  return store.create({
    approval_id: id,
    session_id: 'sess-1',
    server: 'corp-notes',
    tool,
    args: { path: { redacted: true, ref: sha256Ref('secrets.env'), len: 11 } },
    args_hash: sha256Ref('{"path":"secrets.env"}'),
    rule_id: 'careful',
    timeout_at: new Date(Date.now() + 60_000).toISOString(),
    ...over,
  });
}

describe('mcp-recorder holds / approve / deny (hold files written directly)', () => {
  const A1 = 'aaaa1111-0000-4000-8000-000000000001';
  const A2 = 'aaaa2222-0000-4000-8000-000000000002';
  const B1 = 'bbbb0000-0000-4000-8000-000000000003';

  it('holds on a data dir without a holds directory prints "no pending holds" and creates nothing', async () => {
    const dataDir = tmpDir('mcp-rec-holds-');
    const res = await runCli(['holds', '--data-dir', dataDir]);
    expect(res.code).toBe(0);
    expect(res.stdout.trim()).toBe('no pending holds');
    expect(readdirSync(dataDir)).toEqual([]);
    const all = await runCli(['holds', '--data-dir', dataDir, '--all', '--json']);
    expect(all.code).toBe(0);
    expect(JSON.parse(all.stdout)).toEqual([]);
  }, 60_000);

  it('holds lists pending holds as a table (ID AGE SERVER TOOL RULE TIMEOUT), --all adds decided ones, --json is raw', async () => {
    const dataDir = tmpDir('mcp-rec-holds-');
    const store = new HoldStore(dataDir);
    seedHold(store, A1, 'delete_file');
    seedHold(store, A2, 'rm_rf', { rule_id: undefined });
    seedHold(store, B1, 'drop_table');
    store.decide(B1, 'denied', 'tester');

    const human = await runCli(['holds', '--data-dir', dataDir]);
    expect(human.code).toBe(0);
    const [header, ...rows] = human.stdout.trimEnd().split('\n');
    expect(header!.split(/\s+/)).toEqual(['ID', 'AGE', 'SERVER', 'TOOL', 'RULE', 'TIMEOUT']);
    expect(rows).toHaveLength(2);
    expect(human.stdout).toContain('aaaa1111');
    expect(human.stdout).toContain('aaaa2222');
    expect(human.stdout).not.toContain('bbbb0000');
    expect(human.stdout).toContain('delete_file');
    expect(human.stdout).toContain('careful');
    expect(human.stdout).toContain('(default)');
    expect(human.stdout).toMatch(/\b\d+s\b/); // an age / remaining-timeout cell

    const all = await runCli(['holds', '--data-dir', dataDir, '--all']);
    expect(all.code).toBe(0);
    expect(all.stdout.split('\n')[0]!.split(/\s+/)).toEqual(['ID', 'AGE', 'SERVER', 'TOOL', 'RULE', 'TIMEOUT', 'STATUS']);
    expect(all.stdout).toContain('bbbb0000');
    expect(all.stdout).toContain('denied');

    const json = await runCli(['holds', '--data-dir', dataDir, '--json']);
    expect(json.code).toBe(0);
    const list = JSON.parse(json.stdout) as HoldRecord[];
    expect(list.map((h) => h.approval_id).sort()).toEqual([A1, A2]);
    expect(list.every((h) => h.status === 'pending')).toBe(true);
    // No readable payload anywhere: args are the scrubbed tree.
    expect(json.stdout).not.toContain('secrets.env');
    expect(json.stdout).toContain(sha256Ref('secrets.env'));
  }, 90_000);

  it('approve <full id> flips the hold to approved, records who, and prints one confirmation line', async () => {
    const dataDir = tmpDir('mcp-rec-holds-');
    const store = new HoldStore(dataDir);
    seedHold(store, A1, 'delete_file');

    const res = await runCli(['approve', A1, '--data-dir', dataDir]);
    expect(res.code).toBe(0);
    expect(res.stdout.trimEnd().split('\n')).toHaveLength(1);
    expect(res.stdout).toContain(`approved ${A1}`);
    expect(res.stdout).toContain('delete_file');
    expect(res.stdout).toContain('rule careful');

    const rec = store.read(A1)!;
    expect(rec.status).toBe('approved');
    expect(Date.parse(rec.decided_at!)).not.toBeNaN();
    // decided_by is the OS user, best effort — when known it is a non-empty string.
    if (rec.decided_by !== undefined) expect(rec.decided_by.length).toBeGreaterThan(0);
  }, 30_000);

  it('deny <unique prefix> (the 8-char id holds prints) resolves and denies', async () => {
    const dataDir = tmpDir('mcp-rec-holds-');
    const store = new HoldStore(dataDir);
    seedHold(store, A1, 'delete_file');
    seedHold(store, B1, 'drop_table');

    const res = await runCli(['deny', 'bbbb0000', '--data-dir', dataDir]);
    expect(res.code).toBe(0);
    expect(res.stdout).toContain(`denied ${B1}`);
    expect(store.read(B1)!.status).toBe('denied');
    expect(store.read(A1)!.status).toBe('pending');
  }, 30_000);

  it('an ambiguous prefix exits 2 and names the candidates', async () => {
    const dataDir = tmpDir('mcp-rec-holds-');
    const store = new HoldStore(dataDir);
    seedHold(store, A1, 'delete_file');
    seedHold(store, A2, 'rm_rf');

    const res = await runCli(['approve', 'aaaa', '--data-dir', dataDir]);
    expect(res.code).toBe(2);
    expect(res.stderr).toContain('[mcp-recorder] error:');
    expect(res.stderr).toContain('ambiguous');
    expect(res.stderr).toContain('aaaa1111');
    expect(res.stderr).toContain('aaaa2222');
    expect(store.read(A1)!.status).toBe('pending');
    expect(store.read(A2)!.status).toBe('pending');
  }, 30_000);

  it('an unknown id exits 1 (not 2) and leaves the holds untouched', async () => {
    const dataDir = tmpDir('mcp-rec-holds-');
    const store = new HoldStore(dataDir);
    seedHold(store, A1, 'delete_file');

    const res = await runCli(['approve', 'zzzz9999', '--data-dir', dataDir]);
    expect(res.code).toBe(1);
    expect(res.stderr).toContain('no hold matches');
    expect(store.read(A1)!.status).toBe('pending');

    // A path-shaped id can never escape the holds dir: it is simply unknown.
    const evil = await runCli(['deny', '../identity', '--data-dir', dataDir]);
    expect(evil.code).toBe(1);
  }, 60_000);

  it('deciding a hold that is no longer pending exits 1', async () => {
    const dataDir = tmpDir('mcp-rec-holds-');
    const store = new HoldStore(dataDir);
    seedHold(store, A1, 'delete_file');

    expect((await runCli(['approve', A1, '--data-dir', dataDir])).code).toBe(0);
    const again = await runCli(['deny', A1, '--data-dir', dataDir]);
    expect(again.code).toBe(1);
    expect(again.stderr).toContain('not pending');
    expect(store.read(A1)!.status).toBe('approved');
  }, 60_000);

  it('approve / deny without an id exit 2', async () => {
    const dataDir = tmpDir('mcp-rec-holds-');
    const a = await runCli(['approve', '--data-dir', dataDir]);
    expect(a.code).toBe(2);
    expect(a.stderr).toContain('missing <id>');
    const d = await runCli(['deny', '--data-dir', dataDir]);
    expect(d.code).toBe(2);
    expect(d.stderr).toContain('missing <id>');
  }, 60_000);
});

/* ------------------------ record --policy: startup ------------------------ */

/**
 * A "server" that only proves whether it was spawned: it drops a marker file
 * and exits 0. If the recorder refuses to start, the marker never appears.
 */
function markerServer(dir: string): { command: string[]; spawned(): boolean } {
  const marker = join(dir, 'server-spawned');
  const script = `require('fs').writeFileSync(${JSON.stringify(marker)}, 'yes')`;
  return { command: ['node', '-e', script], spawned: () => existsSync(marker) };
}

function storeFiles(dataDir: string): string[] {
  return existsSync(dataDir)
    ? readdirSync(dataDir).filter((f) => f.startsWith('evidence.') || f.startsWith('identity.') || f === 'holds')
    : [];
}

describe('record --policy: startup is fail-closed', () => {
  it('a missing policy file exits 2 before the server is spawned; no store is created', async () => {
    const dir = tmpDir('mcp-rec-gw-start-');
    const dataDir = join(dir, 'data');
    const server = markerServer(dir);
    const res = await runCli(['record', '--data-dir', dataDir, '--policy', join(dir, 'nope.yaml'), '--', ...server.command]);
    expect(res.code).toBe(2);
    expect(res.stderr).toContain('[mcp-recorder] error: policy:');
    expect(res.stderr).toContain('cannot read policy file');
    expect(server.spawned()).toBe(false);
    expect(existsSync(dataDir)).toBe(false);
    expect(res.stdout).toBe(''); // record mode never touches stdout itself
  }, 60_000);

  it('an invalid policy exits 2 listing the errors, before the server is spawned', async () => {
    const dir = tmpDir('mcp-rec-gw-start-');
    const dataDir = join(dir, 'data');
    const policy = writePolicy(dir, 'policy.yaml', INVALID_POLICY);
    const server = markerServer(dir);
    const res = await runCli(['record', '--data-dir', dataDir, '--policy', policy, '--', ...server.command]);
    expect(res.code).toBe(2);
    expect(res.stderr).toContain(`policy: ${resolve(policy)}: invalid policy`);
    expect(res.stderr).toContain('/mcp/rules/0/action');
    expect(server.spawned()).toBe(false);
    expect(storeFiles(dataDir)).toEqual([]);
  }, 60_000);

  it('a policy without an `mcp` section exits 2 (nothing for the gateway to enforce)', async () => {
    const dir = tmpDir('mcp-rec-gw-start-');
    const dataDir = join(dir, 'data');
    const policy = writePolicy(dir, 'policy.yaml', 'version: 1\negress:\n  default: deny\n');
    const server = markerServer(dir);
    const res = await runCli(['record', '--data-dir', dataDir, '--policy', policy, '--', ...server.command]);
    expect(res.code).toBe(2);
    expect(res.stderr).toContain('policy has no `mcp` section');
    expect(server.spawned()).toBe(false);
    expect(storeFiles(dataDir)).toEqual([]);
  }, 60_000);

  it('MCP_RECORDER_POLICY is honoured when --policy is absent (here: pointing at a missing file)', async () => {
    const dir = tmpDir('mcp-rec-gw-start-');
    const dataDir = join(dir, 'data');
    const server = markerServer(dir);
    const res = await runCli(['record', '--data-dir', dataDir, '--', ...server.command], {
      MCP_RECORDER_POLICY: join(dir, 'missing.yaml'),
    });
    expect(res.code).toBe(2);
    expect(res.stderr).toContain('cannot read policy file');
    expect(server.spawned()).toBe(false);
  }, 60_000);

  it('--policy wins over MCP_RECORDER_POLICY', async () => {
    const dir = tmpDir('mcp-rec-gw-start-');
    const dataDir = join(dir, 'data');
    const server = markerServer(dir);
    const bad = writePolicy(dir, 'bad.yaml', INVALID_POLICY);
    const res = await runCli(['record', '--data-dir', dataDir, '--policy', bad, '--', ...server.command], {
      MCP_RECORDER_POLICY: join(dir, 'missing.yaml'),
    });
    expect(res.code).toBe(2);
    expect(res.stderr).toContain(resolve(bad));
    expect(res.stderr).not.toContain('missing.yaml');
    expect(server.spawned()).toBe(false);
  }, 60_000);

  it('MCP_RECORDER_DISABLE=1 with --policy is pure passthrough: gateway off, said on stderr, nothing stored', async () => {
    const dir = tmpDir('mcp-rec-gw-disabled-');
    const dataDir = join(dir, 'data');
    const policy = writePolicy(
      dir,
      'policy.yaml',
      'version: 1\nmcp:\n  rules:\n    - id: no-echo\n      match: { tool: echo }\n      action: deny\n',
    );
    const child = spawnCli(['record', '--data-dir', dataDir, '--policy', policy, '--', 'node', ECHO_SERVER], {
      MCP_RECORDER_DISABLE: '1',
    });
    const stderrText = collect(child.stderr);
    const reader = lineReader(child.stdout!);
    const send = (msg: unknown): void => {
      child.stdin!.write(JSON.stringify(msg) + '\n');
    };
    send(INITIALIZE);
    expect((await readResponse(reader, 1)).result).toBeDefined();
    send({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'echo', arguments: { note: 'kill-switch-probe' } } });
    const call = await readResponse(reader, 2);
    // The deny rule did NOT apply: the server echoed the call back.
    expect(JSON.stringify(call.result)).toContain('kill-switch-probe');
    expect((call.result as { isError?: boolean }).isError).toBeUndefined();
    child.stdin!.end();
    expect(await waitExit(child)).toBe(0);
    expect(stderrText()).toContain('MCP_RECORDER_DISABLE=1');
    expect(stderrText()).toContain('gateway disabled');
    expect(storeFiles(dataDir)).toEqual([]);
  }, 120_000);

  it('http --policy exits 2: gateway mode is stdio-only', async () => {
    const dir = tmpDir('mcp-rec-gw-http-');
    const policy = writePolicy(dir, 'policy.yaml', VALID_POLICY);
    const res = await runCli(['http', '--target', 'http://127.0.0.1:1/mcp', '--policy', policy, '--data-dir', join(dir, 'data')]);
    expect(res.code).toBe(2);
    expect(res.stderr).toContain('stdio transport only');
  }, 60_000);

  it('http IGNORES MCP_RECORDER_POLICY (one stderr note) and records as usual', async () => {
    // Exporting MCP_RECORDER_POLICY in a shell is the pattern docs/gateway.md
    // recommends for stdio servers; it must not make `http` unusable.
    const dir = tmpDir('mcp-rec-gw-http-env-');
    const policy = writePolicy(dir, 'policy.yaml', VALID_POLICY);
    const child = spawnCli(
      ['http', '--target', 'http://127.0.0.1:1/mcp', '--port', '0', '--data-dir', join(dir, 'data')],
      { MCP_RECORDER_POLICY: policy },
    );
    const stderrText = collect(child.stderr);
    const exited = waitExit(child);
    await waitForText(stderrText, 'http proxy listening at');

    const note = stderrText()
      .split('\n')
      .filter((l) => l.includes('MCP_RECORDER_POLICY'));
    expect(note).toEqual([
      '[mcp-recorder] http: MCP_RECORDER_POLICY ignored — gateway mode is available for the stdio transport only',
    ]);
    expect(stderrText()).not.toContain('stdio transport only (drop --policy)');

    child.kill('SIGINT');
    expect(await exited).toBe(0);
  }, 60_000);
});

/* -------------------- record --policy: full gateway e2e --------------------
 * These drive the real proxy in gateway mode and therefore need work package
 * A (the gateway path inside src/proxy/stdio.ts). Until it lands they fail on
 * the first enforcement assertion.
 */

const GATEWAY_POLICY = [
  'version: 1',
  'name: e2e',
  'mcp:',
  '  default: allow',
  '  rules:',
  '    - id: no-secret-notes',
  '      match: { tool: echo, args: { note: "^denied-" } }',
  '      action: deny',
  '      reason: notes starting with denied- are off limits',
  '  boundary: { secrets: redact, injection: flag }',
  '',
].join('\n');

describe('record --policy e2e [needs proxy gateway]', () => {
  it('deny + allow + boundary redaction, then verify / sessions / query / ui / export / verify --bundle', async () => {
    const dir = tmpDir('mcp-rec-gw-e2e-');
    const dataDir = join(dir, 'data');
    const policy = writePolicy(dir, 'policy.yaml', GATEWAY_POLICY);
    const DENIED_NOTE = 'denied-probe-9f3a7b2e';
    const ALLOWED_NOTE = 'allowed-probe-11223344';
    const TOKEN = 'sk-live-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123';

    const child = spawnCli(['record', '--data-dir', dataDir, '--store', 'jsonl', '--policy', policy, '--', 'node', ECHO_SERVER]);
    const stderrText = collect(child.stderr);
    const reader = lineReader(child.stdout!);
    const send = (msg: unknown): void => {
      child.stdin!.write(JSON.stringify(msg) + '\n');
    };

    send(INITIALIZE);
    const init = await readResponse(reader, 1);
    expect((init.result as { serverInfo: { name: string } }).serverInfo.name).toBe('echo-server');

    // Denied: the client gets an isError tool result; the server never echoes it.
    send({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'echo', arguments: { note: DENIED_NOTE } } });
    const denied = await readResponse(reader, 2);
    expect((denied.result as { isError?: boolean }).isError).toBe(true);
    const deniedText = JSON.stringify(denied.result);
    expect(deniedText).not.toContain(DENIED_NOTE);
    expect(deniedText).toContain('no-secret-notes');

    // Allowed: forwarded, echoed back unchanged.
    send({ jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'echo', arguments: { note: ALLOWED_NOTE } } });
    const allowed = await readResponse(reader, 3);
    expect(JSON.stringify(allowed.result)).toContain(ALLOWED_NOTE);

    // Allowed, but the echoed result carries a secret-shaped token: the
    // boundary filter redacts it before the client sees it.
    send({ jsonrpc: '2.0', id: 4, method: 'tools/call', params: { name: 'echo', arguments: { note: `token=${TOKEN}` } } });
    const filtered = await readResponse(reader, 4);
    const filteredText = JSON.stringify(filtered.result);
    expect(filteredText).not.toContain(TOKEN);
    expect(filteredText).toContain('[redacted:sha256:');

    child.stdin!.end();
    expect(await waitExit(child)).toBe(0);
    expect(stderrText()).toMatch(/\[mcp-recorder\] session [0-9a-f]{8} recorded \d+ events/);
    expect(stderrText()).toContain('gateway');

    // --- chain contents -----------------------------------------------------
    const records = readJsonl(dataDir);
    const raw = readFileSync(join(dataDir, 'evidence.jsonl'), 'utf8');
    expect(raw).not.toContain(DENIED_NOTE);
    expect(raw).not.toContain(ALLOWED_NOTE);
    expect(raw).not.toContain(TOKEN);
    const kinds = records.map((r) => r.event.kind);
    expect(kinds[0]).toBe('session_start');
    expect(kinds[kinds.length - 1]).toBe('session_end');
    expect(kinds).toContain('policy_decision');

    const start = records[0]!.event;
    expect(start.kind === 'session_start' && start.policy?.hash).toBe(loadPolicyFile(policy).hash);
    expect(start.kind === 'session_start' && start.policy?.name).toBe('e2e');

    const decisions = records.filter((r): r is ChainRecord & { event: PolicyDecisionEvent } => r.event.kind === 'policy_decision');
    expect(decisions).toHaveLength(1);
    expect(decisions[0]!.event).toMatchObject({ decision: 'deny', tool: 'echo', request_id: 2, rule_id: 'no-secret-notes' });
    expect(decisions[0]!.event.args_hash).toBe(sha256Ref(JSON.stringify({ note: DENIED_NOTE })));

    const calls = records.filter((r): r is ChainRecord & { event: ToolCallEvent } => r.event.kind === 'tool_call');
    expect(calls.map((r) => r.event.request_id).sort()).toEqual([2, 3, 4]);
    const deniedCall = calls.find((r) => r.event.request_id === 2)!.event;
    expect(deniedCall.is_error).toBe(true);
    expect(deniedCall.error?.type).toBe('policy_denied');
    expect(deniedCall.gateway).toMatchObject({ decision: 'deny', rule_id: 'no-secret-notes' });
    // policy_decision precedes its tool_call in the chain
    expect(decisions[0]!.seq).toBeLessThan(calls.find((r) => r.event.request_id === 2)!.seq);
    const allowedCall = calls.find((r) => r.event.request_id === 3)!.event;
    expect(allowedCall.is_error).toBe(false);
    expect(allowedCall.gateway?.decision).toBe('allow');
    const filteredCall = calls.find((r) => r.event.request_id === 4)!.event;
    expect(filteredCall.gateway?.boundary).toMatchObject({ scanned: true, action: 'redact' });
    expect(filteredCall.gateway?.boundary?.secret_refs).toContain(sha256Ref(TOKEN));
    expect(filteredCall.gateway?.boundary?.delivered_result_hash).toBeDefined();
    expect(filteredCall.gateway?.boundary?.delivered_result_hash).not.toBe(filteredCall.result_hash);

    // --- verify -------------------------------------------------------------
    const verify = await runCli(['verify', '--data-dir', dataDir, '--store', 'jsonl']);
    expect(verify.code).toBe(0);
    expect(verify.stdout).toContain('PASS');

    // --- sessions: a denied call is 1 tool call + 1 error --------------------
    const sessions = await runCli(['sessions', '--data-dir', dataDir, '--store', 'jsonl', '--json']);
    expect(sessions.code).toBe(0);
    const list = JSON.parse(sessions.stdout) as Array<{ tool_call_count: number; error_count: number; event_count: number }>;
    expect(list).toHaveLength(1);
    expect(list[0]!.tool_call_count).toBe(3);
    expect(list[0]!.error_count).toBe(1);
    expect(list[0]!.event_count).toBe(records.length);

    // --- query: the denied call's hashed argument, and the redacted token ----
    const query = await runCli(['query', DENIED_NOTE, '--data-dir', dataDir, '--store', 'jsonl', '--json']);
    expect(query.code).toBe(0);
    const qr = JSON.parse(query.stdout) as { matches: Array<{ kind: string; matched_on: string; name?: string }> };
    expect(qr.matches.some((m) => m.kind === 'tool_call' && m.matched_on === 'ref' && m.name === 'echo')).toBe(true);
    const tokenQuery = await runCli(['query', TOKEN, '--data-dir', dataDir, '--store', 'jsonl', '--json']);
    const tq = JSON.parse(tokenQuery.stdout) as { matches: Array<{ kind: string; matched_on: string }> };
    expect(tq.matches.some((m) => m.kind === 'tool_call' && m.matched_on === 'ref')).toBe(true);

    // --- ui --out: POLICY row + gateway badges, nothing readable -------------
    const htmlPath = join(dir, 'replay.html');
    const ui = await runCli(['ui', '--data-dir', dataDir, '--store', 'jsonl', '--out', htmlPath, '--no-open']);
    expect(ui.code).toBe(0);
    const html = readFileSync(htmlPath, 'utf8');
    expect(html).toContain('POLICY');
    expect(html).toContain('gw-deny');
    expect(html).toContain('gw-allow');
    expect(html).not.toContain(DENIED_NOTE);
    expect(html).not.toContain(TOKEN);

    // --- export + verify.cjs + verify --bundle -------------------------------
    const bundleDir = join(dir, 'bundle');
    const exported = await runCli(['export', '--data-dir', dataDir, '--store', 'jsonl', '--dir', bundleDir]);
    expect(exported.code).toBe(0);
    const verifier = spawn('node', ['verify.cjs'], { cwd: bundleDir, stdio: ['ignore', 'pipe', 'pipe'] });
    const verifierOut = collect(verifier.stdout);
    expect(await waitExit(verifier)).toBe(0);
    expect(verifierOut()).toContain('PASS');
    const bundleVerify = await runCli(['verify', '--bundle', bundleDir]);
    expect(bundleVerify.code).toBe(0);
    expect(bundleVerify.stdout).toContain('PASS');
  }, 240_000);

  it('MCP_RECORDER_POLICY alone (no --policy) really enforces: deny + policy_decision + session_start.policy', async () => {
    const dir = tmpDir('mcp-rec-gw-env-e2e-');
    const dataDir = join(dir, 'data');
    const policy = writePolicy(
      dir,
      'policy.yaml',
      [
        'version: 1',
        'name: from-env',
        'mcp:',
        '  default: allow',
        '  rules:',
        '    - id: no-secret-notes',
        '      match: { tool: echo, args: { note: "^denied-" } }',
        '      action: deny',
        '      reason: notes starting with denied- are off limits',
        '',
      ].join('\n'),
    );
    const DENIED_NOTE = 'denied-from-env-7c1d';
    const ALLOWED_NOTE = 'allowed-from-env-3b9f';

    const child = spawnCli(['record', '--data-dir', dataDir, '--store', 'jsonl', '--', 'node', ECHO_SERVER], {
      MCP_RECORDER_POLICY: policy,
    });
    const reader = lineReader(child.stdout!);
    collect(child.stderr);
    const send = (msg: unknown): void => {
      child.stdin!.write(JSON.stringify(msg) + '\n');
    };

    send(INITIALIZE);
    expect((await readResponse(reader, 1)).result).toBeDefined();

    send({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'echo', arguments: { note: DENIED_NOTE } } });
    const denied = await readResponse(reader, 2);
    expect((denied.result as { isError?: boolean }).isError).toBe(true);
    const deniedText = JSON.stringify(denied.result);
    expect(deniedText).toContain('no-secret-notes');
    expect(deniedText).toContain('notes starting with denied- are off limits');
    expect(deniedText).not.toContain(DENIED_NOTE);

    // a non-matching call still goes through untouched
    send({ jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'echo', arguments: { note: ALLOWED_NOTE } } });
    expect(JSON.stringify((await readResponse(reader, 3)).result)).toContain(ALLOWED_NOTE);

    child.stdin!.end();
    expect(await waitExit(child)).toBe(0);

    const records = readJsonl(dataDir);
    const start = records[0]!.event;
    expect(start.kind === 'session_start' && start.policy?.hash).toBe(loadPolicyFile(policy).hash);
    expect(start.kind === 'session_start' && start.policy?.name).toBe('from-env');

    const decisions = records.filter(
      (r): r is ChainRecord & { event: PolicyDecisionEvent } => r.event.kind === 'policy_decision',
    );
    expect(decisions).toHaveLength(1);
    expect(decisions[0]!.event).toMatchObject({ decision: 'deny', tool: 'echo', request_id: 2, rule_id: 'no-secret-notes' });
    expect(decisions[0]!.event.args_hash).toBe(sha256Ref(JSON.stringify({ note: DENIED_NOTE })));

    const denyCall = records
      .map((r) => r.event)
      .find((e): e is ToolCallEvent => e.kind === 'tool_call' && e.request_id === 2);
    expect(denyCall!.is_error).toBe(true);
    expect(denyCall!.gateway).toMatchObject({ decision: 'deny', rule_id: 'no-secret-notes' });
    expect(readFileSync(join(dataDir, 'evidence.jsonl'), 'utf8')).not.toContain(DENIED_NOTE);
    expect((await runCli(['verify', '--data-dir', dataDir, '--store', 'jsonl'])).code).toBe(0);
  }, 240_000);

  it('a held call is parked until `approve` runs in a second CLI process, then forwarded', async () => {
    const dir = tmpDir('mcp-rec-gw-hold-');
    const dataDir = join(dir, 'data');
    const policy = writePolicy(
      dir,
      'policy.yaml',
      [
        'version: 1',
        'mcp:',
        '  rules:',
        '    - id: needs-human',
        '      match: { tool: echo }',
        '      action: hold',
        '  hold: { timeout_ms: 60000, on_timeout: deny }',
        '',
      ].join('\n'),
    );
    const HELD_NOTE = 'held-probe-5a5a5a5a';

    const child = spawnCli(['record', '--data-dir', dataDir, '--store', 'jsonl', '--policy', policy, '--', 'node', ECHO_SERVER]);
    collect(child.stderr);
    const reader = lineReader(child.stdout!);
    const send = (msg: unknown): void => {
      child.stdin!.write(JSON.stringify(msg) + '\n');
    };
    send(INITIALIZE);
    expect((await readResponse(reader, 1)).result).toBeDefined();
    send({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'echo', arguments: { note: HELD_NOTE } } });

    // Wait for the hold file to appear, through the CLI (as an operator would).
    let pending: HoldRecord[] = [];
    const deadline = Date.now() + 30_000;
    while (Date.now() < deadline) {
      const res = await runCli(['holds', '--data-dir', dataDir, '--json']);
      expect(res.code).toBe(0);
      pending = JSON.parse(res.stdout) as HoldRecord[];
      if (pending.length > 0) break;
    }
    expect(pending).toHaveLength(1);
    const hold = pending[0]!;
    expect(hold).toMatchObject({ tool: 'echo', rule_id: 'needs-human', status: 'pending' });
    expect(JSON.stringify(hold)).not.toContain(HELD_NOTE); // hashed args only

    // Other traffic keeps flowing while the call is held.
    send({ jsonrpc: '2.0', id: 3, method: 'tools/list' });
    expect((await readResponse(reader, 3)).result).toBeDefined();

    const approve = await runCli(['approve', hold.approval_id.slice(0, 8), '--data-dir', dataDir]);
    expect(approve.code).toBe(0);
    expect(approve.stdout).toContain(`approved ${hold.approval_id}`);

    const result = await readResponse(reader, 2, 30_000);
    expect(JSON.stringify(result.result)).toContain(HELD_NOTE);

    child.stdin!.end();
    expect(await waitExit(child)).toBe(0);

    const records = readJsonl(dataDir);
    const decision = records.map((r) => r.event).find((e): e is PolicyDecisionEvent => e.kind === 'policy_decision');
    expect(decision).toMatchObject({ decision: 'hold', outcome: 'approved', tool: 'echo', request_id: 2, approval_id: hold.approval_id });
    expect(decision!.waited_ms).toBeGreaterThan(0);
    const call = records.map((r) => r.event).find((e): e is ToolCallEvent => e.kind === 'tool_call' && e.request_id === 2);
    expect(call!.is_error).toBe(false);
    expect(call!.gateway).toMatchObject({ decision: 'hold', outcome: 'approved', approval_id: hold.approval_id });

    const all = await runCli(['holds', '--data-dir', dataDir, '--all', '--json']);
    const allList = JSON.parse(all.stdout) as HoldRecord[];
    expect(allList.find((h) => h.approval_id === hold.approval_id)!.status).toBe('approved');
    expect((await runCli(['verify', '--data-dir', dataDir, '--store', 'jsonl'])).code).toBe(0);
  }, 240_000);
});
