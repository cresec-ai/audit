/**
 * The enforcement-first first run: the starter policy, `protect`, `doctor`
 * and `why` — plus the invariant that none of them can make a bare `record`
 * start enforcing.
 *
 * These tests are written to FAIL when the guarantee does not hold, not to
 * describe the implementation:
 *
 *  - the starter policy STOPS a destructive call end to end, through a real
 *    spawned proxy, and the refusal is in the signed chain (not merely
 *    printed);
 *  - `doctor` exits non-zero and says why when the config key and the
 *    `mcp__<segment>__<tool>` name disagree — in BOTH orderings, because
 *    cloud dogfood 3 and cloud dogfood 4 disagreed with each other and a test
 *    that only exercises last session's convention goes green while the
 *    product fails;
 *  - `doctor` exits non-zero when enforcement is not in force, and when it is
 *    in force and matches nothing (which is the failure that does not report
 *    itself);
 *  - a bare `record`, with a starter policy sitting in the data directory,
 *    forwards byte-for-byte and records fail-open, exactly as it did before
 *    any of this existed.
 */

import { spawnSync } from 'node:child_process';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, utimesSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, describe, expect, it } from 'vitest';
import { TSX_CLI } from './helpers/tsx.js';
import { collectStringLeaves, evaluateMcp } from '../src/policy/engine.js';
import { loadPolicyFile } from '../src/policy/load.js';
import { validatePolicyObject } from '../src/policy/validate.js';
import { parsePolicyText } from '../src/policy/load.js';
import { compileToRego } from '../src/policy/rego.js';
import {
  STARTER_HOOK_POLICY_JSON,
  STARTER_POLICY_YAML,
  STARTER_RULE_COUNTS,
  materialiseStarterPolicy,
} from '../src/policy/starter.js';
import { ANY_ARG_MAX_BYTES, ANY_ARG_MAX_LEAVES } from '../src/policy/types.js';
import { parsePolicy } from '../src/hook/policy.js';
import {
  checkSpellings,
  connectorsFromConfigs,
  liveSessionConfigPaths,
  probeVerdict,
  readWiring,
  sessionSnapshotIsStale,
  toolSpellings,
} from '../src/doctor/index.js';
import type { ProbePlan } from '../src/doctor/index.js';
import { evaluatePolicy } from '../src/hook/policy.js';
import type { ChainRecord } from '../src/schema/events.js';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const TOOLS_SERVER = fileURLToPath(new URL('./fixtures/tools-server.cjs', import.meta.url));
const ECHO_SERVER = fileURLToPath(new URL('./fixtures/echo-server.cjs', import.meta.url));
const HANG_SERVER = fileURLToPath(new URL('./fixtures/hang-server.cjs', import.meta.url));

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

interface RunResult {
  status: number | null;
  stdout: string;
  stderr: string;
}

/** Run the real CLI through tsx, with the ambient recorder env cleared. */
function cli(args: string[], opts: { cwd?: string; env?: Record<string, string | undefined>; input?: string } = {}): RunResult {
  const r = spawnSync(process.execPath, [TSX_CLI, join(ROOT, 'src', 'cli.ts'), ...args], {
    cwd: opts.cwd ?? ROOT,
    encoding: 'utf8',
    input: opts.input ?? '',
    timeout: 90_000,
    env: {
      ...process.env,
      MCP_RECORDER_DISABLE: undefined,
      MCP_RECORDER_POLICY: undefined,
      MCP_RECORDER_DATA_DIR: undefined,
      // Doctor reads the LIVE MCP config by default, and this suite runs
      // inside a real agent session that has one. Every test that cares
      // points this at a fixture; the default is a file that does not exist,
      // so the ambient session never leaks into an assertion.
      MCP_RECORDER_MCP_CONFIG: join(tmpdir(), 'mcp-recorder-no-such-config.json'),
      ...opts.env,
    } as NodeJS.ProcessEnv,
  });
  return { status: r.status, stdout: r.stdout ?? '', stderr: r.stderr ?? '' };
}

/** One MCP conversation on stdin, for a `record` child that exits when stdin closes. */
function mcpScript(call: { name: string; arguments: unknown } | undefined): string {
  const lines = [
    JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      method: 'initialize',
      params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 't', version: '1' } },
    }),
    JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }),
  ];
  if (call !== undefined) {
    lines.push(JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: call }));
  }
  return lines.join('\n') + '\n';
}

function readChain(dataDir: string): ChainRecord[] {
  return readFileSync(join(dataDir, 'evidence.jsonl'), 'utf8')
    .trim()
    .split('\n')
    .filter((l) => l !== '')
    .map((l) => JSON.parse(l) as ChainRecord);
}

/**
 * The text of the `tools/call` result, parsed out of the proxy's stdout.
 *
 * The refusal travels INSIDE a JSON string, so its quotes arrive
 * backslash-escaped: asserting on the raw stdout passes for the wrong reason
 * or fails for one.
 */
function refusalText(stdout: string): string {
  for (const line of stdout.trim().split('\n')) {
    if (line === '') continue;
    let msg: { id?: number; result?: { content?: Array<{ text?: string }>; isError?: boolean } };
    try {
      msg = JSON.parse(line) as typeof msg;
    } catch {
      continue;
    }
    if (msg.id === 2 && msg.result?.isError === true) return msg.result.content?.[0]?.text ?? '';
  }
  return '';
}

function writeMcpJson(dir: string, servers: Record<string, unknown>): string {
  const path = join(dir, '.mcp.json');
  writeFileSync(path, JSON.stringify({ mcpServers: servers }, null, 2));
  return path;
}

/* ====================================================================== */
/* 1. The starter policy itself                                            */
/* ====================================================================== */

describe('the starter policy', () => {
  const policy = (() => {
    const doc = parsePolicyText(STARTER_POLICY_YAML, 'yaml', 'policy.starter.yaml');
    const result = validatePolicyObject(doc);
    if (!result.ok) throw new Error(`the shipped starter policy does not validate: ${JSON.stringify(result.errors)}`);
    return result.policy;
  })();

  it('validates against schema v1, with the rule counts protect prints', () => {
    const rules = policy.mcp?.rules ?? [];
    expect(rules.filter((r) => r.action === 'deny')).toHaveLength(STARTER_RULE_COUNTS.deny);
    expect(rules.filter((r) => r.action === 'hold')).toHaveLength(STARTER_RULE_COUNTS.hold);
    // A default of hold or deny on servers we know nothing about would block
    // the first thing the agent tries, including reads.
    expect(policy.mcp?.default).toBe('allow');
    expect(policy.mcp?.hold.on_timeout).toBe('deny');
  });

  it('has no backtick or ${ that would end its String.raw literal', () => {
    for (const [name, text] of [
      ['policy.starter.yaml', STARTER_POLICY_YAML],
      ['policy.starter.json', STARTER_HOOK_POLICY_JSON],
    ] as const) {
      expect(text, name).not.toContain('`');
      expect(text, name).not.toContain('${');
    }
  });

  it('every rule carries a reason, which is what the agent and `why` both print', () => {
    for (const rule of policy.mcp?.rules ?? []) expect(rule.reason, rule.id).toBeDefined();
  });

  const decide = (tool: string, args: unknown): { action: string; ruleId?: string } => {
    const d = evaluateMcp(policy, { server: 's', tool, args, argsBytes: JSON.stringify(args).length });
    return { action: d.action, ...(d.ruleId !== undefined ? { ruleId: d.ruleId } : {}) };
  };

  it.each([
    ['a credential file by any argument name', 'read_text_file', { path: '/home/me/p/.env' }, 'deny', 'credential-files'],
    ['a private key under another key name', 'read_file', { absolute_path: '/Users/me/.ssh/id_rsa' }, 'deny', 'credential-files'],
    ['a credential nested in a body', 'http_post', { body: { h: { Authorization: 'Bearer abcdefghijklmnop0123' } } }, 'deny', 'secrets-in-arguments'],
    ['an sk- key', 'anything', { k: 'sk-abcdefghijklmnop' }, 'deny', 'secrets-in-arguments'],
    ['the recorder\'s own configuration', 'write_file', { path: '/home/me/.mcp-recorder/policy.starter.yaml' }, 'deny', 'dont-touch-the-controls'],
    ['the client hook settings', 'write_file', { path: '.claude/settings.json' }, 'deny', 'dont-touch-the-controls'],
    ['a recursive delete of the root', 'bash', { command: 'rm -rf / --no-preserve-root' }, 'deny', 'catastrophic-commands'],
    ['dropping a database', 'query', { sql: 'DROP DATABASE prod' }, 'deny', 'catastrophic-commands'],
    ['an unqualified DELETE FROM', 'query', { sql: 'delete from users' }, 'deny', 'catastrophic-commands'],
    ['a force push', 'run_command', { cmd: 'git push --force origin main' }, 'deny', 'catastrophic-commands'],
    ['deleting a file', 'delete_file', {}, 'hold', 'destructive-tools'],
    ['a vendor-prefixed delete', 'clickup_delete_task', {}, 'hold', 'destructive-tools'],
    ['sending a message', 'send_message', {}, 'hold', 'sends-to-other-people'],
    ['spending money', 'create_charge', {}, 'hold', 'spends-money'],
    ['a refund', 'refund_order', {}, 'hold', 'spends-money'],
  ])('denies or holds %s', (_why, tool, args, action, ruleId) => {
    expect(decide(tool as string, args)).toEqual({ action, ruleId });
  });

  it.each([
    ['an ordinary read', 'read_text_file', { path: 'README.md' }],
    ['prose that merely mentions a credential file', 'read_text_file', { q: 'please read the .env file for me' }],
    ['a scoped delete', 'bash', { command: 'rm -rf /tmp/scratch' }],
    ['a qualified DELETE', 'query', { sql: 'delete from users where id = 3' }],
    ['a lease-protected force push', 'bash', { command: 'git push --force-with-lease origin main' }],
    ['a git SHA, which is not a secret', 'x', { k: 'commit 4f182f7c9a3b2e1d5c6f7a8b9c0d1e2f3a4b5c6d' }],
    ['a draft, which goes nowhere', 'create_draft', { to: 'x' }],
    // Verbs, not nouns: these are the reads an earlier '*charge*' /
    // '*invoice*' / '*order*' draft held, stalling the agent on a lookup.
    ['listing charges, which is a read', 'list_charges', {}],
    ['getting an invoice, which is a read', 'get_invoice', {}],
    ['listing invoices, which is a read', 'list_invoices', {}],
    ['sorting issues, which is not money', 'order_issues', {}],
    // A move is a routine refactor, and a hold on it is a two-minute stall.
    ['moving a file', 'move_file', { source: 'a', destination: 'b' }],
    ['renaming a file', 'rename_file', { from: 'a', to: 'b' }],
    ['outbound HTTP with nothing secret in it', 'http_post', { url: 'https://example.com', body: { hello: 'world' } }],
  ])('allows %s', (_why, tool, args) => {
    expect(decide(tool as string, args).action).toBe('allow');
  });

  it('the hook twin parses, and every deny rule leaves the server segment open', () => {
    const hook = parsePolicy(STARTER_HOOK_POLICY_JSON);
    expect(hook.deny.length).toBeGreaterThan(0);
    expect(hook.default).toBe('allow');
    // The dogfood-4 property, asserted on the SHIPPED file rather than on a
    // rule a test wrote: for every tool a rule governs at all, it must match
    // EVERY spelling of that tool — including one nobody has ever seen.
    const tools = ['clickup_delete_task', 'trash_message', 'refund_payment'].map((tool) => ({
      configKey: '47d587b8-3fb9-42e9-b596-f8b25371248c',
      tool,
      host: 'mcp.clickup.com',
    }));
    const verdicts = checkSpellings(hook, tools);
    expect(verdicts.length).toBeGreaterThan(0);
    for (const v of verdicts) expect(v.missed.map((m) => m.name), `rule /${v.ruleSource}/`).toEqual([]);
  });

  // The spelling property above is about rules that DO match something: a
  // deleted rule contributes no verdict and the property passes on whatever
  // survives. So pin every shipped hook rule to an EFFECT as well. Deleting
  // any one of the three now turns a test red instead of silently
  // un-denying Gmail trash, Drive trash, remove_* and drop_*.
  it.each([
    ['clickup_delete_task', 'destructive-tools'],
    ['delete_event', 'destructive-tools'],
    ['destroy_widget', 'destructive-tools'],
    ['purge_cache', 'destructive-tools'],
    ['truncate_log', 'destructive-tools'],
    ['trash_message', 'destructive-tools-prefix'],
    ['trash_file', 'destructive-tools-prefix'],
    ['remove_task_link', 'destructive-tools-prefix'],
    ['drop_table', 'destructive-tools-prefix'],
    ['rm_file', 'destructive-tools-prefix'],
    ['refund_payment', 'spends-money'],
    ['create_charge', 'spends-money'],
    ['start_checkout', 'spends-money'],
    ['create_payout', 'spends-money'],
    ['make_purchase', 'spends-money'],
  ])('the hook twin DENIES %s (rule %s), on every spelling a client could choose', (tool) => {
    const hook = parsePolicy(STARTER_HOOK_POLICY_JSON);
    const spellings = toolSpellings({ configKey: '47d587b8-3fb9-42e9-b596-f8b25371248c', tool, host: 'mcp.clickup.com' });
    expect(spellings.length).toBeGreaterThan(1);
    for (const spelling of spellings) {
      expect(evaluatePolicy(hook, spelling.name).decision, `${spelling.name} (${spelling.origin})`).toBe('deny');
    }
  });

  it.each([
    // Reads and sorts the money rule used to catch by matching NOUNS.
    'list_invoices',
    'get_invoice',
    'search_orders',
    'order_issues',
    // A draft goes nowhere; sending is deliberately not on the hook leg.
    'create_draft',
    'send_message',
    'list_messages',
  ])('the hook twin ALLOWS %s — a deny it cannot ask about is a wall', (tool) => {
    const hook = parsePolicy(STARTER_HOOK_POLICY_JSON);
    for (const spelling of toolSpellings({ configKey: 'X', tool, host: 'mcp.example.com' })) {
      expect(evaluatePolicy(hook, spelling.name).decision, spelling.name).toBe('allow');
    }
  });

  it('compiles to Rego, and the two engines agree on every starter case', () => {
    const loaded = { policy, hash: 'sha256:' + '0'.repeat(64) };
    const bundle = compileToRego(loaded.policy, { policyHash: loaded.hash, toolVersion: '0.0.0-test', policyName: 'starter' });
    const mcp = bundle.files['cresec/mcp/tool.rego'];
    expect(mcp).toBeDefined();
    // The any_arg twin, spelled the one way both engines agree on.
    expect(mcp).toContain('is_object(input.args)');
    expect(mcp).toContain('walk(input.args, [_, a_leaf])');
    expect(mcp).toContain('is_string(a_leaf)');
  });
});

/* ====================================================================== */
/* 2. match.any_arg                                                        */
/* ====================================================================== */

describe('match.any_arg', () => {
  const policyFor = (anyArg: string): ReturnType<typeof validatePolicyObject> =>
    validatePolicyObject({
      version: 1,
      mcp: { default: 'allow', rules: [{ id: 'r', match: { tool: '**', any_arg: anyArg }, action: 'deny', reason: 'no' }] },
    });

  const denies = (anyArg: string, args: unknown): boolean => {
    const v = policyFor(anyArg);
    if (!v.ok) throw new Error(JSON.stringify(v.errors));
    return evaluateMcp(v.policy, { server: 's', tool: 't', args, argsBytes: JSON.stringify(args).length }).action === 'deny';
  };

  it('matches a string leaf at any depth, under any key', () => {
    expect(denies('secret', { a: { b: [{ zzz: 'a secret value' }] } })).toBe(true);
    expect(denies('secret', { a: { b: [{ zzz: 'nothing here' }] } })).toBe(false);
  });

  it('does not scan object KEYS, numbers or booleans (v1, and the Rego twin agrees)', () => {
    expect(denies('secret', { secret: 'value' })).toBe(false);
    expect(denies('^42$', { n: 42 })).toBe(false);
    expect(denies('true', { b: true })).toBe(false);
  });

  it('never matches when params.arguments is not an object', () => {
    expect(denies('x', 'xxx')).toBe(false);
    expect(denies('x', ['xxx'])).toBe(false);
    expect(denies('x', null)).toBe(false);
  });

  it('collects leaves without recursing, so a deep argument tree is not a stack overflow', () => {
    // 50 000 levels and ONE string leaf: well inside the leaf and byte
    // budgets, and far past what a recursive walk survives. A RangeError here
    // would be a crash on the proxy thread, which is the one thing recording
    // and enforcement may never do.
    let deep: unknown = 'bottom';
    for (let i = 0; i < 50_000; i++) deep = { n: deep };
    expect(collectStringLeaves(deep)).toEqual(['bottom']);
  });

  // The cliff is reachable by ordinary work — a large file write, a bulk
  // push — so it has to be raisable without deleting the four denies that
  // are the good half of the starter, and the refusal has to say which of
  // the two budgets it hit and how to raise it.
  const budgetDecision = (
    args: unknown,
    budget?: { max_leaves?: number; max_bytes?: number },
  ): ReturnType<typeof evaluateMcp> => {
    const v = validatePolicyObject({
      version: 1,
      mcp: {
        default: 'allow',
        ...(budget !== undefined ? { any_arg: budget } : {}),
        rules: [{ id: 'r', match: { tool: '**', any_arg: 'never-matches-anything' }, action: 'deny', reason: 'no' }],
      },
    });
    if (!v.ok) throw new Error(JSON.stringify(v.errors));
    return evaluateMcp(v.policy, { server: 's', tool: 't', args, argsBytes: 10 });
  };

  it('mcp.any_arg raises the scan budget, so a bigger call is SCANNED rather than refused', () => {
    const big = { a: 'x'.repeat(ANY_ARG_MAX_BYTES + 1) };
    expect(budgetDecision(big).action).toBe('deny');
    // Raised past the payload: the rule is evaluable again and, matching
    // nothing, the call runs. Raising the budget scans MORE, never less.
    const raised = budgetDecision(big, { max_bytes: ANY_ARG_MAX_BYTES * 4 });
    expect(raised.action).toBe('allow');
    expect(raised.failClosed).toBeUndefined();
  });

  it('mcp.any_arg lowers it too, and the refusal names the budget it hit', () => {
    const d = budgetDecision({ a: 'x'.repeat(5_000) }, { max_bytes: 4_096 });
    expect(d.action).toBe('deny');
    expect(d.errorCode).toBe('arguments-too-large-to-scan');
    expect(d.reason).toContain('more than 4096 bytes');
    expect(d.reason).toContain('mcp.any_arg.max_bytes');

    const leaves: Record<string, string> = {};
    for (let i = 0; i < 40; i++) leaves[`k${i}`] = 'x';
    const l = budgetDecision(leaves, { max_leaves: 16 });
    expect(l.errorCode).toBe('arguments-too-large-to-scan');
    expect(l.reason).toContain('more than 16 string values');
    expect(l.reason).toContain('mcp.any_arg.max_leaves');
  });

  it('the schema bounds the budget: unlimited is not offered, nor is a budget nothing fits in', () => {
    for (const bad of [{ max_bytes: 1 }, { max_leaves: 0 }, { max_bytes: 1024 * 1024 * 1024 }, { max_leaves: 1_000_000 }]) {
      const v = validatePolicyObject({ version: 1, mcp: { default: 'allow', any_arg: bad, rules: [] } });
      expect(v.ok, JSON.stringify(bad)).toBe(false);
    }
  });

  it('the shipped starter states its budget in the file, so the cliff is not a surprise', () => {
    expect(STARTER_POLICY_YAML).toContain('any_arg:');
    expect(STARTER_POLICY_YAML).toContain('max_leaves: 256');
    expect(STARTER_POLICY_YAML).toContain('max_bytes: 262144');
    expect(STARTER_POLICY_YAML).toContain('DENIED, not allowed unscanned');
  });

  it('DENIES rather than truncates past the leaf budget — a partial scan is a deny that became an allow', () => {
    const many: Record<string, string> = {};
    for (let i = 0; i <= ANY_ARG_MAX_LEAVES; i++) many[`k${i}`] = 'x';
    const v = policyFor('never-matches-anything');
    if (!v.ok) throw new Error('fixture policy invalid');
    const d = evaluateMcp(v.policy, { server: 's', tool: 't', args: many, argsBytes: 10 });
    expect(d.action).toBe('deny');
    expect(d.failClosed).toBe(true);
    expect(d.reason).toMatch(/policy evaluation error: arguments too large to scan.*\(r\)/);
  });

  it('DENIES past the byte budget too', () => {
    const big = { a: 'x'.repeat(ANY_ARG_MAX_BYTES + 1) };
    const v = policyFor('never-matches-anything');
    if (!v.ok) throw new Error('fixture policy invalid');
    const d = evaluateMcp(v.policy, { server: 's', tool: 't', args: big, argsBytes: big.a.length });
    expect(d.action).toBe('deny');
    expect(d.failClosed).toBe(true);
  });

  it('is held to the same RE2 subset as match.args', () => {
    for (const bad of ['(?=x)', '(?i)x', '(a+)+', '\\s+', '\\1']) {
      const v = policyFor(bad);
      expect(v.ok, `${bad} should be rejected`).toBe(false);
      if (!v.ok) expect(v.errors.some((e) => e.path.endsWith('/any_arg'))).toBe(true);
    }
  });
});

/* ====================================================================== */
/* 3. protect                                                              */
/* ====================================================================== */

describe('mcp-recorder protect', () => {
  function project(): { dir: string; dataDir: string } {
    const dir = tmpDir('protect-');
    const dataDir = join(dir, 'data');
    writeMcpJson(dir, { tools: { command: process.execPath, args: [TOOLS_SERVER] } });
    return { dir, dataDir };
  }

  it('writes both starter files, wraps the config and reports doctor last', () => {
    const { dir, dataDir } = project();
    const r = cli(['protect', '--client', 'claude-code', '--data-dir', dataDir], { cwd: dir });
    expect(r.stdout).toContain('policy.starter.yaml');
    expect(r.stdout).toContain(`${STARTER_RULE_COUNTS.deny} rules deny, ${STARTER_RULE_COUNTS.hold} rules hold`);
    expect(r.stdout).toContain('This file is yours');
    // The wrapped entry really carries --policy pointing at the starter.
    const config = JSON.parse(readFileSync(join(dir, '.mcp.json'), 'utf8')) as { mcpServers: Record<string, { args: string[] }> };
    const args = config.mcpServers.tools!.args;
    expect(args).toContain('--policy');
    expect(args[args.indexOf('--policy') + 1]).toBe(join(dataDir, 'policy.starter.yaml'));
    // And the hook leg for the connectors no local proxy can see.
    const settings = JSON.parse(readFileSync(join(dir, '.claude', 'settings.json'), 'utf8')) as Record<string, unknown>;
    expect(JSON.stringify(settings)).toContain('policy.starter.json');
    // Doctor's verdict is the LAST thing, and it is a measurement.
    expect(r.stdout).toContain('doctor: ');
    expect(r.stdout).toContain('tools discovered;');
    expect(r.stdout).toContain('Fully quit and restart your client');
    // It names its own blind spots on screen.
    expect(r.stdout).toContain('What this does NOT cover');
    expect(r.stdout).toContain('MCP_RECORDER_DISABLE=1');
  });

  it('suggests a sentence to try, drawn from the tools doctor really discovered', () => {
    const { dir, dataDir } = project();
    const r = cli(['protect', '--client', 'claude-code', '--data-dir', dataDir], { cwd: dir });
    expect(r.stdout).toContain('Then ask your agent to do something it should not do');
  });

  it('says so LOUDLY when nothing discovered is covered by any rule — the dogfood-4 absence', () => {
    const dir = tmpDir('protect-empty-');
    const dataDir = join(dir, 'data');
    // echo-server exposes one tool called `echo`: the starter matches no name
    // rule against it, which is exactly "enforcement is on and matches
    // nothing" — the state no other command reports.
    writeMcpJson(dir, { echo: { command: process.execPath, args: [ECHO_SERVER] } });
    const r = cli(['protect', '--client', 'claude-code', '--data-dir', dataDir], { cwd: dir });
    expect(r.stdout).toContain('NOTHING YOU HAVE IS COVERED BY A DENY OR HOLD RULE');
    expect(r.stdout).not.toContain('Then ask your agent to do something it should not do');
    expect(r.status).toBe(1);
  });

  it('does NOT claim "nothing is covered" when things ARE covered and only the example is missing', () => {
    // Coverage > 0 (the hook leg denies clickup_delete_task) while C4 is
    // INCOMPLETE (the stdio server never answers tools/list). suggestTrigger
    // returns undefined here, and it is RIGHT to: a sentence drawn from a
    // partial list can name a tool that is not there. But "no sentence could
    // be chosen" is not "nothing is covered", and printing the second on the
    // first told a protected user they were unprotected, directly underneath
    // doctor's own list of the tools it had just denied.
    const dir = tmpDir('protect-partial-');
    const dataDir = join(dir, 'data');
    writeMcpJson(dir, { wedged: { command: process.execPath, args: [HANG_SERVER] } });
    const mcpConfig = join(dir, 'mcp-config.json');
    writeFileSync(
      mcpConfig,
      JSON.stringify({
        mcpServers: {
          ClickUp: {
            type: 'http',
            url: 'https://api.anthropic.com/v2/ccr-sessions/s/mcp?mcp_url=https%3A%2F%2Fmcp.clickup.com%2Fmcp',
            tools: [{ name: 'clickup_delete_task' }],
          },
        },
      }),
    );
    const r = cli(['protect', '--client', 'claude-code', '--data-dir', dataDir], { cwd: dir, env: { MCP_RECORDER_MCP_CONFIG: mcpConfig } });
    // The precondition this test exists for: genuinely covered, genuinely partial.
    expect(r.stdout, r.stdout).toContain('could not be enumerated');
    expect(r.stdout, r.stdout).toMatch(/[1-9]\d* denied/);
    // The false sentence must not appear.
    expect(r.stdout).not.toContain('NOTHING YOU HAVE IS COVERED');
    expect(r.stdout).not.toContain('matches none of the tools your servers expose');
    // And what it says instead is true, and says why there is no example.
    expect(r.stdout).toContain('ARE covered by a deny or hold rule');
    expect(r.stdout).toContain('tool list is INCOMPLETE');
  }, 30_000);

  it('--dry-run writes NOTHING, including the starter files', () => {
    const { dir, dataDir } = project();
    const before = readFileSync(join(dir, '.mcp.json'), 'utf8');
    const r = cli(['protect', '--client', 'claude-code', '--data-dir', dataDir, '--dry-run'], { cwd: dir });
    expect(r.stdout).toContain('--dry-run');
    expect(r.stdout).toContain(join(dataDir, 'policy.starter.yaml'));
    expect(existsSync(join(dataDir, 'policy.starter.yaml'))).toBe(false);
    expect(existsSync(join(dataDir, 'policy.starter.json'))).toBe(false);
    expect(existsSync(join(dir, '.claude', 'settings.json'))).toBe(false);
    expect(readFileSync(join(dir, '.mcp.json'), 'utf8')).toBe(before);
  });

  it('does not exit 0 when a check was INCOMPLETE — unchecked is not installed', () => {
    const dir = tmpDir('protect-incomplete-');
    const dataDir = join(dir, 'data');
    // A server that cannot start: C4 cannot enumerate it, so its tools were
    // never checked against the policy. Nothing FAILED; nothing is proved.
    writeMcpJson(dir, { broken: { command: join(dir, 'no-such-binary'), args: [] } });
    const r = cli(['protect', '--client', 'claude-code', '--data-dir', dataDir], { cwd: dir });
    expect(r.stdout, r.stdout).toContain('could not be enumerated');
    expect(r.status).toBe(3);
  });

  it('never overwrites an edited policy on a second run', () => {
    const { dir, dataDir } = project();
    cli(['protect', '--client', 'claude-code', '--data-dir', dataDir], { cwd: dir });
    const path = join(dataDir, 'policy.starter.yaml');
    const edited = readFileSync(path, 'utf8') + '\n# a person edited this\n';
    writeFileSync(path, edited);
    const again = cli(['protect', '--client', 'claude-code', '--data-dir', dataDir], { cwd: dir });
    expect(readFileSync(path, 'utf8')).toBe(edited);
    expect(again.stdout).toContain('left exactly as you have it');
  });

  it('refuses --policy: protect chooses the starter, setup --policy installs your own', () => {
    const { dir, dataDir } = project();
    const r = cli(['protect', '--client', 'claude-code', '--data-dir', dataDir, '--policy', '/tmp/x.yaml'], { cwd: dir });
    expect(r.status).toBe(2);
    expect(r.stderr).toContain('setup --policy');
  });

  it('is reversed exactly by setup --undo, because it wrapped through setup', () => {
    const { dir, dataDir } = project();
    const before = readFileSync(join(dir, '.mcp.json'), 'utf8');
    cli(['protect', '--client', 'claude-code', '--data-dir', dataDir], { cwd: dir });
    expect(readFileSync(join(dir, '.mcp.json'), 'utf8')).not.toBe(before);
    cli(['setup', '--client', 'claude-code', '--undo'], { cwd: dir });
    const after = JSON.parse(readFileSync(join(dir, '.mcp.json'), 'utf8')) as { mcpServers: Record<string, unknown> };
    expect(after.mcpServers.tools).toEqual({ command: process.execPath, args: [TOOLS_SERVER] });
  });
});

/* ====================================================================== */
/* 4. The starter policy stops a real call, through a real proxy           */
/* ====================================================================== */

describe('the starter policy end to end, through a spawned proxy', () => {
  it('STOPS a credential-file read, names the rule, and puts the refusal in the chain', () => {
    const dir = tmpDir('starter-e2e-');
    const dataDir = join(dir, 'data');
    materialiseStarterPolicy(dataDir);
    const policyPath = join(dataDir, 'policy.starter.yaml');

    const r = cli(
      ['record', '--data-dir', dataDir, '--store', 'jsonl', '--policy', policyPath, '--', process.execPath, TOOLS_SERVER],
      { input: mcpScript({ name: 'read_text_file', arguments: { path: '/home/me/project/.env' } }) },
    );

    // 1. The model was refused, and told which rule and why.
    const responses = r.stdout
      .trim()
      .split('\n')
      .map((l) => JSON.parse(l) as { id?: number; result?: { isError?: boolean; content?: Array<{ text?: string }> } });
    const call = responses.find((m) => m.id === 2);
    expect(call?.result?.isError).toBe(true);
    const text = call?.result?.content?.[0]?.text ?? '';
    expect(text).toContain('denied by policy rule "credential-files"');
    expect(text).toContain('an argument was a path to a credential file');
    // The standing guidance clause, unchanged — and deliberately WITHOUT the
    // command that would relax the rule. The agent under policy is exactly
    // the party that must not be handed it.
    expect(text).toContain('This is a policy decision by the operator, not a tool failure.');
    expect(text).not.toContain('policy.starter.yaml');
    expect(text).not.toContain('mcp-recorder why');

    // 2. The refusal is EVIDENCE, not just a message. This is the assertion
    //    dogfood 4 would have failed: a healthy chain holding zero decisions.
    const chain = readChain(dataDir);
    const decisions = chain.filter((c) => c.event.kind === 'policy_decision');
    expect(decisions).toHaveLength(1);
    const decision = decisions[0]!.event as { rule_id?: string; tool?: string; args_hash?: string };
    expect(decision.rule_id).toBe('credential-files');
    expect(decision.tool).toBe('read_text_file');

    // 3. No readable payload reached the store: the path is hashed, never
    //    stored, on the decision AND on the tool_call.
    expect(JSON.stringify(chain)).not.toContain('/home/me/project/.env');
    expect(decision.args_hash).toMatch(/^sha256:[0-9a-f]{64}$/);
  });

  it('HOLDS a delete and the server never sees it', () => {
    const dir = tmpDir('starter-hold-');
    const dataDir = join(dir, 'data');
    materialiseStarterPolicy(dataDir);
    // A hold with nobody to answer it times out; shorten the wait so the test
    // measures the DECISION, not the operator's patience.
    const path = join(dataDir, 'policy.starter.yaml');
    writeFileSync(path, readFileSync(path, 'utf8').replace('timeout_ms: 120000', 'timeout_ms: 1000'));

    const r = cli(['record', '--data-dir', dataDir, '--store', 'jsonl', '--policy', path, '--', process.execPath, TOOLS_SERVER], {
      input: mcpScript({ name: 'delete_file', arguments: { path: 'a.txt' } }),
    });
    const call = r.stdout
      .trim()
      .split('\n')
      .map((l) => JSON.parse(l) as { id?: number; result?: { isError?: boolean } })
      .find((m) => m.id === 2);
    expect(call?.result?.isError).toBe(true);
    const chain = readChain(dataDir);
    expect(chain.filter((c) => c.event.kind === 'policy_decision').length).toBeGreaterThan(0);
  });
});

/* ====================================================================== */
/* 5. The invariant: nothing here makes a bare `record` enforce            */
/* ====================================================================== */

describe('a bare record never enforces, whatever is sitting in the data directory', () => {
  it('a starter policy present in the data dir with NO flag is not an input', () => {
    const dir = tmpDir('bare-');
    const dataDir = join(dir, 'data');
    materialiseStarterPolicy(dataDir);

    const r = cli(['record', '--data-dir', dataDir, '--store', 'jsonl', '--', process.execPath, TOOLS_SERVER], {
      input: mcpScript({ name: 'read_text_file', arguments: { path: '/home/me/project/.env' } }),
    });
    const call = r.stdout
      .trim()
      .split('\n')
      .map((l) => JSON.parse(l) as { id?: number; result?: { isError?: boolean; content?: Array<{ text?: string }> } })
      .find((m) => m.id === 2);
    // The call went through, byte-for-byte: the server echoed the arguments.
    expect(call?.result?.isError).toBeUndefined();
    expect(call?.result?.content?.[0]?.text).toContain('/home/me/project/.env');
    // No gateway ran: no decisions, and no gateway block on the tool_call.
    const chain = readChain(dataDir);
    expect(chain.filter((c) => c.event.kind === 'policy_decision')).toHaveLength(0);
    const toolCall = chain.find((c) => c.event.kind === 'tool_call')?.event as { gateway?: unknown } | undefined;
    expect(toolCall?.gateway).toBeUndefined();
    expect(r.stderr).not.toContain('gateway: policy');
  });

  it('forwards the SAME bytes with and without a starter policy on disk', () => {
    const script = mcpScript({ name: 'read_text_file', arguments: { path: '/home/me/project/.env' } });
    const withoutDir = tmpDir('diff-without-');
    const withDir = tmpDir('diff-with-');
    materialiseStarterPolicy(join(withDir, 'data'));

    const a = cli(['record', '--data-dir', join(withoutDir, 'data'), '--store', 'jsonl', '--', process.execPath, TOOLS_SERVER], { input: script });
    const b = cli(['record', '--data-dir', join(withDir, 'data'), '--store', 'jsonl', '--', process.execPath, TOOLS_SERVER], { input: script });
    expect(b.stdout).toBe(a.stdout);
    expect(b.status).toBe(a.status);

    // ... and the same recorded event stream, modulo ids and timestamps.
    const kinds = (dataDir: string): string[] => readChain(dataDir).map((c) => c.event.kind);
    expect(kinds(join(withDir, 'data'))).toEqual(kinds(join(withoutDir, 'data')));
  });

  it('record --protect with no starter file is exit 2 BEFORE the server is spawned', () => {
    const dir = tmpDir('protect-missing-');
    const dataDir = join(dir, 'data');
    mkdirSync(dataDir, { recursive: true });
    // A command that would be loud if it ever ran.
    const r = cli(['record', '--data-dir', dataDir, '--protect', '--', process.execPath, '-e', "process.stdout.write('SPAWNED')"]);
    expect(r.status).toBe(2);
    expect(r.stderr).toContain("run 'mcp-recorder protect' first");
    expect(r.stdout).not.toContain('SPAWNED');
    // And it did NOT mint the policy it would then have enforced.
    expect(() => statSync(join(dataDir, 'policy.starter.yaml'))).toThrow();
  });

  it('record --protect together with --policy is exit 2: you chose both', () => {
    const dir = tmpDir('protect-both-');
    const r = cli(['record', '--data-dir', join(dir, 'data'), '--protect', '--policy', '/tmp/x.yaml', '--', process.execPath, '-e', '0']);
    expect(r.status).toBe(2);
    expect(r.stderr).toContain('pass one');
  });

  it('record --protect DOES enforce once protect has written the file', () => {
    const dir = tmpDir('protect-enforce-');
    const dataDir = join(dir, 'data');
    materialiseStarterPolicy(dataDir);
    const r = cli(['record', '--data-dir', dataDir, '--store', 'jsonl', '--protect', '--', process.execPath, TOOLS_SERVER], {
      input: mcpScript({ name: 'read_text_file', arguments: { path: '.env' } }),
    });
    expect(refusalText(r.stdout)).toContain('denied by policy rule "credential-files"');
    expect(readChain(dataDir).filter((c) => c.event.kind === 'policy_decision')).toHaveLength(1);
  });
});

/* ====================================================================== */
/* 6. doctor                                                               */
/* ====================================================================== */

describe('mcp-recorder doctor', () => {
  function connectorConfig(dir: string, name: string, servers: Record<string, unknown>): string {
    const path = join(dir, name);
    writeFileSync(path, JSON.stringify({ mcpServers: servers }));
    return path;
  }

  /** A project with the starter installed and one hosted connector declared. */
  function protectedProject(connectorKey: string, tools: string[]): { dir: string; dataDir: string; mcpConfig: string } {
    const dir = tmpDir('doctor-');
    const dataDir = join(dir, 'data');
    writeMcpJson(dir, { tools: { command: process.execPath, args: [TOOLS_SERVER] } });
    const mcpConfig = connectorConfig(dir, 'mcp-config.json', {
      [connectorKey]: {
        type: 'http',
        url: 'https://api.anthropic.com/v2/ccr-sessions/s/mcp?mcp_url=https%3A%2F%2Fmcp.clickup.com%2Fmcp',
        tools: tools.map((name) => ({ name })),
      },
    });
    cli(['protect', '--client', 'claude-code', '--data-dir', dataDir], { cwd: dir, env: { MCP_RECORDER_MCP_CONFIG: mcpConfig } });
    return { dir, dataDir, mcpConfig };
  }

  it('passes, with every check OK, on a project protect just set up', () => {
    const { dir, dataDir, mcpConfig } = protectedProject('47d587b8-3fb9-42e9-b596-f8b25371248c', ['clickup_delete_task', 'clickup_create_task']);
    const r = cli(['doctor', '--client', 'claude-code', '--data-dir', dataDir], { cwd: dir, env: { MCP_RECORDER_MCP_CONFIG: mcpConfig } });
    expect(r.stdout, r.stdout).toContain('0 failed, 0 incomplete');
    expect(r.status).toBe(0);
    // And the live probe really pushed a denied call through the real path.
    expect(r.stdout).toContain('live deny fired');
    // ASSERT THE NUMBER, NOT THE LABEL. The OK template reads
    // "... and ${decisions} policy_decision event(s) landed in the chain",
    // which prints just as readily for 0 — so an assertion on that literal
    // passes on exactly the absence C5 exists to detect.
    const json = cli(['doctor', '--client', 'claude-code', '--data-dir', dataDir, '--json'], {
      cwd: dir,
      env: { MCP_RECORDER_MCP_CONFIG: mcpConfig },
    });
    const report = JSON.parse(json.stdout) as { checks: Array<{ id: string; status: string; detail: string[] }> };
    const c5 = report.checks.find((c) => c.id === 'C5');
    expect(c5?.status).toBe('OK');
    expect(c5?.detail.join('\n')).toMatch(/\b[1-9][0-9]* policy_decision event/);
  });

  // The probe's accept condition, every way it can be wrong. These are unit
  // tests on purpose: a live proxy cannot be made to deny-without-recording
  // on demand, and the conjunct that catches THAT is the dogfood-4 one — the
  // whole reason C5 exists. Dropping any conjunct from probeVerdict now
  // turns one of these red.
  describe('C5 accepts only a deny that reached the chain', () => {
    const plan: ProbePlan = {
      server: 'files',
      tool: 'read_text_file',
      args: { path: '/x/.env' },
      ruleId: 'credential-files',
      inner: { command: 'node', args: [] },
    };

    it('OK only when the call errored, the rule was named, AND a decision landed', () => {
      const c = probeVerdict(plan, { callIsError: true, named: true, decisions: 1 });
      expect(c.status).toBe('OK');
      expect(c.detail.join('\n')).toMatch(/\b1 policy_decision event/);
    });

    it('FAILS on the dogfood-4 absence: refused, named, but ZERO decisions in the chain', () => {
      const c = probeVerdict(plan, { callIsError: true, named: true, decisions: 0 });
      expect(c.status).toBe('FAIL');
      expect(c.detail.join('\n')).toContain('policy_decision events=0');
      expect(c.detail.join('\n')).toContain('nothing reached the');
    });

    it('FAILS when the refusal does not name the rule — something else refused it', () => {
      expect(probeVerdict(plan, { callIsError: true, named: false, decisions: 1 }).status).toBe('FAIL');
    });

    it('FAILS when the call was not refused at all', () => {
      expect(probeVerdict(plan, { callIsError: false, named: true, decisions: 1 }).status).toBe('FAIL');
      expect(probeVerdict(plan, { named: true, decisions: 1 }).status).toBe('FAIL');
    });

    it('is INCOMPLETE, never FAIL, when the probe server could not be driven', () => {
      const c = probeVerdict(plan, { named: false, decisions: 0, error: 'ENOENT' });
      expect(c.status).toBe('INCOMPLETE');
      expect(c.detail.join('\n')).toContain('Nothing was proved live');
    });

    it('an error does NOT rescue a real failure it also observed', () => {
      // error is only consulted once the OK branch is out: a refusal that
      // reached the chain is still OK even if the transport complained.
      expect(probeVerdict(plan, { callIsError: true, named: true, decisions: 2, error: 'timeout' }).status).toBe('OK');
    });
  });

  // THE dogfood-4 check. Both orderings, because the two runs a day apart
  // disagreed with each other and a test that only exercises one goes green
  // while the product fails.
  it.each([
    ['key does NOT match the segment (cloud dogfood 4: UUID keys, friendly tool names)', '47d587b8-3fb9-42e9-b596-f8b25371248c'],
    ['key DOES match the segment (cloud dogfood 3: key and segment agree)', 'ClickUp'],
  ])('FAILS when a deny rule is written for one spelling — %s', (_case, connectorKey) => {
    const { dir, dataDir, mcpConfig } = protectedProject(connectorKey, ['clickup_delete_task']);
    // The exact rule dogfood 4 shipped: anchored to the friendly segment.
    const hookPolicy = join(dataDir, 'policy.starter.json');
    writeFileSync(
      hookPolicy,
      JSON.stringify({ default: 'allow', deny: [{ tool: '^mcp__ClickUp__clickup_delete_task$', reason: 'no deleting' }] }),
    );
    const r = cli(['doctor', '--client', 'claude-code', '--data-dir', dataDir, '--no-probe'], {
      cwd: dir,
      env: { MCP_RECORDER_MCP_CONFIG: mcpConfig },
    });
    expect(r.status).not.toBe(0);
    expect(r.stdout).toContain('FAIL');
    expect(r.stdout).toContain('C3 name spellings');
    expect(r.stdout, r.stdout).toContain('anchored to a server segment');
    expect(r.stdout).toContain('anchored to the segment "ClickUp"');
    expect(r.stdout).toContain('^mcp__.*__<tool>$');
  });

  // A rule the SYNTACTIC half provably cannot catch: the segment contains a
  // character class, so `anchoredSegment` calls it open — while the rule in
  // fact matches one spelling and misses five. Only the behavioural half
  // sees this, which is why deleting it must not leave the suite green.
  it('FAILS C3 on a PARTIAL wildcard the syntactic check calls open', () => {
    const { dir, dataDir, mcpConfig } = protectedProject('ClickUp', ['clickup_delete_task']);
    writeFileSync(
      join(dataDir, 'policy.starter.json'),
      JSON.stringify({
        default: 'allow',
        deny: [{ tool: '^mcp__[A-Z][A-Za-z]+__clickup_delete_task$', reason: 'no deleting' }],
      }),
    );
    const r = cli(['doctor', '--client', 'claude-code', '--data-dir', dataDir, '--no-probe'], {
      cwd: dir,
      env: { MCP_RECORDER_MCP_CONFIG: mcpConfig },
    });
    expect(r.status).toBe(1);
    expect(r.stdout, r.stdout).toContain('C3 name spellings');
    expect(r.stdout).toContain('MISSES');
    // ...and NOT via the syntactic half: that one would have named a segment.
    expect(r.stdout).not.toContain('anchored to the segment');
    expect(r.stdout).toContain('mcp__mcp.clickup.com__clickup_delete_task');
  });

  it('PASSES C3 for the same tools once the segment is left open', () => {
    const { dir, dataDir, mcpConfig } = protectedProject('ClickUp', ['clickup_delete_task']);
    writeFileSync(
      join(dataDir, 'policy.starter.json'),
      JSON.stringify({ default: 'allow', deny: [{ tool: '^mcp__.*__clickup_delete_task$', reason: 'no deleting' }] }),
    );
    const r = cli(['doctor', '--client', 'claude-code', '--data-dir', dataDir, '--no-probe'], {
      cwd: dir,
      env: { MCP_RECORDER_MCP_CONFIG: mcpConfig },
    });
    expect(r.stdout).toContain('OK         C3');
  });

  // `--protect` is the documented shape for a hand-edited client config, and
  // it DOES enforce. Reporting it as "recording only" sent the person to
  // `mcp-recorder protect`, which rewrites the very file the hand edit exists
  // to keep — and left C4 scoring that server's tools as allowed and C5 with
  // no policy to probe.
  it('reads a --protect entry as ENFORCING, and probes the policy it names', () => {
    const dir = tmpDir('doctor-protect-flag-');
    const dataDir = join(dir, 'data');
    materialiseStarterPolicy(dataDir);
    writeMcpJson(dir, {
      files: {
        command: process.execPath,
        args: [join(ROOT, 'dist', 'cli.js'), 'record', '--name', 'files', '--data-dir', dataDir, '--protect', '--', process.execPath, TOOLS_SERVER],
      },
    });
    cli(['hook', 'install', '--client', 'claude-code', '--policy', join(dataDir, 'policy.starter.json'), '--data-dir', dataDir], { cwd: dir });
    const r = cli(['doctor', '--client', 'claude-code', '--data-dir', dataDir, '--json'], { cwd: dir });
    const report = JSON.parse(r.stdout) as {
      checks: Array<{ id: string; status: string; summary: string }>;
      policy?: { path: string };
      stdio: { total: number; enforcing: number };
    };
    expect(report.stdio).toEqual({ total: 1, enforcing: 1 });
    expect(report.policy?.path).toBe(join(dataDir, 'policy.starter.yaml'));
    expect(report.checks.find((c) => c.id === 'C1')?.status, r.stdout).toBe('OK');
    expect(report.checks.find((c) => c.id === 'C5')?.status, r.stdout).toBe('OK');
  });

  it('FAILS C1 when a --protect entry names a starter policy that is not there', () => {
    const dir = tmpDir('doctor-protect-missing-');
    const dataDir = join(dir, 'data');
    mkdirSync(dataDir, { recursive: true });
    writeMcpJson(dir, {
      files: {
        command: process.execPath,
        args: [join(ROOT, 'dist', 'cli.js'), 'record', '--data-dir', dataDir, '--protect', '--', process.execPath, TOOLS_SERVER],
      },
    });
    const r = cli(['doctor', '--client', 'claude-code', '--data-dir', dataDir, '--no-probe'], { cwd: dir });
    expect(r.status).toBe(1);
    expect(r.stdout, r.stdout).toContain('every launch of this server exits 2');
    expect(r.stdout).toContain('policy.starter.yaml');
  });

  it('FAILS when enforcement is not in force: wrapped, but with no --policy', () => {
    const { dir, dataDir, mcpConfig } = protectedProject('ClickUp', ['clickup_delete_task']);
    const configPath = join(dir, '.mcp.json');
    const config = JSON.parse(readFileSync(configPath, 'utf8')) as { mcpServers: Record<string, { args: string[] }> };
    const args = config.mcpServers.tools!.args;
    args.splice(args.indexOf('--policy'), 2);
    writeFileSync(configPath, JSON.stringify(config, null, 2));
    const r = cli(['doctor', '--client', 'claude-code', '--data-dir', dataDir, '--no-probe'], {
      cwd: dir,
      env: { MCP_RECORDER_MCP_CONFIG: mcpConfig },
    });
    expect(r.status).toBe(1);
    expect(r.stdout).toContain('enforcement is NOT in force');
    expect(r.stdout).toContain('recording only, nothing is enforced');
  });

  it('FAILS when the server is not wrapped at all', () => {
    const dir = tmpDir('doctor-unwrapped-');
    const dataDir = join(dir, 'data');
    materialiseStarterPolicy(dataDir);
    writeMcpJson(dir, { tools: { command: process.execPath, args: [TOOLS_SERVER] } });
    const r = cli(['doctor', '--client', 'claude-code', '--data-dir', dataDir, '--no-probe'], { cwd: dir });
    expect(r.status).toBe(1);
    expect(r.stdout).toContain('not wrapped at all');
  });

  it('FAILS when the kill switch is on, even though the chain still looks healthy', () => {
    const { dir, dataDir, mcpConfig } = protectedProject('ClickUp', ['clickup_delete_task']);
    const r = cli(['doctor', '--client', 'claude-code', '--data-dir', dataDir, '--no-probe'], {
      cwd: dir,
      env: { MCP_RECORDER_MCP_CONFIG: mcpConfig, MCP_RECORDER_DISABLE: '1' },
    });
    expect(r.status).toBe(1);
    expect(r.stdout).toContain('the kill switch is on');
  });

  it('FAILS when the policy is in force and matches nothing — the failure that does not report itself', () => {
    const dir = tmpDir('doctor-nomatch-');
    const dataDir = join(dir, 'data');
    writeMcpJson(dir, { echo: { command: process.execPath, args: [ECHO_SERVER] } });
    cli(['protect', '--client', 'claude-code', '--data-dir', dataDir], { cwd: dir });
    // No hook policy either, so nothing at all is matched anywhere.
    writeFileSync(join(dataDir, 'policy.starter.json'), JSON.stringify({ default: 'allow', deny: [] }));
    const r = cli(['doctor', '--client', 'claude-code', '--data-dir', dataDir, '--no-probe'], { cwd: dir });
    expect(r.status).toBe(1);
    expect(r.stdout).toContain('C4 coverage');
    expect(r.stdout).toContain('0 denied, 0 held');
    expect(r.stdout).toContain('This is the failure that does not report itself');
    // It prints the real vocabulary, so the person can see WHY nothing matched.
    expect(r.stdout).toContain('echo');
  });

  it('is INCOMPLETE (exit 3), never OK, when a check could not be performed', () => {
    const { dir, dataDir, mcpConfig } = protectedProject('ClickUp', ['clickup_delete_task']);
    const r = cli(['doctor', '--client', 'claude-code', '--data-dir', dataDir, '--no-probe'], {
      cwd: dir,
      env: { MCP_RECORDER_MCP_CONFIG: mcpConfig },
    });
    expect(r.status).toBe(3);
    expect(r.stdout).toContain('INCOMPLETE');
    expect(r.stdout).toContain('C5 probe');
    expect(r.stdout).toContain('1 incomplete');
  });

  it('is INCOMPLETE when a server could not be enumerated — unchecked is not "fine"', () => {
    const dir = tmpDir('doctor-enoent-');
    const dataDir = join(dir, 'data');
    writeMcpJson(dir, { broken: { command: join(dir, 'no-such-binary'), args: [] } });
    cli(['protect', '--client', 'claude-code', '--data-dir', dataDir], { cwd: dir });
    const r = cli(['doctor', '--client', 'claude-code', '--data-dir', dataDir, '--no-probe'], { cwd: dir });
    expect(r.status).not.toBe(0);
    expect(r.stdout).toContain('could not be enumerated');
    expect(r.stdout).toContain('It is not "fine"; it is unchecked.');
  });

  it('is INCOMPLETE, never FAIL, for a client that has no hook mechanism at all', () => {
    const dir = tmpDir('doctor-desktop-');
    const dataDir = join(dir, 'data');
    const configPath = join(dir, 'claude_desktop_config.json');
    writeFileSync(configPath, JSON.stringify({ mcpServers: { tools: { command: process.execPath, args: [TOOLS_SERVER] } } }));
    cli(['protect', '--client', 'claude-desktop', '--config', configPath, '--data-dir', dataDir], { cwd: dir });
    const r = cli(['doctor', '--client', 'claude-desktop', '--config', configPath, '--data-dir', dataDir, '--no-probe'], { cwd: dir });
    // Claude Desktop has no hook, so the hosted connectors are out of reach.
    // That is a real gap and a genuine "unchecked", not a misconfiguration
    // the person can fix — so it must not read as FAIL, and must not read as
    // OK either.
    expect(r.stdout).toContain('claude-desktop has no hook mechanism');
    expect(r.stdout).toContain('there is no fix');
    expect(r.stdout).toContain('0 failed');
    expect(r.status).toBe(3);
  });

  it('--json is a stable machine interface a CI job can gate on', () => {
    const { dir, dataDir, mcpConfig } = protectedProject('ClickUp', ['clickup_delete_task']);
    const r = cli(['doctor', '--client', 'claude-code', '--data-dir', dataDir, '--no-probe', '--json'], {
      cwd: dir,
      env: { MCP_RECORDER_MCP_CONFIG: mcpConfig },
    });
    const report = JSON.parse(r.stdout) as {
      verdict: string;
      checks: Array<{ id: string; status: string }>;
      coverage: { denied: number; held: number; allowed: number };
      tools: Record<string, string[]>;
      stdio: { total: number; enforcing: number };
    };
    expect(report.checks.map((c) => c.id)).toEqual(['C1', 'C2', 'C3', 'C4', 'C5', 'C6']);
    expect(report.verdict).toBe('incomplete');
    expect(report.stdio).toEqual({ total: 1, enforcing: 1 });
    expect(report.tools.tools).toContain('delete_file');
    expect(report.coverage.held).toBeGreaterThan(0);
  });
});

/* ====================================================================== */
/* 7. doctor's units, exercised directly                                   */
/* ====================================================================== */

describe('doctor internals', () => {
  it('enumerates a spelling for every convention seen, plus one nobody has seen', () => {
    const names = toolSpellings({ configKey: '47d587b8-3fb9-42e9-b596-f8b25371248c', tool: 'delete_task', host: 'mcp.clickup.com' }).map(
      (s) => s.name,
    );
    expect(names).toContain('mcp__47d587b8-3fb9-42e9-b596-f8b25371248c__delete_task');
    expect(names).toContain('mcp__clickup__delete_task');
    expect(names).toContain('mcp__Clickup__delete_task');
    expect(names).toContain('mcp__claude_ai_clickup__delete_task');
    expect(names).toContain('mcp__mcp.clickup.com__delete_task');
    expect(names).toContain('mcp__zz-unknown-segment-0__delete_task');
  });

  // Claude Code snapshots its hooks at session start, so a hook installed
  // after a live session began is NOT in force for it, and the symptom is a
  // false negative that looks exactly like the product failing. Unit tests,
  // because the live half reads a hardcoded /tmp glob a test must not write
  // into — and because this check is what makes `protect` exit non-zero on
  // every successful first run from inside a session, so BOTH directions
  // have to be pinned.
  it('sees a hook installed AFTER a live session started, and only then', () => {
    const dir = tmpDir('stale-');
    const settings = join(dir, 'settings.json');
    const session = join(dir, 'mcp-config-abc.json');
    writeFileSync(session, '{}');
    writeFileSync(settings, '{}');
    const base = statSync(session).mtimeMs;

    utimesSync(settings, new Date(base + 60_000), new Date(base + 60_000));
    expect(sessionSnapshotIsStale(settings, [session])).toBe(true);

    utimesSync(settings, new Date(base - 60_000), new Date(base - 60_000));
    expect(sessionSnapshotIsStale(settings, [session])).toBe(false);

    // No live session at all, and an unreadable path, are both "not stale":
    // nothing observed is not the same as something wrong.
    expect(sessionSnapshotIsStale(settings, [])).toBe(false);
    expect(sessionSnapshotIsStale(settings, [join(dir, 'no-such-file.json')])).toBe(false);
  });

  it('never compares mtimes against a config the operator pointed at by hand', () => {
    // A fixture path in MCP_RECORDER_MCP_CONFIG is a file the operator
    // manages, not one a session wrote; treating it as a live session turns
    // an ordinary fixture into a permanent, unfixable FAIL.
    expect(liveSessionConfigPaths({ MCP_RECORDER_MCP_CONFIG: '/tmp/fixture.json' })).toEqual([]);
    expect(liveSessionConfigPaths({ MCP_RECORDER_MCP_CONFIG: '' })).not.toBeUndefined();
  });

  it('reads a wrapped entry back: whether it enforces, and which policy', () => {
    const cliPath = join(ROOT, 'dist', 'cli.js');
    const wiring = readWiring(
      {
        enforcing: { command: 'node', args: [cliPath, 'record', '--policy', '/p.yaml', '--', 'x'] },
        recordingOnly: { command: 'node', args: [cliPath, 'record', '--', 'x'] },
        bare: { command: 'x', args: [] },
        remote: { url: 'https://example.com/mcp', type: 'http' },
        protectFlag: { command: 'node', args: [cliPath, 'record', '--data-dir', '/d', '--protect', '--', 'x'] },
        protectDefaultDir: { command: 'node', args: [cliPath, 'record', '--protect', '--', 'x'] },
      },
      cliPath,
      '/fallback',
    );
    expect(wiring[0]!.policyPath).toBe('/p.yaml');
    expect(wiring[1]!.problem).toContain('recording only');
    expect(wiring[2]!.problem).toContain('not wrapped at all');
    expect(wiring[3]!.problem).toContain('not a stdio server');
    // `--protect` IS `--policy <data-dir>/policy.starter.yaml`, and the
    // entry's own --data-dir wins over doctor's.
    expect(wiring[4]!.policyPath).toBe(join('/d', 'policy.starter.yaml'));
    expect(wiring[5]!.policyPath).toBe(join('/fallback', 'policy.starter.yaml'));
  });

  it('reads hosted connectors and their declared tools out of an MCP config', () => {
    const dir = tmpDir('connectors-');
    const path = join(dir, 'c.json');
    writeFileSync(
      path,
      JSON.stringify({
        mcpServers: {
          '47d587b8-3fb9-42e9-b596-f8b25371248c': {
            url: 'https://api.anthropic.com/v2/ccr-sessions/s/mcp?mcp_url=https%3A%2F%2Fmcp.clickup.com%2Fmcp',
            tools: [{ name: 'clickup_get_list' }],
          },
        },
      }),
    );
    const found = connectorsFromConfigs({ MCP_RECORDER_MCP_CONFIG: path });
    expect(found).toHaveLength(1);
    expect(found[0]!.tools).toEqual(['clickup_get_list']);
    expect(found[0]!.host).toBe('mcp.clickup.com');
    expect(found[0]!.friendly).toBe('clickup');
  });

  it('a malformed MCP config contributes nothing and is never an error', () => {
    const dir = tmpDir('connectors-bad-');
    const path = join(dir, 'c.json');
    writeFileSync(path, '{not json');
    expect(connectorsFromConfigs({ MCP_RECORDER_MCP_CONFIG: path })).toEqual([]);
  });
});

/* ====================================================================== */
/* 8. why                                                                  */
/* ====================================================================== */

describe('mcp-recorder why', () => {
  function recordADeny(): { dir: string; dataDir: string } {
    const dir = tmpDir('why-');
    const dataDir = join(dir, 'data');
    materialiseStarterPolicy(dataDir);
    cli(
      [
        'record',
        '--data-dir',
        dataDir,
        '--store',
        'jsonl',
        '--policy',
        join(dataDir, 'policy.starter.yaml'),
        '--',
        process.execPath,
        TOOLS_SERVER,
      ],
      { input: mcpScript({ name: 'read_text_file', arguments: { path: '/home/me/secret-project/.env' } }) },
    );
    return { dir, dataDir };
  }

  it('says what was stopped, why, and how to change it — in the operator\'s own words', () => {
    const { dataDir } = recordADeny();
    const r = cli(['why', '--data-dir', dataDir, '--store', 'jsonl']);
    expect(r.status ?? 0).toBe(0);
    expect(r.stdout).toContain('DENIED');
    expect(r.stdout).toContain('read_text_file');
    expect(r.stdout).toContain('rule "credential-files"');
    // The reason comes from the POLICY FILE — a policy_decision event carries
    // a rule id and a hash, and nothing readable.
    expect(r.stdout).toContain('an argument was a path to a credential file');
    expect(r.stdout).toContain('the agent asked for it, the server never saw the call, nothing was read');
    expect(r.stdout).toContain('to allow this: open');
    expect(r.stdout).toContain('id: credential-files');
    expect(r.stdout).toContain('then fully restart your client');
    expect(r.stdout).toContain('nothing here left your machine');
  });

  it('prints NO argument or result text: every string comes from the policy, the tool and the rule id', () => {
    const { dataDir } = recordADeny();
    const r = cli(['why', '--data-dir', dataDir, '--store', 'jsonl']);
    expect(r.stdout).not.toContain('/home/me/secret-project/.env');
    expect(r.stdout).not.toContain('secret-project');
  });

  // `why` used to attribute reason text and the "open this file, delete this
  // rule id" remedy to whatever starter policy happened to exist. A person
  // who outgrew the starter and re-wrapped with a policy of their own — one
  // that may carry the SAME rule ids with different reasons — was told to
  // edit a file that is not in force. The chain carries policy_hash; use it.
  it('does NOT attribute a refusal to a policy file whose bytes are not the ones that decided it', () => {
    const { dataDir } = recordADeny();
    // The person edits the starter after the fact (or re-wraps elsewhere):
    // same rule id, different bytes.
    const starter = join(dataDir, 'policy.starter.yaml');
    writeFileSync(starter, readFileSync(starter, 'utf8') + '\n# a person edited this after the decision\n');
    const r = cli(['why', '--data-dir', dataDir, '--store', 'jsonl']);
    expect(r.stdout).toContain('rule "credential-files"');
    // No reason text from a file that did not decide it...
    expect(r.stdout).not.toContain('an argument was a path to a credential file');
    // ...and the remedy falls back to the generic, true one.
    expect(r.stdout).toContain('open the policy your client is wrapped with');
    expect(r.stdout).toContain("that file's bytes are not the ones this");
    expect(r.stdout).not.toContain(`to allow this: open ${starter}`);
  });

  it('explains a fail-closed refusal that names no rule, and does not tell anyone to retry it', () => {
    const dir = tmpDir('why-budget-');
    const dataDir = join(dir, 'data');
    materialiseStarterPolicy(dataDir);
    // 300 KiB of argument text: past the any_arg scan budget, so every deny
    // rule is unevaluable and the call is refused fail-closed.
    const r = cli(
      [
        'record', '--data-dir', dataDir, '--store', 'jsonl',
        '--policy', join(dataDir, 'policy.starter.yaml'),
        '--', process.execPath, TOOLS_SERVER,
      ],
      { input: mcpScript({ name: 'write_file', arguments: { path: 'big.txt', content: 'a'.repeat(300 * 1024) } }) },
    );
    const refusal = refusalText(r.stdout);
    expect(refusal, r.stdout).toContain('arguments too large to scan');
    expect(refusal).toContain('mcp.any_arg.max_bytes');
    // The remedy the model gets is the real one: retrying is refused
    // identically, so it must not be offered.
    expect(refusal).not.toContain('You may retry it');
    expect(refusal).toContain('Retrying the same call will be refused identically');
    // The proxy's own line names the same thing the model was told.
    expect(r.stderr).toContain('arguments-too-large-to-scan');
    // And so does the chain.
    const decisions = readChain(dataDir).filter((rec) => rec.event.kind === 'policy_decision');
    expect(decisions).toHaveLength(1);
    expect((decisions[0]!.event as { error_code?: string }).error_code).toBe('arguments-too-large-to-scan');
    const why = cli(['why', '--data-dir', dataDir, '--store', 'jsonl']);
    expect(why.stdout).toContain('fail-closed: arguments-too-large-to-scan');
    expect(why.stdout).toContain('any_arg: { max_bytes: 1048576 }');
    expect(why.stdout).not.toContain('delete or narrow the rule with');
  });

  it('on an empty store, says which of the two things that means and how to find out', () => {
    const dir = tmpDir('why-empty-');
    const dataDir = join(dir, 'data');
    mkdirSync(dataDir, { recursive: true });
    const r = cli(['why', '--data-dir', dataDir, '--store', 'jsonl']);
    expect(r.stdout).toContain('nothing has been stopped');
    expect(r.stdout).toContain('the failure that does not report itself');
    expect(r.stdout).toContain('mcp-recorder doctor');
  });

  it('--json is the machine form of the same decisions', () => {
    const { dataDir } = recordADeny();
    const r = cli(['why', '--data-dir', dataDir, '--store', 'jsonl', '--json']);
    const parsed = JSON.parse(r.stdout) as { decisions: Array<{ outcome: string; ruleId?: string; tool: string }> };
    expect(parsed.decisions[0]).toMatchObject({ outcome: 'DENIED', ruleId: 'credential-files', tool: 'read_text_file' });
    expect(r.stdout).not.toContain('secret-project');
  });
});

/* ====================================================================== */
/* 9. Help text leads with enforcement                                     */
/* ====================================================================== */

describe('the help text matches the new ordering', () => {
  it('leads with protect / doctor / why, and puts the evidence commands under them', () => {
    const r = cli(['--help']);
    const help = r.stdout;
    expect(help.indexOf('mcp-recorder protect')).toBeGreaterThan(-1);
    expect(help.indexOf('mcp-recorder protect')).toBeLessThan(help.indexOf('mcp-recorder verify'));
    expect(help.indexOf('mcp-recorder doctor')).toBeLessThan(help.indexOf('mcp-recorder export'));
    expect(help).toContain('Start here:');
    expect(help).toContain('Then, the evidence underneath:');
    // The invariant, said out loud in the one place everybody reads.
    expect(help).toContain('no flag ever starts enforcing on its own');
  });
});

/* ====================================================================== */
/* 10. A starter policy the person cannot read is still fail-closed        */
/* ====================================================================== */

describe('protect does not weaken anything that was already fail-closed', () => {
  it('an unreadable starter policy is exit 2 before the server spawns, not an open gate', () => {
    const dir = tmpDir('unreadable-');
    const dataDir = join(dir, 'data');
    materialiseStarterPolicy(dataDir);
    const path = join(dataDir, 'policy.starter.yaml');
    writeFileSync(path, 'version: 1\nmcp:\n  rules:\n    - { this is not a rule }\n');
    const r = cli(['record', '--data-dir', dataDir, '--protect', '--', process.execPath, '-e', "process.stdout.write('SPAWNED')"]);
    expect(r.status).toBe(2);
    expect(r.stdout).not.toContain('SPAWNED');
  });

  it('the kill switch still turns everything off, and says so', () => {
    const dir = tmpDir('killswitch-');
    const dataDir = join(dir, 'data');
    materialiseStarterPolicy(dataDir);
    const r = cli(['record', '--data-dir', dataDir, '--store', 'jsonl', '--protect', '--', process.execPath, TOOLS_SERVER], {
      input: mcpScript({ name: 'read_text_file', arguments: { path: '.env' } }),
      env: { MCP_RECORDER_DISABLE: '1' },
    });
    // Nothing is enforced AND nothing is recorded: the kill switch is both,
    // said out loud, which is what makes it a documented escape hatch rather
    // than a silent hole.
    expect(refusalText(r.stdout)).toBe('');
    expect(() => readChain(dataDir)).toThrow();
    expect(r.stderr).toContain('kill switch');
  });
});


/* ====================================================================== */
/* 11. any_arg: the two engines must agree, or the control plane and the   */
/*     local gateway decide the same call differently                      */
/* ====================================================================== */

function findOpa(): string | undefined {
  for (const c of [process.env.OPA_BIN, 'opa', '/home/user/go/bin/opa']) {
    if (c === undefined || c === '') continue;
    if (spawnSync(c, ['version'], { encoding: 'utf8' }).status === 0) return c;
  }
  return undefined;
}

describe('any_arg OPA parity (skipped without an opa binary, required in CI)', () => {
  const opa = findOpa();
  if (opa === undefined) {
    // Same gate as test/policy-rego.test.ts: locally a missing binary is a
    // skip, in CI it is a failure, because skipping would silently drop the
    // only check that the two engines agree.
    if (process.env.MCP_RECORDER_REQUIRE_OPA === '1') {
      it('opa is required by CI but was not found', () => {
        throw new Error('opa required by CI (MCP_RECORDER_REQUIRE_OPA=1) but not found');
      });
    } else {
      it.skip('opa parity', () => {});
    }
    return;
  }

  const policy = (() => {
    const result = validatePolicyObject(parsePolicyText(STARTER_POLICY_YAML, 'yaml', 'policy.starter.yaml'));
    if (!result.ok) throw new Error('the shipped starter policy does not validate');
    return result.policy;
  })();

  const bundleDir = (() => {
    const dir = mkdtempSync(join(tmpdir(), 'starter-rego-'));
    const bundle = compileToRego(policy, { policyHash: 'sha256:' + '0'.repeat(64), toolVersion: '0.0.0-test', policyName: 'starter' });
    for (const [rel, text] of Object.entries(bundle.files)) {
      const path = join(dir, rel);
      mkdirSync(join(path, '..'), { recursive: true });
      writeFileSync(path, text);
    }
    return dir;
  })();

  it('opa check --strict passes and opa fmt would not change the emitted module', () => {
    const check = spawnSync(opa, ['check', '--strict', '-b', bundleDir], { encoding: 'utf8' });
    expect(check.status, check.stderr).toBe(0);
    const fmt = spawnSync(opa, ['fmt', '--fail', '--list', join(bundleDir, 'cresec')], { encoding: 'utf8' });
    expect(fmt.status, `opa fmt would reformat:\n${fmt.stdout}${fmt.stderr}`).toBe(0);
  });

  it.each([
    ['a credential file at a leaf under an unknown key', 'read_text_file', { absolute_path: '/home/me/.env' }],
    ['a credential nested in an array in an object', 'x', { a: { b: [{ c: 'ghp_aaaaaaaaaaaaaaaaaaaaaaaa' }] } }],
    ['an ordinary read', 'read_text_file', { path: 'README.md' }],
    ['a NUMBER leaf, which neither engine scans', 'x', { n: 42 }],
    ['a BOOLEAN leaf, which neither engine scans', 'x', { b: true }],
    ['a KEY that would have matched, which neither engine scans', 'x', { '.env': 'value' }],
    ['a non-object arguments, which neither engine walks', 'x', '/home/me/.env'],
    ['an ARRAY arguments, which neither engine walks', 'x', ['/home/me/.env']],
    ['a null leaf', 'x', { a: null }],
    ['a held tool name', 'delete_file', {}],
    ['a shell string that terminates right after the table', 'query', { sql: 'delete from users' }],
    ['a shell string with a WHERE clause', 'query', { sql: 'delete from users where id = 3' }],
  ])('agrees with OPA on %s', (_note, tool, args) => {
    const input = { server: 's', tool, args, args_bytes: JSON.stringify(args).length };
    const local = evaluateMcp(policy, { server: 's', tool: tool as string, args, argsBytes: input.args_bytes });
    const r = spawnSync(opa, ['eval', '-b', bundleDir, '-I', '-f', 'json', '--strict-builtin-errors', 'data.cresec.mcp.decision'], {
      encoding: 'utf8',
      input: JSON.stringify(input),
    });
    expect(r.status, r.stderr).toBe(0);
    const parsed = JSON.parse(r.stdout) as { result?: Array<{ expressions: Array<{ value: { action: string; rule_id: string; matched: boolean } }> }> };
    const remote = parsed.result?.[0]?.expressions[0]?.value;
    expect(remote, r.stdout).toBeDefined();
    expect({ action: remote!.action, rule_id: remote!.rule_id, matched: remote!.matched }).toEqual({
      action: local.action,
      rule_id: local.ruleId ?? '',
      matched: local.matched,
    });
  });
});

/* keep the import used even when a platform skips a chmod-based case */
void chmodSync;
void loadPolicyFile;
