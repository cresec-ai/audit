import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, relative } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { sha256Hex } from '../src/chain/hash.js';
import {
  BUNDLE_FILE_ORDER,
  EGRESS_REGO_PATH,
  MANIFEST_PATH,
  MCP_REGO_PATH,
  bundleFileOrder,
  compileToRego,
  evaluateEgress,
  evaluateMcp,
  loadPolicyFile,
  policyRevision,
  renderEgressModule,
  validatePolicyObject,
} from '../src/policy/index.js';
import type { Decision, EgressRequestInput, McpRequestInput, Policy, RegoBundle } from '../src/policy/index.js';

const ROOT = join(__dirname, '..');
const FIXTURES = join(ROOT, 'test', 'fixtures', 'policies');
const EXPECTED = join(FIXTURES, 'expected');
const FIXTURE_FILES = ['laptop-default.yaml', 'mcp-only.yaml', 'egress-only.yaml', 'empty.json'] as const;
const TOOL_VERSION = '0.0.0-test';

/** Goldens use a hash derived from the fixture NAME so they do not churn when a comment changes. */
function goldenHash(name: string): string {
  return 'sha256:' + sha256Hex(`golden:${name}`);
}

function fixtureName(file: string): string {
  return file.replace(/\.(yaml|yml|json)$/, '');
}

function compileFixture(file: string): { policy: Policy; bundle: RegoBundle; name: string } {
  const loaded = loadPolicyFile(join(FIXTURES, file));
  const name = fixtureName(file);
  const opts = { policyHash: goldenHash(name), toolVersion: TOOL_VERSION, ...(loaded.name !== undefined ? { policyName: loaded.name } : {}) };
  return { policy: loaded.policy, bundle: compileToRego(loaded.policy, opts), name };
}

function writeBundle(dir: string, bundle: RegoBundle): void {
  for (const p of bundleFileOrder(bundle.files)) {
    const full = join(dir, p);
    mkdirSync(dirname(full), { recursive: true });
    writeFileSync(full, bundle.files[p]!);
  }
}

function listFiles(dir: string): string[] {
  const out: string[] = [];
  const walk = (d: string): void => {
    for (const entry of readdirSync(d)) {
      const full = join(d, entry);
      if (statSync(full).isDirectory()) walk(full);
      else out.push(relative(dir, full).split('\\').join('/'));
    }
  };
  walk(dir);
  return out.sort();
}

/* -------------------------------- goldens -------------------------------- */

describe('compileToRego: golden bundles', () => {
  const update = process.env.UPDATE_GOLDENS === '1';

  it.each(FIXTURE_FILES)('%s compiles to test/fixtures/policies/expected/<name>/', (file) => {
    const { bundle, name } = compileFixture(file);
    const dir = join(EXPECTED, name);
    if (update) {
      rmSync(dir, { recursive: true, force: true });
      writeBundle(dir, bundle);
    }
    expect(existsSync(dir), `missing golden dir ${dir} (run with UPDATE_GOLDENS=1)`).toBe(true);
    expect(listFiles(dir)).toEqual(Object.keys(bundle.files).sort());
    for (const p of Object.keys(bundle.files)) {
      expect(bundle.files[p], p).toBe(readFileSync(join(dir, p), 'utf8'));
    }
  });

  it('is deterministic and independent of rule key order', () => {
    const a = compileFixture('laptop-default.yaml');
    const b = compileFixture('laptop-default.yaml');
    expect(a.bundle).toEqual(b.bundle);
    const reordered = validatePolicyObject({
      mcp: { rules: [{ action: 'deny', match: { tool: 'x', server: 's' }, id: 'r' }], default: 'allow' },
      version: 1,
    });
    const ordered = validatePolicyObject({
      version: 1,
      mcp: { default: 'allow', rules: [{ id: 'r', match: { server: 's', tool: 'x' }, action: 'deny' }] },
    });
    if (!reordered.ok || !ordered.ok) throw new Error('fixture invalid');
    const opts = { policyHash: goldenHash('x'), toolVersion: TOOL_VERSION };
    expect(compileToRego(reordered.policy, opts)).toEqual(compileToRego(ordered.policy, opts));
  });
});

describe('compileToRego: bundle layout', () => {
  const { bundle, policy } = compileFixture('laptop-default.yaml');

  it('emits .manifest with the bare hex revision and the gateway root', () => {
    expect(JSON.parse(bundle.files[MANIFEST_PATH]!)).toEqual({
      revision: goldenHash('laptop-default').slice('sha256:'.length),
      roots: ['cresec/gateway'],
    });
    expect(bundle.files[MANIFEST_PATH]!.endsWith('\n')).toBe(true);
  });

  it('emits egress.rego only when the policy has an egress section', () => {
    expect(Object.keys(bundle.files).sort()).toEqual([MANIFEST_PATH, EGRESS_REGO_PATH, MCP_REGO_PATH].sort());
    const mcpOnly = compileFixture('mcp-only.yaml').bundle;
    expect(Object.keys(mcpOnly.files).sort()).toEqual([MANIFEST_PATH, MCP_REGO_PATH].sort());
    expect(() => renderEgressModule(compileFixture('mcp-only.yaml').policy, { policyHash: goldenHash('x'), toolVersion: 'v' })).toThrow(/no egress section/);
    // An egress-only policy still gets an mcp module with the documented default.
    const egressOnly = compileFixture('egress-only.yaml').bundle;
    expect(egressOnly.files[MCP_REGO_PATH]).toContain('default_action := "allow"');
    expect(egressOnly.files[MCP_REGO_PATH]).toContain('rule_matches := set()');
  });

  it('bundleFileOrder puts known files first in canonical order, then extras sorted', () => {
    expect(BUNDLE_FILE_ORDER).toEqual([MANIFEST_PATH, MCP_REGO_PATH, EGRESS_REGO_PATH]);
    expect(bundleFileOrder(bundle.files)).toEqual([MANIFEST_PATH, MCP_REGO_PATH, EGRESS_REGO_PATH]);
    expect(bundleFileOrder({ 'z/extra.rego': '', [MCP_REGO_PATH]: '', 'a/extra.rego': '' })).toEqual([MCP_REGO_PATH, 'a/extra.rego', 'z/extra.rego']);
  });

  it('module header, package, import and shapes follow the design', () => {
    const mcp = bundle.files[MCP_REGO_PATH]!;
    expect(mcp.startsWith('package cresec.gateway.mcp\n\nimport rego.v1\n\n')).toBe(true);
    expect(mcp).toContain(`# Generated by mcp-recorder ${TOOL_VERSION} from policy "laptop-default" (${goldenHash('laptop-default')}). Do not edit.`);
    expect(mcp).toContain('# Input:    {"server": "...", "tool": "...", "args": {...}, "args_bytes": 123}');
    expect(mcp).toContain('# Decision: {"action": "allow"|"hold"|"deny", "rule_id": "...", "reason": "...", "matched": bool}');
    expect(mcp).toContain('\tsome p in ["http_post", "send_*"]\n\tglob.match(p, ["/"], input.tool)\n');
    expect(mcp).toContain('\tv0 := object.get(input.args, ["url"], null)\n\tv0 != null\n');
    expect(mcp).toContain('\tregex.match("^https?://", sprintf("%v", [v0]))\n\tinput.args_bytes <= 65536\n');
    expect(mcp).toContain('first_match := min(rule_matches) if count(rule_matches) > 0');
    expect(mcp).toContain('decision := {"action": default_action, "rule_id": "", "reason": "", "matched": false} if count(rule_matches) == 0');
    expect(mcp).not.toMatch(/^ +/m); // tabs only
    const egress = bundle.files[EGRESS_REGO_PATH]!;
    expect(egress.startsWith('package cresec.gateway.egress\n\nimport rego.v1\n\n')).toBe(true);
    expect(egress).toContain('# Input:    {"host": "...", "method": "GET", "path": "/...", "body_bytes": 123}');
    expect(egress).toContain('\tglob.match("api.github.com", ["."], input.host)\n\tinput.method in ["GET", "HEAD"]\n\tglob.match("/**", ["/"], input.path)\n\tinput.body_bytes <= 1048576\n');
    expect(egress).toContain('default_action := "deny"');
    expect(policy.egress!.default).toBe('deny');
  });

  it('dot-path segments become object.get paths with numeric indexes as numbers', () => {
    const mcp = compileFixture('mcp-only.yaml').bundle.files[MCP_REGO_PATH]!;
    expect(mcp).toContain('v0 := object.get(input.args, ["filters", 0, "field"], null)');
    expect(mcp).toContain('v1 := object.get(input.args, ["limit"], null)');
    expect(mcp).toContain('v2 := object.get(input.args, ["dry_run"], null)');
    expect(mcp).toContain('# rule[0]\nrule_matches contains 0 if {');
    expect(mcp).toContain('{"id": "rule[0]", "action": "allow", "reason": ""},');
  });

  it('escapes every string literal with JSON.stringify', () => {
    const r = validatePolicyObject({
      version: 1,
      name: 'q',
      mcp: {
        rules: [{ id: 'esc', match: { tool: 'say "hi"\t', args: { 'a.b': '^\\d+\\\\$' } }, action: 'deny', reason: 'line\nbreak "x" \u00e9' }],
      },
    });
    if (!r.ok) throw new Error('fixture invalid');
    const out = compileToRego(r.policy, { policyHash: goldenHash('esc'), toolVersion: 'v' }).files[MCP_REGO_PATH]!;
    expect(out).toContain('glob.match("say \\"hi\\"\\t", ["/"], input.tool)');
    expect(out).toContain('regex.match("^\\\\d+\\\\\\\\$", sprintf("%v", [v0]))');
    expect(out).toContain('"reason": "line\\nbreak \\"x\\" é"');
  });

  it('policyRevision accepts sha256: refs or bare hex and rejects anything else', () => {
    const hex = 'a'.repeat(64);
    expect(policyRevision('sha256:' + hex)).toBe(hex);
    expect(policyRevision(hex)).toBe(hex);
    expect(() => policyRevision('sha256:' + 'A'.repeat(64))).toThrow(TypeError);
    expect(() => policyRevision('sha256:abc')).toThrow(/64 lowercase hex/);
    expect(() => compileToRego(policy, { policyHash: 'md5:x', toolVersion: 'v' })).toThrow(TypeError);
  });

  it('uses the loaded file hash as the revision when compiled from loadPolicyFile', () => {
    const loaded = loadPolicyFile(join(FIXTURES, 'empty.json'));
    const out = compileToRego(loaded.policy, { policyHash: loaded.hash, toolVersion: 'v' });
    expect(JSON.parse(out.files[MANIFEST_PATH]!).revision).toBe(loaded.hash.slice('sha256:'.length));
  });
});

/* ------------------------------ OPA parity ------------------------------- */

function findOpa(): string | undefined {
  const candidates = [process.env.OPA_BIN, 'opa', '/home/user/go/bin/opa'].filter((c): c is string => c !== undefined && c !== '');
  for (const c of candidates) {
    const r = spawnSync(c, ['version'], { encoding: 'utf8' });
    if (r.status === 0) return c;
  }
  return undefined;
}

interface OpaDecision {
  action: string;
  rule_id: string;
  reason: string;
  matched: boolean;
}

function opaEval(opa: string, bundleDir: string, query: string, input: unknown): OpaDecision {
  const r = spawnSync(opa, ['eval', '-b', bundleDir, '-I', '-f', 'json', query], { encoding: 'utf8', input: JSON.stringify(input) });
  expect(r.status, `opa eval failed: ${r.stderr}`).toBe(0);
  const parsed = JSON.parse(r.stdout) as { result?: Array<{ expressions: Array<{ value: OpaDecision }> }> };
  const value = parsed.result?.[0]?.expressions[0]?.value;
  expect(value, `opa returned no decision for ${JSON.stringify(input)}: ${r.stdout}`).toBeDefined();
  return value!;
}

function asOpa(d: Decision): OpaDecision {
  return { action: d.action, rule_id: d.ruleId ?? '', reason: d.reason ?? '', matched: d.matched };
}

type McpCase = { kind: 'mcp'; fixture: (typeof FIXTURE_FILES)[number]; input: McpRequestInput; note: string };
type EgressCase = { kind: 'egress'; fixture: (typeof FIXTURE_FILES)[number]; input: EgressRequestInput; note: string };

const mcpIn = (server: string, tool: string, args: unknown, argsBytes: number): McpRequestInput => ({ server, tool, args, argsBytes });
const egressIn = (host: string, method: string, path: string, bodyBytes: number): EgressRequestInput => ({ host, method, path, bodyBytes });

const CASES: Array<McpCase | EgressCase> = [
  { kind: 'mcp', fixture: 'laptop-default.yaml', note: 'deny: args regex + multi-glob', input: mcpIn('corp-notes', 'http_post', { url: 'https://evil' }, 24) },
  { kind: 'mcp', fixture: 'laptop-default.yaml', note: 'deny: second glob of the list', input: mcpIn('corp-notes', 'send_mail', { url: 'http://x' }, 20) },
  { kind: 'mcp', fixture: 'laptop-default.yaml', note: 'default allow: regex does not match', input: mcpIn('corp-notes', 'http_post', { url: 'ftp://x' }, 20) },
  { kind: 'mcp', fixture: 'laptop-default.yaml', note: 'default allow: args path missing', input: mcpIn('corp-notes', 'http_post', { body: 'x' }, 12) },
  { kind: 'mcp', fixture: 'laptop-default.yaml', note: 'default allow: args value is an object', input: mcpIn('corp-notes', 'http_post', { url: { s: 'https://x' } }, 30) },
  { kind: 'mcp', fixture: 'laptop-default.yaml', note: 'default allow: args value is null', input: mcpIn('corp-notes', 'http_post', { url: null }, 12) },
  { kind: 'mcp', fixture: 'laptop-default.yaml', note: 'default allow: args root is an array', input: mcpIn('corp-notes', 'http_post', [{ url: 'https://x' }], 20) },
  { kind: 'mcp', fixture: 'laptop-default.yaml', note: 'deny: max_args_bytes boundary (equal)', input: mcpIn('corp-notes', 'http_post', { url: 'https://x' }, 65536) },
  { kind: 'mcp', fixture: 'laptop-default.yaml', note: 'default allow: max_args_bytes exceeded by one', input: mcpIn('corp-notes', 'http_post', { url: 'https://x' }, 65537) },
  { kind: 'mcp', fixture: 'laptop-default.yaml', note: 'hold: write_* glob', input: mcpIn('fs', 'write_file', { path: '/tmp/x' }, 18) },
  { kind: 'mcp', fixture: 'laptop-default.yaml', note: 'default allow: "*" does not cross the delimiter', input: mcpIn('fs', 'write_x/y', {}, 2) },
  { kind: 'mcp', fixture: 'laptop-default.yaml', note: 'default allow: unknown tool, empty args', input: mcpIn('fs', 'read_file', {}, 2) },
  { kind: 'mcp', fixture: 'mcp-only.yaml', note: 'allow rule[0]: server glob', input: mcpIn('corp-notes', 'read_note', { id: 'n1' }, 11) },
  { kind: 'mcp', fixture: 'mcp-only.yaml', note: 'hold rule[2]: server glob fails, catch-all with small args', input: mcpIn('other', 'read_note', { id: 'n1' }, 11) },
  { kind: 'mcp', fixture: 'mcp-only.yaml', note: 'default deny: catch-all cap exceeded', input: mcpIn('other', 'read_note', { id: 'x' }, 1025) },
  { kind: 'mcp', fixture: 'mcp-only.yaml', note: 'hold rule[2]: catch-all cap boundary', input: mcpIn('other', 'read_note', { id: 'x' }, 1024) },
  { kind: 'mcp', fixture: 'mcp-only.yaml', note: 'allow rule[1]: array index path + number + boolean coercion', input: mcpIn('corp-notes', 'search/deep/x', { filters: [{ field: 'title' }], limit: 42, dry_run: true }, 60) },
  { kind: 'mcp', fixture: 'mcp-only.yaml', note: 'allow rule[1]: string forms of the same values', input: mcpIn('corp-notes', 'list_notes', { filters: [{ field: 'body' }], limit: '7', dry_run: 'true' }, 60) },
  { kind: 'mcp', fixture: 'mcp-only.yaml', note: 'hold rule[2]: limit too large (3 digits)', input: mcpIn('corp-notes', 'list_notes', { filters: [{ field: 'body' }], limit: 420, dry_run: true }, 60) },
  { kind: 'mcp', fixture: 'mcp-only.yaml', note: 'hold rule[2]: boolean false fails ^true$', input: mcpIn('corp-notes', 'list_notes', { filters: [{ field: 'body' }], limit: 4, dry_run: false }, 60) },
  { kind: 'mcp', fixture: 'mcp-only.yaml', note: 'hold rule[2]: filters.0 missing (empty array)', input: mcpIn('corp-notes', 'list_notes', { filters: [], limit: 4, dry_run: true }, 60) },
  { kind: 'mcp', fixture: 'mcp-only.yaml', note: 'hold rule[2]: numeric segment does not address object key "0"', input: mcpIn('corp-notes', 'list_notes', { filters: { '0': { field: 'body' } }, limit: 4, dry_run: true }, 60) },
  { kind: 'mcp', fixture: 'mcp-only.yaml', note: 'allow rule[1]: negative and float numbers coerce identically', input: mcpIn('corp-notes', 'list_notes', { filters: [{ field: 'body' }], limit: 12, dry_run: true, extra: -1.5 }, 60) },
  { kind: 'mcp', fixture: 'empty.json', note: 'default allow: no rules', input: mcpIn('s', 't', { a: 1 }, 7) },
  { kind: 'egress', fixture: 'egress-only.yaml', note: 'allow github: second host glob, "." delimiter', input: egressIn('raw.githubusercontent.com', 'GET', '/o/r/main/f', 0) },
  { kind: 'egress', fixture: 'egress-only.yaml', note: 'default deny: "*" does not cross "."', input: egressIn('a.b.githubusercontent.com', 'GET', '/', 0) },
  { kind: 'egress', fixture: 'egress-only.yaml', note: 'default deny: method not listed', input: egressIn('api.github.com', 'POST', '/repos', 10) },
  { kind: 'egress', fixture: 'egress-only.yaml', note: 'default deny: lower-case method is not a match', input: egressIn('api.github.com', 'get', '/repos', 0) },
  { kind: 'egress', fixture: 'egress-only.yaml', note: 'hold npm-publish: body cap boundary', input: egressIn('registry.npmjs.org', 'PUT', '/-/pkg', 4096) },
  { kind: 'egress', fixture: 'egress-only.yaml', note: 'default deny: body cap exceeded', input: egressIn('registry.npmjs.org', 'PUT', '/-/pkg', 4097) },
  { kind: 'egress', fixture: 'egress-only.yaml', note: 'default deny: path glob /-/** requires the prefix', input: egressIn('registry.npmjs.org', 'PUT', '/pkg', 1) },
  { kind: 'egress', fixture: 'egress-only.yaml', note: 'deny telemetry: any method, /v1/*', input: egressIn('x.telemetry.io', 'PATCH', '/v1/a', 5) },
  { kind: 'egress', fixture: 'egress-only.yaml', note: 'default deny: /v1/* does not cross "/"', input: egressIn('x.telemetry.io', 'GET', '/v1/a/b', 5) },
  { kind: 'egress', fixture: 'egress-only.yaml', note: 'deny telemetry: /v2/** crosses "/"', input: egressIn('x.telemetry.io', 'GET', '/v2/a/b', 5) },
  { kind: 'egress', fixture: 'laptop-default.yaml', note: 'allow github-read: default path /**', input: egressIn('api.github.com', 'HEAD', '/repos/x/y', 0) },
  { kind: 'egress', fixture: 'laptop-default.yaml', note: 'default deny: DELETE', input: egressIn('api.github.com', 'DELETE', '/repos/x/y', 0) },
  { kind: 'egress', fixture: 'empty.json', note: 'default deny: no rules', input: egressIn('h', 'GET', '/', 0) },
];

describe('OPA parity (skipped when no opa binary is available)', () => {
  const opa = findOpa();
  if (opa === undefined) {
    console.warn('[policy-rego.test] no opa binary found (set OPA_BIN, or put `opa` on PATH); skipping OPA parity tests');
    it.skip('opa parity', () => {});
    return;
  }
  const tmp = mkdtempSync(join(tmpdir(), 'mcp-recorder-rego-'));
  afterAll(() => rmSync(tmp, { recursive: true, force: true }));
  const dirs = new Map<string, string>();
  const policies = new Map<string, Policy>();
  for (const file of FIXTURE_FILES) {
    const { bundle, name, policy } = compileFixture(file);
    const dir = join(tmp, name);
    writeBundle(dir, bundle);
    dirs.set(file, dir);
    policies.set(file, policy);
  }

  it.each(FIXTURE_FILES)('%s: opa check --strict passes and opa fmt would not change anything', (file) => {
    const dir = dirs.get(file)!;
    const check = spawnSync(opa, ['check', '--strict', '-b', dir], { encoding: 'utf8' });
    expect(check.status, check.stderr + check.stdout).toBe(0);
    const fmt = spawnSync(opa, ['fmt', '--fail', '--list', join(dir, 'cresec')], { encoding: 'utf8' });
    expect(fmt.status, `opa fmt would reformat:\n${fmt.stdout}${fmt.stderr}`).toBe(0);
  });

  it('the fixtures cover allow, hold, deny and default outcomes', () => {
    const outcomes = new Set(
      CASES.map((c) => {
        const d = c.kind === 'mcp' ? evaluateMcp(policies.get(c.fixture)!, c.input) : evaluateEgress(policies.get(c.fixture)!, c.input);
        return `${d.matched ? d.action : 'default'}`;
      }),
    );
    expect([...outcomes].sort()).toEqual(['allow', 'default', 'deny', 'hold']);
  });

  it.each(CASES.map((c) => [c.note, c] as const))('%s', (_note, c) => {
    const policy = policies.get(c.fixture)!;
    const dir = dirs.get(c.fixture)!;
    if (c.kind === 'mcp') {
      const ts = evaluateMcp(policy, c.input);
      const opaInput = { server: c.input.server, tool: c.input.tool, args: c.input.args, args_bytes: c.input.argsBytes };
      expect(opaEval(opa, dir, 'data.cresec.gateway.mcp.decision', opaInput)).toEqual(asOpa(ts));
    } else {
      const ts = evaluateEgress(policy, c.input);
      const opaInput = { host: c.input.host, method: c.input.method, path: c.input.path, body_bytes: c.input.bodyBytes };
      expect(opaEval(opa, dir, 'data.cresec.gateway.egress.decision', opaInput)).toEqual(asOpa(ts));
    }
  });
});
