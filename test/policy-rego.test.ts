import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, relative } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { sha256Hex } from '../src/chain/hash.js';
import {
  BUNDLE_FILE_ORDER,
  DECISION_SHAPE,
  EGRESS_REGO_PATH,
  EGRESS_ROOT,
  MANIFEST_PATH,
  MCP_REGO_PATH,
  MCP_ROOT,
  bundleFileOrder,
  bundleRoots,
  compileToRego,
  evaluateEgress,
  evaluateMcp,
  loadPolicyFile,
  policyRevision,
  renderEgressModule,
  renderMcpModule,
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

  it('uses the control-plane paths: cresec/mcp/tool.rego and cresec/egress/http.rego (distinct basenames)', () => {
    expect(MCP_REGO_PATH).toBe('cresec/mcp/tool.rego');
    expect(EGRESS_REGO_PATH).toBe('cresec/egress/http.rego');
    expect(MCP_ROOT).toBe('cresec/mcp');
    expect(EGRESS_ROOT).toBe('cresec/egress');
    expect(MCP_REGO_PATH.startsWith(MCP_ROOT + '/')).toBe(true);
    expect(EGRESS_REGO_PATH.startsWith(EGRESS_ROOT + '/')).toBe(true);
    // The Helm ConfigMap flattens by basename, so the two modules must not share one.
    expect(MCP_REGO_PATH.split('/').pop()).not.toBe(EGRESS_REGO_PATH.split('/').pop());
    for (const p of Object.keys(bundle.files)) expect(p, p).not.toContain('gateway');
  });

  it('emits .manifest with the bare hex revision and both roots when egress is present', () => {
    expect(JSON.parse(bundle.files[MANIFEST_PATH]!)).toEqual({
      revision: goldenHash('laptop-default').slice('sha256:'.length),
      roots: ['cresec/mcp', 'cresec/egress'],
    });
    expect(bundle.files[MANIFEST_PATH]!.endsWith('\n')).toBe(true);
    expect(bundle.files[MANIFEST_PATH]!.trim().split('\n')).toHaveLength(1);
  });

  it('lists the cresec/egress root only when http.rego is emitted', () => {
    expect(bundleRoots(policy)).toEqual(['cresec/mcp', 'cresec/egress']);
    const mcpOnly = compileFixture('mcp-only.yaml');
    expect(bundleRoots(mcpOnly.policy)).toEqual(['cresec/mcp']);
    expect(JSON.parse(mcpOnly.bundle.files[MANIFEST_PATH]!).roots).toEqual(['cresec/mcp']);
    for (const file of ['egress-only.yaml', 'empty.json'] as const) {
      const { bundle: b } = compileFixture(file);
      expect(JSON.parse(b.files[MANIFEST_PATH]!).roots, file).toEqual(['cresec/mcp', 'cresec/egress']);
      expect(b.files[EGRESS_REGO_PATH], file).toBeDefined();
    }
    // Every root in the manifest has a module under it, and every module has its root.
    for (const file of FIXTURE_FILES) {
      const { bundle: b } = compileFixture(file);
      const roots = JSON.parse(b.files[MANIFEST_PATH]!).roots as string[];
      const modules = Object.keys(b.files).filter((p) => p !== MANIFEST_PATH);
      expect(modules.map((m) => m.slice(0, m.lastIndexOf('/'))).sort(), file).toEqual([...roots].sort());
    }
  });

  it('emits http.rego only when the policy has an egress section', () => {
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
    expect(mcp.startsWith('package cresec.mcp\n\nimport rego.v1\n\n')).toBe(true);
    expect(mcp).toContain(`# Generated by mcp-recorder ${TOOL_VERSION} from policy "laptop-default" (${goldenHash('laptop-default')}). Do not edit.`);
    expect(mcp).toContain('# Input:    {"server": "...", "tool": "...", "args": {...}, "args_bytes": 123}');
    expect(DECISION_SHAPE).toBe('{"allow": bool, "action": "allow"|"hold"|"deny", "rule_id": "...", "reason": "...", "matched": bool, "deny_reason": "..."}');
    expect(mcp).toContain(`# Decision: ${DECISION_SHAPE}`);
    expect(mcp).toContain('\tsome p in ["http_post", "send_*"]\n\tglob.match(p, ["/"], input.tool)\n');
    expect(mcp).toContain('\tv0 := object.get(input.args, ["url"], null)\n\tv0 != null\n');
    expect(mcp).toContain('\tregex.match("^https?://", sprintf("%v", [v0]))\n\tinput.args_bytes <= 65536\n');
    expect(mcp).toContain('first_match := min(rule_matches) if count(rule_matches) > 0');
    expect(mcp).not.toMatch(/^ +/m); // tabs only
    expect(mcp).not.toContain('cresec.gateway');
    const egress = bundle.files[EGRESS_REGO_PATH]!;
    expect(egress.startsWith('package cresec.egress\n\nimport rego.v1\n\n')).toBe(true);
    expect(egress).toContain(`# Decision: ${DECISION_SHAPE}`);
    expect(egress).toContain('# Input:    {"host": "...", "method": "GET", "path": "/...", "body_bytes": 123}');
    expect(egress).toContain('\tglob.match("api.github.com", ["."], input.host)\n\tinput.method in ["GET", "HEAD"]\n\tglob.match("/**", ["/"], input.path)\n\tinput.body_bytes <= 1048576\n');
    expect(egress).toContain('default_action := "deny"');
    expect(policy.egress!.default).toBe('deny');
  });

  it('decision is a superset of the broker decision: allow + deny_reason next to action/rule_id/reason/matched', () => {
    const tail = [
      '# "rule <id>: <reason>" ("rule <id>" without a reason) when the action is not allow, "" otherwise.',
      'deny_reason(rule) := "" if rule.action == "allow"',
      '',
      'deny_reason(rule) := sprintf("rule %s", [rule.id]) if {',
      '\trule.action != "allow"',
      '\trule.reason == ""',
      '}',
      '',
      'deny_reason(rule) := sprintf("rule %s: %s", [rule.id, rule.reason]) if {',
      '\trule.action != "allow"',
      '\trule.reason != ""',
      '}',
      '',
      'decision := {',
      '\t"allow": rule.action == "allow",',
      '\t"action": rule.action,',
      '\t"rule_id": rule.id,',
      '\t"reason": rule.reason,',
      '\t"matched": true,',
      '\t"deny_reason": deny_reason(rule),',
      '} if {',
      '\tcount(rule_matches) > 0',
      '\trule := rules[first_match]',
      '}',
      '',
      'decision := {',
      '\t"allow": default_action == "allow",',
      '\t"action": default_action,',
      '\t"rule_id": "",',
      '\t"reason": "",',
      '\t"matched": false,',
      '\t"deny_reason": default_deny_reason,',
      '} if count(rule_matches) == 0',
      '',
      '# "default <action>" when no rule matched and the section default is not allow, "" otherwise.',
      'default_deny_reason := "" if default_action == "allow"',
      '',
      'default_deny_reason := sprintf("default %s", [default_action]) if default_action != "allow"',
      '',
    ].join('\n');
    // Same tail in every module of every fixture (mcp and egress, with and without rules).
    for (const file of FIXTURE_FILES) {
      const { bundle: b } = compileFixture(file);
      for (const p of Object.keys(b.files)) {
        if (p === MANIFEST_PATH) continue;
        expect(b.files[p]!.endsWith('\n' + tail), `${file}: ${p}`).toBe(true);
        expect(b.files[p]!.match(/^decision := \{$/gm), `${file}: ${p}`).toHaveLength(2);
      }
    }
    // The two heads are mutually exclusive on count(rule_matches), so `decision` is always defined exactly once.
    const mcp = bundle.files[MCP_REGO_PATH]!;
    expect(mcp.indexOf('first_match := min(rule_matches)')).toBeLessThan(mcp.indexOf('deny_reason(rule) := ""'));
  });

  it('renderMcpModule / renderEgressModule return exactly the bundle files', () => {
    const opts = { policyHash: goldenHash('laptop-default'), toolVersion: TOOL_VERSION, policyName: 'laptop-default' };
    expect(renderMcpModule(policy, opts)).toBe(bundle.files[MCP_REGO_PATH]);
    expect(renderEgressModule(policy, opts)).toBe(bundle.files[EGRESS_REGO_PATH]);
    // Without a policy name the header still renders (empty name), and the modules stay valid.
    const unnamed = renderMcpModule(policy, { policyHash: goldenHash('laptop-default'), toolVersion: TOOL_VERSION });
    expect(unnamed).toContain(`from policy "" (${goldenHash('laptop-default')})`);
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

/** The full decision object as OPA returns it (the broker's `allow`/`deny_reason` plus the policy keys). */
interface OpaDecision {
  allow: boolean;
  action: string;
  rule_id: string;
  reason: string;
  matched: boolean;
  deny_reason: string;
}

function opaEval(opa: string, bundleDir: string, query: string, input: unknown): OpaDecision {
  const r = spawnSync(opa, ['eval', '-b', bundleDir, '-I', '-f', 'json', query], { encoding: 'utf8', input: JSON.stringify(input) });
  expect(r.status, `opa eval failed: ${r.stderr}`).toBe(0);
  const parsed = JSON.parse(r.stdout) as { result?: Array<{ expressions: Array<{ value: OpaDecision }> }> };
  const value = parsed.result?.[0]?.expressions[0]?.value;
  expect(value, `opa returned no decision for ${JSON.stringify(input)}: ${r.stdout}`).toBeDefined();
  return value!;
}

/**
 * What the Rego decision must be for a TS decision — computed here on
 * purpose, independently of the compiler, so the parity test pins the
 * documented contract (docs/policy.md "Compiling to Rego") and not whatever
 * rego.ts happens to emit.
 */
function asOpa(d: Decision): OpaDecision {
  const ruleId = d.ruleId ?? '';
  const reason = d.reason ?? '';
  let denyReason = '';
  if (d.action !== 'allow') {
    if (!d.matched) denyReason = `default ${d.action}`;
    else denyReason = reason === '' ? `rule ${ruleId}` : `rule ${ruleId}: ${reason}`;
  }
  return { allow: d.action === 'allow', action: d.action, rule_id: ruleId, reason, matched: d.matched, deny_reason: denyReason };
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
  // Rules WITHOUT a reason (deny_reason must then be "rule <id>", no trailing colon) and an egress default hold.
  const inlineResult = validatePolicyObject({
    version: 1,
    name: 'inline',
    mcp: {
      default: 'hold',
      rules: [
        { id: 'quiet-deny', match: { tool: 'rm' }, action: 'deny' },
        { id: 'quiet-hold', match: { tool: 'mv' }, action: 'hold' },
        { id: 'quiet-allow', match: { tool: 'ls' }, action: 'allow' },
      ],
    },
    egress: { default: 'hold', rules: [{ id: 'no-colon', match: { host: 'a.b', methods: ['POST'] }, action: 'deny' }] },
  });
  if (!inlineResult.ok) throw new Error('inline fixture invalid');
  const inlinePolicy = inlineResult.policy;
  const inlineDir = join(tmp, 'inline');
  writeBundle(inlineDir, compileToRego(inlinePolicy, { policyHash: goldenHash('inline'), toolVersion: TOOL_VERSION, policyName: 'inline' }));
  const INLINE_CASES: Array<{ kind: 'mcp'; input: McpRequestInput } | { kind: 'egress'; input: EgressRequestInput }> = [
    { kind: 'mcp', input: mcpIn('s', 'rm', {}, 2) },
    { kind: 'mcp', input: mcpIn('s', 'mv', {}, 2) },
    { kind: 'mcp', input: mcpIn('s', 'ls', {}, 2) },
    { kind: 'mcp', input: mcpIn('s', 'cp', {}, 2) },
    { kind: 'egress', input: egressIn('a.b', 'POST', '/', 0) },
    { kind: 'egress', input: egressIn('a.b', 'GET', '/', 0) },
  ];

  it.each(FIXTURE_FILES)('%s: opa check --strict passes and opa fmt would not change anything', (file) => {
    const dir = dirs.get(file)!;
    const check = spawnSync(opa, ['check', '--strict', '-b', dir], { encoding: 'utf8' });
    expect(check.status, check.stderr + check.stdout).toBe(0);
    const fmt = spawnSync(opa, ['fmt', '--fail', '--list', join(dir, 'cresec')], { encoding: 'utf8' });
    expect(fmt.status, `opa fmt would reformat:\n${fmt.stdout}${fmt.stderr}`).toBe(0);
  });

  it.each(FIXTURE_FILES)('%s: the packages live at data.cresec.mcp / data.cresec.egress (no data.cresec.gateway)', (file) => {
    const dir = dirs.get(file)!;
    const r = spawnSync(opa, ['eval', '-b', dir, '-I', '-f', 'json', 'data.cresec'], { encoding: 'utf8', input: '{}' });
    expect(r.status, r.stderr).toBe(0);
    const value = (JSON.parse(r.stdout) as { result: Array<{ expressions: Array<{ value: Record<string, unknown> }> }> }).result[0]!.expressions[0]!.value;
    const roots = (JSON.parse(readFileSync(join(dir, MANIFEST_PATH), 'utf8')) as { roots: string[] }).roots;
    expect(Object.keys(value).sort()).toEqual(roots.map((root) => root.slice('cresec/'.length)).sort());
    expect(value).not.toHaveProperty('gateway');
  });

  it('the parity cases (fixtures + inline policy) cover every deny_reason form', () => {
    const form = (o: OpaDecision): string => {
      if (o.deny_reason === '') return o.matched ? 'allow-rule' : 'allow-default';
      if (!o.matched) return 'default';
      return o.deny_reason.includes(': ') ? 'rule-with-reason' : 'rule-without-reason';
    };
    const fromFixtures = CASES.map((c) =>
      form(asOpa(c.kind === 'mcp' ? evaluateMcp(policies.get(c.fixture)!, c.input) : evaluateEgress(policies.get(c.fixture)!, c.input))),
    );
    const fromInline = INLINE_CASES.map((c) => form(asOpa(c.kind === 'mcp' ? evaluateMcp(inlinePolicy, c.input) : evaluateEgress(inlinePolicy, c.input))));
    expect([...new Set(fromFixtures)].sort()).toEqual(['allow-default', 'allow-rule', 'default', 'rule-with-reason']);
    expect([...new Set([...fromFixtures, ...fromInline])].sort()).toEqual(['allow-default', 'allow-rule', 'default', 'rule-with-reason', 'rule-without-reason']);
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

  it('inline policy: opa check --strict, and deny_reason has no trailing colon without a reason', () => {
    const check = spawnSync(opa, ['check', '--strict', '-b', inlineDir], { encoding: 'utf8' });
    expect(check.status, check.stderr + check.stdout).toBe(0);
    const fmt = spawnSync(opa, ['fmt', '--fail', '--list', join(inlineDir, 'cresec')], { encoding: 'utf8' });
    expect(fmt.status, `opa fmt would reformat:\n${fmt.stdout}${fmt.stderr}`).toBe(0);
    const seen: string[] = [];
    for (const c of INLINE_CASES) {
      if (c.kind === 'mcp') {
        const ts = evaluateMcp(inlinePolicy, c.input);
        const got = opaEval(opa, inlineDir, 'data.cresec.mcp.decision', { server: c.input.server, tool: c.input.tool, args: c.input.args, args_bytes: c.input.argsBytes });
        expect(got, c.input.tool).toEqual(asOpa(ts));
        seen.push(got.deny_reason);
      } else {
        const ts = evaluateEgress(inlinePolicy, c.input);
        const got = opaEval(opa, inlineDir, 'data.cresec.egress.decision', { host: c.input.host, method: c.input.method, path: c.input.path, body_bytes: c.input.bodyBytes });
        expect(got, c.input.method).toEqual(asOpa(ts));
        seen.push(got.deny_reason);
      }
    }
    expect(seen).toEqual(['rule quiet-deny', 'rule quiet-hold', '', 'default hold', 'rule no-colon', 'default hold']);
  });

  it.each(CASES.map((c) => [c.note, c] as const))('%s', (_note, c) => {
    const policy = policies.get(c.fixture)!;
    const dir = dirs.get(c.fixture)!;
    if (c.kind === 'mcp') {
      const ts = evaluateMcp(policy, c.input);
      const opaInput = { server: c.input.server, tool: c.input.tool, args: c.input.args, args_bytes: c.input.argsBytes };
      expect(opaEval(opa, dir, 'data.cresec.mcp.decision', opaInput)).toEqual(asOpa(ts));
    } else {
      const ts = evaluateEgress(policy, c.input);
      const opaInput = { host: c.input.host, method: c.input.method, path: c.input.path, body_bytes: c.input.bodyBytes };
      expect(opaEval(opa, dir, 'data.cresec.egress.decision', opaInput)).toEqual(asOpa(ts));
    }
  });
});
