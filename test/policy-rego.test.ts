import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parse as parseYaml } from 'yaml';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { sha256Hex } from '../src/chain/hash.js';
import {
  BUNDLE_FILE_ORDER,
  CREDENTIALS_REGO_PATH,
  CREDENTIALS_ROOT,
  DECISION_SHAPE,
  EGRESS_REGO_PATH,
  EGRESS_ROOT,
  MANIFEST_PATH,
  MCP_REGO_PATH,
  MCP_ROOT,
  bundleFileOrder,
  bundleRoots,
  compileToRego,
  configureRegexGuard,
  evaluateEgress,
  evaluateMcp,
  regexGuardState,
  resetRegexGuard,
  loadPolicyFile,
  policyRevision,
  renderCredentialsModule,
  renderEgressModule,
  renderMcpModule,
  REGEX_VALUE_CAP,
  ruleLabel,
  validatePolicyObject,
} from '../src/policy/index.js';
import type { Decision, EgressRequestInput, McpRequestInput, Policy, RegoBundle } from '../src/policy/index.js';

const ROOT = join(__dirname, '..');
const FIXTURES = join(ROOT, 'test', 'fixtures', 'policies');
const EXPECTED = join(FIXTURES, 'expected');
const FIXTURE_FILES = ['laptop-default.yaml', 'mcp-only.yaml', 'credentials.yaml', 'egress-only.yaml', 'empty.json'] as const;
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
    expect(BUNDLE_FILE_ORDER).toEqual([MANIFEST_PATH, MCP_REGO_PATH, CREDENTIALS_REGO_PATH, EGRESS_REGO_PATH]);
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
    // Globs are emitted as the REGEX `glob.ts` compiles them to, so OPA and
    // the local engine cannot read the same pattern differently (F2).
    expect(mcp).toContain('\tsome p in ["^http_post$", "^send_[^\\\\/]*$"]\n\tregex.match(p, input.tool)\n');
    expect(mcp).toContain('\tis_object(input.args)\n\tv0 := input.args.url\n');
    expect(mcp).toContain('\tregex.match("^https?://", scalar_text(v0))\n\tinput.args_bytes <= 65536\n');
    // P1: json.marshal, never sprintf("%v") — Go's %v renders 1234567.5 as "1.2345675e+06".
    expect(mcp).not.toContain('sprintf("%v"');
    expect(mcp).toContain('\nscalar_text(v) := v if is_string(v)\n\nscalar_text(v) := json.marshal(v) if not is_string(v)\n');
    expect(mcp).toContain('first_match := min(rule_matches) if count(rule_matches) > 0');
    expect(mcp).not.toMatch(/^ +/m); // tabs only
    expect(mcp).not.toContain('cresec.gateway');
    const egress = bundle.files[EGRESS_REGO_PATH]!;
    expect(egress.startsWith('package cresec.egress\n\nimport rego.v1\n\n')).toBe(true);
    expect(egress).toContain(`# Decision: ${DECISION_SHAPE}`);
    expect(egress).toContain('# Input:    {"host": "...", "method": "GET", "path": "/...", "body_bytes": 123}');
    expect(egress).toContain('\tregex.match("^api\\\\.github\\\\.com$", input.host)\n\tinput.method in ["GET", "HEAD"]\n\tregex.match("^\\\\/[\\\\s\\\\S]*$", input.path)\n\tinput.body_bytes <= 1048576\n');
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

  it('dot-path segments become a reference chain, numeric indexes as numbers', () => {
    const mcp = compileFixture('mcp-only.yaml').bundle.files[MCP_REGO_PATH]!;
    // NOT object.get, which errors on a non-object root and so drops the
    // whole rule from the decision under --strict-builtin-errors (F-compile).
    expect(mcp).not.toContain('object.get(');
    expect(mcp).toContain('v0 := input.args.filters[0].field');
    expect(mcp).toContain('v1 := input.args.limit');
    expect(mcp).toContain('v2 := input.args.dry_run');
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
    expect(out).toContain('regex.match("^say \\"hi\\"\\t$", input.tool)');
    expect(out).toContain('regex.match("^\\\\d+\\\\\\\\$", scalar_text(v0))');
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

/* ------------------------ the credentials module -------------------------- */

describe('compileToRego: cresec/credentials/broker.rego', () => {
  const { bundle, policy } = compileFixture('credentials.yaml');
  const credentials = bundle.files[CREDENTIALS_REGO_PATH]!;

  it('is emitted, rooted and ordered like the other optional section', () => {
    expect(CREDENTIALS_REGO_PATH).toBe('cresec/credentials/broker.rego');
    expect(CREDENTIALS_ROOT).toBe('cresec/credentials');
    expect(CREDENTIALS_REGO_PATH.startsWith(CREDENTIALS_ROOT + '/')).toBe(true);
    // The Helm ConfigMap flattens by basename, so all three must differ.
    const basenames = [MCP_REGO_PATH, CREDENTIALS_REGO_PATH, EGRESS_REGO_PATH].map((p) => p.split('/').pop());
    expect(new Set(basenames).size).toBe(3);
    expect(BUNDLE_FILE_ORDER).toEqual([MANIFEST_PATH, MCP_REGO_PATH, CREDENTIALS_REGO_PATH, EGRESS_REGO_PATH]);
    expect(bundleRoots(policy)).toEqual([MCP_ROOT, CREDENTIALS_ROOT]);
    expect(JSON.parse(bundle.files[MANIFEST_PATH]!).roots).toEqual([MCP_ROOT, CREDENTIALS_ROOT]);
    expect(Object.keys(bundle.files).sort()).toEqual([MANIFEST_PATH, CREDENTIALS_REGO_PATH, MCP_REGO_PATH].sort());
    // And not emitted at all when the policy has no credentials section.
    expect(compileFixture('mcp-only.yaml').bundle.files[CREDENTIALS_REGO_PATH]).toBeUndefined();
    expect(() => renderCredentialsModule(compileFixture('mcp-only.yaml').policy, { policyHash: goldenHash('x'), toolVersion: 'v' })).toThrow(
      /no credentials section/,
    );
    expect(renderCredentialsModule(policy, { policyHash: goldenHash('credentials'), toolVersion: TOOL_VERSION, policyName: 'credentials-example' })).toBe(
      credentials,
    );
  });

  it('ignores credentials[].broker, action_class and method: a remote credential compiles to exactly the Rego a local one does', () => {
    // The emitted module names the credential by id and the site by its
    // globs, host and path; WHERE the credential is resolved (a local
    // source, or the control plane's per-user token endpoint) and the
    // control plane's own inputs (action class, method) are not the Rego's
    // business. So the two spellings must produce one bundle, or the OPA
    // parity gate would be comparing the local engine against a policy
    // that changes shape when brokering moves to the control plane.
    const opts = { policyHash: goldenHash('remote'), toolVersion: TOOL_VERSION };
    const local = validatePolicyObject({
      version: 1,
      mcp: { default: 'allow' },
      credentials: [
        {
          id: 'gmail-drafts',
          provider: 'gmail',
          source: { type: 'env', var: 'GMAIL_TOKEN' },
          use: [{ id: 'draft', tool: 'gmail_create_draft', arg: 'headers.Authorization', host: { fixed: 'gmail.googleapis.com' } }],
        },
      ],
    });
    const remote = validatePolicyObject({
      version: 1,
      mcp: { default: 'allow' },
      credentials: [
        {
          id: 'gmail-drafts',
          provider: 'gmail',
          broker: { kind: 'remote', url: 'https://api.cresec.test', token_env: 'CRESEC_INTERNAL_TOKEN', tenant: 'e2e', user_env: 'CRESEC_USER_ID' },
          use: [
            {
              id: 'draft',
              tool: 'gmail_create_draft',
              arg: 'headers.Authorization',
              host: { fixed: 'gmail.googleapis.com' },
              action_class: 'draft',
              method: 'POST',
            },
          ],
        },
      ],
    });
    if (!local.ok || !remote.ok) throw new Error('fixture invalid');
    expect(remote.policy.credentials![0]!.broker?.kind).toBe('remote');
    expect(compileToRego(remote.policy, opts)).toEqual(compileToRego(local.policy, opts));
    // NEGATIVE CONTROL: the bundle is not vacuous — the site is in it.
    expect(compileToRego(remote.policy, opts).files[CREDENTIALS_REGO_PATH]).toContain('gmail-drafts/draft');
  });

  it('defaults to deny, and says in the module that it is the one section enforced on BOTH sides', () => {
    expect(credentials.startsWith('package cresec.credentials\n\nimport rego.v1\n\n')).toBe(true);
    expect(credentials).toContain(
      '# Input:    {"credential": "...", "server": "...", "tool": "...", "host": "...", "host_source": "argument"|"declared"|"server_name", "path_template": "..."}',
    );
    expect(credentials).toContain(`# Decision: ${DECISION_SHAPE}`);
    expect(credentials).toContain('# Enforced BOTH locally (the gateway broker');
    expect(credentials).toContain('default_action := "deny"');
    // There is no author-settable default: an undeclared use is a deny in
    // every credentials module, whatever the file says elsewhere.
    expect(credentials).not.toContain('default_action := "allow"');
    expect(credentials).not.toMatch(/^ +/m); // tabs only, like the rest of the bundle
  });

  it('gives every site the composed id and keeps file order, so the carve-out still wins', () => {
    expect(credentials).toContain('{"id": "github-issues/no-deletes", "action": "deny", "reason": "an issues token does not delete things"},');
    expect(credentials).toContain('{"id": "github-issues/create-issue", "action": "allow", "reason": ""},');
    expect(credentials.indexOf('"github-issues/no-deletes"')).toBeLessThan(credentials.indexOf('"github-issues/create-issue"'));
    expect(credentials).toContain('# github-issues/no-deletes\nrule_matches contains 0 if {');
  });

  it('matches the credential by id and the site by the same globs the mcp module uses', () => {
    expect(credentials).toContain('\tinput.credential == "github-issues"\n\tregex.match("^corp\\\\-notes$", input.server)\n\tregex.match("^http_delete$", input.tool)\n');
    // A glob list is a `some ... in` over the SAME regex sources glob.ts
    // compiles, not a second matcher.
    expect(credentials).toContain('\tsome h in ["^api\\\\.github\\\\.com$", "^[^\\\\.]*\\\\.github\\\\.com$"]\n\tregex.match(h, input.host)\n');
    expect(credentials).toContain('regex.match("^clickup_[^\\\\/]*$", input.tool)');
  });

  it('carries host_source as a CONDITION, so a checked destination cannot be satisfied by a server name', () => {
    // Three forms, three conditions. Without this line a data plane that
    // filled `host` with the server name would satisfy a site that declared
    // an argument-derived destination, and the decision log could not tell
    // the two apart afterwards.
    expect(credentials).toContain('\tinput.host_source == "argument"\n');
    expect(credentials).toContain('\tinput.host_source == "declared"\n\tinput.host == "api.clickup.com"\n');
    expect(credentials).toContain('\tinput.host_source == "server_name"\n\tregex.match("^db$", input.host)\n');
    expect(credentials.match(/input\.host_source == /g)).toHaveLength(policy.credentials!.flatMap((c) => c.use).length);
  });

  it('binds path_template to the tool name unless the site derived it from an argument', () => {
    expect(credentials).toContain('\tinput.host == "registry.npmjs.org"\n\tinput.path_template == input.tool\n');
    expect(credentials).toContain('\tregex.match("^901[^\\\\/]*$", input.path_template)\n');
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

/**
 * The exact message a required-but-missing OPA must produce. Kept as a
 * constant so the workflow-shape test below can assert on it verbatim.
 */
export const OPA_REQUIRED_MESSAGE = 'opa required by CI (MCP_RECORDER_REQUIRE_OPA=1) but not found';

/** MCP_RECORDER_REQUIRE_OPA is a strict '1' flag: nothing else turns it on. */
export function opaRequired(value: string | undefined): boolean {
  return value === '1';
}

/**
 * The parity gate cannot be switched off by accident. Locally a missing
 * `opa` binary is a skip (nobody has to install OPA to run the suite), but
 * CI sets MCP_RECORDER_REQUIRE_OPA=1 (.github/workflows/ci.yml, Linux job):
 * there a missing binary means the setup-opa step broke, and skipping would
 * silently drop the TypeScript-vs-Rego parity check.
 */
export function opaOrFail(found: string | undefined, required: boolean): string | undefined {
  if (found === undefined && required) throw new Error(OPA_REQUIRED_MESSAGE);
  return found;
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

/**
 * `--strict-builtin-errors` is the load-bearing flag, not a detail. Without
 * it a builtin that ERRORS — `regex.match` on a pattern RE2 cannot load,
 * `glob.match` on a rune it cannot read — is `undefined` in Rego, the rule
 * quietly drops out of `rule_matches`, and the decision comes back as a
 * clean `default allow` that this suite would then compare happily against a
 * TS engine that denies. Every emitted pattern has to survive evaluation for
 * the parity claim to mean anything, so every eval in this file asserts it.
 */
function opaEval(opa: string, bundleDir: string, query: string, input: unknown): OpaDecision {
  const r = spawnSync(opa, ['eval', '-b', bundleDir, '-I', '-f', 'json', '--strict-builtin-errors', query], { encoding: 'utf8', input: JSON.stringify(input) });
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

/**
 * The parity claim is about SEMANTICS: the TypeScript engine and the emitted
 * Rego must reach the same decision. It is not about the regex guard's 25 ms
 * deadline, which OPA has no equivalent of — and on a loaded runner (a full
 * suite with a worker per file, each with its own guard thread) a match that
 * takes 0.03 ms warm can overrun it, poison the pattern and turn an ALLOW
 * into a fail-closed deny. That is correct gateway behaviour and a false
 * parity failure: 5 cases failed that way once in five full-suite runs here.
 *
 * So these tests give the guard a deadline no scheduler hiccup can reach.
 * The deadline itself is tested where it belongs, in test/policy.test.ts,
 * including that it fires, poisons and denies.
 */
const PARITY_DEADLINE_MS = 5_000;

describe('OPA parity (skipped when no opa binary is available, required in CI)', () => {
  beforeAll(() => {
    resetRegexGuard();
    configureRegexGuard({ deadlineMs: PARITY_DEADLINE_MS });
  });
  afterAll(() => {
    resetRegexGuard();
  });

  const found = findOpa();
  if (found === undefined) {
    const required = opaRequired(process.env.MCP_RECORDER_REQUIRE_OPA);
    if (required) {
      // Reported as one failing test rather than a collection error, so the
      // CI log names the gate that was about to be skipped.
      it('opa parity is required in CI', () => {
        opaOrFail(undefined, required);
      });
      return;
    }
    console.warn('[policy-rego.test] no opa binary found (set OPA_BIN, or put `opa` on PATH); skipping OPA parity tests');
    it.skip('opa parity', () => {});
    return;
  }
  const opa: string = found;
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

  /**
   * The credentials module has no local twin to compare against (the swap is
   * decided by the broker, not by `engine.ts`), so these assert the decision
   * the CONTROL PLANE would return for a handful of exchanges — including the
   * three that must not be authorised.
   */
  describe('credentials: what the control plane answers', () => {
    const dir = dirs.get('credentials.yaml')!;
    const exchange = (over: Record<string, string>): OpaDecision =>
      opaEval(opa, dir, 'data.cresec.credentials.decision', {
        credential: 'github-issues',
        server: 'corp-notes',
        tool: 'http_post',
        host: 'api.github.com',
        host_source: 'argument',
        path_template: 'http_post',
        ...over,
      });

    it('allows a declared site, and lets the carve-out above it win', () => {
      expect(exchange({})).toMatchObject({ allow: true, action: 'allow', rule_id: 'github-issues/create-issue', matched: true, deny_reason: '' });
      expect(exchange({ host: 'uploads.github.com' })).toMatchObject({ allow: true, rule_id: 'github-issues/create-issue' });
      expect(exchange({ tool: 'http_delete', path_template: 'http_delete' })).toMatchObject({
        allow: false,
        action: 'deny',
        rule_id: 'github-issues/no-deletes',
        deny_reason: 'rule github-issues/no-deletes: an issues token does not delete things',
      });
    });

    it('denies by default when anything about the tuple is undeclared', () => {
      const unmatched = { allow: false, action: 'deny', matched: false, rule_id: '', deny_reason: 'default deny' };
      // The destination is the agent's to choose, so it is the one that matters.
      expect(exchange({ host: 'attacker.example' }), 'undeclared host').toMatchObject(unmatched);
      expect(exchange({ server: 'echo-server' }), 'undeclared server').toMatchObject(unmatched);
      expect(exchange({ tool: 'echo' }), 'undeclared tool').toMatchObject(unmatched);
      // One credential's site does not authorise another credential.
      expect(exchange({ credential: 'clickup-api' }), 'wrong credential').toMatchObject(unmatched);
      // And a data plane that filled `host` with the server name cannot
      // satisfy a site that declared an argument-derived destination — this
      // is the difference between "host was checked" and "host was a name".
      expect(exchange({ host_source: 'server_name' }), 'host_source downgraded').toMatchObject(unmatched);
      expect(exchange({ host_source: 'declared' }), 'host_source downgraded').toMatchObject(unmatched);
    });

    it('checks the other two host bindings and the argument-derived path', () => {
      const clickup = { credential: 'clickup-api', server: 'clickup', tool: 'clickup_create_task', host: 'api.clickup.com', host_source: 'declared' };
      expect(opaEval(opa, dir, 'data.cresec.credentials.decision', { ...clickup, path_template: '901234' })).toMatchObject({
        allow: true,
        rule_id: 'clickup-api/tasks',
      });
      expect(opaEval(opa, dir, 'data.cresec.credentials.decision', { ...clickup, path_template: '123' })).toMatchObject({ allow: false, matched: false });
      const db = { credential: 'db-readonly', server: 'db', tool: 'query', path_template: 'query' };
      expect(opaEval(opa, dir, 'data.cresec.credentials.decision', { ...db, host: 'db', host_source: 'server_name' })).toMatchObject({
        allow: true,
        rule_id: 'db-readonly/query',
      });
      // `host` is the SERVER NAME in that form, so a real hostname there is
      // a request this policy never described.
      expect(opaEval(opa, dir, 'data.cresec.credentials.decision', { ...db, host: 'db.internal', host_source: 'server_name' })).toMatchObject({
        allow: false,
        matched: false,
      });
    });
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

  /*
   * Scalar coercion (P1), an array `arguments` root (P2) and a two-entry
   * `match.server` list (P5). Each case names the rule it must hit so a
   * regression that makes BOTH engines stop matching still fails the test.
   */
  const parityResult = validatePolicyObject({
    version: 1,
    name: 'parity',
    mcp: {
      default: 'allow',
      rules: [
        { id: 'servers', match: { server: ['corp-*', 'fs'], tool: 'ls' }, action: 'deny', reason: 'two-entry server list' },
        // A numeric FIRST segment: `params.arguments` is an object per MCP,
        // so this can never match — the emitted `is_object(input.args)` and
        // `getPath`'s non-object-root refusal say so in their own engines.
        { id: 'array-root', match: { tool: 'http_post', args: { '0.url': '^https://' } }, action: 'deny', reason: 'numeric first segment' },
        { id: 'object-root', match: { tool: 'http_post', args: { url: '^https://' } }, action: 'deny', reason: 'object root' },
        { id: 'big-float', match: { tool: 'num', args: { n: '^1234567\\.5$' } }, action: 'deny', reason: 'float >= 1e6' },
        { id: 'small-float', match: { tool: 'num', args: { n: '^0\\.00001$' } }, action: 'deny', reason: 'float < 1e-4' },
        { id: 'tiny-float', match: { tool: 'num', args: { n: '^1e-7$' } }, action: 'deny', reason: 'float below 1e-6' },
        { id: 'huge-int', match: { tool: 'num', args: { n: '^1e\\+21$' } }, action: 'deny', reason: 'integer >= 1e21' },
        { id: 'int', match: { tool: 'num', args: { n: '^42$' } }, action: 'deny', reason: 'integer' },
        { id: 'neg-zero', match: { tool: 'num', args: { n: '^0$' } }, action: 'deny', reason: 'negative zero' },
        { id: 'neg-float', match: { tool: 'num', args: { n: '^-1\\.5$' } }, action: 'deny', reason: 'negative float' },
        { id: 'bool', match: { tool: 'num', args: { n: '^true$' } }, action: 'deny', reason: 'boolean' },
      ],
    },
  });
  if (!parityResult.ok) throw new Error('parity fixture invalid');
  const parityPolicy = parityResult.policy;
  const parityDir = join(tmp, 'parity');
  writeBundle(parityDir, compileToRego(parityPolicy, { policyHash: goldenHash('parity'), toolVersion: TOOL_VERSION, policyName: 'parity' }));
  const num = (n: unknown): McpRequestInput => mcpIn('s', 'num', { n }, 16);
  const PARITY_CASES: Array<{ note: string; input: McpRequestInput; ruleId: string | null }> = [
    // P1 — Go's sprintf("%v") renders these as "1.2345675e+06" / "1e-05";
    // json.marshal (and JavaScript's String()) render them as written here.
    { note: 'P1 float >= 1e6', input: num(1234567.5), ruleId: 'big-float' },
    { note: 'P1 float < 1e-4', input: num(0.00001), ruleId: 'small-float' },
    { note: 'P1 float below 1e-6 (exponent form in both)', input: num(1e-7), ruleId: 'tiny-float' },
    { note: 'P1 integer >= 1e21 (exponent form in both)', input: num(1e21), ruleId: 'huge-int' },
    { note: 'P1 integer', input: num(42), ruleId: 'int' },
    { note: 'P1 integer-valued float coerces without a ".0"', input: num(42.0), ruleId: 'int' },
    { note: 'P1 negative zero prints as "0"', input: num(-0), ruleId: 'neg-zero' },
    { note: 'P1 plain zero prints as "0"', input: num(0), ruleId: 'neg-zero' },
    { note: 'P1 negative float', input: num(-1.5), ruleId: 'neg-float' },
    { note: 'P1 boolean true', input: num(true), ruleId: 'bool' },
    { note: 'P1 boolean false matches nothing', input: num(false), ruleId: null },
    { note: 'P1 the string "1234567.5" coerces to itself', input: num('1234567.5'), ruleId: 'big-float' },
    { note: 'P1 a non-scalar never matches', input: num({ v: 42 }), ruleId: null },
    // P2 — an array (or scalar) `arguments` must not resolve any dot-path.
    { note: 'P2 array arguments root with a numeric first segment', input: mcpIn('s', 'http_post', [{ url: 'https://x' }], 22), ruleId: null },
    { note: 'P2 array arguments root, plain path', input: mcpIn('s', 'http_post', ['https://x'], 13), ruleId: null },
    { note: 'P2 scalar arguments root', input: mcpIn('s', 'http_post', 'https://x', 11), ruleId: null },
    { note: 'P2 object arguments root still matches', input: mcpIn('s', 'http_post', { url: 'https://x' }, 22), ruleId: 'object-root' },
    { note: 'P2 object key "0" is not an array index', input: mcpIn('s', 'http_post', { '0': { url: 'https://x' } }, 28), ruleId: null },
    // P5 — a two-entry `match.server` list.
    { note: 'P5 server list: first entry', input: mcpIn('corp-notes', 'ls', {}, 2), ruleId: 'servers' },
    { note: 'P5 server list: second entry', input: mcpIn('fs', 'ls', {}, 2), ruleId: 'servers' },
    { note: 'P5 server list: neither entry', input: mcpIn('other', 'ls', {}, 2), ruleId: null },
    { note: 'P5 server list: "*" does not cross the "/" delimiter', input: mcpIn('corp-a/b', 'ls', {}, 2), ruleId: null },
  ];

  it('parity policy: opa check --strict and opa fmt --fail stay green with the scalar_text helper', () => {
    const check = spawnSync(opa, ['check', '--strict', '-b', parityDir], { encoding: 'utf8' });
    expect(check.status, check.stderr + check.stdout).toBe(0);
    const fmt = spawnSync(opa, ['fmt', '--fail', '--list', join(parityDir, 'cresec')], { encoding: 'utf8' });
    expect(fmt.status, `opa fmt would reformat:\n${fmt.stdout}${fmt.stderr}`).toBe(0);
    const module = readFileSync(join(parityDir, MCP_REGO_PATH), 'utf8');
    expect(module).toContain('scalar_text(v) := json.marshal(v) if not is_string(v)');
    expect(module).not.toContain('sprintf("%v"');
    expect(module).toContain('some s in ["^corp\\\\-[^\\\\/]*$", "^fs$"]');
  });

  it.each(PARITY_CASES.map((c) => [c.note, c] as const))('%s', (_note, c) => {
    const ts = evaluateMcp(parityPolicy, c.input);
    expect(ts.ruleId ?? null, `TypeScript engine picked ${ruleLabel(ts)}`).toBe(c.ruleId);
    const opaInput = { server: c.input.server, tool: c.input.tool, args: c.input.args, args_bytes: c.input.argsBytes };
    expect(opaEval(opa, parityDir, 'data.cresec.mcp.decision', opaInput)).toEqual(asOpa(ts));
  });

  /*
   * `.` and character counting. JavaScript's `.` (no `s` flag) excludes
   * \n \r U+2028 U+2029 and counts UTF-16 units; RE2's excludes \n only and
   * counts runes. Every case below was measured as a DISAGREEMENT against
   * OPA 1.20.2 before the compiler started spelling `.` out for RE2 and the
   * local engine started matching with the `u` flag.
   */
  const dotsResult = validatePolicyObject({
    version: 1,
    name: 'dots',
    mcp: {
      default: 'allow',
      rules: [
        { id: 'dot-star', match: { tool: 'a', args: { s: '^.*secret.*$' } }, action: 'deny', reason: 'secrets' },
        { id: 'rm-rf', match: { tool: 'b', args: { s: '^rm -rf .+$' } }, action: 'deny', reason: 'destructive' },
        { id: 'etc', match: { tool: 'c', args: { s: '^/etc/.+$' } }, action: 'deny', reason: 'system files' },
        { id: 'count8', match: { tool: 'd', args: { s: '^.{1,8}$' } }, action: 'deny', reason: 'short values' },
        { id: 'count2', match: { tool: 'e', args: { s: '^..$' } }, action: 'deny', reason: 'exactly two' },
        { id: 'dot-class', match: { tool: 'f', args: { s: '^[.]$' } }, action: 'deny', reason: 'a literal dot' },
        { id: 'dot-escaped', match: { tool: 'g', args: { s: '^a\\.b$' } }, action: 'deny', reason: 'an escaped dot' },
        // A dash beside a class escape: `u` mode calls it an invalid range,
        // RE2 and non-`u` JavaScript both read it as a literal dash.
        { id: 'class-dash', match: { tool: 'h', args: { s: '^[\\d-z]$' } }, action: 'deny', reason: 'a dash after a class escape' },
      ],
    },
  });
  if (!dotsResult.ok) throw new Error('dots fixture invalid');
  const dotsPolicy = dotsResult.policy;
  const dotsDir = join(tmp, 'dots');
  writeBundle(dotsDir, compileToRego(dotsPolicy, { policyHash: goldenHash('dots'), toolVersion: TOOL_VERSION, policyName: 'dots' }));
  const GRIN = '\u{1F600}';
  const DOT_CASES: Array<{ note: string; input: McpRequestInput; ruleId: string | null }> = [
    { note: 'F9 "." does not match \\r in either engine', input: mcpIn('s', 'a', { s: 'my\rsecret' }, 20), ruleId: null },
    { note: 'F9 "." does not match \\n in either engine', input: mcpIn('s', 'a', { s: 'my\nsecret' }, 20), ruleId: null },
    { note: 'F9 "." does not match U+2028 in either engine', input: mcpIn('s', 'a', { s: `my\u2028secret` }, 20), ruleId: null },
    { note: 'F9 ".*secret.*" still matches ordinary text', input: mcpIn('s', 'a', { s: 'my secret' }, 20), ruleId: 'dot-star' },
    { note: 'F9 "rm -rf .+" does not match a \\r argument', input: mcpIn('s', 'b', { s: 'rm -rf \r/' }, 20), ruleId: null },
    { note: 'F9 "rm -rf .+" still matches a real path', input: mcpIn('s', 'b', { s: 'rm -rf /tmp' }, 20), ruleId: 'rm-rf' },
    { note: 'F9 "/etc/.+" does not match a \\r argument', input: mcpIn('s', 'c', { s: '/etc/\rpasswd' }, 20), ruleId: null },
    { note: 'F9 "/etc/.+" still matches /etc/passwd', input: mcpIn('s', 'c', { s: '/etc/passwd' }, 20), ruleId: 'etc' },
    { note: 'F9 ".{1,8}" counts five astral runes, not ten UTF-16 units', input: mcpIn('s', 'd', { s: GRIN.repeat(5) }, 30), ruleId: 'count8' },
    { note: 'F9 ".{1,8}" rejects nine astral runes', input: mcpIn('s', 'd', { s: GRIN.repeat(9) }, 50), ruleId: null },
    { note: 'F9 ".." is two runes, so one astral character does not match', input: mcpIn('s', 'e', { s: GRIN }, 12), ruleId: null },
    { note: 'F9 ".." still matches two ASCII characters', input: mcpIn('s', 'e', { s: 'ab' }, 12), ruleId: 'count2' },
    { note: 'F9 "." inside a character class stays a literal dot', input: mcpIn('s', 'f', { s: '.' }, 10), ruleId: 'dot-class' },
    { note: 'F9 "[.]" does not match another character', input: mcpIn('s', 'f', { s: 'x' }, 10), ruleId: null },
    { note: 'F9 an escaped "\\." is untouched by the rewrite', input: mcpIn('s', 'g', { s: 'a.b' }, 12), ruleId: 'dot-escaped' },
    { note: 'F9 "a\\.b" does not match "axb"', input: mcpIn('s', 'g', { s: 'axb' }, 12), ruleId: null },
    { note: 'F10 "[\\d-z]" matches a literal dash in both engines', input: mcpIn('s', 'h', { s: '-' }, 10), ruleId: 'class-dash' },
    { note: 'F10 "[\\d-z]" matches a digit', input: mcpIn('s', 'h', { s: '5' }, 10), ruleId: 'class-dash' },
    { note: 'F10 "[\\d-z]" matches "z"', input: mcpIn('s', 'h', { s: 'z' }, 10), ruleId: 'class-dash' },
    { note: 'F10 "[\\d-z]" is not a range: "x" does not match', input: mcpIn('s', 'h', { s: 'x' }, 10), ruleId: null },
  ];

  it('dots policy: "." is emitted as the explicit class, and opa check --strict / opa fmt stay green', () => {
    const module = readFileSync(join(dotsDir, MCP_REGO_PATH), 'utf8');
    expect(module).toContain('regex.match("^[^\\\\n\\\\r\\\\x{2028}\\\\x{2029}]*secret[^\\\\n\\\\r\\\\x{2028}\\\\x{2029}]*$", scalar_text(v0))');
    expect(module).toContain('regex.match("^[.]$", scalar_text(v0))'); // inside a class: untouched
    expect(module).toContain('regex.match("^a\\\\.b$", scalar_text(v0))'); // escaped: untouched
    const check = spawnSync(opa, ['check', '--strict', '-b', dotsDir], { encoding: 'utf8' });
    expect(check.status, check.stderr + check.stdout).toBe(0);
    const fmt = spawnSync(opa, ['fmt', '--fail', '--list', join(dotsDir, 'cresec')], { encoding: 'utf8' });
    expect(fmt.status, `opa fmt would reformat:\n${fmt.stdout}${fmt.stderr}`).toBe(0);
  });

  it.each(DOT_CASES.map((c) => [c.note, c] as const))('%s', (_note, c) => {
    const ts = evaluateMcp(dotsPolicy, c.input);
    expect(ts.ruleId ?? null, `TypeScript engine picked ${ruleLabel(ts)}`).toBe(c.ruleId);
    const opaInput = { server: c.input.server, tool: c.input.tool, args: c.input.args, args_bytes: c.input.argsBytes };
    expect(opaEval(opa, dotsDir, 'data.cresec.mcp.decision', opaInput)).toEqual(asOpa(ts));
  });

  /* ------------- globs decide identically in both engines ----------------
   * OPA's glob library reads a pattern of the form A + crossing-wildcard + B
   * as `HasPrefix(A) && HasSuffix(B)` with no requirement that the two not
   * overlap, so `danger/[crossing]/run` matched `danger/run` there and not
   * here: a deny rule the control plane enforced and the local gateway did
   * not. An odd run of three or more `*` means "at least one character"
   * there and "any run" here, and U+FFFD makes `glob.match` raise `could not
   * read rune`, which is undefined in Rego and drops the rule. None of the
   * three is reachable now: the compiler emits the REGEX `glob.ts` compiles
   * the glob to, so there is one translation.
   */
  const globResult = validatePolicyObject({
    version: 1,
    name: 'globs',
    mcp: {
      default: 'allow',
      rules: [
        { id: 'overlap', match: { tool: 'danger/**/run' }, action: 'deny', reason: 'prefix and suffix overlap' },
        { id: 'triple', match: { tool: 'sh***' }, action: 'deny', reason: 'odd wildcard run' },
        { id: 'replacement', match: { tool: 'bad�tool' }, action: 'deny', reason: 'U+FFFD' },
        { id: 'nul', match: { tool: 'nul\u0000tool' }, action: 'deny', reason: 'U+0000' },
      ],
    },
    egress: {
      default: 'deny',
      rules: [{ id: 'host-overlap', match: { host: 'api.**.github.com', path: '/**' }, action: 'allow', reason: 'host overlap' }],
    },
  });
  if (!globResult.ok) throw new Error(`globs fixture invalid: ${JSON.stringify(globResult.errors)}`);
  const globPolicy = globResult.policy;
  const globDir = join(tmp, 'globs');
  writeBundle(globDir, compileToRego(globPolicy, { policyHash: goldenHash('globs'), toolVersion: TOOL_VERSION, policyName: 'globs' }));

  const GLOB_CASES: Array<{ note: string; input: McpRequestInput; ruleId: string | null }> = [
    { note: 'G1 the prefix and suffix of a crossing wildcard may not overlap ("danger/run")', input: mcpIn('s', 'danger/run', {}, 2), ruleId: null },
    { note: 'G1 a crossing wildcard matches "danger/x/run"', input: mcpIn('s', 'danger/x/run', {}, 2), ruleId: 'overlap' },
    { note: 'G1 a crossing wildcard matches "danger//run" (the run may be empty)', input: mcpIn('s', 'danger//run', {}, 2), ruleId: 'overlap' },
    { note: 'G2 "sh***" matches "sh": an odd wildcard run is still just a run', input: mcpIn('s', 'sh', {}, 2), ruleId: 'triple' },
    { note: 'G2 "sh***" matches "shell"', input: mcpIn('s', 'shell', {}, 2), ruleId: 'triple' },
    { note: 'G3 a U+FFFD in a glob is a literal in both engines', input: mcpIn('s', 'bad�tool', {}, 2), ruleId: 'replacement' },
    { note: 'G3 U+FFFD does not match another character', input: mcpIn('s', 'badxtool', {}, 2), ruleId: null },
    { note: 'G4 a U+0000 in a glob is a literal in both engines', input: mcpIn('s', 'nul\u0000tool', {}, 2), ruleId: 'nul' },
  ];

  it('globs policy: opa check --strict and opa fmt stay green with regex-emitted globs', () => {
    const module = readFileSync(join(globDir, MCP_REGO_PATH), 'utf8');
    expect(module).not.toContain('glob.match(');
    const check = spawnSync(opa, ['check', '--strict', '-b', globDir], { encoding: 'utf8' });
    expect(check.status, check.stderr + check.stdout).toBe(0);
    const fmt = spawnSync(opa, ['fmt', '--fail', '--list', join(globDir, 'cresec')], { encoding: 'utf8' });
    expect(fmt.status, `opa fmt would reformat:\n${fmt.stdout}${fmt.stderr}`).toBe(0);
  });

  it.each(GLOB_CASES.map((c) => [c.note, c] as const))('%s', (_note, c) => {
    const ts = evaluateMcp(globPolicy, c.input);
    expect(ts.ruleId ?? null, `TypeScript engine picked ${ruleLabel(ts)}`).toBe(c.ruleId);
    const opaInput = { server: c.input.server, tool: c.input.tool, args: c.input.args, args_bytes: c.input.argsBytes };
    expect(opaEval(opa, globDir, 'data.cresec.mcp.decision', opaInput)).toEqual(asOpa(ts));
  });

  it.each([
    ['G5 a crossing wildcard in a host may not overlap ("api.github.com")', 'api.github.com', null],
    ['G5 a crossing wildcard in a host matches "api.x.github.com"', 'api.x.github.com', 'host-overlap'],
  ] as const)('%s', (_note, host, ruleId) => {
    const input = egressIn(host, 'GET', '/x', 0);
    const ts = evaluateEgress(globPolicy, input);
    expect(ts.ruleId ?? null).toBe(ruleId);
    const opaInput = { host: input.host, method: input.method, path: input.path, body_bytes: input.bodyBytes };
    expect(opaEval(opa, globDir, 'data.cresec.egress.decision', opaInput)).toEqual(asOpa(ts));
  });

  it('a byte-order mark (and the rest of its class) is escaped, so the bundle loads and reads back unchanged', () => {
    // A U+FEFF pasted in from a document used to compile with exit 0 and then
    // fail to load: `opa check --strict` reported `rego_parse_error:
    // non-terminated object` and `opa eval` exited 2.
    const reason = 'pasted\ufefffrom \u007f\u0085a \u2028document\u2029';
    const r = validatePolicyObject({
      version: 1,
      name: 'bom',
      mcp: { default: 'allow', rules: [{ id: 'bom', match: { tool: 'echo', args: { s: 'a\ufeffb' } }, action: 'deny', reason }] },
    });
    if (!r.ok) throw new Error('bom fixture invalid');
    const dir = join(tmp, 'bom');
    writeBundle(dir, compileToRego(r.policy, { policyHash: goldenHash('bom'), toolVersion: TOOL_VERSION, policyName: 'bom' }));
    const module = readFileSync(join(dir, MCP_REGO_PATH), 'utf8');
    // Nothing of the class survives raw, in a reason OR in a regex literal.
    expect(module).not.toMatch(/[\u007f-\u009f\u2028\u2029\ufeff]/);
    expect(module).toContain('\\ufeff');
    const check = spawnSync(opa, ['check', '--strict', '-b', dir], { encoding: 'utf8' });
    expect(check.status, check.stderr + check.stdout).toBe(0);
    const fmt = spawnSync(opa, ['fmt', '--fail', '--list', join(dir, 'cresec')], { encoding: 'utf8' });
    expect(fmt.status, `opa fmt would reformat:\n${fmt.stdout}${fmt.stderr}`).toBe(0);
    // OPA reads every escaped character back as itself: same reason, and the
    // regex still matches exactly the value that carries the mark.
    const ts = evaluateMcp(r.policy, { server: 's', tool: 'echo', args: { s: 'a\ufeffb' }, argsBytes: 12 });
    expect(ts).toMatchObject({ action: 'deny', ruleId: 'bom', reason });
    const got = opaEval(opa, dir, 'data.cresec.mcp.decision', { server: 's', tool: 'echo', args: { s: 'a\ufeffb' }, args_bytes: 12 });
    expect(got).toEqual(asOpa(ts));
    expect(got.reason).toBe(reason);
    expect(opaEval(opa, dir, 'data.cresec.mcp.decision', { server: 's', tool: 'echo', args: { s: 'ab' }, args_bytes: 10 })).toEqual(
      asOpa(evaluateMcp(r.policy, { server: 's', tool: 'echo', args: { s: 'ab' }, argsBytes: 10 })),
    );
  });

  it('past REGEX_VALUE_CAP the local engine REFUSES rather than answering differently from RE2', () => {
    // RE2 does not truncate and is linear, so it keeps answering for values of
    // any length; the local engine cannot match a 4 KiB+ value against a
    // backtracking regex safely, and truncating it (what it used to do) turned
    // a deny into an allow. So beyond the cap the two engines are not compared
    // decision for decision: the local one stops deciding and fails closed,
    // which is never more permissive than the Rego. Every value up to the cap
    // is compared exactly, here and in every other case of this suite.
    const r = validatePolicyObject({
      version: 1,
      name: 'cap',
      mcp: {
        default: 'allow',
        rules: [
          { id: 'no-rm', match: { tool: 'sh', args: { cmd: 'rm -rf /' } }, action: 'deny', reason: 'destructive' },
          { id: 'allow-x', match: { tool: 'x', args: { s: '^x+$' } }, action: 'allow', reason: 'harmless' },
        ],
      },
    });
    if (!r.ok) throw new Error('cap fixture invalid');
    const dir = join(tmp, 'cap');
    writeBundle(dir, compileToRego(r.policy, { policyHash: goldenHash('cap'), toolVersion: TOOL_VERSION, policyName: 'cap' }));
    const at = (n: number) => 'x'.repeat(n) + 'rm -rf /';
    // At the cap the engines agree exactly, padding and all.
    for (const value of ['rm -rf /', at(REGEX_VALUE_CAP - 8)]) {
      const ts = evaluateMcp(r.policy, { server: 's', tool: 'sh', args: { cmd: value }, argsBytes: value.length + 10 });
      expect(ts).toMatchObject({ action: 'deny', ruleId: 'no-rm', matched: true });
      expect(opaEval(opa, dir, 'data.cresec.mcp.decision', { server: 's', tool: 'sh', args: { cmd: value }, args_bytes: value.length + 10 })).toEqual(asOpa(ts));
    }
    // Past it: OPA still matches the deny rule, the local engine refuses to
    // evaluate — both refuse the call, by different routes.
    const long = at(5_000);
    const tsLong = evaluateMcp(r.policy, { server: 's', tool: 'sh', args: { cmd: long }, argsBytes: long.length + 10 });
    const opaLong = opaEval(opa, dir, 'data.cresec.mcp.decision', { server: 's', tool: 'sh', args: { cmd: long }, args_bytes: long.length + 10 });
    expect(tsLong).toMatchObject({ action: 'deny', matched: false, failClosed: true });
    expect(opaLong).toMatchObject({ action: 'deny', rule_id: 'no-rm', allow: false });
    // And where the Rego would ALLOW, the refusal is stricter, never looser:
    // an unevaluable condition denies, it is not skipped.
    const big = 'x'.repeat(5_000);
    const tsAllow = evaluateMcp(r.policy, { server: 's', tool: 'x', args: { s: big }, argsBytes: big.length + 8 });
    const opaAllow = opaEval(opa, dir, 'data.cresec.mcp.decision', { server: 's', tool: 'x', args: { s: big }, args_bytes: big.length + 8 });
    expect(opaAllow).toMatchObject({ allow: true, rule_id: 'allow-x' });
    expect(tsAllow).toMatchObject({ action: 'deny', failClosed: true });
    expect(tsAllow.action === 'allow').toBe(false);
  });

  it.each(CASES.map((c) => [c.note, c] as const))('%s', (_note, c) => {
    const policy = policies.get(c.fixture)!;
    const dir = dirs.get(c.fixture)!;
    // A poisoned pattern would make the TS engine deny for a reason that has
    // nothing to do with the Rego, so a mismatch below would be a mystery.
    expect(regexGuardState().poisoned, 'a regex was poisoned: this is a guard timeout, not a parity gap').toBe(0);
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

/* ------------- the parity gate cannot be silently switched off ------------
 * B4/B5. The suites above skip themselves when no `opa` binary is found,
 * which is right locally and wrong in CI: a broken setup-opa step would turn
 * the TypeScript-vs-Rego parity check off without failing anything.
 */

interface CiWorkflow {
  jobs: Record<
    string,
    {
      'runs-on'?: string;
      env?: Record<string, string>;
      steps?: { name?: string; uses?: string; with?: Record<string, string> }[];
    }
  >;
}

describe('CI cannot silently skip the OPA parity gate (B4, B5)', () => {
  const CI_YML = fileURLToPath(new URL('../.github/workflows/ci.yml', import.meta.url));
  const ci = parseYaml(readFileSync(CI_YML, 'utf8')) as CiWorkflow;

  it('opaOrFail throws the CI message when the binary is required and missing, and skips otherwise', () => {
    expect(OPA_REQUIRED_MESSAGE).toBe('opa required by CI (MCP_RECORDER_REQUIRE_OPA=1) but not found');
    expect(() => opaOrFail(undefined, true)).toThrow(OPA_REQUIRED_MESSAGE);
    // Not required: the local skip is preserved, exactly as before.
    expect(opaOrFail(undefined, false)).toBeUndefined();
    // A binary that WAS found is returned untouched, required or not.
    expect(opaOrFail('/usr/bin/opa', true)).toBe('/usr/bin/opa');
    expect(opaOrFail('/usr/bin/opa', false)).toBe('/usr/bin/opa');
    // Only a literal '1' arms the gate; nothing else does.
    expect(opaRequired('1')).toBe(true);
    for (const v of [undefined, '', '0', 'true', 'yes', '11']) expect(opaRequired(v)).toBe(false);
  });

  it('the Linux test job sets MCP_RECORDER_REQUIRE_OPA=1 and the Windows job does not', () => {
    expect(ci.jobs['test']?.env?.['MCP_RECORDER_REQUIRE_OPA']).toBe('1');
    expect(ci.jobs['test']?.['runs-on']).toBe('ubuntu-latest');
    // Windows installs no OPA, so requiring it there would fail every build.
    expect(ci.jobs['test-windows']?.env?.['MCP_RECORDER_REQUIRE_OPA']).toBeUndefined();
    const winSteps = ci.jobs['test-windows']?.steps ?? [];
    expect(winSteps.some((s) => (s.uses ?? '').startsWith('open-policy-agent/setup-opa'))).toBe(false);
  });

  it('every suite that looks for an `opa` binary honours the flag (no new silent skip)', () => {
    const testDir = fileURLToPath(new URL('.', import.meta.url));
    const usesOpa = readdirSync(testDir)
      .filter((f) => f.endsWith('.test.ts'))
      .filter((f) => readFileSync(join(testDir, f), 'utf8').includes('function findOpa('));
    expect(usesOpa.sort()).toEqual(['gateway-cli.test.ts', 'policy-rego.test.ts']);
    for (const f of usesOpa) {
      const text = readFileSync(join(testDir, f), 'utf8');
      expect(text, `${f} self-skips without honouring MCP_RECORDER_REQUIRE_OPA`).toContain('MCP_RECORDER_REQUIRE_OPA');
      expect(text, `${f} must use the exact CI message`).toContain(OPA_REQUIRED_MESSAGE);
    }
  });

  it('setup-opa is pinned to an exact version, never `latest`', () => {
    const step = (ci.jobs['test']?.steps ?? []).find((s) => (s.uses ?? '').startsWith('open-policy-agent/setup-opa'));
    expect(step, 'the Linux test job must install OPA').toBeDefined();
    const version = step!.with?.['version'];
    // `opa fmt --fail` is asserted against the emitted Rego above, so an
    // unpinned OPA would break main on a formatter change with no code change.
    expect(version).toBeDefined();
    expect(version).not.toBe('latest');
    expect(version).toMatch(/^\d+\.\d+\.\d+$/);
  });
});
