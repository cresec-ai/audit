/**
 * Compile a normalized policy into an OPA bundle directory laid out like the
 * Cresec control plane (sibling packages to `cresec.broker`, one `decision`
 * object rule each; distinct basenames because the Helm ConfigMap flattens
 * by basename):
 *
 *   .manifest                {"revision": "<policy sha256 hex>", "roots": ["cresec/mcp", "cresec/egress"]}
 *   cresec/mcp/tool.rego     package cresec.mcp     (always)
 *   cresec/egress/http.rego  package cresec.egress  (only when `egress` is present; then and only then
 *                                                    "cresec/egress" is listed in the manifest roots)
 *
 * Output is deterministic (same policy + options => identical bytes), uses
 * tabs like `opa fmt`, `import rego.v1`, and emits every string literal via
 * JSON.stringify (Rego string syntax accepts JSON escapes). Each rule body
 * mirrors `engine.ts` predicate for predicate:
 *
 *   glob.match(pattern, ["/"], input.server)         server / tool / path
 *   glob.match(pattern, ["."], input.host)           host
 *   some p in [...]; glob.match(p, ...)              lists with more than one glob
 *   v0 := object.get(input.args, ["a", 0, "c"], null); v0 != null;
 *   type_name(v0) in {"string", "number", "boolean"}; regex.match(re, scalar_text(v0))
 *   input.args_bytes <= N / input.body_bytes <= N
 *   input.method in ["GET", "HEAD"]
 *
 * `rule_matches` is the set of matching rule indexes and `first_match` its
 * minimum, so "first match wins" is expressed by index, exactly like the TS
 * engine. `rules[i].reason` is always present ("" when unset) so `decision`
 * is never undefined.
 *
 * The `decision` object is a superset of the broker's, so a consumer that
 * only knows `allow` / `deny_reason` (and fails closed on a missing `allow`)
 * can evaluate `data.cresec.mcp.decision` or `data.cresec.egress.decision`
 * unchanged:
 *
 *   {"allow": <action == "allow">, "action": "allow"|"hold"|"deny", "rule_id": "...",
 *    "reason": "...", "matched": bool, "deny_reason": "..."}
 *
 * `deny_reason` is "" when the action is allow; otherwise "rule <id>: <reason>"
 * ("rule <id>" when the rule has no reason) for a matched rule and
 * "default <action>" when no rule matched and the section default applies.
 */

import { dotPathSegments } from './engine.js';
import type { EgressRule, McpRule, Policy } from './types.js';

export interface CompileOptions {
  /** `sha256:<hex>` (or bare 64-hex) of the policy file bytes; becomes the bundle revision. */
  policyHash: string;
  policyName?: string;
  toolVersion: string;
}

export interface RegoBundle {
  /** Published path (relative, "/"-separated) -> file contents. */
  files: Record<string, string>;
}

export const MANIFEST_PATH = '.manifest';
export const MCP_REGO_PATH = 'cresec/mcp/tool.rego';
export const EGRESS_REGO_PATH = 'cresec/egress/http.rego';
/** Manifest root of the MCP module (always present). */
export const MCP_ROOT = 'cresec/mcp';
/** Manifest root of the egress module (listed only when `cresec/egress/http.rego` is emitted). */
export const EGRESS_ROOT = 'cresec/egress';

/** The `.manifest` roots for a policy: `["cresec/mcp"]`, plus `"cresec/egress"` when it has an egress section. */
export function bundleRoots(policy: Policy): string[] {
  return policy.egress === undefined ? [MCP_ROOT] : [MCP_ROOT, EGRESS_ROOT];
}

/** Canonical write order for bundle files. */
export const BUNDLE_FILE_ORDER: readonly string[] = [MANIFEST_PATH, MCP_REGO_PATH, EGRESS_REGO_PATH];

/** The bundle's file paths in canonical order (known files first, then any others sorted). */
export function bundleFileOrder(files: Record<string, string>): string[] {
  const known = BUNDLE_FILE_ORDER.filter((p) => Object.prototype.hasOwnProperty.call(files, p));
  const rest = Object.keys(files)
    .filter((p) => !BUNDLE_FILE_ORDER.includes(p))
    .sort();
  return [...known, ...rest];
}

const HEX64 = /^[0-9a-f]{64}$/;

/** Strip an optional `sha256:` prefix and require 64 lowercase hex. */
export function policyRevision(policyHash: string): string {
  const hex = policyHash.startsWith('sha256:') ? policyHash.slice('sha256:'.length) : policyHash;
  if (!HEX64.test(hex)) {
    throw new TypeError(`policyHash must be "sha256:<64 lowercase hex>", got ${JSON.stringify(policyHash)}`);
  }
  return hex;
}

const q = (s: string): string => JSON.stringify(s);
const qList = (xs: readonly string[]): string => `[${xs.map(q).join(', ')}]`;

function segmentsLiteral(dotPath: string): string {
  return `[${dotPathSegments(dotPath)
    .map((s) => (typeof s === 'number' ? String(s) : q(s)))
    .join(', ')}]`;
}

/** `glob.match` line(s) for one field: a single glob inline, a list via `some`. */
function globLines(globs: readonly string[], delimiter: '/' | '.', subject: string, varName: string): string[] {
  const first = globs[0] as string;
  if (globs.length === 1) return [`glob.match(${q(first)}, [${q(delimiter)}], ${subject})`];
  return [`some ${varName} in ${qList(globs)}`, `glob.match(${varName}, [${q(delimiter)}], ${subject})`];
}

function mcpRuleBody(rule: McpRule): string[] {
  const m = rule.match;
  const lines: string[] = [];
  lines.push(...globLines(m.server, '/', 'input.server', 's'));
  lines.push(...globLines(m.tool, '/', 'input.tool', 'p'));
  if (m.args !== undefined) {
    Object.entries(m.args).forEach(([dotPath, pattern], n) => {
      const v = `v${n}`;
      lines.push(`${v} := object.get(input.args, ${segmentsLiteral(dotPath)}, null)`);
      lines.push(`${v} != null`);
      lines.push(`type_name(${v}) in {"string", "number", "boolean"}`);
      lines.push(`regex.match(${q(pattern)}, scalar_text(${v}))`);
    });
  }
  if (m.max_args_bytes !== undefined) lines.push(`input.args_bytes <= ${m.max_args_bytes}`);
  return lines;
}

function egressRuleBody(rule: EgressRule): string[] {
  const m = rule.match;
  const lines: string[] = [];
  lines.push(...globLines(m.host, '.', 'input.host', 'h'));
  if (m.methods !== undefined) lines.push(`input.method in ${qList(m.methods)}`);
  lines.push(...globLines(m.path, '/', 'input.path', 'p'));
  if (m.max_body_bytes !== undefined) lines.push(`input.body_bytes <= ${m.max_body_bytes}`);
  return lines;
}

/** The documented decision shape (comment in every module header). */
export const DECISION_SHAPE =
  '{"allow": bool, "action": "allow"|"hold"|"deny", "rule_id": "...", "reason": "...", "matched": bool, "deny_reason": "..."}';

/**
 * The module tail shared by both packages: `deny_reason(rule)` and the two
 * `decision` heads (matched rule / section default). Identical in every
 * module so the broker-style consumer sees one shape; formatted exactly like
 * `opa fmt` (tabs, one blank line between rules).
 */
const DECISION_RULES: readonly string[] = [
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
];

/**
 * The scalar -> text helper used by every `args` regex.
 *
 * Strings are matched as they are; numbers and booleans go through
 * `json.marshal`, whose output for a JSON scalar is byte-for-byte what
 * JavaScript's `String()` / `JSON.stringify()` produce (Go's `encoding/json`
 * formats float64 with the same ES6 shortest-round-trip rules, and booleans
 * as "true"/"false"). `sprintf("%v", [v])` must NOT be used here: Go's `%v`
 * prints 1234567.5 as "1.2345675e+06" and 0.00001 as "1e-05", which would
 * make the emitted Rego disagree with the TypeScript engine.
 */
const SCALAR_TEXT_RULES: readonly string[] = [
  '# The exact text the TypeScript engine matches on: strings as-is, numbers and',
  '# booleans through json.marshal (Go formats them exactly like JavaScript String()).',
  'scalar_text(v) := v if is_string(v)',
  '',
  'scalar_text(v) := json.marshal(v) if not is_string(v)',
];

interface ModuleSpec<R extends { id: string; action: string; reason?: string }> {
  pkg: string;
  inputShape: string;
  defaultAction: string;
  rules: readonly R[];
  body: (rule: R) => string[];
  /** Extra rules emitted after the rule bodies (only when the module needs them). */
  helpers?: readonly string[];
}

function renderModule<R extends { id: string; action: string; reason?: string }>(
  spec: ModuleSpec<R>,
  opts: CompileOptions,
): string {
  const revision = policyRevision(opts.policyHash);
  const name = opts.policyName ?? '';
  const out: string[] = [];
  out.push(`package ${spec.pkg}`, '', 'import rego.v1', '');
  out.push(`# Generated by mcp-recorder ${opts.toolVersion} from policy ${q(name)} (sha256:${revision}). Do not edit.`);
  out.push(`# Input:    ${spec.inputShape}`);
  out.push(`# Decision: ${DECISION_SHAPE}`);
  out.push('');
  out.push(`default_action := ${q(spec.defaultAction)}`, '');
  if (spec.rules.length === 0) {
    out.push('rules := []', '');
    out.push('# No rules: nothing ever matches.', 'rule_matches := set()', '');
  } else {
    out.push('rules := [');
    for (const r of spec.rules) {
      out.push(`\t{"id": ${q(r.id)}, "action": ${q(r.action)}, "reason": ${q(r.reason ?? '')}},`);
    }
    out.push(']', '');
    spec.rules.forEach((r, i) => {
      out.push(`# ${r.id}`);
      out.push(`rule_matches contains ${i} if {`);
      for (const line of spec.body(r)) out.push(`\t${line}`);
      out.push('}', '');
    });
  }
  if (spec.helpers !== undefined && spec.helpers.length > 0) out.push(...spec.helpers, '');
  out.push('first_match := min(rule_matches) if count(rule_matches) > 0', '');
  out.push(...DECISION_RULES);
  return out.join('\n') + '\n';
}

/** Render `cresec/mcp/tool.rego`. A policy without `mcp` compiles to the documented default (allow, no rules). */
export function renderMcpModule(policy: Policy, opts: CompileOptions): string {
  const rules = policy.mcp?.rules ?? [];
  return renderModule<McpRule>(
    {
      pkg: 'cresec.mcp',
      inputShape: '{"server": "...", "tool": "...", "args": {...}, "args_bytes": 123}',
      defaultAction: policy.mcp?.default ?? 'allow',
      rules,
      body: mcpRuleBody,
      // Only emitted when something actually calls it, so a policy without
      // `args` conditions compiles to exactly the same module as before.
      ...(rules.some((r) => r.match.args !== undefined) ? { helpers: SCALAR_TEXT_RULES } : {}),
    },
    opts,
  );
}

/** Render `cresec/egress/http.rego`; throws when the policy has no `egress` section. */
export function renderEgressModule(policy: Policy, opts: CompileOptions): string {
  const egress = policy.egress;
  if (egress === undefined) throw new TypeError('policy has no egress section');
  return renderModule<EgressRule>(
    {
      pkg: 'cresec.egress',
      inputShape: '{"host": "...", "method": "GET", "path": "/...", "body_bytes": 123}',
      defaultAction: egress.default,
      rules: egress.rules,
      body: egressRuleBody,
    },
    opts,
  );
}

/** Compile a normalized policy into an OPA bundle (in-memory file map). */
export function compileToRego(policy: Policy, opts: CompileOptions): RegoBundle {
  const revision = policyRevision(opts.policyHash);
  const files: Record<string, string> = {};
  files[MANIFEST_PATH] = JSON.stringify({ revision, roots: bundleRoots(policy) }) + '\n';
  files[MCP_REGO_PATH] = renderMcpModule(policy, opts);
  if (policy.egress !== undefined) files[EGRESS_REGO_PATH] = renderEgressModule(policy, opts);
  return { files };
}
