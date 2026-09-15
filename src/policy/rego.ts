/**
 * Compile a normalized policy into an OPA bundle directory (nhi style):
 *
 *   .manifest                    {"revision": "<policy sha256 hex>", "roots": ["cresec/gateway"]}
 *   cresec/gateway/mcp.rego      package cresec.gateway.mcp     (always)
 *   cresec/gateway/egress.rego   package cresec.gateway.egress  (only when `egress` is present)
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
 *   type_name(v0) in {"string", "number", "boolean"}; regex.match(re, sprintf("%v", [v0]))
 *   input.args_bytes <= N / input.body_bytes <= N
 *   input.method in ["GET", "HEAD"]
 *
 * `rule_matches` is the set of matching rule indexes and `first_match` its
 * minimum, so "first match wins" is expressed by index, exactly like the TS
 * engine. `rules[i].reason` is always present ("" when unset) so `decision`
 * is never undefined.
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
export const MCP_REGO_PATH = 'cresec/gateway/mcp.rego';
export const EGRESS_REGO_PATH = 'cresec/gateway/egress.rego';
export const BUNDLE_ROOTS: readonly string[] = ['cresec/gateway'];

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
  lines.push(...globLines([m.server], '/', 'input.server', 's'));
  lines.push(...globLines(m.tool, '/', 'input.tool', 'p'));
  if (m.args !== undefined) {
    Object.entries(m.args).forEach(([dotPath, pattern], n) => {
      const v = `v${n}`;
      lines.push(`${v} := object.get(input.args, ${segmentsLiteral(dotPath)}, null)`);
      lines.push(`${v} != null`);
      lines.push(`type_name(${v}) in {"string", "number", "boolean"}`);
      lines.push(`regex.match(${q(pattern)}, sprintf("%v", [${v}]))`);
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

interface ModuleSpec<R extends { id: string; action: string; reason?: string }> {
  pkg: string;
  inputShape: string;
  defaultAction: string;
  rules: readonly R[];
  body: (rule: R) => string[];
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
  out.push('# Decision: {"action": "allow"|"hold"|"deny", "rule_id": "...", "reason": "...", "matched": bool}');
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
  out.push('first_match := min(rule_matches) if count(rule_matches) > 0', '');
  out.push(
    'decision := {"action": rules[first_match].action, "rule_id": rules[first_match].id, "reason": rules[first_match].reason, "matched": true} if count(rule_matches) > 0',
    '',
  );
  out.push('decision := {"action": default_action, "rule_id": "", "reason": "", "matched": false} if count(rule_matches) == 0');
  return out.join('\n') + '\n';
}

/** Render `cresec/gateway/mcp.rego`. A policy without `mcp` compiles to the documented default (allow, no rules). */
export function renderMcpModule(policy: Policy, opts: CompileOptions): string {
  return renderModule<McpRule>(
    {
      pkg: 'cresec.gateway.mcp',
      inputShape: '{"server": "...", "tool": "...", "args": {...}, "args_bytes": 123}',
      defaultAction: policy.mcp?.default ?? 'allow',
      rules: policy.mcp?.rules ?? [],
      body: mcpRuleBody,
    },
    opts,
  );
}

/** Render `cresec/gateway/egress.rego`; throws when the policy has no `egress` section. */
export function renderEgressModule(policy: Policy, opts: CompileOptions): string {
  const egress = policy.egress;
  if (egress === undefined) throw new TypeError('policy has no egress section');
  return renderModule<EgressRule>(
    {
      pkg: 'cresec.gateway.egress',
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
  files[MANIFEST_PATH] = JSON.stringify({ revision, roots: [...BUNDLE_ROOTS] }) + '\n';
  files[MCP_REGO_PATH] = renderMcpModule(policy, opts);
  if (policy.egress !== undefined) files[EGRESS_REGO_PATH] = renderEgressModule(policy, opts);
  return { files };
}
