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
 *   regex.match(glob-as-regex, input.server)         server / tool / path
 *   regex.match(glob-as-regex, input.host)           host
 *   some p in [...]; regex.match(p, ...)             lists with more than one glob
 *   v0 := input.args.a[0].c;
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
import { globToRegExpSource, type GlobDelimiter } from './glob.js';
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

/**
 * Characters `JSON.stringify` leaves raw that a Rego module cannot carry as
 * themselves. U+FEFF is the one that bites: a byte-order mark pasted in from
 * a document ends the string token for OPA's lexer, so the bundle compiles
 * with exit 0 and then fails to load with `rego_parse_error: non-terminated
 * object`. The rest of the class is the invisible company it keeps — DEL, the
 * C1 controls and the two Unicode line separators. All of them round-trip
 * through OPA as `\uXXXX` (pinned by the parity suite), so they are escaped
 * rather than rejected and existing policies keep working.
 *
 * An unpaired surrogate is NOT in this class: Go cannot represent one at all
 * (OPA reads `"\ud800"` back as U+FFFD), so `validate.ts` rejects it instead.
 */
const REGO_UNSAFE_TEXT = /[\u007f-\u009f\u2028\u2029\ufeff]/g;

const q = (s: string): string =>
  JSON.stringify(s).replace(REGO_UNSAFE_TEXT, (ch) => `\\u${ch.charCodeAt(0).toString(16).padStart(4, '0')}`);
const qList = (xs: readonly string[]): string => `[${xs.map(q).join(', ')}]`;

/**
 * What RE2 must be given so that `.` means what the local engine means by it.
 *
 * JavaScript's `.` (no `s` flag) excludes \n \r U+2028 U+2029; RE2's excludes
 * \n only. Unaligned, `^.*secret.*$` against "my\rsecret" is an ALLOW here
 * and a DENY in OPA — verified against OPA 1.20.2 — and the same split shows
 * up for `^rm -rf .+$` and `^/etc/.+$`. Rewriting each unescaped `.` outside
 * a character class into the explicit negated class closes it, and leaves
 * every other part of the pattern exactly as the author wrote it. (The other
 * half of the divergence, counting UTF-16 units instead of runes, is closed
 * on the JavaScript side by matching with the `u` flag: see
 * `toUnicodeSource`.)
 */
const RE2_DOT = '[^\\n\\r\\x{2028}\\x{2029}]';

/** The same regex, spelled so RE2 reads `.` exactly as the local engine does. */
export function toRe2Source(pattern: string): string {
  let out = '';
  let inClass = false;
  for (let i = 0; i < pattern.length; i++) {
    const ch = pattern[i] as string;
    if (ch === '\\') {
      out += pattern.slice(i, i + 2); // an escape is a literal in both engines
      i++;
      continue;
    }
    if (inClass) {
      if (ch === ']') inClass = false;
      out += ch; // `.` inside a class is already a literal dot
      continue;
    }
    if (ch === '[') {
      inClass = true;
      out += ch;
      continue;
    }
    out += ch === '.' ? RE2_DOT : ch;
  }
  return out;
}

/**
 * The args lookup for one dot-path, as a chain of references:
 * `input.args["filters"][0]["field"]`.
 *
 * NOT `object.get(input.args, [...], null)`, which is what this emitted
 * until the parity suite was run with `--strict-builtin-errors`: `object.get`
 * raises `operand 1 must be object but got array` when `input.args` is an
 * array or a scalar, and an erroring builtin is `undefined`, so the rule
 * silently leaves the decision. A reference chain is TOTAL — a missing key,
 * a wrong-typed container and a scalar root are all simply undefined, which
 * is what the TS engine does — and it keeps the distinction between the
 * numeric segment `0` (an array index) and the string key `"0"`, which both
 * engines make.
 *
 * A key that is a plain identifier is emitted in dot form, because that is
 * what `opa fmt` rewrites it to and the bundle has to survive
 * `opa fmt --fail`. Rego keywords stay in bracket form, where dot form would
 * not parse.
 */
const REGO_IDENT = /^[A-Za-z_][A-Za-z0-9_]*$/;

/** Rego v1 keywords: `input.args.if` does not parse, `input.args["if"]` does. */
const REGO_KEYWORDS: ReadonlySet<string> = new Set([
  'as', 'contains', 'default', 'else', 'every', 'false', 'if', 'import',
  'in', 'not', 'null', 'package', 'some', 'true', 'with',
]);

function argsRef(dotPath: string): string {
  return dotPathSegments(dotPath)
    .map((s) => {
      if (typeof s === 'number') return `[${String(s)}]`;
      return REGO_IDENT.test(s) && !REGO_KEYWORDS.has(s) ? `.${s}` : `[${q(s)}]`;
    })
    .join('');
}

/**
 * Match line(s) for one glob field: a single glob inline, a list via `some`.
 *
 * The glob is emitted as the REGEX `glob.ts` compiles it to, not as a glob
 * to `glob.match`. OPA's glob library and this one do not read the same
 * pattern the same way, and the differences decide calls:
 *
 *   - `A**B` is `HasPrefix(A) && HasSuffix(B)` there, with no requirement
 *     that the two not overlap, so a tool glob of `danger/`, a crossing
 *     wildcard and `/run` matches the tool `danger/run` (verified against
 *     OPA 1.20.2). Here a crossing wildcard is a run of its own, so it does
 *     not. A `deny` rule was therefore blocked in the control plane and
 *     allowed by the local gateway.
 *   - An odd run of three or more `*` means "at least one character" there
 *     (`sh***` does not match `sh`) and the same as `**` here, which is what
 *     `globToRegExpSource` collapses it to.
 *   - U+FFFD makes `glob.match` raise `could not read rune` and U+0000
 *     returns a flat false, and an erroring builtin is `undefined`, which
 *     drops the whole rule from the decision silently.
 *
 * `regex.match` removes the class: both engines evaluate one translation,
 * emitted by the same function the gateway compiles, over a subset (`[\s\S]*`,
 * `[^<delim>]*`, escaped literals, `^`/`$`) that RE2 and V8 agree on.
 * `docs/policy.md` documents the `**` semantics this keeps.
 */
function globLines(globs: readonly string[], delimiter: GlobDelimiter, subject: string, varName: string): string[] {
  const sources = globs.map((g) => globToRegExpSource(g, delimiter));
  const first = sources[0] as string;
  if (sources.length === 1) return [`regex.match(${q(first)}, ${subject})`];
  return [`some ${varName} in ${qList(sources)}`, `regex.match(${varName}, ${subject})`];
}

function mcpRuleBody(rule: McpRule): string[] {
  const m = rule.match;
  const lines: string[] = [];
  lines.push(...globLines(m.server, '/', 'input.server', 's'));
  lines.push(...globLines(m.tool, '/', 'input.tool', 'p'));
  if (m.args !== undefined) {
    // The ROOT must be a plain object, like `getPath` in the TS engine: an
    // array or scalar `params.arguments` is malformed per MCP and matches no
    // args condition in either engine. This used to be implicit in
    // `object.get`, which ERRORS on a non-object root — and an erroring
    // builtin is undefined, so the agreement rested on a silent failure.
    // Stated as a condition, it is the same answer for the same reason.
    lines.push('is_object(input.args)');
    Object.entries(m.args).forEach(([dotPath, pattern], n) => {
      const v = `v${n}`;
      lines.push(`${v} := input.args${argsRef(dotPath)}`);
      lines.push(`type_name(${v}) in {"string", "number", "boolean"}`);
      lines.push(`regex.match(${q(toRe2Source(pattern))}, scalar_text(${v}))`);
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
