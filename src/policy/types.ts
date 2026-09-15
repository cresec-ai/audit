/**
 * policy.yaml v1 — TypeScript types and defaults.
 *
 * Two families of types live here:
 *
 * - `*Input` types describe the document as an author writes it (after JSON
 *   Schema validation, see `validate.ts`): optional fields may be absent and
 *   `tool` / `host` / `path` may be a single glob or a list.
 * - The plain types (`Policy`, `McpRule`, ...) describe the NORMALIZED form
 *   produced by `normalizePolicy()`: every default is filled in, single globs
 *   are coerced to one-element arrays and every rule carries an id. The
 *   engine (`engine.ts`) and the Rego compiler (`rego.ts`) consume only the
 *   normalized form, so they never have to think about defaults.
 *
 * Invariants: normalized policies are JSON-plain (no RegExp, no functions,
 * no class instances) so they can be logged, hashed and round-tripped
 * through JSON without surprises. Nothing here pre-compiles globs or
 * regexes — that is the engine's job, with its own bounded caches.
 */

export type Action = 'allow' | 'hold' | 'deny';
export type OnTimeout = 'deny' | 'allow';
export type BoundaryMode = 'redact' | 'block' | 'flag' | 'off';
export type OnOversize = 'flag' | 'block';

/* ---------------------------- input (authored) ---------------------------- */

/** A glob or a non-empty list of globs, as written in the file. */
export type GlobOrList = string | string[];

export interface McpMatchInput {
  server?: GlobOrList;
  tool: GlobOrList;
  args?: Record<string, string>;
  max_args_bytes?: number;
}

export interface McpRuleInput {
  id?: string;
  match: McpMatchInput;
  action: Action;
  reason?: string;
}

export interface HoldConfigInput {
  timeout_ms?: number;
  on_timeout?: OnTimeout;
}

export interface BoundaryConfigInput {
  secrets?: BoundaryMode;
  injection?: BoundaryMode;
  max_scan_bytes?: number;
  on_oversize?: OnOversize;
}

export interface McpPolicyInput {
  default?: Action;
  rules?: McpRuleInput[];
  hold?: HoldConfigInput;
  boundary?: BoundaryConfigInput;
}

export interface EgressMatchInput {
  host: GlobOrList;
  methods?: string[];
  path?: GlobOrList;
  max_body_bytes?: number;
}

export interface EgressRuleInput {
  id?: string;
  match: EgressMatchInput;
  action: Action;
  reason?: string;
}

export interface EgressPolicyInput {
  default?: Action;
  rules?: EgressRuleInput[];
}

/** The document shape accepted by the JSON Schema (`docs/policy-schema.json`). */
export interface PolicyInput {
  version: 1;
  name?: string;
  mcp?: McpPolicyInput;
  egress?: EgressPolicyInput;
}

/* ------------------------------- normalized ------------------------------- */

export interface McpMatch {
  /** Globs on the logical server name, delimiter "/". Any one matching is enough. Default ["*"]. */
  server: string[];
  /** Globs on the tool name, delimiter "/". Any one matching is enough. */
  tool: string[];
  /** Dot-path -> RE2-compatible regex. All entries must match. */
  args?: Record<string, string>;
  /** Rule only matches when canonical JSON of args is <= this many bytes. */
  max_args_bytes?: number;
}

export interface McpRule {
  /** Explicit id, or `rule[<index>]` when the author gave none. */
  id: string;
  match: McpMatch;
  action: Action;
  reason?: string;
}

export interface HoldConfig {
  timeout_ms: number;
  on_timeout: OnTimeout;
}

export interface BoundaryConfig {
  secrets: BoundaryMode;
  injection: BoundaryMode;
  max_scan_bytes: number;
  on_oversize: OnOversize;
}

export interface McpPolicy {
  default: Action;
  rules: McpRule[];
  hold: HoldConfig;
  boundary: BoundaryConfig;
}

export interface EgressMatch {
  /** Globs on the host, delimiter ".". Any one matching is enough. */
  host: string[];
  /** Upper-case HTTP methods; absent = any method. */
  methods?: string[];
  /** Globs on the URL path, delimiter "/". Default ["/**"]. */
  path: string[];
  max_body_bytes?: number;
}

export interface EgressRule {
  id: string;
  match: EgressMatch;
  action: Action;
  reason?: string;
}

export interface EgressPolicy {
  default: Action;
  rules: EgressRule[];
}

export interface Policy {
  version: 1;
  name?: string;
  mcp?: McpPolicy;
  egress?: EgressPolicy;
}

/* -------------------------------- defaults -------------------------------- */

export const DEFAULTS = {
  mcp: { default: 'allow' as Action },
  hold: { timeout_ms: 60_000, on_timeout: 'deny' as OnTimeout },
  boundary: {
    secrets: 'redact' as BoundaryMode,
    injection: 'flag' as BoundaryMode,
    max_scan_bytes: 1_048_576,
    on_oversize: 'flag' as OnOversize,
  },
  egress: { default: 'deny' as Action },
  match: { server: '*', path: '/**' },
} as const;

/** Range limits enforced by the JSON Schema (`minimum` / `maximum`). */
export const LIMITS = {
  hold_timeout_ms: { min: 1_000, max: 3_600_000 },
  max_scan_bytes: { min: 4_096, max: 64 * 1024 * 1024 },
} as const;

/** Identifier pattern shared by `name` and rule `id`. */
export const ID_PATTERN = '^[A-Za-z0-9_.:/-]{1,64}$';

/**
 * Values longer than this (UTF-16 units) are truncated before regex matching.
 *
 * 4 KiB, not the 64 KiB of earlier drafts: the local engine matches with V8's
 * BACKTRACKING RegExp, whose worst case grows with the subject length, so the
 * cap is also the bound on how much work one hostile argument can ask for.
 * The Rego side matches with RE2 (linear time) and does not truncate at all,
 * so only values longer than the cap can ever make the two engines disagree —
 * documented in `docs/policy.md`.
 */
export const REGEX_VALUE_CAP = 4_096;

/* ------------------------------- normalize -------------------------------- */

function toList(v: GlobOrList): string[] {
  return typeof v === 'string' ? [v] : [...v];
}

/** Auto-assigned id for a rule without one; brackets keep it outside ID_PATTERN so it can never collide. */
export function autoRuleId(index: number): string {
  return `rule[${index}]`;
}

function normalizeMcpRule(rule: McpRuleInput, index: number): McpRule {
  const match: McpMatch = {
    server: toList(rule.match.server ?? DEFAULTS.match.server),
    tool: toList(rule.match.tool),
  };
  if (rule.match.args !== undefined) match.args = { ...rule.match.args };
  if (rule.match.max_args_bytes !== undefined) match.max_args_bytes = rule.match.max_args_bytes;
  const out: McpRule = { id: rule.id ?? autoRuleId(index), match, action: rule.action };
  if (rule.reason !== undefined) out.reason = rule.reason;
  return out;
}

function normalizeEgressRule(rule: EgressRuleInput, index: number): EgressRule {
  const match: EgressMatch = {
    host: toList(rule.match.host),
    path: toList(rule.match.path ?? DEFAULTS.match.path),
  };
  if (rule.match.methods !== undefined) match.methods = [...rule.match.methods];
  if (rule.match.max_body_bytes !== undefined) match.max_body_bytes = rule.match.max_body_bytes;
  const out: EgressRule = { id: rule.id ?? autoRuleId(index), match, action: rule.action };
  if (rule.reason !== undefined) out.reason = rule.reason;
  return out;
}

/**
 * Fill defaults, coerce single globs to lists and assign missing rule ids.
 * Assumes `raw` already passed schema validation (see `validatePolicyObject`).
 * Pure: never mutates its input.
 */
export function normalizePolicy(raw: PolicyInput): Policy {
  const policy: Policy = { version: 1 };
  if (raw.name !== undefined) policy.name = raw.name;
  if (raw.mcp !== undefined) {
    const m = raw.mcp;
    policy.mcp = {
      default: m.default ?? DEFAULTS.mcp.default,
      rules: (m.rules ?? []).map(normalizeMcpRule),
      hold: {
        timeout_ms: m.hold?.timeout_ms ?? DEFAULTS.hold.timeout_ms,
        on_timeout: m.hold?.on_timeout ?? DEFAULTS.hold.on_timeout,
      },
      boundary: {
        secrets: m.boundary?.secrets ?? DEFAULTS.boundary.secrets,
        injection: m.boundary?.injection ?? DEFAULTS.boundary.injection,
        max_scan_bytes: m.boundary?.max_scan_bytes ?? DEFAULTS.boundary.max_scan_bytes,
        on_oversize: m.boundary?.on_oversize ?? DEFAULTS.boundary.on_oversize,
      },
    };
  }
  if (raw.egress !== undefined) {
    const e = raw.egress;
    policy.egress = {
      default: e.default ?? DEFAULTS.egress.default,
      rules: (e.rules ?? []).map(normalizeEgressRule),
    };
  }
  return policy;
}
