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
/** A glob or a non-empty list of globs, as written in the file. */
export type GlobOrList = string | string[];
export interface McpMatchInput {
    server?: string;
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
export interface McpMatch {
    /** Glob on the logical server name, delimiter "/". Default "*". */
    server: string;
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
export declare const DEFAULTS: {
    readonly mcp: {
        readonly default: Action;
    };
    readonly hold: {
        readonly timeout_ms: 60000;
        readonly on_timeout: OnTimeout;
    };
    readonly boundary: {
        readonly secrets: BoundaryMode;
        readonly injection: BoundaryMode;
        readonly max_scan_bytes: 1048576;
        readonly on_oversize: OnOversize;
    };
    readonly egress: {
        readonly default: Action;
    };
    readonly match: {
        readonly server: "*";
        readonly path: "/**";
    };
};
/** Range limits enforced by the JSON Schema (`minimum` / `maximum`). */
export declare const LIMITS: {
    readonly hold_timeout_ms: {
        readonly min: 1000;
        readonly max: 3600000;
    };
    readonly max_scan_bytes: {
        readonly min: 4096;
        readonly max: number;
    };
};
/** Identifier pattern shared by `name` and rule `id`. */
export declare const ID_PATTERN = "^[A-Za-z0-9_.:/-]{1,64}$";
/** Values longer than this (UTF-16 units) are truncated before regex matching. */
export declare const REGEX_VALUE_CAP = 65536;
/** Auto-assigned id for a rule without one; brackets keep it outside ID_PATTERN so it can never collide. */
export declare function autoRuleId(index: number): string;
/**
 * Fill defaults, coerce single globs to lists and assign missing rule ids.
 * Assumes `raw` already passed schema validation (see `validatePolicyObject`).
 * Pure: never mutates its input.
 */
export declare function normalizePolicy(raw: PolicyInput): Policy;
