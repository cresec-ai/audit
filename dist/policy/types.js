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
/* -------------------------------- defaults -------------------------------- */
export const DEFAULTS = {
    mcp: { default: 'allow' },
    hold: { timeout_ms: 60_000, on_timeout: 'deny' },
    boundary: {
        secrets: 'redact',
        injection: 'flag',
        max_scan_bytes: 1_048_576,
        on_oversize: 'flag',
    },
    egress: { default: 'deny' },
    match: { server: '*', path: '/**' },
};
/** Range limits enforced by the JSON Schema (`minimum` / `maximum`). */
export const LIMITS = {
    hold_timeout_ms: { min: 1_000, max: 3_600_000 },
    max_scan_bytes: { min: 4_096, max: 64 * 1024 * 1024 },
};
/** Identifier pattern shared by `name` and rule `id`. */
export const ID_PATTERN = '^[A-Za-z0-9_.:/-]{1,64}$';
/** Values longer than this (UTF-16 units) are truncated before regex matching. */
export const REGEX_VALUE_CAP = 65_536;
/* ------------------------------- normalize -------------------------------- */
function toList(v) {
    return typeof v === 'string' ? [v] : [...v];
}
/** Auto-assigned id for a rule without one; brackets keep it outside ID_PATTERN so it can never collide. */
export function autoRuleId(index) {
    return `rule[${index}]`;
}
function normalizeMcpRule(rule, index) {
    const match = {
        server: toList(rule.match.server ?? DEFAULTS.match.server),
        tool: toList(rule.match.tool),
    };
    if (rule.match.args !== undefined)
        match.args = { ...rule.match.args };
    if (rule.match.max_args_bytes !== undefined)
        match.max_args_bytes = rule.match.max_args_bytes;
    const out = { id: rule.id ?? autoRuleId(index), match, action: rule.action };
    if (rule.reason !== undefined)
        out.reason = rule.reason;
    return out;
}
function normalizeEgressRule(rule, index) {
    const match = {
        host: toList(rule.match.host),
        path: toList(rule.match.path ?? DEFAULTS.match.path),
    };
    if (rule.match.methods !== undefined)
        match.methods = [...rule.match.methods];
    if (rule.match.max_body_bytes !== undefined)
        match.max_body_bytes = rule.match.max_body_bytes;
    const out = { id: rule.id ?? autoRuleId(index), match, action: rule.action };
    if (rule.reason !== undefined)
        out.reason = rule.reason;
    return out;
}
/**
 * Fill defaults, coerce single globs to lists and assign missing rule ids.
 * Assumes `raw` already passed schema validation (see `validatePolicyObject`).
 * Pure: never mutates its input.
 */
export function normalizePolicy(raw) {
    const policy = { version: 1 };
    if (raw.name !== undefined)
        policy.name = raw.name;
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
//# sourceMappingURL=types.js.map