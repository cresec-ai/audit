/**
 * `mcp-recorder hook` PreToolUse allow/deny policy.
 *
 * Policy file (JSON, optional):
 *   { "deny":    [{"tool": "<regex>", "reason": "..."}],
 *     "allow":   [{"tool": "<regex>"}],
 *     "default": "allow" | "deny" }
 *
 * Evaluated in order: the first matching `deny` rule wins, else the first
 * matching `allow` rule, else `default` (which itself defaults to "allow").
 * `tool` regexes match the FULL hook `tool_name` (e.g.
 * "mcp__ClickUp__clickup_delete_task"), the exact string Claude Code's own
 * hook `matcher` field is tested against.
 *
 * Fail-open: a missing --policy is not an error (no policy = allow
 * everything), and a PRESENT but invalid/malformed policy file is also
 * fail-open — warn once (the caller writes `warning` to stderr) and behave
 * as if no policy were configured. Recording (and this policy engine) must
 * never be the reason a tool call breaks; only a deliberately configured
 * `deny` rule blocks anything.
 */
import { readFileSync } from 'node:fs';
function isPlainObject(v) {
    return typeof v === 'object' && v !== null && !Array.isArray(v);
}
function compileRules(raw, field) {
    if (raw === undefined)
        return [];
    if (!Array.isArray(raw))
        throw new Error(`policy.${field} must be an array`);
    return raw.map((entry, i) => {
        if (!isPlainObject(entry)) {
            throw new Error(`policy.${field}[${i}] must be an object`);
        }
        const r = entry;
        if (typeof r.tool !== 'string' || r.tool.length === 0) {
            throw new Error(`policy.${field}[${i}].tool must be a non-empty string (regex)`);
        }
        let re;
        try {
            re = new RegExp(r.tool);
        }
        catch (cause) {
            const msg = cause instanceof Error ? cause.message : String(cause);
            throw new Error(`policy.${field}[${i}].tool is not a valid regex: ${msg}`);
        }
        const rule = { tool: re };
        if (r.reason !== undefined) {
            if (typeof r.reason !== 'string') {
                throw new Error(`policy.${field}[${i}].reason must be a string`);
            }
            if (r.reason.length > 0)
                rule.reason = r.reason;
        }
        return rule;
    });
}
/** Parse and validate a policy file's text. Throws on any malformed shape —
 *  callers decide how to report that (see `loadPolicy`, which is fail-open). */
export function parsePolicy(text) {
    const raw = JSON.parse(text);
    if (!isPlainObject(raw)) {
        throw new Error('policy file must contain a JSON object');
    }
    const rawPolicy = raw;
    const deny = compileRules(rawPolicy.deny, 'deny');
    const allow = compileRules(rawPolicy.allow, 'allow');
    let def = 'allow';
    if (rawPolicy.default !== undefined) {
        if (rawPolicy.default !== 'allow' && rawPolicy.default !== 'deny') {
            throw new Error('policy.default must be "allow" or "deny"');
        }
        def = rawPolicy.default;
    }
    return { deny, allow, default: def };
}
/** Load a policy file from disk. `path: undefined` means "no policy
 *  configured" (`policy: null`, allow everything) — not a warning. */
export function loadPolicy(path) {
    if (path === undefined)
        return { policy: null };
    let text;
    try {
        text = readFileSync(path, 'utf8');
    }
    catch (cause) {
        const msg = cause instanceof Error ? cause.message : String(cause);
        return { policy: null, warning: `--policy ${path} could not be read (${msg}); allowing all tool calls` };
    }
    try {
        return { policy: parsePolicy(text) };
    }
    catch (cause) {
        const msg = cause instanceof Error ? cause.message : String(cause);
        return { policy: null, warning: `--policy ${path} is invalid (${msg}); allowing all tool calls` };
    }
}
/** Evaluate a policy against a hook's full `tool_name`, and — when given —
 *  its host alias (`mcp__<host>__<tool>`, see `hostAliasToolName` in
 *  src/hook/names.ts): a rule matches when its regex matches EITHER
 *  string, and the first matching rule wins in the same order as before
 *  (deny rules, then allow rules, then `default`). The alias only ever adds
 *  matches, never removes one, so a policy written against raw names
 *  behaves exactly as it did. `policy: null` (no policy configured, or one
 *  that failed to load) always allows. */
export function evaluatePolicy(policy, toolName, alias) {
    if (policy === null)
        return { decision: 'allow' };
    const matches = (rule) => rule.tool.test(toolName) || (alias !== undefined && alias !== toolName && rule.tool.test(alias));
    for (const rule of policy.deny) {
        if (matches(rule)) {
            return { decision: 'deny', reason: rule.reason ?? `denied by policy rule /${rule.tool.source}/` };
        }
    }
    for (const rule of policy.allow) {
        if (matches(rule))
            return { decision: 'allow' };
    }
    return { decision: policy.default };
}
//# sourceMappingURL=policy.js.map