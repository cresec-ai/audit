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
 * hook `matcher` field is tested against. A `deny` rule is ALSO tested
 * against the host alias (`mcp__<host>__<tool>`, src/hook/names.ts) when
 * one resolved; an `allow` rule never is — see `evaluatePolicy`.
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
 *  src/hook/names.ts). The first matching rule wins, in order: deny rules,
 *  then allow rules, then `default`.
 *
 *  THE ALIAS IS DENY-ONLY. A `deny` rule matches when its regex matches
 *  EITHER the raw name or the alias; an `allow` rule matches on the raw
 *  name ONLY. The alias is derived from the MCP config file the hook finds
 *  (`/tmp/mcp-config-*.json` in a cloud session), and that file lives in a
 *  world-writable directory on the same host as the agent the policy is
 *  meant to constrain — an agent with Bash can plant a file that maps any
 *  UUID to any host, or delete the real one. Letting the alias satisfy an
 *  allow rule would let such a file widen a `default: "deny"` policy
 *  (review of the integrated change, E1: a forged `mcp_url` host turned a
 *  denied ClickUp call into an allowed "github" one). Deny-only, a forged
 *  or missing config can only ever ADD a deny or fail to add one — it can
 *  never turn a deny into an allow. (A deny written against the alias alone
 *  can still be dodged by removing the file, which is why docs/hooks.md
 *  tells operators to write a deny that must hold against the raw name,
 *  `[0-9a-f-]{36}` for a cloud UUID.) A policy written against raw names
 *  behaves exactly as it did before aliases existed. `policy: null` (no
 *  policy configured, or one that failed to load) always allows. */
export function evaluatePolicy(policy, toolName, alias) {
    if (policy === null)
        return { decision: 'allow' };
    const aliasMatches = (rule) => alias !== undefined && alias !== toolName && rule.tool.test(alias);
    for (const rule of policy.deny) {
        if (rule.tool.test(toolName) || aliasMatches(rule)) {
            return { decision: 'deny', reason: rule.reason ?? `denied by policy rule /${rule.tool.source}/` };
        }
    }
    for (const rule of policy.allow) {
        if (rule.tool.test(toolName))
            return { decision: 'allow' };
    }
    return { decision: policy.default };
}
//# sourceMappingURL=policy.js.map