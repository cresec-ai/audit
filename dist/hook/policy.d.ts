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
export interface PolicyRule {
    tool: RegExp;
    reason?: string;
}
export interface CompiledPolicy {
    deny: PolicyRule[];
    allow: PolicyRule[];
    default: 'allow' | 'deny';
}
export interface PolicyDecision {
    decision: 'allow' | 'deny';
    /** Set only when decision is 'deny'. */
    reason?: string;
}
/** Parse and validate a policy file's text. Throws on any malformed shape —
 *  callers decide how to report that (see `loadPolicy`, which is fail-open). */
export declare function parsePolicy(text: string): CompiledPolicy;
export interface LoadPolicyResult {
    policy: CompiledPolicy | null;
    /** Set only when `path` was given but could not be read or parsed —
     *  the caller should surface this to stderr; `policy: null` still means
     *  "allow everything" either way. */
    warning?: string;
}
/** Load a policy file from disk. `path: undefined` means "no policy
 *  configured" (`policy: null`, allow everything) — not a warning. */
export declare function loadPolicy(path: string | undefined): LoadPolicyResult;
/** Evaluate a policy against a hook's full `tool_name`. `policy: null` (no
 *  policy configured, or one that failed to load) always allows. */
export declare function evaluatePolicy(policy: CompiledPolicy | null, toolName: string): PolicyDecision;
