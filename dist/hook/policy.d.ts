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
    /** Set only when `path` was given but could not be read or parsed. */
    warning?: string;
    /**
     * `--policy` was given and could not be turned into a decision.
     *
     * This is the one case where `policy: null` does NOT mean "allow
     * everything". Recording is fail-open; ENFORCEMENT is fail-closed, and an
     * operator who passed `--policy` asked for enforcement. Allowing every call
     * because the file has a typo is the failure mode where a security control
     * is off and the only symptom is a line on stderr that nobody reads —
     * measured on this project as exactly how a documented deny silently did
     * nothing for two days (docs/roadmap.md, dogfood 4).
     *
     * `record --policy` already fails closed by exiting 2 before the server is
     * spawned. The hook cannot exit non-zero without breaking the session, so
     * it denies instead. That is recoverable: the default matcher is `mcp__.*`,
     * so Bash and Edit keep working and the operator can fix the file. With
     * `--all-tools` it is not, and `MCP_RECORDER_DISABLE=1` is the documented
     * way out.
     */
    unusable?: boolean;
}
/** Load a policy file from disk. `path: undefined` means "no policy
 *  configured" (`policy: null`, allow everything) — not a warning. */
export declare function loadPolicy(path: string | undefined): LoadPolicyResult;
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
export declare function evaluatePolicy(policy: CompiledPolicy | null, toolName: string, alias?: string): PolicyDecision;
