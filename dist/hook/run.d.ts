/**
 * `mcp-recorder hook` — turn one Claude Code hook invocation into a
 * recorded, redacted evidence-chain event.
 *
 * HOOK CONTRACT (verified against the current docs — cite these, not memory,
 * if this ever needs re-checking):
 *   https://code.claude.com/docs/en/hooks
 *   https://code.claude.com/docs/en/hooks#posttoolusefailure-input
 *   https://code.claude.com/docs/en/hooks-guide
 * Claude Code spawns a fresh process per hook event and feeds it exactly one
 * JSON object on stdin. Every event carries `session_id`, `transcript_path`,
 * `cwd`, `hook_event_name`. PreToolUse/PostToolUse/PostToolUseFailure add
 * `tool_name`, `tool_input`, `tool_use_id`. PostToolUse fires ONLY for a
 * tool call that succeeded and adds `tool_response` (string | object); a
 * call that failed fires PostToolUseFailure INSTEAD, which carries no
 * `tool_response` but `error` (a string whose format depends on the tool)
 * and an optional `is_interrupt` boolean (true when the failure reached
 * Claude Code as an abort — the running tool was cancelled — rather than as
 * an error the tool reported). SessionEnd adds `reason`: one of
 * 'clear'|'resume'|'logout'|'prompt_input_exit'|'other'. Stop (end of an
 * agent turn, recorded as a 'claude-code/stop' notification) has no
 * `reason` field at all. MCP tools are named `mcp__<server>__<tool>` (see
 * src/hook/names.ts); built-ins (Bash, Edit, ...) carry no such prefix.
 *
 * A PreToolUse hook DENIES the call by printing this on stdout and exiting 0:
 *   {"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"..."}}
 * (exit 2 also blocks — using stderr as the reason instead of the JSON — but
 * this command never uses exit 2; see the fail-open note below). ALLOWING is
 * exit 0 with nothing on stdout at all — printing anything else on an allow
 * would be misread as the hook's own decision output.
 *
 * FAIL-OPEN, ALWAYS: this command must never become the reason a tool call
 * is blocked or an agent turn fails. `runHook` never throws and always
 * resolves; any internal error (malformed stdin, a store that can't open, a
 * broken policy file, ...) is swallowed and treated as "allow, record
 * nothing" — this module never asks the caller to exit non-zero. The one
 * intentional exception to "never blocks" is the policy engine: a `deny`
 * rule is a deliberate, operator-configured decision, not a failure.
 */
import type { RecorderConfig } from '../types.js';
import { type ActorStamp } from '../identity/stamp.js';
export interface HookOpts {
    config: RecorderConfig;
    /** Absolute path to a policy file, or undefined for "no policy" (allow all). */
    policyPath?: string;
    /** Logical client name stamped as server.name (`--client`; default 'claude-code'). */
    clientName: string;
    /** Record built-in (non-mcp__) tool calls too, not just MCP ones. */
    allTools: boolean;
    proxyVersion: string;
    /** Additive: the ADR 012 actor claim (`--identity-jwt`), stamped on every event's identity block. */
    actor?: ActorStamp;
}
export interface HookResult {
    /** Always 0 — see the file-level fail-open note. */
    exitCode: 0;
    /** JSON to print on stdout verbatim (a PreToolUse deny) — undefined means
     *  "print nothing", the allow case. */
    stdout?: string;
}
export declare function runHook(stdinText: string, opts: HookOpts): Promise<HookResult>;
