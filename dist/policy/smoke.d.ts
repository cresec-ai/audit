/**
 * `mcp-recorder policy test`: the deny-rule smoke test as a command.
 *
 * docs/pov.md's second rule for a policy meeting is "smoke-test every rule
 * with the real binary, in the exact observed spelling" — before this it was
 * a `printf` of a PreToolUse event into `mcp-recorder hook` that someone had
 * to remember. This module asks the same question of the same engines the
 * real paths use, without spawning anything and without writing to any
 * store:
 *
 *   gateway leg   `record --policy` / `http --policy` (policy.yaml v1):
 *                 `evaluateMcp` over (server, bare tool, arguments).
 *   hook leg      `hook --policy` (the PreToolUse JSON): `evaluatePolicy`
 *                 over the full `mcp__<segment>__<tool>` name.
 *
 * On the hook leg it also answers the question that cost cloud dogfood 4 its
 * two deny rules: does the verdict survive a DIFFERENT server segment? The
 * segment is the client's to choose, so a verdict that changes with it is a
 * rule anchored to one session's spelling (the spellings are doctor C3's,
 * src/doctor/spellings.ts).
 */
import type { CompiledPolicy } from '../hook/policy.js';
import type { Action, Policy } from './types.js';
export type PolicyLeg = 'gateway' | 'hook';
/**
 * Which leg a policy document governs. policy.yaml v1 always carries
 * `version`; the hook's JSON never does and is made of `deny` / `allow` /
 * `default`. Anything else is handed to the gateway leg, whose validator
 * says precisely what is wrong with it.
 */
export declare function detectLeg(doc: unknown): PolicyLeg;
export interface SpellingVerdict {
    name: string;
    origin: string;
    action: 'allow' | 'deny';
}
export interface SmokeResult {
    leg: PolicyLeg;
    /** The tool name exactly as given. */
    tool: string;
    /** Gateway leg: the server the call was evaluated for. */
    server?: string;
    action: Action;
    /** Gateway: the rule id, or the fail-closed error code, or `default`. */
    rule?: string;
    reason?: string;
    /** Gateway: the policy could not be evaluated for this call, so it denied. */
    fail_closed?: true;
    /**
     * Hook leg, `mcp__<segment>__<tool>` names only: the verdict under every
     * other spelling a client could choose for the same tool.
     */
    spellings?: SpellingVerdict[];
    /** Hook leg: spellings whose verdict differs from the one asked about. */
    anchored?: SpellingVerdict[];
}
export declare function smokeGateway(policy: Policy, server: string, tool: string, args: unknown): SmokeResult;
export declare function smokeHook(policy: CompiledPolicy, toolName: string): SmokeResult;
