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
import { evaluatePolicy } from '../hook/policy.js';
import { parseToolName } from '../hook/names.js';
import { toolSpellings } from '../doctor/spellings.js';
import { evaluateMcp, ruleLabel } from './engine.js';
/**
 * Which leg a policy document governs. policy.yaml v1 always carries
 * `version`; the hook's JSON never does and is made of `deny` / `allow` /
 * `default`. Anything else is handed to the gateway leg, whose validator
 * says precisely what is wrong with it.
 */
export function detectLeg(doc) {
    if (typeof doc !== 'object' || doc === null || Array.isArray(doc))
        return 'gateway';
    const keys = Object.keys(doc);
    if (keys.includes('version') || keys.includes('mcp') || keys.includes('egress'))
        return 'gateway';
    return keys.some((k) => k === 'deny' || k === 'allow' || k === 'default') ? 'hook' : 'gateway';
}
export function smokeGateway(policy, server, tool, args) {
    const argsBytes = Buffer.byteLength(JSON.stringify(args ?? {}), 'utf8');
    const d = evaluateMcp(policy, { server, tool, args: args ?? {}, argsBytes });
    const result = { leg: 'gateway', tool, server, action: d.action, rule: ruleLabel(d) };
    if (d.reason !== undefined)
        result.reason = d.reason;
    if (d.failClosed === true)
        result.fail_closed = true;
    return result;
}
export function smokeHook(policy, toolName) {
    const d = evaluatePolicy(policy, toolName);
    const result = { leg: 'hook', tool: toolName, action: d.decision };
    if (d.reason !== undefined)
        result.reason = d.reason;
    const parsed = parseToolName(toolName);
    if (parsed.isMcp) {
        const spellings = toolSpellings({ configKey: parsed.server, tool: parsed.tool }).map((s) => ({
            name: s.name,
            origin: s.origin,
            action: evaluatePolicy(policy, s.name).decision,
        }));
        result.spellings = spellings;
        result.anchored = spellings.filter((s) => s.action !== d.decision);
    }
    return result;
}
//# sourceMappingURL=smoke.js.map