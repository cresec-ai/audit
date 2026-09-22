/**
 * Every `mcp__<segment>__<tool>` spelling a Claude Code client could choose
 * for one tool — the input to `doctor` check C3, the headline check.
 *
 * WHY THIS EXISTS. The `<segment>` in a hook `tool_name` is the PLATFORM's to
 * pick, and so are the keys in the MCP config file, and nothing makes the two
 * agree. Cloud dogfood 3 saw UUID keys with UUID segments; cloud dogfood 4, a
 * day later, saw UUID keys with FRIENDLY segments (`mcp__ClickUp__…`). That
 * one mismatch defeated both deny rules the run existed to prove: two live
 * ClickUp calls executed against the real workspace, twice each, and the
 * 62-event signed bundle — chain PASS — held zero policy decisions. No
 * command reported an error, because the failure was an ABSENCE.
 *
 * So a rule that matches `mcp__ClickUp__clickup_delete_task` and nothing else
 * is not a deny rule, it is a deny rule for one session. This module
 * enumerates the spellings, C3 requires every deny rule to match ALL of them
 * for any tool it matches at all, and the last spelling is deliberately one
 * nobody has ever observed: it is the fuzz case that proves a rule is OPEN
 * rather than merely broad enough for the conventions we happen to know.
 */
/** A UUID-shaped segment, fixed so doctor's output is stable run to run. */
export declare const SYNTHETIC_UUID_SEGMENT = "47d587b8-3fb9-42e9-b596-f8b25371248c";
/** A segment nobody has ever observed. A rule that misses this is anchored. */
export declare const UNKNOWN_SEGMENT = "zz-unknown-segment-0";
/** Where a spelling has been seen, printed beside it when a rule misses it. */
export interface ToolSpelling {
    /** The full hook `tool_name`. */
    name: string;
    /** The `<segment>` this spelling uses. */
    segment: string;
    /** One line of provenance, e.g. "the config key (cloud dogfood 3)". */
    origin: string;
}
export interface SpellingInputs {
    /** The `mcpServers` key this tool's entry is filed under. */
    configKey: string;
    /** The tool's own name, as `tools[].name` declares it. */
    tool: string;
    /**
     * A readable vendor name for the server, when one can be worked out — the
     * config key when it is not a UUID, else the vendor host's own label
     * (`mcp.clickup.com` -> `clickup`). This is the spelling cloud dogfood 4
     * saw where the key was a UUID.
     */
    friendly?: string;
    /** The resolved vendor hostname, when `server.url` resolution succeeded. */
    host?: string;
}
export declare function looksLikeUuid(value: string): boolean;
/**
 * A readable name for a connector, from its config key and (when resolved)
 * its vendor host. Returns undefined when neither yields anything readable,
 * which is the honest answer for `mcp__<uuid>__…` with no config URL.
 */
export declare function friendlyName(configKey: string, host?: string): string | undefined;
/**
 * Every spelling of one tool, deduplicated by `name`, in a stable order.
 *
 * The set always contains at least the config-key spelling, a UUID spelling
 * and the unknown-segment spelling, so C3 has something to prove even for a
 * connector whose vendor never resolved.
 */
export declare function toolSpellings(input: SpellingInputs): ToolSpelling[];
/**
 * Tool names used by C3 when no live MCP config could be read — the local
 * case `docs/hooks.md` documents, where `/tmp/mcp-config-*.json` does not
 * exist at all.
 *
 * Checking a rule against these is NOT the same as checking it against the
 * real vocabulary, and doctor never reports OK on them alone: the status is
 * at best INCOMPLETE. But a rule anchored to one segment misses the fuzz
 * spelling of a probe name exactly as it misses the fuzz spelling of a real
 * one, so the dogfood-4 shape is still caught with no session running —
 * which is the whole point of a check that runs in CI.
 */
export declare const PROBE_CONNECTOR_TOOLS: readonly string[];
/**
 * The literal `<segment>` a hook deny rule is anchored to, or undefined when
 * the rule leaves the segment open.
 *
 * This is the SYNTACTIC half of check C3, and it is the half that does not
 * depend on having the right vocabulary in hand. The behavioural half
 * ("matches some spellings, misses others") only fires for a rule that
 * matches at least one spelling doctor can construct, and doctor cannot
 * construct every spelling: cloud dogfood 4 saw `ClickUp`, where the vendor
 * host reads `clickup`, and no rule for turning one into the other is
 * trustworthy. So `^mcp__ClickUp__clickup_delete_task$` would match NOTHING
 * doctor builds and be reported as fine — the very absence the check exists
 * for.
 *
 * Reading the rule instead settles it: the text between `mcp__` and the next
 * `__` either contains a wildcard or it does not. `^mcp__.*__x$` is open,
 * `^mcp__ClickUp__x$` names a segment the client is free to stop using
 * tomorrow, and neither answer needs a live session.
 */
export declare function anchoredSegment(source: string): string | undefined;
