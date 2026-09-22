/**
 * The STARTER POLICY: enforcement with nothing to author.
 *
 * `mcp-recorder protect` materialises these two files into the data
 * directory and points the existing `setup --policy` / `hook install
 * --policy` code paths at them. They are plain files, owned by the person
 * who ran `protect`, written ONCE and never regenerated over their edits —
 * that is what makes "you can change it" true rather than claimed.
 *
 * Two legs, two name spaces, and they must not be confused:
 *
 *   stdio / HTTP gateway   `record --policy` / `http --policy`
 *       `tool` matches the `tools/call` `params.name` on the wire: the
 *       SERVER's own name for the tool (`delete_file`), no platform segment.
 *
 *   Claude Code hook       `hook --policy`
 *       `tool` matches the full hook `tool_name`, `mcp__<segment>__<tool>`,
 *       where the SEGMENT IS THE PLATFORM'S TO CHOOSE. Every deny rule in
 *       the JSON twin therefore leaves it open (`^mcp__.*__<tool>$`): one
 *       mismatch between the config key and that segment defeated both deny
 *       rules of cloud dogfood 4, and nothing reported an error, because the
 *       failure was an ABSENCE. `mcp-recorder doctor` check C3 exists to
 *       turn that absence into a non-zero exit.
 *
 * NOTHING HERE IS ON THE FORWARDING PATH. These are string constants and a
 * file writer. A starter policy sitting in the data directory is never an
 * input to `resolvePolicyPath`, so it can never switch enforcement on by
 * itself: enforcement is selected explicitly (`protect`, `--protect`,
 * `--policy`, `MCP_RECORDER_POLICY`) or not at all.
 *
 * The two constants below are `String.raw` template literals so the regexes
 * read exactly as they do in the file on disk. A backtick or a `$`-brace in
 * either would end the literal, so a test asserts neither appears.
 */
/** Basename of the gateway-leg starter policy inside the data directory. */
export declare const STARTER_POLICY_FILE = "policy.starter.yaml";
/** Basename of the Claude Code hook-leg starter policy inside the data directory. */
export declare const STARTER_HOOK_POLICY_FILE = "policy.starter.json";
/** `<data-dir>/policy.starter.yaml`. The ONLY path `--protect` ever resolves to. */
export declare function starterPolicyPath(dataDir: string): string;
/** `<data-dir>/policy.starter.json` — the hook leg's twin. */
export declare function starterHookPolicyPath(dataDir: string): string;
/**
 * How many rules of each action the shipped starter carries, so `protect`
 * can say "4 rules deny, 3 rules hold" without parsing its own template, and
 * so a test catches the sentence and the file drifting apart.
 */
export declare const STARTER_RULE_COUNTS: {
    readonly deny: 4;
    readonly hold: 3;
};
export declare const STARTER_POLICY_YAML: string;
export declare const STARTER_HOOK_POLICY_JSON: string;
/** What {@link materialiseStarterFile} did with one file. */
export interface StarterFile {
    path: string;
    /** False when a file was already there — it is left exactly as the person left it. */
    created: boolean;
}
/**
 * Write a starter file if and only if it is not already there.
 *
 * NEVER overwrites: a person who edited their policy and runs `protect`
 * again keeps their edits and is told from the return value that nothing was
 * written. The directory is created 0700 and the file 0600, like the holds
 * directory, because these files name the controls.
 */
export declare function materialiseStarterFile(path: string, contents: string): StarterFile;
/** Both starter files, materialised into `dataDir`. */
export declare function materialiseStarterPolicy(dataDir: string): {
    policy: StarterFile;
    hook: StarterFile;
};
