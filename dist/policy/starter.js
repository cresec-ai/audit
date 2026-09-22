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
import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
/** Basename of the gateway-leg starter policy inside the data directory. */
export const STARTER_POLICY_FILE = 'policy.starter.yaml';
/** Basename of the Claude Code hook-leg starter policy inside the data directory. */
export const STARTER_HOOK_POLICY_FILE = 'policy.starter.json';
/** `<data-dir>/policy.starter.yaml`. The ONLY path `--protect` ever resolves to. */
export function starterPolicyPath(dataDir) {
    return join(dataDir, STARTER_POLICY_FILE);
}
/** `<data-dir>/policy.starter.json` — the hook leg's twin. */
export function starterHookPolicyPath(dataDir) {
    return join(dataDir, STARTER_HOOK_POLICY_FILE);
}
/**
 * How many rules of each action the shipped starter carries, so `protect`
 * can say "4 rules deny, 3 rules hold" without parsing its own template, and
 * so a test catches the sentence and the file drifting apart.
 */
export const STARTER_RULE_COUNTS = { deny: 4, hold: 3 };
export const STARTER_POLICY_YAML = String.raw `version: 1

# mcp-recorder starter policy  (schema v1 — docs/policy.md)
#
# This file was written by 'mcp-recorder protect'. IT IS YOURS. Edit it,
# narrow it, delete rules from it, or delete the whole file and pass a
# '--policy' of your own. Nothing rewrites it: a second 'protect' run leaves
# an existing file exactly as you left it.
#
# The shape of the choice, so you can argue with it:
#
#   * 'default: allow'. Enforcement is aimed at EFFECTS, not applied as a
#     wall. A default of deny or hold on servers we know nothing about would
#     block the first thing your agent tries, including reads.
#   * DENY where a person would essentially never say "yes, quietly", and
#     anchor those rules to ARGUMENTS — what the call does to the world —
#     because a tool NAME is a guess about a vocabulary we do not control.
#   * HOLD where a person plausibly would say yes. A hold is a question; a
#     deny is a wall. Unanswered after two minutes means denied, which is
#     what someone who walked away would have wanted.
#
# To relax a rule: delete it, or narrow its pattern, then FULLY restart your
# client (closing the window is not enough — MCP servers are launched at
# startup). 'mcp-recorder why' prints, for anything that was stopped, the
# rule id to look for here.
#
# Every deny below is checked against your real tools by
# 'mcp-recorder doctor', which FAILS when this policy matches none of them:
# "enforcement is on and matches nothing" is a failure that does not report
# itself.

name: starter

mcp:
  default: allow

  hold:
    # Long enough to notice the agent paused, switch to a terminal, and
    # answer with 'mcp-recorder holds' + 'mcp-recorder approve <id>'.
    #
    # SAY THIS OUT LOUD, because it is the sharpest edge in this file: WHILE
    # A CALL IS HELD YOUR AGENT IS STOPPED, and the only notice is a line on
    # the proxy's stderr, which a GUI client does not show you. Nobody
    # answering means two silent minutes and then a refusal. Lower this if
    # you work in a GUI client; set on_timeout to 'allow' only if you would
    # rather an unattended delete went through than waited.
    timeout_ms: 120000
    on_timeout: deny

  boundary:
    # The shipped defaults, stated so this file is self-describing.
    secrets: redact
    injection: flag

  # How much of one call's arguments the four deny rules below may scan.
  # PAST THIS BUDGET A CALL IS DENIED, not allowed unscanned: a partial scan
  # is a deny that silently became an allow, so the engine refuses to answer
  # instead. THE CLIFF IS REACHABLE BY ORDINARY WORK — writing a 300 KiB
  # generated file through a filesystem server, pushing several files at
  # once — and when you hit it the refusal says 'arguments too large to
  # scan' and names this setting. Raise it rather than deleting the deny
  # rules: a bigger budget scans MORE, never less. It costs time on the
  # thread your client is waiting on, which is why it is bounded.
  any_arg:
    max_leaves: 256
    max_bytes: 262144

  rules:
    # ---------------------------------------------------------------- deny

    # 1. A credential in an outbound tool argument is either exfiltration or
    #    a token being handed to a tool that should not hold it. Working MCP
    #    servers take credentials from their ENVIRONMENT, not from call
    #    arguments. The shapes are the high-confidence ones the tool-result
    #    boundary filter already acts on; generic long hex and long base64
    #    are deliberately absent, because they match git SHAs, checksums and
    #    container digests.
    #    If your server genuinely takes a token as an argument, this denies
    #    its first call. The supported answer is the 'credentials:' broker
    #    section (docs/policy.md), not deleting this rule.
    - id: secrets-in-arguments
      match:
        tool: "**"
        any_arg: '\b(AKIA|ASIA)[0-9A-Z]{16}\b|\bgh[pousr]_[A-Za-z0-9]{20,}\b|\bgithub_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}\b|\bsk-[A-Za-z0-9_-]{10,}\b|\bxox[baprs]-[A-Za-z0-9-]{10,}\b|\beyJ[\w-]{10,}\.[\w-]{10,}\.[\w-]{10,}\b|-----BEGIN [A-Z ]*PRIVATE KEY-----|\b[Bb][Ee][Aa][Rr][Ee][Rr][ \t]+[A-Za-z0-9._~+/=-]{16,}'
      action: deny
      reason: an argument carried something shaped like a credential

    # 2. Reading a credential file into the model's context is the most
    #    common way a secret leaves a machine, and the model does not need
    #    the contents to do the work. The leading (^|/|\) means the value
    #    must BE a path, not merely mention one: prose containing "the .env
    #    file" has a space before '.env' and does not match, while '.env'
    #    and 'src/../.env' do.
    #    Deny rather than hold: there is no version of "yes, read my private
    #    key, quietly" that anyone wants.
    - id: credential-files
      match:
        tool: "**"
        any_arg: '(^|/|\\)(\.env|\.env\.[A-Za-z0-9_-]{1,64}|\.npmrc|\.netrc|\.git-credentials|\.pgpass|id_rsa|id_ed25519|id_ecdsa|id_dsa)$|(^|/|\\)\.ssh(/|\\)|(^|/|\\)\.aws(/|\\)credentials$|(^|/|\\)\.kube(/|\\)config$|\.pem$|\.p12$|\.pfx$'
      action: deny
      reason: an argument was a path to a credential file

    # 3. The one thing an agent must not be able to edit is the thing that
    #    governs it: this policy, the evidence directory, the client's MCP
    #    config and its hook settings.
    #    HONEST LIMIT: this is friction and EVIDENCE, not a boundary. The
    #    agent has a shell, and MCP_RECORDER_DISABLE=1 is documented. What
    #    this rule buys is that the attempt becomes a policy_decision in a
    #    signed chain instead of a silent edit.
    - id: dont-touch-the-controls
      match:
        tool: "**"
        any_arg: '(^|/|\\)\.mcp-recorder(/|\\|$)|(^|/|\\)policy\.starter\.(yaml|yml|json)$|(^|/|\\)claude_desktop_config\.json$|(^|/|\\)\.mcp\.json$|(^|/|\\)\.cursor(/|\\)mcp\.json$|(^|/|\\)\.claude(/|\\)settings(\.local)?\.json$'
      action: deny
      reason: that path is this recorder's own configuration or evidence

    # 4. These reach through servers whose tool NAME tells you nothing
    #    ('bash', 'run_command', 'execute', 'query') and whose ARGUMENT tells
    #    you everything — the exact case argument matching exists for.
    #    HONEST LIMIT: this is four literals, not a shell parser, and it
    #    does not pretend to be one. The SQL keywords are spelled as
    #    character classes because the RE2 subset bans inline
    #    case-insensitivity. "DELETE FROM <table>" matches only the
    #    UNQUALIFIED form (the statement ends right after the table name):
    #    RE2 has no lookahead, so "has no WHERE" is not expressible, but
    #    "terminates right here" is.
    - id: catastrophic-commands
      match:
        tool: "**"
        any_arg: '[Rr][Mm][ \t]+-[A-Za-z]*[Rr][A-Za-z]*[ \t]+(/|/\*|~|~/|~/\*|\$HOME|\$HOME/|\$HOME/\*)([ \t;&|]|$)|--no-preserve-root|[Dd][Rr][Oo][Pp][ \t]+([Dd][Aa][Tt][Aa][Bb][Aa][Ss][Ee]|[Ss][Cc][Hh][Ee][Mm][Aa])\b|[Tt][Rr][Uu][Nn][Cc][Aa][Tt][Ee][ \t]+[Tt][Aa][Bb][Ll][Ee]\b|[Dd][Ee][Ll][Ee][Tt][Ee][ \t]+[Ff][Rr][Oo][Mm][ \t]+[A-Za-z_][A-Za-z0-9_."]*[ \t;]*$|[Gg][Ii][Tt][ \t]+[Pp][Uu][Ss][Hh].*[ \t]--force([^-]|$)'
      action: deny
      reason: that argument would destroy data irreversibly

    # ---------------------------------------------------------------- hold

    # 5. Deletion is the archetype of the irreversible thing, and a hold
    #    asks rather than walls.
    #    THIS RULE IS A GUESS ABOUT A VOCABULARY, and the product treats it
    #    as one: 'mcp-recorder doctor' prints exactly which of YOUR tools it
    #    matched, so the guess becomes a measured fact at install time.
    #    Rules 1-4 catch the effect when the name misses.
    - id: destructive-tools
      match:
        tool:
          - "delete_*"
          - "*_delete"
          - "*_delete_*"
          - "remove_*"
          - "*_remove"
          - "*_remove_*"
          - "destroy_*"
          - "*_destroy_*"
          - "drop_*"
          - "rm"
          - "rm_*"
          - "trash_*"
          - "*_trash_*"
          - "purge_*"
          - "*_purge_*"
          - "truncate_*"
          - "overwrite_*"
      # DELIBERATELY NOT move_* / rename_*. Against a filesystem server they
      # are the ONLY thing this rule matches, and they are a routine refactor
      # — so the first thing the starter did was hold an ordinary edit for
      # two minutes. If you want them, they are one line each; they are left
      # out because a hold nobody answers is a two-minute stall and then a
      # refusal, and that is a bad trade for an operation that loses nothing.
      action: hold
      reason: this tool destroys something; approve it yourself

    # 6. The difference between an agent that helped and an agent that
    #    embarrassed you is usually whether something reached another human.
    #    Hold, not deny, because sending is frequently exactly what was
    #    asked for. Deliberately NOT 'create_draft' / '*_draft': a draft goes
    #    nowhere, and holding it is pure friction.
    - id: sends-to-other-people
      match:
        tool:
          - "send_*"
          - "*_send"
          - "*_send_*"
          - "post_message"
          - "*_post_message"
          - "reply"
          - "reply_*"
          - "*_reply"
          - "forward"
          - "forward_*"
          - "*_forward"
          - "publish_*"
          - "share_*"
          - "*_share_*"
          - "invite_*"
          - "email_*"
          - "sms_*"
      action: hold
      reason: this tool sends something to other people; approve it yourself

    # 7. Money is the canonical irreversible act and the one a security team
    #    asks about first. THESE ARE VERBS, NOT NOUNS, on purpose. An earlier
    #    draft used '*charge*', '*invoice*' and '*order*'; measured against a
    #    real payments vocabulary that held six of seven tools, four of them
    #    pure reads ('list_charges', 'get_invoice', 'list_invoices',
    #    'search_orders'), and against a tracker it held 'order_issues', a
    #    sort. A hold on a read is pure friction: the agent stalls for two
    #    minutes and then is refused for looking something up.
    #    The residual: a tool that spends money under a name none of these
    #    match is NOT held. 'doctor' prints which of your tools this rule
    #    matched, so you can see that rather than assume it.
    - id: spends-money
      match:
        tool:
          - "*purchase*"
          - "*checkout*"
          - "*refund*"
          - "*payout*"
          - "charge_*"
          - "*_charge"
          - "create_*payment*"
          - "send_payment*"
          - "transfer_*"
          - "subscribe_*"
          - "create_subscription*"
      action: hold
      reason: this tool moves money; approve it yourself

    # --------------------------------------------------------------- notes
    #
    # OUTBOUND HTTP IS DELIBERATELY ALLOWED. A large share of useful MCP
    # servers are HTTP clients, and denying them makes the first run a wall
    # of refusals for calls you wanted. What still protects that path is
    # rule 1 (a credential in the arguments is denied) and the boundary
    # filter above (secrets redacted out of results, injection markers
    # flagged). For a hardened laptop, uncomment:
    #
    # - id: no-outbound-http
    #   match:
    #     tool: ["http_post", "http_put", "http_patch", "fetch*"]
    #   action: deny
    #   reason: this machine does not make outbound calls through tools
    #
    # Reads are allowed. tools/list, initialize and every non-tools/call
    # message are untouched, as they are under every gateway-mode policy.
`;
export const STARTER_HOOK_POLICY_JSON = String.raw `{
  "_this_file_is_yours": "Written by 'mcp-recorder protect'. Edit it or delete it; nothing rewrites it. It governs the Claude Code HOOK leg only - the Anthropic-hosted connectors (ClickUp, Gmail, Drive, ...) that no local MCP proxy can see. The stdio and HTTP gateways read policy.starter.yaml instead.",
  "_every_rule_leaves_the_server_segment_open": "A hook tool name is mcp__<server>__<tool>, and the <server> segment is the CLIENT's to choose, not yours. It has differed between two sessions a day apart, and between two surfaces of one machine at the same time: the config keys were UUIDs while the tool names were friendly, and both deny rules of that run silently matched nothing while the calls went through to a real workspace. So every rule here leaves the segment open - ^mcp__.*__<tool>$ - and 'mcp-recorder doctor' FAILS when any rule here is anchored to one spelling.",
  "_why_these_are_denies_and_not_holds": "The hook protocol has no way to ask a question and wait: PreToolUse can allow or deny and nothing else. So this file carries only the irreversible-and-essentially-never-wanted set. The gateway leg (policy.starter.yaml) HOLDS a wider set, because there a hold is possible.",
  "_what_is_deliberately_not_here": "Sending (send_*, reply, forward, share, invite). On the gateway leg those are HELD, which is a question you can answer. Here a hold is impossible, so the only two options were a wall in front of every message your agent was asked to send, or nothing. This file chooses nothing and says so. To add the wall, copy a rule below and use: ^mcp__.*__[A-Za-z0-9_]*(send|reply|forward|share|invite|post_message)[A-Za-z0-9_]*$",
  "default": "allow",
  "deny": [
    {
      "_id": "destructive-tools",
      "tool": "^mcp__.*__[A-Za-z0-9_]*(delete|destroy|purge|truncate)[A-Za-z0-9_]*$",
      "reason": "this tool destroys something and the hook leg cannot ask you first; do it by hand, or narrow this rule in policy.starter.json"
    },
    {
      "_id": "destructive-tools-prefix",
      "tool": "^mcp__.*__(remove|drop|trash|rm)[_A-Za-z0-9]*$",
      "reason": "this tool destroys something and the hook leg cannot ask you first; do it by hand, or narrow this rule in policy.starter.json"
    },
    {
      "_id": "spends-money",
      "tool": "^mcp__.*__[A-Za-z0-9_]*(purchase|payment|charge|checkout|refund|payout)[A-Za-z0-9_]*$",
      "reason": "this tool moves money and the hook leg cannot ask you first; do it by hand, or narrow this rule in policy.starter.json"
    }
  ]
}
`;
/**
 * Write a starter file if and only if it is not already there.
 *
 * NEVER overwrites: a person who edited their policy and runs `protect`
 * again keeps their edits and is told from the return value that nothing was
 * written. The directory is created 0700 and the file 0600, like the holds
 * directory, because these files name the controls.
 */
export function materialiseStarterFile(path, contents) {
    if (existsSync(path))
        return { path, created: false };
    mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
    writeFileSync(path, contents, { mode: 0o600 });
    return { path, created: true };
}
/** Both starter files, materialised into `dataDir`. */
export function materialiseStarterPolicy(dataDir) {
    return {
        policy: materialiseStarterFile(starterPolicyPath(dataDir), STARTER_POLICY_YAML),
        hook: materialiseStarterFile(starterHookPolicyPath(dataDir), STARTER_HOOK_POLICY_JSON),
    };
}
//# sourceMappingURL=starter.js.map