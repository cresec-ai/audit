# Claude Code hooks

`mcp-recorder hook` turns Claude Code's own hooks into recorded, redacted
evidence-chain events, with an optional allow/deny policy. For the story
behind the whole tool, see the [README](../README.md); for the recorded
event format, see [docs/event-schema.md](event-schema.md); for wrapping a
stdio/HTTP MCP server directly, see [docs/install.md](install.md).

## Why this exists

The stdio/HTTP proxy (`mcp-recorder record` / `mcp-recorder http`) only sees
traffic for an MCP server it is itself wrapping. In Claude Code — the CLI,
web/cloud sessions, and the Agent SDK alike — a growing share of tool calls
never go through a locally wrapped server at all: **Anthropic-hosted
connectors** such as `mcp__ClickUp__*`, `mcp__Gmail__*`, `mcp__github__*`,
`mcp__Google_Calendar__*` and `mcp__Google_Drive__*` run entirely on
Anthropic's infrastructure. No local proxy — this one included — can sit in
front of them. (In a Claude Code *cloud* session most of them are not even
named that readably: they arrive as opaque UUIDs — see
[Cloud sessions](#cloud-sessions-uuid-server-names-and-serverurl).)

Every tool call Claude Code makes, hosted connectors included, passes
through its **PreToolUse** hook first, and then exactly one of
**PostToolUse** (the call succeeded) or **PostToolUseFailure** (it failed).
That is the only place a third party gets both *visibility into* and
*control over* those calls. `mcp-recorder hook` is a hook handler that records what it sees there
into the same tamper-evident, redacted evidence store the proxy writes to —
so a Claude Code session, a wrapped local MCP server, and a hosted connector
call can all interleave into one evidence chain, inspected the same way with
`sessions` / `query` / `ui` / `export` / `verify`.

## What this covers, and what it does not

**Covers:** every tool call Claude Code's own agent loop makes — built-in
tools (`Bash`, `Edit`, `Read`, ...) with `--all-tools`, locally configured
MCP servers, and Anthropic-hosted connectors — in the Claude Code CLI, Claude
Code on the web/cloud sessions, and the Agent SDK, wherever hooks can be
configured.

**Does not cover:** claude.ai chat and the Claude Desktop app have no hook
mechanism at all — there is nothing for this to attach to there. (Claude
Desktop's own *MCP servers* can still be wrapped directly with
`mcp-recorder setup --client claude-desktop`, which is a different
mechanism — see [docs/install.md](install.md).) This also only sees what a
hook payload contains: a tool call Claude Code itself never routes through a
hook (there isn't one) is invisible here the same way it always was.

## Install

```sh
mcp-recorder hook install
```

This merges `PreToolUse`/`PostToolUse`/`PostToolUseFailure` (matcher
`mcp__.*`, or `.*` with `--all-tools`) and `SessionEnd`/`Stop` hook entries into
`.claude/settings.json` in the current directory (created if missing),
each running `mcp-recorder hook --data-dir <your data dir>`. It is:

- **Safe**: a timestamped backup (`settings.json.bak-<timestamp>`) is written
  before any change, and every key already in the file — including hook
  entries for other tools — is preserved untouched.
- **Reversible**: `mcp-recorder hook install --undo` removes exactly the
  entries this command added (matched by their exact `command` string),
  leaving everything else in place.
- **Idempotent**: running it again never adds a duplicate entry.

```
mcp-recorder hook install [--settings PATH] [--all-tools] [--policy FILE]
                           [--data-dir D] [--client NAME] [--command CMD]
                           [--dry-run] [--undo] [--json]
```

- `--settings PATH` — settings file to edit (default `.claude/settings.json`
  in the current directory; also works with a user-level
  `~/.claude/settings.json` or a `.claude/settings.local.json`).
- `--all-tools` — matcher `.*` instead of `mcp__.*`, so built-in tools
  (`Bash`, `Edit`, `Read`, ...) are recorded too, not just MCP tools.
- `--policy FILE` — bakes `--policy FILE` into the generated hook command
  (see **Policy** below).
- `--data-dir D` — bakes `--data-dir D` into the generated hook command
  (default `~/.mcp-recorder`, same default as every other subcommand).
- `--command CMD` — use this exact command line instead of the generated
  one, e.g. a repo-relative dogfood form:
  `--command "node dist/cli.js hook --data-dir .mcp-recorder"`.
- `--dry-run` — print what would change; write nothing.
- `--undo` — remove exactly the entries this tool added.

Fully restart Claude Code after installing (or uninstalling) for the hook
change to take effect.

## What gets recorded

- **PreToolUse** → a `tool_call` event immediately, before the tool runs:
  redacted arguments, `result: null`, `duration_ms: 0`, additive
  `phase: "pre"`.
- **PostToolUse** (fires only for a call that *succeeded*) → a second
  `tool_call` event, sharing the same `request_id` (Claude Code's own
  `tool_use_id`) as the PreToolUse event: redacted result, `duration_ms`
  measured between the two, additive `phase: "post"`.
- **PostToolUseFailure** (fires *instead of* PostToolUse for a call that
  *failed* — Claude Code fires exactly one of the two per call) → the same
  second `tool_call` event for the failure: same shared `request_id`,
  `phase: "post"`, `duration_ms` measured the same way, `is_error: true`,
  `result: null` with `result_hash` the hash of canonical `null` (a failure
  carries no `tool_response`), and `error: { type, message_ref }` where
  `type` is `"tool_error"` — or `"interrupted"` when the hook's
  `is_interrupt` field is true (the call was aborted rather than reporting
  an error) — and `message_ref` is the SHA-256 ref of the hook's `error`
  string, computed exactly like every other redacted value
  (`Redactor.hashString`, i.e. `sha256Ref`). The error text itself never
  reaches the store. Before this event was handled, a failed
  hosted-connector call was recorded as a lone `phase: "pre"` event with
  `is_error: false`, nothing to say it failed, and a pending marker left
  behind forever (cloud dogfood 3, surprise 1).
- **SessionEnd** → the session's one `session_end` event (`SessionStart` is
  left alone — it is for environment setup, not evidence). A cloud session
  whose container is reclaimed may never fire it; the session then stays
  open in `sessions`, exactly like a proxy session whose process was killed.
- **Stop** → fires at the end of every agent turn, so it is recorded as a
  `notification` event with method `claude-code/stop` (a turn boundary), not
  as a second `session_end`: a session has exactly one terminal event.
- The first hook event seen for a given Claude Code `session_id` also emits
  a `session_start` event first, so every hook-sourced event for one Claude
  Code session lands in one recorded session (mixed with proxy-recorded
  events too, if any share the same evidence store).
- **Pending markers.** A PreToolUse invocation leaves its timestamp in
  `<data-dir>/hook-pending/<tool_use_id>` for the matching
  PostToolUse/PostToolUseFailure invocation to read back and delete, so
  `duration_ms` can be measured across two separate processes. A marker can
  outlive its call: Claude Code killed mid-call, a cloud session's container
  reclaimed before the post hook ran, or the hook uninstalled (or its
  matcher narrowed) between the two halves all leave it behind, and nothing
  else ever deletes it. Every `SessionEnd` and `Stop` invocation therefore
  sweeps markers older than 24 hours (by file mtime; at most 1000 examined
  per sweep, every error ignored). A swept call keeps its `pre` event in
  the chain — its post half simply never arrived.

**What `duration_ms` means for hook events.** A `post` event's
`duration_ms` is the wall-clock gap between the PreToolUse hook process
writing its pending marker and the PostToolUse/PostToolUseFailure hook
process reading it back: that is Claude Code's own tool dispatch plus two
hook process spawns, **not** the MCP server's latency. Cloud dogfood 3
measured about 1.1–1.4 s per call this way (roughly 1 s of it hook
overhead) for local calls the stdio proxy timed at 1–6 ms. A proxy-recorded
`tool_call` (`record`/`http`) times the request and response crossing the
proxy, which *is* the server's latency — do not compare the two numbers. A
`pre` event always has `duration_ms: 0`, and so does a `post` whose marker
is missing (hook installed mid-session, marker already swept, ...). Claude
Code's PostToolUseFailure payload also carries its own optional
`duration_ms` (the tool's execution time, excluding permission prompts and
PreToolUse hooks); that field is not recorded today.

Every hook-sourced event carries the additive `source: "hook"` field so it's
always distinguishable from a proxy-captured one — see
[docs/event-schema.md](event-schema.md#hook-sourced-events-additive).

**How `sessions` counts a hook session.** All of one Claude Code session's
hook events — whichever MCP servers its tool calls went to — share that
session's `session_id`, so they land in one `sessions` row (the per-server
detail stays on each event's `server.name`, which `query`, `ui` and
`export` all show). In that row:

- `TOOL_CALLS` (`tool_call_count`) is the number of **calls**, not of
  `tool_call` events: each call counts once, on its PreToolUse event, and
  its `post` twin (the PostToolUse or PostToolUseFailure event sharing its
  `request_id`) is the same call. A call whose post half never fired
  (Claude Code killed mid-call, a container reclaimed — see **Pending
  markers** above) still counts once.
- `ERRORS` (`error_count`) counts events with `is_error: true` whichever
  phase — a policy-denied PreToolUse, a PostToolUseFailure, or a
  PostToolUse whose response was shaped `{isError: true}` — so it is per
  call too: a failed call has exactly one such event. A failing `post`
  whose `pre` was never recorded (the hook installed mid-call) counts here
  but not in `TOOL_CALLS`, so `ERRORS` can exceed `TOOL_CALLS`.
- `SERVER` is the session's first event's `server.name`, which for a hook
  session is the client itself (`claude-code`); `SERVERS` (the last column;
  additive `server_count` in `--json`) is the number of distinct
  `server.name` values over the session's **`tool_call` events** — the
  servers actually called — so a session that called ClickUp, GitHub and a
  local server reads `3` (the client's own session-level events are not a
  server). A proxy session reads `1` with or without `--name` (without it,
  `server.name` is the argv-derived basename until the `initialize`
  handshake and the learned `serverInfo.name` after it, but every tool
  call carries one name), and a session that never called a tool reads
  `0`.

**MCP tool names.** Claude Code presents an MCP tool to hooks as
`mcp__<server>__<tool>` (e.g. `mcp__ClickUp__clickup_get_task`). This is
split: `tool` is recorded as the bare underlying name (`clickup_get_task` —
the same form the stdio/HTTP proxy would have recorded had it seen this
call directly), and the server it went to is stamped on
`server.name` (`ClickUp`). A built-in tool (no `mcp__` prefix) is recorded
with `tool` as the full name (e.g. `Bash`) and `server.name: "claude-code"`.
**Only `mcp__`-prefixed tool calls are recorded by default** — pass
`--all-tools` (to `hook` or `hook install`) to also record built-ins.

**Where the server is (`server.url`).** For every MCP tool call the hook
also looks the server segment up in the MCP config file Claude Code was
started with and, when it finds it, stamps the server's endpoint on the
event as the additive `server.url` — `https://mcp.clickup.com/mcp` for a
hosted ClickUp connector, whatever a cloud session's UUID for it is. It goes
on every `pre`/`post` `tool_call` event and nowhere else: a session-level
event (`session_start`, `session_end`, the Stop notification) names the
client itself in `server.name`, so it carries no vendor URL. Absent when
nothing resolved — and then there is no policy alias either. It is what
that file **asserts** about the server, not anything observed on the wire
(the hook sends nothing). See [Cloud sessions](#cloud-sessions-uuid-server-names-and-serverurl)
for where it comes from, what is (not) taken from that file, who can write
it, and the policy alias it enables.

**Redaction.** Exactly the same redaction path the stdio/HTTP proxy uses:
tool arguments are hashed unconditionally (`scrubToolArguments`, same as
every other `tool_call.args`), the result goes through the same
position/value-aware allowlist as a proxy-recorded `tool_call.result`, and
`result_hash` is the SHA-256 of the complete raw result before redaction. No
readable payload string from a hook's stdin ever reaches the store.

## Cloud sessions: UUID server names and `server.url`

In a Claude Code **cloud** session (Claude Code on the web) the
Anthropic-hosted connectors are registered under opaque UUIDs, not the
readable names the CLI and this document use elsewhere. What the hook
sees there is

```
mcp__47d587b8-3fb9-42e9-b596-f8b25371248c__clickup_get_list    ClickUp
mcp__ce5e992d-730d-4f07-95c8-4ba759ea3e3b__send_message        Gmail
mcp__github__pull_request_read                                  only github is readable
```

(cloud dogfood 3, surprise 2). The UUID is what Claude Code calls the
server: it is what Claude Code's own hook `matcher` is tested against and
what its transcript shows, so **`server.name` is recorded as the UUID,
unchanged** — renaming it would make the evidence disagree with Claude
Code's own record of the same call. The UUID → service mapping exists in
exactly one place: the MCP config file Claude Code was started with,
`/tmp/mcp-config-<session>.json`, shaped like

```json
{"mcpServers":{
  "github":{"url":"https://api.anthropic.com/v2/ccr-sessions/<session>/github/mcp","type":"http",
            "headers":{"X-Session-UUID":"<session>","X-MCP-Server-ID":"..."}},
  "47d587b8-3fb9-42e9-b596-f8b25371248c":{
            "url":"https://api.anthropic.com/v2/ccr-sessions/<session>/mcp?mcp_server_id=...&mcp_url=https%3A%2F%2Fmcp.clickup.com%2Fmcp&toolbox_mcp_server_id=47d587b8-...",
            "type":"http","tools":[{"name":"clickup_get_list","permission_policy":"always_allow"}, ...]},
  ...}}
```

Every hosted connector is reached through an Anthropic relay URL; for a
UUID-named one the vendor endpoint rides along, URL-encoded, in the
relay URL's `mcp_url` query parameter.

For every MCP tool call, `mcp-recorder hook` looks the server segment up in
that file and records what it finds as the additive `server.url`: the
decoded `mcp_url` when present (`https://mcp.clickup.com/mcp`), else the
entry's own URL — so `github` gets its relay,
`https://api.anthropic.com/v2/ccr-sessions/sha256:.../github/mcp`. The
URL's hostname also becomes the **policy alias** described under
[Policy](#policy-allow--deny). The sources, in order:

1. **`MCP_RECORDER_MCP_CONFIG`** — one path, or comma-separated paths tried
   in order. Set it in the environment the hook runs in to pin a specific
   file (or to point a local Claude Code's hook at its own `.mcp.json`).
2. Otherwise **the files matching `/tmp/mcp-config-*.json`** — what a cloud
   session has, so cloud sessions need no configuration at all.

The first file whose `mcpServers` has the segment wins; at most 16
candidate files are consulted. **Nothing else from the file is recorded**:
not the `headers` (they carry the session id and server ids), not the
session id embedded in the relay URL's path (it is replaced in place by its
`sha256:` ref, computed exactly like every other redacted value, so a
blast-radius `query` for the session id still finds the events), not the
`tools` list or its permission policies, not any other entry. The recorded
URL is scrubbed the way the http proxy scrubs its `--target` before
stamping it on events — userinfo stripped, query string and fragment
dropped — and then more strictly: every path segment that is secret-shaped,
an opaque identifier (a UUID, a `cse_...` session id) **or not a short
vocabulary token** (`[A-Za-z0-9._-]{1,32}`, like `v2`, `ccr-sessions`,
`github`, `mcp`) is hashed, so no readable text the file chooses can reach
the store through a path. Unlike the http proxy's target, the stripped
pieces (userinfo, query values) are **dropped without fingerprints** — the
proxy fingerprints a credential it goes on to send; the hook sends nothing.
A scrubbed URL longer than 2048 characters is not usable at all (no `url`,
no alias; a hosted connector's oversized `mcp_url` falls back to its relay
URL exactly as a non-http one does). This is fail-open like everything
else here: a missing, unreadable, malformed or oversized (> 4 MiB) file is
ignored, an entry with no usable URL (a stdio server) yields nothing, and
the call is allowed and recorded exactly the same either way — just
without `server.url` and without a policy alias.

**Who can write that file.** `/tmp` is world-writable, the hook runs as
the same user as the agent (root, in a cloud session), and the agent the
policy is meant to constrain has `Bash`: one command can rewrite
`/tmp/mcp-config-<session>.json`, plant a `/tmp/mcp-config-!.json` that
sorts before it and maps any UUID to any host, or delete it. Setting
`MCP_RECORDER_MCP_CONFIG` changes nothing about that in a cloud session —
it names a path in the same environment. So `server.url` is that file's
claim about where a server is, and the policy alias built from it is a
**convenience, not a security boundary**: it is tested against `deny`
rules only, never `allow` rules (a forged file can add a deny or make one
miss, never turn a deny into an allow — see [Policy](#policy-allow--deny)),
and a deny that must hold is written against the raw name too.

## Policy: allow / deny

An optional JSON file passed as `--policy FILE` (to `hook` directly, or
baked into the installed command via `hook install --policy FILE`) decides,
per **PreToolUse** call, whether to allow it through or deny it outright —
Claude Code then never runs the tool at all.

```json
{
  "deny": [
    { "tool": "^mcp__(ClickUp|[0-9a-f-]{36}|mcp\\.clickup\\.com)__clickup_delete_task$", "reason": "destructive ClickUp calls are blocked" },
    { "tool": "^mcp__(Gmail|[0-9a-f-]{36})__(send_message|trash_.*)$" }
  ],
  "allow": [
    { "tool": "^mcp__github__.*$" }
  ],
  "default": "allow"
}
```

- `tool` is a **regex tested against the full hook `tool_name`** — the same
  string Claude Code's own hook `matcher` field is tested against (e.g.
  `mcp__ClickUp__clickup_delete_task`, or `Bash` for a built-in). A
  **`deny` rule is also tested**, when the server's origin was resolved
  (see [Cloud sessions](#cloud-sessions-uuid-server-names-and-serverurl)),
  **against the alias `mcp__<host>__<tool>`**: a cloud session's
  `mcp__47d587b8-3fb9-42e9-b596-f8b25371248c__clickup_delete_task` is
  also tested as `mcp__mcp.clickup.com__clickup_delete_task`, and the rule
  matches when either string matches. An **`allow` rule is tested against
  the raw name only**, never the alias: the alias comes from a file the
  agent under policy can write (see **Who can write that file** above), so
  it may add a deny but must never satisfy an allow — otherwise a forged
  `mcp_url` host could turn a `default: "deny"` policy's denial of a
  ClickUp call into an allowed "github" one. That is why the example spells
  the ClickUp rule `(ClickUp|[0-9a-f-]{36}|mcp\.clickup\.com)`: `ClickUp`
  is the name a local Claude Code gives the connector; `[0-9a-f-]{36}` is
  any UUID a cloud session may give it — the **raw** form, the only one
  that still holds when the config file is forged, shadowed or gone (the
  tool name is specific enough on its own: only ClickUp has a
  `clickup_delete_task`), so a deny that must hold always includes it, as
  the Gmail rule does; and `mcp.clickup.com` is the host every cloud
  session resolves it to, a readable convenience for the reader of the
  policy. Read `server.url` off a recorded event (`query --json`, `ui`), or
  the `mcp_url` in `/tmp/mcp-config-*.json`, to learn a connector's host.
  An alias exists only for a host that looks like one — lowercase, dotted
  (`mcp.clickup.com`; never `github`, `localhost` or an IPv6 literal), no
  `_`, at most 253 characters — so it can never collide with the raw
  `mcp__<server>__<tool>` grammar. `github` keeps its readable name in
  cloud sessions, so `^mcp__github__` needs no alias (its alias would be
  the relay host, `mcp__api.anthropic.com__...`). The alias is only ever
  used for policy evaluation: it is never recorded and never shown to
  Claude Code.
- Evaluated in order: the first matching `deny` rule wins; else the first
  matching `allow` rule; else `default` (itself `"allow"` unless set to
  `"deny"`). The alias can only ever add a `deny` match, so a policy
  written against raw names behaves exactly as it did, and no config file —
  forged, shadowed or deleted — can widen a decision.
- A `deny` rule's `reason` (when given) is shown to Claude Code — and,
  through it, to whoever is watching the session — as the reason the tool
  call was blocked.

A denied call still gets recorded: a `tool_call` event with `is_error: true`
and `error.type: "policy_denied"` (an additive value under the schema's
existing free-form `error.type` string field — see
[docs/event-schema.md](event-schema.md#hook-sourced-events-additive)), so
the block itself is part of the evidence chain, not just Claude Code's own
transcript.

**A missing `--policy` is not an error** — no policy configured means allow
everything, exactly as if `hook` had no `--policy` flag at all. **A present
but malformed policy file is fail-open too**: `hook` warns once on stderr
and behaves exactly as if no policy were configured, rather than failing the
tool call over a typo in a config file. Recording, and this policy engine,
must never be the reason a tool call breaks — only a genuinely configured
`deny` rule ever blocks anything.

## Fail-open guarantees

Recording must never become the reason a tool call fails or an agent turn
breaks. `mcp-recorder hook`:

- **Never throws and never exits non-zero.** Any internal failure — a
  broken store, a malformed policy file, unparseable stdin, a filesystem
  error — is swallowed and treated as "allow, record nothing", with at most
  a `[mcp-recorder]`-prefixed line on stderr (which Claude Code does not
  surface as a blocking reason on exit 0).
- **Prints nothing on an allow.** Only a deliberate policy `deny` writes
  anything to stdout, matching exactly the `hookSpecificOutput` shape
  Claude Code expects (see **Hook contract**, below) — printing anything
  else on an allow would risk being misread as a decision.
- **Times out its own stdin read** (5s) rather than depending solely on
  Claude Code's own hook timeout, so a hung stdin can never hang the tool
  call it's attached to.
- The one deliberate exception to "never blocks": a `--policy` `deny` rule.
  That is an operator-configured decision, not a failure.

## Performance

Each `PreToolUse`/`PostToolUse`/`PostToolUseFailure`/`SessionEnd`/`Stop`
hook invocation is a fresh, short-lived Node process — Claude Code spawns one per hook event, not
one long-lived process per session — that reads a small JSON object from
stdin, redacts and appends at most one or two events to the evidence store
(the same fail-open, off-the-hot-path append path the proxy uses), and
exits. There is no persistent proxy latency added to the tool call itself
the way `record`'s inline stdio tap has: the recording happens in the
hook's own out-of-band process, in parallel with (not inside) Claude Code's
own handling of the tool call.

## Hook contract (for reference)

Verified against the current Claude Code docs (cited in
`src/hook/run.ts`'s file-level comment too, in case this ever needs
re-checking):

- <https://code.claude.com/docs/en/hooks>
- <https://code.claude.com/docs/en/hooks#posttoolusefailure-input> (the
  `PostToolUseFailure` input fields quoted below)
- <https://code.claude.com/docs/en/hooks-guide>

Claude Code spawns one process per hook event and feeds it a single JSON
object on stdin, with at least `session_id`, `transcript_path`, `cwd`, and
`hook_event_name`. `PreToolUse`/`PostToolUse`/`PostToolUseFailure` add
`tool_name`, `tool_input`, and `tool_use_id`; `PostToolUse` (fired only for
a call that succeeded) also adds `tool_response` (`string | object`).
`PostToolUseFailure` fires instead of `PostToolUse` for a call that failed:
it carries no `tool_response`, but `error` (a string — "the format depends
on the tool that failed"), an optional boolean `is_interrupt` ("true when
the failure reached Claude Code as an abort rather than as an error the
tool reported"), and an optional `duration_ms` of its own. It cannot block
anything (the failure already happened), so `mcp-recorder hook` prints
nothing for it. `SessionEnd` adds `reason`
(`"clear" | "resume" | "logout" | "prompt_input_exit" | "other"`); `Stop` (a turn boundary, recorded as a `claude-code/stop` notification)
carries no `reason` at all. A `PreToolUse` hook denies the call by printing,
on exit 0:

```json
{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"..."}}
```

(exit 2 also blocks — using stderr as the reason instead of the JSON — but
`mcp-recorder hook` never uses exit 2; see **Fail-open guarantees** above).
Allowing is exit 0 with nothing on stdout. MCP tools are matched/named as
`mcp__<server>__<tool>`.
