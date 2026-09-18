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
[Cloud sessions](#cloud-sessions-uuid-server-names-and-serverurl). Locally
they are named differently again, and differently per surface: the Desktop
"Code" tab uses the connector's UUID, the CLI uses `claude_ai_<Name>` — see
[Local sessions](#local-sessions-no-config-file-so-no-serverurl).)

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
- `ENDED` is an end time only when the session's `session_end` is genuinely
  its LAST event. A Claude Code session resumed under the same `session_id`
  goes on recording after its SessionEnd hook fired — cloud dogfood 4's
  session recorded a `session_end` at 07:59:20 and then tool calls until
  12:41:08 — and every count in the row is a live aggregate over all of it.
  Such a row reads `(reopened)`, and `LAST_EVENT` (the last column;
  additive `last_event_at` in `--json`) gives the instant the counts run
  through; `--json` still reports the `session_end` itself as `ended_at`.
  A session with no `session_end` at all reads `(open)`, as before. Nothing
  about the event schema changes for this — a resumed session emits no
  second `session_start`, and a `session_end` is recorded exactly as it
  always was; only the summary stops presenting a superseded one as an end.
- `SERVER` is the session's first event's `server.name`, which for a hook
  session is the client itself (`claude-code`); `SERVERS` (additive
  `server_count` in `--json`) is the number of distinct
  `server.name` values over the session's **`tool_call` events** — the
  servers actually called — so a session that called ClickUp, GitHub and a
  local server reads `3` (the client's own session-level events are not a
  server). A proxy session usually reads `1` with or without `--name`, and
  a session that never called a tool reads `0`. Without `--name`,
  `server.name` is the argv-derived basename until the `initialize`
  handshake and the learned `serverInfo.name` after it, so a proxy session
  reads `2` when a tool call was sealed on the early side of that line —
  ordinary in gateway mode, where a denied call is answered by the proxy
  without waiting for the server. Hook sessions are unaffected: they have
  no such handshake.
- `DECISIONS` (additive `policy_decision_count` in `--json`) counts the
  enforcement actions gateway mode took. A hook session always reads `0`:
  `hook --policy` decides with its own JSON allow/deny file (see
  [Policy](#policy-allow--deny)) and records a denied call as a `tool_call`
  with `error.type: "policy_denied"`, not as the `policy_decision` event
  the stdio gateway seals. `ERRORS` is where a hook deny shows up.
- `LAST_EVENT` (additive `last_event_at` in `--json`) is the timestamp of
  the session's last event — the instant every count in the row runs
  through. `ENDED` shows an end time only when the `session_end` really is
  the last event; a session resumed under the same id keeps recording after
  its `session_end` and reads `(reopened)` instead, which is the shape a
  resumed Claude Code session takes.

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
Anthropic-hosted connectors may be registered under opaque UUIDs rather than
the readable names the CLI and this document use elsewhere. What the hook
saw in one such session is

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

**The naming convention is the platform's, it varies per session, and the
two sides can disagree.** Cloud dogfood 3 saw UUID-keyed config *and*
UUID-prefixed tool names. Cloud dogfood 4, on the same repository a day
later, saw a **UUID-keyed config file and friendly tool names**
(`mcp__ClickUp__clickup_filter_tasks`, `mcp__Gmail__*`,
`mcp__Google_Calendar__*`, `mcp__Google_Drive__*`). **On a local machine
there is no such file at all, and no key of any kind** — see [Local
sessions](#local-sessions-no-config-file-so-no-serverurl). So the
`<server>` segment of a tool name is **not** guaranteed to be
a key of `mcpServers`, and resolution must not assume it is — the first
shipped version did, which is exactly how dogfood 4's deny policy failed
(see [Write deny rules against the tool](#write-deny-rules-against-the-tool-not-the-server-segment)).
Resolution is best-effort either way: when it misses, the event is still
recorded, just without `server.url` and without an alias.

For every MCP tool call, `mcp-recorder hook` finds that connector's entry in
that file and records what it finds as the additive `server.url`: the
decoded `mcp_url` when present (`https://mcp.clickup.com/mcp`), else the
entry's own URL — so `github` gets its relay,
`https://api.anthropic.com/v2/ccr-sessions/sha256:.../github/mcp`. The
URL's hostname also becomes the **policy alias** described under
[Policy](#policy-allow--deny).

**Which entry — and why it is not just the key.** The config key and the
tool-name segment are not always the same convention, and which way a session
goes varies:

| session | `mcpServers` key | tool name the hook sees |
| --- | --- | --- |
| cloud dogfood 3 | UUID | `mcp__47d587b8-…__clickup_get_list` |
| cloud dogfood 4 | UUID | `mcp__ClickUp__clickup_filter_tasks` |
| local dogfood 6, WSL CLI | **no config file, so no key** | `mcp__claude_ai_ClickUp__clickup_filter_tasks` |
| local dogfood 6, Desktop "Code" tab | **no config file, so no key** | `mcp__47d587b8-…__clickup_filter_tasks` |

(The two local rows are one machine, one account, one connector. They are
measured; an earlier version of this table claimed a local session was keyed
`ClickUp` with friendly tool names, which was an assumption and is wrong.)

So the entry is looked for two ways, in this order:

1. **By key** — the entry whose `mcpServers` key is exactly the segment. The
   precise route, tried in every candidate file before route 2 is.
2. **By declared tool** — the entry whose `tools[]` declares exactly the tool
   being called, used only when **exactly one** entry of the file declares it
   and that file keys no entry by the segment at all. Zero declarations, or
   two or more, resolve to nothing: an ambiguous file is never guessed at,
   because a wrong attribution would produce a **wrong** `deny`. An entry
   with `tools: null` or no `tools` (the shape `github` has) never matches
   this route.

Route 2 is what cloud dogfood 4 was missing: that run's config was UUID-keyed
while Claude Code named the tools `mcp__ClickUp__…`, the key lookup missed,
and so nothing resolved — no `server.url` on a single hosted-connector event,
no policy alias, and both of the run's `deny` rules failed to fire while the
calls ran against the real workspace.

The sources, in order:

1. **`MCP_RECORDER_MCP_CONFIG`** — one path, or comma-separated paths tried
   in order. Set it in the environment the hook runs in to pin a specific
   file. It has to be a file shaped like the one above — an `mcpServers` map
   whose entries carry a `url`. Pointing it at a project `.mcp.json` resolves
   nothing, because those entries are stdio commands with no `url`, and local
   dogfood 6 found nothing else on a local machine that has the shape either
   (see [Local sessions](#local-sessions-no-config-file-so-no-serverurl)).
2. Otherwise **the files matching `/tmp/mcp-config-*.json`** — what a cloud
   session has, so cloud sessions need no configuration at all.

The first file whose `mcpServers` keys the segment wins; only when no
candidate file does is route 2 tried, again in file order, so the precise
route beats the fallback even across files (`/tmp` holds one
`mcp-config-<session>.json` per live session, so several can match). At most
16 candidate files are consulted. **Nothing else from the file is recorded**:
not the `headers` (they carry the session id and server ids), not the
session id embedded in the relay URL's path (it is replaced in place by its
`sha256:` ref, computed exactly like every other redacted value, so a
blast-radius `query` for the session id still finds the events), not the
`tools` list or its permission policies (route 2 compares a `tools[].name`
against the tool being called and records nothing from it), not any other
entry. The recorded
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
and a deny that must hold is written against the raw name too. Route 2
inherits that unchanged — it only decides which entry of the same untrusted
file is read — and its uniqueness requirement is there so a forged or sloppy
file cannot attribute a tool to the wrong vendor and produce a wrong deny.

## Local sessions: no config file, so no `server.url`

Everything above is about a **cloud** session, where `/tmp/mcp-config-*.json`
exists. On a local machine it does not. **Local dogfood 6**
(`evidence/local-dogfood-6/REPORT.md`, Part 1 — 2026-09-17, one Windows 11
machine with two Claude Code surfaces on one claude.ai account: a WSL2 CLI and
the Desktop "Code" tab) looked for it and found nothing:

- **No `/tmp/mcp-config-*.json`, ever.** Checked before a `claude -p` session,
  polled every 0.25 s *while* one ran, and after it exited: zero files each
  time. A scan of the Windows host's `%TEMP%`, `%LOCALAPPDATA%\Temp` and
  `C:\tmp` for `mcp-config*` printed nothing, and neither surface's `claude`
  process is launched with `--mcp-config`.
- **No claude.ai connector in any `mcpServers` map on that machine.** Windows
  and WSL `~/.claude.json` have empty `mcpServers`; the project `.mcp.json`
  holds only the two stdio servers this repository wraps; the Desktop *chat*
  config's `clickup` entry is a stdio `command`/`args` pair with no `url` and
  no `tools[]`. The connectors actually live in `remoteMcpServersConfig`
  inside a Desktop session-metadata file (`…\claude-code-sessions\…json`),
  which has **no `mcpServers` key at all**, and in nothing the CLI exposes.
- **Pointing `MCP_RECORDER_MCP_CONFIG` at those two files resolves nothing**,
  which the run tested directly: with the Desktop session file the event came
  out with `server.name` = the UUID and no `url`; with the Desktop chat config
  it came out `server.name: "clickup"` and no `url`.

**So on a local session neither route resolves.** Route 1 has no candidate
file to key into and route 2 has no `tools[]` to match, for hosted connectors
and `.mcp.json` servers alike. `server.url` is never recorded, no host alias
is ever derived, and PR #16's declared-tool fallback cannot run at all. That
holds unless you point `MCP_RECORDER_MCP_CONFIG` by hand at a file that
really is an `mcpServers` map with `url`s — and nothing on that machine was.

**The operator consequence, plainly: on a local session, only tool-anchored
deny rules work.** A rule spelled as a host alias cannot fire, because the
alias cannot be derived. Write this:

```json
{ "tool": "^mcp__.*__clickup_filter_tasks$", "reason": "bulk task reads are blocked" }
```

That is the rule local dogfood 6 ran, and it blocked both live
`clickup_filter_tasks` attempts in a fresh WSL CLI session — the calls came
back to the model as `mcp-recorder policy: df6-local: tool-anchored deny`, no
workspace data was returned, and Claude Code listed both under
`permission_denials`. The recorded deny carries
`server.name: "claude_ai_ClickUp"`, `error.type: "policy_denied"` and **no
`server.url`**: the block came from the tool segment of the name, which needs
no resolution. A rule written `^mcp__mcp\.clickup\.com__clickup_filter_tasks$`
would have matched nothing in that session.

**And do not anchor on the server segment either.** One ClickUp connector,
one account: **two different segments on one machine at the same time, and a
third in the cloud**.

| Where | Segment the hook sees |
| --- | --- |
| Desktop "Code" tab (Windows host) | `mcp__47d587b8-3fb9-42e9-b596-f8b25371248c__clickup_filter_tasks` |
| WSL CLI (`claude -p`) | `mcp__claude_ai_ClickUp__clickup_filter_tasks` |
| Cloud session (cloud dogfood 4) | `mcp__ClickUp__clickup_filter_tasks` |

The same connector, the same person, the same day for the first two. A rule,
a permission entry or an allowlist anchored to any one of those spellings is
surface-specific and silently stops matching on the others — see [Write deny
rules against the
tool](#write-deny-rules-against-the-tool-not-the-server-segment).

**Recording itself is unaffected.** The local run recorded every call, hashed
the arguments, chained and signed them, and `verify` passed; what is missing
is only the connector's origin and everything derived from it. Local dogfood 6
covered two surfaces on one machine, so read it as "this is what a local
machine did", not as a guarantee about every local machine — but do not plan a
local deployment on a host alias that has never been observed locally.

## Policy: allow / deny

An optional JSON file passed as `--policy FILE` (to `hook` directly, or
baked into the installed command via `hook install --policy FILE`) decides,
per **PreToolUse** call, whether to allow it through or deny it outright —
Claude Code then never runs the tool at all.

```json
{
  "deny": [
    { "tool": "^mcp__.*__clickup_delete_task$", "reason": "destructive ClickUp calls are blocked" },
    { "tool": "^mcp__.*__(send_message|trash_message|trash_thread)$", "reason": "no sending or trashing mail — from any connector that has these tools" }
  ],
  "allow": [
    { "tool": "^mcp__github__.*$" }
  ],
  "default": "allow"
}
```

- `tool` is a **regex tested against the full hook `tool_name`** — the same
  string Claude Code's own hook `matcher` field is tested against (e.g.
  `mcp__ClickUp__clickup_delete_task`, or `Bash` for a built-in). Write the
  `<server>` segment open (`^mcp__.*__<tool>$`) as the example above does:
  that segment is platform-controlled and changes between sessions, and a
  rule anchored to one spelling of it silently stops matching when it
  changes — see [Write deny rules against the
  tool](#write-deny-rules-against-the-tool-not-the-server-segment), which is
  the part of this page to read before writing a policy you intend to rely
  on. A **`deny` rule is also tested**, when the server's origin was resolved
  (see [Cloud sessions](#cloud-sessions-uuid-server-names-and-serverurl); in
  a local session it never is, see [Local
  sessions](#local-sessions-no-config-file-so-no-serverurl)),
  **against the alias `mcp__<host>__<tool>`**: a cloud session's
  `mcp__47d587b8-3fb9-42e9-b596-f8b25371248c__clickup_delete_task` is
  also tested as `mcp__mcp.clickup.com__clickup_delete_task`, and the rule
  matches when either string matches. An **`allow` rule is tested against
  the raw name only**, never the alias: the alias comes from a file the
  agent under policy can write (see **Who can write that file** above), so
  it may add a deny but must never satisfy an allow — otherwise a forged
  `mcp_url` host could turn a `default: "deny"` policy's denial of a
  ClickUp call into an allowed "github" one. So the alias is a
  **convenience, deny-only and best-effort**: it exists only when the
  config file was found, parsed and matched to this server, it is derived
  from a file the agent under policy can rewrite, and it is never the thing
  a deny should rest on — an open `<server>` segment costs nothing and
  holds whether or not resolution worked. Read `server.url` off a recorded
  event (`query --json`, `ui`), or the `mcp_url` in
  `/tmp/mcp-config-*.json`, to learn a connector's host.
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
everything, exactly as if `hook` had no `--policy` flag at all.

**A present but unusable policy file DENIES.** If `--policy` was given and
the file cannot be read or cannot be parsed, every tool call the hook governs
is denied until it is fixed, with the reason on stderr and in the evidence.
Recording is fail-open; *enforcement* is fail-closed, and passing `--policy`
is asking for enforcement. `record --policy` already does this by exiting 2
before the server is spawned; the hook cannot exit non-zero without breaking
the session, so it denies instead.

This changed deliberately. It used to warn and allow, which meant a typo
silently disarmed the control and the only symptom was one line on stderr —
the failure mode that left dogfood 4's deny rules doing nothing for two days
while the run looked healthy.

It is recoverable: the default matcher is `mcp__.*`, so Bash, Edit and Read
keep working and you can fix the file from the same session. With
`--all-tools` it is not, and `MCP_RECORDER_DISABLE=1` is the documented way
out. The hook still never exits non-zero and never crashes the session.

### Write deny rules against the tool, not the server segment

The `<server>` segment of `mcp__<server>__<tool>` is chosen by the platform,
not by you and not by this tool. It has been observed as a UUID
(`mcp__47d587b8-…__clickup_filter_tasks`) in one cloud session and as a
friendly name (`mcp__ClickUp__clickup_filter_tasks`) in another on the same
repository a day later, and the MCP config file's own keying is a separate
choice that can disagree with the segment. **Treat it as unstable.**

It is not only a cloud phenomenon, and not only a per-session one. Local
dogfood 6 found **one ClickUp connector, one account, one machine, carrying
two different segments at the same time** — `mcp__47d587b8-…__clickup_*` in
the Desktop "Code" tab and `mcp__claude_ai_ClickUp__clickup_*` in the WSL
CLI — with cloud dogfood 4's `mcp__ClickUp__…` as a third form of the same
connector. Anchoring on the segment therefore also makes a rule
*surface-specific*: it can hold in the terminal and miss in the Desktop tab on
the same laptop.

This is not hypothetical. Cloud dogfood 4 ran a live Claude Code session
with the hook installed on
`PreToolUse`/`PostToolUse`/`PostToolUseFailure`/`SessionEnd`/`Stop` and this
policy committed at session start:

```json
{
  "deny": [
    { "tool": "^mcp__mcp\\.clickup\\.com__clickup_filter_tasks$" },
    { "tool": "^mcp__[0-9a-f-]{36}__clickup_get_workspace_members$" }
  ],
  "default": "allow"
}
```

Two deliberately independent routes to the same block: the resolved host
alias, and the raw UUID form. **Both failed.** Both ClickUp calls executed
against the real workspace and returned real data, twice each. Claude Code
presented the tools as `mcp__ClickUp__clickup_filter_tasks` and
`mcp__ClickUp__clickup_get_workspace_members`: `ClickUp` is not a UUID, so
the second rule could not match; the config file was keyed by UUID, so the
segment `ClickUp` resolved to nothing and there was no host alias for the
first rule to match either. The session's signed bundle
(`evidence/cloud-dogfood-4/incident.zip`, 62 events, `verify --bundle` and
the bundle's standalone `verify.cjs` both PASS) contains **zero
`policy_denied` events**, and no `server.url` on any hosted-connector event
except `github`'s. The hook itself ran throughout and recorded all 16
pre/post pairs with correctly hashed arguments — observation worked,
enforcement did not.

**The robust shape leaves the segment open.** `tool` is a regex tested
against the whole `tool_name` (`evaluatePolicy`, `src/hook/policy.ts`), so
`.*` in the segment position is all it takes.

Not like this — each of these is anchored to one spelling of a name you do
not control:

```json
{ "tool": "^mcp__ClickUp__clickup_filter_tasks$" }
{ "tool": "^mcp__[0-9a-f-]{36}__clickup_get_workspace_members$" }
{ "tool": "^mcp__mcp\\.clickup\\.com__clickup_filter_tasks$" }
```

Like this — anchored to the tool, which is the vendor's name for the
operation and the part that actually decides what happens:

```json
{ "tool": "^mcp__.*__clickup_filter_tasks$", "reason": "bulk task reads are blocked" }
{ "tool": "^mcp__.*__clickup_get_workspace_members$" }
```

Worked through the namings dogfood 3 and dogfood 4 each saw:

| `tool_name` the hook receives | alias resolved | dogfood 4's rules | `^mcp__.*__…$` |
| --- | --- | --- | --- |
| `mcp__ClickUp__clickup_filter_tasks` | none (what happened live) | allow | **deny** |
| `mcp__ClickUp__clickup_get_workspace_members` | none (what happened live) | allow | **deny** |
| `mcp__47d587b8-…__clickup_filter_tasks` | `mcp__mcp.clickup.com__…` | deny | **deny** |
| `mcp__47d587b8-…__clickup_get_workspace_members` | `mcp__mcp.clickup.com__…` | deny | **deny** |
| `mcp__ClickUp__clickup_filter_tasks` | `mcp__mcp.clickup.com__…` | deny | **deny** |
| `mcp__claude_ai_ClickUp__clickup_filter_tasks` (local dogfood 6, WSL CLI) | none, and none is possible locally | allow | **deny — what happened live** |

The fifth row is the friendly name once the connector-resolution fix lets the
alias resolve: it repairs one of dogfood 4's two routes. The sixth is a local
session, where no alias can resolve at all ([Local
sessions](#local-sessions-no-config-file-so-no-serverurl)) and the open rule
is the only one that can fire — it did, blocking both live attempts. The open
rule held in every row, including the three that happened live, with no
resolution at all.

Three things follow.

- **An open segment denies that tool on every MCP server**, hosted or local.
  For a `deny` that is the safe direction of error, and many connector tool
  names are vendor-prefixed (`clickup_…`, `drive_…`) so collisions are rare.
  Where a name is generic (`send_message`, `search`, `read_file`),
  an open segment is a wider block than you may have meant — widen it
  deliberately rather than narrowing it back to a server segment.
- **The host alias is not a second line of defence.** It is deny-only,
  best-effort, and exists only when the server resolved against the MCP
  config — so it can vanish for exactly the reason a segment-anchored rule
  stops matching, which is what made dogfood 4's two "independent" routes
  fail together. **On a local session it is not a line of defence at all:
  there is no config file, so the alias never exists.** Use it to make a
  policy readable, never to make it hold.
- **`allow` rules are segment-anchored by necessity** (they are never tested
  against the alias). `^mcp__github__.*$` stops matching if that server is
  ever renamed: under `default: "allow"` nothing changes, under
  `default: "deny"` the call is denied. That fails closed, which is right,
  but it will surprise you if you are not expecting it.

**Smoke-test a rule instead of assuming it matches.** A policy that never
fires looks exactly like a policy with nothing to block — dogfood 4's only
signal was a zero count in the evidence. Take the tool name from a recorded
event (`query --json`, `ui`, or `server.name` plus the tool in `sessions`)
or from Claude Code's own transcript, and feed it to the hook directly:

```sh
printf '%s' '{"hook_event_name":"PreToolUse","session_id":"policy-smoke",
  "tool_name":"mcp__ClickUp__clickup_filter_tasks","tool_input":{}}' \
  | mcp-recorder hook --policy .claude/policy.json --data-dir /tmp/policy-smoke
```

A matching rule prints exactly one line:

```json
{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"mcp-recorder policy: bulk task reads are blocked"}}
```

Empty output means the call was allowed — the rule does not match that name.
(The smoke test records the synthetic call like any other, which is why it
points at a throwaway `--data-dir`.) After a real session,
`grep -c '"policy_denied"' events.jsonl` in an
unzipped bundle (or a `query` for the call) says whether the deny fired for
real, and that check is worth doing once per policy you rely on.

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
