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
front of them.

Every tool call Claude Code makes, hosted connectors included, passes
through its **PreToolUse** and **PostToolUse** hooks first. That is the only
place a third party gets both *visibility into* and *control over* those
calls. `mcp-recorder hook` is a hook handler that records what it sees there
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

This merges `PreToolUse`/`PostToolUse` (matcher `mcp__.*`, or `.*` with
`--all-tools`) and `SessionEnd`/`Stop` hook entries into
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
- **PostToolUse** → a second `tool_call` event, sharing the same
  `request_id` (Claude Code's own `tool_use_id`) as the PreToolUse event:
  redacted result, `duration_ms` measured between the two, additive
  `phase: "post"`.
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

Every hook-sourced event carries the additive `source: "hook"` field so it's
always distinguishable from a proxy-captured one — see
[docs/event-schema.md](event-schema.md#hook-sourced-events-additive).

**MCP tool names.** Claude Code presents an MCP tool to hooks as
`mcp__<server>__<tool>` (e.g. `mcp__ClickUp__clickup_get_task`). This is
split: `tool` is recorded as the bare underlying name (`clickup_get_task` —
the same form the stdio/HTTP proxy would have recorded had it seen this
call directly), and the server it went to is stamped on
`server.name` (`ClickUp`). A built-in tool (no `mcp__` prefix) is recorded
with `tool` as the full name (e.g. `Bash`) and `server.name: "claude-code"`.
**Only `mcp__`-prefixed tool calls are recorded by default** — pass
`--all-tools` (to `hook` or `hook install`) to also record built-ins.

**Redaction.** Exactly the same redaction path the stdio/HTTP proxy uses:
tool arguments are hashed unconditionally (`scrubToolArguments`, same as
every other `tool_call.args`), the result goes through the same
position/value-aware allowlist as a proxy-recorded `tool_call.result`, and
`result_hash` is the SHA-256 of the complete raw result before redaction. No
readable payload string from a hook's stdin ever reaches the store.

## Policy: allow / deny

An optional JSON file passed as `--policy FILE` (to `hook` directly, or
baked into the installed command via `hook install --policy FILE`) decides,
per **PreToolUse** call, whether to allow it through or deny it outright —
Claude Code then never runs the tool at all.

```json
{
  "deny": [
    { "tool": "^mcp__ClickUp__clickup_delete_task$", "reason": "destructive ClickUp calls are blocked" },
    { "tool": "^mcp__Gmail__(send_message|trash_.*)$" }
  ],
  "allow": [
    { "tool": "^mcp__github__.*$" }
  ],
  "default": "allow"
}
```

- `tool` is a **regex tested against the full hook `tool_name`** — the same
  string Claude Code's own hook `matcher` field is tested against (e.g.
  `mcp__ClickUp__clickup_delete_task`, or `Bash` for a built-in).
- Evaluated in order: the first matching `deny` rule wins; else the first
  matching `allow` rule; else `default` (itself `"allow"` unless set to
  `"deny"`).
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

Each `PreToolUse`/`PostToolUse`/`SessionEnd`/`Stop` hook invocation is a
fresh, short-lived Node process — Claude Code spawns one per hook event, not
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
- <https://code.claude.com/docs/en/hooks-guide>

Claude Code spawns one process per hook event and feeds it a single JSON
object on stdin, with at least `session_id`, `transcript_path`, `cwd`, and
`hook_event_name`. `PreToolUse`/`PostToolUse` add `tool_name`, `tool_input`,
and `tool_use_id`; `PostToolUse` also adds `tool_response`
(`string | object`). `SessionEnd` adds `reason`
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
