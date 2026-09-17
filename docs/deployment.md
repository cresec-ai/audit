# Deployment: what this looks like inside a customer

How `@edut/mcp-recorder` actually gets installed, per agent platform, and what
the customer holds, sees and loses on each one. [docs/install.md](install.md)
is the per-client walkthrough (config paths, Windows, WSL, uninstall); this
page is the layer above it: which platforms can be covered at all, how a
platform reaches a fleet rather than one laptop, what breaks each one, and in
what order a security team should roll it out.

**[docs/connector-coverage.md](connector-coverage.md) is the authority** on
what each surface exposes and what needs Anthropic. It has been publicly
corrected twice for claiming coverage the evidence did not support. This page
applies its conclusions; it does not extend them. Where the two disagree, that
page wins and this one is wrong.

## How to read this page

Every platform row carries how we know it.

| Marking | Means |
| --- | --- |
| **Live** | Observed in a real session, against a real client, with an artifact you can check. The run is named. |
| **Tested** | Run here against the real binary, or covered by the test suite. No live third-party session. |
| **Inferred** | From Anthropic's or a vendor's documentation, read but not re-verified by us. |
| **None** | We have no evidence at all. Nothing on this page is generalised from Claude Code to a platform we have not run. |
| **New** | Part of the evidence-sink work landing alongside this document. No live session has used it yet. |

**Check your build before relying on anything marked New.** If
`mcp-recorder ship --status` is not a command your install has, or your install
ignores `MCP_RECORDER_SINK`, the sink is not in it: everything marked **New**
here is design, and `mcp-recorder export` is still the only transport. Nothing
else on this page depends on it.

**Live evidence exists for one family of surfaces: Claude Code.** Five cloud
dogfood runs (`evidence/cloud-dogfood-1` … `-5`) and this repository's own
continuously-recorded sessions are all Claude Code. For Claude Desktop chat,
claude.ai web, Cowork, Codex, Cursor and the Copilot coding agent we have
configuration files, vendor documentation and reasoning — and no recorded
session. Those rows say so.

## The three things being deployed

They are separable, and a customer can stop after any one of them.

1. **The tap** — where traffic is observed. Either Claude Code hook entries in
   a settings file, or a client's MCP config rewritten so each stdio server
   launches through `mcp-recorder record`, or both. Nothing else in this
   project is a tap.
2. **The store** — a data directory (`~/.mcp-recorder` by default) holding the
   hash-chained evidence and one ed25519 identity. The directory is created
   `0700` and `identity.key` is `0600`; a directory that already existed is
   left as you made it and gets one warning on stderr if it is group- or
   world-accessible. This is the source of truth and stays so.
3. **The transport** — how evidence leaves the machine. Today: `export` writes
   a signed zip and a human moves it. **New:** `MCP_RECORDER_SINK` plus a
   background `mcp-recorder ship` process replicates the sealed chain to a
   receiver within seconds. See [Why not commits](#why-not-commits).

Optional and orthogonal: **the policy** — `hook --policy` (deny a Claude Code
tool call before it runs) or `record --policy` (gateway mode over a wrapped
stdio server). Enforcement is fail-closed. Recording, and the sink, are
fail-open. The two never share a code path or a timeout budget.

---

## The minimum install

One command, and one environment variable that is the entire opt-in — plus a
second carrying the token, which is deliberately not folded into the URL:
userinfo in a URL leaks into process listings, shell history and error
strings. Concretely, on a machine that already has Node >= 20 and
`mcp-recorder` on `PATH`
(`npm install -g github:cresec-ai/audit#main` — see
[docs/install.md](install.md#install-the-cli)):

```sh
# 1. the sink: setting the URL is the entire opt-in                      [New]
export MCP_RECORDER_SINK=https://sink.example.com
export MCP_RECORDER_SINK_TOKEN=<install token>   # or MCP_RECORDER_SINK_TOKEN_FILE=/etc/mcp-recorder/token

# 2. the tap: one command, one settings file
mkdir -p .claude          # see the gotcha below — hook install does NOT create it
mcp-recorder hook install --data-dir /opt/mcp-recorder/data
```

There is no `MCP_RECORDER_SINK_ENABLED`. Absent `MCP_RECORDER_SINK`, there is
no sink and no shipper, and behaviour is byte-identical to today's. A
malformed sink URL is a warning and a disabled sink, never a failed proxy
start — the same way an invalid `--redact` is handled.

`hook install` is idempotent, takes a timestamped backup, preserves every
other key in the file, and `--undo` removes exactly what it added. It writes
one `hooks` block, and that block registers five events. This is the real
output of the command, with `--command` used to show the published-binary
form:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "mcp__.*",
        "hooks": [
          { "type": "command", "command": "mcp-recorder hook --data-dir /opt/mcp-recorder/data" }
        ]
      }
    ],
    "PostToolUse":        [ { "matcher": "mcp__.*", "hooks": [ { "type": "command", "command": "…same…" } ] } ],
    "PostToolUseFailure": [ { "matcher": "mcp__.*", "hooks": [ { "type": "command", "command": "…same…" } ] } ],
    "SessionEnd":         [ { "hooks": [ { "type": "command", "command": "…same…" } ] } ],
    "Stop":               [ { "hooks": [ { "type": "command", "command": "…same…" } ] } ]
  }
}
```

(`PostToolUse` through `Stop` are written out in full by the command; they are
abbreviated here only to fit. The default command is absolute —
`"/path/to/node" "/path/to/dist/cli.js" hook --data-dir …` — so the hook works
regardless of the shell's cwd or `PATH`.)

**Two facts to budget for, both checked here against the real binary:**

- **`hook install` does not create `.claude/`.** In a directory without it the
  command exits **2**, writes nothing, and prints one line. This does not match
  [docs/hooks.md](hooks.md#install) ("created if missing"), and it has never
  bitten a dogfood because this repository already has a `.claude/`. Put
  `mkdir -p .claude` in your rollout script.

  ```
  $ mcp-recorder hook install
  [mcp-recorder] error: ENOENT: no such file or directory, open '…/.claude/settings.json.tmp-363eb4a2dd51'
  $ echo $?
  2
  ```

- **Claude Code snapshots hooks at session start.** Installing mid-session does
  nothing until the next session. This cuts both ways: an agent cannot
  uninstall the hook out from under a running session either.

Then confirm, in the session *after* the install:

```
$ mcp-recorder sessions --data-dir /opt/mcp-recorder/data
$ mcp-recorder verify  --data-dir /opt/mcp-recorder/data
$ mcp-recorder ship --status     # [New] sink URL, key fingerprint, chain_id, local head,
                                 # receiver next_seq, attested_seq, lag, last error, last success
```

That is the whole install for a Claude Code surface. Wrapping local stdio MCP
servers (`mcp-recorder setup --client …`) is a second, independent step, needed
only when you also want the full JSON-RPC of a server you run yourself, or
gateway-mode enforcement over it.

---

## Platform by platform

The short form first. "Stop a call" means block it **before** it executes.

| Platform | What the install is | Fleet reach | Stop a call? | How we know |
| --- | --- | --- | --- | --- |
| Claude Code CLI | Hook entries in a settings file; optionally an MCP config rewrite | Managed settings pushed by MDM | **Yes** — `hook --policy` | **Live** for the tap (this repository's own 651-event chain), but every artifact we keep is from a cloud or remote session; managed settings **Inferred** |
| Claude Code IDE extension | Same settings files | Same | **Yes** | **Inferred** |
| Claude Code — Desktop "Code" tab | Same settings files | Same | **Yes** | **Inferred** |
| Claude Code cloud sessions | Hook entry committed in the repo's `.claude/settings.json`; env vars in the environment config | Every session started from that repo or branch | **Yes** — proven live | **Live** (dogfood 5: two rule shapes, four blocked ClickUp calls) |
| Claude Code Agent SDK | Nothing ships today — no adapter exists | — | Would be, with a shim | **None** (SDK hook callbacks: **Inferred**) |
| Claude Desktop chat | MCP config rewrite of local stdio servers; `--bridge` for a vendor with a public MCP endpoint | None we know of | **Yes**, wrapped servers only (gateway mode) | **Tested**; bridge **Experimental** |
| claude.ai web | **Nothing to install** | — | **No** | **Inferred** (connector-coverage) |
| Cowork | **Unknown — treat as not covered** | — | **No** | **None**; the probe has not been run |
| Codex CLI | MCP config rewrite in `.codex/config.toml` (trusted projects only) | Per repo, per-user trust; no managed push known | **Yes**, wrapped servers only | **Tested** (config committed here); never run live |
| Codex cloud | Setup script installs the CLI; no stdio MCP to wrap | — | **No** | **Inferred** |
| Cursor (local) | MCP config rewrite (`setup --client cursor`) | None we know of | **Yes**, wrapped servers only | **Tested**; never run live |
| Cursor (cloud agents) | Dashboard MCP entry + `.cursor/environment.json` install step | Per project, from the dashboard | **Yes**, wrapped servers only | **Tested** (config documented); never run live |
| Copilot coding agent | Repository/org MCP settings entry + `copilot-setup-steps.yml` | Repository and organisation settings | **Yes**, wrapped servers only | **Tested** (config documented); never run live |

### Claude Code — CLI

**How we know: Live.** The hook tap has run in real Claude Code sessions
continuously on this repository. The dogfood store as this page was written:

```
$ mcp-recorder verify --data-dir .mcp-recorder
verify store .mcp-recorder/evidence.db (sqlite)
pinned signer: ed25519 4df5a615355855b9… (.mcp-recorder/identity.pub)
PASS — chain intact: 651 event(s), head seq 651
signed head: seq 651 by ed25519 4df5a615355855b9… at 2026-09-17T06:41:29.949Z

$ mcp-recorder sessions --data-dir .mcp-recorder
SESSION   STARTED                   ENDED       SERVER       EVENTS  TOOL_CALLS  ERRORS  SERVERS  DECISIONS  LAST_EVENT
566b8a54  2026-09-15T16:08:39.130Z  (reopened)  claude-code  421     172         2       3        0          2026-09-17T06:41:29.945Z
```

(trimmed: the 44 other rows, all proxy sessions from the two servers this
repository wraps in its own `.mcp.json`; data-directory paths shortened, the
run passed an absolute `--data-dir`.) One hook-sourced session of 421
events and 172 tool calls across three servers, interleaved into the same chain
as those proxy sessions — which is also live evidence that a Claude Code client
launches a recorder-wrapped stdio entry out of a project `.mcp.json` and
records it. **The caveat worth stating:** every artifact this repository keeps
comes from a cloud or remote Claude Code session. A laptop CLI install runs the
identical binary against the identical settings file, and we keep no recorded
artifact of one.

- **What the install is.** Hook entries in one of Claude Code's settings files:
  a project `.claude/settings.json`, the user-level `~/.claude/settings.json`,
  a `.claude/settings.local.json`, or an enterprise **managed settings** file.
  Optionally `mcp-recorder setup --client claude-code` also rewrites
  `.mcp.json` / `~/.claude.json` so locally configured stdio servers launch
  through the recorder.
- **Fleet reach.** Managed settings, deployed by MDM to a path the user cannot
  write, plus `allowManagedHooksOnly` so a user's own hooks cannot run
  alongside. Anthropic documents the managed-settings path as
  `/Library/Application Support/ClaudeCode/managed-settings.json` (macOS) and
  `/etc/claude-code/managed-settings.json` (Linux); take the Windows path from
  Anthropic's own documentation rather than from here. **Inferred** — we have
  never deployed one. `disableClaudeAiConnectors` and allowed/denied MCP server
  lists are the same lever set.
- **What it sees.** Every `mcp__*` tool call, before it runs and again after:
  tool name, hashed arguments, hashed result or hashed error string,
  `duration_ms` measured across the two hook processes, and `server.url` when
  connector resolution succeeds. With `--all-tools`, built-ins (`Bash`,
  `Edit`, `Read`) too. For servers wrapped with `record`, the full JSON-RPC in
  both directions.
- **What it cannot see.** The Anthropic-to-vendor hop for hosted connectors —
  that call is made from Anthropic's infrastructure on every surface, and no
  proxy of ours is on it. What a `Bash` command does once it has started.
  Anything in a session that began before the hook was installed. Any tool call
  Claude Code does not route through a hook.
- **Stop a call: yes.** `hook --policy` denies before the tool runs. Read
  [docs/hooks.md](hooks.md#write-deny-rules-against-the-tool-not-the-server-segment)
  first: in dogfood 4 two deny rules aimed at a platform-controlled name
  segment both silently missed and both live calls executed. Write
  `^mcp__.*__<tool>$`, and smoke-test it.
- **What the customer holds.** The settings file, the data directory and its
  ed25519 key, and — with the sink — a bearer token. No repository, no CA, no
  account. `NODE_EXTRA_CA_CERTS` only if their egress proxy terminates TLS;
  certificate verification is never disabled.
- **What breaks it, and how they notice.** Node missing or `PATH` wrong (the
  generated command is absolute, so this mostly bites hand-written entries);
  someone edits the hook out of the settings file; a session that started
  before the install; `MCP_RECORDER_DISABLE=1` in the environment (recording
  stops — a `hook --policy` deny still fires); the data directory deleted.
  Noticed through: a frozen head at the receiver while heartbeats continue,
  `ship --status`, `verify`, and `sessions` gaining no new rows.

### Claude Code — IDE extension and the Desktop "Code" tab

**How we know: Inferred.** Same binary, same settings files, same hook contract
as the CLI, per Anthropic's documentation and
[docs/connector-coverage.md](connector-coverage.md). We have run neither.
Everything in the CLI section applies unchanged *if* that documentation is
right. If a customer's assurance case rests on one of these two, test it before
claiming it.

### Claude Code — cloud sessions (Claude Code on the web)

**How we know: Live**, and this is the best-evidenced surface in the project.
Dogfood 5 (`evidence/cloud-dogfood-5`: 46 events, `verify --bundle` and the
bundle's own `verify.cjs` both PASS) ran a cloud session with the hook
installed at session start and a two-route deny policy: both routes fired,
neither ClickUp call reached the workspace, and gateway mode denied `http_post`
through a real agent for the first time. Dogfood 4 is the counter-example and
is required reading: same mechanism, both deny rules missed, both live calls
executed, and zero policy decisions inside a 62-event bundle that verifies
PASS.

- **What the install is.** The hook entry committed in the repository's
  `.claude/settings.json` — the same entry `hook install` writes — plus
  `.mcp.json` wrapping for repository-declared MCP servers, plus (with the
  sink) two environment variables in the environment configuration. Nothing is
  installed on any machine; the container is built from the repository.
- **Fleet reach.** Every cloud session started from that repository or branch,
  automatically. That is genuine reach with a genuine limit: the hook entry
  lives in a file inside the repository, which the agent can also edit. Hooks
  are snapshotted at session start, so an edit cannot take effect mid-session —
  but it does in the next one, unless the branch is protected.
- **What it sees.** Anthropic-hosted connector calls, which in a cloud session
  are frequently named by opaque UUID rather than by vendor
  (`mcp__47d587b8-…__clickup_get_list`). `server.url` is recovered best-effort
  from `/tmp/mcp-config-<session>.json`; that file is world-writable and the
  agent has `Bash`, so it is a claim, not a boundary. See
  [docs/hooks.md](hooks.md#cloud-sessions-uuid-server-names-and-serverurl).
- **What it cannot see.** The vendor hop. And there is no Anthropic-side
  backstop on this surface: the Compliance API explicitly does not cover Claude
  Code on the web [Inferred, connector-coverage].
- **Stop a call: yes**, proven live in dogfood 5.
- **What the customer holds.** The repository, the environment configuration
  and a token. Note what that means: on this surface the control point is a git
  branch — exactly the coupling the sink removes for *evidence*, still true for
  *configuration*.
- **What breaks it, and how they notice.** The container is reclaimed before
  `SessionEnd` fires, leaving the session `(open)` and pending markers behind
  (swept after 24 h). Egress blocked: the shipper sends nothing, and the
  receiver's absence alert is the only signal. **Two hard requirements on this
  surface**, or cloud sessions ship nothing: the shipper must honour
  `HTTPS_PROXY`/`NO_PROXY`, and must trust the agent proxy's CA through
  `NODE_EXTRA_CA_CERTS` rather than disabling verification. Egress from a cloud
  session to an external host is confirmed working, so this is viable here and
  not only on a laptop.

### Claude Code — Agent SDK

**How we know: None.** Anthropic documents the SDK's hooks as in-process
callbacks carrying the same payloads, plus `canUseTool` [Inferred]. But
`mcp-recorder hook` is a CLI that reads one JSON object on stdin, and **no
adapter for the SDK exists in this repository**. An SDK application would have
to shell out to the binary from its own hook callback, or the recorder would
need a small library entry point. Neither is written and neither is tested.
**What the customer holds: nothing of ours**, unless they write that shim
themselves — in which case they hold it. Do not sell this surface.

### Claude Desktop — chat

**How we know: Tested.** `setup` was exercised here — preview, write, undo,
sidecar restore — and the client-path resolution is covered by the suite. It is
**not** Verified: no MCP client process has launched an entry this command
wrote, in this environment or in any artifact this repository keeps.
[docs/red-team.md](red-team.md) is the hand-written walkthrough for doing it
yourself in Claude Desktop.

- **What the install is.** `mcp-recorder setup --client claude-desktop`
  rewrites each stdio server in `claude_desktop_config.json` to launch through
  the recorder, with a timestamped backup and a sidecar so `--undo` restores
  the exact originals. On Windows it also finds a Microsoft Store (MSIX)
  install. Fully quit and restart the app afterwards — closing the window is
  not enough.
- **Fleet reach: effectively none.** The config is a per-user file in the
  user's profile. An MDM could template it, but Anthropic offers no managed MCP
  configuration for Desktop chat that we know of, and the org-level connector
  policy that does exist is enforced on Anthropic's side, not by us.
- **What it sees.** Only local stdio servers, plus remote endpoints you replace
  with a local `mcp-remote` bridge (`setup --bridge`, **Experimental**; the
  user must re-authorise through the bridge, and the bridged server is then
  available only in Claude Desktop).
- **What it cannot see.** Remote connectors added in Settings → Connectors —
  an OAuth flow to an endpoint Anthropic's backend calls, with nothing local to
  sit in front of. Desktop Extensions (`.mcpb`) are local but `setup` does not
  wrap them yet. Chat content, always.
- **Stop a call:** yes for wrapped servers, through gateway mode
  (`setup --policy`). Nothing for connectors.
- **What the customer holds.** A per-user config file, the data directory and
  its key, and — with the sink — a token. No repository and no CA. There is no
  central artifact anyone can point at, which is the honest reason this surface
  does not scale past a handful of machines.
- **What breaks it, and how they notice.** The user adds a remote connector
  instead of a local server, and it is simply invisible — the most common
  silent failure on this surface. Or they forget the restart. It is noticed by
  running `sessions` and finding the server missing, not by any error.

### claude.ai web

**How we know: Inferred, and the answer is nothing.** There is no local process
and no hook mechanism. The only customer-side feeds are Anthropic's own —
inference hooks (beta, Enterprise), the Compliance API (Enterprise), the
activity feed, OpenTelemetry — and this project has **no receiver for any of
them**; that is option D in
[docs/connector-coverage.md](connector-coverage.md) and it is not started. None
of them can block a connector call before it runs; the user-facing "needs
approval" prompt is the only per-call gate, and it is Anthropic's.

**What the customer holds: nothing of ours.** They hold an Anthropic
Enterprise contract, or no visibility at all. Say it to a buyer plainly: on
claude.ai web we install nothing, see nothing and stop nothing today.

### Cowork

**How we know: None, and the evidence points the wrong way.** An earlier draft
of [docs/connector-coverage.md](connector-coverage.md) inferred that Claude
Code hooks fire in Cowork, and was corrected. Anthropic's documentation says
Cowork does not read the Claude Code CLI's `~/.claude` directory; two community
issues on `anthropics/claude-code` (#63360, #77708) report empirically that
hooks do not fire there. Neither is conclusive, neither is about this tool, and
**the read-only probe that would settle it has not been run** — run one
connector call inside Cowork in a directory containing this repository and
check whether `.mcp-recorder` gains anything.

Until then Cowork is a blind spot. Whether a local stdio MCP server configured
inside Cowork could be wrapped is equally untested. **What the customer holds:
nothing of ours.** Do not put Cowork in a coverage table as covered, and do not
infer it from Claude Code.

### Codex — CLI

**How we know: Tested.** This repository ships a `.codex/config.toml` that
wraps its two demo servers through `scripts/dogfood-wrap.sh`, so the
configuration shape is real and committed. No Codex session's evidence exists
here, and cross-tool verification for Codex is still an open task.

- **What the install is.** An MCP config rewrite: each `[mcp_servers.*]`
  entry's `command`/`args` launches the recorder, which launches the server.
  `startup_timeout_sec` needs headroom on a first run that installs
  dependencies.
- **Fleet reach.** Per repository, and only for a project the user has marked
  trusted in `~/.codex/config.toml`
  (`[projects."/abs/path"] trust_level = "trusted"`). We know of no managed
  push. This is a developer-opt-in surface, not a fleet surface.
- **What it sees.** Full JSON-RPC for the stdio servers it wraps, and nothing
  else — Codex's own model traffic, its built-in tools and any platform-side
  connector are all outside it.
- **Stop a call:** yes, for wrapped servers, through gateway mode. There is no
  third-party pre-execution hook on Codex that this project uses.
- **What the customer holds.** A repository file, a per-user trust entry, the
  data directory and its key, and — with the sink — a token. No CA.
- **What breaks it, and how they notice.** The project is not trusted, the
  config is ignored, and nothing is recorded — a silent no-op with no error.
  Check `sessions` after a first call; absence is the only symptom.

### Codex — cloud

**How we know: Inferred.** The environment's Setup script can install the
recorder (`sh scripts/bootstrap.sh`), but per
[docs/install.md](install.md#cloud-coding-agents) stdio MCP servers are not
supported there today, so there is nothing to wrap and no tap. An HTTP MCP
server could in principle be fronted with `mcp-recorder http`, but that means
hosting a proxy and we have never done it for this platform. **What the
customer holds: nothing of ours.** Treat as not covered.

### Cursor

**How we know: Tested.** `setup --client cursor` resolves and rewrites
`~/.cursor/mcp.json`, this repository commits a `.cursor/mcp.json` and a
`.cursor/environment.json`, and none of it has been exercised by a live Cursor
session whose evidence we keep.

- **What the install is.** Local: an MCP config rewrite. Cloud agents: the MCP
  server is configured in the Cursor dashboard (stdio form in
  [docs/install.md](install.md#cloud-coding-agents)), with
  `.cursor/environment.json`'s `install` step putting the recorder in place.
- **Fleet reach.** Per user (local) or per project (dashboard). We know of no
  managed push for either.
- **What it sees / cannot see.** The stdio servers it wraps, fully; Cursor's
  own agent tools and any platform-side connector, not at all.
- **Stop a call:** yes for wrapped servers, gateway mode only. Cursor documents
  an agent-hooks mechanism of its own [Inferred, vendor documentation, not
  re-verified by us]; **nothing in this repository targets it, we have not
  tested it, and no coverage should be claimed from it** until someone does.
- **What the customer holds.** A per-user config file or a dashboard entry, the
  data directory and its key, and — with the sink — a token. No CA. On cloud
  agents, also whatever egress allowlist the platform applies.
- **What breaks it, and how they notice.** A config edited in the dashboard
  rather than in the repository drifts silently from what the repository says.
  Same detection as everywhere: no new sessions, no heartbeat.

### GitHub Copilot coding agent

**How we know: Tested.** The MCP settings JSON and
`.github/workflows/copilot-setup-steps.yml` are documented and committed; no
Copilot session has been recorded.

- **What the install is.** Two repository settings: the MCP servers JSON
  (Settings → Copilot → MCP servers) wrapping each `type: local` server through
  the recorder, and the `copilot-setup-steps` workflow on the default branch to
  install dependencies.
- **Fleet reach.** Repository and organisation settings — the best fleet story
  of the non-Claude platforms, because both are admin-controlled rather than
  user-controlled.
- **What it sees / cannot see.** The MCP servers the repository declares.
  **Not** the platform's own tooling: GitHub's built-in agent tools do not pass
  through anything a repository can configure, so a Copilot agent's GitHub
  operations are invisible to us.
- **Stop a call:** yes for wrapped servers, gateway mode only.
- **What the customer holds.** Repository and organisation settings, a
  workflow file, and — with the sink — a token, plus a sink host on the
  runner's egress allowlist. No CA, and no data directory that outlives the
  run: on this platform the evidence must leave the runner or it is gone.
- **What breaks it, and how they notice.** The runner is ephemeral, and its
  egress may be restricted by the platform's own firewall, so a sink host that
  is not allowlisted means a whole run's evidence never leaves. On a short-lived
  runner, add a final `mcp-recorder ship --drain --timeout 30s` step — and make
  it `continue-on-error` / `|| true`, because a sink outage must never fail a
  customer's build. That is the fail-open rule applied to CI. Until the shipper
  is in your build, `mcp-recorder export` plus a workflow artifact is the
  reliable route.

---

## Why not commits

Today evidence reaches us by being committed to a branch: a session runs
`mcp-recorder export`, writes `incident.zip`, commits it under
`evidence/cloud-dogfood-N/` and pushes. Five branches exist that way, each with
a `REPORT.md` and a bundle that verifies.

**Why that was right for dogfooding.** It needed no infrastructure at all. It
worked from a sandboxed cloud container that already had git credentials. And
the bundle is self-verifying — a hash chain plus an ed25519 head signature,
checkable with a dependency-free `verify.cjs` — so the transport never had to
be trusted. Anyone can re-verify dogfood 5's bundle off the branch today.
`export` is not going away: it remains the right artifact to hand to a third
party, an auditor or a court.

**Why it is not a product.** Four reasons, each independently disqualifying.

1. **It needs a repository and a push credential.** Every install would need
   write access to somewhere — a credential we would be asking the customer to
   hand to the agent under observation. Our own dogfooding hit exactly this:
   one run could not push at all, because GitHub write access was denied to
   both the git remote and the API.
2. **It is batch, not live.** The bundle is written at the end. A container
   reclaimed mid-session, a laptop lid, a `SIGKILL` — and nothing ships. The
   evidence that matters is usually the last thing before the kill.
3. **It needs a human to remember to look.** Nothing alerts. A branch that
   never appears looks exactly like a branch nobody has read yet. There is no
   detector for "this install went quiet".
4. **The agent under observation controls delivery.** It runs `export`, it runs
   `git push`, it chooses the range and the moment. Evidence whose delivery the
   observed party controls is not evidence.

The sink replaces the transport and nothing else: the same sealed records, the
same signatures, shipped continuously to a receiver the observed agent does not
control. The local store stays the source of truth; the receiver is a replica.

---

## Where the evidence lands, who can read it, and what the sink changes

### Where it lands

| | What is there | Who can read it |
| --- | --- | --- |
| **Local data dir** (`~/.mcp-recorder`, or `--data-dir`) | `evidence.db` / `evidence.jsonl`, `identity.key` (0600), `identity.pub`, plus `hook-pending/`, `hook-sessions/` and `holds/` when in use. Directory created 0700. | Any process running as that uid — **including the agent**, on a machine where the agent runs as the same user. |
| **The receiver** (**New**) | A replica of the sealed chain, plus a `received_at` beside every record — the only metadata the sender does not control. | Whoever operates the receiver. |
| **A bundle** (`export`) | `events.jsonl`, `manifest.json`, `public_key.pem`, `verify.cjs`, `README.txt`. | Whoever you hand it to. |

**What any reader gets is structure, not content.** Every string leaf and every
object key is replaced by `sha256:<hex>` plus a length before anything is
written. A reader sees which tool was called, on which server, when, whether it
failed, and how the calls chain together — never the arguments or the results.
Someone who already holds a candidate value can confirm it was seen, with
`query`. This is also why the sink can be a plain replica: **records ship
verbatim as sealed**, because altering anything inside `event` would break
`record.hash` and fail verification at the receiver. There is no second
redaction pass on the wire, and no opportunity for one.

Event `timestamp` is `Date.now()` on the observed machine — a claim, not a
clock. The receiver's `received_at` is the only trustworthy time in the system.

### Who the receiver trusts, and what a stolen token buys — **[New]**

Two layers, with two different jobs, and collapsing them is the mistake this
design exists to avoid.

- **The bearer token** authorises the *channel*: may this connection write to
  this tenant at all. It is rotatable and revocable server-side, and on an
  unsegregated laptop the observed agent can read it.
- **The data directory's existing ed25519 identity** authenticates the
  *content*. It is the same key that already signs every chain head and that
  `verify` already pins. Every request carries the public key plus a detached
  signature, and the receiver files records under the **key**, never under the
  token.

So a stolen token cannot write into another install's chain (that needs the
other install's private key), cannot forge events that verify (the receiver
recomputes every record hash and checks every signature), and cannot delete
history (the API has no DELETE, no PUT and no PATCH, and the commit is
insert-if-absent). What it does buy is nuisance: creating new chains under the
attacker's own key if the tenant permits open enrolment, reading a cursor for a
`chain_id` they already know (`next_seq` and a head hash — never content), and
burning rate limit.

**Enrolment, the operator's choice of two modes**, and it is the choice that
decides how much the token matters:

- **PINNED** — the operator registers each install's public key out of band; it
  is in `identity.pub`. An unknown key is refused. The right default for a
  managed fleet, and what the stage-3 gate above means.
- **TOFU** — the first key seen on a token is bound to it; later keys on the
  same token are accepted but flagged and do not count as attested until an
  operator acknowledges. Pragmatic for a laptop or self-serve rollout, and the
  operator still gets the signal.

### What happens when the sink is down

Nothing, to the agent. This is the house rule and it is not negotiable:
recording is fail-open, and a sink that is down, slow, unreachable or returning
errors must never block a tool call, deny one, change the proxy's stdout bytes,
or make it exit non-zero. The shipper is a separate process; it never runs on
the forwarding path.

| Condition | Local store | Agent experience | What the receiver sees |
| --- | --- | --- | --- |
| Unreachable / DNS / TLS failure | Untouched, keeps growing | Nothing | No records, no heartbeat → **absence alert** |
| Slow | Untouched | Nothing | Lag, quantified and signed by the sender's own key |
| 500 | Untouched | Nothing | Absence, then the whole backlog on reconnect |
| 401 / 403 | Untouched | Nothing; one stderr line | Absence — an install that cannot authenticate looks exactly like one that was switched off, which is correct |
| Shipper killed | Untouched | Nothing | Absence |
| Disk full | The existing fail-open path: retry, then count the drops | Nothing | A **counted** drop, reported in `SessionEnd.events_dropped`, and that event itself ships |

Nothing is ever dropped from the local store because of the sink; the backlog
is bounded only by disk, and on reconnect it ships from the receiver's own
cursor rather than from anything the sender believes. Every POST also carries a
signed statement of the sender's current local head, so "delivered versus
sealed" is a subtraction attested by the sender's own key.

**The receiver must alert on missing heartbeats.** That is a contract
obligation, not a feature: a receiver that does not alert on silence has not
implemented this design, and every "the agent turned it off" case below
degrades to silence.

### Can the agent disable it?

**On an unsegregated machine: yes, in several ways, and you should know each
one and what it looks like from the receiver.** The recorder sees what is
routed through it; on a laptop the agent controls the routing, runs as the same
uid, and can read the signing key.

| What the agent can do | Effect | What the receiver sees | What actually closes it |
| --- | --- | --- | --- |
| `MCP_RECORDER_DISABLE=1` | Recording stops (a `hook --policy` deny still fires) | Heartbeats continue, head stops advancing — a live install with a frozen chain | Pin the environment outside the agent's reach |
| Delete the hook entry from `.claude/settings.json` | No tap from the next session on | The same frozen-head signature | Managed settings, on a path the agent's uid cannot write |
| Edit `.mcp.json` to drop the wrapper, or call the MCP server directly | That server is unrecorded | Frozen or thinned chain | Managed MCP configuration; deny arbitrary egress from the agent's uid |
| Point `MCP_RECORDER_SINK` at its own collector | The real receiver gets nothing | **Absence** | Pin the config; allowlist only the sink host |
| Kill the shipper | Backlog stops shipping | **Absence** | A supervisor (systemd/launchd) the agent's uid cannot signal |
| Delete `evidence.db`, keep `identity.key` | A fresh chain starts at seq 1 | A **second `chain_id` for an enrolled key** — a loud event, not a silent reset | This is exactly why `chain_id` is the seq-1 hash and not the public key |
| Read `identity.key` and sign a forged history | A clean parallel chain that verifies | **Nothing** — this is the one case it cannot detect | Run the agent as a different, less-privileged uid; or a hardware-backed key |

**The claim we do not make, verbatim:** the recorder does not prove what an
agent *did*. It proves what *reached the chain*, and that what reached it has
not been altered since. On an unsegregated machine, an agent that owns the
signing key can also author the chain. The sink's contribution is narrower and
still valuable: it makes the record durable off-box within seconds, makes
editing it detectable, and makes withholding and silence measurable.

### What the customer must do at OS or fleet level

In rough order of value. Only the first closes the forged-chain case.

1. **Run the agent as a different, less-privileged user than the recorder.**
   `identity.key`, the data directory and the sink configuration must be
   unreadable and unwritable by the agent's uid — a dedicated `mcp-recorder`
   user, or the recorder behind a socket the agent may only write to. This is
   in tension with the default (`~/.mcp-recorder`, 0700, under the agent's own
   user), and that default is for visibility, not adversarial assurance.
2. **Pin the configuration outside the agent's reach.** Sink URL and token in a
   root-owned MDM profile, a systemd `Environment=` or a launchd plist — not a
   shell profile and not a repository file. For Claude Code, the
   managed-settings path rather than `.claude/settings.json`, which the agent
   can edit.
3. **Make the shipper non-optional.** A supervisor restarts it and the agent's
   uid cannot signal it. A killed shipper then means a killed machine, which is
   a different and louder alert.
4. **Alert on absence.** An enrolled install with no heartbeat for N intervals
   is an incident. Without this, the whole design is opt-in on the attacker's
   side.
5. **Control egress.** Allow the sink host, deny arbitrary egress from the
   agent's uid, so "ship to my own collector" is a blocked connection rather
   than a silent success.
6. **Hardware-backed keys** if the forged-chain case must be closed
   cryptographically rather than operationally. A TPM/Secure Enclave/YubiKey
   key is unexportable, so a compromised agent can sign while it is running but
   cannot forge history offline or on another machine. Not what ships.

One sentence for the fleet section of any proposal: **the threat-model claims
hold only in the configuration where 1, 2, 3 and 4 are all true.** On a laptop
where the agent runs as the operator, this configuration buys visibility, not
adversarial assurance, and the documentation should say so where the customer
will read it.

---

## A rollout order a security team will accept

Observe first, then enforce. Each stage has an exit criterion checked against
recorded evidence, never against "the session finished".

**Stage 0 — inventory (half a day).** List the surfaces actually in use. Write
down now, in the rollout plan, that claude.ai web, Claude Desktop chat and
Cowork are *not covered* — rather than discovering it at stage 3. Then decide
which covered surface carries the most risk; it is usually the one with
write-capable connectors.

**Stage 1 — observe, one team, no policy (about two weeks).** `hook install`
with no `--policy`, plus the sink in TOFU enrolment. No deny rules at all. Exit
criteria: heartbeats arriving from every enrolled install; `verify` PASS both
locally and at the receiver; `sessions` rows that match what people say they
did; no measurable latency complaint. Rollback is `hook install --undo`,
`setup --undo`, and unsetting one environment variable.

**Stage 2 — prove the record rather than assuming it (one day).** Run a
deliberate incident — [docs/red-team.md](red-team.md) is the scripted one — and
then verify the evidence end to end: `export` a bundle, hand it to someone who
was not in the session, and have them verify it with `--public-key` obtained
out of band. A bundle checked against its own manifest proves internal
consistency and nothing more.

**Stage 3 — pin (one to two weeks).** Move keys to PINNED enrolment. Move the
sink URL and token into managed configuration. Move the hook entry into managed
settings. Split the uid. Turn on absence alerting and page a human with it.
Exit criterion: an install whose agent deletes the hook entry produces an
alert, and you have watched that alert fire in a drill.

**Stage 4 — enforce, in the narrowest possible band (one to two weeks).** Deny
rules only for destructive operations (`*_delete_*`, `trash_*`, outbound mail),
anchored to the tool with the server segment left open. **Smoke-test every rule
before trusting it** — a policy that never fires looks exactly like a policy
with nothing to block, which is the whole of the dogfood-4 lesson:

```sh
printf '%s' '{"hook_event_name":"PreToolUse","session_id":"policy-smoke",
  "tool_name":"mcp__ClickUp__clickup_delete_task","tool_input":{}}' \
  | mcp-recorder hook --policy .claude/policy.json --data-dir /tmp/policy-smoke
```

A matching rule prints one `permissionDecision: "deny"` line; empty output
means it does not match that name. Exit criterion: for each rule you intend to
rely on, one deny observed in recorded evidence
(`grep -c '"policy_denied"'` over an exported bundle), not merely a session
that appeared to behave.

**Stage 5 — widen slowly, and keep counting both shapes.** Gateway mode for
locally wrapped servers, if you run any. Remember that the two enforcement
paths record a denial differently: the gateway emits a `policy_decision` event
*and* a `tool_call`; the hook emits only the `tool_call` with
`error.type: "policy_denied"`; and `sessions`' `DECISIONS` column counts only
the former. Any "how much did we block?" query must handle both shapes.

**What not to do:** do not start at stage 4. An enforcement rollout that has
not first proved observation cannot tell a rule that is working from a rule
that never matched — which is precisely what happened in dogfood 4, where the
only symptom of total enforcement failure was a zero count nobody was looking
at.

---

## Where to read next

- [docs/install.md](install.md) — per-client config paths, Windows and WSL,
  uninstall, troubleshooting.
- [docs/connector-coverage.md](connector-coverage.md) — the authority on what
  each surface exposes and what needs Anthropic.
- [docs/hooks.md](hooks.md) — the Claude Code tap in detail: what is recorded,
  connector resolution, and how to write a deny rule that holds.
- [docs/gateway.md](gateway.md) and [docs/policy.md](policy.md) — enforcement
  over a wrapped stdio server.
- [docs/overview.md](overview.md) — what changes on a machine once this is
  installed, and what it costs.
- [docs/red-team.md](red-team.md) — the incident drill for stage 2.
