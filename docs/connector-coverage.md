# Visibility and control over Claude's built-in connectors

Decision memo, 2026-09-15. Question: how does `@edut/mcp-recorder` get
visibility into, and control over, the connectors Claude ships with
(ClickUp, GitHub, Gmail, Google Drive, Google Calendar, Slack, ...) on
claude.ai web, Claude Desktop, Cowork and Claude Code, given that none of
them is a local MCP server the recorder can wrap?

Evidence tags used below: **[observed]** was verified directly inside a
Claude Code cloud session on this repository (see `evidence/cloud-dogfood-*`
and the session notes); **[docs]** comes from Anthropic or vendor
documentation read on 2026-09-15 by the research pass and was not
independently re-verified (the refutation pass of that research did not
complete). Where two sources disagree, the disagreement is recorded rather
than resolved.

## Bottom line

- **The connector-to-vendor hop is Anthropic's, on every surface.** For
  claude.ai web, Claude Desktop chat, Cowork and Claude Code cloud sessions
  the call to Google, GitHub, Slack or ClickUp is made from Anthropic's
  infrastructure with OAuth tokens held in Anthropic's vault. No local proxy,
  no network-edge device and no configuration file of ours can sit on that
  hop. Anything "wire level" there needs Anthropic. [observed for Claude Code
  cloud sessions; docs for the other surfaces]
- **Claude Code is the one surface where a third party gets pre-execution
  control.** Its PreToolUse/PostToolUse/PostToolUseFailure hooks fire for every connector tool
  (`mcp__<server>__<tool>`) with the full input and, after the call, the
  response, and a hook can deny or rewrite the call. Hooks committed in a
  repository run in cloud sessions, and organisations can push them to every
  CLI, IDE and Desktop Code-tab session through managed settings. That is
  why `mcp-recorder hook` exists (PR #10): it turns those hooks into
  evidence-chain events with an allow/deny policy. [observed: hooks run in
  cloud sessions; docs: managed settings reach]
- **On claude.ai web, Desktop chat and Cowork, the only customer-side taps
  are Anthropic's own feeds, and they are Enterprise-gated.** Inference hooks
  (beta) deliver each turn's `tool_use`/`tool_result` blocks in real time and
  can stop the next inference but cannot block one tool call before it runs.
  The Compliance API returns transcripts minutes later and cannot block.
  Cowork emits OpenTelemetry events with tool and MCP names and parameters.
  Team plans get org-level per-tool policies (allow / needs approval /
  blocked) and nothing per call. [docs]
- **The vendor side is the other place to look, and it is uneven.** Slack
  (Enterprise), Atlassian and Notion (Enterprise) log per-tool-call activity
  attributed to the AI app; Google logs per-API-method OAuth activity with
  hours of lag; GitHub logs writes; ClickUp logs nothing per call. None of
  it carries a correlation id or request parameters, and none can block per
  call. [docs]
- **The way every MCP gateway product gets into the path is the same, and it
  is open to us:** front the vendor's public MCP endpoint with our own
  server, register that as an organisation custom connector, and have admins
  block the directory version. Google Drive, Gmail, Calendar, Slack and
  ClickUp connectors are vendor-hosted public MCP endpoints
  (`drivemcp.googleapis.com`, `mcp.slack.com/mcp`, `mcp.clickup.com/mcp`),
  so this works for them; the GitHub connector in cloud sessions is served
  from an Anthropic path and cannot be fronted. [observed: upstream URLs in
  the cloud session's MCP config; docs: custom connector mechanics]

## Where each connector call executes, per surface

| Surface | Where the connector call runs | What we can see today | What we can control today |
|---|---|---|---|
| claude.ai web chat | Anthropic relay to the vendor's MCP endpoint | Enterprise: inference hooks (real time, after the call), Compliance API (minutes). Team and below: nothing per call. | Org per-tool policy (allow / needs approval / blocked); the user-facing "needs approval" prompt is the only per-call gate. |
| Claude Desktop chat | Same as web. `claude_desktop_config.json` governs local stdio servers only; remote connectors are not in it. [observed: `setup` finds no connector entries] | Same as web. | Same as web. `setup --bridge` (PR #9) replaces a connector with a local `mcp-remote` bridge the recorder wraps, at the cost of the user re-authorising through the bridge. |
| Cowork (Desktop, local or remote) | Anthropic-side for connectors; local MCP servers in-process | Compliance API transcripts, Cowork OpenTelemetry (Team+Enterprise), local `audit.jsonl` transcripts HMAC-chained by Anthropic. Whether Claude Code hooks fire for connectors delivered to Cowork as in-process `sdk` servers is inferred from the OTel `decision_source: "hook"` field and needs an empirical test. [docs] | Org per-tool policy. |
| Claude Code cloud session | Connectors are `type: http` MCP servers in `/tmp/mcp-config-<session>.json`, pointing at `api.anthropic.com/v2/ccr-sessions/<session>/mcp?mcp_url=<vendor>` with `X-MCP-Server-ID`, `X-MCP-Server-Origin` and `X-Session-UUID` headers; the relay forwards to the vendor. [observed] | PreToolUse/PostToolUse/PostToolUseFailure hooks from the repository's `.claude/settings.json` fire with full `tool_input` and `tool_response`, or the error string on PostToolUseFailure; the session transcript JSONL holds every `tool_use`/`tool_result`. [observed] | Hooks can deny or rewrite. `mcp-recorder hook` records and enforces. |
| Claude Code CLI, IDE, Desktop Code tab | Connector JSON-RPC leaves the machine for Anthropic's relay over HTTPS | Same hooks; Claude Code OpenTelemetry `tool_result` events with MCP server and tool names (and input when enabled). [docs] | Hooks; managed settings can lock them (`allowManagedHooksOnly`); `disableClaudeAiConnectors`, allowed/denied MCP server lists. [docs] |
| Agent SDK | Loads claude.ai connectors under claude.ai login | Hooks are callbacks with the same payloads; `canUseTool`. [docs] | Same. |
| Managed Agents (beta) | Customer-visible event stream | `agent.mcp_tool_use` / `agent.mcp_tool_result` with full input and content; MCP tools default to `always_ask`. First-party connectors (Gmail, Drive) are not offered there. [docs] | Per-call confirmation. |

## Anthropic-provided controls and feeds

All of these are Anthropic features an organisation turns on; the recorder
can ingest them as evidence sources but cannot replace them. [docs]

- **Org connector policy** (Team and Enterprise): enable or disable a
  connector org-wide; per-tool ceilings of "always allow", "needs approval",
  "blocked"; Enterprise custom roles with per-role tool grants;
  Enterprise-managed authentication through Okta. Real time, enforced on
  Anthropic's side. Desktop local and SSH Claude Code sessions only honour
  "blocked".
- **Inference hooks** (Enterprise, beta): before every governed inference,
  Anthropic POSTs the transcript, including `tool_use {tool_name, input}` and
  `tool_result {content, is_error, tool_name}` blocks, to a customer or
  vendor endpoint that answers allow or deny, with configurable fail-open or
  fail-closed and a shadow mode. Covers claude.ai, Cowork and Claude Code
  including the web. A connector call is visible only after it executed, in
  the next prompt frame, so this archives in real time and can stop the
  conversation but cannot pre-block one call. "Response-side enforcement is
  planned".
- **Compliance API** (Enterprise, not Team): chat and session transcripts,
  queryable within minutes, retained six years. Cowork local and remote
  sessions and Claude Code CLI, Desktop and IDE transcripts include MCP calls
  as `tool_use`/`tool_result`. Claude Code on the web is explicitly not
  captured. **Unresolved:** one research lens reports the chat-messages
  endpoint returns `tool_use`/`tool_result` blocks with `integration_name`
  and `mcp_server_url`; another reports it returns text, files and artifacts
  only. Check against the live schema before relying on it.
- **Activity feed**: admin and configuration events (`mcp_tool_policy_updated`,
  `mcp_server_*`, `integration_user_connected`, ...), never per-call
  invocations.
- **OpenTelemetry**: Cowork (Team and Enterprise) emits prompts, MCP server
  and tool names, parameters and approval decisions, no result content;
  Claude Code emits `claude_code.tool_result` with `mcp_server_name`,
  `mcp_tool_name` and, with `OTEL_LOG_TOOL_DETAILS=1`, `tool_input`, plus
  `tool_decision` with `decision_source=hook`. Managed settings can force it
  on, and it works in cloud sessions.
- **Enterprise-managed auth** (Okta, GA June 2026): grant, scope and revoke
  connector access by IdP group. Explicitly no per-call visibility: the IdP
  sees token issuance, not MCP traffic.

## What is impossible without Anthropic

- Intercepting the Anthropic-to-vendor hop, redacting vendor data before the
  model sees it, or reading Anthropic's internal connector-execution logs.
- Blocking one connector call before it runs on claude.ai web, Desktop chat
  or Cowork. The user-facing "needs approval" prompt is the only per-call gate.
- Transcripts of Claude Code on the web through the Compliance API.
- Any of the Compliance API, inference hooks or audit logs on a Team plan.
- Splicing the recorder in by URL substitution: the `*.mcp.claude.com` hosts
  Claude Code displays for connectors do not resolve in public DNS (only the
  Microsoft 365 one does) and the real transport is an Anthropic relay bound
  to the claude.ai session token. [observed: NXDOMAIN; docs: relay]

## Options, with coverage and effort

| Option | Covers | Pre-execution control | Effort | Status |
|---|---|---|---|---|
| A. `mcp-recorder hook` (Claude Code hooks) | Claude Code CLI, IDE, Desktop Code tab, cloud sessions, Agent SDK; every `mcp__*` tool including connectors | Yes: deny or rewrite per call, policy file | Done | Merged in PR #10; `hook install` writes the settings entries; dogfood 3 exercises it in a cloud session |
| B. Local bridge (`setup --bridge`, `mcp-remote`) | Claude Desktop and Claude Code for vendors with public MCP endpoints, when the user replaces the directory connector | Yes, through the stdio proxy (gateway mode once PR #8 lands) | Done | Merged in PR #9; user re-authorises through the bridge |
| C. Hosted recording gateway as a custom connector | claude.ai web, Desktop chat, Cowork, Claude Code, for vendors with public MCP endpoints (Google, Slack, ClickUp; not GitHub) | Yes, at our gateway | High: OAuth 2.1 authorisation server toward Claude (metadata, PKCE, claude.ai callback, sub-10-second token endpoint), OAuth client per vendor with an encrypted per-user token vault (the MCP spec forbids token passthrough), multi-tenant public HTTPS host reachable from Anthropic's egress range, plus the evidence sink | Not started. This is the product-shaped option: every incumbent gateway logs to a conventional store; the tamper-evident chain is the differentiator |
| D. Ingest Anthropic feeds (inference-hook receiver, Compliance API puller, OTel collector) | Everything the feeds cover, including claude.ai web | Inference hooks: stop the next turn; others: none | Medium: an HTTPS receiver that seals each frame into the chain; a poller; an OTLP endpoint | Not started; Enterprise customers only |
| E. Vendor audit-log correlation | Slack, Atlassian, Google Drive, Notion well; Gmail, Calendar, GitHub partially; ClickUp not at all | None | Medium; no shared correlation id, lag of hours, plan-gated | Not started |
| F. Client-side capture (browser extension or TLS-intercepting proxy on the claude.ai wire) | claude.ai web and Desktop chat, after the fact | None | Medium, fragile: undocumented endpoints, TLS fingerprinting; consumer terms bar automated access and reverse engineering, so only on enterprise-managed devices as an explicitly unsupported tier | Not recommended as a product surface |
| G. Wrap Desktop Extensions (`.mcpb`) | Locally installed Desktop extensions | Yes, through the stdio proxy | Low: repackage `manifest.json` `server.mcp_config.command` to the recorder, re-sign, deploy through org allowlist | Follow-up |

## Recommendation

1. **Ship A and prove it** (done, being proven by dogfood 3): every Claude
   Code surface gets pre-execution visibility and control over connector
   calls today, with nothing from Anthropic.
2. **Decide on C.** It is the only path to visibility and control on
   claude.ai web, Desktop chat and Cowork without an Enterprise contract, and
   it is a real product: a hosted gateway that is an OAuth 2.1 authorisation
   server toward Claude and an OAuth client toward each vendor, with our
   evidence chain behind it. Scope it for ClickUp first (public MCP endpoint,
   no vendor-side audit log, so the gap is largest), then Google and Slack.
3. **Build D for Enterprise customers** as evidence sources: an
   inference-hook receiver that seals every frame into the chain is the
   fastest "everything on claude.ai" story, and the Compliance API puller
   backfills what the hook misses.
4. **Ask Anthropic** for a supported egress webhook or a configurable
   connector endpoint on the server-side hop, and for Compliance API coverage
   of Claude Code on the web. Until then, C is the only lever we own there.
5. **Two experiments to run next:** (a) whether Claude Code hooks fire for
   connectors delivered to Cowork as in-process servers; (b) which
   `tool_use` fields the Compliance API chat-messages endpoint actually
   returns.

## Sources

Anthropic: Claude Code hooks reference and guide, MCP and connectors
documentation, Claude Code on the web (connectors are called from
Anthropic's infrastructure, also in self-hosted environments), Compliance
API, inference hooks, Cowork and Claude Code OpenTelemetry, organisation
connector settings and custom roles, Enterprise-managed authentication,
Managed Agents. Vendors: Slack, Atlassian, Google Workspace, GitHub, Notion
and ClickUp audit-log and MCP documentation. MCP: authorization
specification (token passthrough forbidden). Observations: this
repository's cloud dogfood sessions (`evidence/cloud-dogfood-2`, and
`evidence/cloud-dogfood-3` once pushed) and the connector wiring found in
`/tmp/mcp-config-<session>.json` inside a Claude Code cloud session.
