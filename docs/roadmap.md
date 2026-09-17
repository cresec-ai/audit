# Roadmap: where this project actually is

`@edut/mcp-recorder` is one npm-shaped package in this repository. The plan
around it is larger than the package, and most of that plan is not code that
lives here. This page separates the three, so that nobody installs the
recorder expecting a hosted control plane.

The source of truth for planning is the ClickUp list
[🛠️ MVP — MCP Black Box](https://app.clickup.com/t/86exx61xv), 71 items. This
page is the engineering reading of it, checked against the repository.

**Snapshot:** `origin/main` at `b322dea`, version `0.1.0`, Node 22 on Linux.
This page will drift; the commit is how you tell how far. Everything below
described as verified was run against that code while writing this page, and
the commands are in [What did we verify, and how?](#what-did-we-verify-and-how).
Anything we could not run is labelled as unverified rather than left to read
as fact.

## Which bucket does a thing belong in?

| Bucket | Where the code is | What you get by installing this package |
|---|---|---|
| **Shipped** | this repository, `origin/main` | all of it |
| **In progress** | this repository, branches and open work | some of it, unevenly — see below |
| **v2, planned** | a Go monorepo that does not exist in this repository | **none of it** |

The v2 plan (agentctl CLI, edge daemon, hosted control plane, approvals
inbox, Slack approvals, multi-tenant Helm deploy) targets a different
codebase. `origin/main` contains zero `.go` files. No amount of installing
`@edut/mcp-recorder` produces a hosted gateway or an approvals UI.

## What can I install and use today?

The package is **not on npm**. `npm view @edut/mcp-recorder version` returns
404, so `npx -y @edut/mcp-recorder` does not resolve for anyone. Install from
git:

```sh
npm install -g github:cresec-ai/audit#main
mcp-recorder --version
```

Getting it onto npm is part of
[OSS packaging: README, license, landing](https://app.clickup.com/t/86exx6206),
which is still in progress. Until then, every `npx -y @edut/mcp-recorder`
snippet in the README and in [docs/install.md](install.md) is a *future* form,
and the docs say so.

### What is shipped and verified

Each row states the limit next to the capability, not below it.

| Capability | Verified by running | The limit, in the same breath |
|---|---|---|
| Transparent stdio proxy (`record`) | 2,097,668 bytes out of a hostile stream, identical sha256 wrapped and unwrapped | Holds for `record` **without** `--policy`. Gateway mode is not byte-for-byte; see below |
| Added latency | `npm run bench`: p50 added 0.829 ms against a 5 ms gate | Measured against a local fixture server over stdio on one machine. It is not a prediction about your server |
| Fail-open recording | named tests in `test/cli.test.ts` ("an unwritable `--data-dir` still spawns the server and exits with its code") and `test/hook.test.ts` ("a broken policy file is fail-open") | Fail-open means a store failure never becomes a deny. It also means a store failure can lose an event rather than stop traffic |
| Hashed payloads | the literal `quarterly-revenue-2026` appears 0 times in the exported bundle; arguments carry `sha256:` refs | The *hash* is in the bundle. Anyone holding the plaintext can confirm a match, which is the point of `query` |
| Hash chain + ed25519 head signature (`verify`) | `PASS — chain intact: 6 event(s), head seq 6` | Detects alteration of a chain you hold. It does not prove the chain was ever complete |
| Dependency-free bundle verification | `node verify.cjs` inside an exported bundle: `PASS` | **A bundle's key is self-pinned.** Verifying a bundle against the key inside it proves nothing against someone who forged the whole bundle. Real assurance needs `--public-key` obtained out of band. The tool prints this itself |
| Blast-radius `query` | found the demo canary in 2 events by hash, across the read and the exfiltration call | Finds what was recorded. A call no vantage point saw is not there |
| Replay timeline (`ui`) | `ui --out replay.html` wrote a 24,719-byte page with no external `src`, `href` or `<link>` reference | Static page or local web UI. No hosted viewer exists |
| `setup` for a client's config | `setup --config <fixture> --dry-run` wrapped 1 stdio server, skipped 4 remote ones with reasons | Wraps **stdio** servers. Remote connectors are skipped by design — they are not on this machine |
| Claude Code hook (`hook`) | a PreToolUse deny returned `permissionDecision: "deny"`; the denied call is in the chain as `error.type: "policy_denied"` | Claude Code surfaces only. Not claude.ai web, not Claude Desktop chat. Cowork should be assumed **not** covered — see [docs/connector-coverage.md](connector-coverage.md) |
| HTTP MCP proxy (`http`) | `test/http-proxy.test.ts`, 17 tests pass | Records only. `http --policy` is rejected: gateway mode is stdio-only |
| Test suite | `npm test`: 526 passed, 2 skipped, 26 files | The suite spawns real child processes and is timing-sensitive. One run of three on a loaded machine produced 66 failures that did not reproduce |

The ClickUp items behind these are all complete:
[stdio MCP passthrough proxy (forward unchanged)](https://app.clickup.com/t/86exx61yr),
[Define + freeze event schema](https://app.clickup.com/t/86exx61z0),
[Edge redaction (allow-list; hash the rest)](https://app.clickup.com/t/86exx61z2),
[Latency benchmark (<5ms p50, never blocks)](https://app.clickup.com/t/86exx61z3),
[SQLite append-only store](https://app.clickup.com/t/86exx61z5),
[Hash chain + ed25519 chain-head signing](https://app.clickup.com/t/86exx61ze),
[`verify` CLI subcommand](https://app.clickup.com/t/86exx61zh),
[Tamper test suite](https://app.clickup.com/t/86exx61zn),
[Replay HTML timeline (see → act → effect)](https://app.clickup.com/t/86exx61zw),
["Which sessions touched X?" blast-radius query](https://app.clickup.com/t/86exx61zz),
[Signed evidence-bundle export](https://app.clickup.com/t/86exx6201) and
[Scripted prompt-injection exfiltration demo](https://app.clickup.com/t/86exx6204).
Milestones [M0 — Setup & passthrough MCP proxy](https://app.clickup.com/t/86exx61x0),
[M1 — Recorder core](https://app.clickup.com/t/86exx61x9),
[M2 — Tamper-evident store](https://app.clickup.com/t/86exx61xf) and
[M3 — Replay + export](https://app.clickup.com/t/86exx61xq) are closed.

`mcp-recorder hook` and `setup --bridge` are not on that list. They came out
of the connector research and shipped in PR #10 and PR #9.

### Three vantage points, and they are not equivalent

This is the single thing most likely to be misread, so it is stated here as
well as in [docs/connector-coverage.md](connector-coverage.md), which remains
the authority.

| Vantage point | Sees | Cannot see |
|---|---|---|
| `record` (stdio proxy) | every byte to and from a local stdio MCP server it wraps | anything it does not wrap, including every Anthropic-hosted connector |
| `hook` (Claude Code PreToolUse/PostToolUse/PostToolUseFailure) | every tool call Claude Code's agent loop makes, hosted connectors included, on the CLI, IDE, Desktop Code tab, cloud sessions and the Agent SDK | claude.ai web chat, Claude Desktop chat, and — until a probe says otherwise — Cowork |
| `http` | traffic to an HTTP MCP server it fronts | the Anthropic-to-vendor hop, which is Anthropic's on every surface |

The hook is the **only third-party vantage point we have found on
Anthropic-hosted connectors.** That is why it exists. It is not a nicer
version of the proxy; it covers a different set of calls.

## What did we verify, and how?

Real commands, real output, trimmed where noted. Long data-directory paths
are shortened to `$D`, and long hex digests to their first 16 characters,
which is how the tool prints them anyway.

**Byte-for-byte transparency, independently re-checked.** The same 2 MB
hostile stream (CRLF framing, a non-JSON line, an embedded NUL, invalid
UTF-8, a 2 MiB line, an unterminated tail) written one byte at a time to the
bare fixture server and to the same server behind `record`:

```
input bytes   : 2097610
bare   bytes  : 2097668 sha256 8598cb849bf57d3edbb75017795b596a489af31cc37d62ca2003df70d7ca7fa8
wrapped bytes : 2097668 sha256 8598cb849bf57d3edbb75017795b596a489af31cc37d62ca2003df70d7ca7fa8
IDENTICAL
```

The project's own testing has taken this to 35.6 MB against the same shapes.
The run above is a smaller re-check, not a replacement for it.

**Latency.** `npm run bench`, trimmed to the table:

```
  series    p50         p95         p99
  direct    0.057ms     0.076ms     0.114ms
  wrapped   0.886ms     1.301ms     1.962ms
  added     0.829ms     1.226ms     1.849ms
  ✓ PASS — p50 added latency = 0.829ms (gate: < 5ms)
```

**Record, inspect, export, verify.** A three-call session against
`test/fixtures/echo-server.cjs`:

```
$ mcp-recorder sessions --data-dir "$D"
SESSION   STARTED                   ENDED                     SERVER  EVENTS  TOOL_CALLS  ERRORS  SERVERS
6944effc  2026-09-17T04:37:47.257Z  2026-09-17T04:37:47.291Z  notes   6       1           0       1

$ mcp-recorder verify --data-dir "$D"
pinned signer: ed25519 817f042c1ad9d87f… (…/identity.pub)
PASS — chain intact: 6 event(s), head seq 6

$ mcp-recorder query quarterly-revenue-2026 --data-dir "$D"
TIMESTAMP                 KIND       NAME  SESSION   MATCHED_ON  PATH
2026-09-17T04:37:47.288Z  tool_call  echo  6944effc  ref         $.args.note
```

The tool argument reached the store as
`{"len":22,"redacted":true,"ref":"sha256:c937d875…"}`. `grep -c
quarterly-revenue-2026 events.jsonl` in the exported bundle returns `0`.

**The self-pinning caveat, printed by the tool.** Trimmed output of
`node verify.cjs` inside a bundle:

```
PASS: evidence bundle verified
  events     : 6 (seq 1..6)
  signed by  : ed25519 817f042c1ad9d87f… at 2026-09-17T04:38:03.281Z
  key check  : NOT independently verified - the key came from this bundle
               itself (public_key.pem / manifest.json), which an attacker
               who forged the whole bundle controls too. Re-run with
               --public-key <hex|path> using a key you obtained out of band
               (e.g. from the operator directly) for real assurance.
```

**The hook, denying a call.** One PreToolUse object on stdin, policy denying
`clickup_delete_task`:

```
$ printf '%s' '{"hook_event_name":"PreToolUse","tool_name":"mcp__ClickUp__clickup_delete_task",…}' \
    | mcp-recorder hook --data-dir "$D" --policy policy.json
{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny",
 "permissionDecisionReason":"mcp-recorder policy: destructive ClickUp calls are blocked"}}
```

The denied call is in the evidence chain, not only in Claude Code's
transcript: `"error": {"type": "policy_denied", "message_ref": "sha256:…"},
"is_error": true, "phase": "pre"`.

## What is being built right now?

Milestone [M4 — Demo & design-partner launch](https://app.clickup.com/t/86exx61xv)
is the open one.

### Gateway mode

[P2-7 MCP gateway mode: JSON-RPC proxy, per-tool allow/hold/deny, tool-result boundary filter (folds Edut M0)](https://app.clickup.com/t/z8n6b5yta4)
is still open in ClickUp, but PR #8 **has merged**: `origin/main` is
`b322dea`, the gateway-mode merge commit. An install from `#main` taken at or
after `b322dea` has gateway mode; an earlier one does not. ClickUp is behind
the repository here, not ahead of it. `record --policy` turns the recorder
into an enforcing gateway; without `--policy` nothing changes.

We verified gateway mode in a tree whose `src/gateway/`, `src/policy/` and
`src/proxy/stdio.ts` are byte-identical to `origin/main` (`diff -rq`, no
differences), so the following applies to main as merged.

| Behaviour | Verified by running | The limit |
|---|---|---|
| Per-tool `deny` | the scripted demo under `docs/examples/policy.demo.yaml`: `gateway: denied tools/call "http_post" (rule no-exfil)` | Enforcement is **fail-closed**: what cannot be evaluated is denied. That includes a non-JSON line, which record mode forwards untouched and the gateway refuses |
| Boundary filter, secrets | `gateway: redacted tool result … (1 secret-shaped, 0 injection marker(s))`; an AWS key in a result reached the client as `[redacted:sha256:1a5d44a2dca19669]` | A heuristic on a deliberately narrow pattern set. Over 1.08 million lines of third-party TypeScript it rewrites 692 lines (measured by the project, pinned in CI, `docs/policy.md`) |
| Boundary filter, injection markers | with `injection: block`, a result carrying "Ignore all previous instructions…" came back as an `isError` result naming the policy | The default is `flag`, not `block`, because false positives on security documentation are expected |
| Hold and approve | a held call parked for 8.2 s, `holds` listed it, `approve <id>` released it, the client got its real result | A hold blocks that one call until decided or timed out. On timeout the policy's `on_timeout` decides; the examples use `deny`. A hold matched inside a JSON-RPC batch is treated as a deny — a batch element has nowhere to park |
| Transport scope | `http --target … --policy …` exits 2: `gateway mode is available for the stdio transport only` | Gateway mode is stdio-only. The `hook` policy is a separate, simpler allow/deny engine |

```
$ mcp-recorder holds --data-dir "$D"
ID        AGE  SERVER  TOOL  RULE                TIMEOUT
55ad2668  3s   notes   echo  echo-needs-a-human  1m

$ mcp-recorder approve 55ad2668 --data-dir "$D"
approved 55ad2668-71e2-413a-8c30-ba83149e5c42: echo on notes (rule echo-needs-a-human) by root
```

See [docs/gateway.md](gateway.md) for the walk-through and
[docs/policy.md](policy.md) for the rule semantics. `docs/gateway.md` carries
a "What gateway mode does not do" section; read it before relying on
enforcement.

### policy.yaml v1 and the Rego compiler

[P1-5 policy.yaml schema v1 + JSON Schema validation + compiler to Rego (existing OPA bundle endpoint)](https://app.clickup.com/t/z8n6b5yt9p)
shipped with PR #8 and is still marked in progress. Verified:

```
$ mcp-recorder policy validate docs/examples/policy.laptop.yaml
…/policy.laptop.yaml: valid (3 mcp rules, 0 egress rules)

$ mcp-recorder policy compile docs/examples/policy.laptop.yaml | head -5
package cresec.mcp
import rego.v1
# Generated by mcp-recorder 0.1.0 from policy "laptop" (sha256:07f24908…). Do not edit.
```

The limit is the point of the item. A policy may carry `mcp` rules and
`egress` rules; the compiler emits a module for each. **This package enforces
only the MCP half.** Egress rules compile and are then the v2 sidecar's job,
and the sidecar does not exist yet. The tool says so rather than pretending
otherwise:

```
$ mcp-recorder policy validate test/fixtures/policies/egress-only.yaml
…/egress-only.yaml: valid (0 mcp rules, 3 egress rules)
  warning: no "mcp" section — nothing for the gateway to enforce
  (record --policy and setup --policy will refuse it)

$ mcp-recorder policy compile test/fixtures/policies/egress-only.yaml --out "$OUT"
wrote 3 file(s) to …
  .manifest
  cresec/mcp/tool.rego
  cresec/egress/http.rego
```

### Documentation and packaging

[P1-12 Docs: 10-minute quickstart for laptop and CI](https://app.clickup.com/t/z8n6b5yt9x)
and [OSS packaging: README, license, landing](https://app.clickup.com/t/86exx6206)
are both open. The concrete gaps: the package is not on npm, and the install
docs carry two forms (git today, npx later) that a first-time reader has to
hold in their head.

[Recruit 5 design partners](https://app.clickup.com/t/86exx620b) and
[Launch post: HN / r/LocalLLaMA / MCP community](https://app.clickup.com/t/86exx620f)
are not started.

## What is planned but not in this repository?

Everything below is the v2 plan. It targets a Go monorepo — an `agentctl`
CLI, an edge daemon, and a hosted control plane — and **none of it is in this
repository or in this package.** Some of it folds work from here: the
hosted gateway phase folds the MCP proxy, and the evidence phase folds the
tamper-evident store.

| Phase | What it is | Relationship to this package |
|---|---|---|
| [v2 · P0 — Harness Audit CLI (Wk 1–2)](https://app.clickup.com/t/z8n6b5yt92) | `agentctl scan` over CI workflows, local agent configs, secret reachability, egress and MCP inventory, with an HTML report | New code. Reads configuration; records nothing |
| [v2 · P1 — Tier 1 Sidecar: secrets brokering + egress (Wk 2–7)](https://app.clickup.com/t/z8n6b5yt93) | forward proxy with a per-install CA, network-namespace launcher, synthetic credentials, request-aware policy, vendor policy packs | This is where compiled `egress` rules would finally be enforced |
| [v2 · P2 — Tier 2 Hosted Gateway + vendor compilers (Wk 6–11)](https://app.clickup.com/t/z8n6b5yt94) | multi-tenant hosted ingress, `compile --target claude-web / codex-cloud / copilot`, drift detection, sessions UI | The hosted version of what `record --policy` does locally. Option C in [docs/connector-coverage.md](connector-coverage.md) |
| [v2 · P3 — Approval gates + evidence (Wk 9–13)](https://app.clickup.com/t/z8n6b5yt95) | hold state machine over a 428 contract, Slack approval service, one-shot tokens, approvals inbox UI | The local `holds` / `approve` / `deny` commands are the laptop-scale ancestor. There is no inbox, no Slack, no token here |
| [v2 · P4 — Pilot instrumentation + hardening (Wk 10–14)](https://app.clickup.com/t/z8n6b5yt96) | pilot metrics, partner weekly report, per-tenant bypass mode and runbook | Nothing in this package |
| [v2 · Red-team & hosted-conformance suites (nightly, from Wk 4)](https://app.clickup.com/t/z8n6b5yt97) | nightly adversarial and conformance runs | This repository has [docs/red-team.md](red-team.md) and a CI suite, not a nightly hosted one |

Representative not-started items, so the shape is concrete:
[P0-1 Scaffold apps/agentctl (cobra CLI, goreleaser, edge-daemon module conventions)](https://app.clickup.com/t/z8n6b5yt98),
[P0-4 scan/secrets-reach — credentials readable by the agent UID, with redaction guarantees](https://app.clickup.com/t/z8n6b5yt9b),
[P1-1 Forward proxy in edge daemon: CONNECT + TLS termination, per-install CA, child-only trust injection](https://app.clickup.com/t/z8n6b5yt9j),
[P1-9 cresec/agentctl-action composite GitHub Action + POST /v1/sessions/ci OIDC bootstrap](https://app.clickup.com/t/z8n6b5yt9u),
[P2-3 compile --target claude-web: custom cloud environment JSON + setup script + managed settings fragment](https://app.clickup.com/t/z8n6b5yta0),
[P3-2 Approval service: approval table, NATS approvals.<tenant>, Slack Block Kit Approve/Deny, signed callbacks, expiry](https://app.clickup.com/t/z8n6b5yta9),
[P3-5 UI: approvals inbox (discoveries-inbox card pattern) + policy simulation against last 7 days of decisions](https://app.clickup.com/t/z8n6b5ytac).

## How should I read the ClickUp week numbers?

As sequence, not as promises. "Wk 1–2" means the phase comes first, and "Wk
6–11" means that phase overlaps the one before it. No week number on this
page maps to a calendar date, and none of them is a commitment.

## What have we learned that changed the plan?

Two findings changed the shape of the work rather than its order.

### Hosted connectors cannot be wrapped, so the hook exists

The original design was one vantage point: wrap an MCP server, record its
traffic. That covers local stdio servers and nothing else. On every Claude
surface, a connector call to Google, GitHub, Slack or ClickUp is made from
Anthropic's infrastructure with tokens in Anthropic's vault. No local proxy,
no configuration file of ours and no network device can sit on that hop.

The research behind [docs/connector-coverage.md](connector-coverage.md) found
exactly one third-party vantage point that does see those calls, and can
block them before they run: Claude Code's own PreToolUse hook. That is why
`mcp-recorder hook` exists, and why it is a first-class recording path rather
than a convenience.

It is also why that document is a living one. It has been publicly corrected
twice for claiming coverage its evidence did not support — most recently the
Cowork row, which was inferred from an OpenTelemetry field name and is now
recorded as unproven and assumed negative. Coverage claims there carry
`[observed]` or `[docs]` tags for this reason. Treat that file, not this one,
as the authority on what each vantage point sees.

### A documented deny silently did nothing, so deny rules are written against the tool

Cloud dogfood 4 ran a live Claude Code session with the hook installed and a
policy that denied two real ClickUp calls two independent ways: once through
the resolved host alias, once through the raw UUID form.

**Both denies missed. Both calls executed against the real workspace, twice
each. The signed 62-event bundle holds no record of a policy decision at
all.** The hook ran and recorded the calls correctly. The docs said the deny
worked. It did not.

The cause was a naming assumption. Hook policy resolution looked the server
segment up as a **key** in `/tmp/mcp-config-<session>.json`. That session's
file was keyed by UUID while Claude Code handed the hook the friendly segment
`ClickUp`, so nothing resolved: no vendor URL, no host alias, and the
UUID-shaped rule could not match a name that was never a UUID. Both
conventions are the platform's, and which one a session uses varies. Dogfood
3 saw UUID keys with UUID tool names. Dogfood 4 saw UUID keys with friendly
tool names. A local session has friendly keys with friendly names.

Two things changed.

**Resolution no longer assumes the key matches the segment.** The exact-key
lookup stays the preferred route; when it finds nothing, the entry whose
`tools[]` declares this exact tool name is used instead, and only when
exactly one entry declares it. Ambiguity resolves to nothing rather than to a
guess. The alias stays deny-only, so a forged config can still only ever add
a deny.

Reproduced side by side against the dogfood-4 config shape — UUID-keyed file,
friendly tool-name segment — with a policy denying
`^mcp__mcp\.clickup\.com__clickup_delete_task$`:

```
# build without the fix
$ … | mcp-recorder hook --policy policy.host.json
(no output — the call was ALLOWED)

# build with the fix
$ … | mcp-recorder hook --policy policy.host.json
{"hookSpecificOutput":{…,"permissionDecision":"deny",
 "permissionDecisionReason":"mcp-recorder policy: destructive ClickUp calls are blocked"}}
```

**This fix has not merged to `origin/main`.** It is on the
`claude/p0-subagents-scoping-qibt2p` branch at `3002b0f`. Until it merges, an
install from `#main` has the dogfood-4 behaviour, and a live re-test (dogfood
5) has not been run against the fix.

**Deny rules are documented against the tool, not the server segment.** A
rule anchored on the tool name fires under either convention, with no
resolution, no config file and no alias involved. Verified on the build
*without* the fix, with `^mcp__[^_]+__clickup_delete_task$`:

| Tool name the hook received | Decision |
|---|---|
| `mcp__ClickUp__clickup_delete_task` | deny |
| `mcp__47d587b8-3fb9-42e9-b596-f8b25371248c__clickup_delete_task` | deny |

The tool name is usually specific enough on its own: only ClickUp has a
`clickup_delete_task`. The host alias remains a readable convenience for
whoever reads the policy, not the thing a deny should depend on. See the
Policy section of [docs/hooks.md](hooks.md).

The wider lesson is the one this project now applies to documentation: a
merged, documented, tested feature can be inert in production, and only a
live run says otherwise. The mechanism for that is a dogfood session against
real connectors, with the findings written down whichever way they fall.
Reports are on the `evidence/cloud-dogfood-*` branches.

## What do we still not know?

Open questions, listed because they are load-bearing and unanswered.

- **Does the hook fire in Cowork?** Assumed no. Two community issues report
  that it does not, and Anthropic's documentation says Cowork does not read
  the Claude Code CLI's `~/.claude` directory — though that sentence is about
  skills, plugins and connectors rather than hooks, and about `~/.claude`
  rather than a repository's own `.claude/settings.json`. Neither source is
  conclusive. The probe is read-only and takes minutes. It has not been run.
- **Does the deny work live, now?** The resolution fix is verified against a
  fixture that reproduces the dogfood-4 shape. It has not been verified
  against a live hosted connector in a cloud session.
- **What does `sessions` show for a session that was ended and reopened?**
  Dogfood 4 found a row whose `ENDED` timestamp and counts were a stale
  snapshot while the same session went on recording. Work on this is in
  progress and not merged.
- **Which `tool_use` fields does the Compliance API actually return?** Two
  research passes disagree. Do not rely on it without checking the live
  schema.
- **Do the other agent surfaces behave?** Codex CLI, Cursor and the rest have
  configuration wired up in this repository but no equivalent of the dogfood
  runs that Claude Code has had.

## Where to read next

- [README.md](../README.md) — what the tool promises, and the honest security
  model.
- [docs/install.md](install.md) — install per client, Windows and WSL,
  uninstall, troubleshooting.
- [docs/connector-coverage.md](connector-coverage.md) — the authority on what
  each vantage point can and cannot see, per surface.
- [docs/hooks.md](hooks.md) — the Claude Code tap and its policy.
- [docs/gateway.md](gateway.md) and [docs/policy.md](policy.md) — gateway
  mode and `policy.yaml` v1.
- [docs/event-schema.md](event-schema.md) — the frozen
  `edut.mcp-recorder.event.v1` format. Additive optional fields only.
