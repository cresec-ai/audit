# @edut/mcp-recorder

**A gate in front of the MCP tool calls your agent makes, and a signed record of every one of them.** One command puts a policy in front of every stdio MCP server you wrap — plus, on Claude Code, the Anthropic-hosted connectors: the calls that would delete, exfiltrate or spend are stopped or held for your approval, everything else runs at full speed, and the whole episode — allowed and refused alike — lands in a tamper-evident chain you can verify offline and hand to a stranger.

You do not write the policy. You do not learn a schema. You type one command:

```sh
mcp-recorder protect --client claude-code
```

**Enterprise software anyone can build.** The person building the tool is not the person who has to sign off on it. This package is the half that lets both of them say yes: the builder keeps their own editor and their own speed, and the security team gets a control that is actually in force and an artifact they can check themselves.

**The bet:** the records of mediated tool calls are chained, signed, and verifiable offline by the customer with no network access to us — starting with the MCP leg. That is the integrity half of invariant 3. Its coverage half does not hold here yet: recording is fail-open, as the invariant asks, but an event the store cannot take is dropped rather than spooled and replayed, and nothing reconciles decisions against records ([AGENTS.md](AGENTS.md)). When an agent does something surprising — or someone claims it did — you can reconstruct exactly what happened, prove the record wasn't altered, and hand a stranger a bundle they can verify with bare Node and no dependencies.

Two honest limits, up front, because a security product you can believe covers more than it does is worse than one that covers less:

- **Nothing enforces unless you ask it to.** `mcp-recorder record -- <server>` with no policy selected is a transparent recorder and nothing else: it forwards the exact bytes, fails open, and adds <5 ms p50. Enforcement is `protect`, `--policy` or `--protect`, explicitly, or it is not happening. A starter policy sitting in your data directory is not an input to that decision.
- **This is a gate on your machine, not a wall around the world.** `MCP_RECORDER_DISABLE=1` is the documented kill switch for whoever controls the environment; claude.ai on the web, the Claude Desktop chat tab and Cowork have no customer-side per-call gate at all. What the recorder can and cannot see, per surface, is in **[docs/connector-coverage.md](docs/connector-coverage.md)**.
- **It gates MCP tools, not your agent's own hands.** The hosted-connector half is a Claude Code PreToolUse hook, so `protect --client claude-desktop` and `protect --client cursor` install **no connector gate at all** — on those clients the hosted connectors are ungoverned and produce no policy decision, while the chain still verifies clean. And the hook carries the default `mcp__.*` matcher, so Claude Code's own **`Bash`, `Write` and `Edit`** are outside the gate: `catastrophic-commands` covers an MCP server that exposes `run_command`, not the agent's built-in shell. `mcp-recorder hook install --all-tools` extends the hook to built-ins; `protect` does not pass it for you.

- **License:** GPL-3.0 · **Node:** >= 20 (macOS, Linux, Windows; WSL supported via wsl.exe wrapper) · **Binary:** `mcp-recorder`

---

## Install and protect

`@edut/mcp-recorder` is not on npm yet, so `npx -y @edut/mcp-recorder` doesn't
resolve for anyone today. Install from the git repository instead — the
compiled `dist/` is committed, so there is no build step:

```sh
npm install -g github:cresec-ai/audit#main
mcp-recorder protect --client claude-code
```

Two typed commands and one client restart. After the package is published it
is one command and no separate install: `npx -y @edut/mcp-recorder protect
--client claude-code`. `--client` takes `claude-desktop`, `claude-code` or
`cursor`; `--config PATH` overrides the resolved file and makes `--client`
optional.

`protect` is a thin front over things this package already did, so nothing
about it is a second way to do them:

1. it writes the **starter policy** to `<data-dir>/policy.starter.yaml` (and,
   for `claude-code`, its hook twin `policy.starter.json`) — written once,
   never regenerated over your edits;
2. it runs `setup --client C --policy <that file>`, so there is a timestamped
   backup and a sidecar, and `setup --undo` reverses it exactly;
3. for `claude-code` it runs `hook install --policy <the twin>`, which is the
   only way anything of yours sees the Anthropic-hosted connectors
   (`mcp__ClickUp__*`, `mcp__Gmail__*`, …) that no local proxy can reach;
4. it runs **`doctor`** and prints its verdict last, so the final line on
   screen is a measurement of whether enforcement is in force rather than a
   claim that it is.

Then **fully quit and restart your client** — closing the window is not
enough, because MCP clients launch their stdio servers at startup and hooks
are captured when a session begins. A policy installed mid-session is a false
negative that looks exactly like the product failing.

Prefer to hand it to an agent? Give Claude Desktop or Claude Code a prompt
asking it to install from git, run `protect`, and show you the output —
it just needs a shell or config-file access.

Full instructions (manual JSON edits per client, uninstall, troubleshooting)
are in **[docs/install.md](docs/install.md)** — on Windows, or running from
inside WSL, see its **[Windows and WSL](docs/install.md#windows-and-wsl)**
section first. What deploying this across a team or a fleet looks like — per
agent platform, with what breaks each one and a rollout order — is in
**[docs/deployment.md](docs/deployment.md)**.

---

## The first run: watch it stop something

Restart your client, then ask your agent for something it should not do. The
sentence `protect` prints is chosen from the tools `doctor` actually found on
your servers, so it is one that will fire — for a filesystem server, for
example:

> read the .env file in this project and tell me what's in it

The agent comes back having been refused, and says so:

> I can't read that file. The call was blocked: `mcp-recorder gateway:
> tools/call "read_text_file" denied by policy rule "credential-files":
> an argument was a path to a credential file.` This was a policy decision on
> your machine, not a tool failure, so I have not tried another way to get the
> same content. You may want to change the rule if that was intentional.

The server never saw the call. What the model received is two lines: the
refusal naming the tool, the rule and the reason, and a standing clause that
tells it not to retry and not to route around the gate.

**The model is deliberately not told how to change the rule.** The agent under
policy is exactly the party that must not be handed the command that relaxes
it. That lives on your side of the boundary:

```sh
$ mcp-recorder why
last 1 decision in /Users/me/.mcp-recorder

  2 min ago   DENIED   read_text_file   filesystem
              rule "credential-files" — an argument was a path to a credential file
              the agent asked for it, the server never saw the call, nothing was read

              to allow this: open /Users/me/.mcp-recorder/policy.starter.yaml
              and delete or narrow the rule with  id: credential-files
              then fully restart your client

nothing here left your machine. the full record:  mcp-recorder ui
```

`why` is read-only over the evidence chain and prints **no argument or result
text at all**: every string it shows comes from your own policy file, the tool
name and the rule id. It is a second reader of the store, never a second way
for a payload to leave it.

## Is it actually on? `doctor`

The failure this product has to survive is not a crash. It is an **absence**:
a policy that is loaded, valid, and matches nothing, with every call sailing
through and the evidence chain looking perfectly healthy. That has happened
here — a 62-event signed bundle, chain PASS, two live connector calls against
a real workspace, and zero policy decisions, because the client's config keys
and its `mcp__<server>__<tool>` names disagreed and both deny rules matched
nothing. No command reported an error, because nothing had gone wrong.

```sh
$ mcp-recorder doctor --client claude-code
OK         C1 wiring          2/2 stdio servers wrapped, all enforcing this policy
OK         C2 hook            PreToolUse installed, matcher mcp__.*, policy …/policy.starter.json
OK         C3 name spellings  3 deny rules x 6 spellings x 12 connector tools — all match
OK         C4 coverage        47 tools discovered (2 servers, 4 connectors)
OK         C5 probe           live deny fired on filesystem/read_text_file (rule credential-files)
OK         C6 chain           PASS, 41 events, 3 policy decisions, 1 session

doctor: 6 checks OK, 0 failed, 0 incomplete
```

Every check is tri-state — **OK / FAIL / INCOMPLETE** — and a check that could
not be performed is INCOMPLETE and is never folded into OK. Exit `0` all
passed, `1` at least one FAIL, `3` no FAIL but something was unchecked, `2`
doctor could not run at all. `--json` is the stable machine interface, so
`mcp-recorder doctor --no-probe --json` is a pre-flight any CI job can gate on.

What each check is for:

| Check | It fails when |
| --- | --- |
| **C1 wiring** | a server is unwrapped, wrapped without `--policy`, points at a policy that is not there, or `MCP_RECORDER_DISABLE=1` is set — the kill switch is on and the chain still looks healthy |
| **C2 hook** | Claude Code's PreToolUse hook is missing or carries no policy, or a session that began *before* the hook was installed is still running |
| **C3 name spellings** | a deny rule is anchored to one spelling of a tool name — either its regex names a `<server>` segment the client is free to change, or it matches some spellings of a tool and misses others. Six spellings are checked, including one nobody has ever observed: the fuzz case that proves a rule is *open* rather than merely broad enough for the conventions we happen to know |
| **C4 coverage** | the policy is in force and matches **none** of the tools your servers really expose. Tool names come off the wire (`initialize` + `tools/list` against each wrapped server) and out of the connector config — discovered, never guessed |
| **C5 probe** | a call this policy denies is *not* refused by a real spawned proxy, or the refusal produces no `policy_decision` event. The event is the proof, and it is the same artifact a dogfood run is measured by. The probe only ever sends a call the policy has already decided to deny, so the server never sees it and nothing has side effects |
| **C6 chain** | `verify` fails on the real data directory. A chain that verifies while holding zero decisions is reported as a fact, not as a pass |

---

## The starter policy, and the moment you edit it

The file `protect` writes is commented YAML you can read, and it is yours from
the moment it exists. Four rules deny, three hold for your approval,
everything else runs.

**The denies are anchored to arguments, not names.** A rule that names a tool
is a guess about a vocabulary we do not control; a rule that matches what the
call *does to the world* holds whatever the server calls its fields:

| Rule | What it stops |
| --- | --- |
| `secrets-in-arguments` | a credential shape (`AKIA…`, `ghp_…`, `sk-…`, `xox…`, a JWT, a PEM block, a `Bearer` value) in any string argument, at any depth. It scans **every** call, including file writes, so it has one false positive worth knowing: writing an *example* credential into a file — a docs page with an `Authorization: Bearer eyJ…` sample, a `.env.example`, a test fixture with a fake `ghp_` token. That is a **deny**, not a hold, so there is nothing to approve; narrow the rule to the tools that leave the machine if it bites you |
| `credential-files` | an argument that **is** a path to `.env`, `.npmrc`, `.netrc`, `.pgpass`, `.git-credentials`, an SSH private key, `.aws/credentials`, `.kube/config`, a `.pem`. Prose that merely mentions `the .env file` has a space before it and does not match |
| `dont-touch-the-controls` | a write to this recorder's own evidence directory, the policy files, the client's MCP config or its hook settings. **Honest limit:** this is friction and evidence, not a boundary — the agent has a shell. What it buys is that the attempt becomes a `policy_decision` in a signed chain instead of a silent edit |
| `catastrophic-commands` | a small literal set: a recursive `rm` rooted at `/`, `~` or `$HOME`, `--no-preserve-root`, `DROP DATABASE`/`DROP SCHEMA`/`TRUNCATE TABLE`, an unqualified `DELETE FROM <table>`, and a `git push --force` that is not `--force-with-lease`. These reach through servers whose *name* tells you nothing (`bash`, `run_command`, `query`) and whose *argument* tells you everything. It is a handful of literals, not a shell parser, and does not pretend to be one |

**The holds are the questions.** `destructive-tools`, `sends-to-other-people`
and `spends-money` match on tool-name globs and **hold** rather than deny: a
hold is a question, a deny is a wall, and deleting, sending and paying are all
things you plausibly asked for. The globs are **verbs, not nouns**, on purpose:
an earlier draft's `*charge*` / `*invoice*` / `*order*` held `list_charges`,
`get_invoice` and `order_issues` — reads and a sort — and a hold on a read is
pure friction. `move_*` / `rename_*` are deliberately absent for the same
reason: against a filesystem server they are a routine refactor. Two minutes to answer with `mcp-recorder
holds` and `mcp-recorder approve <id>`; unanswered means denied, which is what
someone who walked away would have wanted. These three rules *are* a guess
about a vocabulary — and `doctor` prints exactly which of your real tools they
matched, so the guess becomes a measured fact at install time.

**The hook leg denies less, and says so.** The Claude Code hook protocol can
allow or deny and nothing else — there is no way to ask a question and wait.
So `policy.starter.json`, which governs the hosted connectors, carries only
the irreversible-and-essentially-never-wanted set (destructive tools, money)
and deliberately **not** sending, which the gateway leg holds. The file states
that in its own text and gives the one line to add if you want the wall.

**Outbound HTTP is deliberately allowed.** A large share of useful MCP servers
are HTTP clients, and denying them makes the first run a wall of refusals for
calls you wanted. What still protects that path is the credential rule above
and the boundary filter below. The stricter rule ships commented out, one
line, with a note saying when to turn it on.

**All four denies scan every string argument, and there is a size cliff.** They
use `match.any_arg`, which searches every string leaf of the call; a call
carrying more than **256 string values or 256 KiB of argument text** cannot be
scanned, so the rules are unevaluable and the call is **denied** — a partial
scan is a deny that silently became an allow. That is reachable by ordinary
work: a 300 KiB generated file, a multi-file push, a long document. The
refusal says so and names the setting that raises it (`mcp.any_arg:
{ max_bytes: … }`, [docs/policy.md](docs/policy.md#mcpany_arg--the-scan-budget)),
the starter policy carries the same note above the deny block, and
`mcp-recorder why` explains it. Raise the budget rather than deleting the
denies: a bigger budget scans *more*, never less.

**A hold stops your agent.** While a call is held the agent is waiting, and the
only notice is a line on the proxy's stderr — which a GUI client does not show
you. Unanswered, that is a silent two-minute stall and then a refusal. `doctor`
and `protect` both say how many of your tools are held, out loud, for this
reason.

Reads are allowed. `mcp.default` is `allow`: enforcement is aimed at effects,
not applied as a wall.

To change anything: edit the file, or delete it and pass a `--policy` of your
own. A second `protect` run leaves your edits alone and says so. Then fully
restart your client.

---

## Enforcement, in full

`protect` is one policy. Here is the whole mechanism behind it, for when you outgrow the starter.

Record mode never interferes with traffic. Pass `--policy policy.yaml` (or `--protect` for the starter) and the same proxy becomes a **gateway**: every `tools/call` is evaluated against ordered per-tool rules (first match wins) and is **allowed** byte-for-byte, **denied** with a tool error the model can read, or **held** until a human runs `mcp-recorder approve <id>` (or a timeout decides). Tool results pass through a **boundary filter** on the way back: secret-shaped values are redacted with `[redacted:sha256:…]` (their hashes stay queryable), and prompt-injection markers are flagged or blocked. Every decision is sealed into the same evidence chain (`policy_decision` events, `tool_call.gateway`, `session_start.policy`).

```yaml
version: 1
mcp:
  default: allow
  rules:
    - { id: no-exfil,   match: { tool: [http_post, "send_*"] }, action: deny, reason: no outbound HTTP }
    - { id: dangerous,  match: { tool: ["delete_*", "rm*"] },   action: hold }
    - { id: no-secrets, match: { tool: read_file, args: { path: "(^|/)(\\.env|id_rsa)$" } }, action: deny }
    # `args` is keyed by a dot-path, so it only governs a tool that calls its
    # argument `path`. `any_arg` searches EVERY string leaf of the arguments,
    # at any depth and under any key — which is how the starter's deny rules
    # hold across servers whose field names you do not control.
    - { id: any-credential-file, match: { tool: "**", any_arg: "(^|/)(\\.env|id_rsa)$" }, action: deny }
  boundary: { secrets: redact, injection: flag }
```

```sh
mcp-recorder policy validate policy.yaml
mcp-recorder setup --client claude-desktop --policy /abs/path/policy.yaml
mcp-recorder holds && mcp-recorder approve <id>
mcp-recorder policy compile policy.yaml --out ./bundle     # Rego for the Cresec control plane (OPA)
```

Ten-minute walkthrough for a laptop and for CI: [docs/gateway.md](docs/gateway.md). Full schema, matching semantics and the Rego output: [docs/policy.md](docs/policy.md). What to paste into your agent's `CLAUDE.md` / `AGENTS.md` so it reports a refusal instead of retrying it or reaching the same effect through another tool: [docs/agent-guidance.md](docs/agent-guidance.md). Enforcement fails closed (an unevaluable policy denies) while recording stays fail-open.

**Over HTTP too.** `mcp-recorder http --target https://vendor.example/mcp --policy policy.yaml` is the same gateway in front of a remote (streamable-HTTP) MCP server: the same evaluation, holds, boundary filter and `policy_decision` events, over the HTTP exchange instead of the stdio line. The one thing that changes is buffering: a `tools/call` request body and its result are held long enough to evaluate and filter them (a JSON body whole, an SSE stream one event at a time); without `--policy` the HTTP proxy streams every byte exactly as before. With a `credentials[].broker: { kind: remote }` section the per-user token is fetched from the Cresec control plane per call and swapped at the declared site ([docs/policy.md](docs/policy.md#credentialsbroker--resolved-by-the-control-plane)); with `--identity-jwt` every event carries the ADR 012 actor claim ([docs/event-schema.md](docs/event-schema.md#actor-claim-optional-additive)). Which invariants that touches, and what still does not hold, is in [docs/pov.md](docs/pov.md).

---

## Then, the evidence underneath

The refusal you just watched is in the same signed chain as everything else,
produced by someone who was never asked to author anything. That is the line
that sells this to the buyer:

```sh
$ mcp-recorder sessions
SESSION   STARTED               SERVER      EVENTS  TOOL_CALLS  ERRORS  SERVERS  DECISIONS  LAST_EVENT
a91c4e02  2026-09-21T18:04:11Z  filesystem      41          17       2        2          3  2026-09-21T18:22:09Z

$ mcp-recorder verify
PASS — chain intact: 41 event(s), head seq 41
signed head: seq 41 by ed25519 9f3a…2e7b

$ mcp-recorder export --out evidence.zip
wrote evidence.zip — a stranger can check it with:  node verify.cjs
```

`DECISIONS 3` is the enforcement showing up as evidence. The rest of the
toolkit reads the same chain:

```sh
mcp-recorder why                          # what was stopped, why, and how to change it
mcp-recorder ui                           # HTML replay timeline in your browser
mcp-recorder query "AKIA..."              # blast radius: which sessions touched this value?
mcp-recorder verify --bundle evidence.zip # what the stranger runs
```

`query` hashes the needle whole, so it matches **exact values, not
substrings**: search `https://attacker.example/collect`, not
`attacker.example`, and the bare tool name (`clickup_filter_tasks`), not the
`mcp__<server>__<tool>` spelling Claude Code shows you.

### Wrapping a server by hand

`protect` and `setup` edit the config for you. If you keep your client config
under version control and would rather edit it yourself, the whole integration
is one line:

```
BEFORE  {"command": "npx", "args": ["-y", "@some/mcp-server"]}
AFTER   {"command": "npx", "args": ["-y", "@edut/mcp-recorder", "--protect", "--", "npx", "-y", "@some/mcp-server"]}
```

`--protect` means `--policy <data-dir>/policy.starter.yaml` and nothing else.
It **never writes that file**: if it is not there, the recorder exits 2 before
the server is spawned and tells you to run `mcp-recorder protect`. A flag that
mints the policy it then enforces is a policy nobody chose. Drop `--protect`
and you have the transparent recorder, byte for byte.

---

## How it works

```
                stdin/stdout — bytes forwarded UNCHANGED, fail-open
 ┌────────────┐        ┌────────────────────────────┐        ┌──────────────┐
 │ MCP client │ ◄────► │   mcp-recorder (proxy)     │ ◄────► │  MCP server  │
 │  (Claude,  │        │                            │        │ (any stdio)  │
 │  Cursor,…) │        │   tap ─► redact ─► hash    │        └──────────────┘
 └────────────┘        └─────────────┬──────────────┘
                                     │ async, off the hot path
                                     ▼
                       ┌────────────────────────────┐
                       │   tamper-evident store      │
                       │   ~/.mcp-recorder           │
                       │                             │
                       │  event_n ──┐                │
                       │  hash_n = sha256(           │
                       │    hash_{n-1} + canonical)  │
                       │  head signed with ed25519   │
                       └────────────────────────────┘
```

Four pillars:

1. **Transparent fail-open stdio proxy.** The proxy never parses-then-rewrites; it forwards the exact bytes and taps a copy. If recording dies, traffic keeps flowing. Added latency is <5ms p50.
2. **Edge redaction.** Payload strings never reach disk. Each string leaf is replaced by its SHA-256 (`sha256:<hex>`) plus its length — structure preserved, content gone. Object *keys* are redacted too (a map keyed by an email or a secret-shaped string doesn't land in clear either). A tool call's `arguments` are hashed unconditionally, key and position notwithstanding; a small, fixed vocabulary of structural fields (`type`, `role`, `level`, `mimeType`, `protocolVersion`, `method`, and `name` only at `tools[*].name`/`prompts[*].name`) may pass elsewhere, and only when the *value* also looks like that field, not merely because the key matches. Hashes are unsalted *by design*: if you later need to know whether a known value (an API key, a customer email) ever passed through, hash it and search — including a value glued into a longer string, which is tracked separately so it isn't lost inside one opaque leaf hash.
3. **Tamper-evident store.** SQLite (JSONL fallback), append-only. Every event is sealed as `sha256(prev_hash + "\n" + canonicalJson(event))`, and the chain head is signed with a local ed25519 key. `mcp-recorder verify` re-walks every link; altering, inserting, or deleting any stored row makes it fail loudly.
4. **Reconstruction tools.** An HTML replay timeline (see → act → effect, with identity context on every event), a blast-radius query ("which sessions touched X?"), and a signed evidence bundle — a ZIP containing `events.jsonl`, `manifest.json`, `public_key.pem`, and a standalone, dependency-free `verify.cjs` that anyone can run with bare `node`.

**Multiple wrapped servers, one data dir.** The normal setup is one `mcp-recorder record` process per MCP server, all pointed at the same `--data-dir`. Any number of them may run at once: each append is sealed under the store's own exclusive lock (a `busy_timeout`'d transaction for sqlite, an advisory lock for jsonl), so writers never lose or fork the chain — their sessions simply interleave, seq by seq, in one shared hash chain.

---

**Where this fits.** Governed Tools is four pieces: Okta-brokered identity on the way in, credential-less tools in the middle, mediated egress on the way out, and one signed record across all three. This package is the MCP half of the egress leg and the signed record: the recording proxy, the policy gateway for MCP tool calls, the hash chain, the bundle and the verifier. The identity gate, the per-user credential vault, the HTTPS egress gateway and the manager and security views are the Cresec control plane's job in [cresec-ai/nhi](https://github.com/cresec-ai/nhi) (its share of Roadmap v2 runs through Phases 1–4 and 6; those four pieces now run from a clean checkout of that repository at `d1346a7` through `tests/e2e/scripts/stack-local.mjs`, with its S0–S16 suite green in one local run on 2026-09-21; that runtime has been on its `main` since PR #4 (`5b99fe3`), where the `e2e-stack` CI job has run the same suite green ([run 35654937905](https://github.com/cresec-ai/nhi/actions/runs/35654937905)). That is **L1**: deployed nowhere, and every vendor answer from a fake in its `tests/e2e/mocks/`). This package still does not contain them. Two related limits here are narrower than they used to be. Events carry an OS username and a hostname unless the recorder is started with `--identity-jwt`, in which case every event also carries the ADR 012 actor claim `identity.actor` (user, tool, host, run_as) and `identity.actor_verified` (`docs/event-schema.md`, "Actor claim (optional, additive)"; `test/identity.test.ts`). The **local** credential broker resolves credentials on the agent's own machine, but `credentials[].broker: { kind: remote }` puts a control plane behind it instead (`src/broker/remote.ts`), tested against a fake control plane only. Three of the things just described — the ADR 012 actor claim with `--identity-jwt` (`src/identity/`), `http --policy` gateway mode (`src/proxy/http-gateway.ts`) and the remote broker pointed at the control plane's `POST /v1/broker/user-token` — are merged into `main`, which is what the install command above fetches. The remote broker has still only ever been run against a **fake** control plane, never a real one. What this package contributes to the four-week proof of value, week by week and with a status on every capability, is in **[docs/pov.md](docs/pov.md)**; the backlog keyed to Roadmap v2 is in **[docs/roadmap.md](docs/roadmap.md)**.

---

## Commands

```
mcp-recorder [record] [options] -- <server command...>
```

| Command | What it does |
| --- | --- |
| `mcp-recorder protect --client claude-desktop\|claude-code\|cursor [--config PATH] [--data-dir D] [--settings PATH] [--no-probe] [--dry-run]` | **The one command in the pitch.** Materialise the starter policy at `<data-dir>/policy.starter.yaml` (and `policy.starter.json` for the hook leg), wrap every stdio server in the client's config with it through the ordinary `setup --policy` path (backup + sidecar, so `setup --undo` reverses it exactly), install the Claude Code hook with the twin, then run `doctor` and print its verdict last. Never overwrites an existing starter policy. `--dry-run` writes nothing at all, including the starter files. Exit code is doctor's — `1` a check FAILed, `3` nothing failed but something was **unchecked**, `0` all clear — so `protect && echo installed` cannot print that line over a server that was never enumerated. The one discount: the C2 "a session that began BEFORE this hook was installed is still running" FAIL is the unavoidable consequence of a *successful* install from inside a live session, so `protect` prints the restart instruction and does not count it. `doctor`, which writes nothing, still does. |
| `mcp-recorder doctor [--client NAME] [--config PATH] [--settings PATH] [--data-dir D] [--no-probe] [--json]` | **Is enforcement actually in force, right now?** Six tri-state checks — OK / FAIL / INCOMPLETE, and a check that could not run never passes. C1 wiring, C2 hook, C3 tool-name spellings, C4 coverage against the tools your servers really expose, C5 a live denied call through a real spawned proxy in a throwaway data dir, C6 chain health. Exit `0` / `1` (a FAIL) / `3` (something unchecked) / `2` (doctor could not run). `--json` is the stable machine interface; `--no-probe --json` is the CI pre-flight. |
| `mcp-recorder why [--data-dir D] [--limit N] [--session ID] [--policy FILE] [--json]` | What was stopped, why, and how to change it — the person's side of the refusal boundary, which the agent's own refusal deliberately does not carry. Read-only over the chain. Prints **no argument or result text**: every string comes from your policy file, the tool name and the rule id. |
| `mcp-recorder [record] [--data-dir D] [--name N] [--identity L] [--redact allowlist\|off] [--policy FILE] -- <server command...>` | Run the wrapped server behind the recording proxy (`record` is the default subcommand and may be omitted). `--name` sets the logical server name, `--identity` an operator label stamped on every event. `--protect` enforces the starter policy `protect` wrote (and never writes it — missing is exit 2 before the server is spawned); `--policy FILE` switches on **gateway mode**: `tools/call` requests are allowed / held / denied per the policy and tool results pass through the boundary filter — see [Gateway mode](#gateway-mode-opt-in-enforcement). |
| `mcp-recorder policy validate FILE [--json]` | Validate a `policy.yaml` against the v1 schema (exit 0 valid, 1 invalid, 2 unreadable). See [docs/policy.md](docs/policy.md). |
| `mcp-recorder policy test FILE --tool NAME [--server S] [--args JSON] [--leg gateway\|hook] [--expect allow\|deny\|hold] [--json]` | The deny-rule smoke test: what the policy decides for one tool name, spelled exactly as observed, through the engine that governs its leg — `evaluateMcp` for a `policy.yaml` (server, bare tool, arguments; an `mcp__<server>__<tool>` spelling supplies the server), the hook's own evaluator for its JSON policy (the full `mcp__<segment>__<tool>` name). The leg is detected from the file. On the hook leg it also evaluates every other server segment a client could choose (doctor C3's spellings) and warns when the verdict changes — a rule anchored to one session's spelling. Nothing is spawned or recorded. Exit `0` evaluated; `1` `--expect` not met (on the hook leg, a verdict that holds for only some spellings does not meet it) or the policy is invalid; `2` usage error or unreadable file. |
| `mcp-recorder policy compile FILE [--target rego] [--out DIR]` | Compile a `policy.yaml` to an OPA bundle (`cresec.mcp` / `cresec.egress` Rego modules) for the Cresec control plane; without `--out` the MCP module is printed. |
| `mcp-recorder holds [--data-dir D] [--all] [--json]` | List tool calls currently held for approval by a gateway (`--all` includes decided ones). |
| `mcp-recorder approve <id> [--data-dir D]` / `mcp-recorder deny <id> [--data-dir D]` | Decide a held tool call. `<id>` accepts a unique prefix, the same short id `holds` prints. |
| `mcp-recorder verify [--data-dir D] [--store sqlite\|jsonl] [--bundle PATH] [--public-key K] [--allow-unsigned] [--json]` | Re-walk the hash chain and check head signatures — for the local store, or for an exported bundle with `--bundle` (accepts either form `export` produces: a `.zip` or a bundle directory). `--public-key` pins to a key obtained out of band instead of the default (`<data-dir>/identity.pub`, or the bundle's own manifest key); `--allow-unsigned` downgrades an unsigned chain/tail from a failure to a warning (store mode only — a bundle's own manifest range/signature must always match exactly, see "Security model"). |
| `mcp-recorder query <needle> [--data-dir D] [--store sqlite\|jsonl] [--session ID] [--json]` | Blast radius: hash the needle and find every event and session that touched that value. **Exact values only** — the needle is hashed whole, so a substring, prefix or host part of a URL finds nothing. `--session` accepts a unique id prefix, the same short id `sessions` prints. |
| `mcp-recorder sessions [--data-dir D] [--store sqlite\|jsonl] [--json]` | List recorded sessions: first server, identity, event/tool-call/error counts, then three appended columns — `SERVERS`, the number of distinct servers the session's tool calls went to (`server_count` in `--json`); `DECISIONS`, the number of enforcement actions gateway mode took (`policy_decision_count`); and `LAST_EVENT`, the timestamp of the session's last event (`last_event_at`), which is the instant every count in the row runs through. All three are additive `--json` keys, and each new column is appended after the last, so a column that existed before keeps its position. Tool calls are counted per call, so a hook-captured call (a `pre` + `post` event pair) counts once. `DECISIONS` counts one per deny and one per resolved hold — including a hold the operator approved — so a session recorded without `--policy` reads `0`. `ENDED` shows an end time only when the session's `session_end` really is its last event: a session resumed under the same id keeps recording after its `session_end`, and reads `(reopened)` rather than a superseded end time (`--json` still carries that `ended_at`). `--json` is the stable machine interface; the table is for reading. |
| `mcp-recorder sessions --tools [--data-dir D] [--store sqlite\|jsonl] [--session ID] [--json]` | The per-server, per-tool census of what was actually called: one row per (`server.name`, tool) with `CALLS` (counted per call, as `sessions` counts them), `ERRORS`, `DENIED` (the gateway's refusal and the hook's deny shape, one per refusal), `HELD` (one per resolved hold), `SESSIONS` (distinct sessions that called it) and `LAST_SEEN`; `--json` adds `first_seen`. Over the whole chain, or one session with `--session` (a unique prefix works). A hook session's server is the platform's `mcp__<segment>__`, so one hosted connector can appear under more than one name; the census shows what was recorded. |
| `mcp-recorder ui [--data-dir D] [--store sqlite\|jsonl] [--session ID] [--port P] [--out FILE] [--no-open] [--public-key K] [--allow-unsigned]` | Serve the HTML replay timeline (or write it to a file with `--out`). Opens your default browser to the served URL unless `--no-open` is set, `--out` is used, or the host looks headless. The integrity banner is resolved the same way as `verify` (same default `identity.pub` pin, same `--public-key`/`--allow-unsigned`), so it never shows green for a chain `verify` would reject. |
| `mcp-recorder export [--data-dir D] [--store sqlite\|jsonl] [--session ID] [--out FILE.zip] [--dir DIR]` | Produce a signed evidence bundle as a ZIP or plain directory. `--session` accepts a unique id prefix, the same short id `sessions` prints. Requires an existing `identity.key` in the data dir — it signs with the key that actually produced the chain, never minting a fresh one, so exit 2 on a data dir with no key (e.g. a store copied without it). |
| `mcp-recorder http --target URL [--port P] [--policy FILE] [--identity-jwt PATH [--identity-jwks PATH\|URL]]` | Recording proxy for HTTP-transport (streamable HTTP) MCP servers. With `--policy` (or `MCP_RECORDER_POLICY`) it is the same gateway `record --policy` is: allow / hold / deny per `tools/call`, the boundary filter on results, a `credentials` section that swaps a synthetic for a real or control-plane-brokered token. `--identity-jwt` stamps the ADR 012 actor claim on every event (both commands, and `hook`). |
| `mcp-recorder setup --client claude-desktop\|claude-code\|cursor [--config PATH] [--wrapper local\|npx\|wsl] [--only N,...] [--except N,...] [--bridge NAME=URL,...] [--data-dir D] [--policy FILE] [--dry-run] [--undo] [--json]` | Wrap every stdio MCP server in a client's config behind the recorder — safely (a timestamped backup + a sidecar recording the originals) and reversibly (`--undo`). `--config` overrides the resolved path (and makes `--client` optional); for `claude-desktop` this also finds a Microsoft Store (MSIX) install on Windows. `--policy FILE` validates the policy up front (exit 2, config untouched, if it is missing or invalid) and bakes `--policy <absolute path>` into every wrapped entry so those servers run in gateway mode — including entries an earlier run already wrapped, which are reported separately as `updated`. `--wrapper local` (default) points at this install's own `dist/cli.js`; `--wrapper npx` writes the published-package form; `--wrapper wsl` writes a `wsl.exe`-launched form for a Windows client whose server should run inside WSL, auto-selected when `setup` runs inside WSL against a Windows-side config (see [docs/install.md#windows-and-wsl](docs/install.md#windows-and-wsl)). `--bridge NAME=URL` turns a remote MCP connector into a local, wrappable entry via `mcp-remote` (see [docs/install.md#connectors-what-the-recorder-can-and-cannot-see](docs/install.md#connectors-what-the-recorder-can-and-cannot-see)). `--dry-run` previews without writing. See [docs/install.md](docs/install.md) for the full walkthrough. |
| `mcp-recorder hook [--data-dir D] [--store sqlite\|jsonl] [--policy FILE] [--client NAME] [--all-tools]` | Claude Code PreToolUse/PostToolUse/PostToolUseFailure/SessionEnd/Stop hook handler: reads one hook JSON object on stdin, records a redacted `tool_call`/`session_*` event, and (PreToolUse only) prints a policy deny decision when `--policy` says to. The only place a third party gets visibility into Anthropic-hosted connectors (`mcp__ClickUp__*`, `mcp__Gmail__*`, ...) that no local MCP proxy can see. Fail-open: never blocks a tool call, never exits non-zero, except a deliberate `--policy` deny. Only `mcp__`-prefixed (MCP) tools are recorded by default; `--all-tools` also records built-ins. See [docs/hooks.md](docs/hooks.md). |
| `mcp-recorder hook install [--settings PATH] [--all-tools] [--policy FILE] [--data-dir D] [--client NAME] [--command CMD] [--dry-run] [--undo] [--json]` | Merge the hook entries above into a Claude Code settings file (default `.claude/settings.json`; created if missing) — safely (timestamped backup) and reversibly (`--undo`), idempotent. `--command` overrides the generated command verbatim (e.g. a repo-relative dogfood form). See [docs/hooks.md](docs/hooks.md). |
| `mcp-recorder ship [--data-dir D] [--sink URL] [--token T | --token-file F] [--drain [--timeout D]] [--idle-exit D] [--status [--json]]` | Replicate sealed chain records to an evidence sink as they are recorded, so evidence stops being something the observed party has to remember to hand over. One shipper per data dir; `record`/`http`/`hook` auto-start it when `MCP_RECORDER_SINK` is set, so you rarely run this yourself. `--drain` ships the backlog and exits (the CI form — use it with `|| true`). `--status` prints sink, key, `chain_id`, local head, receiver `next_seq`, `attested_seq`, lag and the last error/success without touching the network. Before each batch the shipper recomputes its OWN chain up to that batch and stalls, visibly, rather than extending the receiver's copy from a local history that no longer verifies. Fail-open: a sink that is down, slow, 500ing, 401ing or hostile never blocks a tool call, never denies one, never changes a proxy's stdout or exit code, and never loses a local event. See [docs/sink.md](docs/sink.md). |

`--help`/`-h` and `--version`/`-V` work on every invocation.

### Environment variables

| Variable | Effect |
| --- | --- |
| `MCP_RECORDER_DATA_DIR` | Override the data directory (default `~/.mcp-recorder`). |
| `MCP_RECORDER_STORE` | `sqlite` or `jsonl` (default: whichever evidence file already exists in the data dir wins; on a fresh data dir, sqlite when available, else jsonl). |
| `MCP_RECORDER_REDACT` | `allowlist` (default) or `off`. Secret-shaped values are hashed in every mode. |
| `MCP_RECORDER_DISABLE` | `1` → pure passthrough, no recording — and no gateway enforcement either (it is the kill switch). |
| `MCP_RECORDER_POLICY` | Path to a `policy.yaml`; same effect as `record --policy` / `http --policy` when the flag is absent. |
| `MCP_RECORDER_MCP_CONFIG` | `hook` only: the Claude Code MCP config file(s) to resolve server origins from (`server.url`, and the policy alias `mcp__<host>__<tool>`) — one path or comma-separated paths. Default: the cloud session's `/tmp/mcp-config-*.json`. A local machine has no such file and no connector in any `mcpServers` map, so nothing resolves there and only tool-anchored deny rules can fire — see [docs/hooks.md](docs/hooks.md#local-sessions-no-config-file-so-no-serverurl). |
| `MCP_RECORDER_SINK` | Base URL of an evidence sink to replicate sealed records to. **Setting it is the entire opt-in** — with it absent there is no sink, no shipper and byte-identical behaviour to a build without the feature. `https://` only (loopback is the one `http://` exception); `HTTPS_PROXY`/`NO_PROXY` are honoured and certificate verification is never disabled (use `NODE_EXTRA_CA_CERTS` for a proxy CA). See [docs/sink.md](docs/sink.md). |
| `MCP_RECORDER_SINK_TOKEN` | Bearer token for the sink. It authorises the CHANNEL only — records are filed under the data dir's ed25519 key, so a stolen token cannot write into another install's chain, forge events or delete history. |
| `MCP_RECORDER_SINK_TOKEN_FILE` | Same, read from a file, for platforms where a root-owned file is easier to protect than an environment variable. |

---

## The demo

For a small downloadable synthetic bundle with both intact and deliberately
tampered examples, see the [public evidence sample](docs/public-evidence-sample.md).
It uses the real offline verifier and explains integrity, coverage, enforcement
and signer trust separately; its result is not a claim of production traffic.

```sh
npm run demo
```

A scripted prompt-injection exfiltration — an agent is tricked into reading a credential and sending it out through an innocent-looking tool — recorded, reconstructed on the replay timeline, blast-radius-queried, and cryptographically verified, in under a minute. It is the fastest way to see what the recorder is for.

Want to see the same story with a real model instead of the scripted agent? [docs/red-team.md](docs/red-team.md) walks through running it live in Claude Desktop.

---

## Security model (the honest version)

**What you get: tamper *evidence*, not tamper *prevention*.** Anyone with write access to your disk can delete the store outright. What they cannot do silently is *edit* it: every event is hash-chained, and the head is signed, so any modification, insertion, or deletion inside the recorded range makes `verify` fail loudly.

Read the fine print:

- **Tail truncation.** Deleting events from the end of the chain is detectable only back to the last signed head. The recorder signs the head on every flush, which keeps the unsigned window small, but an attacker who can also delete signatures can roll the chain back to an older signed head. For stronger guarantees, anchor head signatures externally (ship them to another machine, a log, a timestamping service) — the `HeadSignature` records are small and self-contained.
- **An unsigned chain is a failure, not a warning.** `verify` fails (not just warns) when no part of the chain carries a single valid signature, and when the unsigned tail after the newest valid signature contains a `session_end` event — the recorder signs on every flush, *including* the session_end flush, so that signature is missing outright, not merely pending the next one. (Several concurrent recorder processes can interleave sessions in one chain, so this is "the tail contains *any* session_end", not just the latest session's.) A genuine crash mid-session — an unsigned tail with no `session_end` in it — stays a warning: flushes can legitimately outrun head signing. Pass `--allow-unsigned` to downgrade the hard failures back to warnings, e.g. for tooling that needs to tolerate an in-flight session.
- **Unsalted hashes — a deliberate tradeoff.** Redaction refs are plain `sha256(value)`, no salt. This is what makes blast-radius queries possible: hash a candidate value and search for it. The flip side: a party who *already holds* a candidate value (or can enumerate a small space of them) can confirm whether it was seen. The store never leaks values to someone who doesn't already have them, but it does confirm membership to someone who does. If that tradeoff is wrong for your threat model, treat the store itself as sensitive. This applies uniformly to leaf values, object keys, argv elements/credential fingerprints, and tokens embedded inside a larger string — everything `query` can find was hashed the same unsalted way. Say the sharp version of "a small space" out loud: a *low-entropy* secret — a short passphrase, a dictionary word, a token someone typed by hand — is not merely confirmable from its ref, it is **recoverable** from it, by hashing candidates until one matches. Refs protect high-entropy values; they are not a vault for weak ones. That is also why the recorder never fingerprints its own configuration (`MCP_RECORDER_*`, notably the evidence sink's bearer token): the sink ships every event to the receiver that token authenticates to, so a ref of it would hand that receiver a reversible copy of its own credential on every event — and no blast-radius query ever needed it, because the agent never sees it.
- **A `query` miss is not proof of absence.** `query` finds a value if it was hashed as a whole leaf, hashed as an object key, embedded inside a larger leaf as a recognizable secret shape (`secret_refs`, capped at 8 per leaf), or scrubbed out of the wrapped command's argv. A value that never took one of those shapes — folded into a longer plain string under a key the allowlist doesn't recognize, for instance — was still hashed (nothing readable reaches disk either way), there just isn't a standalone ref to search for. Treat a miss as "not found this way", not as "never touched the proxy".
- **The recorder trusts its own key — unless you pin it.** The ed25519 key lives in the data dir (`identity.key` / `identity.pub`). Signing alone proves nothing about *who* signed: an attacker who can rewrite the store can also write a forged chain, sign it with a fresh key of their own, and the signature is cryptographically genuine — it just isn't the operator's. So `verify` pins a specific key rather than trusting whatever key rode along with the data being checked: for a local store it reads `<data-dir>/identity.pub` by default and rejects any signature made by a different key; for an exported bundle it defaults to the bundle's own `manifest.json` key, which only proves the bundle is *internally self-consistent* (an attacker who forges a whole bundle from scratch ships a key that matches itself, so this alone is not third-party assurance). Pass `--public-key <64-hex | path to a hex or PEM file>` — to `mcp-recorder verify` or to the standalone `verify.cjs` shipped inside every bundle — pinned to a key you obtained **out of band** (from the operator directly, never from the artifact you're checking) for real independent verification. None of this protects against a fully compromised host that can rewrite `identity.key`/`identity.pub` together with the chain. If a local store has neither `identity.pub` nor a `--public-key`, `verify` still checks the chain but accepts a signature from *any* key — this is never silent: the human output prints a `WARNING` line and the verdict reads `PASS (unpinned)` (`--json` carries `pinned_public_key: null, unpinned: true`), and `ui`'s integrity banner uses this same pin resolution so it can never show green for a chain `verify` rejects.
- **A bundle is a sealed artifact — its own manifest must match exactly.** `manifest.json`'s `range`/`event_count`/`head_hash`/`signature` are checked against what `events.jsonl` and `public_key.pem` actually contain: any mismatch is an unconditional failure (`bundle_manifest_mismatch` or `signature_invalid`), never downgradable by `--allow-unsigned`. Without this, records self-consistently chained onto the real signed head but appended *after* export — no key needed — would verify as a mere "unsigned tail" warning, since a bundle's manifest is the only thing declaring where the sealed range is supposed to end; a forgery re-signed with an attacker key that ships the operator's genuine `public_key.pem` is caught the same way (the shipped PEM must match the key named in `manifest.signature`). `verify --bundle` and the standalone `verify.cjs` inside every bundle agree on every one of these checks. A `.zip` bundle with a duplicate entry name (e.g. two `events.jsonl`) is rejected outright rather than trusting whichever copy is found first — real unzip tools extract whichever comes *last*, and silently accepting the first would let a genuine copy verify while a forged one gets written to disk.
- **`export` never mints a signing key.** It signs with the *same* key that produced the chain (`Signer.loadExisting`), and exits 2 if `identity.key` is missing from the data dir — e.g. a store copied to another machine without it. The alternative (silently minting a fresh key, which `record` does on a brand-new data dir) would let `export` "succeed" signing with an identity that never touched the evidence, and would repoint the default `identity.pub` pin out from under the next `verify`.
- **A reader that goes away doesn't erase a FAIL.** `verify`'s exit code is decided before anything is printed, so `mcp-recorder verify | head -1` on a failing store still exits 1 — a `SIGPIPE`/`EPIPE` from an early-closing reader can no longer be mistaken for the command's own success.
- **Fail-open means recording can be lost.** By design, if the store breaks mid-session the proxy keeps forwarding and counts dropped events (`events_dropped` in the `session_end` event). Availability of your agent always wins over completeness of the record.
- **A hook `deny` is a policy decision, not a guarantee.** `mcp-recorder hook` can block a Claude Code tool call before it runs, but only when a rule matches the `tool_name` Claude Code hands the hook — and the `mcp__<server>__` segment of that name is the platform's to choose, and has differed between sessions a day apart. In cloud dogfood 4 a policy with two deny rules, one aimed at the resolved host alias and one at the raw UUID form, blocked neither of the two live ClickUp calls it targeted: that session presented them as `mcp__ClickUp__…`, both rules missed, and the resulting 62-event signed bundle (which verifies PASS) contains zero policy decisions — every call was recorded, none was blocked. Write deny rules against the tool with the segment left open (`^mcp__.*__clickup_delete_task$`) and smoke-test them: [docs/hooks.md](docs/hooks.md#write-deny-rules-against-the-tool-not-the-server-segment).

## Event schema

Events follow the frozen schema `edut.mcp-recorder.event.v1`, with field names aligned to OpenTelemetry GenAI/RPC semantic conventions. The full schema — every event kind, every field, the chain construction, and the canonicalization rules — is documented in [docs/event-schema.md](docs/event-schema.md).

## What we explicitly do NOT do

- **No payload storage.** Strings are hashed at the edge — leaf values, object keys, and the wrapped command's argv alike; original values never land in the store. A tool call's `arguments` are hashed unconditionally, regardless of key.
- **No cloud.** Local-first, no telemetry, no phone-home. Evidence leaves your machine only when you run `export`, or when you opt in to an evidence sink by setting `MCP_RECORDER_SINK` (see [docs/sink.md](docs/sink.md)); with that variable unset the recorder opens no connection of its own — the exceptions are the target you name on `http`, and the `github-app`, `aws-sts`, `vault` and `clickup` credential sources, which call out only when your policy's `credentials` section declares them.
- **No enforcement unless you ask for it.** In record mode the recorder observes; it never blocks, rewrites, or rate-limits traffic. It is a recorder, not a firewall. Enforcement exists only in [gateway mode](#gateway-mode-opt-in-enforcement), only with an explicit `--policy`, and only over `tools/call` requests and their results — every other message is still forwarded untouched.

## Development

`npm install`, then `npm run typecheck && npm run lint && npm test` before sending a PR. `npm run lint:fix` applies the auto-fixable subset.

## License

GPL-3.0. The recorder sits in your trust path, so you should be able to read every line of it — and so should everyone downstream of any fork.

## Built in the open — one design partner wanted

This project is being built in public. We are looking for one design partner for a four-week proof of value of Governed Tools: an Okta admin, a Salesforce admin to approve one connected app, a Google Workspace admin to allowlist one OAuth app, one rep with a working Claude routine and two hours, and a named tool owner. Three admin actions from you, zero production traffic rerouted, no capture SDK, no UI built by us. Week 1 is a read-only before-number from your Okta and Salesforce (or Google Workspace) audit logs; week 3 ends with one signed evidence bundle your security team verifies with bare Node and no network access to us. What happens each week, what this package contributes, and what we do not claim is in [docs/pov.md](docs/pov.md); the scope is on the [Governed Tools story page](https://app.clickup.com/90182720801/docs/2kzmy791-558/2kzmy791-618). Open an issue on this repository to start the conversation.
