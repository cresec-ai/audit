# The first run — enforcement first, evidence underneath

**Status: implemented.** `protect`, `doctor`, `why`, the starter policy and
`match.any_arg` all ship; `test/protect-doctor.test.ts` pins the guarantees
below, including the dogfood-4 detection in both orderings and the invariant
that a bare `record` still enforces nothing. Three details of the design
below were changed while building it, and this document has NOT been rewritten
around them — it is kept as the design it was, and these are the deltas:

1. **The hook twin denies less than the gateway twin.** The hook protocol has
   no way to ask a question and wait, so a `hold` is not expressible there.
   `policy.starter.json` therefore carries only the
   irreversible-and-essentially-never-wanted set (destructive tools, money)
   and deliberately NOT sending, which the gateway leg holds. The file says so
   in its own text and gives the line to add if you want the wall.
2. **Check C3 got a second, syntactic half.** The behavioural check ("matches
   some spellings, misses others") cannot fire for a rule whose one spelling
   doctor is unable to construct — cloud dogfood 4 saw `ClickUp` where the
   vendor host reads `clickup`, and no rule for turning one into the other is
   trustworthy. So C3 also READS the rule: a regex that names a literal
   `<segment>` between `mcp__` and `__` is a FAIL whatever the vocabulary.
   That is what makes the check work in CI with no session running.
3. **`why` reads the boundary report's real fields.** `BoundaryReport` carries
   `secrets_found` / `injection_found` / `action`, not the names sketched
   here, and `why` only lists a result the filter actually ACTED on.
4. **The hold globs are verbs, not nouns, and there are fewer of them.**
   Measured against real vocabularies, the sketched `*charge*` / `*invoice*` /
   `*order*` held `list_charges`, `get_invoice` and `order_issues` — reads and
   a sort — and `move_*` / `rename_*` were the ONLY thing `destructive-tools`
   matched on a filesystem server, holding a routine refactor. A hold stops
   the agent, so a hold on a read is not caution, it is a stall. Those globs
   are gone; the four argument-anchored denies are unchanged.
5. **The `any_arg` scan budget is a settable policy field.** `mcp.any_arg:
   { max_leaves, max_bytes }`. The cliff (256 leaves / 256 KiB by default) is
   reachable by ordinary work — a large file write, a bulk push — and past it
   every `any_arg` rule is unevaluable, so the call is DENIED. It now names
   itself (`policy_decision.error_code: "arguments-too-large-to-scan"`, the
   same string on the proxy's stderr and behind a refusal clause that does
   NOT invite a retry), and `why` explains it. This design did not have it.
6. **`why` checks `policy_hash` before it blames a file.** The sketch had
   `why` read reasons out of the starter policy whenever one existed. A person
   who outgrew the starter and re-wrapped with their own policy — possibly
   with the same rule ids — was then told to edit a file that is not in force.
   Reason text and the "open this file, delete this rule id" remedy are now
   printed only when the candidate file's bytes hash to the decision's
   `policy_hash`.

It specifies
the first five minutes of `@edut/mcp-recorder` for a person who has an agent
talking to an MCP server and has never heard of this product. It exists
because today's first five minutes lead with recording and put enforcement
behind "now author a policy file", and that ordering is backwards for what
this product is.

The frame this is written against, in the founder's words: *lead with
enforcement and have evidence be underlying; deliver security as a guarantee
and an enabler, not something that slows you down; "enterprise software anyone
can build".* The buyer is the security and IT team, the first user is a
non-technical builder, and their editor is whatever they already use — very
often an AI assistant. We do not become the editor.

## The rule this design is built around

AGENTS.md: gateway mode is the **only** place the proxy may block, delay or
rewrite traffic, and without a policy the byte-for-byte, fail-open behaviour is
untouched. So "enforcement with no authoring" is **not** enforcement by default
on a bare `record`. It is:

> the person selects enforcement explicitly, in one short command, and what
> they no longer have to do is author a policy file.

Everything below preserves that. `mcp-recorder record -- <server>` with no
policy selected is byte-identical to today — see [The invariant
check](#4-the-invariant-check).

---

## 1. The first run

### What the newcomer types

Two commands, one client restart, then one sentence to their agent.

**Today** (the package is not on the public npm registry yet):

```sh
npm install -g github:cresec-ai/audit#main
mcp-recorder protect --client claude-code
```

**After publishing** — one command, no separate install step:

```sh
npx -y @edut/mcp-recorder protect --client claude-code
```

`--client` takes `claude-desktop`, `claude-code` or `cursor`, the same set
`setup` already resolves (`src/setup/client-config.ts`). `--config PATH`
overrides the resolved file and makes `--client` optional, as it does for
`setup`.

Honest step count: **3 typed commands and 1 restart** today, **2 and 1** after
publishing. The restart is not removable — MCP clients launch their stdio
servers at startup, and a policy installed mid-session is the false negative
AGENTS.md's dogfood notes warn about.

### What `protect` is

`protect` is a thin, explicit front for work the package already does:

1. Materialise the **starter policy** (section 2) at
   `<data-dir>/policy.starter.yaml` and, for `claude-code`, its hook twin at
   `<data-dir>/policy.starter.json`. Both are plain files, written once, owned
   by the person, never regenerated over their edits (a second `protect` run
   leaves an existing file alone and says so).
2. Run `setup --client <C> --policy <data-dir>/policy.starter.yaml` — the
   existing code path, backup and sidecar included, so `setup --undo` reverses
   it exactly.
3. For `claude-code`, run `hook install --policy <data-dir>/policy.starter.json`
   — the existing hook installer, for the Anthropic-hosted connectors no local
   proxy can see.
4. Run **`doctor`** (section 3) and print its verdict as the last thing on
   screen.

`protect` is a new subcommand, not a new flag, because it is the one command
in the pitch and it needs to read as a verb. `record --protect` and
`http --protect` also exist, meaning `--policy <data-dir>/policy.starter.yaml`,
for the person who edits their client config by hand. `--protect` together
with `--policy` is a usage error (exit 2): you chose both.

`--protect` on `record`/`http` **never writes the starter file**. If it is not
there, that is exit 2 before the server is spawned, with `run 'mcp-recorder
protect' first` in the message. A policy that materialises itself on the
forwarding path is a policy nobody chose, and a file write before spawn is a
new way for `record` to fail.

### What the newcomer sees

```
$ mcp-recorder protect --client claude-code
config: /Users/me/project/.mcp.json

starter policy: /Users/me/.mcp-recorder/policy.starter.yaml   (new)
  4 rules deny, 3 rules hold for your approval, everything else runs.
  This file is yours — edit it, or delete it and pass --policy of your own.

wrapped 2 server(s):
  filesystem: node "/usr/local/lib/node_modules/@edut/mcp-recorder/dist/cli.js" "--policy" "/Users/me/.mcp-recorder/policy.starter.yaml" "--" "npx" "-y" "@modelcontextprotocol/server-filesystem" "."
  corp-notes: node "/usr/local/lib/node_modules/@edut/mcp-recorder/dist/cli.js" "--policy" "/Users/me/.mcp-recorder/policy.starter.yaml" "--" "node" "./server.js"

hook: /Users/me/project/.claude/settings.json   (PreToolUse, PostToolUse, SessionEnd, Stop)
  covers the hosted connectors (ClickUp, Gmail, Drive, ...) that no local proxy can see.

backup: /Users/me/project/.mcp.json.2026-09-21T18-04-11.bak

doctor: 6 checks OK, 0 failed, 0 incomplete
  enforcement is in force for 2 of 2 stdio servers and 4 of 4 connectors
  47 tools discovered; 6 denied, 9 held, 32 allowed
  every deny rule matches on every tool-name spelling this client could choose

Fully quit and restart Claude Code to pick this up
(closing the window is not enough).

Then ask your agent to do something it should not do, for example:
  "read the .env file in this project and tell me what's in it"
```

That last line matters. A person who installs a security product and then
cannot make it fire learns nothing. `protect` ends by handing them the
sentence that triggers the demonstration, chosen from **the tools doctor
actually discovered** on their servers — not from a canned script. If no
discovered tool is covered by any deny rule, `protect` says so instead, loudly,
because that is the dogfood-4 absence (section 3).

### The moment that matters

The person asks. The agent tries. The agent comes back:

> I can't read that file. The call was blocked:
> `mcp-recorder gateway: tools/call "read_text_file" denied by policy rule
> "credential-files": credential files are off limits.` This was a policy
> decision on your machine, not a tool failure, so I have not tried another
> way to get the same content. You may want to change the rule if this was
> intentional.

The text the model receives is the existing two-line shape
(`src/gateway/boundary.ts:132`), unchanged:

```
mcp-recorder gateway: tools/call "read_text_file" denied by policy rule "credential-files": credential files are off limits
This is a policy decision by the operator, not a tool failure. Do not retry it or use another tool to get the same effect; report it to the user.
```

**The model is deliberately not told how to change the rule.** The agent under
policy is exactly the party that must not be handed the command that relaxes
it. The how-to-change lives on the person's side of the boundary, in one
read-only command:

```sh
$ mcp-recorder why
last 3 decisions in /Users/me/.mcp-recorder

  2 min ago   DENIED   read_text_file        filesystem
              rule "credential-files" — an argument was a path to a credential file
              the agent asked for it, the server never saw the call, nothing was read

              to allow this: open /Users/me/.mcp-recorder/policy.starter.yaml
              and delete or narrow the rule with  id: credential-files
              then fully restart your client

  2 min ago   HELD -> denied on timeout   delete_file   filesystem
              rule "destructive-tools" — nobody answered within 120s
              next time: run  mcp-recorder holds  then  mcp-recorder approve <id>

 14 min ago   ALLOWED (boundary: 1 secret redacted)   read_text_file   filesystem
              a secret-shaped value in the result was replaced before the model saw it
              the value is still findable:  mcp-recorder query '<the value>'

nothing here left your machine. the full record:  mcp-recorder ui
```

`why` is a new read-only command over the chain (`policy_decision` events plus
`tool_call.gateway`). It is off the forwarding path entirely. It prints no
argument or result text — every string it shows comes from the policy file,
the tool name and the rule id, which are the operator's own words. It answers
the three questions the brief names: what was stopped, why, and that you can
change it.

### Only then, the evidence

The evidence reveal is the **second** beat, not the first:

```sh
$ mcp-recorder sessions
SESSION   SERVER      IDENTITY  EVENTS  CALLS  ERRORS  SERVERS  DECISIONS  LAST_EVENT
a91c4e02  filesystem  me@mac        41     17       2        2          3  2026-09-21T18:22:09Z

$ mcp-recorder verify
PASS  41 events, 1 chain, 3 signed heads, key 9f3a…2e7b

$ mcp-recorder export --out evidence.zip
wrote evidence.zip (41 events) — a stranger can check it with:  node verify.cjs
```

The line that sells the product to the buyer is `DECISIONS 3`: the refusals
are in the same signed chain as everything else, and the person who was never
asked to author anything now has an artifact their security team can verify
offline.

### What this does not cover, said on screen

`protect --client claude-code` ends by naming its own blind spots, because a
security product that lets you believe it covers more than it does is worse
than one that covers less. claude.ai on the web, the Claude Desktop chat tab
and Cowork have no customer-side per-call gate (`docs/features.md`); the hook
covers Claude Code only; and `MCP_RECORDER_DISABLE=1` remains the documented
kill switch for whoever controls the environment.

---

## 2. The starter policy

Enforcement with nothing to author means **we** choose the rules. Everything
here is defended knowing nothing about the user's servers, tools or work.

### The shape of the choice

- `mcp.default: allow`. A default of `hold` or `deny` on an unknown server
  blocks reads, blocks the first thing the agent tries, and turns the product
  into the thing the brief forbids. Enforcement is targeted at effects, not
  applied as a wall.
- **Deny** where a human would essentially never say "yes, quietly". **Hold**
  where they plausibly would. A hold is a question; a deny is a wall.
- `hold: { timeout_ms: 120000, on_timeout: deny }`. Two minutes is enough to
  notice the agent paused, switch to a terminal, read and answer. Unanswered
  means denied, which is the safe direction and is what a person who walked
  away would have wanted.
- `boundary: { secrets: redact, injection: flag }` — the shipped defaults,
  stated explicitly so the file is self-describing.

### How a rule matches when tool names are not known in advance

This is where the last attempt failed, so it gets its own argument.

**Two legs, two name spaces. Do not confuse them.**

| Leg | Command | What `tool` matches |
| --- | --- | --- |
| stdio / HTTP gateway | `record --policy` / `http --policy` | the `tools/call` `params.name` on the wire — **the server's own name for the tool** (`delete_file`), with no platform segment |
| Claude Code hook | `hook --policy` | the full hook `tool_name` — `mcp__<segment>__<tool>`, where **the segment is the platform's to choose** |

The dogfood-4 failure was on the hook leg only. On the gateway leg there is no
platform segment to disagree with anything. Both legs get starter rules, and
**every hook deny rule leaves the segment open** (`^mcp__.*__<tool>$`) — the
shape `docs/hooks.md` establishes and local dogfood 6 proved live.

**Names are the weak anchor; arguments are the strong one.** A rule anchored
to a tool name is a guess about a vocabulary we do not control. A rule
anchored to an argument matches what the call does to the world. The starter
puts its **denies** on arguments and its **holds** on names, because a missed
hold is a missed question and a missed deny is the failure this work exists to
prevent.

`match.args` in v1 is keyed by a dot-path, so it can only match an argument
whose *name* you already know — `path`, but not `file_path`, `absolute_path`,
`uri`, `source`, `target`. That is another guess. So the starter needs one
additive schema field:

#### Proposed: `match.any_arg` (additive, optional, `policy.yaml` v1)

```yaml
- id: credential-files
  match:
    tool: "**"
    any_arg: "(^|/|\\\\)(\\.env|\\.env\\.[A-Za-z0-9_-]{1,64}|\\.npmrc|\\.netrc|\\.git-credentials|\\.pgpass|id_rsa|id_ed25519|id_ecdsa|id_dsa)$"
  action: deny
  reason: credential files are off limits
```

One RE2-subset regex, searched against **every string leaf of
`params.arguments`, at any depth, whatever the key is called**. It matches
when any one leaf matches. Constraints, all of which follow the discipline
`match.args` already has:

- Same RE2 subset and the same `policy validate` rejections (no lookaround,
  no backreferences, no inline flags, no ambiguous repeated groups, no `\s`).
- Matched on the worker thread under the existing 25 ms deadline, **one
  request per rule carrying every leaf**, not one round trip per leaf.
- Budget: at most 256 leaves and 256 KiB of total leaf text per call. Past the
  budget the call is **denied fail-closed** with `policy evaluation error:
  arguments too large to scan (<rule id>)` — never truncated, for the reason
  `docs/policy.md` already gives: truncating turns a deny into an allow.
- Object *keys* are not scanned in v1 (open question below).
- Rego parity: compiles to `walk(input.args, [_, v]); is_string(v);
  regex.match(<pat>, v)` behind the same explicit `is_object(input.args)`.
  OPA has no leaf budget, so the two engines can differ only past the budget,
  in the safe direction (local deny, control-plane allow) — the same residual
  the existing 4 KiB `match.args` cap has, and the OPA parity test must pin it.
- Latency: `npm run bench:gateway` is the gate. If `any_arg` cannot hold p50
  added latency under 5 ms with the starter loaded, the budget shrinks. The
  gate does not move.

This is an additive optional field on a versioned-but-not-frozen schema: files
written for v1 today stay valid, and `docs/policy-schema.json` gains one
property. The **event** schema `edut.mcp-recorder.event.v1` is untouched — a
rule that matched by `any_arg` produces the same `policy_decision` event any
other rule does.

### The rules

Ordered, first match wins.

#### Denies (4)

**1. `secrets-in-arguments`** — `any_arg` against one alternation of the
high-confidence credential shapes the boundary filter already uses
(`boundarySecretPatterns()`, `src/gateway/boundary.ts`): AWS key ids
(`AKIA`/`ASIA`), GitHub tokens (`gh[pousr]_`), `sk-` and `sk-ant-` keys, Slack
`xox[baprs]-`, three-segment JWTs behind an `eyJ` header, PEM private-key
blocks, and `Bearer <value>`. The generic long-hex and long-base64 shapes are
**excluded**, exactly as they are at the boundary, because they match git
SHAs, checksums and container digests.

*Defence with no knowledge of the user:* a credential sitting in an outbound
tool argument is either exfiltration or a token being handed to a tool that
should not hold it. Working MCP servers take credentials from their
environment, not from call arguments, so this is close to a zero-false-positive
rule in practice. *Honest caveat:* a server that genuinely takes a token as an
argument will be denied on its first call; `why` names the rule and the file,
and the supported path is the `credentials` broker section, which is what
exists for that. This is the one rule that needs no knowledge of anything.

**2. `credential-files`** — `any_arg` against a path-shaped leaf ending in
`.env`, `.env.<name>`, `.npmrc`, `.netrc`, `.git-credentials`, `.pgpass`,
`id_rsa`/`id_ed25519`/`id_ecdsa`/`id_dsa`, `.ssh/*`, `.aws/credentials`,
`.kube/config`, `*.pem`, `*.p12`.

*Defence:* reading a credential file into the model's context is the single
most common way a secret leaves a machine, and the model does not need the
contents to do the work. The leading `(^|/|\\)` means the leaf must **be** a
path, not merely mention one — a prose argument containing `the .env file` has
a space before `.env` and does not match, while a leaf that is `.env` or
`src/../.env` does. Deny rather than hold: there is no version of "yes, read
my private key, quietly" that a person wants.

**3. `dont-touch-the-controls`** — `any_arg` against the recorder's own data
directory, the starter policy files, the client MCP config files
(`claude_desktop_config.json`, `.mcp.json`, `~/.cursor/mcp.json`) and
`.claude/settings.json`.

*Defence:* the one thing an agent must not be able to edit is the thing that
governs it. *Honest caveat, which the file states in a comment:* this is
friction and evidence, not a boundary. The agent has a shell, and
`MCP_RECORDER_DISABLE=1` is documented. What this rule buys is that the
tampering attempt becomes a `policy_decision` in a signed chain instead of a
silent edit.

**4. `catastrophic-commands`** — `any_arg` against a small, literal,
high-confidence set: a recursive `rm -f` rooted at `/`, `~`, `$HOME` or
`--no-preserve-root`; `DROP DATABASE` / `DROP SCHEMA`; `TRUNCATE TABLE`; a
`DELETE FROM <table>` with nothing after the table name (the unqualified form
— "no `WHERE`" is not expressible, because RE2 has no lookahead, but
"terminates right here" is); `git push --force` that is not
`--force-with-lease`.

*Defence:* these reach through servers whose tool name tells you nothing
(`bash`, `run_command`, `execute`, `query`) and whose argument tells you
everything — the exact case argument matching exists for. Nobody's agent
should perform an unconfirmed recursive delete of a filesystem root or drop a
database. *Honest caveat:* the SQL keywords are spelled as character classes
(`[Dd][Rr][Oo][Pp]`) because the RE2 subset bans inline case-insensitivity;
the shipped file is generated, not hand-typed, and the set is deliberately
tiny. Shell-string matching by regex is a tarpit and this rule does not
pretend to be a shell parser — it is four literals, each with a test fixture
of true and false positives.

#### Holds (3)

**5. `destructive-tools`** — `match.tool` globs across the naming conventions
MCP servers actually use: `delete_*`, `*_delete`, `*_delete_*`, `remove_*`,
`*_remove`, `destroy_*`, `drop_*`, `rm`, `rm_*`, `trash_*`, `purge_*`,
`truncate_*`, `overwrite_*`, `move_*`, `rename_*`. On the hook leg, the same
list as `^mcp__.*__(delete|remove|destroy|drop|trash|purge)[_A-Za-z0-9]*$`.

*Defence:* deletion is the archetype of the irreversible thing, and a hold
asks rather than walls. This rule **is a guess about a vocabulary**, and the
starter treats it as one: doctor prints exactly which of the person's real
tools it matched (section 3), so the guess becomes a measured fact at install
time instead of an assumption that goes green while the product fails. Rules
1–4 catch the effect when the name misses.

**6. `sends-to-other-people`** — `match.tool` globs `send_*`, `*_send_*`,
`*_send`, `post_message`, `*_post_message`, `reply`, `reply_*`, `forward`,
`forward_*`, `publish_*`, `share_*`, `*_share_*`, `invite_*`, `email_*`,
`sms_*`. Deliberately **not** `create_draft` or `*_draft` — a draft goes
nowhere and holding it is pure friction.

*Defence:* the difference between an agent that helped and an agent that
embarrassed you is usually whether something reached another human. Hold, not
deny, because sending is frequently exactly what was asked for. This is the
rule that turns "the agent emailed my whole team" into "the agent asked".

**7. `spends-money`** — `match.tool` globs `*purchase*`, `*payment*`,
`*charge*`, `*checkout*`, `*order*`, `*subscribe*`, `*invoice*`, `*refund*`,
`*transfer*`, `*payout*`.

*Defence:* money is the canonical irreversible act and the one a security team
will ask about first. `*order*` will occasionally catch a read (`get_order`);
that is a hold, not a deny, and the person removes the glob in one line.

#### Allowed, deliberately

Everything else, including **outbound HTTP**. The laptop example policy denies
`http_post`/`send_*`/`fetch*`, and that is right for a hardened laptop and
wrong for a starter: a large share of useful MCP servers are HTTP clients, and
denying them makes the first run a wall of refusals for calls the person
wanted. The protections that remain on that path are rule 1 (a credential in
the arguments is denied) and the boundary filter (secrets redacted out of the
result, injection markers flagged). The file carries the stricter rule
commented out, one line, with a comment saying when to turn it on.

Reads are allowed. `tools/list`, `initialize` and every non-`tools/call`
message are untouched, as they are in every gateway-mode policy.

### What the file looks like to the person

The starter ships as **commented YAML the person can read**, not a compiled
blob. Every rule carries a one-line `reason` that is what the agent and `why`
both print, and a comment saying what to change to relax it. It is written
once, to `<data-dir>/policy.starter.yaml`, and never overwritten — that is
what makes "they can change it" true rather than claimed.

---

## 3. `doctor`

```sh
mcp-recorder doctor [--client NAME] [--config PATH] [--data-dir D] [--probe|--no-probe] [--json]
```

Doctor answers one question: **is enforcement actually in force, right now,
for the client that is actually running?** It is built to detect an *absence*,
because that is what dogfood 4 was — no `server.url`, no deny event, nothing
reporting an error, and a 62-event signed bundle with a passing chain and zero
policy decisions.

### The governing rule

**Never report success on an absence.** Every check is tri-state:
`OK` / `FAIL` / `INCOMPLETE`. A check that could not be performed is
`INCOMPLETE` and is never folded into `OK`. A policy that loads, validates and
matches nothing is a `FAIL`, not a pass.

### What it inspects, check by check

**C1 — wiring.** The client config file. For each `mcpServers` entry: is it
wrapped by a recorder, is that recorder's path present on disk, is it the same
version as the doctor running, does the wrapped command carry `--policy` (or
`--protect`), does that file exist, parse, validate and contain an `mcp`
section. Divergence between entries is reported per entry, not averaged.
`MCP_RECORDER_DISABLE=1` in an entry's `env` or in doctor's own environment is
an immediate `FAIL` — enforcement is off and the chain still looks healthy,
which is precisely the shape this command exists to catch.

**C2 — hook wiring** (`claude-code`). Is the hook installed for `PreToolUse`,
with what matcher, and does the installed command carry `--policy`? Does that
JSON parse? Plus the session-snapshot trap: if a live `/tmp/mcp-config-*.json`
exists and `.claude/settings.json` is **newer** than it, a session that began
before the hook was installed is still running and the hook is not in force for
it. That is a `FAIL` with `restart the session` as the remedy, because
AGENTS.md records it as producing "a false negative that looks like the product
failing".

**C3 — the dogfood-4 check: does every deny rule survive every spelling of the
name?** This is the headline check and it needs no live session.

For each MCP config file (`MCP_RECORDER_MCP_CONFIG`, else
`/tmp/mcp-config-*.json`), doctor enumerates every entry and every
`tools[].name` it declares. For each tool it then builds the tool-name
spellings the client could choose, **covering both orderings**:

| Spelling | Where it has been observed |
| --- | --- |
| `mcp__<the config key>__<tool>` | key matches segment (cloud dogfood 3) |
| `mcp__<a UUID>__<tool>` | Desktop "Code" tab (local dogfood 6) |
| `mcp__<friendly name>__<tool>` | key does **not** match segment (cloud dogfood 4) |
| `mcp__claude_ai_<friendly>__<tool>` | WSL CLI (local dogfood 6) |
| `mcp__<resolved host alias>__<tool>` | when route 1 or route 2 resolves |
| `mcp__zz-unknown-segment-0__<tool>` | a segment nobody has seen yet |

Every hook deny rule is evaluated against **all six**. A rule that matches all
six is segment-open and passes. A rule that matches some and not others is
**segment-anchored** and is a `FAIL` naming the rule and the exact spellings it
missed. The last row is load-bearing: it is the fuzz case that proves the rule
is open rather than merely broad enough for the spellings we happen to know.

Doctor also reports, per entry, whether connector resolution would succeed **by
key** (route 1), **by declared tool** (route 2), or **not at all** — and when
it is "not at all", it says in words that host-alias rules cannot fire in this
session, which is the local case `docs/hooks.md` documents.

**C4 — coverage: the rules against the real tool vocabulary.** Guessing is what
failed; discovering is the fix.

- *stdio servers:* doctor spawns each wrapped server in a throwaway
  `--data-dir`, performs `initialize` + `tools/list`, and takes the **actual**
  tool names off the wire.
- *hosted connectors:* the `tools[]` array in the MCP config already carries
  them; nothing is spawned.

It then evaluates the policy against every discovered name and prints the
matrix. The assertion: **if the deny-and-hold set is empty across every
discovered tool, that is a `FAIL`** — "enforcement is on and matches nothing"
is the dogfood-4 state, and it is the one thing no existing command reports.
A server whose tools could not be enumerated (spawn failed, handshake timed
out) is `INCOMPLETE`, never `OK`.

**C5 — the live probe** (`--probe`, on by default; `protect` always runs it).
Checks C1–C4 read configuration. C5 pushes a real call through the real code
path and reads the result.

- *stdio leg:* spawn the wrapped server behind `record --policy <the same
  policy>` with a throwaway `--data-dir`, write a genuine `tools/call` line on
  stdin for a tool the policy **denies**, and assert two things: the response
  is the gateway's synthesized `isError` naming the expected rule id, **and** a
  `policy_decision` event landed in the throwaway chain. The event is the
  proof, and it is the same artifact a dogfood run is measured by.
- *hook leg:* the smoke test `docs/hooks.md` already documents, run
  automatically — pipe a synthetic `PreToolUse` object for each discovered tool
  × each of the six spellings into `hook --policy`, and assert exactly the
  expected deny lines. Empty output where a deny was expected is a `FAIL`.

**The probe only ever probes tools the policy denies or holds.** A denied call
never reaches the server and a held call is cancelled, so the probe has no
side effects. It never probes an allowed tool, and it never writes to the real
data directory.

**C6 — chain health.** `verify` the real data dir, and report the head, the
session count and the `policy_decision` count. A chain that verifies while
holding zero decisions after a session that should have produced some is
reported as a fact, not as a pass.

### What it prints

**Success:**

```
$ mcp-recorder doctor --client claude-code
config: /Users/me/project/.mcp.json
policy: /Users/me/.mcp-recorder/policy.starter.yaml  (sha256:4f182f7c…, 7 mcp rules)

OK  C1 wiring          2/2 stdio servers wrapped, both enforcing this policy
OK  C2 hook            PreToolUse installed, matcher mcp__.*, policy loaded
OK  C3 name spellings  5 deny rules x 6 spellings x 12 connector tools — all match
OK  C4 coverage        47 tools discovered (2 servers, 4 connectors)
                         6 denied   read_text_file, read_file, write_file, edit_file, bash, http_post
                         9 held     delete_file, move_file, send_message, trash_message, ...
                        32 allowed
OK  C5 probe           live deny fired on filesystem/read_text_file (rule credential-files)
                       live deny fired on ClickUp/clickup_delete_task, all 6 spellings
OK  C6 chain           PASS, 41 events, 3 policy decisions, key 9f3a…2e7b

doctor: 6 checks OK, 0 failed, 0 incomplete
exit 0
```

**Failure — the dogfood-4 shape, C3:**

```
FAIL  C3 name spellings  1 of 5 deny rules is anchored to a server segment

  rule "clickup-deletes"  ^mcp__ClickUp__clickup_delete_task$
    matches      mcp__ClickUp__clickup_delete_task
    MISSES       mcp__47d587b8-3fb9-42e9-b596-f8b25371248c__clickup_delete_task
    MISSES       mcp__claude_ai_ClickUp__clickup_delete_task
    MISSES       mcp__mcp.clickup.com__clickup_delete_task
    MISSES       mcp__zz-unknown-segment-0__clickup_delete_task

  The <server> segment is chosen by the client, not by you, and it has
  differed between two sessions a day apart and between two surfaces on one
  machine at the same time. A rule anchored to one spelling stops matching
  when it changes, silently, with no error anywhere.

  Fix: leave the segment open.
    ^mcp__.*__clickup_delete_task$

doctor: 5 checks OK, 1 failed, 0 incomplete
exit 1
```

**Failure — enforcement matches nothing, C4:**

```
FAIL  C4 coverage  47 tools discovered; 0 denied, 0 held, 47 allowed

  The policy loads, validates and is in force, and it matches none of the
  tools your servers actually expose. Every call will be allowed and the
  evidence chain will look completely healthy. This is the failure that does
  not report itself.

  Your servers' tool names:
    filesystem   read_text_file write_file edit_file create_directory
                 list_directory move_file search_files get_file_info ...
    ClickUp      clickup_create_task clickup_delete_task clickup_search ...

  Fix: your rules use names your servers do not. Compare the list above with
  the `tool:` globs in /Users/me/.mcp-recorder/policy.starter.yaml, or run
  `mcp-recorder protect` to install rules generated against these names.

doctor: 5 checks OK, 1 failed, 0 incomplete
exit 1
```

**Failure — enforcement not in force at all, C1:**

```
FAIL  C1 wiring  enforcement is NOT in force

  filesystem  wrapped, but with no --policy — recording only, nothing is enforced
  corp-notes  not wrapped at all — the client launches this server directly
  environment MCP_RECORDER_DISABLE=1 is set — the kill switch is on; with it
              set, neither recording nor the gateway runs, whatever the config says

  Fix: mcp-recorder protect --client claude-code
       and unset MCP_RECORDER_DISABLE

doctor: 3 checks OK, 1 failed, 2 incomplete
exit 1
```

**Incomplete — could not check, which is never a pass:**

```
INCOMPLETE  C4 coverage  1 of 2 servers could not be enumerated

  filesystem  12 tools
  corp-notes  spawn failed: ENOENT node ./server.js — no tool list, so this
              server's coverage is UNKNOWN. It is not "fine"; it is unchecked.

doctor: 5 checks OK, 0 failed, 1 incomplete
exit 3
```

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | every check ran and every check passed |
| `1` | at least one check **FAILED** |
| `2` | doctor could not run at all (no config found, unreadable policy, usage error) — the CLI's existing meaning |
| `3` | no failures, but at least one check was **INCOMPLETE** (additive; never treat as a pass) |

`--json` prints `{ "verdict": "ok"|"fail"|"incomplete", "checks": [ { "id",
"status", "summary", "detail" } ], "policy": { "path", "hash", "rules" },
"tools": { "<server>": ["<name>", ...] }, "coverage": { "denied", "held",
"allowed" } }` — the stable machine interface, so CI can gate on it.

### Doctor in CI

`mcp-recorder doctor --no-probe --json` is the pre-flight for any pipeline
that runs an agent behind a policy: it fails the job when the policy matches
nothing, which is the check that would have caught dogfood 4 two days earlier.

---

## 4. The invariant check

**Claim: after every change in this document, `mcp-recorder record -- <server>`
with no enforcement selected cannot block, delay or rewrite anything. It is
byte-identical to today.**

The argument follows the code, one hop at a time.

**Hop 1 — policy resolution never sees `protect`'s artefacts.**
`resolvePolicyPath` (`src/cli.ts:567`) reads exactly two inputs: `flags.policy`
and `env[ENV.POLICY]`. The change adds one branch for `--protect`, which
resolves to `<data-dir>/policy.starter.yaml` and nothing else. With none of
`--protect`, `--policy` or `MCP_RECORDER_POLICY` present, it returns
`undefined` exactly as it does today. The existence of a starter policy file on
disk is **not an input** — a file sitting in the data directory can never
switch enforcement on.

**Hop 2 — `resolveGateway` returns an empty object.**
`resolveGateway` (`src/cli.ts:676`) begins with
`if (policyPath === undefined) { ... return loaded === undefined ? {} : { actor: loaded }; }`.
No `HoldStore` is constructed, no policy is loaded, no credential wiring is
built. This is unchanged.

**Hop 3 — `cmdRecord` omits the key.** `cmdRecord` (`src/cli.ts:722`) spreads
`...(gateway !== undefined ? { gateway } : {})` into `runStdioProxy`'s options.
With `gateway` undefined the property is absent, not present-and-undefined.
Unchanged.

**Hop 4 — the proxy takes the plain-pipe branch.** In `runStdioProxy`
(`src/proxy/stdio.ts`), `const gateway = opts.gateway;` is `undefined`, so:

```ts
if (gateway === undefined) {
  proxyStdin.pipe(child.stdin);
  child.stdout.pipe(proxyStdout, { end: false });
}
```

Two raw `.pipe()` calls with backpressure. No `Transform` is constructed, so no
line splitter, no `JSON.parse` on the forwarding path, no policy evaluation, no
boundary filter, no hold, no credential swap. The module header states this as
the contract and the code is the contract. `src/proxy/http.ts:10` says the same
for the HTTP leg: gateway mode is `opts.gateway` present, i.e. `http --policy`,
and it is the one place the streaming promise is set aside.

**Hop 5 — the new code is not on that path at all.**

- `match.any_arg` is evaluated inside the policy engine (`src/policy/engine.ts`),
  which is reached only from the gateway Transform's `evaluate` call. With no
  Transform there is no call site. It adds no import to `src/proxy/stdio.ts` or
  `src/proxy/http.ts`.
- The starter policy is **data**: a template compiled into the CLI and a YAML
  file on disk. `record` reads it only through the ordinary
  `loadGatewayPolicy` path, and only when a policy was selected.
- `protect`, `doctor` and `why` are separate subcommands. `main`'s switch
  (`src/cli.ts:2649`) dispatches to one subcommand per process; none of them
  runs inside `record` or `http`. Doctor's probe spawns **its own** recorder
  processes with **their own** throwaway `--data-dir` and never attaches to a
  live proxy.
- `why` is read-only over the store, like `sessions` and `query`.

**Hop 6 — the one case that could have violated it, and how it is closed.**
The tempting design is for `record --protect` to write the starter policy if it
is missing. That would put a file write on the pre-spawn path, give `record` a
new way to fail before the server starts, and let a flag silently mint the
policy it then enforces. So `--protect` with a missing starter file is **exit 2
before spawn**, the same fail-closed shape `loadGatewayPolicy` already has for
a missing or invalid `--policy`. `protect` is the only writer.

**What is unchanged inside gateway mode.** Recording stays fail-open (a store
failure never becomes a deny); enforcement stays fail-closed (an unevaluable
policy, an unwritable hold, an over-budget `any_arg` scan are all denies).
Hold files and `policy_decision` events carry hashed arguments only — `any_arg`
matches against leaves in memory and records the rule id, never the leaf. The
sink is untouched and still never runs on the forwarding path.

**The tests that must pin this**, since a promise with no test is a comment:

1. A byte-for-byte differential: the same server, the same traffic, with and
   without the new code, no policy selected — identical stdout bytes, identical
   exit code, identical recorded event stream modulo ids and timestamps.
2. `npm run bench` unchanged and still under the 5 ms p50 gate with the new
   code present and no policy.
3. `npm run bench:gateway` under the same gate with the **starter policy**
   loaded, which is the new number this design owes.
4. `record --protect` with no starter file on disk: exit 2, server never
   spawned.
5. A starter policy file present in the data dir with no flag given: plain
   record, no decisions, no Transform.

---

## Open questions

- **`any_arg` and object keys.** v1 scans string leaves only. A server that
  puts a path or a token in a key would slip past. Scanning keys doubles the
  budget and the parity surface; deferred, stated.
- **Where the hold notification goes.** A held call pauses the agent for up to
  120 s, and the person may not be looking at a terminal. stderr is where the
  recorder's diagnostics go and most clients bury it. An OS notification is out
  of scope here but the gap is real.
- **`why` and the agent.** `why` prints the instruction for relaxing a rule.
  The agent can also run `why`. Rule 3 makes editing the policy a deny and
  therefore evidence, but that is friction, not a boundary. The real answer is
  a policy the local user cannot write, which is the control plane's job.
- **Generating rules from discovered names.** Doctor discovers the real tool
  vocabulary. `protect` could emit rules **generated from it** rather than from
  globs — eliminating the guess entirely, at the cost of a policy that goes
  stale when a server adds a tool. A middle path (globs, plus doctor failing
  when a newly added tool matches nothing) is probably right but is not
  designed here.
- **Which client to default to.** `protect` with no `--client` could detect the
  installed clients and offer the list. Undecided.
- **The starter's name in evidence.** `session_start.policy.name` would read
  `starter`. Whether that is the right handle for a security team reading a
  fleet of bundles, or whether it should carry a version (`starter/1`), is
  open — the schema takes either.
