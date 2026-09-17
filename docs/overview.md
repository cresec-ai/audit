# What this is, and what it does to your setup

`@edut/mcp-recorder` records what your agent's MCP tools actually did, into a
local, tamper-evident log. This page is for deciding whether to run it, and
for knowing what changed once you have.

It does not repeat [docs/install.md](install.md), which is the installation
walkthrough for each client, or the 60-second quickstart in
[README.md](../README.md). Read those for the how; read this for the what and
the cost.

**How the claims on this page were checked.** Every command below was run on
2026-09-17 against this checkout — `@edut/mcp-recorder` v0.1.0, Node v22.22.2,
Linux — and every output block is pasted from that run, trimmed where the text
says so. Commands are written as `mcp-recorder ...`, the installed binary
name; they were run here as `node dist/cli.js ...` from the checkout. Where a
tool call had to be driven without a real client, a short script speaking
JSON-RPC on stdin stood in for one, and the blocks below say so. Where
something could not be checked here, it is labelled in place. Gateway mode is
not in this checkout at all; its section says how it was checked instead.

## What problem does it solve?

An agent with MCP tools reads and writes real systems: your files, your
repositories, your mailbox, your ticket tracker. When something goes wrong — a
credential that appears in a tool result, an instruction hidden in a document
the agent read, a write nobody meant to authorise — the tool calls themselves
are usually gone, and what remains is a chat transcript nobody can attest to.
This records each of those calls as it happens, into a hash-chained local log
with payloads hashed rather than stored, so afterwards you can reconstruct
what the agent saw and did, and demonstrate that the log was not edited.

## What is running once it is installed?

One extra process per wrapped server. Your MCP client launches
`mcp-recorder record -- <your server command>` instead of the server; the
recorder spawns the server as its child and sits between the two pipes. The
client's view does not change: in record mode the proxy forwards the exact
bytes in both directions and taps a copy.

That byte-for-byte transparency has been checked repeatedly against hostile
streams up to 35.6 MB — non-JSON noise, CRLF framing, embedded NUL, invalid
UTF-8, multi-MB lines, unterminated tails — with identical sha256 in both
directions, including with the client writing one byte at a time. The
repository's own transparency test was re-run here and passes:

```
$ npx vitest run test/stdio-proxy.test.ts -t "forwards bytes unchanged"
 ✓ test/stdio-proxy.test.ts (18 tests | 17 skipped) 61ms
 Test Files  1 passed (1)
      Tests  1 passed | 17 skipped (18)
```

Nothing is sent anywhere. A search of `src/` for `fetch(`, `http.request`,
`https.request`, `net.connect` and `new WebSocket` returns no hit outside
`src/proxy/http.ts`, which is the `http` subcommand forwarding to the target
you name. Evidence leaves the machine only when you run `export`.

### Where the evidence lands

The default data directory is `~/.mcp-recorder` (override with `--data-dir` or
`MCP_RECORDER_DATA_DIR`). A session of 12 tool calls recorded into a fresh
directory leaves three files:

```
$ ls -l .mcp-recorder
-rw-r--r-- 1 root root 90112 Sep 17 04:29 evidence.db
-rw------- 1 root root    65 Sep 17 04:29 identity.key
-rw-r--r-- 1 root root    65 Sep 17 04:29 identity.pub
```

`evidence.db` is the append-only hash-chained event log (sqlite by default;
the jsonl backend writes `evidence.jsonl` plus `signatures.jsonl` instead).
`identity.key` is the local ed25519 signing key, generated on first run, and
`identity.pub` is the public half that `verify` pins to. Treat `identity.key`
like an SSH key. [docs/install.md](install.md#where-the-data-lives-and-whats-in-it)
covers permissions and the multiple-servers-one-directory case.

Two subdirectories appear only when the relevant feature is in use:
`hook-pending/` and `hook-sessions/` for the Claude Code hook tap, and
`holds/` for gateway mode.

No readable payload reaches any of it. Each string leaf and each object key is
replaced by `sha256:<hex>` plus its length before anything is written. After
recording 200 tool calls whose arguments contained distinctive strings, none
of those strings appears in the store:

```
$ for s in 'SELECT id, email' 'srv/reports' 'quarterly reconciliation'; do
>   printf '%-26s %s\n' "$s" "$(grep -c -- "$s" evidence.jsonl)"; done
SELECT id, email           0
srv/reports                0
quarterly reconciliation   0
```

## What do you get out of a recorded session?

These were run here against the data directory left by `npm run demo` (a
scripted prompt-injection exfiltration; no model, no network, the credential
and the leak are planted), copied to a shorter path so the output fits.

What ran:

```
$ mcp-recorder sessions --data-dir data
SESSION   STARTED                   ENDED                     SERVER      EVENTS  TOOL_CALLS  ERRORS  SERVERS
96f079a1  2026-09-17T04:20:17.266Z  2026-09-17T04:20:17.997Z  corp-notes  9       4           0       1
```

Whether the record is intact:

```
$ mcp-recorder verify --data-dir data
verify store /home/user/ovcheck/data/evidence.db (sqlite)
pinned signer: ed25519 49f04d1ef6134e2d… (/home/user/ovcheck/data/identity.pub)
PASS — chain intact: 9 event(s), head seq 9
signed head: seq 9 by ed25519 49f04d1ef6134e2d… at 2026-09-17T04:20:17.998Z
```

Blast radius for a value you already hold — the planted credential, hashed and
looked up:

```
$ mcp-recorder query 'sk-demo-EXFILTRATION-c4n4ry-9f3a7b2e' --data-dir data
TIMESTAMP                 KIND       NAME       SESSION   MATCHED_ON  PATH
2026-09-17T04:20:17.974Z  tool_call  read_file  96f079a1  ref         $.result.content[0].text.secret_refs[0]
2026-09-17T04:20:17.976Z  tool_call  http_post  96f079a1  ref         $.args.body

2 matches across 1 sessions
```

The credential was read out of a file and then appeared in the body of an
outbound POST. Neither value is stored; both were found by hash. A `query`
miss is not proof of absence — [README.md](../README.md#security-model-the-honest-version)
sets out which shapes are findable.

`verify` fails loudly on an edit. A single altered field in one event of a
206-event chain, with everything else left alone:

```
$ mcp-recorder verify --data-dir tampered
verify store /home/user/ovcheck/tampered/evidence.jsonl (jsonl)
pinned signer: ed25519 7457c76468e6469d… (/home/user/ovcheck/tampered/identity.pub)
FAIL — evidence does NOT verify: 206 event(s) checked
signed head: seq 206 by ed25519 7457c76468e6469d… at 2026-09-17T04:22:09.358Z

TYPE           SEQ  DETAIL
hash_mismatch  6    stored hash 1a85ca052dbc4e4b… != recomputed 086143032bc05c33… — the event was altered
```

(exit code 1; the two hashes are trimmed here for width.)

`export` writes a bundle a stranger can check with bare Node and no install:

```
$ mcp-recorder export --data-dir .mcp-recorder --dir bundle
[mcp-recorder] exported 18 event(s) (seq 1..18), head c79cee16d2cc85e8… signed by ed25519 03d6914e31957926…
$ ls -l bundle
-rw-r--r-- 1 root root   481 Sep 17 04:29 README.txt
-rw-r--r-- 1 root root 40030 Sep 17 04:29 events.jsonl
-rw-r--r-- 1 root root   923 Sep 17 04:29 manifest.json
-rw-r--r-- 1 root root   113 Sep 17 04:29 public_key.pem
-rw-r--r-- 1 root root 10534 Sep 17 04:29 verify.cjs
```

**The limit is in the tool's own output, and it matters.** Running the
bundle's verifier without a key obtained out of band proves internal
consistency and nothing more:

```
$ node verify.cjs
PASS: evidence bundle verified
  events     : 18 (seq 1..18)
  signed by  : ed25519 03d6914e31957926d40aac65df01a62af0476b9dbe2a608df052e7dacfce2917 at 2026-09-17T04:29:08.126Z
  key check  : NOT independently verified - the key came from this bundle
               itself (public_key.pem / manifest.json), which an attacker
               who forged the whole bundle controls too. Re-run with
               --public-key <hex|path> using a key you obtained out of band
               (e.g. from the operator directly) for real assurance.
```

(trimmed: the hash lines and the unsigned-metadata block are omitted.) For
real third-party assurance the verifier needs `--public-key`, pinned to a key
the recipient got from the operator directly rather than from the artefact
being checked.

There is also a replay timeline — see, act, effect, with identity context on
each event — served locally or written to a file. It was rendered here but not
reviewed page by page for this document:

```
$ mcp-recorder ui --data-dir data --out timeline.html
[mcp-recorder] wrote replay page to /home/user/ovcheck/timeline.html
```

## Where can it see your agent's traffic?

There are three vantage points. They are not equivalent, and the difference
decides whether this tool is useful to you at all.
[docs/connector-coverage.md](connector-coverage.md) is the authority on what
each surface exposes; this table is the short form.

| Vantage point | How it attaches | What it can see | What it can do about it | How that was checked |
| --- | --- | --- | --- | --- |
| `record` — stdio proxy | your client launches the server through it, one config line | every JSON-RPC message in both directions, for that one local server | nothing in record mode; allow / hold / deny per tool in gateway mode (not in this checkout) | verified here: `npm run demo`, a 200-call session, the transparency test above |
| `hook` — Claude Code PreToolUse / PostToolUse / PostToolUseFailure | entries in a Claude Code settings file | per call: tool name, the full input, and the response or the error string — for every `mcp__*` tool, **including Anthropic-hosted connectors** | deny a call before it runs, via `--policy` | verified here against the documented hook JSON on stdin; **not** re-proven against a live hosted connector, see below |
| `http` — HTTP-transport proxy | you point the client at the proxy instead of the server | the HTTP MCP traffic it proxies | nothing; `http --policy` is rejected with exit 2 | the repository's `test/http-proxy.test.ts` was run here, 17 tests pass; no live remote server was exercised for this page |

A fourth arrangement is really the first one in disguise: `setup --bridge`
replaces a remote connector with a local `mcp-remote` process, which the
recorder then wraps like any other stdio server. It works only for vendors
with a public MCP endpoint, and the user has to re-authorise through the
bridge. See [docs/install.md](install.md#bridge-a-remote-mcp-server).

### The hosted-connector gap, stated plainly

For the connectors Claude ships with — ClickUp, GitHub, Gmail, Google Drive,
Slack and the rest — the call to the vendor is made from Anthropic's
infrastructure, on every surface. No local proxy of ours sits on that hop. The
Claude Code hook is the only third-party tap this project has found on those
connectors, and it covers Claude Code only: the CLI, the IDE extension, the
Desktop Code tab, cloud sessions and the Agent SDK. Of those, the cloud
session is the one the project observed hooks firing in directly; the rest
come from Anthropic's documentation. On claude.ai web and
Desktop chat the only customer-side feeds are Anthropic's own, and they are
Enterprise-gated. Cowork should be treated as **not** covered by the hook
until a probe says otherwise; `docs/connector-coverage.md` records the
evidence for that, including two community reports that hooks do not fire
there.

Feeding the hook the documented PreToolUse and PostToolUse JSON for a
connector-shaped tool works here, including finding a secret embedded in a
longer argument string:

```
$ mcp-recorder hook --data-dir data-hook < pre.json     # exit 0, no output = allow
$ mcp-recorder hook --data-dir data-hook < post.json
$ mcp-recorder sessions --data-dir data-hook
SESSION   STARTED                   ENDED   SERVER       EVENTS  TOOL_CALLS  ERRORS  SERVERS
11111111  2026-09-17T04:25:23.135Z  (open)  claude-code  3       1           0       1

$ mcp-recorder query 'AKIAIOSFODNN7EXAMPLE' --data-dir data-hook
TIMESTAMP                 KIND       NAME          SESSION   MATCHED_ON  PATH
2026-09-17T04:25:23.135Z  tool_call  send_message  11111111  ref         $.args.body.secret_refs[0]
2026-09-17T04:25:23.292Z  tool_call  send_message  11111111  ref         $.args.body.secret_refs[0]

2 matches across 1 sessions
```

A deny rule fires against the same payload:

```
$ mcp-recorder hook --data-dir data-hookdeny --policy hook-policy.json < pre.json
{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"mcp-recorder policy: outbound mail from agents needs a human"}}
```

**Do not read more into that than it shows.** Those are synthetic payloads fed
on stdin, not a live session against a real connector. In cloud dogfood 4, two
hook deny rules aimed at a live Anthropic-hosted connector both missed: the
calls ran, twice each, against a real workspace, and the signed 62-event
bundle carried no record of either deny. The cause was naming — a cloud
session gives a connector a per-session UUID as its server name, and the rules
had been written against the readable name. The fix is in this checkout (PR
\#13: a deny rule is now also tested against an `mcp__<host>__<tool>` alias
resolved from the session's MCP config). It has not been re-proven against a
live hosted connector since. Until it has, treat a hook deny rule against a
hosted connector as untested, and write it to match the raw name as well as
the alias — [docs/hooks.md](hooks.md#policy-allow--deny) gives the shape.

## What are the two modes, and why is one fail-open and the other fail-closed?

**Record mode** observes. It is the default, it is what this checkout has, and
it forwards bytes unchanged.

**Gateway mode** enforces. It is `record --policy <file>`, and it adds
per-tool allow / hold / deny, plus a boundary filter over tool results that
redacts secret-shaped values and flags or blocks prompt-injection markers. It
is **not merged to main and not in this checkout**. Everything in this section
about gateway mode was run against a separate tree carrying PR #8; treat it as
a preview of behaviour that may still change. Its own documentation is
`docs/gateway.md` and `docs/policy.md` in that branch.

The split in failure behaviour is deliberate and it runs in opposite
directions:

| | Record mode | Gateway mode |
| --- | --- | --- |
| Store cannot be written | recording is disabled, traffic continues | a call needing a hold is **denied** |
| Policy cannot be read | not applicable | exits 2 before the server is spawned |
| A message cannot be parsed | forwarded unchanged | refused, with a JSON-RPC error to the client |
| Guiding rule | never break the agent | never fail into permitting |

The reasoning is that a flight recorder that can ground the aircraft is worse
than no flight recorder — people turn it off. An enforcement point that
silently permits what it could not evaluate is worse than no enforcement point
— people believe it. So recording drops events rather than blocking traffic,
and enforcement refuses calls rather than waving them through.

Both halves were exercised here with the same broken data directory (a path
whose parent is a regular file, so the store cannot be created).

Record mode keeps going, and says how much it lost. (A stand-in client script
sends one `initialize` and one `tools/call`, and prints what came back as
`CLIENT RECEIVED`; everything else is the recorder's own stderr.)

```
$ mcp-recorder record --data-dir /home/user/ovcheck/blocker/nope -- node echo-server.cjs
[mcp-recorder] recording disabled (init failed, traffic unaffected): ENOTDIR: not a directory, mkdir '/home/user/ovcheck/blocker/nope'
CLIENT RECEIVED: {"content":[{"type":"text","text":"{\"hello\":\"world\"}"}]}
[mcp-recorder] session 075fbada recorded 0 events (6 dropped) -> (recording disabled)
```

The tool call succeeded. Six events were dropped, and the count is reported
(it is also carried in the session's `session_end` event, so the gap is itself
part of the record when the store is working again).

Gateway mode, same directory, same stand-in client, and a policy that holds
the call for approval:

```
$ mcp-recorder record --policy hold-policy.yaml --data-dir /home/user/ovcheck/blocker/nope -- node echo-server.cjs
[mcp-recorder] gateway: cannot write hold for tools/call "echo" (ENOTDIR: ...); denying
[mcp-recorder] gateway: denied tools/call "echo" (rule echo-needs-a-human)
CLIENT RECEIVED: {"content":[{"type":"text","text":"mcp-recorder gateway: tools/call \"echo\" denied by policy rule \"echo-needs-a-human\": hold unavailable\nThe gateway could not reach a policy decision, so it refused this call rather than allow it unchecked. You may retry it; ..."}],"isError":true}
```

(trimmed: the repeated ENOTDIR path and the tail of the guidance clause.) A
missing policy file is refused before the server starts, so a typo cannot
become an allow-everything gateway:

```
$ mcp-recorder record --policy does-not-exist.yaml -- node echo-server.cjs
[mcp-recorder] error: policy: cannot read policy file does-not-exist.yaml: ENOENT: no such file or directory, open '…'
$ echo $?
2
```

(trimmed: the absolute path is repeated twice in the real message.)

What gateway mode did when it worked, on the same scripted incident as the
demo above: the outbound POST was denied by rule, the planted credential was
redacted out of the `read_file` result before the agent saw it, and both
decisions were sealed into the chain (trimmed to the agent's own lines):

```
$ npm run demo -- --policy docs/examples/policy.demo.yaml
    │ [mcp-recorder] gateway: policy demo (1 rule)
    │ [mcp-recorder] gateway: redacted tool result of tools/call "read_file" (1 secret-shaped, 0 injection marker(s))
    │ agent: read secrets.env — the gateway redacted the credential before it reached me (exfiltrating the placeholder anyway)
    │ [mcp-recorder] gateway: denied tools/call "http_post" (rule no-exfil)
    │ [mcp-recorder] session 0d1c7c0c recorded 10 events (0 dropped)
    │ PASS — chain intact: 10 event(s), head seq 10
```

A `hold` blocks that one call and nothing else until a human decides. Verified
end to end in the PR #8 tree: the call was held, `holds` listed it, `approve`
released it, and the original request was then forwarded.

```
$ mcp-recorder holds --data-dir data-hold
ID        AGE  SERVER       TOOL  RULE                TIMEOUT
280ec768  9s   echo-server  echo  echo-needs-a-human  1m
$ mcp-recorder approve 280ec768 --data-dir data-hold
approved 280ec768-16c7-40f8-949e-c963a071e2cf: echo on echo-server (rule echo-needs-a-human) by root
```

and, in the gateway's own stderr:

```
[mcp-recorder] gateway: hold 280ec768-16c7-40f8-949e-c963a071e2cf approved; forwarding tools/call "echo" after 16035.62 ms
CLIENT RECEIVED: {"content":[{"type":"text","text":"{\"path\":\"/etc/passwd\"}"}]}
```

Three limits belong here rather than in a footnote. Gateway mode is **not**
byte-for-byte transparent: a line it cannot parse, or one larger than the
scanner's buffer (documented as 32 MiB), is refused with a JSON-RPC error
instead of being forwarded, because it cannot be shown harmless without
parsing. Hold approvals are local trust — anyone who can write the data
directory can approve a held call. And enforcement is stdio only:

```
$ mcp-recorder http --target http://127.0.0.1:9/mcp --policy hold-policy.yaml
[mcp-recorder] error: http: gateway mode is available for the stdio transport only (drop --policy)
$ echo $?
2
```

## What does it cost?

### Latency

`npm run bench` measures added latency over 300 timed round-trips against a
5 ms p50 gate. Two runs here:

```
  series    p50         p95         p99
  direct    0.057ms     0.076ms     0.104ms
  wrapped   0.759ms     1.147ms     1.372ms
  added     0.703ms     1.071ms     1.268ms
  ✓ PASS — p50 added latency = 0.703ms (gate: < 5ms)
```

The second run gave 0.773 ms p50, 1.092 ms p95, 1.626 ms p99. The project's
other recent p50 figures are 0.757, 0.896, 0.918 and 0.951 ms, so under 1 ms
p50 is the consistent picture.

Read that with its limit attached: the benchmark wraps the repository's echo
fixture, which answers in about 0.06 ms. The number is the proxy's added cost,
not a total; against a real server that takes tens or hundreds of milliseconds
it disappears into the noise.

**The hook path is far more expensive and is a different measurement.** Claude
Code spawns one process per hook event, so a call tapped by the hook pays two
process spawns. `docs/hooks.md` reports about 1.1–1.4 s per call measured in
cloud dogfood 3, roughly 1 s of it hook overhead, for calls the stdio proxy
timed at 1–6 ms. That figure was not re-measured for this page.

### Disk

Stored bytes track the number and shape of messages, not the size of the
payloads, because every string becomes a fixed-width `sha256:` reference.
Measured here, all from the same 200-tool-call session (206 events):

| What was recorded | Backend | Bytes on disk | Per event |
| --- | --- | --- | --- |
| 200 calls, about 250 B of arguments each | jsonl | 363,920 | 1,766 B |
| the same, on a machine with six credential-shaped environment variables | jsonl | 509,552 | 2,474 B |
| the same | sqlite (default) | 872,448 | 4,235 B |
| a second identical session appended to that sqlite store | sqlite | +847,872 | 4,116 B |
| **200 calls, about 20 KB of arguments each** | jsonl | **364,533** | **1,770 B** |

The last row is the one to read twice. Roughly eighty times the payload
produced 0.2% more evidence. What does drive per-event size is the identity
block that every event carries, including one fingerprint per
credential-shaped environment variable: six of them added about 700 bytes to
every event.

As a rough scale, on this machine, with this fixture and this argument shape,
10,000 tool calls come to about 18 MB on the jsonl backend and about 41 MB on
sqlite. Your servers, your arguments and your environment will move that
figure, so measure before you plan capacity. There is no retention, rotation
or pruning yet: the store grows until you delete it.

### What it does not do

- **It does not store payloads.** You cannot read back what a tool returned.
  You can confirm that a value you already hold passed through, via `query`.
  If that trade is wrong for you, this is the wrong tool.
- **It does not prevent tampering, it makes tampering evident.** Anyone who
  can write your disk can delete the store outright, and `verify` cannot
  detect a store that has been deleted. What they cannot do quietly is edit it.
- **It does not defend against a fully compromised host** that rewrites the
  chain and `identity.key` together.
- **Record mode does not enforce anything.** It never blocks, rewrites or
  rate-limits. Enforcement needs gateway mode, which is not merged.
- **It cannot see the Anthropic-to-vendor hop** on any surface, and cannot
  block a connector call before it runs on claude.ai web, Desktop chat or
  Cowork. See [docs/connector-coverage.md](connector-coverage.md).
- **It does not aggregate across machines**, and has no fleet view, no
  retention policy and no external anchoring of chain heads yet.
- **It is not on npm.** Install from git; see [docs/install.md](install.md).

## Is this for you?

It fits if:

- you run agents against local stdio MCP servers and want a record you can
  hand to someone else;
- you need to answer "did this credential ever pass through an agent, and
  where did it go" after the fact;
- you use Claude Code and want per-call visibility into Anthropic-hosted
  connectors, accepting that a deny rule against one is untested since the
  naming fix;
- you would rather the enforcement point sat on your machine than in a
  vendor's console, and you can wait for gateway mode to merge.

It does not fit if:

- your agents run on claude.ai web, Desktop chat or Cowork and you want
  per-call visibility — the tap does not exist, and
  [docs/connector-coverage.md](connector-coverage.md) sets out what does;
- you need readable payloads in the log for debugging;
- you need tamper prevention, a WORM store, or an auditor-grade retention
  regime;
- you need enforcement today, or enforcement over the HTTP transport
  (`http --policy` is rejected);
- you cannot tolerate a record with gaps in it. Recording is fail-open by
  design, and a store failure loses events rather than stopping the agent.

## Where to go next

- [docs/install.md](install.md) — installation, per-client config, Windows and
  WSL, uninstall, troubleshooting.
- [docs/connector-coverage.md](connector-coverage.md) — the authority on what
  each surface exposes, and what needs Anthropic.
- [docs/hooks.md](hooks.md) — the Claude Code tap in detail, including the
  policy file and its fail-open guarantees.
- [docs/event-schema.md](event-schema.md) — the frozen
  `edut.mcp-recorder.event.v1` schema, the chain construction and the
  canonicalisation rules.
- [docs/red-team.md](red-team.md) — running the demo incident against a real
  model instead of the scripted agent.
