# What this is, and what it does to your setup

`@edut/mcp-recorder` records what your agent's MCP tools actually did, into a
local, tamper-evident log, and — with a policy file — can allow, hold or deny
those calls before they run. This page is for deciding whether to run it, and
for knowing what changed once you have.

It does not repeat [docs/install.md](install.md), which is the installation
walkthrough for each client, or the 60-second quickstart in
[README.md](../README.md). Read those for the how; read this for the what and
the cost.

**How the claims on this page were checked.** Every command below was run on
2026-09-17 against this checkout — `main` at `6307cc3`, `@edut/mcp-recorder`
v0.1.0, Node v22.22.2, Linux — and every output block is pasted from that run.
Gateway mode (`record --policy`, `holds`/`approve`/`deny`, the boundary
filter, `policy validate`/`compile`) merged in PR #8 (`b322dea`) and is in this
checkout; it was run here like everything else. Commands are written as
`mcp-recorder ...`, the installed binary name; they were run here as
`node dist/cli.js ...` from the checkout. Where a tool call had to be driven
without a real client, a short script speaking JSON-RPC on stdin stood in for
one, and the blocks below say so. Output is trimmed only where the text says
so. Where something could not be checked here, it is labelled in place, and
[What has been proven against live connectors](#what-has-been-proven-against-live-connectors)
points at the evidence branch you can check yourself.

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

The repository's two transparency tests were re-run here and pass:

```
$ npx vitest run test/stdio-proxy.test.ts -t "forwards bytes unchanged"
 ✓ test/stdio-proxy.test.ts (20 tests | 19 skipped) 62ms
 Test Files  1 passed (1)
      Tests  1 passed | 19 skipped (20)

$ npx vitest run test/stdio-proxy.test.ts -t "every byte the client sent"
 ✓ test/stdio-proxy.test.ts (20 tests | 19 skipped) 522ms
 Test Files  1 passed (1)
      Tests  1 passed | 19 skipped (20)
```

(trimmed: the timing footer of each run, and the matched test's own name line
in the second.)

The second is the one that matters. It runs the same deliberately nasty
stream twice — once straight into the server, once through the proxy — and
compares the raw buffers in both directions. The stream carries CRLF framing,
a bare CRLF, non-JSON noise, a JSON-RPC integer past 2^53, an unterminated
trailing line, and, in each direction, a single line larger than the proxy's
own 32 MiB tap cap. Every byte matches.

Nothing is sent anywhere. Searching `src/` for the ways a Node program opens
a socket finds two files, and both are servers this tool runs locally on your
behalf:

```
$ grep -rnE "from 'node:(http|https|net|tls|dgram)'|\bfetch\(|new WebSocket" src/
src/replay/serve.ts:13:import { createServer } from 'node:http';
src/replay/serve.ts:14:import type { IncomingMessage, ServerResponse } from 'node:http';
src/proxy/http.ts:11:import { createServer, request as httpRequest } from 'node:http';
src/proxy/http.ts:12:import type { IncomingMessage, OutgoingHttpHeaders, ServerResponse } from 'node:http';
src/proxy/http.ts:13:import { request as httpsRequest } from 'node:https';
src/proxy/http.ts:17:import type { AddressInfo } from 'node:net';
```

`src/replay/serve.ts` is the local replay UI (`ui` without `--out`);
`src/proxy/http.ts` is the `http` subcommand, forwarding to the target you
name on the command line. There is no `fetch`, no WebSocket, and no other
outbound client anywhere in `src/`. Evidence leaves the machine only when you
run `export`.

### Where the evidence lands

The default data directory is `~/.mcp-recorder` (override with `--data-dir` or
`MCP_RECORDER_DATA_DIR`). A session recorded into a fresh directory leaves
three files:

```
$ ls -l data
-rw-r--r-- 1 root root 45056 Sep 17 05:38 evidence.db
-rw------- 1 root root    65 Sep 17 05:38 identity.key
-rw-r--r-- 1 root root    65 Sep 17 05:38 identity.pub
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
SESSION   STARTED                   ENDED                     SERVER      EVENTS  TOOL_CALLS  ERRORS  SERVERS  DECISIONS  LAST_EVENT
35393152  2026-09-17T05:26:14.634Z  2026-09-17T05:26:15.571Z  corp-notes  9       4           0       1        0          2026-09-17T05:26:15.571Z
```

Read `DECISIONS` with care: it counts `policy_decision` events, which only
gateway mode emits. A hook deny is a real, recorded enforcement action that
leaves this column at 0 — see
[Known gaps](#known-gaps-in-what-this-reports).

Whether the record is intact:

```
$ mcp-recorder verify --data-dir data
verify store /home/user/ovcheck/data/evidence.db (sqlite)
pinned signer: ed25519 cd06d0f0f32fe6d1… (/home/user/ovcheck/data/identity.pub)
PASS — chain intact: 9 event(s), head seq 9
signed head: seq 9 by ed25519 cd06d0f0f32fe6d1… at 2026-09-17T05:26:15.572Z
```

Blast radius for a value you already hold — the planted credential, hashed and
looked up:

```
$ mcp-recorder query 'sk-demo-EXFILTRATION-c4n4ry-9f3a7b2e' --data-dir data
TIMESTAMP                 KIND       NAME       SESSION   MATCHED_ON  PATH
2026-09-17T05:26:15.544Z  tool_call  read_file  35393152  ref         $.result.content[0].text.secret_refs[0]
2026-09-17T05:26:15.547Z  tool_call  http_post  35393152  ref         $.args.body

2 matches across 1 sessions
```

The credential was read out of a file and then appeared in the body of an
outbound POST. Neither value is stored; both were found by hash. A `query`
miss is not proof of absence — [README.md](../README.md#security-model-the-honest-version)
sets out which shapes are findable.

`verify` fails loudly on an edit. One altered field — a tool name — in one
event of a 204-event chain, with everything else left alone:

```
$ mcp-recorder verify --data-dir tampered
verify store /home/user/ovcheck/tampered/evidence.jsonl (jsonl)
pinned signer: ed25519 7c530b57a19a3f31… (/home/user/ovcheck/tampered/identity.pub)
FAIL — evidence does NOT verify: 204 event(s) checked
signed head: seq 204 by ed25519 7c530b57a19a3f31… at 2026-09-17T05:27:14.051Z

TYPE                      SEQ  DETAIL
hash_mismatch             6    stored hash 626c07b5… != recomputed 889ba67a… — the event was altered
signature_chain_mismatch  6    a valid signature attests hash 626c07b5… at seq 6, but the chain recomputes to 889ba67a…
```

(exit code 1; the hashes are trimmed to their first four bytes for width.)

`export` writes a bundle a stranger can check with bare Node and no install:

```
$ mcp-recorder export --data-dir data --dir bundle
[mcp-recorder] exported 9 event(s) (seq 1..9), head 99d06215a1971643… signed by ed25519 cd06d0f0f32fe6d1…
[mcp-recorder] bundle dir: /home/user/ovcheck/bundle
[mcp-recorder] verify anywhere with: node verify.cjs (inside the bundle)
$ ls -l bundle
-rw-r--r-- 1 root root   479 Sep 17 05:38 README.txt
-rw-r--r-- 1 root root 15903 Sep 17 05:38 events.jsonl
-rw-r--r-- 1 root root   920 Sep 17 05:38 manifest.json
-rw-r--r-- 1 root root   113 Sep 17 05:38 public_key.pem
-rw-r--r-- 1 root root 10534 Sep 17 05:38 verify.cjs
```

**The limit is in the tool's own output, and it matters.** Running the
bundle's verifier without a key obtained out of band proves internal
consistency and nothing more:

```
$ node verify.cjs
PASS: evidence bundle verified
  events     : 9 (seq 1..9)
  signed by  : ed25519 cd06d0f0f32fe6d1cba6c9f54832e8186a52a7504fc15c543d0f520afb99b781 at 2026-09-17T05:38:08.820Z
  key check  : NOT independently verified - the key came from this bundle
               itself (public_key.pem / manifest.json), which an attacker
               who forged the whole bundle controls too. Re-run with
               --public-key <hex|path> using a key you obtained out of band
               (e.g. from the operator directly) for real assurance.
```

(trimmed: the base/head hash lines and the unsigned-metadata block are
omitted.) For real third-party assurance the verifier needs `--public-key`,
pinned to a key the recipient got from the operator directly rather than from
the artefact being checked. `verify --bundle` says the same thing about its
own default pin.

There is also a replay timeline — see, act, effect, with identity context on
each event — served locally or written to a file:

```
$ mcp-recorder ui --data-dir data --out timeline.html --no-open
[mcp-recorder] wrote replay page to /home/user/ovcheck/timeline.html
```

One sharp edge, reproduced here: a `--data-dir` pointing at a store that does
not exist produces a page that looks fine and is empty, with no warning and
exit code 0.

```
$ mcp-recorder ui --data-dir /home/user/ovcheck/no-such-store --out empty.html --no-open
[mcp-recorder] wrote replay page to /home/user/ovcheck/empty.html
$ echo $?
0
$ grep -o 'chain intact[^<]*' empty.html | head -1
chain intact, 0 events, head unsigned
```

The green tick is truthful about a chain of zero events, but it reads as
reassurance. Omitting `--data-dir` altogether does the same thing against the
default `~/.mcp-recorder`, which is how it bit cloud dogfood 5. Check the
event count and the store path before you conclude anything from a replay
page.

## Where can it see your agent's traffic?

There are three vantage points. They are not equivalent, and the difference
decides whether this tool is useful to you at all.
[docs/connector-coverage.md](connector-coverage.md) is the authority on what
each surface exposes; this table is the short form.

| Vantage point | How it attaches | What it can see | What it can do about it | How that was checked |
| --- | --- | --- | --- | --- |
| `record` — stdio proxy | your client launches the server through it, one config line | every JSON-RPC message in both directions, for that one local server | nothing in record mode; allow / hold / deny per tool, and a boundary filter over results, in gateway mode | verified here: `npm run demo` with and without `--policy`, a 200-call session, both transparency tests, a live hold/approve round trip |
| `hook` — Claude Code PreToolUse / PostToolUse / PostToolUseFailure | entries in a Claude Code settings file | per call: tool name, the full input, and the response or the error string — for every `mcp__*` tool, **including Anthropic-hosted connectors** | deny a call before it runs, via `--policy` | verified here against the documented hook JSON on stdin, including a deny; and live in cloud dogfood 5, where two deny rules blocked four real ClickUp calls — see below for what that did and did not prove |
| `http` — HTTP-transport proxy | you point the client at the proxy instead of the server | the HTTP MCP traffic it proxies | nothing; `http --policy` is rejected with exit 2 | the repository's `test/http-proxy.test.ts` was run here, 17 tests pass; the `--policy` rejection was run here; no live remote server was exercised for this page |

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
session is the one the project has observed hooks firing in directly; the rest
come from Anthropic's documentation. On claude.ai web and Desktop chat the
only customer-side feeds are Anthropic's own, and they are Enterprise-gated.
Cowork should be treated as **not** covered by the hook until a probe says
otherwise; `docs/connector-coverage.md` records the evidence for that,
including two community reports that hooks do not fire there.

Feeding the hook the documented PreToolUse and PostToolUse JSON for a
connector-shaped tool works here, including finding a secret embedded in a
longer argument string:

```
$ mcp-recorder hook --data-dir data-hook < pre.json     # exit 0, no output = allow
$ mcp-recorder hook --data-dir data-hook < post.json
$ mcp-recorder sessions --data-dir data-hook
SESSION   STARTED                   ENDED   SERVER       EVENTS  TOOL_CALLS  ERRORS  SERVERS  DECISIONS  LAST_EVENT
11111111  2026-09-17T05:29:09.526Z  (open)  claude-code  3       1           0       1        0          2026-09-17T05:29:14.564Z

$ mcp-recorder query 'AKIAIOSFODNN7EXAMPLE' --data-dir data-hook
TIMESTAMP                 KIND       NAME          SESSION   MATCHED_ON  PATH
2026-09-17T05:29:09.526Z  tool_call  send_message  11111111  ref         $.args.body.secret_refs[0]
2026-09-17T05:29:14.564Z  tool_call  send_message  11111111  ref         $.args.body.secret_refs[0]

2 matches across 1 sessions
```

A deny rule fires against the same payload:

```
$ mcp-recorder hook --data-dir data-hookdeny --policy hook-policy.json < pre.json
{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"mcp-recorder policy: outbound mail from agents needs a human"}}
```

Those are synthetic payloads fed on stdin. What happened against real hosted
connectors is the next section, and it is the part worth reading closely.

## What has been proven against live connectors

Five cloud dogfood runs have driven this from inside a real Claude Code cloud
session; the last three (3, 4 and 5) exercised Anthropic-hosted connectors
through the hook. Each left a `REPORT.md` and a signed evidence bundle on an
`evidence/cloud-dogfood-*` branch. The latest is `evidence/cloud-dogfood-5`,
and you can check it without trusting this page:

```
$ git show origin/evidence/cloud-dogfood-5:evidence/cloud-dogfood-5/incident.zip > incident.zip
$ mcp-recorder verify --bundle incident.zip
verify bundle /home/user/ovcheck/incident.zip
pinned signer: ed25519 cf8121b10b9dba36… (bundle's own manifest.json — self-pinned; pass --public-key with a key obtained out of band for independent assurance)
PASS — chain intact: 46 event(s), head seq 46
signed head: seq 46 by ed25519 cf8121b10b9dba36… at 2026-09-17T04:58:15.166Z
```

(trimmed: the unsigned-metadata block.) The bundle's own standalone verifier
agrees, and `evidence/cloud-dogfood-5/REPORT.md` on the same branch is the
full account. Counting the events in that bundle here reproduces the run's
headline numbers, against the previous run's bundle as a baseline:

| Counted over the signed bundle's `events.jsonl` | dogfood 4 | dogfood 5 |
| --- | --- | --- |
| events | 62 | 46 |
| `policy_decision` events | 0 | 1 |
| events carrying a `gateway` field | 0 | 4 |
| events containing `"policy_denied"` | 0 | 5 |
| events with `server.url` set | 2 (github's relay only) | 14 (ClickUp ×6, github ×2, Gmail ×2, Calendar ×2, Drive ×2) |

Grepping the same `events.jsonl` for the injection fixture's `SYSTEM
OVERRIDE` text, its exfil URL, `secrets.env`, the ClickUp list id and the
account owner's personal identifiers returns zero matches for every one of
them. Dogfood 5's own report records the same result for the evidence store
and the replay page, which are not on the branch and were not re-checked
here.

What the run established:

- **Both hook deny routes blocked live ClickUp calls, twice each.** Route A
  was spelled as the host alias only
  (`^mcp__mcp\.clickup\.com__clickup_filter_tasks$`); route B was tool-anchored
  with the server segment left open
  (`^mcp__.*__clickup_get_workspace_members$`). Neither call reached the
  workspace.
- **Gateway mode ran in a live agent session for the first time.**
  `http_post` was denied through a real agent, with a readable `isError`
  refusal naming the rule, and `list_notes` was allowed. Every earlier
  gateway test drove a synthetic client.
- **A prompt-injection fixture was flagged and not obeyed.** The recorded
  boundary result is `injection_found: 1`, `action: "flag"`; the agent never
  read `secrets.env` and never called the exfil URL.

### The caveat, and how it was closed

Dogfood 5's session happened to have its MCP config keyed by UUID *and* its
tool names UUID-prefixed. The two agreed, so connector resolution succeeded
on **route 1** — the plain config-key lookup — and PR #16's new
**declared-tool fallback (route 2)** never executed. Across three live runs,
route 2 has run zero times: dogfood 3, route 1 sufficed; dogfood 4, route 1
broke and route 2 did not exist yet; dogfood 5, route 1 sufficed again. So
dogfood 5's denies firing did **not** by itself prove the fix.

That gap was closed here, with the real binary rather than a unit test. This
session's own real MCP config was rebuilt into dogfood 4's exact failing
shape — every `mcpServers` key replaced by a UUID, so no `ClickUp` key
exists, with each entry's `tools[]` left intact — `MCP_RECORDER_MCP_CONFIG`
was pointed at it, and the hook was driven with the *friendly* tool name
`mcp__ClickUp__clickup_filter_tasks` against a host-alias-only deny rule.
The rule can only match if the connector resolved, and route 1 cannot
resolve it, because no key matches the segment:

```
$ python3 mismatch-config.py
wrote /home/user/ovcheck/mcp-config-uuid-keys.json
keys : 36b8b2c3-…, 383f942b-…, 69449651-…, d2c7098e-…, ebac5cf4-…, ecce8851-…
has a "ClickUp" key? False
clickup_filter_tasks still declared in exactly one entry? True

$ MCP_RECORDER_MCP_CONFIG=mcp-config-uuid-keys.json \
>   mcp-recorder hook --data-dir data-route2 --policy alias-only-policy.json < pre-clickup.json
{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"mcp-recorder policy: host-alias-only rule: this can only match if the connector resolved"}}
```

(trimmed: the six UUID keys are shortened.) The recorded event carries the
resolution that made the rule match:

```
{
 "kind": "tool_call",
 "tool": "clickup_filter_tasks",
 "server": {
  "command": "hook:claude-code",
  "name": "ClickUp",
  "transport": "stdio",
  "url": "https://mcp.clickup.com/mcp"
 },
 "error": { "type": "policy_denied", "message_ref": "sha256:2c1909bc…" },
 "phase": "pre"
}
```

(read out of the store with sqlite; the `message_ref` hash and the identity
block are trimmed.) `server.name` is the segment Claude Code used, and
`server.url` is what route 2 resolved from the entry that declares
`clickup_filter_tasks`.

A control run of the identical call with no config file present allows it,
and records no `server.url` — so the deny came from resolution and not from
something else:

```
$ MCP_RECORDER_MCP_CONFIG=no-such-config.json \
>   mcp-recorder hook --data-dir data-control --policy alias-only-policy.json < pre-clickup.json
$ echo $?
0
```

Nothing on stdout and exit 0 is how the hook says "allow". The control's
recorded event carries `"error": null` and no `server.url` at all.

**State it precisely.** The declared-tool fallback is proven against the real
binary in the exact shape that defeated dogfood 4, and **cloud dogfood 6 then
ran it inside a live session**: that run rewrote its own MCP config at session
start so no key could match any segment, and the host-alias-only rule fired and
blocked both live ClickUp calls, with
`server.url: "https://mcp.clickup.com/mcp"` on the denied events. The mismatch
was forced deliberately; no run has yet been handed one by the platform.

**And none of it happens on a laptop.** Local dogfood 6 found no
`/tmp/mcp-config-*.json` on a local machine — not before, during or after a
session — and no claude.ai connector in any `mcpServers` map there, so
`server.url` is never recorded locally and a host-alias rule can never fire.
If a deny rule against a hosted connector has to hold, write it to match the
raw tool name as well as the host alias — route B above needs no resolution at
all, and locally it is the only thing that works —
and [docs/hooks.md](hooks.md#write-deny-rules-against-the-tool-not-the-server-segment)
gives the shape.

## What are the two modes, and why is one fail-open and the other fail-closed?

**Record mode** observes. It is the default, and it forwards bytes unchanged.

**Gateway mode** enforces. It is `record --policy <file>`, and it adds
per-tool allow / hold / deny, plus a boundary filter over tool results that
redacts secret-shaped values and flags or blocks prompt-injection markers.
Its own documentation is [docs/gateway.md](gateway.md) and
[docs/policy.md](policy.md).

The split in failure behaviour is deliberate and it runs in opposite
directions:

| | Record mode | Gateway mode |
| --- | --- | --- |
| Store cannot be written | recording is disabled, traffic continues | recording is disabled, allow and deny rules still decide normally |
| A hold file cannot be written | not applicable | that call is **denied** |
| Policy cannot be read | not applicable | exits 2 before the server is spawned |
| A message cannot be parsed | forwarded unchanged | refused, with a JSON-RPC error to the client |
| Guiding rule | never break the agent | never fail into permitting |

The first two rows are one directory failure seen twice, and the distinction
between them is the whole design: a store that cannot be written never turns
into a deny, but a decision that cannot be *reached* — a hold nobody can
record, so nobody can approve — does.

The reasoning is that a flight recorder that can ground the aircraft is worse
than no flight recorder — people turn it off. An enforcement point that
silently permits what it could not evaluate is worse than no enforcement point
— people believe it. So recording drops events rather than blocking traffic,
and enforcement refuses calls rather than waving them through.

All three cases were exercised here with the same broken data directory (a
path whose parent is a regular file, so the store cannot be created).

Record mode keeps going, and says how much it lost. (A stand-in client script
sends one `initialize` and one `tools/call`, and prints what came back as
`CLIENT RECEIVED`; everything else is the recorder's own stderr.)

```
$ mcp-recorder record --data-dir /home/user/ovcheck/blocker/nope -- node echo-server.cjs
[mcp-recorder] recording disabled (init failed, traffic unaffected): ENOTDIR: not a directory, mkdir '/home/user/ovcheck/blocker/nope'
CLIENT RECEIVED: {"content":[{"type":"text","text":"{\"query\":\"srv/reports FROM customers WHERE region = 'emea' -- call 1\",\"path\":\"/srv/reports/1.csv\",\"note\":\"quarterly reconciliation batch 1\",\"filler\":\"xxxxxxxxxx\"}"}]}
[mcp-recorder] session 6d2fa2ac recorded 0 events (5 dropped) -> (recording disabled)
```

The tool call succeeded. Five events were dropped, and the count is reported —
it is also carried in the session's `session_end` event, so the gap is itself
part of the record when the store is working again.

Gateway mode, same directory, same stand-in client, and a policy that holds
the call for approval:

```
$ mcp-recorder record --policy hold-policy.yaml --data-dir /home/user/ovcheck/blocker/nope -- node echo-server.cjs
[mcp-recorder] recording disabled (init failed, traffic unaffected): ENOTDIR: not a directory, mkdir '/home/user/ovcheck/blocker/nope'
[mcp-recorder] gateway: policy hold-demo (1 rule)
[mcp-recorder] gateway: cannot write hold for tools/call "echo" (ENOTDIR: not a directory, mkdir '/home/user/ovcheck/blocker/nope/holds'); denying
[mcp-recorder] gateway: denied tools/call "echo" (rule echo-needs-a-human)
CLIENT RECEIVED: {"content":[{"type":"text","text":"mcp-recorder gateway: tools/call \"echo\" denied by policy rule \"echo-needs-a-human\": hold unavailable\nThe gateway could not reach a policy decision, so it refused this call rather than allow it unchecked. …"}],"isError":true}
[mcp-recorder] session 04626e11 recorded 0 events (6 dropped) -> (recording disabled)
```

(trimmed: the tail of the guidance clause.) The deny is not the store failing.
The same broken directory with a policy whose rule is `allow` lets the call
through:

```
$ mcp-recorder record --policy allow-policy.yaml --data-dir /home/user/ovcheck/blocker/nope -- node echo-server.cjs
[mcp-recorder] recording disabled (init failed, traffic unaffected): ENOTDIR: not a directory, mkdir '/home/user/ovcheck/blocker/nope'
[mcp-recorder] gateway: policy allow-demo (1 rule)
CLIENT RECEIVED: {"content":[{"type":"text","text":"{\"query\":\"srv/reports FROM customers WHERE region = 'emea' -- call 1\",\"path\":\"/srv/reports/1.csv\",\"note\":\"quarterly reconciliation batch 1\",\"filler\":\"xxxxxxxxxx\"}"}]}
[mcp-recorder] session 6c943010 recorded 0 events (5 dropped) -> (recording disabled)
```

Recording failed open in all three runs — same first line every time. What
differs is whether the enforcement decision could be reached at all.

A policy that cannot be read is refused before the server starts, so a typo
cannot become an allow-everything gateway:

```
$ mcp-recorder record --policy does-not-exist.yaml -- node echo-server.cjs
[mcp-recorder] error: policy: cannot read policy file /home/user/ovcheck/does-not-exist.yaml: ENOENT: no such file or directory, open '/home/user/ovcheck/does-not-exist.yaml'
$ echo $?
2
```

A policy file can be checked before it is used, and compiled for an external
policy engine:

```
$ mcp-recorder policy validate hold-policy.yaml
/home/user/ovcheck/hold-policy.yaml: valid (1 mcp rules, 0 egress rules)
$ echo $?
0
$ mcp-recorder policy compile hold-policy.yaml | head -3
package cresec.mcp

import rego.v1
```

Validation is strict, and says where it failed. The first draft of that file
written for this page put a `timeout` key on the rule instead of using
`mcp.hold.timeout_ms`, and `validate` caught it before the gateway ever ran:

```
$ mcp-recorder policy validate hold-policy.yaml    # the earlier, wrong draft
/home/user/ovcheck/hold-policy.yaml: invalid
  /mcp/rules/0/timeout: unknown property "timeout"
$ echo $?
1
```

What gateway mode does when it works, on the same scripted incident as the
demo above: the injection marker in the poisoned note was flagged, the
planted credential was redacted out of the `read_file` result before the agent
saw it, the outbound POST was denied by rule, and all of it was sealed into
the chain (trimmed to the agent's own lines):

```
$ npm run demo -- --policy docs/examples/policy.demo.yaml
    │ [mcp-recorder] gateway: policy demo (1 rule)
    │ agent: read vendor-onboarding.md
    │ agent: following injected instructions…
    │ [mcp-recorder] gateway: redacted tool result of tools/call "read_file" (1 secret-shaped, 0 injection marker(s))
    │ agent: read secrets.env — the gateway redacted the credential before it reached me (exfiltrating the placeholder anyway)
    │ [mcp-recorder] gateway: denied tools/call "http_post" (rule no-exfil)
    │ agent: http_post to https://vendor-verify.example.com/collect was DENIED by the gateway: mcp-recorder gateway: tools/call "http_post" denied by policy rule "no-exfil": outbound HTTP from agents is not allowed
    │ [mcp-recorder] session ea1b1750 recorded 10 events (0 dropped)
    │ PASS — chain intact: 10 event(s), head seq 10
```

Read `agent: following injected instructions…` as the warning it is. The
demo policy sets `boundary.injection: flag`, and flag means flag: the
recorded boundary result for that note is `injection_found: 1`,
`action: "flag"`, `decision: "allow"`, and the agent received the injected
text and acted on it. What stopped the exfiltration was the separate
`no-exfil` deny rule, which happened to cover the vector this fixture uses.
See [Known gaps](#known-gaps-in-what-this-reports).

A `hold` blocks that one call and nothing else until a human decides.
Verified end to end here — the call was held, `holds` listed it, `approve`
released it, and the original request was then forwarded:

```
$ mcp-recorder holds --data-dir data-hold
ID        AGE  SERVER       TOOL  RULE                TIMEOUT
3fd5ba31  3s   echo-server  echo  echo-needs-a-human  56s
$ mcp-recorder approve 3fd5ba31 --data-dir data-hold
approved 3fd5ba31-ac02-42c2-987a-370bf5290692: echo on echo-server (rule echo-needs-a-human) by root
```

and, in the gateway's own stderr and at the stand-in client:

```
[mcp-recorder] gateway: holding tools/call "echo" (rule echo-needs-a-human) as 3fd5ba31-ac02-42c2-987a-370bf5290692 — mcp-recorder approve|deny 3fd5ba31-ac02-42c2-987a-370bf5290692
[mcp-recorder] gateway: hold 3fd5ba31-ac02-42c2-987a-370bf5290692 approved; forwarding tools/call "echo" after 6614.9 ms
CLIENT RECEIVED: {"content":[{"type":"text","text":"{\"query\":\"srv/reports FROM customers WHERE region = 'emea' -- call 1\",…}"}]}
[mcp-recorder] session 352b574d recorded 6 events (0 dropped) -> /home/user/ovcheck/data-hold/evidence.db
```

(trimmed: the tail of the echoed arguments on the `CLIENT RECEIVED` line.)
The 6.6 seconds is how long the approval took to type, not overhead.

Three limits belong here rather than in a footnote. Gateway mode is **not**
byte-for-byte transparent: a line it cannot parse, or one larger than the
scanner's buffer (32 MiB, `DEFAULT_MAX_LINE_BYTES` in `src/proxy/framing.ts`),
is refused with a JSON-RPC error instead of being forwarded, because it cannot
be shown harmless without parsing. Hold approvals are local trust — anyone who
can write the data directory can approve a held call. And enforcement is stdio
only:

```
$ mcp-recorder http --target http://127.0.0.1:9/mcp --policy hold-policy.yaml
[mcp-recorder] error: http: gateway mode is available for the stdio transport only (drop --policy)
$ echo $?
2
```

## Known gaps in what this reports

These are open as of `6307cc3`. Each was reproduced here on this checkout,
and each is a case where what you see under-states or mis-states what
happened.

**1. `sessions`'s `DECISIONS` column reads 0 for a hook session that denied
calls.** A hook deny is recorded as a `tool_call` with
`error.type: "policy_denied"`, not as a `policy_decision` event, and
`DECISIONS` counts only the latter. Side by side — a gateway session that
held and then allowed one call, and the hook session from the route-2 test
above that denied one:

```
$ mcp-recorder sessions --data-dir data-hold
SESSION   STARTED                   ENDED                     SERVER           EVENTS  TOOL_CALLS  ERRORS  SERVERS  DECISIONS  LAST_EVENT
352b574d  2026-09-17T05:31:30.616Z  2026-09-17T05:31:37.276Z  echo-server.cjs  6       1           0       1        1          2026-09-17T05:31:37.276Z

$ mcp-recorder sessions --data-dir data-route2
SESSION   STARTED                   ENDED   SERVER       EVENTS  TOOL_CALLS  ERRORS  SERVERS  DECISIONS  LAST_EVENT
22222222  2026-09-17T05:38:23.646Z  (open)  claude-code  2       1           1       1        0          2026-09-17T05:38:23.646Z
```

The deny is in `ERRORS`, not in `DECISIONS`. Anyone reading `DECISIONS` as
their at-a-glance enforcement signal would conclude, wrongly, that nothing
was enforced. Cloud dogfood 5's own hosted-connector session shows `ERRORS 5,
DECISIONS 0` with four real blocked calls behind it.

**2. The two enforcement paths use different event shapes for the same
thing.** A gateway deny emits a `policy_decision` event *and* a `tool_call`
carrying `error.type: "policy_denied"`. A hook deny emits only the latter.
Counted over `export --dir` bundles of the two runs above — `gwbundle` from
the gateway demo's store, `hookbundle` from the route-2 hook store:

```
$ grep -c '"kind":"policy_decision"' gwbundle/events.jsonl    # gateway deny
1
$ grep -c '"policy_denied"' gwbundle/events.jsonl
1
$ grep -c '"kind":"policy_decision"' hookbundle/events.jsonl  # hook deny
0
$ grep -c '"policy_denied"' hookbundle/events.jsonl
1
```

Counting `policy_decision` events alone therefore undercounts hook denies by
design. Count both.

**3. The replay page badges the two differently.** A gateway deny gets a
pill-style badge; a hook deny gets the generic error badge with inline text.
Both are visible, neither is hidden, but the same concept — this call was
blocked — does not look the same. The two pages are `ui --out` over the same
two stores as above:

```
$ grep -oE 'class="badge[^"]*"' gw.html | sort | uniq -c
      3 class="badge boundary"
      1 class="badge err"
      4 class="badge genai"
      3 class="badge gw gw-allow"
      2 class="badge gw gw-deny"
$ grep -oE 'class="badge[^"]*"' hookdeny.html | sort | uniq -c
      1 class="badge err"
      1 class="badge genai"
```

**4. `boundary.injection: flag` flags but does not block.** The injected text
still reaches the agent, as the demo transcript above shows. In cloud dogfood
5 the fixture was flagged and the agent did not obey it, but what actually
prevented harm was the separate `no-exfil` deny rule, which happened to cover
that fixture's exfil vector. A fixture using a different vector would have
been flagged and nothing more. If you want the text stopped rather than
noted, set `injection: block` or `redact` — and read
[docs/policy.md](policy.md#mcpboundary) for what each one costs.

**5. `ui` against a missing or empty store produces a plausible-looking empty
page**, with no warning and exit 0. Shown above under
[What do you get out of a recorded session](#what-do-you-get-out-of-a-recorded-session).

## What does it cost?

### Latency

`npm run bench` measures added latency over 300 timed round-trips against a
5 ms p50 gate. Two runs here:

```
  series    p50         p95         p99
  direct    0.049ms     0.061ms     0.083ms
  wrapped   0.899ms     1.464ms     1.808ms
  added     0.850ms     1.403ms     1.725ms
  ✓ PASS — p50 added latency = 0.850ms (gate: < 5ms)
```

The second run gave 0.802 ms p50, 1.167 ms p95, 1.786 ms p99. Two runs is two
runs; what they show is roughly a fifth of the gate, not a figure to quote to
three decimal places. Run the bench on your own hardware before you rely on
the number.

Read that with its limit attached: the benchmark wraps the repository's echo
fixture, which answers in about 0.05 ms. The number is the proxy's added cost,
not a total; against a real server that takes tens or hundreds of milliseconds
it disappears into the noise. Gateway mode is a separate, opt-in measurement
(`npm run bench:gateway`), and it was not run for this page.

**The hook path is a different measurement, and its recorded durations are
not this tool's cost.** Claude Code spawns one process per hook event, so a
call tapped by the hook pays two process spawns; the recording itself happens
out of band, in those processes, not inside the call
([docs/hooks.md](hooks.md#performance)). The `duration_ms` the hook records is
the wall-clock gap between its own PreToolUse and PostToolUse events, which
includes Claude Code's own handling of the call as well as the two spawns. In
cloud dogfood 3 that gap was 1,147–1,408 ms on calls the stdio proxy, sitting
on the same two `corp-notes` tools, timed at 1.07 ms and 2.94 ms. Do not read
the difference as recorder overhead; nothing here separates the two. That
figure was not re-measured for this page.

### Disk

Stored bytes track the number and shape of messages, not the size of the
payloads, because every string becomes a fixed-width `sha256:` reference.
Measured here, all from 200-tool-call sessions of 204 events each, on a
machine with six credential-shaped environment variables unless the row says
otherwise:

| What was recorded | Backend | Bytes on disk | Per event |
| --- | --- | --- | --- |
| 200 calls, about 250 B of arguments each | jsonl | 497,890 | 2,441 B |
| the same, with no credential-shaped env vars set | jsonl | 353,678 | 1,734 B |
| the same | sqlite (default) | 933,888 | 4,578 B |
| a second identical session appended to that sqlite store | sqlite | +909,312 | 4,457 B |
| **200 calls, about 20 KB of arguments each** | jsonl | **498,699** | **2,445 B** |

The last row is the one to read twice. Roughly eighty times the payload
produced 0.16% more evidence. What does drive per-event size is the identity
block that every event carries, including one fingerprint per
credential-shaped environment variable: the second row is the first one with
those six removed, and the difference is 707 bytes on every event.

The jsonl backend also writes a `signatures.jsonl` beside `evidence.jsonl`
(75,576 B for the first row); the sizes above are `evidence.jsonl` alone.

As a rough scale, on this machine, with this fixture and this argument shape,
10,000 tool calls come to about 25 MB of `evidence.jsonl` plus about 4 MB of
signatures, or about 45 MB on sqlite. Your servers, your arguments and your
environment will move that figure, so measure before you plan capacity. There
is no retention, rotation or pruning yet: the store grows until you delete it.

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
  rate-limits. Enforcement needs gateway mode or a hook policy.
- **Gateway mode enforces only what a policy names**, and only for
  `tools/call` requests and their results. A `flag` boundary action does not
  stop anything reaching the agent.
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
  connectors, with deny rules that have now blocked real connector calls in a
  live session — subject to the resolution caveat above;
- you would rather the enforcement point sat on your machine than in a
  vendor's console, and per-tool allow / hold / deny over a local stdio
  server is the shape of control you want.

It does not fit if:

- your agents run on claude.ai web, Desktop chat or Cowork and you want
  per-call visibility — the tap does not exist, and
  [docs/connector-coverage.md](connector-coverage.md) sets out what does;
- you need readable payloads in the log for debugging;
- you need tamper prevention, a WORM store, or an auditor-grade retention
  regime;
- you need enforcement over the HTTP transport (`http --policy` is rejected),
  or enforcement that is byte-for-byte transparent;
- you need a single console that reports every enforcement action uniformly —
  today the two paths report differently, as
  [Known gaps](#known-gaps-in-what-this-reports) sets out;
- you cannot tolerate a record with gaps in it. Recording is fail-open by
  design, and a store failure loses events rather than stopping the agent.

## Where to go next

- [docs/install.md](install.md) — installation, per-client config, Windows and
  WSL, uninstall, troubleshooting.
- [docs/deployment.md](deployment.md) — what deploying this in a customer looks
  like, per agent platform: what the install is, how it reaches a fleet, what
  breaks it, and a rollout order.
- [docs/connector-coverage.md](connector-coverage.md) — the authority on what
  each surface exposes, and what needs Anthropic.
- [docs/hooks.md](hooks.md) — the Claude Code tap in detail, including the
  policy file, connector resolution and its fail-open guarantees.
- [docs/gateway.md](gateway.md) and [docs/policy.md](policy.md) — gateway
  mode, `policy.yaml` v1 and the boundary filter.
- [docs/event-schema.md](event-schema.md) — the frozen
  `edut.mcp-recorder.event.v1` schema, the chain construction and the
  canonicalisation rules.
- [docs/red-team.md](red-team.md) — running the demo incident against a real
  model instead of the scripted agent.
