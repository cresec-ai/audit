# Dogfood 7 — a credential swapped in a live agent session

Every other load-bearing claim in [docs/pov.md](../pov.md) has a named live
run behind it. The credential swap did not. This run is that, and it also
re-checks the two enforcement bugs fixed alongside it.

## What is being proven

1. **The swap fires for a real agent.** An agent calls a tool with a synthetic
   in `headers.Authorization`. The server receives the **real** token; the
   agent's transcript and the evidence chain hold only the synthetic.
2. **An undeclared site gets the synthetic.** The swap is destination-bound:
   a tool that is not a declared site receives the placeholder, and the
   upstream rejects it.
3. **A policy that cannot be loaded denies** rather than silently allowing.
4. **`ui --out` names the store it opened** when nobody passed `--data-dir`.

## Why the byte journal

The recorder's own evidence is the thing under test, so it cannot also be the
only witness for what crossed to the server. `test/e2e/fixtures/wire-server.cjs`
appends every raw stdin line to a journal as base64 of the exact octets. A
swap that never happened, or a line the proxy quietly re-serialised, would
both look fine from inside the chain and wrong in the journal.

## Setup

```bash
bash scripts/dogfood7-setup.sh
```

Writes `/tmp/dogfood7/{policy.yaml,mcp.json,journal.jsonl}`, mints a real
token and a synthetic, and prints the synthetic. The real token goes into the
recorder's environment and nowhere the agent is told to look.

That is **not** a confidentiality claim. On a single-uid machine the agent
could read the setup script. It keeps the transcript honest: whatever ends up
in the chain got there because the recorder put it there.

## Scripted pre-flight (run this before relying on it)

Dogfood 4 failed because two deny rules matched nothing and the only symptom
was a zero nobody was watching. Smoke-test first, every time.

Driving the wrapped server directly, measured on this branch:

```
[mcp-recorder] gateway: swapped credential "df7-post-token" into tools/call
  "post_message" for api.example.test (decision ba55bd1f…, ttl 30s)

REAL token reached the server : True
synthetic reached the server  : False
ref(real)         in chain    : False
ref(Bearer real)  in chain    : False
ref(Bearer synth) in chain    : True
```

and `query "Bearer <synthetic>"` returns one match at
`$.args.headers.Authorization`. The chain verifies.

Note the shape of that last check. Argument values are redacted to refs, so
the synthetic is not in the store as a literal either — what proves the right
one was recorded is that `sha256("Bearer " + synthetic)` is present and both
forms of the real token are absent.

## The live run

Point a Claude Code session at `/tmp/dogfood7/mcp.json` and have the agent
call `post_message` against `https://api.example.test/v1/messages` with
`headers.Authorization: "Bearer <synthetic>"`.

Then check, in this order:

| Check | Command | Must show |
|---|---|---|
| The server got the real token | decode `/tmp/dogfood7/journal.jsonl` | real token present, synthetic absent |
| The chain got only the synthetic | `query "Bearer <synthetic>" --data-dir /tmp/dogfood7/data` | one match at `$.args.headers.Authorization` |
| The real token is nowhere | grep the data dir for the token and for its sha256 | both absent |
| The chain is intact | `verify --data-dir /tmp/dogfood7/data` | PASS |
| Undeclared site | ask the agent to call another tool with the synthetic | journal shows the **synthetic** |
| Policy fail-closed | point `--policy` at a missing file, make one MCP call | `permissionDecision: deny` |
| Store provenance | `ui --out /tmp/x.html --no-open` with no `--data-dir` | stderr names the default store, and the page header names it too |

## Recording the result

Commit the evidence bundle and the journal to `evidence/dogfood-7`, and write
what actually happened — including anything that did not fire. A run that
passes for a reason unrelated to the fix under test has happened here before
(docs/roadmap.md), so state how each check was distinguished from a vacuous
pass.
