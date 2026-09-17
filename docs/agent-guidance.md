# Telling your agent what a refusal means

Gateway mode ([docs/gateway.md](gateway.md)) refuses tool calls. The thing on
the other end of that refusal is a model, and a model that does not understand
a refusal does not stop — it improvises. This page is the snippet you paste
into the agent's project instructions so it stops instead.

## The failure modes

A denied call comes back as an ordinary `isError` tool result, which is how
the session stays alive. But "tool error" is a category the model already has
a plan for, and none of its usual moves are right here:

- **The retry loop.** Tool errors are usually transient, so the model tries
  again. A policy deny is deterministic: the same call denies the same way
  every time. Twenty identical `policy_decision` events, no progress, and the
  human finds out when they read the transcript.
- **The workaround.** The model reads "`http_post` is denied" as a fact about
  `http_post`, not about sending data outwards, and reaches for `bash` and
  `curl` — or a second filesystem server, or a tool the rule's glob does not
  cover. The effect the operator forbade happens anyway. **A policy the agent
  routes around is not a policy.**
- **The silent give-up.** The model decides the tool is broken, drops that
  branch of the task, and reports success on everything else. The human never
  learns a control fired, which is the outcome that makes a gateway pointless.
- **The impatient hold.** A held call takes as long as a human takes to answer
  `mcp-recorder approve`. Nothing at all comes back while it is parked — the
  gateway sends the client no progress note, no partial result, nothing. An
  agent that reads that silence as a hang starts a second route to the same
  effect, and now the operator approves one call while the other has already
  run.

## Why the runtime text is not enough on its own

Almost every refusal the gateway synthesizes carries one of two standard
clauses on a second line. Which one depends on **who refused**:

```
This is a policy decision by the operator, not a tool failure. Do not retry it or use another tool to get the same effect; report it to the user.
```

goes on the refusals somebody decided — a rule denied the call, `mcp.default`
denied it, a human denied the hold (or the timeout the operator configured ran
out), or the boundary filter blocked a result. And:

```
The gateway could not reach a policy decision, so it refused this call rather than allow it unchecked. You may retry it; do not use another tool to get the same effect, and report it to the user.
```

goes on the refusals where the gateway **failed closed**: the policy could not
be evaluated, the hold file could not be written, 256 holds were already
pending, a `hold` rule matched inside a JSON-RPC batch (a batch element has
nowhere to park, so nobody is ever asked), the session ended under a parked
hold — including one a human had already approved — or a result was too large
to scan. No one decided anything about that call, so the text does not claim
they did, and it does not forbid the retry that is often exactly what clears
it. The test is who decided, not how it turned out: a hold a human denied and
a hold the operator's own `on_timeout: deny` ended are both policy decisions,
while a hold that simply ran out of session is not.

Three refusals carry neither clause, because for them both would be untrue;
they are listed at the end of this page.

That floor is not the fix. It arrives *after* the model has committed to a
plan, as one line of tool output competing with everything else in the
context; it is deliberately one sentence pair because it is charged to the
agent's context on every single refusal; and it cannot know anything about
your setup — who to escalate to, which alternative tools are also off limits,
what "tell the user" should look like in your workflow. Instructions the agent
reads *before* it plans are weighted very differently from output it reads
after. Install the snippet.

## The snippet

Paste this into `CLAUDE.md`, `AGENTS.md`, `.cursor/rules/`, or whatever file
your agent reads as project instructions:

```markdown
## Tool calls refused by the mcp-recorder gateway

Some MCP tools here run behind a policy gateway. Its refusals come back as an
`isError` tool result whose text starts with `mcp-recorder gateway:`. The
first line says WHAT happened; a second line, when there is one, says WHO
refused. Read both — they are independent, so check each list separately.

**Second line — who refused, and whether you may retry:**

- `This is a policy decision by the operator` — a person or their policy
  decided this. Do not retry this call.
- `The gateway could not reach a policy decision` — nobody decided anything;
  the gateway could not evaluate the call and refused rather than let it
  through unchecked. Retrying is allowed and often works: the condition (a
  full hold queue, an oversized result, a transient failure) usually clears.
- Neither line — see `must be unique while in flight` below, or a hold your
  own client cancelled, which needs no action from you.

Whichever it is: never reach the same effect through another tool or a shell
command (a denied `http_post` is still denied as `curl`), and never drop the
task silently.

**First line — what happened (check these in order):**

- `exceeds max_scan_bytes` — the result was too big to scan, so it was
  withheld unread. Nothing about your call was judged. Re-run it asking for
  less output: a page, a byte range, a narrower filter.
- `secret-shaped value` or `injection marker` — the call already ran, and its
  result was withheld because of what was in it. Do not re-run it to get the
  bytes another way, and do not read the same content through another tool.
- `must be unique while in flight` — a client bug, not a policy decision: two
  calls used the same JSON-RPC request id. Retry with a fresh id, exactly as
  the text says.
- `(hold ` — this call went to a human for approval. While a call is held you
  see **nothing at all**: no progress note, no partial result. It looks like a
  tool call that is taking a long time, because that is what it is. Do not
  read that silence as a hang, and start no second route to the same effect
  while you wait. By the time you can read any text naming a `hold`, the hold
  is already over and that text says how it ended — `(hold not started)` means
  the session was shutting down, so nobody was ever asked.
- `denied by policy` — this call was refused. If the second line says a person
  or their policy decided it, that decision is final for THIS call — but the
  tool is not broken and is not necessarily off limits, because rules can
  match on arguments, so the same tool called with different arguments may
  well be allowed. Read the reason and the rule id the text quotes before
  deciding what, if anything, to do next.

Whenever a call is refused, tell the user in your reply which tool was
refused, the rule id if the text quotes one, and the reason. Then ask them to
approve it, change the policy, or do it themselves.
```

Nothing in it is specific to one policy, so it can go in a shared or generated
instructions file. If a rule denies something the agent has an obvious
substitute for, adding one line naming the substitute — "outbound HTTP is off
limits, including via `bash`" — is worth more than anything generic.

## What the gateway actually sends

So you can check the snippet against reality, these are the exact first lines.
The clause named in the right-hand comment follows on a second line:

```
mcp-recorder gateway: tools/call "http_post" denied by policy rule "no-exfil": outbound HTTP from agents is not allowed on this machine    # policy decision
mcp-recorder gateway: tools/call "rm" denied by policy (no rule matched; mcp.default is deny)                                              # policy decision
mcp-recorder gateway: tools/call "delete_file" denied by policy rule "danger" (hold abc-123 timed out): needs a human                      # policy decision
mcp-recorder gateway: tools/call "delete_file" denied by policy rule "danger" (hold abc-123 was denied): needs a human                     # policy decision
mcp-recorder gateway: tool result blocked by policy (1 secret-shaped value, 0 injection markers)                                           # policy decision
mcp-recorder gateway: tools/call "rm" denied by policy: too many pending holds                                                             # fail-closed
mcp-recorder gateway: tools/call "read_file" denied by policy: policy evaluation error: regex timed out (exfil-guard)                      # fail-closed
mcp-recorder gateway: tools/call "send_mail" denied by policy rule "needs-human": hold unavailable                                         # fail-closed
mcp-recorder gateway: tools/call "send_mail" denied by policy rule "needs-human": session_end (hold not started)                           # fail-closed
mcp-recorder gateway: tools/call "delete_file" denied by policy rule "danger" (hold abc-123 was abandoned at session end): needs a human   # fail-closed
mcp-recorder gateway: tool result blocked by policy (result of 5000 bytes exceeds max_scan_bytes 4096)                                     # fail-closed
```

Three gateway-synthesized refusals carry no clause at all:

```
mcp-recorder gateway: tools/call "delete_file" denied by policy rule "danger" (hold abc-123 was cancelled): needs a human
mcp-recorder gateway: tools/call "read_file" refused: a tools/call with this id is already in flight. JSON-RPC request id 7 must be unique while in flight; retry with a fresh id.
mcp-recorder gateway: tools/call with a null id is not a valid request
```

The first is a hold the **client itself** withdrew with
`notifications/cancelled` — nothing was refused, and the client that cancelled
already knows. The second is a client id-allocation bug and carries its own
advice, which really does work. The third is the odd one out for the snippet
as well as for the clauses: a `tools/call` sent with `"id": null` is not a
valid JSON-RPC request, so it comes back as a **JSON-RPC error** (code
`-32600`, the text above in `error.message`), not as an `isError` tool result
— a client that sends one usually swallows it rather than showing the model
anything, so the snippet's matching rule never sees it.

## Guidance is not enforcement

The snippet asks for cooperation; it does not compel it. A model that ignores
it, or a prompt injection that talks it out of it, still reaches for the
substitute tool — and the gateway will still be the thing that stops it, or
will not. So treat this page as a way to make refusals *legible*, and keep the
policy itself as the control: if `http_post` is denied because outbound HTTP
is not allowed, deny the shell tool that can also make requests
([docs/policy.md](policy.md)). Every refusal, and every call that went around
one, is in the evidence chain either way.
