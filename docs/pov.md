# The proof of value, and what this package carries in it

`@edut/mcp-recorder` is the MCP gateway and evidence-chain leg of **Cresec
Governed Tools**. This page tells the story the product is sold on, walks the
four-week proof of value week by week as the ClickUp story page scopes it, and
says for each week what this package contributes — with a status on every
capability — and what the control plane in
[`cresec-ai/nhi`](https://github.com/cresec-ai/nhi) has to supply.

Every capability named here carries a status, and the statuses are load-bearing:

| tag | meaning |
|---|---|
| **shipped** | on `main` of this repository, with a test or a named live run behind it |
| **in-flight** | written but not landed; named branch or worktree |
| **retiring** | exists in the control plane and is being removed under [Retire v1 components](https://app.clickup.com/t/z8n6b5z509) |
| **needs-build** | does not exist; a Roadmap v2 ticket says where it lands |
| **needs-nhi** | exists as code in the control plane (`cresec-ai/nhi`) but is not runnable from a clean checkout today |
| **aspirational** | nobody has built it and it is not scheduled |

A narrative that quietly assumes a **needs-build** capability is worse than
useless — it gets caught in the room. [What we do not
claim](#what-we-do-not-claim) is the list that keeps that from happening, and it
is the most important section here.

The source of truth for the story and the POV scope is the ClickUp doc
[NHI Platform — Product Thesis & Strategic Analysis](https://app.clickup.com/90182720801/docs/2kzmy791-558):
the [Governed Tools story page](https://app.clickup.com/90182720801/docs/2kzmy791-558/2kzmy791-618),
the [build brief](https://app.clickup.com/90182720801/docs/2kzmy791-558/2kzmy791-638)
and the [thesis reconciliation](https://app.clickup.com/90182720801/docs/2kzmy791-558/2kzmy791-598).
The backlog is the ClickUp list
[🛠️ MVP — MCP Black Box](https://app.clickup.com/90182720801/v/l/li/901818701787);
[docs/roadmap.md](roadmap.md) is its engineering reading.

---

## Two repositories, one product

Governed Tools is four pieces: Okta-brokered identity on the way in,
credential-less tools in the middle, mediated egress on the way out, and one
signed record across all three. Two repositories build it.

**[`cresec-ai/nhi`](https://github.com/cresec-ai/nhi) — the Cresec control
plane.** What Roadmap v2 assigns to it: the identity gate (a hosted OIDC front
issuing the identity JWT, with Okta Cross App Access and Entra OBO on top of
the existing RFC 8693 `/v1/tokens/exchange`), the per-user credential vault
(OpenBao, tokens keyed by (user, connector)), the HTTPS egress gateway (the v1
Go data-plane proxy re-targeted at internal tools), the policy engine, the
NATS JetStream record stream, and the manager and security views — all
**needs-build** on top of what exists (the RFC 8693 exchange, the EdDSA JWT
issuer, the OpenBao and OPA clients, the Go data-plane proxy: **needs-nhi**).
It is a pnpm + Turborepo + Go monorepo: a Fastify API over Postgres with
Drizzle schemas, OpenBao, OPA, a Next.js console. Its `/broker/exchange`
decision path (OPA → OpenBao → audit, returning a `decision_id`) — minus its
synthetic keying, which nhi leaves undecided — its OpenBao client and its Rego
bundle are plumbing that Roadmap v2 reuses; they are not the product. Its last
commit on `main` is `1864a59`, dated 2026-05-25. "NHI" stays as the
repository's name and as a technical term for non-human identities; it is no
longer the product's name. One term to read carefully: nhi's older docs and
its stack section use "control plane" for `apps/api` alone (the May 2026
architecture has control plane, data plane and edge as three halves); this
page uses it for the whole repository, as the brief does.

**`@edut/mcp-recorder` (this repository) — the MCP gateway and the evidence
chain.** A TypeScript npm package that runs beside the agent with no server
and no database. Three vantage points: `record` (a transparent stdio proxy in
front of a local MCP server), `hook` (a Claude Code PreToolUse/PostToolUse tap
— the only third-party visibility we have found into Anthropic-hosted
connectors), and `http` (a recording proxy in front of a remote HTTP MCP
server). Gateway mode adds per-tool allow / hold / deny and a tool-result
boundary filter. Evidence is a hash-chained, ed25519-signed store with
`verify`, `export`, `query`, `sessions` and a replay timeline and, when
`MCP_RECORDER_SINK` is set, replicated to an evidence sink as it is recorded. In Roadmap v2 terms this repository supplies
the MCP gateway of
[Phase 3 — Egress gateway: HTTPS + MCP mediation](https://app.clickup.com/t/z8n6b5z4zr)
and the chain, bundle and verifier of
[Phase 4 — Evidence chain & views](https://app.clickup.com/t/z8n6b5z4zv).

Who owns what, keyed to the Roadmap v2 ticket that owns the concept:

| Concept | This repository | Control plane | Roadmap v2 owner, and why |
|---|---|---|---|
| Evidence chain | hash chain + ed25519 head signatures, `verify`, signed portable bundles, live sink replication with fork/gap detection, shipper self-check — **shipped**. Produced and signed at the observed party's edge, then replicated so the observed party cannot silently withhold | `SHA-256(prev ‖ seq ‖ canonicalJson)` in Postgres, written by the control plane about its own decisions; a daily S3 anchor whose writer is interface-only — **needs-nhi** | [Evidence stream + bundles + verifier](https://app.clickup.com/t/z8n6b5z50m). The two chains are different claims to an auditor: one is the observed party's own signed record, the other is the vendor's log. Keep both; do not describe them as one chain |
| Credential brokering | a local broker with seven sources and a synthetic-for-real swap at declared sites, keyed by credential id — **shipped**; on one machine a context and audit control, not a confidentiality one (see [the swap section](#the-credential-swap-what-dogfood-7-proved-and-what-it-did-not)) | synthetic issuance, `/broker/exchange`, OpenBao, per-tenant pepper, keyed by (data-plane instance, synthetic credential) — **needs-nhi** | [[C1] Per-user OAuth connect flows](https://app.clickup.com/t/z8n6b5z8cm): tokens in OpenBao keyed by (user, connector). Neither existing broker is keyed that way today |
| Policy | `policy.yaml` v1, local engine, Rego compiler — **shipped** | OPA, one hand-written Rego bundle — **needs-nhi** | [Policy engine](https://app.clickup.com/t/z8n6b5z50k): (user × tool version) → (connector × tool × scope), action classes read / draft / send / write, draft-only default. Today there are two authoring surfaces, and that is a defect |
| Proxying | stdio + HTTP MCP proxies, MCP-aware — **shipped** | Go data-plane proxy, mTLS, LRU cache, NATS invalidation — **needs-nhi** | [HTTPS egress gateway](https://app.clickup.com/t/z8n6b5z50h) is the data-plane proxy re-targeted; [MCP gateway](https://app.clickup.com/t/z8n6b5z50j) is this repository. Different layers; neither replaces the other |

The join between the two sides is the **actor claim** — (user, tool,
tool-version, host) on every record — and that is a
[Phase 0 decision](https://app.clickup.com/t/z8n6b5z507) not yet taken, so
nothing implements it. `decision_id` already rides the broker protocol
(`src/broker/protocol.ts`) and lands as the attribute
`cresec.broker.decision_id` on swapped `tool_call` events
(`src/gateway/credentials.ts`); it is absent from `policy_decision` events
(`src/schema/events.ts`). The evidence sink's wire contract and the Rego
compile target are the other two seams.

---

## The story

Told in full on the
[Governed Tools story page](https://app.clickup.com/90182720801/docs/2kzmy791-558/2kzmy791-618);
this is the short form.

Lendaro is a 400-person fintech: Okta for identity, Salesforce for accounts,
Gmail for mail, and forty-odd internal tools built in the last six months,
most of them by people who do not write code. Ori sells to mid-market lenders.
He spent a weekend teaching Claude his Monday — find his accounts with no
touch in two weeks, check what is new about each, write an opener in his
voice, drop drafts into Gmail, log the touch in Salesforce — and his reply
rate doubled. It works because it runs *as him*: his accounts, his mailbox,
his logins.

Noa, his manager, wants it for all thirty reps. IT says no. One rep's Claude
touching Salesforce and Gmail is a shrug; thirty copies is a security review:
who sent what to which customer, who approved it, what happens when a rep
leaves, what does it cost. So the routine gets pasted around Slack, three
reps get it half-working, one sends from Ori's mailbox by accident, and it
dies. That gap — AI made Ori capable and the company cannot let his capability
spread — is the customer.

With Governed Tools, Ori presses "Share as a team tool". Cresec splits what he
built into steps everyone shares and settings each rep owns (voice,
exclusions, accounts). Dana opens the team catalog, signs in with Okta,
connects her own Salesforce and Gmail once, and runs it. It runs as Dana. The
tool holds none of her credentials: every call to Salesforce or Gmail passes
through the gateway, which resolves that it is Dana, through Ori's tool
version 3, checks that Dana is allowed to draft but not yet send, injects her
credential, and records the action. Noa sees 30 reps and 412 touches this
week, by rep and by account. Security sees the same page with a signed record
behind every action and never sees a password. Finance sees cost per touch
drop, because the plumbing steps run as code and the model is called only
where Ori's judgment is needed. When Ori leaves, Noa gets a nudge — "Ori's
tool has 28 users and no owner" — and reassigns it. Nothing breaks.

No lock-in: the tool runs on Lendaro's Vercel or Lambda, built in Cursor,
Lovable, v0 or Retool. Cresec's pieces are a sign-in gate, ten lines of
middleware and a gateway URL; the exit is replacing two environment variables
with real credentials. The eight invariants that hold this together are in the
[build brief](https://app.clickup.com/90182720801/docs/2kzmy791-558/2kzmy791-638);
the four that bind this repository are quoted in [`AGENTS.md`](../AGENTS.md).

---

## The proof of value, week by week

Four weeks, one partner, three admin actions from them, zero production
traffic rerouted, no capture SDK, no UI built by us. Scope and success
criteria are quoted from the
[story page](https://app.clickup.com/90182720801/docs/2kzmy791-558/2kzmy791-618);
the status tags and the "what this package contributes" parts are ours.

One thing to say plainly, once, before the weeks. **In the POV as scoped, the
partner's tool is an HTTPS tool on their own Vercel or Lambda talking to
Salesforce and Gmail.** The calls it makes are HTTPS API calls, not MCP calls.
So the HTTPS egress gateway in the control plane
([z8n6b5z50h](https://app.clickup.com/t/z8n6b5z50h)) carries the POV's
conversion, and this package carries two things: the MCP route — a tool, or a
rep's Claude, that reaches a vendor through MCP goes through this gateway
([z8n6b5z50j](https://app.clickup.com/t/z8n6b5z50j)) — and the evidence
discipline — one signed, chained record per mediated call, exported as a
bundle a stranger verifies offline
([z8n6b5z50m](https://app.clickup.com/t/z8n6b5z50m)). Where the ClickUp plan
does not put this package on the POV's critical path, this page does not
claim it is.

### Week 0 — what the partner provides

An Okta admin; a Salesforce admin to approve one connected app; a Google
Workspace admin to allowlist one OAuth app; one rep with a working Claude
routine and two hours; a named tool owner. Nothing from this package is
installed in week 0. Signing the partner is
[Phase 6's 30-day clock](https://app.clickup.com/t/z8n6b5z50r).

### Week 1 — the before-number

**In the room.** A read-only pull of the Okta System Log and app inventory,
plus one connector-side audit log (Salesforce Event Monitoring or Google
Workspace audit). The hour-1 artifact: apps → service accounts → % of
third-party actions attributable to a named person, plus the orphan list.
Success: the CISO sees a number under 20% and does not dispute it. Invariant 2
rules the week: the pull layer requests no write scopes, ever.

**What this package contributes.** Nothing on the critical path. Week 1 is
[Phase 1 — Pull layer & hour-1 artifact](https://app.clickup.com/t/z8n6b5z4zj):
[Okta ingest](https://app.clickup.com/t/z8n6b5z50b),
[connector-side audit ingest](https://app.clickup.com/t/z8n6b5z50c),
[identity join + attribution report](https://app.clickup.com/t/z8n6b5z50e),
[[B1] tenant onboarding](https://app.clickup.com/t/z8n6b5z8cj) and
[[B2] hour-1 artifact renderer](https://app.clickup.com/t/z8n6b5z8ck) — all
**needs-build**, all in the control plane.

The one optional contribution is depth. If the rep's Claude routine runs in
Claude Code, `hook install` (**shipped**) records every MCP tool call it makes,
hosted connectors included, into a chain that exists before any gateway does.
That is the "capture for depth" leg of the
[thesis reconciliation](https://app.clickup.com/90182720801/docs/2kzmy791-558/2kzmy791-598),
not the "pull for coverage" leg the week is scored on. Qualify it first: the
installed matcher is `mcp__.*`, so a routine that uses only built-in tools
produces an empty store, and Claude Code snapshots hooks at session start, so
a session that began before the install records nothing.

**What the control plane must supply.** All of it. The pull layer exists in
neither repository yet; the nearest existing code in `cresec-ai/nhi` is
`apps/api/src/audit_harvest` (a normaliser for vendor audit events, GitHub
today), `apps/api/src/providers/github/audit.ts` (the puller) and
`apps/api/src/siem`, all undecided for reuse.

### Week 2 — convert one tool

**In the room.** The rep's tool, on the partner's own hosting, made
credential-less: an Okta sign-in gate, identity forwarding, gateway URLs.
Drafts only. Success: attribution on that tool goes from ~0% to >90%; p95
overhead under 50 ms; the rep cannot tell the difference except that it is
cheaper.

**What this package contributes.** The MCP leg of the conversion and the
evidence behind it:

| Capability | Status | The limit, in the same breath |
|---|---|---|
| `record` transparent stdio proxy, fail-open, byte-for-byte | shipped | the gateway's recording path. The byte-for-byte test drives CRLF framing, non-JSON noise and a line past the 32 MiB tap cap in both directions |
| `http` recording proxy for a remote MCP server | shipped | byte-for-byte without `--policy`; one live public server is the whole of the live evidence for the transport |
| `http --policy`: the gateway over the streamable-HTTP transport | in-flight (this branch; tested, not verified live) | the same evaluation, holds, boundary filter, `credentials` swap and events as `record --policy`, over the HTTP exchange (`src/proxy/http.ts`). The one difference: a `tools/call` body and its result are buffered long enough to evaluate and filter them (a JSON body whole, an SSE stream one event at a time) — the gateway-mode exception AGENTS.md allows. Proven against a journaling fake vendor MCP and a fake control plane (S17a, `test/e2e/http-gateway.e2e.test.ts`); S17b, a live vendor remote MCP, has not run. Touches invariants 1 and 3 as the rows below say |
| Gateway mode `record --policy`: allow / hold / deny, tool-result boundary filter | shipped (stdio, verified live); in-flight over HTTP | rules key on (server, tool, args), not (user × tool version); the read / draft / send / write action class is a per-site declaration a remote credential sends to the control plane, not something this engine applies; draft-only is a policy the operator writes today, not a default the engine applies |
| Per-user token injection from the control plane | in-flight (this branch; tested against a fake control plane) | `credentials[].broker: { kind: remote }` wires `RemoteBroker` (`src/broker/wire.ts`) to `POST /v1/broker/user-token` exactly as nhi's `docs/internal/contracts/user-token.md` specifies, keyed by (user, connector, tool, action class, target) from the identity JWT or the policy; the returned access token is swapped at the declared site as a local source's would be, never logged, never recorded; the control plane's `decision_id` lands on the `tool_call` and the `policy_decision`; a 403 is a deny with the control plane's reason, a 5xx / timeout / connection failure is a deny with `control_plane_unavailable` (fail closed, bounded at 5 s). **Invariant 1** is touched, not met by this leg alone: the token is fetched per call and absent from the agent's context, transcript and chain, but the fetching process can read it, so this is the client of credential absence, not credential absence. **Invariant 3**: the decision id is on the record. Nothing here degrades: an unreachable control plane denies (ADR 013), there is no read-only fallback (invariant 8 still unimplemented) |
| Local credential broker + `credentials` policy section + synthetic-for-real swap at declared sites, with result scrub | shipped | the ancestor of Phase 3 token injection, proven live in dogfood 7 ([below](#the-credential-swap-what-dogfood-7-proved-and-what-it-did-not)). On one machine a context and audit control, not a confidentiality one |
| Added latency | shipped, measured 2026-09-17 | 0.792 ms p50 added, stdio, against a local echo fixture, gate < 5 ms (`npm run bench`). Nothing here measures the HTTP transport or a remote hop, which is what the week's p95 < 50 ms criterion is about |
| Actor claim (user, tool, tool-version, host) on every record | in-flight (this branch) | ADR 012's shape, as an additive optional `identity.actor` on every event (`docs/event-schema.md`), decoded from the identity JWT given with `--identity-jwt` (or a policy's `identity_jwt_env`); verified against a JWKS only with `--identity-jwks`, and every event says which (`identity.actor_verified`, beside the claim so `actor` stays the control plane's shape byte for byte; `exp`/`iat` are checked in both modes). **Invariant 3**: the record now carries who acted; the chain and `verify.cjs` are unchanged (they hash whatever is there). What still does not hold: the claim is stamped from a token the operator supplies at start, so one proxy process is one actor and a session with no token is unattributed; nothing here checks the person is still active (that is the control plane's status check) |

The attribution number the week is scored on comes from the control plane's
identity join, not from anything this package counts. `sessions`
(**shipped**) lists one row per recorded session with tool calls, errors,
servers and decisions; it is a census of MCP traffic, not an attribution
report, and the per-server, per-tool form (`sessions --tools`) is
**needs-build**.

**What the control plane must supply.** The identity gate and the per-user
token in OpenBao —
[Phase 2 — Identity gate & propagation](https://app.clickup.com/t/z8n6b5z4zn):
[XAA/OBO brokering](https://app.clickup.com/t/z8n6b5z50f),
[hosted OIDC front](https://app.clickup.com/t/z8n6b5z9fc),
[middleware packages](https://app.clickup.com/t/z8n6b5z50g),
[[C1] per-user OAuth connect flows](https://app.clickup.com/t/z8n6b5z8cm),
all **needs-build** on top of the existing RFC 8693 exchange and JWT issuer,
which are **needs-nhi** — and the HTTPS egress gateway with per-user token
injection and redacted recording
([z8n6b5z50h](https://app.clickup.com/t/z8n6b5z50h), **needs-build** on the
re-targeted data-plane proxy). The
[[A3] walking skeleton](https://app.clickup.com/t/z8n6b5z8ch) is, per the
build brief, a Fastify service — validate the identity JWT, fetch the per-user
token from OpenBao, forward to Salesforce and Gmail, one record per call to
NATS — and whether it replaces the Go proxy or is absorbed into it is
undecided; nhi's ticket table says the same.

### Week 3 — spread

**In the room.** Four more reps run the tool as themselves; send is enabled
for two; the manager view is live; one signed evidence bundle is exported to
security. Success: every action attributed to the right rep and account; no
rep needed the owner's help to start; the bundle verifies independently.

**What this package contributes.** The bundle format and its verifier, and
the policy discipline.

"One signed evidence bundle exported to security" has two parts, and only one
of them is shipped here. The *format and the verifier* are `export` plus the
dependency-free verifier (**shipped**): a ZIP holding `events.jsonl`,
`manifest.json`, `public_key.pem` and a standalone `verify.cjs` that security
runs with bare Node — no install, no account, no network access to us, which
is invariant 3's offline clause. The *contents* are not: the converted tool's
actions are HTTPS calls through the control plane's egress gateway, and
`export` covers only MCP traffic captured by `record` or `hook`. The week-3
bundle of those actions has to come from the control plane's evidence stream
([z8n6b5z50m](https://app.clickup.com/t/z8n6b5z50m), **needs-build**) reusing
this bundle format and `verify.cjs` rather than a second verifier; nhi's
`docs/governed-tools.md` says the same. Where the rep's routine also reaches
a vendor through MCP, `export` holds that leg today. The tool volunteers its own limit,
unprompted: `key check : NOT independently verified - the key came from this
bundle itself… Re-run with --public-key <hex|path> using a key you obtained
out of band`. Lean on that line; it buys more credibility than the `PASS`
does. The bundle carries the actor claim when the recorder was started with
an identity JWT (`identity.actor`, **in-flight** on this branch; without one
the record is honestly unattributed). What it does not carry: a
regulator-mapped export pack (EU AI Act Art. 12; SOC 2 CC6/CC7) — nothing
in `src/` maps the bundle to either, and no page describes such a mapping
([z8n6b5z9ff](https://app.clickup.com/t/z8n6b5z9ff), **needs-build**).

Per-rep policy — Dana may draft, two reps may send — is
[Phase 3's policy engine](https://app.clickup.com/t/z8n6b5z50k): per
(user × tool version), with read / draft / send / write action classes and a
draft-only default (invariant 5). **Needs-build.** What exists today is
per-tool allow / hold / deny in gateway mode and tool-anchored deny rules in
the hook policy (**shipped**), plus two lessons that carry over whichever
engine evaluates the rule:

1. **Anchor deny rules on the tool, never on the server segment.**
   `^mcp__.*__clickup_delete_task$`, not `^mcp__mcp\.clickup\.com__…$`. That
   segment is platform-controlled, varies between sessions and surfaces, and
   on a laptop is never resolved at all. Cloud dogfood 4 is why this is a
   rule: two redundant deny rules matched nothing, both live ClickUp calls
   returned real data, and the only symptom was a zero nobody was watching.
   The 62-event signed bundle holds no policy decision at all.
2. **Smoke-test every rule with the real binary, in the exact observed
   spelling**, by piping a PreToolUse event into `mcp-recorder hook`. The
   thirty seconds where a rule someone wrote from memory prints *nothing* is
   the most useful moment in the meeting. A `policy test --tool <name>`
   command that does this is **needs-build**; today it is a `printf` someone
   has to remember.

The manager view is
[Phase 4's views ticket](https://app.clickup.com/t/z8n6b5z50n) and belongs to
the control plane (**needs-build**). This package has a replay timeline (`ui`,
**shipped**) over one store, and a `DECISIONS` column in `sessions` that
counts both deny shapes — gateway `policy_decision` events and the hook's
denied `pre` call — with the replay page badging both alike
([one deny event shape](https://app.clickup.com/t/z8n6b5z1zr), counting and
badging **in-flight** on this branch; the shapes themselves stay two).
Neither is a manager view, and nobody should show them as one.

**What the control plane must supply.** Per-user OAuth for four more reps
([C1]), the send action class for two of them, the manager view, and the NATS
JetStream record stream
([z8n6b5z50m](https://app.clickup.com/t/z8n6b5z50m), **needs-build**). Where
this package's sink lands — an ingest endpoint in the control plane speaking
the sink's wire contract ([docs/sink.md](sink.md), `receiver/` as the
reference), or two evidence stores kept apart — is undecided, and nhi's page
records it the same way. Today the sink's reference receiver is the
file-backed HTTPS service in `receiver/`, not NATS and not the control
plane's audit tables.

### Week 4 — readout

**In the room.** The before/after number, the bundle, the orphan list, and a
pricing conversation anchored on whichever unit the partner reached for
first: governed tool, governed connector, or governed action.

**What this package contributes.** The bundle format again, now over three
weeks of traffic — the HTTPS actions from the control plane's stream once
[z8n6b5z50m](https://app.clickup.com/t/z8n6b5z50m) lands, the MCP leg from
`export` — and the verification story told the honest way: their auditor, who
has never met us, runs one command on bare Node against a key handed over
through a different channel, and gets `PASS`. Everything else on the readout
— the number ([z8n6b5z9f9](https://app.clickup.com/t/z8n6b5z9f9)), the
orphan list, the pricing instrumentation
([z8n6b5z9fa](https://app.clickup.com/t/z8n6b5z9fa)) — is the control plane's.

### Kill signals

Reps keep going back to the pasted prompt instead of the catalog; the partner
refuses the credential-less swap after seeing their own number; attribution
turns out to be solvable with native Okta/Entra features alone. None of these
is about this package, and nothing in this package can rescue any of them.

---

## The credential swap: what dogfood 7 proved, and what it did not

This package's local broker is the ancestor of Phase 3's per-user token
injection, not the POV's credential story. It still matters, because it is the
only credential swap either repository has run live, and because of what
running it found.

The agent holds a synthetic; the gateway swaps it for the real token at a
declared site, and the real value reaches neither the client nor the evidence
chain. Four end-to-end tests in `test/e2e/credential-swap.e2e.test.ts` run
the real binary and assert on what crossed the wire: the server receives the
real credential while the client and the chain see only the synthetic; a tool
that hands its input back gets the **synthetic**, because an echo is not a
declared site; a declared site aimed at an undeclared host is denied and
nothing is forwarded; and a positive control confirms that a secret nothing
excludes *is* fingerprinted, so the absence assertions cannot pass vacuously.
**Shipped**, merged as PR #20 (`74dce0e`).

**Proven live in dogfood 7** (branch `evidence/dogfood-7`; commit `5d3dace`
on `main` records it): a real Claude Code agent called the tool, the byte
journal shows `Authorization: Bearer df7-real-…` reaching the server, the
chain holds only the synthetic's ref, and a second call to an undeclared tool
carried the synthetic out as written — destination binding doing its job. The
bundle on that branch was not re-opened for this revision of the page.

It took three attempts, and the first two are the reason to tell it. Claude
Code sent the declared argument's parent as a JSON **string** rather than a
nested object, so the dot-path resolved to nothing and the gateway **silently
forwarded the synthetic** — no swap, no deny, no log line. The cause was the
tool's own `inputSchema` leaving the property untyped; typing it fixed it on
the first try, while saying so in the prompt did not. The gateway now refuses
that case (`site_arg_unresolved`) instead of forwarding, and
[docs/policy.md](policy.md) documents the trap. A control that silently does
nothing is the failure mode Governed Tools exists to make impossible —
invariant 1 says enforcement is credential absence, not policy text — and we
found it in our own feature by running it for real.

The honest claim, and say it before any demo rather than after:

> Credential brokering keeps the real credential out of the model's context,
> out of the transcript and out of the evidence chain, and turns every use of
> it into a policy-checked decision recorded under a decision id. It does not
> hide the credential from anything that can run code as the same OS user —
> which includes the agent's own shell.

On a single-uid developer laptop this is a **context and audit** control, not a
confidentiality one. It becomes a confidentiality control only when the
resolver runs as a principal the agent is not — which is exactly why the
control plane holds the token in OpenBao and injects it at the gateway.

---

## Feature map

Keyed to the Roadmap v2 phase each capability serves. Owner is `recorder`
(this repository) or `control plane` (`cresec-ai/nhi`). Phase parents:
[0](https://app.clickup.com/t/z8n6b5z4zf),
[1](https://app.clickup.com/t/z8n6b5z4zj),
[2](https://app.clickup.com/t/z8n6b5z4zn),
[3](https://app.clickup.com/t/z8n6b5z4zr),
[4](https://app.clickup.com/t/z8n6b5z4zv),
[5](https://app.clickup.com/t/z8n6b5z4zx),
[6](https://app.clickup.com/t/z8n6b5z501).

| Feature | Phase | Ticket | Status | Owner |
|---|---|---|---|---|
| Transparent stdio proxy (`record`), fail-open, `MCP_RECORDER_DISABLE=1` kill switch | 3 | [MCP gateway](https://app.clickup.com/t/z8n6b5z50j) | shipped | recorder |
| Gateway allow / hold / deny (`record --policy`), `holds`/`approve`/`deny` | 3 | [MCP gateway](https://app.clickup.com/t/z8n6b5z50j) | shipped (stdio, verified live); in-flight over HTTP (`http --policy`, tested against fakes) | recorder |
| Tool-result boundary filter (secrets rewritten to `[redacted:sha256:…]`) | 3 | [MCP gateway](https://app.clickup.com/t/z8n6b5z50j) | shipped | recorder |
| Tool-result injection markers (**flag, does not block**) | 3 | [MCP gateway](https://app.clickup.com/t/z8n6b5z50j) | shipped | recorder |
| Claude Code hook tap (`hook`), hook policy deny | 3 | [MCP gateway](https://app.clickup.com/t/z8n6b5z50j) | shipped | recorder |
| `hook install` / `--undo` | 3 | [hook install --undo](https://app.clickup.com/t/z8n6b5z30j) | shipped (rough edges) | recorder |
| Hook connector resolution → `server.url` | 3 | — | shipped (cloud sessions only) | recorder |
| `policy validate` + Rego compiler (OPA parity test) | 3 | [Policy engine](https://app.clickup.com/t/z8n6b5z50k) | shipped; egress rules compile and nothing enforces them | recorder |
| Policy per (user × tool version); read / draft / send / write classes; draft-only default | 3 | [Policy engine](https://app.clickup.com/t/z8n6b5z50k) | needs-build | control plane, recorder |
| Deny-rule smoke test as a command (`policy test`) | 3 | — | needs-build | recorder |
| `http` recording proxy for remote MCP servers | 3 | [MCP gateway](https://app.clickup.com/t/z8n6b5z50j) | shipped | recorder |
| `http --policy`: gateway for remote MCP servers, per-user token injection from the control plane | 3 | [MCP gateway](https://app.clickup.com/t/z8n6b5z50j) | in-flight (this branch): `http --policy` and `credentials[].broker: { kind: remote }` → `POST /v1/broker/user-token`, tested against a journaling fake vendor MCP and a fake control plane (S17a); no live vendor remote MCP yet (S17b). Touches invariants 1 and 3 (per-user token fetched per call, decision id on the record); invariant 1 is met only with the control plane's injection | recorder |
| Broker core + 7 credential sources; `credentials` policy section + Rego emitter; gateway synthetic→real swap + result scrub; 4-test e2e suite; live in dogfood 7 | 3 | — | shipped (local broker) | recorder |
| Added-latency bench, stdio (`npm run bench`, gate p50 < 5 ms) | 3 | — | shipped; not the HTTPS p95 < 50 ms measurement | recorder |
| Degrade mode, MCP leg: the MCP gateway falls back to read-only when the control plane is unreachable, replacing the all-or-nothing `MCP_RECORDER_DISABLE` (invariant 8) | 3 | [z8n6b5z9fd](https://app.clickup.com/t/z8n6b5z9fd) | needs-build (the kill switch removes enforcement entirely) | recorder, MCP leg only |
| Degrade mode, HTTPS leg: the customer's tool falls back to read-only when the egress gateway is unreachable (the middleware and proxy half of invariant 8) | 3 | [z8n6b5z50g](https://app.clickup.com/t/z8n6b5z50g), [z8n6b5z50h](https://app.clickup.com/t/z8n6b5z50h), [z8n6b5z9fd](https://app.clickup.com/t/z8n6b5z9fd) | needs-build | control plane |
| HTTPS egress gateway (data-plane proxy re-targeted); [A3] walking skeleton (a Fastify service per the build brief; whether it replaces the Go proxy or is absorbed into it is undecided) | 3 | [HTTPS egress gateway](https://app.clickup.com/t/z8n6b5z50h), [[A3]](https://app.clickup.com/t/z8n6b5z8ch) | needs-build on a needs-nhi base (the Go proxy exists; the JWT validation, per-user fetch, redacted recording and the Fastify skeleton do not) | control plane |
| Identity gate (hosted OIDC, XAA/OBO), middleware packages | 2 | [z8n6b5z50f](https://app.clickup.com/t/z8n6b5z50f), [z8n6b5z9fc](https://app.clickup.com/t/z8n6b5z9fc), [z8n6b5z50g](https://app.clickup.com/t/z8n6b5z50g) | needs-build | control plane |
| [A2] reference tool, both states | 2 | [[A2]](https://app.clickup.com/t/z8n6b5z8cg) | needs-build | undecided (nhi supplies the JWT and gateway URLs) |
| Per-user OAuth in OpenBao keyed by (user, connector) | 2 | [[C1]](https://app.clickup.com/t/z8n6b5z8cm) | needs-build | control plane |
| Hash chain + ed25519 signatures + `verify` | 4 | [Evidence stream + bundles + verifier](https://app.clickup.com/t/z8n6b5z50m) | shipped | recorder |
| Signed bundle (`export`) + dependency-free verifier | 4 | [z8n6b5z50m](https://app.clickup.com/t/z8n6b5z50m) | shipped | recorder |
| Edge redaction (unsalted refs + length; args hashed unconditionally) | 4 | [z8n6b5z50m](https://app.clickup.com/t/z8n6b5z50m) | shipped (invariant 4's no-plaintext clause holds for the MCP leg; there is no whole-request hash field on `tool_call` events) | recorder |
| Blast-radius `query`, `sessions`, replay timeline (`ui`) | 4 | — | shipped | recorder |
| Live evidence sink (`ship`, `MCP_RECORDER_SINK`) + reference receiver; shipper self-check | 4 | [z8n6b5z50m](https://app.clickup.com/t/z8n6b5z50m) | shipped (HTTPS replica, not NATS) | recorder |
| `decision_id` as `cresec.broker.decision_id` on swapped `tool_call` events | 4 | — | shipped | recorder |
| `decision_id` on `policy_decision` events | 4 | — | in-flight (this branch): additive optional field, the local engine's uuid or the control plane's own id; invariant 3 (the decision joins the record) | recorder |
| Actor claims (user, tool, tool-version, host) on every record | 0, 4 | [Actor-claim schema](https://app.clickup.com/t/z8n6b5z507) | in-flight (this branch): ADR 012's shape as `identity.actor`, from `--identity-jwt`; `identity.actor_verified` true only with `--identity-jwks`; invariant 3 | both |
| `DECISIONS` counting both deny shapes; one deny event shape | 4 | [z8n6b5z1zr](https://app.clickup.com/t/z8n6b5z1zr) | in-flight (this branch) for the counting and the replay badges; the two shapes remain (invariant 3's exactly-one-record clause still does not hold: a gateway deny is a `policy_decision` plus a synthetic `tool_call`, a hook call is `pre` + `post`) | recorder |
| `sessions --tools` census | 4 | — | needs-build | recorder |
| `receiver/` in package `files`; HTTP export route for signed replica bundles | 4 | — | in-flight (this branch): `receiver/` (and `src/`, which it imports) ship in the package, `receiver/Dockerfile` builds it, `GET /v1/chains/{chain_id}/export` serves the attested replica bundle to the operator; S18's pinned-enrolment arm is in `test/e2e/ship.e2e.test.ts` | recorder |
| Evidence stream on NATS JetStream; regulator-mapped export pack (Art. 12, SOC 2 CC6/CC7) | 4 | [z8n6b5z50m](https://app.clickup.com/t/z8n6b5z50m), [z8n6b5z9ff](https://app.clickup.com/t/z8n6b5z9ff) | needs-build | both |
| Payload PII/redaction policy decided before the first bundle leaves (invariant 4) | 4 | [z8n6b5z9fg](https://app.clickup.com/t/z8n6b5z9fg) | needs-build (this package's edge-redaction rules and its plaintext hostname/OS-username decision are the starting point) | both |
| Manager view, security view, ownership-decay alerts | 4 | [z8n6b5z50n](https://app.clickup.com/t/z8n6b5z50n) | needs-build | control plane |
| `setup --dry-run` / `--undo` config rewriting | 5 | — | shipped (Tested, not Verified: no real client has launched what it wrote) | recorder |
| Agent guidance for holds (`docs/agent-guidance.md`) | 5 | — | shipped | recorder |
| Scripted prompt-injection demo (`npm run demo`, `--policy`) | 5 | — | shipped (a fixed script, not the [A2] reference tool) | recorder |
| "Publish as governed tool" skill, credential-less templates; routine → team tool split (shared steps vs per-rep settings); tool registry + ownership; conversion runbook; Lovable/v0 and Retool templates | 5 | [z8n6b5z50p](https://app.clickup.com/t/z8n6b5z50p), [z8n6b5z9f4](https://app.clickup.com/t/z8n6b5z9f4), [z8n6b5z9f5](https://app.clickup.com/t/z8n6b5z9f5), [z8n6b5z9f6](https://app.clickup.com/t/z8n6b5z9f6), [z8n6b5z9f7](https://app.clickup.com/t/z8n6b5z9f7) | needs-build | control plane |
| POV runbook and prerequisites checklist; success-metric dashboard; pricing instrumentation; seed deck | 6 | [z8n6b5z9f8](https://app.clickup.com/t/z8n6b5z9f8), [z8n6b5z9f9](https://app.clickup.com/t/z8n6b5z9f9), [z8n6b5z9fa](https://app.clickup.com/t/z8n6b5z9fa), [z8n6b5z9fb](https://app.clickup.com/t/z8n6b5z9fb) | needs-build | control plane |
| npm publication | — | [OSS packaging](https://app.clickup.com/t/86exx6206) | needs-build (`npm view` is E404 on 2026-09-20) | recorder |
| SIEM export; fleet aggregation, retention, pruning, external anchoring | — | — | needs-build, not on Roadmap v2 | recorder |
| Control-plane authentication and tenancy | — | — (no ticket; nhi says it precedes every phase) | needs-build (no authentication hook; every console-facing plugin trusts a caller-supplied `tenant_id`; the two exceptions, `/v1/tokens/exchange` and the Tailscale webhook, authenticate by payload) | control plane |
| Edge daemon, Chrome MV3 extension, Gmail watch, mobile network extensions | 0 | [Retire v1 components](https://app.clickup.com/t/z8n6b5z509) | retiring | control plane |
| This documentation: both repositories re-pointed at the Governed Tools story | 0 | [z8n6b5z9fh](https://app.clickup.com/t/z8n6b5z9fh) | in-flight (this branch) | both |
| Credential swap for Anthropic-hosted connectors | — | — | **aspirational (architecturally impossible)** | — |
| Approvals inbox, Slack approve/deny | — | — | aspirational | — |

---

## What we do not claim

Each line was checked by running the thing, not by reading about it. The
recorder and broker lines were re-checked on 2026-09-20 at `74dce0e`; the
control-plane lines by reading `cresec-ai/nhi` at `1864a59`.

**Install and packaging**
- *"Just run `npx -y @edut/mcp-recorder`."* — `npm view` returns E404. Every
  `npx` line in our docs is a future form until we publish.
- *"Nothing in the first meeting needs network."* — the demo does not; the
  install does (`npm install -g github:cresec-ai/audit#main` reaches GitHub
  and the npm registry, and `demo/agent.ts` shells `npx tsx`). Pre-stage it.
- *"The demo produces exactly 9 events in 5.0 seconds."* — 4.9s to 8.3s, and a
  cold-start retry can double the chain and still report success. Announce what
  is on screen.
- *"1,503 tests."* — true only where OPA is installed, and only at the commit
  it was counted. The Rego parity tests self-skip without the binary, so a
  bare `npm test` reported **1,401** where 1,503 was counted (commit not
  recorded) and **1,643** at `5f59c70`; [docs/roadmap.md](roadmap.md) records
  1317 at `6307cc3`. No count exists for `74dce0e`. CI's Linux job installs
  OPA and sets `MCP_RECORDER_REQUIRE_OPA=1`; the Windows job does not. Quote
  the environment and the commit with the number.

**Evidence**
- *"Nothing is stored in plaintext."* — every payload string is a ref, but
  hostname and OS username are plaintext by design, on proxy and hook events
  alike, and the `approver` on a hold is an OS username too. Frame it as
  attribution — and say in the same breath that it is not per-user identity.
- *"The evidence is tamper-proof."* — tamper-**evident**. Hashes are unsalted by
  design, so a low-entropy secret is recoverable from its ref. On an
  unsegregated machine, an agent that owns the signing key can author the chain.
- *"Your auditor verified the bundle."* — not until they used `--public-key` from
  a channel that is not the bundle. The tool says so itself; lean on that.
- *"If it happened, `query` will find it."* — `query` matches whole values only.
  A miss means "not found this way", not "never happened".
- *"Every record says which person did it."* — no. There is no Okta or OIDC
  code in this package, no user claim in any event, and no tool version
  anywhere in the schema. The identity block carries a fingerprint,
  `os_user`, `hostname`, the MCP client name and version, an operator label
  and credential fingerprints. The actor claim (user, tool, tool-version,
  host) is a [Phase 0 decision](https://app.clickup.com/t/z8n6b5z507), then
  additive optional fields.
- *"The record is Art. 12 / SOC 2 ready."* — the chain and the bundle exist;
  the regulator mapping does not. No export pack, no control mapping.

**Enforcement**
- *"`ui --out` just writes an empty page if you forget `--data-dir`."* — it used
  to render `~/.mcp-recorder` silently. It now names the store on stderr, and
  the page header already carried `store: jsonl · /path/to/evidence.jsonl`, so
  a page handed to someone else does say where it came from.
- *"It stops prompt injection."* — `boundary.injection: flag` is the default and
  does **not** block. What prevents harm is a deny rule on the vector.
- *"`DECISIONS` shows how much we blocked."* — it counts decisions, both the
  gateway's and the hook's, and an approved hold counts as one; it does not
  count calls that were never attempted.
- *"You can gate your remote HTTP MCP servers."* — on this branch, yes, with
  the same policy as stdio; it has been proven against a fake vendor MCP and
  a fake control plane, not against a real vendor (S17b).
- *"Your policy is enforced centrally by OPA."* — `policy compile` emits a bundle
  and nothing consumes it.
- *"Dana can draft but not send."* — not from this package. Rules key on
  (server, tool, args); there is no user in the rule, no tool version, and no
  read / draft / send / write class. Draft-only-by-default is a policy an
  operator writes, not a default the engine applies.
- *"If the gateway is down the tool goes read-only."* — no. `MCP_RECORDER_DISABLE=1`
  turns off recording **and** enforcement together; there is no read-only
  fallback. Invariant 8 is unimplemented here.

**Credentials**
- *"The agent never has access to your credentials."* — it does. It can read the
  environment variable, file or command the broker reads, and the policy that
  names them. What it does not have is a credential in its context or its
  transcript, and it cannot use one without leaving a decision record.
- *"Prompt injection cannot use your credentials."* — it cannot **steal** them,
  given destination-bound swapping. It can absolutely cause an authorised,
  policy-permitted use of one. The gain is that the use is bounded and on the
  record; narrow it with `hold` on high-impact sites.
- *"The real token never leaves the vault."* — true of the hosted control plane,
  false of the local broker, where the token is resolved on the same machine as
  the agent.
- *"The local broker is per-user credential injection."* — it is not. It
  resolves a credential by its id from env, file, exec, GitHub App, AWS STS,
  Vault or ClickUp sources on the agent's own machine. Nothing in it knows
  which person is acting. Per-user injection is the control plane's
  [[C1]](https://app.clickup.com/t/z8n6b5z8cm); the remote broker
  (`credentials[].broker: { kind: remote }`) is its client and asks for that
  person's token per call — it is only as per-user as the identity JWT it
  was started with, and it is not runnable against a real control plane
  until nhi's endpoint exists.
- *"Synthetic credentials are useless if stolen."* — useless off the machine;
  on the machine they are redeemable, and on the machine is where the attacker
  already is.
- *"Least privilege"* / *"scoped credentials"* — only where the policy constrains
  the destination as well as the tool. A `use` site with an unconstrained host
  is a full-privilege credential with extra steps, which is why the schema makes
  it an error rather than a default-allow.
- *"Revocation is instant."* — a cached decision is live for its TTL, and
  revoking does not recall a call already in flight. Quote the number.
- *"We have demonstrated the credential swap."* — against the built binary by
  four end-to-end tests, and live once, in dogfood 7: one tool, one laptop,
  one real Claude Code session. Not against a control plane, and not for a
  named user.
- *"Point it at Cresec and your synthetics keep working."* — a locally-minted
  synthetic cannot resolve against the control plane: the per-tenant pepper
  lives in OpenBao and the HMAC is computed there.
- *"Cresec's control plane is ready."* — verified by reading on 2026-09-20: it
  cannot serve one successful `/broker/exchange` from a clean checkout
  (`unknown_data_plane`, then `unknown_synthetic` because preseed stores a
  literal `fakeHash` where the HMAC belongs, then an unhandled `VaultNotFound`
  — a 500, not a deny — because preseed writes no vault paths;
  `vault_missing_token` fires only when a blob exists without a `token` key),
  `issueSynthetic` has zero call sites, the sole OPA
  deny rule keys on a field `exchange.ts` never sends, `startCronJobs` is
  never called, and there is no authentication hook across its 21 route
  plugins: every console-facing plugin trusts a caller-supplied `tenant_id`,
  and the two exceptions, `/v1/tokens/exchange` and the Tailscale webhook,
  authenticate by payload. `docs/governed-tools.md` in `cresec-ai/nhi`
  carries the same six claims with a verdict each; nhi rates claims 2 and 5
  **partly**, and this page adopts its corrections.
- *"We will swap the credential on your ClickUp or Gmail connector too."* —
  architecturally impossible. Hosted connectors authenticate on Anthropic's
  infrastructure. We can deny those calls; we can never swap their credential.
- *"Here is the revocation demo."* — do not show the control plane's revocation
  screen. It is a client-side animation by its own source comment.

**Positioning**
- *"Install `mcp-recorder` and you have Governed Tools."* — you have the MCP
  gateway and the evidence chain. The identity gate, the per-user vault, the
  HTTPS egress gateway and the views are the control plane, and none of them
  is runnable from a clean checkout today.
- *"This package is on the POV's critical path."* — the POV's tool is an
  HTTPS tool; the HTTPS egress gateway carries it. This package carries the
  MCP route, and the bundle format and verifier the week-3 bundle reuses;
  that bundle's HTTPS contents come from the control plane's stream.
- *"There is a manager view."* — there is a replay page over one store. No
  manager view, no security view, no attribution percentage, no
  ownership-decay alert.
- *"It rolls up across your fleet."* — no fleet view, no aggregation, no
  retention, no pruning, no external anchoring.
- *"`setup` will rewrite your configs safely."* — rated **Tested, not Verified**:
  no real client has ever launched what it wrote. Use `--dry-run` in the room.
- *"The binary says so too."* — not yet. `mcp-recorder --help` still prints
  the old tagline (`src/cli.ts`); `src/` is out of scope for this revision,
  so the installed binary lags this page until the next `src/` change.

---

## The critical path

What this repository must build for Roadmap v2 Phase 3 and Phase 4. Every
item is either a ClickUp ticket or a needs-build item the
[build brief](https://app.clickup.com/90182720801/docs/2kzmy791-558/2kzmy791-638)
names. Every schema change is an additive optional field, because
`edut.mcp-recorder.event.v1` is frozen.

1. **Actor claims on every record** — ADR 012 decided the shape (user, tool,
   tool-version, host, run_as). Landed in the identity block as the optional
   `actor` field, learned from the control plane's identity JWT
   (`--identity-jwt`, `--identity-jwks` to verify it). **In-flight** on this
   branch; invariant 3.
2. **`decision_id` on `policy_decision` events** — the join key already on
   swapped `tool_call` events, made uniform. **In-flight** on this branch.
3. **`http --policy` plus token injection from the control plane** —
   [MCP gateway](https://app.clickup.com/t/z8n6b5z50j): the gateway over the
   streamable-HTTP transport, and `RemoteBroker` wired behind
   `credentials[].broker: { kind: remote }` against nhi's now-decided
   endpoint, `POST /v1/broker/user-token`, keyed by (user, connector, tool,
   action class, target) from the identity JWT. **In-flight** on this
   branch, tested against fakes (S17a); the live vendor run (S17b) and the
   control plane's own endpoint are what remain. Invariants 1 and 3.
4. **Degrade mode, MCP leg** — the MCP gateway goes read-only when the
   control plane is unreachable, in place of the all-or-nothing kill switch
   ([Phase 3](https://app.clickup.com/t/z8n6b5z4zr) deliverable
   [z8n6b5z9fd](https://app.clickup.com/t/z8n6b5z9fd), invariant 8).
   The other half — the customer's HTTPS tool falling back to read-only when
   the egress gateway is unreachable — is the control plane's, in its
   middleware ([z8n6b5z50g](https://app.clickup.com/t/z8n6b5z50g)) and
   gateway ([z8n6b5z50h](https://app.clickup.com/t/z8n6b5z50h)).
   **Needs-build.**
5. **One deny event shape** —
   [z8n6b5z1zr](https://app.clickup.com/t/z8n6b5z1zr): `DECISIONS` counts
   both shapes and the replay page badges them alike — **in-flight** on this
   branch. The shapes themselves stay two: a hook deny has no usable JSON-RPC
   request id, so it is not simply "emit a `policy_decision`", and invariant
   3's exactly-one-record clause still does not hold for either surface.
6. **Export-pack mapping** — the bundle mapped to EU AI Act Art. 12 and
   SOC 2 CC6/CC7 controls
   ([z8n6b5z9ff](https://app.clickup.com/t/z8n6b5z9ff)). Phase 4.
   **Needs-build.**

Also tracked, with tickets, and not on this path: npm publication
([OSS packaging](https://app.clickup.com/t/86exx6206)); `hook install --undo`
byte-exactness ([z8n6b5z30j](https://app.clickup.com/t/z8n6b5z30j)); `query`
exact-match ergonomics ([z8n6b5z30k](https://app.clickup.com/t/z8n6b5z30k));
two recorders on one store ([z8n6b5z30m](https://app.clickup.com/t/z8n6b5z30m));
`ship --drain` ([z8n6b5z30n](https://app.clickup.com/t/z8n6b5z30n)); the
`ui --out` and `injection: flag` rough edges
([z8n6b5z1zx](https://app.clickup.com/t/z8n6b5z1zx)).

The control plane is on the path, not off it. Nothing above produces a
per-user record without the identity gate
([Phase 2](https://app.clickup.com/t/z8n6b5z4zn)) issuing the JWT the gateway
reads, and nothing above injects a per-user token without
[[C1]](https://app.clickup.com/t/z8n6b5z8cm) putting it in OpenBao.

---

## Where to read next

- [`docs/connector-coverage.md`](connector-coverage.md) — what each vantage point can and cannot see, per surface
- [`docs/roadmap.md`](roadmap.md) — the backlog behind this story, keyed to Roadmap v2, with the verification transcripts
- [`docs/gateway.md`](gateway.md) — how enforcement actually behaves
- [`docs/policy.md`](policy.md) — `policy.yaml` v1, the `credentials` section and the swap sites
- [`docs/sink.md`](sink.md) — the evidence sink wire contract and threat model
- [`docs/deployment.md`](deployment.md) — what a customer install looks like per platform
- [`AGENTS.md`](../AGENTS.md) — the invariants that bind this repository, and the rules that must hold
- ClickUp: the [story page](https://app.clickup.com/90182720801/docs/2kzmy791-558/2kzmy791-618), the [build brief](https://app.clickup.com/90182720801/docs/2kzmy791-558/2kzmy791-638), the [thesis reconciliation](https://app.clickup.com/90182720801/docs/2kzmy791-558/2kzmy791-598), and the list [🛠️ MVP — MCP Black Box](https://app.clickup.com/90182720801/v/l/li/901818701787)
