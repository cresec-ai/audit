# Venice (venice.io), and how this project differs

Competitive memo, 2026-09-17. Three questions: what does Venice Security
sell, how do its integrations work, and how long does it take to deploy and
prove — each read against what `@edut/mcp-recorder` does today and what
[docs/roadmap.md](../roadmap.md) says it will do.

**This memo is public, like the rest of this repository.** Every claim about
Venice is quoted from their own material or marked as our reading of it.
Nothing here came from a customer, a call, a trial or a briefing. If anyone
at Venice reads this and something is wrong, open an issue and it gets
corrected in place, the way [docs/connector-coverage.md](../connector-coverage.md)
has been corrected twice.

Evidence tags, used in the same spirit as the connector memo:

- **[vendor]** — Venice's own site or blog, read 2026-09-17. Not
  independently verified.
- **[press]** — third-party coverage of their launch.
- **[ours]** — verified in this repository; the page that verifies it is
  linked.
- **[inferred]** — our reading. It may be wrong, and it is marked so you can
  discount it separately from the sourced claims.

## Not to be confused with

`venice.ai` is a different, unrelated company — a privacy-first LLM provider.
This memo is about **`venice.io` / Venice Security**, an enterprise
privileged-access-management (PAM) vendor. Searches for "venice ai security"
return both.

## Bottom line

- **Same incident, opposite ends.** Venice's answer to "an agent went rogue"
  is *it could not have — it held no standing access*. Ours is *here is the
  signed, replayable record of exactly what it did, and proof nobody edited
  it*. Neither answer substitutes for the other.
- **Their agent enforcement point is an MCP server.** *"To the agent Venice
  looks like just another MCP server; in practice it's the single control
  point in front of every system the agent can touch."* [vendor] That is the
  same architecture [docs/connector-coverage.md](../connector-coverage.md)
  calls option C, and it inherits the same limits that document maps: it sees
  only what is routed through it, and it cannot sit on the
  Anthropic-to-vendor hop.
- **Their Claude integration is an identity read, not a per-call gate.** It
  pulls users, admins, groups and roles from the Claude Compliance API to
  score blast radius and prioritise enrolment. [vendor] The Compliance API
  returns transcripts minutes later and cannot block a call. [ours,
  connector-coverage]
- **Deployment time is unverifiable from outside.** Every number is
  first-party. No G2 or Gartner Peer Insights listing, no named customer case
  study with a timeline, no analyst implementation write-up, no public job
  listings, and the Trust Center is gated behind a request form.
- **They are a funded company with customers; this is a v0.1.0 package that
  is not on npm.** Feature comparison flatters us and stage comparison
  flatters them. Both are true at once.

## What Venice is

| | |
|---|---|
| Category | Privileged Access Management, "adaptive"; Zero Standing Privilege via Just-in-Time access [vendor] |
| Founded / launched | Out of stealth February 2026 [press] |
| Funding | $33M: $8M seed led by Index Ventures, $25M Series A led by IVP with Index, Vine Ventures, Holly Ventures. Angels include Assaf Rappaport (Wiz), Dor Knafo, Gil Azrielant (Axis Security) [press] |
| Founders | Rotem Lurie (CEO, ex-Axis Security head of product), Or Vaknin (CTO, ex-Transmit Security, Flow Security) [press] |
| Customers | "Fortune 500 enterprises" in finance, media, hospitality, manufacturing, healthcare, technology; none named [press] |
| Headline result | "reducing standing privileges by 99%" [press] |
| Compliance | SOC 2 and GDPR claimed on the site; the Trust Center itself is gated [vendor] |
| Identity scope | Human, machine (NHI) and AI agent, under "one risk engine. One audit trail" [vendor] |

Named product surfaces, verbatim: "Runtime Identity Gateway for Agents",
"Unified Access", "Contextual", "Migration", "Accountability", "ZSP dashboard
with AI insights", "Audit Center", "Shared Account Support", "One-Click JIT
Onboarding". [vendor]

## How the integrations work

Three distinct mechanisms. Only the first is the AI-agent story, and the
three are easy to conflate because the marketing does not separate them.

### 1. The agent path — Venice is an MCP server

The load-bearing quote, from
[the Identity Gateway post](https://www.venice.io/blog/tailored-access-gateway):

> To the agent Venice looks like just another MCP server; in practice it's
> the single control point in front of every system the agent can touch.

So the integration is: point the agent at Venice's MCP endpoint instead of at
the real tools. On Claude that means registering it as an organisation custom
connector and having admins block the directory versions — the mechanics are
in [docs/connector-coverage.md](../connector-coverage.md), which identified
this as "the way every MCP gateway product gets into the path" before we knew
Venice had taken it. [ours]

Behaviour once in path, verbatim [vendor]:

- *"Venice sits between every agent and every resource, evaluating every call
  against the declared task."*
- *"Venice evaluates, decides, and intervenes while the call is still
  happening."*
- *"Agents get access for the task and access is revoked the moment the task
  ends."*
- *"Agents are forced to request access keeping them in policy and stopping
  lateral movement."*
- *"Venice records every request, access grant, and session action and ties
  them to named identities."*

What their material does not state: which protocols beyond MCP are covered,
how traffic is routed to the gateway, how the "declared task" is captured or
who supplies it, how an agent identity is bound to a session, or what happens
to a call to a tool that is not fronted. We asked those questions of the
pages and they are not answered anywhere public.

**[inferred]** Three consequences follow from the architecture regardless of
what the marketing says, because they follow for *any* MCP gateway, ours
included:

1. Coverage equals routing. A tool the agent can reach without traversing the
   gateway is ungoverned, and nothing in the gateway can know it happened.
2. On claude.ai web chat, Claude Desktop chat and Cowork, the connector call
   is made from Anthropic's infrastructure with tokens in Anthropic's vault.
   Fronting a *vendor* MCP endpoint reaches those surfaces; fronting nothing
   does not. The GitHub connector in Claude Code cloud sessions is served from
   an Anthropic path and cannot be fronted at all. [ours, connector-coverage]
3. A "declared task" check is a check on the *request*. An injected
   instruction that arrives inside a correctly scoped, correctly authorised
   read is still correctly scoped and correctly authorised.

### 2. The Claude path — Compliance API identity sync

From [the Claude Compliance API post](https://www.venice.io/blog/claude-compliance-api),
Venice pulls:

> every Claude Enterprise user, admin, group, and role across Claude chat,
> Cowork, and Claude Code, and connects each one to the identity it already
> governs across your identity providers, cloud platforms, and data stores

That feeds blast-radius scoring — *"scores the real reachable damage if that
user's Claude were compromised"* — which ranks who to enrol first. Claude
Enterprise organisations only. [vendor]

This is an identity-graph read. It is not a per-call control, and the
Compliance API cannot block: it returns transcripts minutes after the fact.
[ours, connector-coverage] The enforcement in their Claude story comes from
the MCP gateway in §1 and from the JIT elevation in §3, not from this feed.

### 3. The estate path — discovery, then JIT elevation on the target

Discovery: *"Venice scans existing vaults, shared accounts, and standing
permissions across cloud and on-prem environments."* [vendor]

Elevation, from the Identity Gateway post — this is the sentence that says
what "agentless" actually means:

> provisions the access, elevating the specific short-lived access the task
> needs on the target system itself and rolling it back the moment the work
> is done

**[inferred]** "On the target system itself", with no vault and no host
agent, means Venice calls each target's own administrative interface — IdP
group membership, cloud IAM role, database grant, local account. That is a
credential-mutating integration, which is why it is agentless and also why it
is privileged.

Migration from a legacy PAM runs in three stated steps: discovery,
translation of legacy permissions into JIT policy, and transition support
that rotates credentials and monitors usage while both systems are live.
*"no hard cutover, no freeze window, no regression risk."* [vendor]

No integration is named anywhere on the public site. No Okta, no Entra, no
AWS, no Kubernetes, no SSH or RDP, no API documentation, no architecture
diagram.

## How long it takes to deploy, and how you would know

### What they claim

| Claim | Where |
|---|---|
| "It takes minutes to add a server, database, or cloud resource to Venice" | [Just-in-Time Access](https://www.venice.io/solutions/just-in-time-access) |
| "Venice runs step by step, environment by environment to reach a company-wide deployment in weeks" | [Replace Your Legacy PAM](https://www.venice.io/solutions/replace-your-legacy-pam) |
| "no agents, proxies, or heavy deployment work" | [Index Ventures](https://www.indexventures.com/perspectives/venice-security-emerges-from-stealth-with-33m-in-funding-to-redefine-enterprise-privileged-access-management-in-the-ai-era/) |
| "no hard cutover, no freeze window, no regression risk" | Replace Your Legacy PAM |
| "onboarding takes minutes", "standing privileges gone", CyberArk replaced on SOX servers | unnamed electronics-company testimonial, homepage |

### What is not available

Checked 2026-09-17: no G2 listing, no Gartner Peer Insights entry, no named
customer case study carrying a timeline, no analyst or practitioner write-up
with implementation detail, no public job listings (the
[careers](https://www.venice.io/careers) page renders no roles), and
[trust.venice.io](https://trust.venice.io/) shows "Loading trust data…" with
certifications, subprocessors, controls and architecture behind a request
form. The [SiliconANGLE launch piece](https://siliconangle.com/2026/02/19/venice-security-launches-33m-bring-access-management-enterprise/)
contains no architecture at all.

So the honest answer to "how long does it take": **from outside, you cannot
know.** Every figure is first-party and currently unfalsifiable. Note the
symmetry with our own position — this repository's response to the same
problem is [docs/features.md](../features.md), where each capability states
the command that proves it and the limit in the same breath. That is the
comparison we would rather be judged on than a feature grid.

### The structural estimate [inferred]

More useful than their number, because it follows from §3 rather than from
marketing. If JIT is delivered by mutating entitlements on the target, then
before the first "minutes" of onboarding, a customer has granted a third
party the right to change IdP group membership, cloud IAM and database grants
across the estate. In any Fortune 500 that is a security review, a privileged
integration approval and a change-advisory board. "Minutes" is plausible for
the per-resource step and says nothing about time to the first protected
resource.

For the agent gateway specifically, deployment time is the time to
re-register every connector organisation-wide and block the directory
versions — an org-admin task per connector, per surface, which also breaks
any agent reaching a tool that has not been fronted yet.

Neither of these is a criticism of Venice. They are what the architecture
costs, and the same costs would apply to us if we shipped
[v2 · P2 — Tier 2 Hosted Gateway](https://app.clickup.com/t/z8n6b5yt94).

## Where this project and Venice actually differ

| | `@edut/mcp-recorder` | Venice |
|---|---|---|
| Primary artifact | Tamper-**evident** evidence chain | Access **decision** (grant / revoke) |
| Enforcement point | MCP JSON-RPC boundary (stdio proxy) and the Claude Code `PreToolUse` hook | An MCP server in front of the tools, plus elevation on the target itself |
| Identity model | None. Session, server, tool, hashes | Identity-first; human, machine and agent on one risk engine and one audit trail |
| Credentials | Never touched | Core: JIT minting, shared accounts, revoke on task end |
| Deployment | Local-first, zero cloud, zero telemetry, GPL-3.0 | Agentless SaaS control plane |
| Non-identity surfaces (a stdio server someone `npx`'d this morning) | Covered | Out of scope — needs a target with an identity plane |
| claude.ai web / Desktop chat / Cowork | **Not covered** — documented gap | Identity visibility via Compliance API, minutes late; enforcement only for tools routed through their gateway |
| Tool results on the way back | Boundary filter: secret redaction, injection markers flagged or blocked | Not addressed; a declared-task check is request-side |
| Evidence portability | Signed bundle, dependency-free verifier, verifiable with no vendor in the loop | "Audit Center" inside their tenant |
| Stage | v0.1.0, not on npm, no design partners yet | Funded, Fortune 500 customers, SOC 2 claimed |

## What each does that the other cannot, today

**Only this project:** byte-for-byte recording of a local stdio MCP server at
~0.79 ms p50 added latency; a portable signed bundle a stranger verifies with
bare Node and no dependencies; denying one specific tool call inside Claude
Code including Anthropic-hosted connectors, which
[docs/connector-coverage.md](../connector-coverage.md) argues is the only
third-party pre-execution vantage point that exists there; running in sixty
seconds with nothing leaving the machine; being read line by line under
GPL-3.0, which matters for something sitting in a trust path.

**Only Venice:** removing standing privilege at all; brokering, rotating and
time-boxing credentials; an organisation-wide posture view a CISO can act on;
multi-tenancy, SOC 2, and a vendor to sign a contract with.

The sharpest asymmetry is prompt injection, in both directions. Zero Standing
Privilege does not see an injected instruction inside an authorised call —
our boundary filter is aimed exactly there. But our own default is
`injection: flag`, which **does not block** ([docs/features.md](../features.md),
tracked as [Two rough edges dogfood 5 hit](https://app.clickup.com/t/z8n6b5z1zx)),
so today that advantage is partly theoretical.

## Where the roadmaps collide

Today the overlap is small. It stops being small at v2:
[P1 — Tier 1 Sidecar: secrets brokering + egress](https://app.clickup.com/t/z8n6b5yt93)
is synthetic placeholder credentials swapped at a forward proxy with
credential helpers;
[P3 — Approval gates + evidence](https://app.clickup.com/t/z8n6b5yt95) is
Slack approvals with one-shot tokens bound to a request digest;
[P2 — Tier 2 Hosted Gateway](https://app.clickup.com/t/z8n6b5yt94) is a
multi-tenant hosted gateway. That is Venice's floor plan.

The archived `[v1]` ClickUp folder shows this team built much of that
machinery once already — synthetic-to-real credential mapping, RFC 8693 token
exchange, short-TTL token minting, soft and hard revoke, shadow-NHI
detection, risk scoring — and archived it to become the flight recorder.
Walking back into that space means competing on their strongest ground with
an eighteen-month, $33M head start against us.

## Questions to ask them

Useful in a bake-off, and equally useful turned around on ourselves. The
first four have no good answer for any MCP gateway, this project included.

1. When an agent calls a tool that is not fronted by your gateway, what
   happens — and how would the customer find out that it happened?
2. How is enforcement delivered on claude.ai web chat, Claude Desktop chat
   and Cowork? Our reading of those surfaces is in
   [docs/connector-coverage.md](../connector-coverage.md); if the answer is
   "we cover them", ask by which mechanism.
3. Who supplies the "declared task"? If the agent declares it, what prevents
   a prompt-injected agent from declaring a broader one?
4. An injected instruction arrives inside a correctly scoped, correctly
   authorised read. Which control sees it?
5. What does the audit record look like *outside* your tenant? Can a third
   party verify it without trusting you, and what exactly does the signature
   prove?
6. What write permissions are required in our IdP, cloud IAM and target
   systems on day one, and what is the blast radius of the integration
   itself?
7. Time from contract to first protected resource, at our size, from a
   reference customer rather than from you.

Venice's own buyer checklist, for symmetry [vendor]:

> Do not ask which slice of this moment it covers, because the moment will
> move. Ask whether it lives in the access layer, whether it can remove
> standing access instead of just watching it, and whether it will still be
> doing its job two waves of AI from now.

Worth answering honestly rather than deflecting: by that test this project is
not in the access layer and does not remove standing access. It is also worth
noting that
[their critique of the category](https://www.venice.io/blog/most-ai-agent-security-solutions-wont-hold-heres-why)
dismisses "gateways inspecting individual tool calls" as watch-only, while
their own agent product is a gateway inspecting individual tool calls. That
tension is theirs to resolve, not evidence of bad faith.

## What we could not find out

Listed because it is load-bearing and unanswered, in the style of
[docs/roadmap.md](../roadmap.md#what-do-we-still-not-know).

- **Which systems they actually integrate with.** No integration is named
  publicly. Unknown whether that is early-stage coverage or deliberate
  opacity.
- **Whether the MCP gateway is their only agent enforcement path**, or
  whether network-level or target-level interception also exists.
- **What the Trust Center contains** — subprocessors, hosting, data flows,
  SOC 2 report type. Gated.
- **Real deployment timelines.** No third-party data point exists.
- **Whether they are hiring forward-deployed or professional-services
  engineers**, which would be the strongest public signal that deployment is
  heavy regardless of the agentless claim. Their careers page lists nothing;
  LinkedIn was not checked.
- **Anything hands-on.** Nobody here has seen a demo or a trial.

## Sources

Venice, read 2026-09-17: [homepage](https://www.venice.io/),
[Secure AI Agents](https://www.venice.io/secure-ai-agents),
[Zero Standing Privileges](https://www.venice.io/solutions/privilage-visability),
[Just-in-Time Access](https://www.venice.io/solutions/just-in-time-access),
[Replace Your Legacy PAM](https://www.venice.io/solutions/replace-your-legacy-pam),
[blog index](https://www.venice.io/blog),
[A Suit for Every Identity](https://www.venice.io/blog/tailored-access-gateway),
[Venice integrates with the Claude Compliance API](https://www.venice.io/blog/claude-compliance-api),
[Here's Why most AI Agent Security Solutions Won't Hold](https://www.venice.io/blog/most-ai-agent-security-solutions-wont-hold-heres-why),
[careers](https://www.venice.io/careers),
[Trust Center](https://trust.venice.io/) (gated).

Press: [Index Ventures launch post](https://www.indexventures.com/perspectives/venice-security-emerges-from-stealth-with-33m-in-funding-to-redefine-enterprise-privileged-access-management-in-the-ai-era/),
[SiliconANGLE](https://siliconangle.com/2026/02/19/venice-security-launches-33m-bring-access-management-enterprise/),
[TipRanks](https://www.tipranks.com/news/private-companies/venice-positions-identity-as-ai-control-layer-in-enterprise-security),
[NHI Mgmt Group forum on the Claude integration](https://nhimg.org/community/nhi-product-announcements-forum/claude-enterprise-identities-are-your-access-controls-keeping-up/).

Ours: [docs/connector-coverage.md](../connector-coverage.md) for what each
vantage point can see and control per Claude surface,
[docs/features.md](../features.md) for what is verified and what the limit is,
[docs/roadmap.md](../roadmap.md) for the v2 phases, and the ClickUp list
[🛠️ MVP — MCP Black Box](https://app.clickup.com/90182720801/v/l/li/901818701787).
