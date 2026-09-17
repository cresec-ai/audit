# Local dogfood 6 — prompt

Copy everything below the line into a local Claude Code session, running in your
`audit` checkout.

Context for you, not for the agent: `main` is at `6dc4399` and does **not**
carry the evidence sink — that lives on the unmerged branch
`feat/evidence-sink` (`1d8fe99`), which is why Part 4 switches branches
explicitly instead of quietly testing a tree without it.

---

You are running the **local leg of cloud dogfood 6** for `@edut/mcp-recorder`,
on my own machine (WSL). Do NOT ask me clarifying questions — if something is
ambiguous, pick the most reasonable option, write down what you chose and why,
and carry on. **A negative result is a good outcome. Do not try to make
anything pass.** Every claim in your report must come from a command you
actually ran, with its real output pasted. If you cannot run something, say so
rather than describing what it would have done.

**Why this run exists.** Everything we know about this tool in a real agent
session comes from Anthropic *cloud* sessions. We have never once run it in a
local Claude Code session. Two things can only be learned here: how a local
session names and configures its MCP servers, and whether anything about WSL
breaks the recorder.

## Part 0 — start clean, and record the ground truth first

```sh
cd <your audit checkout>
git stash list && git status --short      # note anything dirty BEFORE you touch it
git fetch origin && git checkout main && git pull origin main
git log --oneline -5
node --version && npm --version
sh scripts/bootstrap.sh
npm run typecheck && npx eslint . && npm test
```

Report the test counts. If anything fails on a clean `main` on this machine but
passes in CI, **that is a finding in itself** — WSL has bitten this project
before (native `.cmd` spawning, path translation between Windows and Linux
filesystems).

## Part 1 — the naming-convention datum

This is the single most valuable thing this run can produce.

`mcp-recorder hook` resolves a connector by looking the server segment of
`mcp__<server>__<tool>` up as a **key** in the session's MCP config, falling
back to the entry whose `tools[]` **declares that exact tool**. Across three
cloud dogfoods those two conventions have disagreed once and agreed twice — and
we have **no data at all** from a local session.

Report, without printing any headers, tokens or secrets:

- Does `/tmp/mcp-config-*.json` even exist locally? If not, **where does your
  Claude Code keep MCP server config** — `~/.claude.json`, a project
  `.mcp.json`, something else? Print its **keys only**.
- The actual tool names you see for any connectors: `mcp__ClickUp__…`,
  `mcp__<uuid>__…`, `mcp__github__…`?
- **State plainly whether the config key equals the tool-name segment on this
  machine.**

If you have no hosted connectors locally, say so — that is itself worth
knowing — and skip to Part 3.

## Part 2 — does a hook deny work locally?

Create `/tmp/df6-local-policy.json`:

```json
{
  "deny": [
    { "tool": "^mcp__.*__clickup_filter_tasks$", "reason": "df6-local: tool-anchored deny" }
  ],
  "default": "allow"
}
```

Install the hook against a scratch data dir (check `node dist/cli.js hook
install --help` for the real flags; roughly `--data-dir /tmp/df6-local
--policy /tmp/df6-local-policy.json`), then **start a NEW session** — hooks are
captured at session start, so an already-open session will not pick this up —
and try the denied tool for real, twice.

Report: blocked, or executed and returned real data? Then run `sessions`,
`verify` and `query` against `/tmp/df6-local` and paste the output.

## Part 3 — gateway mode locally

Wrap the repo's own demo server with
`record --policy docs/examples/policy.demo.yaml` and drive it. Confirm
`http_post` is denied with a readable refusal, and that an allowed call is
forwarded byte-for-byte. Quote the exact refusal text.

## Part 4 — the live sink (needs a different branch)

The sink is **not on main**:

```sh
git checkout feat/evidence-sink && sh scripts/bootstrap.sh && npm run compile
MCPR_RECEIVER_TOKEN=local-ingest npm run receiver -- serve --data-dir /tmp/df6-rx --port 8787 &
```

**Confirm the startup line says `ingest auth  1 token(s)`.** If it says `0`, or
the port was already in use, you are talking to the wrong process and
everything after this point is meaningless. (I made exactly this mistake: a
health check returned 200 and I read it as success, while the real receiver had
failed to start with `EADDRINUSE` and I was querying a stale tokenless one.)

Then record a session with:

```sh
MCP_RECORDER_SINK=http://127.0.0.1:8787 \
MCP_RECORDER_SINK_TOKEN=local-ingest \
NO_PROXY=127.0.0.1 \
node dist/cli.js record --data-dir /tmp/df6-sink -- <some stdio MCP server>
```

Afterwards ask the **receiver** what it holds rather than trusting the
recorder's own output:

```sh
curl -sS --noproxy 127.0.0.1 \
  -H "Authorization: Bearer $(cat /tmp/df6-rx/operator-token.txt)" \
  http://127.0.0.1:8787/v1/chains
```

Report `records_held`, `attested_seq`, `chain_id_verified`, and whether
`claimed_head_hash` equals `head_hash` — a claimed head ahead of the stored one
means records are being withheld.

**Then the tamper test.** Copy the data dir, alter one field of a mid-chain
event while leaving the hashes untouched, and try to ship the copy. Report
exactly what happens — both what `verify` says and what the shipper does.

## Part 5 — write it up

Create `evidence/local-dogfood-6/REPORT.md` in the style of
`evidence/cloud-dogfood-5/REPORT.md` (read it first; it is on branch
`evidence/cloud-dogfood-5`). It must contain:

- the Part 1 convention table
- any WSL-specific problems, with the exact error
- what worked and what did not, per part
- a blunt **"surprises / things that look wrong"** section

Describe the shape of any personal data and omit its content.

Commit on a new branch `evidence/local-dogfood-6` and push it. **Do not merge.
Do not modify tracked files outside `evidence/`.**

Finally: `git checkout main`, and restore anything Part 0 found dirty.
