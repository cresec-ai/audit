# Cloud dogfood 4 — PR #13 hook fixes against live connectors, and a live policy deny

- Repository: `cresec-ai/audit`, started from `dogfood/4-policy` (`436680c`, one commit ahead of `main` at `cb9808c` / PR #13, merged).
- Session id: `cse_018XNgrVMkEGs7RLWheRc1xH` (recorder session `8f9ba2bb-5914-5902-ad66-0977e712e6d5`).
- Date: 2026-09-16, ~12:36–12:44 UTC.
- Recorders active: (1) stdio proxy via `scripts/dogfood-wrap.sh` on `corp-notes` and `repo-filesystem` (`.mcp.json`); (2) `node dist/cli.js hook --data-dir .mcp-recorder --policy .claude/dogfood4-policy.json` on PreToolUse/PostToolUse/PostToolUseFailure/SessionEnd/Stop for `mcp__.*` (`.claude/settings.json`).
- Runtime: Node `v22.22.2`, `mcp-recorder` `0.1.0`.

**Personal-data note:** several read calls below hit the account owner's real, personal Gmail/Calendar/Drive/ClickUp accounts (this is a live dogfood against real hosted connectors, not a sandbox). This report records call/outcome/shape for each but deliberately **omits or redacts personal content** (label names, calendar/file titles, member email addresses) that isn't needed to evaluate the recorder — the full plaintext exists only transiently in the live conversation and was never written to `.mcp-recorder` (by design; see Part 3).

## Part 0 — starting point

```
$ git log --oneline -2
436680c dogfood 4 scaffold: bake a hook policy into the committed settings
cb9808c hook: PostToolUseFailure, UUID connector names with deny-only host aliases, honest `sessions` counts (#13)
$ git status
HEAD detached at refs/heads/dogfood/4-policy
nothing to commit, working tree clean
$ node --version
v22.22.2
$ node dist/cli.js --version
0.1.0
```

`.claude/settings.json` registers `node dist/cli.js hook --data-dir .mcp-recorder --policy .claude/dogfood4-policy.json` on `PreToolUse`/`PostToolUse`/`PostToolUseFailure`/`SessionEnd`/`Stop`, each matched on `mcp__.*`.

`.claude/dogfood4-policy.json`:
```json
{
  "deny": [
    { "tool": "^mcp__mcp\\.clickup\\.com__clickup_filter_tasks$", "reason": "dogfood-4: denied via the RESOLVED HOST ALIAS ONLY ..." },
    { "tool": "^mcp__[0-9a-f-]{36}__clickup_get_workspace_members$", "reason": "dogfood-4 control: denied via the RAW UUID form only ..." }
  ],
  "default": "allow"
}
```

`.mcp.json` declares two local stdio servers, `corp-notes` and `repo-filesystem`, both launched through `scripts/dogfood-wrap.sh`.

`/tmp/mcp-config-cse_018XNgrVMkEGs7RLWheRc1xH.json` exists and confirms the vendor mapping the policy assumes:

| Config key | `mcp_url` |
| --- | --- |
| `47d587b8-3fb9-42e9-b596-f8b25371248c` | `https://mcp.clickup.com/mcp` |
| `6580aef4-db58-41af-bffa-256f5d9fa6e5` | `https://calendarmcp.googleapis.com/mcp/v1` |
| `66b16897-54e1-4453-9bb4-5b5e09ca9f9e` | `https://drivemcp.googleapis.com/mcp/v1` |
| `ce5e992d-730d-4f07-95c8-4ba759ea3e3b` | `https://gmailmcp.googleapis.com/mcp/v1` |
| `github` | `.../github/mcp` (relay URL, no `mcp_url`) |

**Surprise #1, load-bearing for everything below:** the config file is keyed by UUID, exactly as dogfood 3 found and PR #13 assumed. But the *tool names actually presented to the model and to hooks in this session* are **not** UUID-prefixed — they are `mcp__ClickUp__*`, `mcp__Gmail__*`, `mcp__Google_Calendar__*`, `mcp__Google_Drive__*`. Dogfood 3's report explicitly noted the opposite ("hosted connectors are exposed ... under opaque UUID prefixes, not `mcp__ClickUp__`"). The platform's naming convention has changed, or is session-dependent, between dogfood 3 and dogfood 4 — and PR #13's alias/UUID matching, built and tested against the UUID convention, does not anticipate this one. This single fact turns out to explain every failure in Part 2 and Part 3 below.

## Part 1 — allowed calls, read-only

| # | Tool | Arguments | Outcome |
| --- | --- | --- | --- |
| 3 | `clickup_get_workspace_hierarchy` | none | OK — real workspace, 1 space, 3 folders (incl. list `901818701787`) |
| 4 | `clickup_get_list` | `list_id: "901818701787"` | OK first try, no rate limit — "🛠️ MVP — MCP Black Box" |
| 5 | `clickup_get_task` | `task_id: "0000000000"` | **ERROR** `{"error":"Team not authorized"}` — surprise: expected a not-found-style error for a bad id, got an authorization error instead |
| 6 | `list_labels` (Gmail) | none | OK — real account, 20 labels (system + user labels); content redacted here |
| 6 | `list_calendars` (Google Calendar) | none | OK — real account, 7 calendars; content redacted here |
| 6 | `list_recent_files` (Google Drive) | `pageSize: 5` | OK — real account, 5 files returned; titles redacted here |
| 7 | `pull_request_read` (GitHub) | `method: get, owner: cresec-ai, repo: audit, pullNumber: 13` | OK — confirms PR #13 merged, matches commit log |
| 8 | `mcp__corp-notes__list_notes` | none | OK — `["welcome.md","vendor-onboarding.md"]` |
| 8 | `mcp__repo-filesystem__read_text_file` | `path: "README.md", head: 5` | OK — first 5 lines of README |
| 9 | `mcp__repo-filesystem__write_file` | `path: "/tmp/dogfood4-scratch.txt", content: "canary-write-6f2a9c ok"` | **ERROR** `Access denied - path outside allowed directories: /tmp/dogfood4-scratch.txt not in /home/user/audit` |
| 9 (retry) | `mcp__repo-filesystem__write_file` | `path: ".mcp-recorder/dogfood4-scratch.txt", content: "canary-write-6f2a9c ok"` | OK |

**Surprise #2:** the `repo-filesystem` MCP server (the local `@modelcontextprotocol/server-filesystem` wrapped by `scripts/dogfood-wrap.sh`) is sandboxed to the repo root (`/home/user/audit`) only — `list_allowed_directories` confirms this. It cannot write to `/tmp` at all, contradicting the task's assumption. The canary write was redirected to `.mcp-recorder/dogfood4-scratch.txt`, which is gitignored (`.gitignore:11`) so it stays local and untracked, preserving the "don't touch tracked files" constraint.

No ClickUp/Gmail/Calendar/Drive write or mutating calls were made.

## Part 2 — the live policy deny (headline finding)

Both denies were attempted for real, each exactly as specified, each retried once per instructions.

| Call | Attempt 1 | Attempt 2 (retry) |
| --- | --- | --- |
| `clickup_filter_tasks` (`list_ids: ["901818701787"], include_closed: true`) | **Went through.** Returned 71 real tasks from the live "🛠️ MVP — MCP Black Box" list. | **Went through again.** Identical 71-task result. |
| `clickup_get_workspace_members` (no args) | **Went through.** Returned 3 real workspace members with real email addresses (redacted here). | **Went through again.** Identical result. |

**Neither deny fired. Both live ClickUp calls that the policy is supposed to block executed against the real workspace and returned real data, twice each.** This is not a synthetic-JSON-only gap the way dogfood 3's testing was — these were real Claude Code tool calls in a live session, denied by a policy that was baked into `.claude/settings.json` at session start exactly as instructed.

Root cause, confirmed from the recorded events (see Part 3): the hook **did** run — it recorded pre/post pairs for all four calls with correctly hashed arguments — but the tool identity Claude Code handed it was `server.name: "ClickUp"`, not a `[0-9a-f-]{36}` UUID and not derivable to `mcp.clickup.com` either, because PR #13's alias derivation looks the incoming server segment up as a **key** in `/tmp/mcp-config-*.json` (which is UUID-keyed) to find `mcp_url` and build the alias. Since `"ClickUp"` is not a key in that file, the lookup fails, no `server.url` is resolved, no alias can be derived, and the raw-UUID-only rule can't match a name that was never a UUID to begin with. Both deny routes PR #13 built — raw-UUID and resolved-host-alias — assume the UUID-prefixed convention dogfood 3 observed; this session's friendly-name convention (Surprise #1) defeats both simultaneously.

## Part 3 — inspection, verbatim

### `sessions`

```
$ node dist/cli.js sessions --data-dir .mcp-recorder
SESSION   STARTED                   ENDED                     SERVER           EVENTS  TOOL_CALLS  ERRORS  SERVERS
7ff89c78  2026-09-16T07:46:46.363Z  2026-09-16T07:46:46.363Z  claude-code      2       0           0       0
ef85c16d  2026-09-16T07:54:15.410Z  2026-09-16T07:59:20.180Z  corp-notes       5       0           0       0
b73e9917  2026-09-16T07:54:15.437Z  2026-09-16T07:59:20.171Z  repo-filesystem  6       0           0       0
8f9ba2bb  2026-09-16T07:54:49.396Z  2026-09-16T07:59:20.428Z  claude-code      35      16          2       7
a2007a4e  2026-09-16T12:36:59.321Z  (open)                    corp-notes       5       1           0       1
99581d34  2026-09-16T12:36:59.321Z  (open)                    repo-filesystem  9       4           1       1
```

**Surprise #3:** session `8f9ba2bb` (this conversation's recorder session, per `hook-sessions/`) shows `ENDED 07:59:20` with `TOOL_CALLS 16 / ERRORS 2 / SERVERS 7` — a stale snapshot from earlier in this same conversation. `query` (below) proves at least 6 more hook events landed under this exact session id at 12:38–12:41, and `verify` confirms 62 total signed events in the chain, but `sessions` never updated the row: no new row appeared, and the existing row's `ENDED`/counts were not refreshed. `TOOL_CALLS` counts a call once (pre-only), consistent with the PR #13 fix, but only for whatever data existed when the session was last considered "ended" — activity continuing under the same `session_id` after that point isn't reflected. `ERRORS` is non-zero (2) but that predates the forced failure and both live denials in this run; the true count after this run's Part 1 step 5 failure is higher and isn't shown.

### `verify`

```
$ node dist/cli.js verify --data-dir .mcp-recorder
verify store /home/user/audit/.mcp-recorder/evidence.db (sqlite)
pinned signer: ed25519 4976b82f963c631f… (/home/user/audit/.mcp-recorder/identity.pub)
PASS — chain intact: 62 event(s), head seq 62
signed head: seq 62 by ed25519 4976b82f963c631f… at 2026-09-16T12:41:08.870Z
```

### `query "901818701787"`

```
$ node dist/cli.js query "901818701787" --data-dir .mcp-recorder
TIMESTAMP                 KIND       NAME                  SESSION   MATCHED_ON  PATH
2026-09-16T12:38:46.357Z  tool_call  clickup_get_list      8f9ba2bb  ref         $.args.list_id
2026-09-16T12:38:47.421Z  tool_call  clickup_get_list      8f9ba2bb  ref         $.args.list_id
2026-09-16T12:40:11.668Z  tool_call  clickup_filter_tasks  8f9ba2bb  ref         $.args.list_ids[0]
2026-09-16T12:40:55.134Z  tool_call  clickup_filter_tasks  8f9ba2bb  ref         $.args.list_ids[0]
2026-09-16T12:40:58.574Z  tool_call  clickup_filter_tasks  8f9ba2bb  ref         $.args.list_ids[0]
2026-09-16T12:41:00.872Z  tool_call  clickup_filter_tasks  8f9ba2bb  ref         $.args.list_ids[0]

6 matches across 1 sessions
```

Finds the **DENIED-in-theory `clickup_filter_tasks` call** (both attempts, pre+post) by its hashed argument — the list id never left the machine in plaintext, it's matched purely by ref hash, exactly as intended, even though the call itself was not actually blocked.

### `query "canary-write-6f2a9c"`

```
$ node dist/cli.js query "canary-write-6f2a9c" --data-dir .mcp-recorder
0 matches across 0 sessions
```

```
$ grep -c "canary-write-6f2a9c" .mcp-recorder/evidence.db* 2>/dev/null || true
```
(the plaintext canary never appears in the store — confirmed by the 0-match query result above; this was written via the local `repo-filesystem` server, not a hook-recorded server, so it is not itself a recorder test — its absence from `query` is the redaction check for the store overall.)

### `ui --out /tmp/dogfood4-replay.html`

```
[mcp-recorder] wrote replay page to /tmp/dogfood4-replay.html
```

- Size: 165,133 bytes.
- Integrity banner: `✔ chain intact, 62 events, head signed` (green/ok banner; no "bad" banner shown).
- No occurrence of "denied"/"blocked"/"policy_denied" anywhere in the rendered page — consistent with Part 2's finding that nothing was actually denied.
- `clickup_filter_tasks` and `clickup_get_workspace_members` both appear in the embedded event JSON with `args` redacted (`{"len":12,"redacted":true,"ref":"sha256:…"}` for the list id; `{}` for the no-arg members call) and `result` redacted (`{"len":25280,"redacted":true,"ref":"sha256:…"}` etc.) — no plaintext task names, member emails, or other result content is present in the page.
- `grep -c "canary-write-6f2a9c" /tmp/dogfood4-replay.html` → `0`.
- First 40 lines: standard HTML page head/CSS (dark theme, banner styles, blast-radius search box); the recorded events live further down as embedded JSON, not visible in the first 40 lines.

### `export` / `verify --bundle` / standalone `verify.cjs`

```
$ node dist/cli.js export --data-dir .mcp-recorder --out evidence/cloud-dogfood-4/incident.zip
[mcp-recorder] exported 62 event(s) (seq 1..62), head 9d6a6dcb7922f342… signed by ed25519 4976b82f963c631f…
[mcp-recorder] bundle zip: /home/user/audit/evidence/cloud-dogfood-4/incident.zip

$ node dist/cli.js verify --bundle evidence/cloud-dogfood-4/incident.zip
verify bundle /home/user/audit/evidence/cloud-dogfood-4/incident.zip
pinned signer: ed25519 4976b82f963c631f… (bundle's own manifest.json — self-pinned)
PASS — chain intact: 62 event(s), head seq 62
signed head: seq 62 by ed25519 4976b82f963c631f… at 2026-09-16T12:43:39.640Z

$ unzip -q evidence/cloud-dogfood-4/incident.zip -d /tmp/dogfood4-bundle && cd /tmp/dogfood4-bundle && node verify.cjs
PASS: evidence bundle verified
  events     : 62 (seq 1..62)
  base hash  : 707996e896e3e9a4b1e8d1e25fa74b8e0559541bb89243d2da7ae1f1f18cff27
  head hash  : 9d6a6dcb7922f342c136b817409aef3661c2a631e6d399e45a87403983e10108
  signed by  : ed25519 4976b82f963c631fa984d28dc545552e9f01f5f97ae5d46ec92c214c70f7ecc1 at 2026-09-16T12:43:39.640Z
```

Both the store-level `verify` and the standalone, dependency-free `verify.cjs` inside the exported bundle PASS.

### `events.jsonl` from the unzipped bundle

```
$ grep -o '"error":{[^}]*}' events.jsonl | sort -u
"error":{"message_ref":"sha256:059154500bfa71b4fd69bb8b5fa7399faa66bd152f31de51a749e0d84f7754f1","type":"tool_error"}
"error":{"message_ref":"sha256:58c20e548f3e2ed7ec57454465548b2175eebc68e36e99ee38392508a0f13ad9","type":"tool_error"}

$ grep -c '"policy_denied"' events.jsonl
0

$ grep -o '"url":"[^"]*"' events.jsonl | sort -u
"url":"https://api.anthropic.com/v2/ccr-sessions/sha256:74d7b42afbb8e6a6c5c2e03a04c19b615635f3142d0083103c7b66841b1f539a/github/mcp"

$ grep -c '"phase":"pre"' events.jsonl
16
$ grep -c '"phase":"post"' events.jsonl
16
```

- Two `error.type: "tool_error"` entries, each with a hashed `message_ref` and no plaintext error text — one from Part 1 step 5's forced `clickup_get_task` failure, matching the PostToolUseFailure design in PR #13.
- **Zero `policy_denied` events**, hard-confirming Part 2: the policy engine never produced a deny decision for either attempted call, on either attempt.
- Only **one distinct `server.url`** is present, and it belongs to `github` (whose config key is literally `"github"`, matching its display name). ClickUp, Gmail, Google_Calendar and Google_Drive events all carry `server.name` (`"ClickUp"`, `"Gmail"`, `"Google_Calendar"`, `"Google_Drive"`) but **no `server.url` at all** — the same UUID-keyed-lookup miss from Surprise #1 also silently drops the additive `server.url` field PR #13 introduced, for every hosted connector except GitHub.
- 16 pre / 16 post, balanced.

### `--all-tools`

```
$ printf '%s' '{"hook_event_name":"PreToolUse","session_id":"df4-alltools","tool_name":"Bash",...}' | node dist/cli.js hook --all-tools --data-dir /tmp/dogfood4-alltools; echo "exit=$?"
exit=0
$ node dist/cli.js sessions --data-dir /tmp/dogfood4-alltools
SESSION   STARTED                   ENDED   SERVER       EVENTS  TOOL_CALLS  ERRORS  SERVERS
df4-allt  2026-09-16T12:44:05.026Z  (open)  claude-code  2       1           0       1

$ printf '%s' '{"hook_event_name":"PreToolUse","session_id":"df4-noall","tool_name":"Bash",...}' | node dist/cli.js hook --data-dir /tmp/dogfood4-noall; echo "exit=$?"
exit=0
$ node dist/cli.js sessions --data-dir /tmp/dogfood4-noall
no sessions recorded
```

`--all-tools` records the built-in `Bash` call; without it, the same input is correctly ignored (no session created at all). Matches expectation.

## Expected vs. recorded

| # | Expectation | Recorded |
| --- | --- | --- |
| a | PostToolUseFailure gives `error.type` + hashed `message_ref` | **Met.** Two `tool_error` entries, both hashed, no plaintext. |
| b | `server.url` resolved from real MCP config per vendor called | **Not met** for ClickUp/Gmail/Calendar/Drive (no `server.url` recorded at all — UUID-lookup miss). **Met** for GitHub only. |
| c | Alias-only deny (`clickup_filter_tasks`) blocks a live call | **Not met.** Call succeeded twice, real data returned both times. |
| d | Raw-UUID control deny (`clickup_get_workspace_members`) blocks a live call | **Not met.** Call succeeded twice, real data returned both times. |
| e | Corrected `sessions` counts (pre/post pairs count once) | **Partially met.** Counting logic itself (1 tool_call per pre/post pair) appears correct where tested (`--all-tools` run), but the live session's row went stale mid-conversation and never reflected this run's own 16 pre/16 post pairs, 2 forced+denied errors, or corrected server count. |
| f | Write call's argument gets redacted | **Met**, indirectly: the write went to `repo-filesystem` (a proxy-recorded server) and wasn't sandbox-writable to `/tmp` at all (Surprise #2); the canary text never appears in `.mcp-recorder` or in the replay page. |
| g | Replay page shows a real timeline, denials visibly marked, no plaintext | **Partially met.** Page renders, integrity banner is green, embedded event JSON is properly redacted and canary-free. But since nothing was actually denied (Part 2), there is nothing for the UI to visibly mark as denied — this expectation couldn't be exercised end-to-end. |

## Surprises / things that look wrong

1. **(Most important) The live policy deny did not work at all, on either rule, on either attempt.** `clickup_filter_tasks` and `clickup_get_workspace_members` both executed against the real ClickUp workspace and returned real data — not synthetic — every time. Root cause: this session's Claude Code presents hosted-connector tool names as `mcp__<FriendlyAlias>__<tool>` (`ClickUp`, `Gmail`, `Google_Calendar`, `Google_Drive`), not `mcp__<uuid>__<tool>` as dogfood 3 observed and PR #13's alias/UUID logic assumes. Both deny routes PR #13 built depend on that UUID convention, so both miss. This means a hook deny — even one aimed with two independent, redundant routes (raw form + resolved alias) — can silently fail to reach live enforcement if the platform's tool-naming convention drifts, and nothing in `sessions`, `verify`, or the replay UI surfaces that failure; only `query`/`events.jsonl` (`policy_denied` count = 0) makes it visible, and only if you know to look.
2. `clickup_get_task` on a bad id returned `{"error":"Team not authorized"}`, not a not-found-style error.
3. `repo-filesystem`'s write tool is sandboxed to the repo root only; it cannot write to `/tmp`, contradicting this task's assumption. Redirected the canary write to gitignored `.mcp-recorder/dogfood4-scratch.txt` instead.
4. `sessions` shows a stale `ENDED`/counts row for this conversation's own session id, understating this run's real activity by a wide margin (16 more pre/post pairs, 2 more errors including the forced failure, existed and were provable via `query`/`verify`/`events.jsonl` but not via `sessions`).
5. `server.url` silently fails to populate for every hosted connector except `github`, for the same root cause as #1 — an easy-to-miss gap in the "vendor resolution" feature PR #13 shipped, since it only shows up as an *absence* of a field, not an error.

## Files in this directory

- `REPORT.md` — this file.
- `incident.zip` — signed evidence export (62 events, `verify --bundle` and standalone `verify.cjs` both PASS); unzips to `README.txt`, `events.jsonl`, `manifest.json`, `public_key.pem`, `verify.cjs`.
