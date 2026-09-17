# Install guide

Canonical instructions for getting `mcp-recorder` in front of your MCP servers.
For the story behind the tool, see the [README](../README.md); for the event
format, see [docs/event-schema.md](event-schema.md).

## Requirements

- **Node.js >= 20.** Check with `node --version`.
- **macOS, Linux, or Windows** — Windows is supported natively (CI-tested on
  `windows-latest`): the proxy resolves `.cmd`/`.bat` shims (like `npx`)
  through `cmd.exe` itself, no shell required in your config. Running
  entirely inside WSL works too — see **[Windows and WSL](#windows-and-wsl)**
  below for the two ways to set it up.
- No database to run, no account, no network access required. Everything is
  local files under a data directory (default `~/.mcp-recorder`).

## Install the CLI

### A. From npm (once published)

`@edut/mcp-recorder` is not on the npm registry yet, so this does not work
today — but once it ships, this is the intended path and needs no separate
install step:

```sh
npx -y @edut/mcp-recorder --version
```

Watch the project for the npm release; the commands below (B) are the way to
get the same thing right now.

### B. From git (today)

Install straight from the repository. The built `dist/` is committed, so
this needs no build step and no TypeScript toolchain on your machine:

```sh
npm install -g github:cresec-ai/audit#main
```

If you had an older install, the same command replaces it.

**npm 11 (the npm that ships with Node 24) and the SQLite backend.** npm 11
refuses to run a dependency's install script on a global install unless you
allow it, and better-sqlite3 needs its script to fetch the native binding.
Without it the recorder still works — it falls back to the JSONL store and
says so once on stderr — but to get SQLite, allow the script:

```sh
npm install -g --allow-scripts=better-sqlite3 github:cresec-ai/audit#main
```

(or `npm config set allow-scripts=better-sqlite3 --location=user` once, for
every future global install). npm 10 runs the script without being asked.

Confirm it worked:

```sh
mcp-recorder --version
# 0.1.0
```

If `mcp-recorder` isn't found afterward, check `npm config get prefix` is on
your `PATH` (a common gap with nvm/volta setups) — or skip the global install
and invoke it from a local clone instead:

```sh
git clone https://github.com/cresec-ai/audit.git
cd audit
npm ci && npm run compile   # dev dependencies, then rebuild dist/ from src/
node dist/cli.js --version
npm install -g .       # optional: put `mcp-recorder` on your PATH from this clone
```

## Wrap your servers

`mcp-recorder` doesn't change what your MCP servers do — it sits between your
client and each server's stdio, so the client's config just needs to launch
the server *through* the recorder instead of directly.

### The one-command way: `mcp-recorder setup`

`setup` rewrites a client's MCP config in place, wrapping every stdio server
entry with the recorder. Always preview first:

```sh
mcp-recorder setup --client claude-desktop --dry-run
mcp-recorder setup --client claude-desktop
```

```
mcp-recorder setup --client <claude-desktop|claude-code|cursor> [--config PATH] [--wrapper local|npx|wsl]
                   [--only NAME[,NAME...]] [--except NAME[,NAME...]] [--bridge NAME=URL[,NAME=URL...]]
                   [--data-dir D] [--policy FILE] [--dry-run] [--undo] [--json]
```

- `--client` picks the config file automatically:
  - `claude-desktop`: `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS), `%APPDATA%\Claude\claude_desktop_config.json` (Windows), or `~/.config/Claude/claude_desktop_config.json` (Linux)
    — and on Windows, when that `%APPDATA%` path doesn't exist, a **Microsoft
    Store (MSIX)** install instead: `%LOCALAPPDATA%\Packages\Claude_<hash>\LocalCache\Roaming\Claude\claude_desktop_config.json`
    (the `Claude_<hash>` package folder name varies per machine; `setup`
    finds it automatically, or errors asking for `--config` if more than one
    matches)
  - `claude-code`: `~/.claude.json`, or a project's `.mcp.json`
  - `cursor`: `~/.cursor/mcp.json`
  - `--config PATH` overrides the resolved path.
  - Running inside **WSL**: if the Linux-side path above doesn't exist,
    `setup` automatically looks for it on the **Windows** side instead (e.g.
    `/mnt/c/Users/<you>/AppData/Roaming/Claude/claude_desktop_config.json`,
    MSIX included)
    — see [Windows and WSL](#windows-and-wsl) below.
  - `--bridge NAME=URL` turns a *remote* MCP connector into a local, wrappable
    entry — see [Connectors: what the recorder can and cannot
    see](#connectors-what-the-recorder-can-and-cannot-see) below.
- `--wrapper local` (the default) points at this Node binary and this
  install's `dist/cli.js` by absolute path. `--wrapper npx` writes the
  `npx -y @edut/mcp-recorder` form (once the package is on npm). `--wrapper
  wsl` writes a `wsl.exe -e node ...` form so a **Windows** client can launch
  a server that actually runs inside **WSL**; from inside WSL, `setup`
  auto-selects it for you whenever the resolved config is a Windows-side
  file (see [Windows and WSL](#windows-and-wsl)) — you don't need to pass it
  by hand in that case.
- `--only NAME,...` / `--except NAME,...` limit which server entries get
  wrapped; entries that are already `url`/`http` (not stdio) are always
  skipped, and an already-wrapped entry is never wrapped twice.
- `--bridge NAME=URL[,NAME=URL...]` (repeatable) adds `NAME` as a local
  `npx -y mcp-remote URL` entry before wrapping — see [Connectors: what the
  recorder can and cannot see](#connectors-what-the-recorder-can-and-cannot-see).
- Every run writes a timestamped `.bak` of the config plus a sidecar record,
  so `mcp-recorder setup --client <same> --undo` restores the originals
  exactly.
- `--policy FILE` switches the wrapped servers into **gateway mode**: the
  policy is validated up front (a missing, invalid or `mcp`-less file exits 2
  and leaves the config untouched), then baked into each wrapped entry as
  `--policy <absolute path>` — absolute because clients launch servers from
  their own working directory. Entries an earlier `setup` run already wrapped
  are updated in place too (the flag is added, or an existing one repointed;
  they are reported as `updated policy on: ...`), so one run really does
  apply the policy to every server in the config. Ignored with `--undo`. See
  [docs/gateway.md](gateway.md) for what enforcement does.
- `--dry-run` prints the resulting config without writing anything.
- `--data-dir D` sets the data directory baked into the wrapped commands
  (default `~/.mcp-recorder`).
- Exit codes: `0` success, `1` config file not found, `2` usage error or
  unparsable JSON.
- `setup` ends by reminding you to **fully quit and restart** the client —
  see below, this is not optional.

If `setup` isn't available in your installed build yet, use the manual edit
below — it produces the same result.

### Manual JSON edit, per client

In every case, pick the local-wrapper form (works today, before npm
publish) or the npx form (works after `@edut/mcp-recorder` is published).
Change **only** the `command`/`args` of the server you're wrapping; leave
`env` and everything else as-is.

#### Claude Desktop

macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
Linux: `~/.config/Claude/claude_desktop_config.json`

Before:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/Users/me/projects"]
    }
  }
}
```

After — local wrapper (today):

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "/usr/bin/node",
      "args": [
        "/path/to/mcp-recorder/dist/cli.js", "--",
        "npx", "-y", "@modelcontextprotocol/server-filesystem", "/Users/me/projects"
      ]
    }
  }
}
```

`/usr/bin/node` should be the absolute output of `which node`; `dist/cli.js`
is inside wherever you installed the package from git (run `npm root -g` and
look under `@edut/mcp-recorder/dist/cli.js`, or use the path of a local
clone).

After — npx wrapper (once published):

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": [
        "-y", "@edut/mcp-recorder", "--",
        "npx", "-y", "@modelcontextprotocol/server-filesystem", "/Users/me/projects"
      ]
    }
  }
}
```

#### Claude Code

Config lives in `~/.claude.json` (user-level) or a project's `.mcp.json`.
The CLI form works either way:

```sh
claude mcp add filesystem -- node /path/to/mcp-recorder/dist/cli.js -- npx -y @modelcontextprotocol/server-filesystem .
```

Or edit `.mcp.json` directly — local wrapper (today):

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "node",
      "args": [
        "/path/to/mcp-recorder/dist/cli.js", "--",
        "npx", "-y", "@modelcontextprotocol/server-filesystem", "."
      ]
    }
  }
}
```

npx wrapper (once published):

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": [
        "-y", "@edut/mcp-recorder", "--",
        "npx", "-y", "@modelcontextprotocol/server-filesystem", "."
      ]
    }
  }
}
```

#### Cursor

`~/.cursor/mcp.json` — same shape as Claude Desktop. Local wrapper (today):

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "node",
      "args": [
        "/path/to/mcp-recorder/dist/cli.js", "--",
        "npx", "-y", "@modelcontextprotocol/server-filesystem", "/Users/me/projects"
      ]
    }
  }
}
```

npx wrapper (once published):

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": [
        "-y", "@edut/mcp-recorder", "--",
        "npx", "-y", "@modelcontextprotocol/server-filesystem", "/Users/me/projects"
      ]
    }
  }
}
```

### Restart the client

Whichever way you edited the config — `setup` or by hand — **fully quit and
restart** the client afterward (closing the window is not enough for Claude
Desktop; also true for Cursor). MCP servers are only launched at startup, so
a running client keeps using its old, unwrapped process until it's relaunched.

## Windows and WSL

**Claude Desktop is a Windows program** — even if you also have WSL
installed, Claude Desktop itself runs on Windows and its config
(`claude_desktop_config.json`) lives under your Windows profile, not inside
any WSL distro. That means the MCP servers it launches run as Windows
processes too, by default. You have two options, and they can be mixed
per-server (`--only`/`--except`).

### Option 1 — recorder on Windows

Run everything on the Windows side; WSL doesn't come into it at all.

1. Install Node.js >= 20 on Windows (from [nodejs.org](https://nodejs.org) or
   `winget install OpenJS.NodeJS.LTS`).
2. In **PowerShell**:

   ```powershell
   npm install -g github:cresec-ai/audit#main
   mcp-recorder setup --client claude-desktop --dry-run
   mcp-recorder setup --client claude-desktop
   ```

3. Restart Claude Desktop. Sessions land under `%USERPROFILE%\.mcp-recorder`
   (override with `--data-dir` or `MCP_RECORDER_DATA_DIR`, same as anywhere
   else). Run `mcp-recorder sessions` / `ui` / `verify` from PowerShell too.

This is the simplest option, and the only one that works for a server that's
Windows-only (something that shells out to a `.exe`, for instance).

How the recorder launches the server on Windows: an `.exe` is spawned
directly; a `.cmd`/`.bat` shim (which is what `npx`, `npm` and `uvx` are on
Windows) has to go through `cmd.exe`, so its arguments are escaped the same
way `cross-spawn` does it. Two consequences of `cmd.exe` being in the loop:
a `%VAR%` sequence inside an argument is expanded by `cmd.exe` before the
server sees it (no escaping can prevent that), and an argument containing a
line break is refused outright — the recorder exits with an error instead of
letting `cmd.exe` run the text after the break as a second command.

### Option 2 — recorder and servers inside WSL

Keep your servers (and the recorder) running inside WSL — useful if your
servers, their dependencies, or your usual dev environment already live
there. From inside WSL:

```sh
mcp-recorder setup --client claude-desktop --dry-run
mcp-recorder setup --client claude-desktop
```

Since Claude Desktop's config isn't on the Linux side, `setup` looks for it
on the Windows side instead — under
`/mnt/c/Users/<you>/AppData/Roaming/Claude/claude_desktop_config.json` — and,
finding it, automatically writes the `--wrapper wsl` form instead of the
ordinary local-node form (a plain Linux `node` path in `command` would be
meaningless to a Windows process). The result looks like this:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "wsl.exe",
      "args": [
        "-d", "Ubuntu-22.04", "-e",
        "/home/you/.nvm/versions/node/v20.18.0/bin/node",
        "/home/you/audit/dist/cli.js",
        "record", "--name", "filesystem", "--data-dir", "/home/you/.mcp-recorder",
        "--",
        "npx", "-y", "@modelcontextprotocol/server-filesystem", "/home/you/projects"
      ]
    }
  }
}
```

Claude Desktop spawns `wsl.exe`, which launches the recorder (and the server
behind it) inside your WSL distro. Consequences worth knowing:

- **The wrapped server now runs inside WSL**, so any paths in its own
  args must be *Linux* paths (`/home/you/projects`, not
  `C:\Users\you\projects`) — `setup` never rewrites the original server's
  own arguments, only wraps around them.
- **A Windows-only server can't go through this path** — if one of your
  servers shells out to a `.exe` or otherwise needs to run on Windows, wrap
  it with Option 1 instead and use `--except <name>` here (or `--only` on
  the Windows side) to split the set.
- **Env vars are forwarded via `WSLENV`.** wsl.exe only passes a Windows
  environment variable through to the WSL process when its name is listed
  in the `WSLENV` variable; `setup` adds any keys your server's `env` block
  already had to `WSLENV` automatically, so this is handled for you — you
  don't need to set `WSLENV` yourself for a server `setup` wrapped.
- **The data dir is the Linux-side one** (`~/.mcp-recorder` inside your
  distro, always passed explicitly with `--data-dir` since `wsl.exe -e`
  launches the target directly — with no shell in the loop, `~` is never
  expanded). Run `mcp-recorder sessions` / `ui` / `verify` / `export` from
  inside WSL, not PowerShell.

**Troubleshooting a WSL-wrapped server:** copy the exact `command`/`args`
from the config and run it from PowerShell yourself — this surfaces stderr a
client's UI usually hides:

```powershell
wsl.exe -d Ubuntu-22.04 -e /home/you/.nvm/versions/node/v20.18.0/bin/node /home/you/audit/dist/cli.js record --name filesystem --data-dir /home/you/.mcp-recorder -- npx -y @modelcontextprotocol/server-filesystem /home/you/projects
```

A couple of things that specifically trip people up here:

- **nvm and similar Node version managers.** If `node` itself came from nvm,
  its directory usually isn't on the `PATH` a non-interactive `wsl.exe -e`
  launch sees, which can break `npx` resolution for the *wrapped* server.
  The recorder adds its own Node's directory to the wrapped child's
  `PATH` for exactly this reason, so `npx` still resolves even in that
  environment. It is placed ahead of the Windows entries WSL's interop
  appends (`/mnt/c/Program Files/nodejs`, ...), so a Node installed on
  Windows can never capture a bare `npx` meant for WSL — but if you've
  swapped Node versions since running `setup`,
  re-run it so the baked-in `node` path (`process.execPath`, resolved at
  `setup` time) still points somewhere real.
- **`wsl.exe -e` needs absolute paths** — it does not go through a shell, so
  there's no `~` expansion and no `PATH` search for the program it launches
  directly (`node`, here). `setup` always writes absolute paths for exactly
  this reason; if you hand-edit this form, keep them absolute.

### Cursor

Same two options, same reasoning — Cursor on Windows reads
`~/.cursor/mcp.json` under your Windows profile:

- **Option 1** (recorder on Windows): `mcp-recorder setup --client cursor`
  from PowerShell.
- **Option 2** (recorder in WSL): `mcp-recorder setup --client cursor` from
  WSL — `setup` finds `/mnt/c/Users/<you>/.cursor/mcp.json` on the Windows
  side the same way, and wraps it with the same `wsl.exe` form.

### Claude Code in WSL

Nothing special here — Claude Code running inside WSL is a plain Linux
install using `~/.claude.json` (or a project's `.mcp.json`) on the Linux
side, same as any other Linux setup. There's no separate Windows-side config
for it to fall back to.

## Connectors: what the recorder can and cannot see

`claude_desktop_config.json` isn't the only way Claude Desktop reaches an MCP
server. Whether `setup` can wrap one depends entirely on how it's added:

| Kind | Where it runs | Recordable? |
| --- | --- | --- |
| Local MCP servers in `claude_desktop_config.json` | Your machine, stdio | **Yes** — `setup` wraps it |
| Desktop Extensions (`.mcpb`) | Your machine, stdio | Local, but not yet wrapped by `setup` (planned) |
| Remote connectors (Settings → Connectors) | **Anthropic's infrastructure**, not your machine | **No** — see below |

A **remote connector** — one you add from Claude Desktop's Settings →
Connectors, such as ClickUp at `https://mcp.clickup.com/mcp` — is an OAuth
flow to a remote MCP endpoint that Claude's own backend calls, not a local
process your machine ever runs: the OAuth callback for these is
`https://claude.ai/api/mcp/auth_callback`, and none of it is a `command`/`args`
entry in `claude_desktop_config.json` for `setup` to find. There is nothing
local for the recorder to sit in front of.

The way to record such a server today is `--bridge`: it reaches the *same*
remote MCP endpoint, but from your machine, through the
[`mcp-remote`](https://www.npmjs.com/package/mcp-remote) bridge, so it
becomes a local stdio entry `setup` can wrap like any other. Google Drive,
Gmail and Calendar are served from Google-hosted MCP endpoints as well
(`drivemcp`, `gmailmcp` and `calendarmcp.googleapis.com`, as seen in a Claude
Code cloud session's connector wiring), but whether an independent OAuth
client such as `mcp-remote` can authorise against them is untested; the GitHub
connector has no vendor endpoint at all. Inside Claude Code (CLI, IDE, Desktop
Code tab, cloud sessions) the recorder sees every connector call anyway,
through Claude Code's own hooks: see [docs/hooks.md](hooks.md). The full
picture of what can and cannot be seen or controlled per surface is in
[docs/connector-coverage.md](connector-coverage.md).

### Bridge a remote MCP server

```sh
mcp-recorder setup --client claude-desktop --bridge clickup=https://mcp.clickup.com/mcp --dry-run
mcp-recorder setup --client claude-desktop --bridge clickup=https://mcp.clickup.com/mcp
```

This adds `clickup` to your config as `npx -y mcp-remote https://mcp.clickup.com/mcp`,
then wraps *that* with the recorder — so the sidecar's "original" for
`--undo` is the unwrapped `mcp-remote` entry, not the remote connector itself
(`--undo` removes the recorder, not the bridge; delete the `clickup` entry by
hand if you want the bridge gone too).

The first time Claude Desktop launches a bridged server, `mcp-remote` opens
an OAuth flow in your browser, the same authorization you'd get adding it as
a connector. To pre-authorize from a terminal instead of waiting for that
first launch:

```sh
npx -y mcp-remote https://mcp.clickup.com/mcp
```

Tokens land under `~/.mcp-auth` and are reused by the wrapped server.

**In WSL:** the browser OAuth step opens on Windows even when the recorder
and `mcp-remote` run inside WSL — WSL2 forwards `localhost`, so the callback
mcp-remote listens for still reaches it.

**Caveat:** once bridged, that server is only available in **Claude
Desktop**, wired through this specific config — not on claude.ai or mobile,
which still reach the connector directly through Anthropic's infrastructure.

## Install with Claude

You can hand the install off to Claude itself — Claude Desktop or Claude
Code — with a prompt like this. Copy it in as-is:

```
Install @edut/mcp-recorder and wrap my MCP servers with it.

1. It isn't on npm yet, so install it from git:
   npm install -g github:cresec-ai/audit#main
   Confirm with: mcp-recorder --version

2. Run `mcp-recorder setup --client <claude-desktop|claude-code|cursor> --dry-run`
   for my client (pick the one you're running in, or ask me). Show me the
   diff it would make before changing anything.

3. Once I confirm, run the same command without --dry-run to apply it.

4. Tell me to fully quit and restart the client — closing the window is not
   enough, the MCP servers only reload on relaunch.

If I'm on Windows or WSL, follow the Windows and WSL section of
docs/install.md and tell me which option you're using before changing
anything.

Do not skip the dry-run step, and do not silently pick a client if more than
one config file is present.
```

For this to work, Claude needs either a shell/terminal tool (to run `npm
install` and `mcp-recorder setup`) or, at minimum, the ability to read and
write the client's config file directly and reminders about the restart step.

## Check it works

After wrapping a server and restarting the client, make one tool call
through it (ask the agent to do something trivial, like listing files), then
from a terminal:

```sh
mcp-recorder sessions          # your session should show up: server, event/tool-call counts
mcp-recorder verify            # PASS — chain intact, head signature valid
mcp-recorder ui                # opens the HTML replay timeline in your browser
mcp-recorder query "<a value your call touched>"   # blast-radius: which sessions/events touched it
```

If `sessions` comes back empty, see Troubleshooting below.

**`query` matches exact values, not substrings.** The needle is hashed whole
and compared against stored refs, so pass the value exactly as the agent
passed it. `query attacker.example` finds nothing while
`query https://attacker.example/collect` finds the call, and
`query mcp__claude_ai_ClickUp__clickup_filter_tasks` — the name Claude Code
shows you — finds nothing while the bare `clickup_filter_tasks` finds both
calls, because the server and the tool are stored as separate fields. Both
misses are from local dogfood 6, where they cost an investigation.

## Where the data lives and what's in it

Default data directory: `~/.mcp-recorder` (override with `--data-dir` or
`MCP_RECORDER_DATA_DIR`). One data dir can — and normally does — hold
sessions from several wrapped servers at once (see "Multiple servers, one
data dir" below).

| File | Contents |
| --- | --- |
| `evidence.db` (or `events.jsonl` for the jsonl backend) | The append-only, hash-chained event log. |
| `identity.key` | The local ed25519 private signing key. Generated on first run. Treat it like any other private key — it's what lets `verify` trust the chain head. |
| `identity.pub` | The matching public key, in hex. This is what `verify` pins to by default. Safe to share for out-of-band verification. |

**Payloads are hashed, not stored.** Every string leaf in a tool call
(arguments, results, note contents, file contents — anything that isn't a
small fixed set of structural fields like `type`/`role`/`method`/`name`) is
replaced on disk by `sha256:<hex>` plus its length before it's ever written.
Object *keys* are redacted the same way. The original bytes never touch
disk; only someone who already holds a candidate value can confirm it was
seen, via `query`.

**Permissions:** the data directory and its files are created with your
normal user umask (no special hardening beyond that yet) — anyone who can
read your home directory can read the store, so `identity.key` should be
treated with the same care as an SSH key if you're on a shared machine.

## Multiple servers, one data dir

Point every wrapped server at the same `--data-dir` (or just rely on the
shared default `~/.mcp-recorder`) and their sessions interleave into one hash
chain, each write serialized under the store's own lock:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "node",
      "args": ["/path/to/mcp-recorder/dist/cli.js", "--name", "filesystem", "--", "npx", "-y", "@modelcontextprotocol/server-filesystem", "."]
    },
    "corp-notes": {
      "command": "node",
      "args": ["/path/to/mcp-recorder/dist/cli.js", "--name", "corp-notes", "--", "npx", "tsx", "demo/server.ts"]
    }
  }
}
```

`mcp-recorder sessions` then lists sessions from both servers; `query` and
`export` search/bundle across all of them by default.

## Uninstall / undo

**If you used `setup`:**

```sh
mcp-recorder setup --client <claude-desktop|claude-code|cursor> --undo
```

restores the config exactly as it was before wrapping (from the `.bak` +
sidecar `setup` wrote). Restart the client afterward.

**If you edited by hand:** replace each wrapped entry's `command`/`args`
back with the original server command (the "Before" snippet for your
client, above), then restart the client.

**To remove the recorded data:** the data directory is just files —
`rm -rf ~/.mcp-recorder` (or your `--data-dir`) deletes everything,
including the signing key. There's nothing else to clean up; uninstalling
the CLI (`npm uninstall -g @edut/mcp-recorder`) doesn't touch it.

## Troubleshooting

**The server doesn't start / the client shows a connection error.** Run the
exact wrapped command by hand in a terminal and read the output directly —
this reproduces almost everything a client's UI hides:

```sh
node /path/to/mcp-recorder/dist/cli.js --data-dir ~/.mcp-recorder --name filesystem -- npx -y @modelcontextprotocol/server-filesystem /path
```

If the *underlying* server fails on its own (unrelated to the recorder), run
it directly without the wrapper to confirm — `npx -y @modelcontextprotocol/server-filesystem /path`.

**Rule out the recorder entirely.** Set `MCP_RECORDER_DISABLE=1` in the
wrapped command's environment: traffic flows straight through with nothing
recorded. If the problem persists with this set, it isn't the recorder.

**`mcp-recorder setup` says `Unknown option '--client'`.** The `mcp-recorder`
on your `PATH` is an older install from before `setup` existed, not the one
you just installed. `which -a mcp-recorder` lists every copy; remove the
stale one (or `npm uninstall -g @edut/mcp-recorder` under the Node version
that owns it), then `hash -r`. `npm ls -g @edut/mcp-recorder` shows where
the current one lives.

**Read stderr.** The recorder never writes diagnostics to stdout (stdout is
the MCP wire) — everything it logs is prefixed `[mcp-recorder]` on stderr.
Claude Desktop and Cursor both keep per-server log files; check those first.

**Windows.** Supported natively — the proxy resolves `.cmd`/`.bat` shims
(like `npx`) through `cmd.exe` itself, no shell needed in your config. If a
wrapped server won't start, run the exact `command`/`args` from the config
directly in PowerShell to see its real output, same as the Linux/macOS
troubleshooting step above. Running inside WSL instead (recorder and servers
on the Linux side, `wsl.exe`-wrapped for a Windows client) has its own
troubleshooting notes — see [Windows and WSL](#windows-and-wsl).

## Cloud coding agents

Each platform installs dependencies through its own hook, and all of them call
the same `scripts/bootstrap.sh`. Where a platform lets a repository declare
MCP servers, the recorder wraps them the same way as `.mcp.json` does.

| Platform | Environment setup | MCP servers |
| --- | --- | --- |
| Claude Code on the web | `.claude/hooks/session-start.sh` (SessionStart hook), loaded automatically | `.mcp.json`, loaded automatically |
| GitHub Copilot coding agent | `.github/workflows/copilot-setup-steps.yml` on the default branch (job `copilot-setup-steps`) | Repository Settings → Copilot → MCP servers (JSON below) |
| Cursor cloud agents | `.cursor/environment.json` (`install` runs at build time) | Dashboard only (cursor.com/agents → MCP), stdio form below; `.cursor/mcp.json` serves local Cursor |
| OpenAI Codex cloud | Environment settings → Setup script: `sh scripts/bootstrap.sh` | Not supported for stdio servers today |
| OpenAI Codex CLI | `sh scripts/bootstrap.sh` (see `AGENTS.md`) | `.codex/config.toml` (trusted projects only) |

Copilot coding agent MCP configuration (repository settings):

```json
{
  "mcpServers": {
    "corp-notes": {
      "type": "local",
      "command": "sh",
      "args": ["scripts/dogfood-wrap.sh", "--name", "corp-notes", "--", "npx", "tsx", "demo/server.ts"],
      "tools": ["*"]
    }
  }
}
```

Cursor cloud agent MCP server (dashboard form, stdio):

```json
{
  "mcpServers": {
    "corp-notes": {
      "type": "stdio",
      "command": "sh",
      "args": ["scripts/dogfood-wrap.sh", "--name", "corp-notes", "--", "npx", "tsx", "demo/server.ts"]
    }
  }
}
```

Two caveats apply everywhere: the platform's own connectors (for example
GitHub or ClickUp offered by the platform) do not pass through anything a
repository can configure, so they are not recorded; and a cloud container is
ephemeral, so export a bundle (`mcp-recorder export`) before the session ends
if the evidence must outlive it.
