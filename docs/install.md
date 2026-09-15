# Install guide

Canonical instructions for getting `mcp-recorder` in front of your MCP servers.
For the story behind the tool, see the [README](../README.md); for the event
format, see [docs/event-schema.md](event-schema.md).

## Requirements

- **Node.js >= 18.17** (macOS or Linux). Check with `node --version`.
- **macOS or Linux.** Windows is not supported yet: the proxy spawns the
  wrapped command directly (no shell), and on Windows that breaks `npx` and
  other `.cmd`/`.bat` shims. If you're on Windows, use WSL for now.
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

Install straight from the repository. `npm install` runs the package's
`prepare` script automatically, which builds `dist/` for you — no manual
build step needed.

```sh
npm install -g github:cresec-ai/audit#claude/p0-subagents-scoping-qibt2p
```

Once this branch merges, the equivalent from `main` will be:

```sh
npm install -g github:cresec-ai/audit#main
```

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
cd audit && git checkout claude/p0-subagents-scoping-qibt2p
npm ci   # runs `prepare` -> builds dist/
node dist/cli.js --version
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
mcp-recorder setup --client <claude-desktop|claude-code|cursor> [--config PATH] [--wrapper local|npx]
                   [--only NAME[,NAME...]] [--except NAME[,NAME...]] [--data-dir D] [--dry-run] [--undo] [--json]
```

- `--client` picks the config file automatically:
  - `claude-desktop`: `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `~/.config/Claude/claude_desktop_config.json` (Linux)
  - `claude-code`: `~/.claude.json`, or a project's `.mcp.json`
  - `cursor`: `~/.cursor/mcp.json`
  - `--config PATH` overrides the resolved path.
- `--wrapper local` (the default) points at this Node binary and this
  install's `dist/cli.js` by absolute path — the form that works before
  publish. `--wrapper npx` writes the future `npx -y @edut/mcp-recorder` form
  (use it once the package is on npm).
- `--only NAME,...` / `--except NAME,...` limit which server entries get
  wrapped; entries that are already `url`/`http` (not stdio) are always
  skipped, and an already-wrapped entry is never wrapped twice.
- Every run writes a timestamped `.bak` of the config plus a sidecar record,
  so `mcp-recorder setup --client <same> --undo` restores the originals
  exactly.
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

## Install with Claude

You can hand the install off to Claude itself — Claude Desktop or Claude
Code — with a prompt like this. Copy it in as-is:

```
Install @edut/mcp-recorder and wrap my MCP servers with it.

1. It isn't on npm yet, so install it from git:
   npm install -g github:cresec-ai/audit#claude/p0-subagents-scoping-qibt2p
   Confirm with: mcp-recorder --version

2. Run `mcp-recorder setup --client <claude-desktop|claude-code|cursor> --dry-run`
   for my client (pick the one you're running in, or ask me). Show me the
   diff it would make before changing anything.

3. Once I confirm, run the same command without --dry-run to apply it.

4. Tell me to fully quit and restart the client — closing the window is not
   enough, the MCP servers only reload on relaunch.

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

**Read stderr.** The recorder never writes diagnostics to stdout (stdout is
the MCP wire) — everything it logs is prefixed `[mcp-recorder]` on stderr.
Claude Desktop and Cursor both keep per-server log files; check those first.

**Windows.** Not supported yet — the proxy spawns the wrapped command
without a shell, which breaks `npx`/`.cmd` shims on Windows. Use WSL, or
wait for native Windows support.
