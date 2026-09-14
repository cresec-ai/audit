# @edut/mcp-recorder

**A black-box flight recorder for MCP.** Wrap any MCP server in one config line and every tool call your agent makes is recorded into a tamper-evident, replayable, exportable evidence store — on your machine, with the payloads redacted at the edge.

**The bet:** record every agent tool call; make the record tamper-evident; keep it local-first. Nothing to trust, nothing to break. When an agent does something surprising — or someone claims it did — you can reconstruct exactly what happened, prove the record wasn't altered, and hand a stranger a bundle they can verify with bare Node and no dependencies.

```
BEFORE  {"command": "npx", "args": ["-y", "@some/mcp-server"]}
AFTER   {"command": "npx", "args": ["-y", "@edut/mcp-recorder", "--", "npx", "-y", "@some/mcp-server"]}
```

That's the whole integration. The proxy forwards bytes unchanged, fails open (recording failure never breaks traffic), and adds <5ms p50 latency.

- **License:** GPL-3.0 · **Node:** >= 18.17 · **Binary:** `mcp-recorder`

---

## 60-second quickstart

### 1. Wrap a server

**Claude Desktop** — `claude_desktop_config.json`:

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

**Claude Code** — one command:

```sh
claude mcp add filesystem -- npx -y @edut/mcp-recorder -- npx -y @modelcontextprotocol/server-filesystem .
```

or in `.mcp.json`:

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

**Cursor** — `~/.cursor/mcp.json`:

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

### 2. Use your agent normally

Traffic flows through untouched. Every tool call lands in `~/.mcp-recorder` as a redacted, hash-chained event.

### 3. Look at what happened

```sh
npx @edut/mcp-recorder sessions          # what ran, when, by whom
npx @edut/mcp-recorder ui                # HTML replay timeline in your browser
npx @edut/mcp-recorder verify            # prove the record is intact
npx @edut/mcp-recorder query "AKIA..."   # blast radius: which sessions touched this value?
npx @edut/mcp-recorder export --out evidence.zip   # signed bundle a stranger can verify
```

---

## How it works

```
                stdin/stdout — bytes forwarded UNCHANGED, fail-open
 ┌────────────┐        ┌────────────────────────────┐        ┌──────────────┐
 │ MCP client │ ◄────► │   mcp-recorder (proxy)     │ ◄────► │  MCP server  │
 │  (Claude,  │        │                            │        │ (any stdio)  │
 │  Cursor,…) │        │   tap ─► redact ─► hash    │        └──────────────┘
 └────────────┘        └─────────────┬──────────────┘
                                     │ async, off the hot path
                                     ▼
                       ┌────────────────────────────┐
                       │   tamper-evident store      │
                       │   ~/.mcp-recorder           │
                       │                             │
                       │  event_n ──┐                │
                       │  hash_n = sha256(           │
                       │    hash_{n-1} + canonical)  │
                       │  head signed with ed25519   │
                       └────────────────────────────┘
```

Four pillars:

1. **Transparent fail-open stdio proxy.** The proxy never parses-then-rewrites; it forwards the exact bytes and taps a copy. If recording dies, traffic keeps flowing. Added latency is <5ms p50.
2. **Edge redaction.** Payload strings never reach disk. Each string leaf is replaced by its SHA-256 (`sha256:<hex>`) plus its length — structure preserved, content gone. Hashes are unsalted *by design*: if you later need to know whether a known value (an API key, a customer email) ever passed through, hash it and search.
3. **Tamper-evident store.** SQLite (JSONL fallback), append-only. Every event is sealed as `sha256(prev_hash + "\n" + canonicalJson(event))`, and the chain head is signed with a local ed25519 key. `mcp-recorder verify` re-walks every link; altering, inserting, or deleting any stored row makes it fail loudly.
4. **Reconstruction tools.** An HTML replay timeline (see → act → effect, with identity context on every event), a blast-radius query ("which sessions touched X?"), and a signed evidence bundle — a ZIP containing `events.jsonl`, `manifest.json`, `public_key.pem`, and a standalone, dependency-free `verify.cjs` that anyone can run with bare `node`.

**Multiple wrapped servers, one data dir.** The normal setup is one `mcp-recorder record` process per MCP server, all pointed at the same `--data-dir`. Any number of them may run at once: each append is sealed under the store's own exclusive lock (a `busy_timeout`'d transaction for sqlite, an advisory lock for jsonl), so writers never lose or fork the chain — their sessions simply interleave, seq by seq, in one shared hash chain.

---

## Commands

```
mcp-recorder [record] [options] -- <server command...>
```

| Command | What it does |
| --- | --- |
| `mcp-recorder [record] [--data-dir D] [--name N] [--identity L] [--redact allowlist\|off] -- <server command...>` | Run the wrapped server behind the recording proxy (`record` is the default subcommand and may be omitted). `--name` sets the logical server name, `--identity` an operator label stamped on every event. |
| `mcp-recorder verify [--json] [--bundle PATH]` | Re-walk the hash chain and check head signatures — for the local store, or for an exported bundle with `--bundle`. |
| `mcp-recorder query <needle> [--json]` | Blast radius: hash the needle and find every event and session that touched that value. |
| `mcp-recorder sessions [--json]` | List recorded sessions: server, identity, event/tool-call/error counts. |
| `mcp-recorder ui [--port P] [--out FILE] [--no-open]` | Serve the HTML replay timeline (or write it to a file with `--out`). |
| `mcp-recorder export [--session ID] [--out FILE.zip] [--dir DIR]` | Produce a signed evidence bundle as a ZIP or plain directory. |
| `mcp-recorder http --target URL [--port P]` | Recording proxy for HTTP-transport MCP servers. |

### Environment variables

| Variable | Effect |
| --- | --- |
| `MCP_RECORDER_DATA_DIR` | Override the data directory (default `~/.mcp-recorder`). |
| `MCP_RECORDER_STORE` | `sqlite` or `jsonl` (default: try sqlite, fall back to jsonl). |
| `MCP_RECORDER_REDACT` | `allowlist` (default) or `off`. Secret-shaped values are hashed in every mode. |
| `MCP_RECORDER_DISABLE` | `1` → pure passthrough, no recording. |

---

## The demo

```sh
npm run demo
```

A scripted prompt-injection exfiltration — an agent is tricked into reading a credential and sending it out through an innocent-looking tool — recorded, reconstructed on the replay timeline, blast-radius-queried, and cryptographically verified, in under a minute. It is the fastest way to see what the recorder is for.

---

## Security model (the honest version)

**What you get: tamper *evidence*, not tamper *prevention*.** Anyone with write access to your disk can delete the store outright. What they cannot do silently is *edit* it: every event is hash-chained, and the head is signed, so any modification, insertion, or deletion inside the recorded range makes `verify` fail loudly.

Read the fine print:

- **Tail truncation.** Deleting events from the end of the chain is detectable only back to the last signed head. The recorder signs the head on every flush, which keeps the unsigned window small, but an attacker who can also delete signatures can roll the chain back to an older signed head. For stronger guarantees, anchor head signatures externally (ship them to another machine, a log, a timestamping service) — the `HeadSignature` records are small and self-contained.
- **Unsalted hashes — a deliberate tradeoff.** Redaction refs are plain `sha256(value)`, no salt. This is what makes blast-radius queries possible: hash a candidate value and search for it. The flip side: a party who *already holds* a candidate value (or can enumerate a small space of them) can confirm whether it was seen. The store never leaks values to someone who doesn't already have them, but it does confirm membership to someone who does. If that tradeoff is wrong for your threat model, treat the store itself as sensitive.
- **The recorder trusts its own key.** The ed25519 key lives in the data dir. An attacker who owns the key can re-sign a forged chain. The signature proves the chain was produced by the holder of that key, and a bundle proves integrity to a third party who pins the public key — it does not protect against a fully compromised host.
- **Fail-open means recording can be lost.** By design, if the store breaks mid-session the proxy keeps forwarding and counts dropped events (`events_dropped` in the `session_end` event). Availability of your agent always wins over completeness of the record.

## Event schema

Events follow the frozen schema `edut.mcp-recorder.event.v1`, with field names aligned to OpenTelemetry GenAI/RPC semantic conventions. The full schema — every event kind, every field, the chain construction, and the canonicalization rules — is documented in [docs/event-schema.md](docs/event-schema.md).

## What we explicitly do NOT do

- **No payload storage.** Strings are hashed at the edge; original values never land in the store.
- **No cloud.** Local-first, no telemetry, no phone-home. Evidence leaves your machine only when you run `export`.
- **No enforcement.** The recorder observes; it never blocks, rewrites, or rate-limits traffic. It is a flight recorder, not a firewall.

## License

GPL-3.0. The recorder sits in your trust path, so you should be able to read every line of it — and so should everyone downstream of any fork.

## Built in the open — design partners wanted

This project is being built in public and shaped by real incident-response and compliance workflows. If you run agents with MCP in anger and want a say in where this goes — verification workflows, retention, external anchoring, fleet aggregation — open an issue or reach out. Early design partners get their problems prioritized.
