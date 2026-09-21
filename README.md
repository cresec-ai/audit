# @edut/mcp-recorder

**The MCP gateway and evidence-chain leg of Cresec Governed Tools.** Wrap any MCP server in one config line and every tool call your agent makes through that server is recorded into a tamper-evident, replayable, exportable evidence store — on your machine, with the payloads redacted at the edge — and, with a policy file, allowed, held or denied before it runs.

**The bet:** every mediated tool call produces exactly one record, chained to the previous one, signed, and verifiable offline by the customer with no network access to us — starting with the MCP leg. When an agent does something surprising — or someone claims it did — you can reconstruct exactly what happened, prove the record wasn't altered, and hand a stranger a bundle they can verify with bare Node and no dependencies.

```
BEFORE  {"command": "npx", "args": ["-y", "@some/mcp-server"]}
AFTER   {"command": "npx", "args": ["-y", "@edut/mcp-recorder", "--", "npx", "-y", "@some/mcp-server"]}
```

That's the whole integration. The proxy forwards bytes unchanged, fails open (recording failure never breaks traffic), and adds <5ms p50 latency.

- **License:** GPL-3.0 · **Node:** >= 20 (macOS, Linux, Windows; WSL supported via wsl.exe wrapper) · **Binary:** `mcp-recorder`

**Where this fits.** Governed Tools is four pieces: Okta-brokered identity on the way in, credential-less tools in the middle, mediated egress on the way out, and one signed record across all three. This package is the MCP half of the egress leg and the signed record: the recording proxy, the policy gateway for MCP tool calls, the hash chain, the bundle and the verifier. The identity gate, the per-user credential vault, the HTTPS egress gateway and the manager and security views are the Cresec control plane's job in [cresec-ai/nhi](https://github.com/cresec-ai/nhi) (its share of Roadmap v2 runs through Phases 1–4 and 6; none of it is runnable from a clean checkout today), and this package does not contain them: events here carry an OS username and a hostname, not a named person, and the local credential broker resolves credentials on the agent's own machine rather than injecting a per-user token from a control plane. What this package contributes to the four-week proof of value, week by week and with a status on every capability, is in **[docs/pov.md](docs/pov.md)**; the backlog keyed to Roadmap v2 is in **[docs/roadmap.md](docs/roadmap.md)**.

---

## Install

`@edut/mcp-recorder` is not on npm yet, so `npx -y @edut/mcp-recorder` doesn't
resolve for anyone today. Install from the git repository instead — `npm
install` builds it for you, no manual build step:

```sh
npm install -g github:cresec-ai/audit#main
mcp-recorder --version
```

Then wrap every stdio server in a client's config with one command
(`--dry-run` first to preview):

```sh
mcp-recorder setup --client claude-desktop --dry-run
mcp-recorder setup --client claude-desktop
```

Or hand the whole thing to Claude: give Claude Desktop or Claude Code a
prompt asking it to install from git, run `setup --dry-run`, show you the
diff, then apply it — Claude just needs a shell/terminal or config-file
access to do this for you.

Full instructions (manual JSON edits per client, uninstall, troubleshooting)
are in **[docs/install.md](docs/install.md)** — on Windows, or running from
inside WSL, see its **[Windows and WSL](docs/install.md#windows-and-wsl)**
section first. What the recorder can and cannot see of Claude's built-in
connectors, per surface, and what needs Anthropic, is in
**[docs/connector-coverage.md](docs/connector-coverage.md)**. What deploying
this across a team or a fleet looks like — per agent platform, with what
breaks each one and a rollout order — is in
**[docs/deployment.md](docs/deployment.md)**.

## 60-second quickstart

### 1. Wrap a server

The snippets below use the `npx -y @edut/mcp-recorder` form, which is what
you'll use **once the package is published to npm**. Until then, use the
**local wrapper** form instead — absolute paths to `node` and this
install's `dist/cli.js` — either by running `mcp-recorder setup` (above) or
by hand; see [docs/install.md](docs/install.md#wrap-your-servers) for the
exact before/after JSON for each client.

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
mcp-recorder sessions          # what ran, when, by whom
mcp-recorder ui                # HTML replay timeline in your browser
mcp-recorder verify            # prove the record is intact
mcp-recorder query "AKIA..."   # blast radius: which sessions touched this value?
mcp-recorder export --out evidence.zip   # signed bundle a stranger can verify
mcp-recorder verify --bundle evidence.zip   # what the stranger runs (or `node verify.cjs` inside the bundle)
```

`query` hashes the needle whole, so it matches **exact values, not
substrings**: search `https://attacker.example/collect`, not
`attacker.example`, and the bare tool name (`clickup_filter_tasks`), not the
`mcp__<server>__<tool>` spelling Claude Code shows you.

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
2. **Edge redaction.** Payload strings never reach disk. Each string leaf is replaced by its SHA-256 (`sha256:<hex>`) plus its length — structure preserved, content gone. Object *keys* are redacted too (a map keyed by an email or a secret-shaped string doesn't land in clear either). A tool call's `arguments` are hashed unconditionally, key and position notwithstanding; a small, fixed vocabulary of structural fields (`type`, `role`, `level`, `mimeType`, `protocolVersion`, `method`, and `name` only at `tools[*].name`/`prompts[*].name`) may pass elsewhere, and only when the *value* also looks like that field, not merely because the key matches. Hashes are unsalted *by design*: if you later need to know whether a known value (an API key, a customer email) ever passed through, hash it and search — including a value glued into a longer string, which is tracked separately so it isn't lost inside one opaque leaf hash.
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
| `mcp-recorder [record] [--data-dir D] [--name N] [--identity L] [--redact allowlist\|off] [--policy FILE] -- <server command...>` | Run the wrapped server behind the recording proxy (`record` is the default subcommand and may be omitted). `--name` sets the logical server name, `--identity` an operator label stamped on every event. `--policy FILE` switches on **gateway mode**: `tools/call` requests are allowed / held / denied per the policy and tool results pass through the boundary filter — see [Gateway mode](#gateway-mode-opt-in-enforcement). |
| `mcp-recorder policy validate FILE [--json]` | Validate a `policy.yaml` against the v1 schema (exit 0 valid, 1 invalid, 2 unreadable). See [docs/policy.md](docs/policy.md). |
| `mcp-recorder policy compile FILE [--target rego] [--out DIR]` | Compile a `policy.yaml` to an OPA bundle (`cresec.mcp` / `cresec.egress` Rego modules) for the Cresec control plane; without `--out` the MCP module is printed. |
| `mcp-recorder holds [--data-dir D] [--all] [--json]` | List tool calls currently held for approval by a gateway (`--all` includes decided ones). |
| `mcp-recorder approve <id> [--data-dir D]` / `mcp-recorder deny <id> [--data-dir D]` | Decide a held tool call. `<id>` accepts a unique prefix, the same short id `holds` prints. |
| `mcp-recorder verify [--data-dir D] [--store sqlite\|jsonl] [--bundle PATH] [--public-key K] [--allow-unsigned] [--json]` | Re-walk the hash chain and check head signatures — for the local store, or for an exported bundle with `--bundle` (accepts either form `export` produces: a `.zip` or a bundle directory). `--public-key` pins to a key obtained out of band instead of the default (`<data-dir>/identity.pub`, or the bundle's own manifest key); `--allow-unsigned` downgrades an unsigned chain/tail from a failure to a warning (store mode only — a bundle's own manifest range/signature must always match exactly, see "Security model"). |
| `mcp-recorder query <needle> [--data-dir D] [--store sqlite\|jsonl] [--session ID] [--json]` | Blast radius: hash the needle and find every event and session that touched that value. **Exact values only** — the needle is hashed whole, so a substring, prefix or host part of a URL finds nothing. `--session` accepts a unique id prefix, the same short id `sessions` prints. |
| `mcp-recorder sessions [--data-dir D] [--store sqlite\|jsonl] [--json]` | List recorded sessions: first server, identity, event/tool-call/error counts, then three appended columns — `SERVERS`, the number of distinct servers the session's tool calls went to (`server_count` in `--json`); `DECISIONS`, the number of enforcement actions gateway mode took (`policy_decision_count`); and `LAST_EVENT`, the timestamp of the session's last event (`last_event_at`), which is the instant every count in the row runs through. All three are additive `--json` keys, and each new column is appended after the last, so a column that existed before keeps its position. Tool calls are counted per call, so a hook-captured call (a `pre` + `post` event pair) counts once. `DECISIONS` counts one per deny and one per resolved hold — including a hold the operator approved — so a session recorded without `--policy` reads `0`. `ENDED` shows an end time only when the session's `session_end` really is its last event: a session resumed under the same id keeps recording after its `session_end`, and reads `(reopened)` rather than a superseded end time (`--json` still carries that `ended_at`). `--json` is the stable machine interface; the table is for reading. |
| `mcp-recorder ui [--data-dir D] [--store sqlite\|jsonl] [--session ID] [--port P] [--out FILE] [--no-open] [--public-key K] [--allow-unsigned]` | Serve the HTML replay timeline (or write it to a file with `--out`). Opens your default browser to the served URL unless `--no-open` is set, `--out` is used, or the host looks headless. The integrity banner is resolved the same way as `verify` (same default `identity.pub` pin, same `--public-key`/`--allow-unsigned`), so it never shows green for a chain `verify` would reject. |
| `mcp-recorder export [--data-dir D] [--store sqlite\|jsonl] [--session ID] [--out FILE.zip] [--dir DIR]` | Produce a signed evidence bundle as a ZIP or plain directory. `--session` accepts a unique id prefix, the same short id `sessions` prints. Requires an existing `identity.key` in the data dir — it signs with the key that actually produced the chain, never minting a fresh one, so exit 2 on a data dir with no key (e.g. a store copied without it). |
| `mcp-recorder http --target URL [--port P] [--policy FILE] [--identity-jwt PATH [--identity-jwks PATH\|URL]]` | Recording proxy for HTTP-transport (streamable HTTP) MCP servers. With `--policy` (or `MCP_RECORDER_POLICY`) it is the same gateway `record --policy` is: allow / hold / deny per `tools/call`, the boundary filter on results, a `credentials` section that swaps a synthetic for a real or control-plane-brokered token. `--identity-jwt` stamps the ADR 012 actor claim on every event (both commands, and `hook`). |
| `mcp-recorder setup --client claude-desktop\|claude-code\|cursor [--config PATH] [--wrapper local\|npx\|wsl] [--only N,...] [--except N,...] [--bridge NAME=URL,...] [--data-dir D] [--policy FILE] [--dry-run] [--undo] [--json]` | Wrap every stdio MCP server in a client's config behind the recorder — safely (a timestamped backup + a sidecar recording the originals) and reversibly (`--undo`). `--config` overrides the resolved path (and makes `--client` optional); for `claude-desktop` this also finds a Microsoft Store (MSIX) install on Windows. `--policy FILE` validates the policy up front (exit 2, config untouched, if it is missing or invalid) and bakes `--policy <absolute path>` into every wrapped entry so those servers run in gateway mode — including entries an earlier run already wrapped, which are reported separately as `updated`. `--wrapper local` (default) points at this install's own `dist/cli.js`; `--wrapper npx` writes the published-package form; `--wrapper wsl` writes a `wsl.exe`-launched form for a Windows client whose server should run inside WSL, auto-selected when `setup` runs inside WSL against a Windows-side config (see [docs/install.md#windows-and-wsl](docs/install.md#windows-and-wsl)). `--bridge NAME=URL` turns a remote MCP connector into a local, wrappable entry via `mcp-remote` (see [docs/install.md#connectors-what-the-recorder-can-and-cannot-see](docs/install.md#connectors-what-the-recorder-can-and-cannot-see)). `--dry-run` previews without writing. See [docs/install.md](docs/install.md) for the full walkthrough. |
| `mcp-recorder hook [--data-dir D] [--store sqlite\|jsonl] [--policy FILE] [--client NAME] [--all-tools]` | Claude Code PreToolUse/PostToolUse/PostToolUseFailure/SessionEnd/Stop hook handler: reads one hook JSON object on stdin, records a redacted `tool_call`/`session_*` event, and (PreToolUse only) prints a policy deny decision when `--policy` says to. The only place a third party gets visibility into Anthropic-hosted connectors (`mcp__ClickUp__*`, `mcp__Gmail__*`, ...) that no local MCP proxy can see. Fail-open: never blocks a tool call, never exits non-zero, except a deliberate `--policy` deny. Only `mcp__`-prefixed (MCP) tools are recorded by default; `--all-tools` also records built-ins. See [docs/hooks.md](docs/hooks.md). |
| `mcp-recorder hook install [--settings PATH] [--all-tools] [--policy FILE] [--data-dir D] [--client NAME] [--command CMD] [--dry-run] [--undo] [--json]` | Merge the hook entries above into a Claude Code settings file (default `.claude/settings.json`; created if missing) — safely (timestamped backup) and reversibly (`--undo`), idempotent. `--command` overrides the generated command verbatim (e.g. a repo-relative dogfood form). See [docs/hooks.md](docs/hooks.md). |
| `mcp-recorder ship [--data-dir D] [--sink URL] [--token T | --token-file F] [--drain [--timeout D]] [--idle-exit D] [--status [--json]]` | Replicate sealed chain records to an evidence sink as they are recorded, so evidence stops being something the observed party has to remember to hand over. One shipper per data dir; `record`/`http`/`hook` auto-start it when `MCP_RECORDER_SINK` is set, so you rarely run this yourself. `--drain` ships the backlog and exits (the CI form — use it with `|| true`). `--status` prints sink, key, `chain_id`, local head, receiver `next_seq`, `attested_seq`, lag and the last error/success without touching the network. Before each batch the shipper recomputes its OWN chain up to that batch and stalls, visibly, rather than extending the receiver's copy from a local history that no longer verifies. Fail-open: a sink that is down, slow, 500ing, 401ing or hostile never blocks a tool call, never denies one, never changes a proxy's stdout or exit code, and never loses a local event. See [docs/sink.md](docs/sink.md). |

`--help`/`-h` and `--version`/`-V` work on every invocation.

### Environment variables

| Variable | Effect |
| --- | --- |
| `MCP_RECORDER_DATA_DIR` | Override the data directory (default `~/.mcp-recorder`). |
| `MCP_RECORDER_STORE` | `sqlite` or `jsonl` (default: whichever evidence file already exists in the data dir wins; on a fresh data dir, sqlite when available, else jsonl). |
| `MCP_RECORDER_REDACT` | `allowlist` (default) or `off`. Secret-shaped values are hashed in every mode. |
| `MCP_RECORDER_DISABLE` | `1` → pure passthrough, no recording — and no gateway enforcement either (it is the kill switch). |
| `MCP_RECORDER_POLICY` | Path to a `policy.yaml`; same effect as `record --policy` / `http --policy` when the flag is absent. |
| `MCP_RECORDER_MCP_CONFIG` | `hook` only: the Claude Code MCP config file(s) to resolve server origins from (`server.url`, and the policy alias `mcp__<host>__<tool>`) — one path or comma-separated paths. Default: the cloud session's `/tmp/mcp-config-*.json`. A local machine has no such file and no connector in any `mcpServers` map, so nothing resolves there and only tool-anchored deny rules can fire — see [docs/hooks.md](docs/hooks.md#local-sessions-no-config-file-so-no-serverurl). |
| `MCP_RECORDER_SINK` | Base URL of an evidence sink to replicate sealed records to. **Setting it is the entire opt-in** — with it absent there is no sink, no shipper and byte-identical behaviour to a build without the feature. `https://` only (loopback is the one `http://` exception); `HTTPS_PROXY`/`NO_PROXY` are honoured and certificate verification is never disabled (use `NODE_EXTRA_CA_CERTS` for a proxy CA). See [docs/sink.md](docs/sink.md). |
| `MCP_RECORDER_SINK_TOKEN` | Bearer token for the sink. It authorises the CHANNEL only — records are filed under the data dir's ed25519 key, so a stolen token cannot write into another install's chain, forge events or delete history. |
| `MCP_RECORDER_SINK_TOKEN_FILE` | Same, read from a file, for platforms where a root-owned file is easier to protect than an environment variable. |

---

## The demo

```sh
npm run demo
```

A scripted prompt-injection exfiltration — an agent is tricked into reading a credential and sending it out through an innocent-looking tool — recorded, reconstructed on the replay timeline, blast-radius-queried, and cryptographically verified, in under a minute. It is the fastest way to see what the recorder is for.

Want to see the same story with a real model instead of the scripted agent? [docs/red-team.md](docs/red-team.md) walks through running it live in Claude Desktop.

---

## Gateway mode (opt-in enforcement)

Record mode never interferes with traffic. Pass `--policy policy.yaml` and the same proxy becomes a **gateway**: every `tools/call` is evaluated against ordered per-tool rules (first match wins) and is **allowed** byte-for-byte, **denied** with a tool error the model can read, or **held** until a human runs `mcp-recorder approve <id>` (or a timeout decides). Tool results pass through a **boundary filter** on the way back: secret-shaped values are redacted with `[redacted:sha256:…]` (their hashes stay queryable), and prompt-injection markers are flagged or blocked. Every decision is sealed into the same evidence chain (`policy_decision` events, `tool_call.gateway`, `session_start.policy`).

```yaml
version: 1
mcp:
  default: allow
  rules:
    - { id: no-exfil,   match: { tool: [http_post, "send_*"] }, action: deny, reason: no outbound HTTP }
    - { id: dangerous,  match: { tool: ["delete_*", "rm*"] },   action: hold }
    - { id: no-secrets, match: { tool: read_file, args: { path: "(^|/)(\\.env|id_rsa)$" } }, action: deny }
  boundary: { secrets: redact, injection: flag }
```

```sh
mcp-recorder policy validate policy.yaml
mcp-recorder setup --client claude-desktop --policy /abs/path/policy.yaml
mcp-recorder holds && mcp-recorder approve <id>
mcp-recorder policy compile policy.yaml --out ./bundle     # Rego for the Cresec control plane (OPA)
```

Ten-minute walkthrough for a laptop and for CI: [docs/gateway.md](docs/gateway.md). Full schema, matching semantics and the Rego output: [docs/policy.md](docs/policy.md). What to paste into your agent's `CLAUDE.md` / `AGENTS.md` so it reports a refusal instead of retrying it or reaching the same effect through another tool: [docs/agent-guidance.md](docs/agent-guidance.md). Enforcement fails closed (an unevaluable policy denies) while recording stays fail-open.

**Over HTTP too.** `mcp-recorder http --target https://vendor.example/mcp --policy policy.yaml` is the same gateway in front of a remote (streamable-HTTP) MCP server: the same evaluation, holds, boundary filter and `policy_decision` events, over the HTTP exchange instead of the stdio line. The one thing that changes is buffering: a `tools/call` request body and its result are held long enough to evaluate and filter them (a JSON body whole, an SSE stream one event at a time); without `--policy` the HTTP proxy streams every byte exactly as before. With a `credentials[].broker: { kind: remote }` section the per-user token is fetched from the Cresec control plane per call and swapped at the declared site ([docs/policy.md](docs/policy.md#credentialsbroker--resolved-by-the-control-plane)); with `--identity-jwt` every event carries the ADR 012 actor claim ([docs/event-schema.md](docs/event-schema.md#actor-claim-optional-additive)). Which invariants that touches, and what still does not hold, is in [docs/pov.md](docs/pov.md).

---

## Security model (the honest version)

**What you get: tamper *evidence*, not tamper *prevention*.** Anyone with write access to your disk can delete the store outright. What they cannot do silently is *edit* it: every event is hash-chained, and the head is signed, so any modification, insertion, or deletion inside the recorded range makes `verify` fail loudly.

Read the fine print:

- **Tail truncation.** Deleting events from the end of the chain is detectable only back to the last signed head. The recorder signs the head on every flush, which keeps the unsigned window small, but an attacker who can also delete signatures can roll the chain back to an older signed head. For stronger guarantees, anchor head signatures externally (ship them to another machine, a log, a timestamping service) — the `HeadSignature` records are small and self-contained.
- **An unsigned chain is a failure, not a warning.** `verify` fails (not just warns) when no part of the chain carries a single valid signature, and when the unsigned tail after the newest valid signature contains a `session_end` event — the recorder signs on every flush, *including* the session_end flush, so that signature is missing outright, not merely pending the next one. (Several concurrent recorder processes can interleave sessions in one chain, so this is "the tail contains *any* session_end", not just the latest session's.) A genuine crash mid-session — an unsigned tail with no `session_end` in it — stays a warning: flushes can legitimately outrun head signing. Pass `--allow-unsigned` to downgrade the hard failures back to warnings, e.g. for tooling that needs to tolerate an in-flight session.
- **Unsalted hashes — a deliberate tradeoff.** Redaction refs are plain `sha256(value)`, no salt. This is what makes blast-radius queries possible: hash a candidate value and search for it. The flip side: a party who *already holds* a candidate value (or can enumerate a small space of them) can confirm whether it was seen. The store never leaks values to someone who doesn't already have them, but it does confirm membership to someone who does. If that tradeoff is wrong for your threat model, treat the store itself as sensitive. This applies uniformly to leaf values, object keys, argv elements/credential fingerprints, and tokens embedded inside a larger string — everything `query` can find was hashed the same unsalted way. Say the sharp version of "a small space" out loud: a *low-entropy* secret — a short passphrase, a dictionary word, a token someone typed by hand — is not merely confirmable from its ref, it is **recoverable** from it, by hashing candidates until one matches. Refs protect high-entropy values; they are not a vault for weak ones. That is also why the recorder never fingerprints its own configuration (`MCP_RECORDER_*`, notably the evidence sink's bearer token): the sink ships every event to the receiver that token authenticates to, so a ref of it would hand that receiver a reversible copy of its own credential on every event — and no blast-radius query ever needed it, because the agent never sees it.
- **A `query` miss is not proof of absence.** `query` finds a value if it was hashed as a whole leaf, hashed as an object key, embedded inside a larger leaf as a recognizable secret shape (`secret_refs`, capped at 8 per leaf), or scrubbed out of the wrapped command's argv. A value that never took one of those shapes — folded into a longer plain string under a key the allowlist doesn't recognize, for instance — was still hashed (nothing readable reaches disk either way), there just isn't a standalone ref to search for. Treat a miss as "not found this way", not as "never touched the proxy".
- **The recorder trusts its own key — unless you pin it.** The ed25519 key lives in the data dir (`identity.key` / `identity.pub`). Signing alone proves nothing about *who* signed: an attacker who can rewrite the store can also write a forged chain, sign it with a fresh key of their own, and the signature is cryptographically genuine — it just isn't the operator's. So `verify` pins a specific key rather than trusting whatever key rode along with the data being checked: for a local store it reads `<data-dir>/identity.pub` by default and rejects any signature made by a different key; for an exported bundle it defaults to the bundle's own `manifest.json` key, which only proves the bundle is *internally self-consistent* (an attacker who forges a whole bundle from scratch ships a key that matches itself, so this alone is not third-party assurance). Pass `--public-key <64-hex | path to a hex or PEM file>` — to `mcp-recorder verify` or to the standalone `verify.cjs` shipped inside every bundle — pinned to a key you obtained **out of band** (from the operator directly, never from the artifact you're checking) for real independent verification. None of this protects against a fully compromised host that can rewrite `identity.key`/`identity.pub` together with the chain. If a local store has neither `identity.pub` nor a `--public-key`, `verify` still checks the chain but accepts a signature from *any* key — this is never silent: the human output prints a `WARNING` line and the verdict reads `PASS (unpinned)` (`--json` carries `pinned_public_key: null, unpinned: true`), and `ui`'s integrity banner uses this same pin resolution so it can never show green for a chain `verify` rejects.
- **A bundle is a sealed artifact — its own manifest must match exactly.** `manifest.json`'s `range`/`event_count`/`head_hash`/`signature` are checked against what `events.jsonl` and `public_key.pem` actually contain: any mismatch is an unconditional failure (`bundle_manifest_mismatch` or `signature_invalid`), never downgradable by `--allow-unsigned`. Without this, records self-consistently chained onto the real signed head but appended *after* export — no key needed — would verify as a mere "unsigned tail" warning, since a bundle's manifest is the only thing declaring where the sealed range is supposed to end; a forgery re-signed with an attacker key that ships the operator's genuine `public_key.pem` is caught the same way (the shipped PEM must match the key named in `manifest.signature`). `verify --bundle` and the standalone `verify.cjs` inside every bundle agree on every one of these checks. A `.zip` bundle with a duplicate entry name (e.g. two `events.jsonl`) is rejected outright rather than trusting whichever copy is found first — real unzip tools extract whichever comes *last*, and silently accepting the first would let a genuine copy verify while a forged one gets written to disk.
- **`export` never mints a signing key.** It signs with the *same* key that produced the chain (`Signer.loadExisting`), and exits 2 if `identity.key` is missing from the data dir — e.g. a store copied to another machine without it. The alternative (silently minting a fresh key, which `record` does on a brand-new data dir) would let `export` "succeed" signing with an identity that never touched the evidence, and would repoint the default `identity.pub` pin out from under the next `verify`.
- **A reader that goes away doesn't erase a FAIL.** `verify`'s exit code is decided before anything is printed, so `mcp-recorder verify | head -1` on a failing store still exits 1 — a `SIGPIPE`/`EPIPE` from an early-closing reader can no longer be mistaken for the command's own success.
- **Fail-open means recording can be lost.** By design, if the store breaks mid-session the proxy keeps forwarding and counts dropped events (`events_dropped` in the `session_end` event). Availability of your agent always wins over completeness of the record.
- **A hook `deny` is a policy decision, not a guarantee.** `mcp-recorder hook` can block a Claude Code tool call before it runs, but only when a rule matches the `tool_name` Claude Code hands the hook — and the `mcp__<server>__` segment of that name is the platform's to choose, and has differed between sessions a day apart. In cloud dogfood 4 a policy with two deny rules, one aimed at the resolved host alias and one at the raw UUID form, blocked neither of the two live ClickUp calls it targeted: that session presented them as `mcp__ClickUp__…`, both rules missed, and the resulting 62-event signed bundle (which verifies PASS) contains zero policy decisions — every call was recorded, none was blocked. Write deny rules against the tool with the segment left open (`^mcp__.*__clickup_delete_task$`) and smoke-test them: [docs/hooks.md](docs/hooks.md#write-deny-rules-against-the-tool-not-the-server-segment).

## Event schema

Events follow the frozen schema `edut.mcp-recorder.event.v1`, with field names aligned to OpenTelemetry GenAI/RPC semantic conventions. The full schema — every event kind, every field, the chain construction, and the canonicalization rules — is documented in [docs/event-schema.md](docs/event-schema.md).

## What we explicitly do NOT do

- **No payload storage.** Strings are hashed at the edge — leaf values, object keys, and the wrapped command's argv alike; original values never land in the store. A tool call's `arguments` are hashed unconditionally, regardless of key.
- **No cloud.** Local-first, no telemetry, no phone-home. Evidence leaves your machine only when you run `export`, or when you opt in to an evidence sink by setting `MCP_RECORDER_SINK` (see [docs/sink.md](docs/sink.md)); with that variable unset the recorder opens no connection of its own — the exceptions are the target you name on `http`, and the `github-app`, `aws-sts`, `vault` and `clickup` credential sources, which call out only when your policy's `credentials` section declares them.
- **No enforcement unless you ask for it.** In record mode the recorder observes; it never blocks, rewrites, or rate-limits traffic. It is a recorder, not a firewall. Enforcement exists only in [gateway mode](#gateway-mode-opt-in-enforcement), only with an explicit `--policy`, and only over `tools/call` requests and their results — every other message is still forwarded untouched.

## Development

`npm install`, then `npm run typecheck && npm run lint && npm test` before sending a PR. `npm run lint:fix` applies the auto-fixable subset.

## License

GPL-3.0. The recorder sits in your trust path, so you should be able to read every line of it — and so should everyone downstream of any fork.

## Built in the open — one design partner wanted

This project is being built in public. We are looking for one design partner for a four-week proof of value of Governed Tools: an Okta admin, a Salesforce admin to approve one connected app, a Google Workspace admin to allowlist one OAuth app, one rep with a working Claude routine and two hours, and a named tool owner. Three admin actions from you, zero production traffic rerouted, no capture SDK, no UI built by us. Week 1 is a read-only before-number from your Okta and Salesforce (or Google Workspace) audit logs; week 3 ends with one signed evidence bundle your security team verifies with bare Node and no network access to us. What happens each week, what this package contributes, and what we do not claim is in [docs/pov.md](docs/pov.md); the scope is on the [Governed Tools story page](https://app.clickup.com/90182720801/docs/2kzmy791-558/2kzmy791-618). Open an issue on this repository to start the conversation.
