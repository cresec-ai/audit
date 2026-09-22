#!/usr/bin/env node
/**
 * mcp-recorder CLI — subcommand dispatch.
 *
 * record / http modes NEVER print to stdout (stdout is the MCP wire);
 * diagnostics go to stderr prefixed "[mcp-recorder]". Inspection commands
 * (verify/query/sessions) print human or --json output on stdout.
 *
 * Exit codes: 0 ok (record/http: the wrapped server's code), 1 verification
 * failed / nothing to export, 2 usage or unexpected error.
 */
import { spawn } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';
import { sha256Hex } from './chain/hash.js';
import { openConfiguredStore, setupProxyRecording } from './capture/setup.js';
import { Signer, publicKeyHexFromPem } from './chain/keys.js';
import { ensureDataDir, resolveConfig, resolveConfigLenient } from './config.js';
import { BUNDLE_FILES, exportBundle } from './export/bundle.js';
import { readZipEntries } from './export/unzip.js';
import { HoldError, HoldStore } from './gateway/holds.js';
import { credentialSwapFromPolicy, identityJwtEnvFromPolicy } from './broker/wire.js';
import { IdentityJwtError, loadActor } from './identity/actor.js';
import { PolicyLoadError, parsePolicyText, sourceForPath } from './policy/load.js';
import { STARTER_RULE_COUNTS, materialiseStarterPolicy, starterHookPolicyPath, starterPolicyPath } from './policy/starter.js';
import { STALE_SESSION_CODE, doctorExitCode, doctorVerdictLines, renderDoctor, runDoctor } from './doctor/run.js';
import { bundleFileOrder, compileToRego } from './policy/rego.js';
import { detectLeg, smokeGateway, smokeHook } from './policy/smoke.js';
import { parsePolicy as parseHookPolicy } from './hook/policy.js';
import { parseToolName as parseHookToolName } from './hook/names.js';
import { formatPolicyErrors, validatePolicyObject } from './policy/validate.js';
import { buildHookCommand, planHookInstall, planHookUndo } from './hook/install.js';
import { runHook } from './hook/run.js';
import { runHttpProxy } from './proxy/http.js';
import { runStdioProxy } from './proxy/stdio.js';
import { toolCensus } from './query/census.js';
import { queryStore } from './query/touched.js';
import { resolveSinkConfig } from './sink/config.js';
import { runShipper } from './sink/shipper.js';
import { acquireShipLock, readCursorCache, readShipStatus, shipperLooksAlive, } from './sink/state.js';
import { renderTimelineHtml } from './replay/render.js';
import { serveUi } from './replay/serve.js';
import { CLIENT_KINDS, isClientKind, resolveClientConfigPath } from './setup/client-config.js';
import { detectEol, detectIndent, readSidecarStrict, removeSidecar, sidecarPath, stripBom, writeBackup, writeJsonAtomic, writeSidecarAtomic, } from './setup/io.js';
import { chooseWrapper, detectWsl, isWindowsMountPath, windowsHomeCandidates } from './setup/wsl.js';
import { bridgeEntry, isAlreadyWrapped, isSameBridgeEntry, parseBridgeSpecs, planWrap, structuralUnwrap, } from './setup/wrap.js';
import { ENV, FILES } from './types.js';
import { verifyRecords, verifyStore } from './verify/verify.js';
import { VERSION } from './version.js';
const SUBCOMMANDS = [
    'protect',
    'doctor',
    'why',
    'record',
    'verify',
    'query',
    'sessions',
    'ui',
    'export',
    'http',
    'setup',
    'policy',
    'holds',
    'approve',
    'deny',
    'hook',
    'ship',
];
const HELP = `@edut/mcp-recorder v${VERSION} — a gate in front of every tool call your agent makes, and a signed record of every one of them

Start here:
  mcp-recorder protect --client <claude-desktop|claude-code|cursor>
      ONE COMMAND, NOTHING TO AUTHOR. Installs the starter policy
      (<data-dir>/policy.starter.yaml — 4 deny rules, 3 hold-for-approval
      rules, everything else runs), wraps every stdio server in the client's
      config behind this gateway, installs the Claude Code hook for the
      hosted connectors no local proxy can see, and finishes by running
      'doctor' so the last line on screen is a MEASUREMENT of whether
      enforcement is in force, not a claim that it is. The policy file is
      yours from that moment: edit it, or delete it and pass --policy of
      your own. A second run never overwrites your edits.
      Then fully quit and restart your client, and ask your agent to do
      something it should not.
  mcp-recorder doctor  [--client NAME] [--config PATH] [--no-probe] [--json]
      is enforcement ACTUALLY in force, right now? Six checks, each
      OK / FAIL / INCOMPLETE — a check that could not run NEVER passes.
      It reads the wiring, the hook, and every tool your servers really
      expose, pushes one live denied call through the real code path, and
      FAILS when the policy matches nothing (which no other command
      reports) or when a deny rule is anchored to one spelling of a tool
      name the client is free to change. Exit 0 ok, 1 failed, 3 incomplete.
  mcp-recorder why     [--data-dir D] [--limit N] [--session ID] [--json]
      what was stopped, why, and how to change it. Read-only over the
      evidence chain; prints no argument or result text, only tool names,
      rule ids and the reasons out of your own policy file. This is the
      person's side of the boundary: the agent's refusal deliberately does
      NOT tell the model how to relax a rule

Then, the evidence underneath:
  mcp-recorder sessions [--data-dir D] [--json]      what ran, and how many decisions
  mcp-recorder verify   [--data-dir D] [--json]      the chain + head signatures
  mcp-recorder ui       [--data-dir D]               replay timeline in a browser
  mcp-recorder export   [--out FILE.zip]             a bundle a stranger can verify

Everything else:
  mcp-recorder [record] [flags] [--policy FILE | --protect] -- <server command...>
      transparent stdio proxy: forwards bytes unchanged, records redacted events.
      With --policy FILE (or MCP_RECORDER_POLICY, or --protect for the
      starter policy) it becomes a GATEWAY: every tools/call is allowed /
      held / denied per the policy and tool results pass through the
      boundary filter (see docs/gateway.md). A policy that cannot be loaded
      exits 2 before the server is spawned (fail closed). WITHOUT one of
      those flags nothing is enforced and the proxy is byte-for-byte what it
      has always been — no flag ever starts enforcing on its own, and a
      starter policy sitting in the data directory is not an input
  mcp-recorder policy validate FILE [--json]
      check a policy.yaml against schema v1 (exit 0 valid, 1 invalid, 2 unreadable)
  mcp-recorder policy compile FILE [--target rego] [--out DIR]
      compile a policy.yaml to an OPA bundle for the Cresec control plane;
      without --out the MCP module (cresec/mcp/...) is printed to stdout
  mcp-recorder policy test FILE --tool NAME [--server S] [--args JSON]
                           [--leg gateway|hook] [--expect allow|deny|hold] [--json]
      the deny-rule smoke test: what this policy decides for one tool name,
      spelled exactly as observed, through the same engine the gateway
      (policy.yaml) or the hook (its JSON policy) uses. The leg is detected
      from the file. On the hook leg it also checks every other server
      segment a client could choose and warns when the verdict changes.
      Exit 0 evaluated, 1 --expect not met (on the hook leg: under EVERY
      spelling) or invalid policy, 2 usage/unreadable
  mcp-recorder holds    [--data-dir D] [--all] [--json]
      list tools/call requests a gateway is holding for approval
      (--all includes decided / expired ones)
  mcp-recorder approve  <id> [--data-dir D]
  mcp-recorder deny     <id> [--data-dir D]
      decide a held call; <id> may be a unique prefix, as 'holds' prints it
  mcp-recorder verify   [--data-dir D] [--bundle PATH] [--public-key K] [--allow-unsigned] [--json]
      verify the hash chain + head signatures (exit 1 on failure); --bundle
      accepts a .zip or a bundle directory. By default pins to
      <data-dir>/identity.pub (store mode) or the bundle's own manifest key
      (bundle mode); --public-key overrides either with a key obtained out
      of band (64-hex, or a path to a hex or PEM file)
  mcp-recorder query    <needle> [--data-dir D] [--session ID] [--json]
      blast radius: trace a value through the evidence chain
  mcp-recorder sessions [--data-dir D] [--json]
      list recorded sessions
  mcp-recorder sessions --tools [--data-dir D] [--session ID] [--json]
      per-server, per-tool census of what was actually called: calls,
      errors, denied, held, how many sessions, last seen
  mcp-recorder ui       [--data-dir D] [--session ID] [--port N] [--out FILE] [--no-open]
                        [--public-key K] [--allow-unsigned]
      replay timeline (local web UI, opened in your browser unless --no-open
      or --out is given; or --out FILE for a static page). The integrity
      banner uses the same pin as 'verify' (identity.pub by default)
  mcp-recorder export   [--data-dir D] [--session ID] [--out FILE.zip] [--dir DIR]
      signed evidence bundle a stranger can verify with plain Node.js
  mcp-recorder http     --target URL [--port N] [--policy FILE] [flags]
      transparent streamable-HTTP proxy in front of an HTTP MCP server.
      With --policy FILE (or MCP_RECORDER_POLICY) it is a GATEWAY like
      'record --policy': tools/call requests are allowed / held / denied,
      results pass the boundary filter, and a 'credentials' section swaps
      a synthetic for a real (or control-plane brokered) token. Only then
      are tools/call bodies and results buffered; everything else streams
  mcp-recorder setup    --client <claude-desktop|claude-code|cursor> [--config PATH]
                        [--wrapper local|npx|wsl] [--only N,...] [--except N,...]
                        [--bridge NAME=URL,...] [--data-dir D] [--policy FILE] [--dry-run] [--undo] [--json]
      wrap every stdio MCP server in a client's config behind this recorder,
      safely (timestamped backup + sidecar) and reversibly (--undo). --config
      overrides the resolved path and makes --client optional. For
      claude-desktop this also finds a Microsoft Store (MSIX) install when
      the ordinary %APPDATA%\\Claude\\... config doesn't exist. --policy FILE
      validates the policy and bakes '--policy <absolute path>' into every
      wrapped entry (gateway mode) — entries an earlier run already wrapped
      are updated in place and reported separately. Inside WSL, when the
      resolved config belongs to a Windows-side client, --wrapper wsl is auto-selected
      (spawns the wrapped server via wsl.exe so a Windows client can actually
      launch it) unless --wrapper is given.
      --bridge NAME=URL turns a remote MCP connector (one Claude Desktop
      would otherwise reach from Anthropic's own servers, never touching
      this machine) into a local entry via 'npx -y mcp-remote URL', then
      wraps that like any other stdio server
  mcp-recorder hook     [--data-dir D] [--store B] [--policy FILE] [--client NAME] [--all-tools]
      Claude Code PreToolUse/PostToolUse/PostToolUseFailure/SessionEnd/Stop
      hook handler: reads one hook JSON object on stdin, records a redacted
      tool_call/session_* event, and (PreToolUse only) prints a policy deny decision when
      --policy says to. This is the ONLY place a third party gets visibility
      into Anthropic-hosted connectors (mcp__ClickUp__*, mcp__Gmail__*, ...)
      that no local MCP proxy can see. Recording is fail-open: it never blocks
      a tool call and never exits non-zero. Enforcement is fail-closed: a
      --policy that cannot be read or parsed denies what it governs until it
      is fixed. Only mcp__-prefixed (MCP) tools are recorded by default;
      --all-tools also records built-ins (Bash, Edit, ...). See docs/hooks.md.
  mcp-recorder hook install [--settings PATH] [--all-tools] [--policy FILE]
                        [--data-dir D] [--client NAME] [--command CMD]
                        [--dry-run] [--undo] [--json]
      merge PreToolUse/PostToolUse/PostToolUseFailure (matcher mcp__.* or .*
      with --all-tools) and SessionEnd/Stop hook entries running 'hook' into a Claude Code
      settings file (default .claude/settings.json in cwd; created if
      missing), safely (timestamped backup) and reversibly (--undo).
      --command overrides the generated command verbatim (e.g. a
      repo-relative dogfood form)
  mcp-recorder ship     [--data-dir D] [--sink URL] [--token T | --token-file F]
                        [--drain [--timeout 30s]] [--idle-exit 15m] [--status [--json]]
      replicate sealed chain records to an evidence sink as they are
      recorded, so evidence is no longer something the observed party has to
      remember to hand over. One shipper per data dir (<data-dir>/ship.lock);
      record/http/hook auto-start it when a sink is configured, so you rarely
      run this yourself. --drain ships the backlog and exits (the CI form:
      put it in a final step with '|| true' — a sink outage must never fail a
      build). --status prints sink, key, chain_id, local head, receiver
      next_seq, attested_seq, lag and the last error/success, without
      touching the network.
      Fail-open: a sink that is down, slow, 500ing, 401ing or hostile never
      blocks a tool call, never denies one, never changes a proxy's stdout or
      exit code, and never loses a local event. The local store stays the
      source of truth; the sink is a replica.
  mcp-recorder --help | --version

Flags:
  --data-dir D    evidence directory (default ~/.mcp-recorder; env MCP_RECORDER_DATA_DIR)
  --store B       evidence backend: sqlite | jsonl     (env MCP_RECORDER_STORE)
  --redact M      redaction mode: allowlist | off      (env MCP_RECORDER_REDACT)
  --name NAME     logical server name stamped on events
  --identity L    operator identity label stamped on events
  --policy FILE   record / http: policy.yaml to enforce (gateway mode; env MCP_RECORDER_POLICY)
                   setup: bake '--policy <absolute FILE>' into every wrapped entry,
                   already-wrapped ones included
  --protect       record / http: enforce <data-dir>/policy.starter.yaml, for a
                   hand-edited client config. It NEVER writes that file —
                   missing is exit 2 before the server is spawned, naming
                   'mcp-recorder protect', which is the only thing that
                   writes one. With --policy as well it is exit 2: you chose both
  --no-probe      doctor: skip the live denied call (C5 is then INCOMPLETE, never OK)
  --limit N       why: how many decisions to print (default 5)
  --identity-jwt PATH
                   record / http / hook: a file holding the identity JWT the
                   Cresec control plane minted for the signed-in person; its
                   claims become the 'actor' block (user, tool, host, run_as)
                   on every event and key the per-user token requests of a
                   'credentials[].broker: { kind: remote }' policy. Decoded,
                   NOT verified, unless --identity-jwks is given (the events
                   say so: identity.actor_verified is false)
  --identity-jwks PATH|URL
                   verify the identity JWT's EdDSA signature against this
                   JWKS ({ keys: [...] }); a token that does not verify is a
                   startup error (exit 2)
  --target T      policy compile: output target, only 'rego' (default)
                   http: the upstream MCP server URL
  --all           holds: include decided / expired holds, not just pending ones
  --session ID    select a session (query / ui / export / sessions --tools); a unique prefix of
                   the id works too, same as the ids 'sessions' prints
  --public-key K  pin verify to this ed25519 key instead of the default
                   (64-hex, or a path to a file holding hex or a PEM)
  --allow-unsigned
                   verify: downgrade an unsigned chain/tail to a warning
                   instead of a failure (still reported, never silent)
  --json          machine-readable output (verify / query / sessions / setup / policy validate / policy test / holds)
  --tools         sessions: one row per (server, tool) instead of per session
  --tool NAME     policy test: the tool name to evaluate, exactly as observed
  --server S      policy test (gateway leg): the server the call goes to
  --args JSON     policy test (gateway leg): the call's arguments object
  --leg L         policy test: gateway | hook (default: detected from the file)
  --expect A      policy test: exit 1 unless the verdict is A (allow | deny | hold)
  --client NAME   protect / doctor / setup: claude-desktop | claude-code | cursor
                   hook / hook install: logical client name stamped on events
                   (default 'claude-code')
  --config PATH   setup: config file to edit (overrides --client's default)
  --wrapper W     setup: local (default, this install) | npx (published form) |
                   wsl (wsl.exe, auto-selected for a Windows-side config in WSL)
  --only N,...    setup: wrap only these server names
  --except N,...  setup: wrap every server except these names
  --bridge NAME=URL[,...]
                   setup: bridge a remote MCP connector as a local NAME
                   entry (via npx -y mcp-remote URL), repeatable
  --dry-run       setup / hook install: print what would change; write nothing
  --undo          setup / hook install: undo what this tool added
  --policy FILE   hook / hook install: PreToolUse allow/deny policy JSON (see docs/hooks.md)
  --all-tools     hook / hook install: also record built-in tools (Bash,
                   Edit, ...), not just mcp__-prefixed MCP tools
  --settings PATH hook install: settings file to edit (default
                   .claude/settings.json in cwd)
  --command CMD   hook install: override the generated hook command verbatim
  --sink URL      evidence sink base URL (env MCP_RECORDER_SINK); https only,
                   loopback is the only http exception. Setting it is the
                   whole opt-in — absent, nothing changes at all
  --token T       sink bearer token                 (env MCP_RECORDER_SINK_TOKEN)
  --token-file F  read the bearer token from a file (env MCP_RECORDER_SINK_TOKEN_FILE)
  --drain         ship: ship the backlog and exit, for short-lived CI runners
  --timeout D     ship --drain: wall-clock budget (default 30s)
  --idle-exit D   ship: exit after this long with no new records and no
                   delivery (default 15m; 0 keeps it running, for a
                   supervised systemd/launchd unit)
  --status        ship: print sink/key/chain/lag/last error and exit
  --help, -h      show this help and exit
  --version, -V   show the version and exit

Environment:
  MCP_RECORDER_DISABLE=1   pure passthrough, nothing recorded — and no gateway
                           enforcement either (it is the kill switch)
  MCP_RECORDER_POLICY=F    same as 'record --policy F' / 'http --policy F' when
                           the flag is absent
  MCP_RECORDER_MCP_CONFIG=PATH[,PATH...]
                           hook: Claude Code MCP config file(s) to resolve
                           server origins (server.url, policy alias
                           mcp__<host>__<tool>) from; default: the cloud
                           session's /tmp/mcp-config-*.json (see docs/hooks.md)
  MCP_RECORDER_SINK=URL    replicate sealed records to this evidence sink.
                           SETTING IT IS THE ENTIRE OPT-IN — with it absent
                           there is no sink, no shipper, and behaviour is
                           byte-identical to a build without the feature
  MCP_RECORDER_SINK_TOKEN=T        bearer token for the sink
  MCP_RECORDER_SINK_TOKEN_FILE=F   ...or a file holding it, for platforms
                           where a root-owned file is easier to protect than
                           an environment variable
  HTTPS_PROXY / NO_PROXY / NODE_EXTRA_CA_CERTS
                           honoured by the shipper (node:https does not read
                           the first two itself). Certificate verification is
                           never disabled — point NODE_EXTRA_CA_CERTS at the
                           proxy's CA instead
`;
const FLAG_DEFS = {
    'data-dir': { type: 'string' },
    store: { type: 'string' },
    redact: { type: 'string' },
    name: { type: 'string' },
    identity: { type: 'string' },
    session: { type: 'string' },
    port: { type: 'string' },
    out: { type: 'string' },
    dir: { type: 'string' },
    bundle: { type: 'string' },
    target: { type: 'string' },
    'public-key': { type: 'string' },
    'allow-unsigned': { type: 'boolean' },
    json: { type: 'boolean' },
    'no-open': { type: 'boolean' },
    client: { type: 'string' },
    config: { type: 'string' },
    wrapper: { type: 'string' },
    only: { type: 'string' },
    except: { type: 'string' },
    bridge: { type: 'string', multiple: true },
    'dry-run': { type: 'boolean' },
    undo: { type: 'boolean' },
    policy: { type: 'string' },
    protect: { type: 'boolean' },
    probe: { type: 'boolean' },
    'no-probe': { type: 'boolean' },
    limit: { type: 'string' },
    'identity-jwt': { type: 'string' },
    'identity-jwks': { type: 'string' },
    all: { type: 'boolean' },
    'all-tools': { type: 'boolean' },
    settings: { type: 'string' },
    command: { type: 'string' },
    sink: { type: 'string' },
    token: { type: 'string' },
    'token-file': { type: 'string' },
    drain: { type: 'boolean' },
    status: { type: 'boolean' },
    timeout: { type: 'string' },
    'idle-exit': { type: 'string' },
    surface: { type: 'string' },
    tools: { type: 'boolean' },
    tool: { type: 'string' },
    server: { type: 'string' },
    args: { type: 'string' },
    expect: { type: 'string' },
    leg: { type: 'string' },
    help: { type: 'boolean', short: 'h' },
    version: { type: 'boolean', short: 'V' },
};
/* -------------------------------- helpers ------------------------------- */
function err(msg) {
    throw new Error(msg);
}
function diag(msg) {
    try {
        process.stderr.write(`[mcp-recorder] ${msg}\n`);
    }
    catch {
        /* even diagnostics are fail-open */
    }
}
/**
 * Last-resort safety net for record/http mode: an exception that somehow
 * escapes every other fail-open guard must never take the wrapped server's
 * traffic down with it. Logs once, best-effort, and keeps the process alive.
 */
let uncaughtGuardInstalled = false;
let uncaughtLogged = false;
function installUncaughtExceptionGuard() {
    if (uncaughtGuardInstalled)
        return;
    uncaughtGuardInstalled = true;
    process.on('uncaughtException', (error) => {
        if (uncaughtLogged)
            return;
        uncaughtLogged = true;
        const detail = error instanceof Error ? (error.stack ?? error.message) : String(error);
        diag(`uncaught exception (recording degraded, traffic unaffected): ${detail}`);
    });
}
function out(msg) {
    process.stdout.write(msg + '\n');
}
function asStr(v) {
    return typeof v === 'string' ? v : undefined;
}
/** `--bridge` collects into a string[] (`multiple: true`); every other flag
 * this returns undefined for, same as `asStr` does for a non-string. */
function asStrArr(v) {
    return Array.isArray(v) ? v : [];
}
function parsePort(v) {
    const s = asStr(v);
    if (s === undefined)
        return undefined;
    const n = Number(s);
    if (!Number.isInteger(n) || n < 0 || n > 65535)
        err(`invalid --port '${s}'`);
    return n;
}
const HEX64 = /^[0-9a-f]{64}$/i;
/**
 * Resolve `verify --public-key <value>` to a 64-hex raw ed25519 public key.
 * `value` is either the hex itself, or a path to a file holding either the
 * hex or an SPKI PEM (the same file identity.pub or public_key.pem already
 * are) — this is how a third party pins a key they obtained out of band,
 * rather than trusting whatever key ships alongside the data being checked.
 */
function resolvePublicKeyArg(value) {
    const trimmed = value.trim();
    if (HEX64.test(trimmed))
        return trimmed.toLowerCase();
    let content;
    try {
        content = readFileSync(resolve(trimmed), 'utf8');
    }
    catch (cause) {
        const msg = cause instanceof Error ? cause.message : String(cause);
        return err(`--public-key '${value}' is neither 64-hex nor a readable file: ${msg}`);
    }
    const text = content.trim();
    if (HEX64.test(text))
        return text.toLowerCase();
    if (text.includes('BEGIN PUBLIC KEY')) {
        try {
            return publicKeyHexFromPem(text);
        }
        catch (cause) {
            const msg = cause instanceof Error ? cause.message : String(cause);
            return err(`--public-key file '${value}' is not a valid ed25519 public key PEM: ${msg}`);
        }
    }
    return err(`--public-key file '${value}' is neither 64-hex nor a PEM public key`);
}
function formatTable(headers, rows) {
    const widths = headers.map((h, i) => Math.max(h.length, ...rows.map((r) => (r[i] ?? '').length)));
    const line = (cells) => cells.map((c, i) => (c ?? '').padEnd(widths[i] ?? 0)).join('  ').trimEnd();
    return [line(headers), ...rows.map(line)].join('\n');
}
function id8(id) {
    return id.slice(0, 8);
}
/**
 * Resolve `--session` against the store's session list: an exact id, or a
 * unique prefix of the kind `sessions`/`query`/run summaries print (8 chars
 * onward). An ambiguous or unmatched prefix is a usage error (exit 2) that
 * names the candidates, rather than export's exact-match ENOTFOUND or
 * query's silent zero matches.
 */
function resolveSessionId(store, raw) {
    if (raw === undefined)
        return undefined;
    const sessions = store.sessions();
    const exact = sessions.find((s) => s.session_id === raw);
    if (exact !== undefined)
        return exact.session_id;
    const matches = sessions.filter((s) => s.session_id.startsWith(raw));
    if (matches.length === 1)
        return matches[0].session_id;
    if (matches.length > 1) {
        err(`--session '${raw}' is ambiguous — it matches ${matches.length} sessions: ` +
            matches.map((s) => id8(s.session_id)).join(', '));
    }
    err(`--session '${raw}' matches no recorded session`);
}
/**
 * Quiet exit on EPIPE (e.g. `mcp-recorder verify | head -1`) instead of the
 * default uncaught-exception stack trace — the reader going away early isn't
 * a failure of the command that was writing to it.
 */
function guardStdoutEpipe() {
    process.stdout.on('error', (cause) => {
        // Exit with whatever code the command had already decided on (e.g.
        // cmdVerify sets process.exitCode = 1 for a FAILing chain BEFORE it
        // prints) rather than hardcoding 0 — otherwise `verify | head -1` on a
        // failing store would report success just because the reader went away
        // mid-write.
        if (cause.code === 'EPIPE')
            process.exit(process.exitCode ?? 0);
        throw cause;
    });
}
/**
 * Best-effort browser open for `ui`'s served URL. Fire-and-forget: never
 * awaited, and any failure (missing opener, spawn error) is swallowed — it
 * must never affect the command's behavior or exit code. Skipped outright on
 * a headless Linux host (no DISPLAY/WAYLAND_DISPLAY), since spawning
 * xdg-open there has nothing to open and would just error.
 */
function tryOpenBrowser(url) {
    if (process.platform !== 'darwin' &&
        process.platform !== 'win32' &&
        process.env.DISPLAY === undefined &&
        process.env.WAYLAND_DISPLAY === undefined) {
        return;
    }
    const [cmd, args] = process.platform === 'darwin'
        ? ['open', [url]]
        : process.platform === 'win32'
            ? ['cmd', ['/c', 'start', '""', url]]
            : ['xdg-open', [url]];
    try {
        const child = spawn(cmd, args, { detached: true, stdio: 'ignore' });
        child.on('error', () => {
            /* best-effort: no opener available on this host — nothing to do */
        });
        child.unref();
    }
    catch {
        /* best-effort: never fatal to the ui command */
    }
}
function writeRunSummary(setup) {
    const stats = setup.stats();
    const sid = setup.sessionId();
    diag(`session ${sid !== undefined ? id8(sid) : '--------'} recorded ${stats.written} events ` +
        `(${stats.dropped} dropped) -> ${setup.storePath ?? '(recording disabled)'}`);
}
/**
 * Block until SIGINT/SIGTERM. Holds the event loop open itself (signal
 * listeners alone do not), so it also covers unref()'d servers like the UI's.
 *
 * The listeners are installed synchronously, when this is CALLED — so call
 * it before printing "(Ctrl-C to stop)", not after. A process that announces
 * itself first and arms the handler second has a window in which a SIGINT
 * kills it with the default disposition (exit 130, no clean close, no run
 * summary), and a script or test that reacts to the announcement lands in
 * that window often enough to matter.
 */
function waitForShutdownSignal() {
    return new Promise((resolveWait) => {
        const keepAlive = setInterval(() => {
            /* keep the event loop alive */
        }, 60_000);
        const onSignal = () => {
            clearInterval(keepAlive);
            resolveWait();
        };
        process.once('SIGINT', onSignal);
        process.once('SIGTERM', onSignal);
    });
}
/**
 * `--policy FILE`, else `MCP_RECORDER_POLICY`, resolved to an absolute path
 * (record is launched by MCP clients from arbitrary working directories).
 * Empty values count as absent.
 */
function resolvePolicyPath(flags, env, dataDir) {
    const flag = asStr(flags.policy);
    const wantsProtect = flags.protect === true;
    if (wantsProtect && flag !== undefined && flag !== '') {
        err("--protect and --policy both select a policy: pass one. --protect means --policy <data-dir>/policy.starter.yaml");
    }
    if (wantsProtect) {
        if (dataDir === undefined)
            err('--protect needs a data directory to find the starter policy in');
        return starterPolicyPath(dataDir);
    }
    const raw = flag !== undefined && flag !== '' ? flag : env[ENV.POLICY];
    if (raw === undefined || raw === '')
        return undefined;
    return resolve(raw);
}
/** Read + parse + validate a policy file. Throws (exit 2) only when the file cannot be read. */
function readPolicyForCli(path, what) {
    let bytes;
    try {
        bytes = readFileSync(path);
    }
    catch (cause) {
        const msg = cause instanceof Error ? cause.message : String(cause);
        return err(`${what}: cannot read policy file ${path}: ${msg}`);
    }
    const source = sourceForPath(path);
    let doc;
    try {
        doc = parsePolicyText(bytes.toString('utf8'), source, path);
    }
    catch (cause) {
        if (!(cause instanceof PolicyLoadError))
            throw cause;
        // PolicyLoadError messages are "<path>: <detail>"; keep just the detail
        // so the error line reads like every other "<pointer>: <message>" one.
        const prefix = `${path}: `;
        const detail = cause.message.startsWith(prefix) ? cause.message.slice(prefix.length) : cause.message;
        return { ok: false, errors: [{ path: '', message: detail, keyword: source }] };
    }
    const result = validatePolicyObject(doc);
    if (!result.ok)
        return { ok: false, errors: result.errors };
    const loaded = { policy: result.policy, hash: 'sha256:' + sha256Hex(bytes), source, path };
    if (result.policy.name !== undefined)
        loaded.name = result.policy.name;
    return { ok: true, loaded };
}
/** "  <pointer>: <message>" lines, one per error, for the human output. */
function indentedPolicyErrors(errors) {
    return formatPolicyErrors(errors)
        .split('\n')
        .map((line) => `  ${line}`);
}
/**
 * Load the policy a gateway will enforce. FAIL CLOSED: any problem is a
 * usage error (exit 2) raised BEFORE the wrapped server is spawned — a
 * broken or missing policy must never silently degrade to "allow
 * everything". A policy without an `mcp` section has nothing the stdio
 * gateway could enforce, so it is refused the same way.
 */
function loadGatewayPolicy(path) {
    const read = readPolicyForCli(path, 'policy');
    if (!read.ok) {
        const n = read.errors.length;
        return err(`policy: ${path}: invalid policy (${n} error${n === 1 ? '' : 's'})\n` +
            indentedPolicyErrors(read.errors).join('\n'));
    }
    if (read.loaded.policy.mcp === undefined) {
        return err(`policy: ${path}: policy has no \`mcp\` section — nothing for the gateway to enforce`);
    }
    return read.loaded;
}
/* ------------------------------ subcommands ------------------------------ */
/**
 * The identity JWT (`--identity-jwt PATH`, else the env var a remote
 * credential's `identity_jwt_env` names), decoded — and verified when
 * `--identity-jwks` is given. FAIL CLOSED like the policy: a JWT the
 * operator supplied and the recorder cannot read, or asked to have verified
 * and cannot, is exit 2 before anything is spawned, never a session that
 * quietly records no actor. Absent both, `undefined`: events carry no
 * `actor`, which is the honest unattributed state.
 */
async function resolveActor(flags, policy, what) {
    const jwtPath = asStr(flags['identity-jwt']);
    const jwks = asStr(flags['identity-jwks']);
    const jwtEnv = policy === undefined ? undefined : identityJwtEnvFromPolicy(policy.policy);
    const jwtFromEnv = jwtEnv === undefined ? undefined : process.env[jwtEnv];
    try {
        const loaded = await loadActor({
            ...(jwtPath !== undefined && jwtPath !== '' ? { jwtPath: resolve(jwtPath) } : {}),
            ...(jwtFromEnv !== undefined && jwtFromEnv !== '' ? { jwt: jwtFromEnv } : {}),
            ...(jwks !== undefined && jwks !== '' ? { jwks: /^https?:\/\//i.test(jwks) ? jwks : resolve(jwks) } : {}),
        });
        if (loaded === undefined) {
            if (jwks !== undefined && jwks !== '')
                err(`${what}: --identity-jwks needs an identity JWT (--identity-jwt PATH, or the policy's identity_jwt_env)`);
            return undefined;
        }
        diag(`identity: actor ${loaded.actor.user.email} via ${loaded.actor.tool.name}@${loaded.actor.tool.version}` +
            ` (run_as ${loaded.actor.run_as}; ${loaded.verified ? 'signature verified' : 'NOT verified: decoded only'})`);
        return loaded;
    }
    catch (cause) {
        if (cause instanceof IdentityJwtError)
            return err(`${what}: ${cause.message}`);
        throw cause;
    }
}
/**
 * Gateway mode is the ONE deliberate exception to fail-open, and it is
 * decided here, before any store is opened or any process spawned: an
 * operator who asked for enforcement gets enforcement or a clear exit 2.
 * MCP_RECORDER_DISABLE=1 is the documented kill switch — it turns the
 * gateway off along with recording (pure passthrough, said out loud).
 * Shared by `record` and `http`, which enforce the same policy the same way.
 */
async function resolveGateway(flags, config, what) {
    const policyPath = resolvePolicyPath(flags, process.env, config.dataDir);
    if (policyPath === undefined) {
        const loaded = await resolveActor(flags, undefined, what);
        return loaded === undefined ? {} : { actor: loaded };
    }
    if (config.disabled) {
        diag(`MCP_RECORDER_DISABLE=1 — gateway disabled too (kill switch): policy ${policyPath} is NOT enforced, ` +
            'pure passthrough');
        return {};
    }
    // `--protect` NEVER WRITES the starter policy. Materialising it here would
    // put a file write on the pre-spawn path, give `record` a new way to fail
    // before the server starts, and let a flag silently mint the policy it then
    // enforces. Missing is exit 2 before spawn — the same fail-closed shape
    // `loadGatewayPolicy` already has for a missing `--policy`, with a message
    // that names the one command that does write it.
    if (flags.protect === true && !existsSync(policyPath)) {
        err(`${what} --protect: no starter policy at ${policyPath} — run 'mcp-recorder protect' first ` +
            '(it is the only thing that writes one)');
    }
    const policy = loadGatewayPolicy(policyPath);
    // The actor comes BEFORE the wiring: its claims key the per-user token
    // requests (user_id, tenant, tool) of a remote credential.
    const loadedActor = await resolveActor(flags, policy, what);
    // The holds dir is created lazily by HoldStore (0700) on the first
    // hold, independent of the evidence store: a store that fails to open
    // degrades recording to passthrough but never enforcement.
    const gateway = { policy, holdStore: new HoldStore(config.dataDir) };
    // A `credentials:` section turns the gateway into a broker as well as a
    // gate. Building it here, beside the policy, keeps the one deliberate
    // exception to fail-open in one place: a credentials section that
    // cannot be turned into a broker exits 2 rather than running with a
    // swap the operator believes is on. Absent section, absent env
    // binding, or a broker that refuses its own config are three different
    // outcomes and the operator hears which one.
    try {
        const wiring = credentialSwapFromPolicy({
            policy: policy.policy,
            env: process.env,
            warn: diag,
            ...(loadedActor !== undefined ? { identity: loadedActor.claims, identityJwt: loadedActor.token } : {}),
        });
        if (wiring !== undefined)
            gateway.credentials = wiring.swap;
    }
    catch (e) {
        err(`policy ${policyPath}: ${e.message}`);
    }
    return { gateway, ...(loadedActor !== undefined ? { actor: loadedActor } : {}) };
}
async function cmdRecord(flags, serverCommand) {
    if (serverCommand.length === 0) {
        err("record: missing server command (usage: mcp-recorder [record] [flags] -- <command...>)");
    }
    installUncaughtExceptionGuard();
    // Lenient: nothing about recording configuration may prevent the wrapped
    // server from spawning. Bad --redact/--store values fall back to defaults.
    const { config, warnings } = resolveConfigLenient({ flags, env: process.env });
    for (const w of warnings)
        diag(w);
    const { gateway, actor } = await resolveGateway(flags, config, 'record');
    const setup = await setupProxyRecording(config, diag, { surface: 'record', flags });
    const exitCode = await runStdioProxy({
        command: serverCommand,
        recorder: setup.recorder,
        redactor: setup.redactor,
        ...(config.serverName !== undefined ? { serverName: config.serverName } : {}),
        ...(config.identityLabel !== undefined ? { identityLabel: config.identityLabel } : {}),
        ...(gateway !== undefined ? { gateway } : {}),
        ...(actor !== undefined ? { actor } : {}),
        proxyVersion: VERSION,
    });
    writeRunSummary(setup);
    process.exit(exitCode);
}
async function cmdHttp(flags) {
    const targetUrl = asStr(flags.target) ?? err('http: --target URL is required');
    const port = parsePort(flags.port);
    installUncaughtExceptionGuard();
    // Lenient: nothing about recording configuration may prevent the proxy
    // from standing up. Bad --redact/--store values fall back to defaults.
    const { config, warnings } = resolveConfigLenient({ flags, env: process.env });
    for (const w of warnings)
        diag(w);
    // The same gateway the stdio proxy runs, over HTTP: same policy loader
    // (fail closed, exit 2 before the port is bound), same holds dir, same
    // broker wiring. Without --policy the proxy is the byte-for-byte recorder.
    const { gateway, actor } = await resolveGateway(flags, config, 'http');
    const setup = await setupProxyRecording(config, diag, { surface: 'http', flags });
    const proxy = await runHttpProxy({
        targetUrl,
        ...(port !== undefined ? { port } : {}),
        recorder: setup.recorder,
        redactor: setup.redactor,
        ...(config.serverName !== undefined ? { serverName: config.serverName } : {}),
        ...(config.identityLabel !== undefined ? { identityLabel: config.identityLabel } : {}),
        ...(gateway !== undefined ? { gateway } : {}),
        ...(actor !== undefined ? { actor } : {}),
        proxyVersion: VERSION,
    });
    if (gateway !== undefined) {
        const rules = gateway.policy.policy.mcp?.rules.length ?? 0;
        diag(`gateway: policy ${gateway.policy.name ?? gateway.policy.path} (${rules} rule${rules === 1 ? '' : 's'}) enforced over HTTP`);
    }
    // Only the origin: the target may carry credentials in its userinfo, path
    // or query, and this line lands in terminals, scrollback and log capture.
    let targetOrigin = '<target>';
    try {
        const u = new URL(targetUrl);
        targetOrigin = `${u.protocol}//${u.host}`;
    }
    catch {
        /* leave the placeholder */
    }
    const shutdown = waitForShutdownSignal(); // armed before the announcement, see the helper
    diag(`http proxy listening at ${proxy.url} -> ${targetOrigin} (Ctrl-C to stop)`);
    await shutdown;
    await proxy.close();
    writeRunSummary(setup);
    process.exit(0);
}
function printVerifyHuman(result, source, pinned, unsignedMetadata) {
    out(`verify ${source}`);
    // pinned is undefined ONLY for the store-mode branch that found neither
    // --public-key nor <data-dir>/identity.pub — bundle mode always pins to
    // something (the manifest's own key, at minimum). That's a silent downgrade
    // from "this PASS proves who signed it" to "this PASS accepts a signature
    // from ANY key" — deleting identity.pub (or copying a store without it)
    // must not look identical to a normal pinned PASS, so this is a loud
    // warning, never a quiet omission.
    const unpinned = pinned === undefined;
    if (pinned !== undefined) {
        out(`pinned signer: ed25519 ${pinned.hex.slice(0, 16)}… (${pinned.source})`);
    }
    else {
        out('WARNING: no public key to pin against — neither <data-dir>/identity.pub nor ' +
            '--public-key is available, so a signature from ANY key is accepted. This does ' +
            'NOT prove who signed the chain. Pass --public-key with a key obtained out of ' +
            'band for real assurance.');
    }
    // A warning-only chain (an unsigned tail we chose to tolerate) still says
    // PASS, but distinctly — it's a weaker guarantee than a fully-signed chain.
    const hasWarning = result.problems.some((p) => p.warning === true);
    if (result.ok) {
        const labels = [...(unpinned ? ['unpinned'] : []), ...(hasWarning ? ['unsigned tail'] : [])];
        const label = labels.length > 0 ? `PASS (${labels.join(', ')})` : 'PASS';
        out(`${label} — chain intact: ${result.checked_events} event(s), head seq ${result.head.seq}`);
    }
    else {
        out(`FAIL — evidence does NOT verify: ${result.checked_events} event(s) checked`);
    }
    const sig = result.verified_signature;
    if (sig !== undefined) {
        out(`signed head: seq ${sig.seq} by ed25519 ${sig.public_key.slice(0, 16)}… at ${sig.signed_at}`);
    }
    if (unsignedMetadata !== undefined) {
        out('');
        out('UNSIGNED metadata (not covered by the signature - informational only):');
        if (unsignedMetadata.session_id !== undefined) {
            out(`  session_id  : ${unsignedMetadata.session_id}`);
        }
        out(`  created_at  : ${unsignedMetadata.created_at}`);
        out(`  tool_version: ${unsignedMetadata.tool_version}`);
    }
    if (result.problems.length > 0) {
        out('');
        out(formatTable(['TYPE', 'SEQ', 'DETAIL'], result.problems.map((p) => [
            p.type + (p.warning === true ? ' (warning)' : ''),
            String(p.seq),
            p.detail,
        ])));
    }
}
/* ------------------------------- bundle reading ------------------------------- */
const BUNDLE_REQUIRED_FILES = [BUNDLE_FILES.MANIFEST, BUNDLE_FILES.EVENTS, BUNDLE_FILES.PUBLIC_KEY];
function assertBundleId(manifest, where) {
    if (manifest.bundle !== 'edut.mcp-recorder.bundle.v1') {
        err(`unrecognized bundle id in ${where}: ${String(manifest.bundle)}`);
    }
}
/** Extract the manifest fields the head signature does not cover (see UnsignedBundleMetadata). */
function unsignedMetadataOf(manifest) {
    const out = {
        created_at: manifest.created_at,
        tool_version: manifest.tool_version,
    };
    if (manifest.session_id !== undefined)
        out.session_id = manifest.session_id;
    return out;
}
function parseEventsJsonl(text) {
    return text
        .split('\n')
        .filter((line) => line.trim() !== '')
        .map((line) => JSON.parse(line));
}
/**
 * A bundle is a sealed, self-declared range: manifest.json's range/
 * event_count/head_hash/signature must exactly match what events.jsonl (and
 * public_key.pem) actually contain, or a forged tail chained onto a genuine
 * signed head — self-consistent, no key needed — would otherwise slip past
 * verifyRecords as a mere "unsigned tail" warning (that check only walks the
 * chain it's given; it has no notion of the manifest's own claims). Every
 * mismatch here is an unconditional failure, never downgradable by
 * --allow-unsigned: a bundle is an exported, sealed artifact, not an
 * in-flight recording. This mirrors verify.cjs's checks 1-4 exactly — keep
 * the two in sync.
 */
function checkBundleManifestConsistency(manifest, records, publicKeyPemText) {
    const problems = [];
    const push = (seq, detail) => {
        problems.push({ type: 'bundle_manifest_mismatch', seq, detail });
    };
    const first = records[0];
    const last = records[records.length - 1];
    if (records.length !== manifest.event_count) {
        push(last?.seq ?? 0, `events.jsonl has ${records.length} record(s) but manifest.event_count declares ${manifest.event_count}`);
    }
    if (first !== undefined && first.seq !== manifest.range.from_seq) {
        push(first.seq, `first record seq ${first.seq} does not match manifest.range.from_seq ${manifest.range.from_seq}`);
    }
    if (last !== undefined && last.seq !== manifest.range.to_seq) {
        push(last.seq, `last record seq ${last.seq} does not match manifest.range.to_seq ${manifest.range.to_seq}`);
    }
    if (last !== undefined && last.hash !== manifest.head_hash) {
        push(last.seq, `last record hash ${last.hash} does not match manifest.head_hash ${manifest.head_hash} — events were appended or removed after export`);
    }
    if (manifest.signature.seq !== manifest.range.to_seq) {
        push(manifest.signature.seq, `manifest.signature.seq ${manifest.signature.seq} does not match manifest.range.to_seq ${manifest.range.to_seq}`);
    }
    if (manifest.signature.chain_hash !== manifest.head_hash) {
        push(manifest.signature.seq, `manifest.signature.chain_hash ${manifest.signature.chain_hash} does not match manifest.head_hash ${manifest.head_hash}`);
    }
    // The shipped public_key.pem must be the SAME key manifest.signature names
    // — mirrors verify.cjs step 4. A forgery re-signed with an attacker key
    // that ships the operator's genuine PEM (or vice versa) is caught here even
    // though the chain/signature math above is internally self-consistent.
    let pemHex;
    try {
        pemHex = publicKeyHexFromPem(publicKeyPemText);
    }
    catch (cause) {
        const msg = cause instanceof Error ? cause.message : String(cause);
        problems.push({
            type: 'signature_invalid',
            seq: manifest.signature.seq,
            detail: `public_key.pem is not a valid ed25519 public key: ${msg}`,
        });
    }
    if (pemHex !== undefined && pemHex !== manifest.signature.public_key.toLowerCase()) {
        problems.push({
            type: 'signature_invalid',
            seq: manifest.signature.seq,
            detail: 'public_key.pem does not match the manifest signing key',
        });
    }
    if (manifest.public_key_pem !== publicKeyPemText) {
        push(manifest.signature.seq, 'public_key.pem on disk differs from the PEM embedded in manifest.json (manifest.public_key_pem)');
    }
    return problems;
}
async function verifyManifestAgainst(manifest, records, publicKeyPemText, pinOpts) {
    const pinnedPublicKeyHex = pinOpts.expectedPublicKeyHex ?? manifest.signature.public_key;
    const chainResult = await verifyRecords(records, [manifest.signature], {
        baseHash: manifest.base_hash,
        expectedPublicKeyHex: pinnedPublicKeyHex,
        ...(pinOpts.allowUnsigned !== undefined ? { allowUnsigned: pinOpts.allowUnsigned } : {}),
    });
    // Bundle mode: an unsigned tail is never a mere warning — a bundle is a
    // sealed artifact, never in-flight. Unconditional, same as the
    // manifest-consistency checks below: neither is gated on --allow-unsigned.
    // In practice the consistency checks already reject any tail that could
    // produce this, but strip the warning flag here too as defense in depth.
    const chainProblems = chainResult.problems.map((p) => p.type === 'unsigned_tail' ? { type: p.type, seq: p.seq, detail: p.detail } : p);
    const manifestProblems = checkBundleManifestConsistency(manifest, records, publicKeyPemText);
    const problems = [...chainProblems, ...manifestProblems];
    const result = {
        ...chainResult,
        problems,
        ok: problems.every((p) => p.warning === true),
    };
    return { result, pinnedPublicKeyHex };
}
async function verifyBundleFromDir(dir, pinOpts) {
    const manifestPath = join(dir, BUNDLE_FILES.MANIFEST);
    const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
    assertBundleId(manifest, manifestPath);
    const records = parseEventsJsonl(readFileSync(join(dir, BUNDLE_FILES.EVENTS), 'utf8'));
    const publicKeyPemText = readFileSync(join(dir, BUNDLE_FILES.PUBLIC_KEY), 'utf8');
    const { result, pinnedPublicKeyHex } = await verifyManifestAgainst(manifest, records, publicKeyPemText, pinOpts);
    return {
        result,
        source: `bundle ${dir}`,
        pinnedPublicKeyHex,
        unsignedMetadata: unsignedMetadataOf(manifest),
    };
}
async function verifyBundleFromZip(zipPath, buf, pinOpts) {
    const entries = readZipEntries(buf, BUNDLE_REQUIRED_FILES);
    const missing = BUNDLE_REQUIRED_FILES.filter((name) => !entries.has(name));
    if (missing.length > 0) {
        err(`${zipPath} is not a valid evidence bundle (missing ${missing.join(', ')} — ` +
            'expected the .zip produced by `mcp-recorder export`)');
    }
    const manifest = JSON.parse(entries.get(BUNDLE_FILES.MANIFEST).toString('utf8'));
    assertBundleId(manifest, `${zipPath} (${BUNDLE_FILES.MANIFEST})`);
    const records = parseEventsJsonl(entries.get(BUNDLE_FILES.EVENTS).toString('utf8'));
    const publicKeyPemText = entries.get(BUNDLE_FILES.PUBLIC_KEY).toString('utf8');
    const { result, pinnedPublicKeyHex } = await verifyManifestAgainst(manifest, records, publicKeyPemText, pinOpts);
    return {
        result,
        source: `bundle ${zipPath}`,
        pinnedPublicKeyHex,
        unsignedMetadata: unsignedMetadataOf(manifest),
    };
}
/**
 * Read a bundle for `verify --bundle PATH`: either form `export` produces —
 * a plain directory, or the default `.zip` (sniffed by its `PK` magic, not
 * by file extension, so a renamed bundle still works). Anything else gets a
 * helpful error instead of the raw ENOTDIR/ENOENT a fs call would throw.
 */
async function verifyBundleDir(bundlePath, pinOpts = {}) {
    const resolved = resolve(bundlePath);
    let stat;
    try {
        stat = statSync(resolved);
    }
    catch {
        err(`--bundle ${resolved} does not exist`);
    }
    if (stat.isDirectory())
        return verifyBundleFromDir(resolved, pinOpts);
    if (stat.isFile()) {
        const buf = readFileSync(resolved);
        if (buf.length >= 4 && buf[0] === 0x50 && buf[1] === 0x4b /* 'PK' */) {
            return verifyBundleFromZip(resolved, buf, pinOpts);
        }
        err(`--bundle ${resolved} is not a recognized evidence bundle ` +
            '(expected a directory or a .zip produced by `mcp-recorder export`)');
    }
    err(`--bundle ${resolved} is neither a file nor a directory`);
}
/**
 * Resolve `verify`'s store-mode pin (explicit --public-key, else this data
 * dir's own identity.pub, else none) and run verifyStore against it. Shared
 * by cmdVerify and cmdUi's integrity banner so the two always agree — before
 * this was factored out, `ui` called verifyStore(store) with no pin and no
 * --allow-unsigned at all, so it could show green for a chain `verify`
 * itself rejects.
 */
async function resolveStoreVerify(store, config, opts) {
    let expectedPublicKeyHex = opts.explicitPublicKeyHex;
    let pinSource = '--public-key';
    if (expectedPublicKeyHex === undefined) {
        // Default pin: this data dir's own identity.pub, so a chain rewritten
        // and re-signed with a fresh, unrelated key is rejected instead of
        // silently accepted — see README "Security model".
        const pubPath = join(config.dataDir, FILES.PUBLIC_KEY);
        if (existsSync(pubPath)) {
            expectedPublicKeyHex = readFileSync(pubPath, 'utf8').trim().toLowerCase();
            pinSource = pubPath;
        }
    }
    const verifyOpts = { allowUnsigned: opts.allowUnsigned };
    if (expectedPublicKeyHex !== undefined)
        verifyOpts.expectedPublicKeyHex = expectedPublicKeyHex;
    const result = await verifyStore(store, verifyOpts);
    const pinned = expectedPublicKeyHex !== undefined ? { hex: expectedPublicKeyHex, source: pinSource } : undefined;
    return { result, pinned };
}
/**
 * Say which store an inspection command opened, when nobody named one.
 *
 * `--data-dir` and MCP_RECORDER_DATA_DIR both being absent resolves to
 * ~/.mcp-recorder, which is right for a laptop with one store and wrong in
 * every way that matters when it is not what the operator meant. Measured:
 * `ui --out page.html` run in an empty directory exits 0 and writes a
 * 183 KB page holding 54 events from the home store — in a customer room,
 * somebody else's traffic rendered as if it were theirs. The page carries no
 * hint of where it came from, so nothing downstream can catch it either.
 *
 * Refusing would break the laptop case this default exists for, so the
 * command says what it did instead, on stderr, where it cannot be mistaken
 * for output. Silence still means "you told me which store".
 */
function announceDefaultDataDir(flags, config) {
    if (flags['data-dir'] !== undefined)
        return;
    if (process.env[ENV.DATA_DIR] !== undefined && process.env[ENV.DATA_DIR] !== '')
        return;
    diag(`reading the default store at ${config.dataDir} (no --data-dir given)`);
}
async function cmdVerify(flags) {
    const allowUnsigned = flags['allow-unsigned'] === true;
    const publicKeyFlag = asStr(flags['public-key']);
    const explicitPublicKeyHex = publicKeyFlag !== undefined ? resolvePublicKeyArg(publicKeyFlag) : undefined;
    guardStdoutEpipe();
    let result;
    let source;
    let pinned;
    let unsignedMetadata;
    const bundle = asStr(flags.bundle);
    if (bundle !== undefined) {
        const bundleResult = await verifyBundleDir(bundle, {
            ...(explicitPublicKeyHex !== undefined ? { expectedPublicKeyHex: explicitPublicKeyHex } : {}),
            allowUnsigned,
        });
        result = bundleResult.result;
        source = bundleResult.source;
        unsignedMetadata = bundleResult.unsignedMetadata;
        pinned = {
            hex: bundleResult.pinnedPublicKeyHex,
            source: explicitPublicKeyHex !== undefined
                ? '--public-key'
                : "bundle's own manifest.json — self-pinned; pass --public-key with a key " +
                    'obtained out of band for independent assurance',
        };
    }
    else {
        const config = resolveConfig({ flags, env: process.env });
        announceDefaultDataDir(flags, config);
        const store = openConfiguredStore(config, { readOnly: true });
        try {
            const resolved = await resolveStoreVerify(store, config, { explicitPublicKeyHex, allowUnsigned });
            result = resolved.result;
            pinned = resolved.pinned;
            source = `store ${store.path} (${store.backend})`;
        }
        finally {
            store.close();
        }
    }
    // Set the exit code BEFORE printing: printVerifyHuman/JSON.stringify below
    // can fail partway through with EPIPE (e.g. `verify | head -1`), and
    // guardStdoutEpipe's handler exits with process.exitCode — an exit code
    // set only after a successful print would never take effect on that path,
    // silently turning a FAIL into an apparent success.
    if (!result.ok)
        process.exitCode = 1;
    if (flags.json === true) {
        const payload = pinned !== undefined
            ? { ...result, pinned_public_key: pinned.hex, pinned_public_key_source: pinned.source }
            : { ...result, pinned_public_key: null, unpinned: true };
        out(JSON.stringify(payload, null, 2));
    }
    else {
        printVerifyHuman(result, source, pinned, unsignedMetadata);
    }
}
async function cmdQuery(flags, positionals) {
    guardStdoutEpipe();
    const needle = positionals[0] ?? err('query: missing <needle> argument');
    const config = resolveConfig({ flags, env: process.env });
    announceDefaultDataDir(flags, config);
    const store = openConfiguredStore(config, { readOnly: true });
    try {
        const sessionId = resolveSessionId(store, asStr(flags.session));
        const result = queryStore(store, needle, sessionId !== undefined ? { sessionId } : {});
        if (flags.json === true) {
            out(JSON.stringify(result, null, 2));
            return;
        }
        if (result.matches.length > 0) {
            out(formatTable(['TIMESTAMP', 'KIND', 'NAME', 'SESSION', 'MATCHED_ON', 'PATH'], result.matches.map((m) => [
                m.timestamp,
                m.kind,
                m.name ?? '',
                id8(m.session_id),
                m.matched_on,
                m.path,
            ])));
            out('');
        }
        out(`${result.matches.length} matches across ${result.sessions.length} sessions`);
    }
    finally {
        store.close();
    }
}
/**
 * The ENDED cell. A `session_end` is NOT necessarily a session's last event:
 * a Claude Code session resumed under the same session_id keeps recording
 * after it (cloud dogfood 4: session_end at 07:59:20, tool calls until
 * 12:41:08), and every count in the row is a live aggregate over all of it.
 * Printing that superseded timestamp under "ENDED" invites the reading the
 * dogfood report actually made — "it ended at 07:59:20, so the later counts
 * must be stale". So an end time is printed only when the session_end is
 * genuinely the last event; a session that was ended and then reopened
 * reads `(reopened)` (its session_end stays in `--json` as `ended_at`), and
 * one that never ended reads `(open)` as it always has. LAST_EVENT carries
 * the instant the counts run through in every case.
 */
function endedCell(s) {
    if (s.ended_at === undefined)
        return '(open)';
    if (s.last_event_at !== undefined && s.last_event_at > s.ended_at)
        return '(reopened)';
    return s.ended_at;
}
/**
 * `sessions --tools`: the per-server, per-tool census (src/query/census.ts),
 * over the whole chain or one session (`--session`, a prefix works).
 */
function printToolCensus(store, flags) {
    const rawSession = asStr(flags.session);
    const sessionId = rawSession === undefined ? undefined : resolveSessionId(store, rawSession);
    const rows = toolCensus(store.iterate(sessionId === undefined ? undefined : { sessionId }));
    if (flags.json === true) {
        out(JSON.stringify(rows, null, 2));
        return;
    }
    if (rows.length === 0) {
        out(sessionId === undefined ? 'no tool calls recorded' : `no tool calls recorded in session ${id8(sessionId)}`);
        return;
    }
    out(formatTable(['SERVER', 'TOOL', 'CALLS', 'ERRORS', 'DENIED', 'HELD', 'SESSIONS', 'LAST_SEEN'], rows.map((r) => [
        r.server === '' ? '-' : r.server,
        r.tool,
        String(r.calls),
        String(r.errors),
        String(r.denied),
        String(r.held),
        String(r.sessions),
        r.last_seen,
    ])));
}
async function cmdSessions(flags) {
    guardStdoutEpipe();
    const config = resolveConfig({ flags, env: process.env });
    announceDefaultDataDir(flags, config);
    const store = openConfiguredStore(config, { readOnly: true });
    try {
        if (flags.tools === true) {
            printToolCensus(store, flags);
            return;
        }
        const sessions = store.sessions();
        if (flags.json === true) {
            out(JSON.stringify(sessions, null, 2));
            return;
        }
        if (sessions.length === 0) {
            out('no sessions recorded');
            return;
        }
        // New columns are appended LAST so every column that existed before
        // them keeps its position for anyone who split this table by column
        // index; `--json` is the stable machine interface (README).
        out(formatTable([
            'SESSION',
            'STARTED',
            'ENDED',
            'SERVER',
            'EVENTS',
            'TOOL_CALLS',
            'ERRORS',
            'SERVERS',
            'DECISIONS',
            'LAST_EVENT',
        ], sessions.map((s) => [
            id8(s.session_id),
            s.started_at,
            endedCell(s),
            s.server_name,
            String(s.event_count),
            String(s.tool_call_count),
            String(s.error_count),
            // Distinct server.name values over the session's tool_call events:
            // 1 for a proxy session, the number of servers called for a hook
            // session (SERVER is only the first event's — 'claude-code' there).
            s.server_count === undefined ? '' : String(s.server_count),
            // policy_decision events: what gateway mode denied or held (an
            // approved hold included), 0 for a session recorded without a
            // policy. A denied call also shows up under TOOL_CALLS and
            // ERRORS — the refusal the client was handed is a call too.
            s.policy_decision_count === undefined ? '' : String(s.policy_decision_count),
            // The instant every count in this row runs through — the same for
            // a session that ended and stayed ended, later for a reopened or
            // still-open one.
            s.last_event_at ?? '',
        ])));
    }
    finally {
        store.close();
    }
}
async function cmdUi(flags) {
    guardStdoutEpipe();
    const config = resolveConfig({ flags, env: process.env });
    announceDefaultDataDir(flags, config);
    const store = openConfiguredStore(config, { readOnly: true });
    try {
        const sessionId = resolveSessionId(store, asStr(flags.session));
        const outFile = asStr(flags.out);
        // Route through the SAME pin resolution `verify` uses (identity.pub by
        // default, or --public-key / --allow-unsigned if given) so the integrity
        // banner never shows green for a chain `mcp-recorder verify` rejects.
        const publicKeyFlag = asStr(flags['public-key']);
        const explicitPublicKeyHex = publicKeyFlag !== undefined ? resolvePublicKeyArg(publicKeyFlag) : undefined;
        const allowUnsigned = flags['allow-unsigned'] === true;
        const { result: verify } = await resolveStoreVerify(store, config, {
            explicitPublicKeyHex,
            allowUnsigned,
        });
        if (outFile !== undefined) {
            const html = renderTimelineHtml(store, {
                ...(sessionId !== undefined ? { sessionId } : {}),
                verify,
            });
            writeFileSync(outFile, html);
            diag(`wrote replay page to ${resolve(outFile)}`);
            return;
        }
        const port = parsePort(flags.port) ?? 0;
        const ui = await serveUi({
            store,
            verify,
            port,
            ...(sessionId !== undefined ? { sessionId } : {}),
        });
        const shutdown = waitForShutdownSignal(); // armed before the announcement, see the helper
        diag(`replay UI at ${ui.url} (Ctrl-C to stop)`);
        if (flags['no-open'] !== true)
            tryOpenBrowser(ui.url);
        await shutdown;
        await ui.close();
    }
    finally {
        store.close();
    }
}
function exportTimestamp(now) {
    const p = (n) => String(n).padStart(2, '0');
    return (`${now.getFullYear()}${p(now.getMonth() + 1)}${p(now.getDate())}` +
        `-${p(now.getHours())}${p(now.getMinutes())}${p(now.getSeconds())}`);
}
async function cmdExport(flags) {
    guardStdoutEpipe();
    const config = resolveConfig({ flags, env: process.env });
    announceDefaultDataDir(flags, config);
    const store = openConfiguredStore(config, { readOnly: true });
    try {
        if (store.count() === 0) {
            diag('error: nothing to export — the evidence store is empty');
            process.exitCode = 1;
            return;
        }
        const dirPath = asStr(flags.dir);
        const zipPath = asStr(flags.out) ??
            (dirPath === undefined
                ? `./mcp-recorder-bundle-${exportTimestamp(new Date())}.zip`
                : undefined);
        const sessionId = resolveSessionId(store, asStr(flags.session));
        // loadExisting, NOT load: export must sign with the key that actually
        // produced the chain. Minting a fresh one here (as record's Signer.load
        // does) would sign evidence with an identity that never touched it, and
        // silently repoint identity.pub out from under the next `verify` — see
        // Signer.loadExisting's doc comment.
        const signer = await Signer.loadExisting(config.dataDir);
        const manifest = await exportBundle({
            store,
            signer,
            toolVersion: VERSION,
            ...(sessionId !== undefined ? { sessionId } : {}),
            ...(zipPath !== undefined ? { zipPath } : {}),
            ...(dirPath !== undefined ? { dirPath } : {}),
        });
        diag(`exported ${manifest.event_count} event(s) (seq ${manifest.range.from_seq}..${manifest.range.to_seq})` +
            (manifest.session_id !== undefined ? ` of session ${id8(manifest.session_id)}` : '') +
            `, head ${manifest.head_hash.slice(0, 16)}… signed by ed25519 ${manifest.signature.public_key.slice(0, 16)}…`);
        if (zipPath !== undefined)
            diag(`bundle zip: ${resolve(zipPath)}`);
        if (dirPath !== undefined)
            diag(`bundle dir: ${resolve(dirPath)}`);
        diag('verify anywhere with: node verify.cjs (inside the bundle)');
    }
    finally {
        store.close();
    }
}
/* ------------------------- policy validate / compile ----------------------- */
function printPolicyInvalid(path, errors, jsonOut) {
    // Exit code BEFORE printing, for the same EPIPE reason as cmdVerify.
    process.exitCode = 1;
    if (jsonOut) {
        out(JSON.stringify({ path, valid: false, errors }, null, 2));
        return;
    }
    out(`${path}: invalid`);
    for (const line of indentedPolicyErrors(errors))
        out(line);
}
/**
 * Non-fatal things worth saying about a VALID policy. Today there is exactly
 * one: a policy the schema accepts (an `egress`-only file is valid — the
 * top level requires one of `mcp`/`egress`, not both) that the stdio gateway
 * has nothing to enforce, so `record --policy` and `setup --policy` refuse
 * it with exit 2. `policy validate` still exits 0 — the file IS valid, and
 * the sidecar consumes its `egress` section — but saying nothing here is how
 * a CI step that validates a policy passes while every wrapped server
 * refuses to start.
 */
function policyWarnings(loaded) {
    if (loaded.policy.mcp !== undefined)
        return [];
    return [
        'no "mcp" section — nothing for the gateway to enforce ' +
            '(record --policy and setup --policy will refuse it)',
    ];
}
function policyRuleCounts(loaded) {
    return {
        mcp: loaded.policy.mcp?.rules.length ?? 0,
        egress: loaded.policy.egress?.rules.length ?? 0,
    };
}
/**
 * `policy test`: one tool name through the engine that governs its leg, the
 * deny-rule smoke test docs/pov.md asks for before a policy meeting ends.
 * Exit 0 when evaluated (and, with --expect, when the verdict is the one
 * expected), 1 when --expect is not met or the policy is invalid, 2 on a
 * usage error or an unreadable file. Nothing is spawned, nothing recorded.
 */
function cmdPolicyTest(path, flags, jsonOut) {
    const tool = asStr(flags.tool) ?? err('policy test: missing --tool NAME (the tool name exactly as observed)');
    if (tool === '')
        err('policy test: --tool must not be empty');
    const expect = asStr(flags.expect);
    if (expect !== undefined && expect !== 'allow' && expect !== 'deny' && expect !== 'hold') {
        err(`policy test: invalid --expect '${expect}' (expected allow, deny or hold)`);
    }
    const legFlag = asStr(flags.leg);
    if (legFlag !== undefined && legFlag !== 'gateway' && legFlag !== 'hook') {
        err(`policy test: invalid --leg '${legFlag}' (expected gateway or hook)`);
    }
    let text;
    try {
        text = readFileSync(path, 'utf8');
    }
    catch (cause) {
        const msg = cause instanceof Error ? cause.message : String(cause);
        return err(`policy test: cannot read policy file ${path}: ${msg}`);
    }
    let leg;
    if (legFlag !== undefined) {
        leg = legFlag;
    }
    else {
        let doc;
        try {
            doc = parsePolicyText(text, sourceForPath(path), path);
        }
        catch {
            doc = undefined; // the gateway reader below reports the parse error
        }
        leg = detectLeg(doc);
    }
    let result;
    if (leg === 'hook') {
        if (flags.server !== undefined || flags.args !== undefined) {
            err('policy test: --server and --args apply to the gateway leg; a hook rule sees only the full tool name');
        }
        let hookPolicy;
        try {
            hookPolicy = parseHookPolicy(text);
        }
        catch (cause) {
            // The real hook DENIES every call it governs when this happens; say
            // so, and fail rather than report that denial as a rule's verdict.
            const msg = cause instanceof Error ? cause.message : String(cause);
            process.exitCode = 1;
            out(`${path}: invalid hook policy (${msg}) — 'mcp-recorder hook --policy' would deny every call it governs`);
            return;
        }
        result = smokeHook(hookPolicy, tool);
    }
    else {
        const read = readPolicyForCli(path, 'policy test');
        if (!read.ok) {
            printPolicyInvalid(path, read.errors, jsonOut);
            return;
        }
        if (read.loaded.policy.mcp === undefined) {
            err(`policy test: ${path} has no "mcp" section — nothing for the gateway to evaluate`);
        }
        let server = asStr(flags.server);
        let bare = tool;
        if (server === undefined) {
            const parsed = parseHookToolName(tool);
            if (!parsed.isMcp) {
                err('policy test: the gateway leg needs --server S (the wrapped server\'s name, as --name or its serverInfo gives it), ' +
                    'or a tool spelled mcp__<server>__<tool>');
            }
            server = parsed.server;
            bare = parsed.tool;
        }
        let args = {};
        const rawArgs = asStr(flags.args);
        if (rawArgs !== undefined) {
            try {
                args = JSON.parse(rawArgs);
            }
            catch (cause) {
                const msg = cause instanceof Error ? cause.message : String(cause);
                err(`policy test: --args is not JSON: ${msg}`);
            }
            if (typeof args !== 'object' || args === null || Array.isArray(args)) {
                err('policy test: --args must be a JSON object (the tools/call params.arguments)');
            }
        }
        result = smokeGateway(read.loaded.policy, server, bare, args);
    }
    // A verdict that changes with the server segment is not the verdict the
    // person expected: it holds for one session's spelling (cloud dogfood 4).
    const anchoredCount = result.anchored?.length ?? 0;
    const met = expect === undefined || (result.action === expect && anchoredCount === 0);
    // Exit code BEFORE printing, for the same EPIPE reason as cmdVerify.
    if (!met)
        process.exitCode = 1;
    if (jsonOut) {
        out(JSON.stringify({ path, ...result, ...(expect !== undefined ? { expect, expectation_met: met } : {}) }, null, 2));
        return;
    }
    const subject = result.leg === 'gateway' ? `server=${result.server ?? ''} tool=${result.tool}` : result.tool;
    const by = result.leg === 'gateway' ? `  rule ${result.rule ?? 'default'}` : '';
    out(`${result.action.toUpperCase()}  ${subject}${by}   (${result.leg} leg, ${path})`);
    if (result.reason !== undefined)
        out(`  reason: ${result.reason}`);
    if (result.fail_closed === true)
        out('  the policy could not be evaluated for this call, so the gateway refuses it (fail closed)');
    if (result.anchored !== undefined && result.spellings !== undefined) {
        if (result.anchored.length === 0) {
            out(`  same verdict under all ${String(result.spellings.length)} server-segment spellings a client could choose`);
        }
        else {
            out(`  WARNING: ${String(result.anchored.length)} of ${String(result.spellings.length)} spellings of this tool get a different verdict —`);
            out('  the server segment is the client\'s to choose, so this rule holds for one spelling only:');
            for (const s of result.anchored)
                out(`    ${s.action.toUpperCase()}  ${s.name}   (${s.origin})`);
        }
    }
    if (!met) {
        out(result.action === expect
            ? `  expected ${expect} under every spelling, got it under ${String((result.spellings?.length ?? 0) - anchoredCount)} of ${String(result.spellings?.length ?? 0)}`
            : `  expected ${expect ?? ''}, got ${result.action}`);
    }
}
async function cmdPolicy(flags, positionals) {
    guardStdoutEpipe();
    const usage = 'usage: mcp-recorder policy validate <file> [--json] | mcp-recorder policy compile <file> [--target rego] [--out DIR]' +
        ' | mcp-recorder policy test <file> --tool NAME [--server S] [--args JSON] [--leg gateway|hook] [--expect allow|deny|hold] [--json]';
    const verb = positionals[0] ?? err(`policy: missing <validate|compile|test> (${usage})`);
    if (verb !== 'validate' && verb !== 'compile' && verb !== 'test') {
        err(`policy: unknown verb '${verb}' (expected 'validate', 'compile' or 'test'; ${usage})`);
    }
    const fileArg = positionals[1] ?? err(`policy ${verb}: missing <file> (${usage})`);
    if (positionals.length > 2) {
        err(`policy ${verb}: unexpected argument '${positionals[2]}' (${usage})`);
    }
    const jsonOut = flags.json === true;
    const path = resolve(fileArg);
    if (verb === 'test') {
        cmdPolicyTest(path, flags, jsonOut);
        return;
    }
    if (verb === 'validate') {
        const read = readPolicyForCli(path, 'policy validate');
        if (!read.ok) {
            printPolicyInvalid(path, read.errors, jsonOut);
            return;
        }
        const counts = policyRuleCounts(read.loaded);
        const warnings = policyWarnings(read.loaded);
        if (jsonOut) {
            out(JSON.stringify({
                path,
                valid: true,
                ...(read.loaded.name !== undefined ? { name: read.loaded.name } : {}),
                hash: read.loaded.hash,
                source: read.loaded.source,
                mcp_rules: counts.mcp,
                egress_rules: counts.egress,
                warnings,
            }, null, 2));
            return;
        }
        out(`${path}: valid (${counts.mcp} mcp rules, ${counts.egress} egress rules)`);
        for (const w of warnings)
            out(`  warning: ${w}`);
        return;
    }
    // compile
    const target = asStr(flags.target) ?? 'rego';
    if (target !== 'rego')
        err(`policy compile: invalid --target '${target}' (expected 'rego')`);
    const read = readPolicyForCli(path, 'policy compile');
    if (!read.ok) {
        printPolicyInvalid(path, read.errors, jsonOut);
        return;
    }
    const bundle = compileToRego(read.loaded.policy, {
        policyHash: read.loaded.hash,
        ...(read.loaded.name !== undefined ? { policyName: read.loaded.name } : {}),
        toolVersion: VERSION,
    });
    const files = bundle.files;
    const order = bundleFileOrder(files);
    const outDir = asStr(flags.out);
    if (outDir !== undefined) {
        const dir = resolve(outDir);
        for (const rel of order) {
            // Bundle paths are '/'-separated and produced by the compiler itself
            // (never user input); join per segment so subdirs land right on win32.
            const abs = join(dir, ...rel.split('/'));
            mkdirSync(dirname(abs), { recursive: true });
            writeFileSync(abs, files[rel]);
        }
        out(`wrote ${order.length} file(s) to ${dir}`);
        for (const rel of order)
            out(`  ${rel}`);
        return;
    }
    // Without --out: the MCP module alone, located in the compiler's own file
    // map (never a hard-coded name): the module published under cresec/mcp/,
    // else the .rego whose basename names mcp.
    const mcpPath = mcpModulePath(order);
    if (mcpPath === undefined)
        err('policy compile: the compiler produced no MCP (cresec/mcp/) module');
    process.stdout.write(files[mcpPath]);
}
/** The MCP Rego module's path inside a compiled bundle's file list, if any. */
function mcpModulePath(paths) {
    return (paths.find((p) => p.startsWith('cresec/mcp/')) ??
        paths.find((p) => p.endsWith('.rego') && /(^|\/)[^/]*mcp[^/]*\.rego$/.test(p)));
}
/* --------------------------- holds / approve / deny ------------------------ */
/** "12s", "3m", "2h", "1d" — coarse, for the AGE / TIMEOUT columns. */
function formatDuration(ms) {
    const s = Math.max(0, Math.floor(ms / 1000));
    if (s < 60)
        return `${s}s`;
    const m = Math.floor(s / 60);
    if (m < 60)
        return `${m}m`;
    const h = Math.floor(m / 60);
    if (h < 48)
        return `${h}h`;
    return `${Math.floor(h / 24)}d`;
}
/** ms until `iso`, or undefined when the timestamp does not parse. */
function msUntil(iso, now) {
    const t = Date.parse(iso);
    return Number.isNaN(t) ? undefined : t - now;
}
async function cmdHolds(flags) {
    guardStdoutEpipe();
    const config = resolveConfig({ flags, env: process.env });
    const all = flags.all === true;
    // Read-only: a missing holds dir is simply "no holds" (never created here).
    const holds = new HoldStore(config.dataDir).list({ all });
    if (flags.json === true) {
        out(JSON.stringify(holds, null, 2));
        return;
    }
    if (holds.length === 0) {
        out(all ? 'no holds recorded' : 'no pending holds');
        return;
    }
    const now = Date.now();
    const timeoutCell = (h) => {
        if (h.status !== 'pending')
            return '-';
        const left = msUntil(h.timeout_at, now);
        if (left === undefined)
            return '?';
        return left <= 0 ? 'expired' : formatDuration(left);
    };
    const ageCell = (h) => {
        const since = msUntil(h.created_at, now);
        return since === undefined ? '?' : formatDuration(-since);
    };
    const headers = ['ID', 'AGE', 'SERVER', 'TOOL', 'RULE', 'TIMEOUT', ...(all ? ['STATUS'] : [])];
    out(formatTable(headers, holds.map((h) => [
        id8(h.approval_id),
        ageCell(h),
        h.server,
        h.tool,
        h.rule_id ?? '(default)',
        timeoutCell(h),
        ...(all ? [h.status] : []),
    ])));
}
/**
 * `approve <id>` / `deny <id>`: resolve an exact id or a unique prefix (the
 * 8-char form `holds` prints), then flip the pending hold file. Exit 2 on
 * usage / ambiguity (names the candidates), 1 when the hold does not exist
 * or is no longer pending, 0 with one confirmation line otherwise. The
 * deciding OS user is recorded best-effort (HoldStore fills it in).
 */
async function cmdDecide(flags, positionals, decision) {
    guardStdoutEpipe();
    const verb = decision === 'approved' ? 'approve' : 'deny';
    const raw = positionals[0] ?? err(`${verb}: missing <id> (usage: mcp-recorder ${verb} <id> [--data-dir D])`);
    if (positionals.length > 1)
        err(`${verb}: unexpected argument '${positionals[1]}'`);
    const config = resolveConfig({ flags, env: process.env });
    const holdStore = new HoldStore(config.dataDir);
    const resolved = holdStore.resolveId(raw);
    if (!resolved.ok) {
        if (resolved.reason === 'ambiguous') {
            const candidates = holdStore
                .list({ all: true })
                .filter((h) => h.approval_id.startsWith(raw))
                .map((h) => `${id8(h.approval_id)} (${h.tool}, ${h.status})`);
            err(`${verb}: '${raw}' is ambiguous — it matches ${candidates.length} holds: ${candidates.join(', ')}` +
                ' (give more of the id)');
        }
        diag(`error: ${verb}: no hold matches '${raw}' in ${holdStore.dir} (see 'mcp-recorder holds --all')`);
        process.exitCode = 1;
        return;
    }
    let rec;
    try {
        rec = holdStore.decide(resolved.id, decision);
    }
    catch (cause) {
        if (cause instanceof HoldError && (cause.code === 'not_pending' || cause.code === 'not_found')) {
            diag(`error: ${verb}: ${cause.message}`);
            process.exitCode = 1;
            return;
        }
        throw cause;
    }
    const rule = rec.rule_id !== undefined ? ` (rule ${rec.rule_id})` : '';
    const by = rec.decided_by !== undefined ? ` by ${rec.decided_by}` : '';
    out(`${decision} ${rec.approval_id}: ${rec.tool} on ${rec.server}${rule}${by}`);
}
/* ---------------------------------- ship ----------------------------------
 * `mcp-recorder ship` is the evidence sink's SENDER: it replicates sealed
 * chain records to a receiver as they are recorded, so evidence stops being
 * something the observed party has to remember to hand over.
 *
 * It is a SEPARATE PROCESS on purpose, and that is forced rather than
 * preferred: `hook` is a short-lived process per hook invocation, so there is
 * no long-lived event loop to host an in-process shipper, and blocking a hook
 * on a POST would put sink latency in front of every tool call. One shipper
 * per data dir, enforced by the <data-dir>/ship.lock directory.
 *
 * Fail-open, absolutely: nothing this command does — or fails to do — can
 * block a tool call, deny one, change a proxy's stdout or its exit code.
 */
/** Accept `30s`, `5m`, `2h` or bare seconds. */
function parseDurationMs(raw, what) {
    const m = /^(\d+(?:\.\d+)?)(ms|s|m|h)?$/.exec(raw.trim());
    if (m === null)
        err(`invalid ${what} '${raw}' (expected e.g. 30s, 5m, 2h)`);
    const value = Number(m[1]);
    switch (m[2] ?? 's') {
        case 'ms':
            return Math.round(value);
        case 's':
            return Math.round(value * 1000);
        case 'm':
            return Math.round(value * 60_000);
        default:
            return Math.round(value * 3_600_000);
    }
}
function shipStatusReport(config, sinkUrl) {
    const status = readShipStatus(config.dataDir);
    let localHeadSeq = 0;
    let store;
    try {
        store = openConfiguredStore(config, { readOnly: true });
        localHeadSeq = store.head().seq;
    }
    catch {
        /* status must work on a data dir nothing has recorded to */
    }
    finally {
        try {
            store?.close();
        }
        catch {
            /* best effort */
        }
    }
    const resolvedSink = sinkUrl ?? status?.sink ?? '(none configured)';
    const cached = sinkUrl !== undefined ? readCursorCache(config.dataDir, sinkUrl) : undefined;
    const nextSeq = status?.next_seq ?? cached?.next_seq;
    const report = {
        sink: resolvedSink,
        state: status?.state ?? 'never run',
        local_head_seq: localHeadSeq,
        lag: nextSeq !== undefined ? Math.max(0, localHeadSeq - (nextSeq - 1)) : localHeadSeq,
        shipper_running: shipperLooksAlive(config.dataDir),
    };
    const key = status?.key ?? cached?.key;
    if (key !== undefined)
        report.key = key;
    const chainId = status?.chain_id ?? cached?.chain_id;
    if (chainId !== undefined)
        report.chain_id = chainId;
    if (nextSeq !== undefined)
        report.next_seq = nextSeq;
    const attested = status?.attested_seq ?? cached?.attested_seq;
    if (attested !== undefined)
        report.attested_seq = attested;
    if (status?.last_success_at !== undefined)
        report.last_success_at = status.last_success_at;
    if (status?.last_error !== undefined)
        report.last_error = status.last_error;
    if (status?.last_error_at !== undefined)
        report.last_error_at = status.last_error_at;
    return report;
}
async function cmdShip(flags) {
    guardStdoutEpipe();
    const { config, warnings } = resolveConfigLenient({ flags, env: process.env });
    for (const w of warnings)
        diag(w);
    const { sink, warnings: sinkWarnings } = resolveSinkConfig({ flags, env: process.env });
    /* --status is a pure read: no network, no lock, no side effect. It is the
     * operator's whole mental model in one screen, and what turns a stall from
     * an invisible condition into a human-legible one. */
    if (flags.status === true) {
        const report = shipStatusReport(config, sink?.url);
        if (flags.json === true) {
            out(JSON.stringify(report, null, 2));
            return;
        }
        out(`sink:         ${report.sink}`);
        out(`key:          ${report.key ?? '(unknown)'}`);
        out(`chain_id:     ${report.chain_id ?? '(unknown)'}`);
        out(`state:        ${report.state}${report.shipper_running ? ' (shipper running)' : ''}`);
        out(`local head:   seq ${String(report.local_head_seq)}`);
        out(`receiver:     next_seq ${report.next_seq !== undefined ? String(report.next_seq) : '?'}` +
            `${report.attested_seq !== undefined ? `, attested_seq ${String(report.attested_seq)}` : ''}`);
        out(`lag:          ${String(report.lag)} record(s) not yet at the receiver`);
        out(`last success: ${report.last_success_at ?? '(never)'}`);
        out(`last error:   ${report.last_error ?? '(none)'}${report.last_error_at !== undefined ? ` @ ${report.last_error_at}` : ''}`);
        return;
    }
    for (const w of sinkWarnings)
        diag(w);
    if (sink === undefined) {
        err(`ship: no sink configured (set ${ENV.SINK} or pass --sink https://...)`);
    }
    const drain = flags.drain === true;
    const timeoutRaw = asStr(flags.timeout);
    const drainTimeoutMs = drain ? parseDurationMs(timeoutRaw ?? '30s', '--timeout') : undefined;
    const idleExitRaw = asStr(flags['idle-exit']);
    const idleExitMs = idleExitRaw !== undefined ? parseDurationMs(idleExitRaw, '--idle-exit') : undefined;
    const surfaceRaw = asStr(flags.surface);
    const surface = surfaceRaw === 'record' || surfaceRaw === 'hook' || surfaceRaw === 'http' ? surfaceRaw : 'ship';
    ensureDataDir(config.dataDir);
    const lock = acquireShipLock(config.dataDir);
    if (lock === undefined) {
        // One in-flight shipper per chain is the whole ordering rule; a second
        // one would pipeline batches against the same cursor.
        diag('ship: another shipper is already running for this data dir');
        return;
    }
    let signer;
    try {
        // loadExisting, never load(): a shipper that MINTED a key would start
        // signing under an identity that never touched the evidence — the same
        // failure loadExisting exists to prevent for `export`.
        signer = await Signer.loadExisting(config.dataDir);
    }
    catch (cause) {
        lock.release();
        diag(`ship: ${cause instanceof Error ? cause.message : String(cause)}`);
        return;
    }
    const store = openConfiguredStore(config, { readOnly: true });
    const release = () => {
        try {
            store.close();
        }
        catch {
            /* best effort */
        }
        lock.release();
    };
    for (const signal of ['SIGINT', 'SIGTERM']) {
        process.on(signal, () => {
            release();
            process.exit(0);
        });
    }
    try {
        const result = await runShipper({
            dataDir: config.dataDir,
            sink,
            store,
            signer,
            toolVersion: VERSION,
            surface,
            log: (msg) => {
                try {
                    process.stderr.write(msg.endsWith('\n') ? msg : `${msg}\n`);
                }
                catch {
                    /* fail-open */
                }
            },
            touchLock: () => lock.touch(),
            ...(drain ? { drain: true } : {}),
            ...(drainTimeoutMs !== undefined ? { drainTimeoutMs } : {}),
            ...(idleExitMs !== undefined ? { idleExitMs } : {}),
        });
        if (drain) {
            diag(`ship: delivered ${String(result.delivered)} record(s), ` +
                `receiver next_seq ${String(result.nextSeq)}, lag ${String(result.lag)} (${result.state})`);
        }
    }
    finally {
        release();
    }
}
/* --------------------------------- setup ---------------------------------
 * `mcp-recorder setup` rewrites a client config's `mcpServers` entries to run
 * behind this recorder. cli.ts owns every filesystem side effect and exit
 * code; src/setup/wrap.ts decides *what* the new JSON should look like
 * (pure functions over parsed JSON) and src/setup/io.ts provides the
 * backup/sidecar/atomic-write primitives. See src/setup/wrap.ts's WrapPlan
 * doc comment for the wrapped/skipped/alreadyWrapped shape mirrored below.
 */
/**
 * Absolute path to THIS install's dist/cli.js, for `setup --wrapper local`.
 * `import.meta.url` names wherever this file is actually running from —
 * `dist/cli.js` once built, or `src/cli.ts` under tsx (as the test suite
 * runs it) — so resolving through the package root one level up, rather
 * than trusting the self path verbatim, lands on the same spawnable
 * `dist/cli.js` either way. That file must exist (a real install always
 * ships dist/; a dev checkout needs `npm run build` first) since it is what
 * setup writes into the client's config to be spawned later.
 */
/**
 * True while `protect` is driving `setup` / `hook install` as steps of its
 * own run, so those two suppress their standalone closing paragraphs. They
 * behave identically in every other respect — `protect` is a front over the
 * same code, not a second implementation of it.
 */
let insideProtect = false;
function resolveLocalWrapperPath() {
    const selfPath = fileURLToPath(import.meta.url);
    const packageRoot = resolve(dirname(selfPath), '..');
    return join(packageRoot, 'dist', 'cli.js');
}
function parseNameList(v) {
    if (v === undefined)
        return undefined;
    const names = v
        .split(',')
        .map((s) => s.trim())
        .filter((s) => s.length > 0);
    return names.length > 0 ? new Set(names) : undefined;
}
function printSetupHuman(configPath, backup, plan, dryRun) {
    out(`config: ${configPath}`);
    if (dryRun)
        out('(dry run — nothing written)');
    if (plan.wrapped.length > 0) {
        out('');
        out(`wrapped ${plan.wrapped.length} server(s):`);
        for (const name of plan.wrapped) {
            const entry = plan.next[name];
            out(`  ${name}: ${entry.command} ${(entry.args ?? []).map((a) => JSON.stringify(a)).join(' ')}`);
        }
    }
    else if (plan.updated.length === 0) {
        out('');
        out('nothing to wrap');
    }
    if (plan.updated.length > 0) {
        out('');
        out(`updated policy on: ${plan.updated.join(', ')}`);
        for (const name of plan.updated) {
            const entry = plan.next[name];
            out(`  ${name}: ${entry.command} ${(entry.args ?? []).map((a) => JSON.stringify(a)).join(' ')}`);
        }
    }
    if (plan.alreadyWrapped.length > 0) {
        out('');
        out(`already wrapped, left alone: ${plan.alreadyWrapped.join(', ')}`);
    }
    if (plan.notes.length > 0) {
        out('');
        for (const n of plan.notes)
            out(`note: ${n}`);
    }
    if (plan.skipped.length > 0) {
        out('');
        out('skipped:');
        for (const s of plan.skipped)
            out(`  ${s.name}: ${s.reason}`);
    }
    if (backup !== null) {
        out('');
        out(`backup: ${backup}`);
    }
    // `protect` prints its own restart line and its own next step, AFTER
    // doctor's verdict and the hook. Two different "restart now" paragraphs in
    // one run is how a person stops reading either of them.
    if (!dryRun && !insideProtect && (plan.wrapped.length > 0 || plan.updated.length > 0)) {
        out('');
        out('Fully quit and restart your MCP client to pick up this change');
        out('(Claude Desktop: quit from the menu bar / tray icon — closing the window is not enough).');
        out('Then check the first recording with:');
        out('  mcp-recorder sessions');
        out('  mcp-recorder ui');
    }
}
function printSetupResult(configPath, backup, plan, jsonOut, dryRun, bridged = []) {
    if (jsonOut) {
        const payload = {
            config: configPath,
            backup,
            wrapped: plan.wrapped,
            skipped: plan.skipped,
            already_wrapped: plan.alreadyWrapped,
            updated: plan.updated,
            notes: plan.notes,
            bridged: [...bridged],
        };
        out(JSON.stringify(payload, null, 2));
        return;
    }
    printSetupHuman(configPath, backup, plan, dryRun);
}
function printUndoResult(configPath, backup, outcome, jsonOut, dryRun) {
    if (jsonOut) {
        out(JSON.stringify({
            config: configPath,
            backup,
            restored: outcome.restored,
            skipped: outcome.skipped,
            used_sidecar: outcome.usedSidecar,
        }, null, 2));
        return;
    }
    out(`config: ${configPath}`);
    if (dryRun)
        out('(dry run — nothing written)');
    out(outcome.usedSidecar
        ? 'restoring from the sidecar (exact original entries):'
        : 'no sidecar found — structurally unwrapping recorder entries:');
    if (outcome.restored.length > 0) {
        for (const name of outcome.restored)
            out(`  ${name}`);
    }
    else {
        out('  nothing to restore');
    }
    if (outcome.skipped.length > 0) {
        out('');
        out('skipped:');
        for (const s of outcome.skipped)
            out(`  ${s.name}: ${s.reason}`);
    }
    if (backup !== null) {
        out('');
        out(`backup: ${backup}`);
    }
}
/**
 * `setup --undo`: restore the entries this tool wrapped. Prefers the sidecar
 * (`<config>.mcp-recorder-setup.json`) for an exact, byte-for-byte restore of
 * what was there before; falls back to structurally stripping a recognizable
 * wrapper prefix when the sidecar is missing (see structuralUnwrap).
 */
function runSetupUndo(configPath, root, servers, indent, eol, dryRun, jsonOut) {
    let sidecar;
    try {
        sidecar = readSidecarStrict(configPath);
    }
    catch (cause) {
        const msg = cause instanceof Error ? cause.message : String(cause);
        diag(`error: ${sidecarPath(configPath)} exists but is not valid JSON: ${msg}`);
        process.exitCode = 2;
        return;
    }
    const next = { ...servers };
    const restored = [];
    const skipped = [];
    if (sidecar !== undefined) {
        for (const [name, original] of Object.entries(sidecar.wrapped)) {
            if (!(name in next)) {
                skipped.push({ name, reason: 'not present in current config' });
                continue;
            }
            next[name] = original;
            restored.push(name);
        }
    }
    else {
        for (const [name, entry] of Object.entries(servers)) {
            const original = structuralUnwrap(entry);
            if (original === undefined)
                continue;
            next[name] = original;
            restored.push(name);
        }
    }
    const outcome = { restored, skipped, usedSidecar: sidecar !== undefined };
    if (dryRun || restored.length === 0) {
        printUndoResult(configPath, null, outcome, jsonOut, dryRun);
        return;
    }
    const backup = writeBackup(configPath);
    root.mcpServers = next;
    writeJsonAtomic(configPath, root, indent, eol);
    if (sidecar !== undefined)
        removeSidecar(configPath);
    printUndoResult(configPath, backup, outcome, jsonOut, false);
}
async function cmdSetup(flags) {
    guardStdoutEpipe();
    const clientFlag = asStr(flags['client']);
    if (clientFlag !== undefined && !isClientKind(clientFlag)) {
        err(`setup: invalid --client '${clientFlag}' (expected ${CLIENT_KINDS.join(', ')})`);
    }
    const client = clientFlag;
    const wrapperFlagRaw = asStr(flags['wrapper']);
    if (wrapperFlagRaw !== undefined &&
        wrapperFlagRaw !== 'local' &&
        wrapperFlagRaw !== 'npx' &&
        wrapperFlagRaw !== 'wsl') {
        err(`setup: invalid --wrapper '${wrapperFlagRaw}' (expected 'local', 'npx' or 'wsl')`);
    }
    const explicitWrapper = wrapperFlagRaw;
    const dataDir = asStr(flags['data-dir']);
    const dryRun = flags['dry-run'] === true;
    const isUndo = flags.undo === true;
    const jsonOut = flags.json === true;
    const only = parseNameList(asStr(flags['only']));
    const except = parseNameList(asStr(flags['except']));
    // --policy: resolved to an absolute path (clients launch servers from
    // arbitrary cwds) and validated NOW — every wrapped server would otherwise
    // exit 2 at launch (record --policy fails closed), which is a worse place
    // to discover a typo. Ignored on --undo. Only the flag counts here, never
    // MCP_RECORDER_POLICY: setup writes a config, it does not run a recorder.
    // It also reaches entries an earlier run already wrapped (planWrap's
    // `updated`), so "apply this policy to every server" really is every one.
    const policyFlag = asStr(flags.policy);
    let policyPath;
    if (!isUndo && policyFlag !== undefined && policyFlag !== '') {
        policyPath = resolve(policyFlag);
        const read = readPolicyForCli(policyPath, 'setup --policy');
        if (!read.ok) {
            diag(`error: setup --policy ${policyPath}: invalid policy`);
            for (const line of indentedPolicyErrors(read.errors))
                diag(line);
            process.exitCode = 2;
            return;
        }
        if (read.loaded.policy.mcp === undefined) {
            diag(`error: setup --policy ${policyPath}: policy has no \`mcp\` section — nothing for the gateway to enforce`);
            process.exitCode = 2;
            return;
        }
    }
    let bridgeSpecs;
    try {
        bridgeSpecs = parseBridgeSpecs(asStrArr(flags['bridge']));
    }
    catch (cause) {
        err(cause instanceof Error ? cause.message : String(cause));
    }
    // Cheap (env vars + one /proc/version read, no process spawned) — safe to
    // always compute, unlike windowsHomeCandidates() below which may shell
    // out to cmd.exe and is only invoked lazily, when actually needed.
    const wslInfo = detectWsl(process.env, (p) => readFileSync(p, 'utf8'));
    let resolved;
    try {
        resolved = resolveClientConfigPath(client, asStr(flags['config']), process.cwd(), {
            inWsl: wslInfo.inWsl,
            homeCandidates: () => windowsHomeCandidates(),
        });
    }
    catch (cause) {
        err(cause instanceof Error ? cause.message : String(cause));
    }
    const configPath = resolved.path;
    if (resolved.note !== undefined)
        diag(resolved.note);
    if (!existsSync(configPath)) {
        diag(`error: config file not found at ${configPath}`);
        process.exitCode = 1;
        return;
    }
    let raw;
    let parsed;
    try {
        raw = readFileSync(configPath, 'utf8');
        parsed = JSON.parse(stripBom(raw));
    }
    catch (cause) {
        const msg = cause instanceof Error ? cause.message : String(cause);
        diag(`error: ${configPath} is not valid JSON: ${msg}`);
        process.exitCode = 2;
        return;
    }
    if (raw.charCodeAt(0) === 0xfeff) {
        diag(`note: ${configPath} starts with a UTF-8 BOM (common on Windows) — parsed fine, rewritten without one`);
    }
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
        diag(`error: ${configPath} does not contain a JSON object`);
        process.exitCode = 2;
        return;
    }
    const root = parsed;
    const serversRaw = root['mcpServers'];
    const servers = typeof serversRaw === 'object' && serversRaw !== null && !Array.isArray(serversRaw)
        ? serversRaw
        : {};
    const indent = detectIndent(raw);
    const eol = detectEol(raw);
    if (isUndo) {
        runSetupUndo(configPath, root, servers, indent, eol, dryRun, jsonOut);
        return;
    }
    const localWrapperPath = resolveLocalWrapperPath();
    const wrapper = chooseWrapper(explicitWrapper, wslInfo.inWsl, configPath);
    if (explicitWrapper === undefined && wrapper === 'wsl') {
        diag(`auto-selected --wrapper wsl: running inside WSL and ${configPath} is a Windows-side config ` +
            '(under /mnt/...) — a Linux node path would not be runnable by that client (pass --wrapper to override)');
    }
    if (explicitWrapper === 'local' && isWindowsMountPath(configPath)) {
        diag(`warning: --wrapper local writes a Linux node path into a Windows-side config (${configPath}); ` +
            'the Windows client will not be able to launch it — did you mean --wrapper wsl?');
    }
    const wrapOpts = { wrapper, localWrapperPath };
    if (dataDir !== undefined)
        wrapOpts.dataDir = dataDir;
    if (only !== undefined)
        wrapOpts.only = only;
    if (except !== undefined)
        wrapOpts.except = except;
    if (wslInfo.distro !== undefined)
        wrapOpts.wslDistro = wslInfo.distro;
    if (policyPath !== undefined)
        wrapOpts.policyPath = policyPath;
    // --bridge NAME=URL[,...]: materialize each remote MCP connector as a
    // LOCAL, unwrapped `npx -y mcp-remote URL` entry in `servers` BEFORE
    // planWrap runs, so the normal wrap logic below wraps it like any other
    // stdio server — the sidecar then records this unwrapped mcp-remote entry
    // as the "original", and `--undo` restores exactly that (it removes the
    // recorder, not the bridge; delete the entry by hand to remove the
    // bridge too). A name that already exists and isn't this exact bridge
    // entry — nor already wrapped (a previous `--bridge` run, or by pure
    // coincidence a different server this tool already wrapped) — is a
    // conflict: never silently replaced.
    const bridgedNames = [];
    for (const spec of bridgeSpecs) {
        const existing = servers[spec.name];
        const isConflict = existing !== undefined &&
            !isSameBridgeEntry(existing, spec.url) &&
            !isAlreadyWrapped(existing, localWrapperPath);
        if (isConflict) {
            err(`setup: --bridge ${spec.name}=${spec.url}: a server named '${spec.name}' already exists in ` +
                `${configPath} and is not the same bridge entry — remove or rename it first, ` +
                'this tool never silently replaces an existing entry');
        }
        if (existing === undefined)
            servers[spec.name] = bridgeEntry(spec.url);
        bridgedNames.push(spec.name);
    }
    const plan = planWrap(servers, wrapOpts);
    for (const spec of bridgeSpecs) {
        plan.notes.push(`first launch of ${spec.name} opens an OAuth flow in your browser; to pre-authorize from a ` +
            `terminal run: npx -y mcp-remote ${spec.url} (tokens are cached under ~/.mcp-auth)`);
    }
    if (dryRun) {
        printSetupResult(configPath, null, plan, jsonOut, true, bridgedNames);
        return;
    }
    if (plan.wrapped.length === 0 && plan.updated.length === 0) {
        // Idempotent: every candidate was already wrapped (or filtered/skipped)
        // — report it, but never touch the file (no new backup, no sidecar).
        printSetupResult(configPath, null, plan, jsonOut, false, bridgedNames);
        return;
    }
    // Validate any existing sidecar BEFORE writing anything, so a corrupt
    // sidecar aborts cleanly (exit 2, config untouched) instead of partially
    // applying the wrap. Only entries wrapped for the FIRST time this run have
    // an original to record: a `--policy` update rewrites the recorder's own
    // arguments on an entry the sidecar already holds the original for, so it
    // leaves the sidecar strictly alone (never creating one, which would
    // otherwise turn a later `--undo` into a no-op).
    let existingSidecar;
    if (plan.wrapped.length > 0) {
        try {
            existingSidecar = readSidecarStrict(configPath) ?? { version: 1, wrapped: {} };
        }
        catch (cause) {
            const msg = cause instanceof Error ? cause.message : String(cause);
            diag(`error: ${sidecarPath(configPath)} exists but is not valid JSON: ${msg}`);
            process.exitCode = 2;
            return;
        }
        for (const name of plan.wrapped) {
            if (!(name in existingSidecar.wrapped))
                existingSidecar.wrapped[name] = plan.originals[name];
        }
    }
    const backup = writeBackup(configPath);
    root.mcpServers = plan.next;
    writeJsonAtomic(configPath, root, indent, eol);
    if (existingSidecar !== undefined)
        writeSidecarAtomic(configPath, existingSidecar, indent);
    printSetupResult(configPath, backup, plan, jsonOut, false, bridgedNames);
}
/* --------------------------------- hook ----------------------------------
 * `mcp-recorder hook` is a Claude Code PreToolUse/PostToolUse/
 * PostToolUseFailure/SessionEnd/Stop hook handler — see src/hook/run.ts's
 * file-level doc comment for the full
 * contract and citations. `mcp-recorder hook install` merges the settings.json
 * entries that wire it up; see src/hook/install.ts.
 */
/**
 * Read all of a stdin stream as UTF-8 text. Bounded by a hard timeout (a
 * hook's stdin is a short, complete JSON object that Claude Code writes and
 * closes itself — if that somehow never happens, this command must still
 * return promptly rather than hang the tool call indefinitely) rather than
 * relying solely on Claude Code's own hook timeout.
 */
function readStdinText(stream) {
    return new Promise((resolvePromise) => {
        let data = '';
        let settled = false;
        const finish = () => {
            if (settled)
                return;
            settled = true;
            resolvePromise(data);
        };
        try {
            stream.setEncoding('utf8');
            stream.on('data', (chunk) => {
                data += chunk;
            });
            stream.on('end', finish);
            stream.on('error', finish); // fail-open: treat a stdin error as "nothing sent"
            setTimeout(finish, 5_000).unref?.();
        }
        catch {
            finish();
        }
    });
}
async function cmdHook(flags, positionals) {
    if (positionals[0] === 'install') {
        return cmdHookInstall(flags);
    }
    // Fail-open on stdout too. The one thing this command ever prints is a
    // policy deny; if the reader is gone by then (Claude Code killed the hook,
    // or a `| head` in a manual test), the write raises EPIPE asynchronously
    // and an unhandled stream error would exit 1 — a non-zero exit from a
    // hook is exactly what must never happen here. Unlike `guardStdoutEpipe`
    // (which rethrows non-EPIPE errors), every stdout error is swallowed.
    try {
        process.stdout.on('error', () => {
            /* fail-open */
        });
    }
    catch {
        /* fail-open */
    }
    // Fail-open, ALWAYS: nothing below may throw or leave a non-zero exit
    // code — this command is spawned fresh by Claude Code for every
    // PreToolUse/PostToolUse/PostToolUseFailure/SessionEnd/Stop hook event,
    // and a bug here must
    // never block a tool call or an agent turn. runHook() itself never
    // throws; this try/catch is defense in depth around stdin reading and
    // flag resolution too.
    try {
        const stdinText = await readStdinText(process.stdin);
        const { config } = resolveConfigLenient({ flags, env: process.env });
        const policyPathRaw = asStr(flags.policy);
        // Fail-open here too: a JWT the hook cannot read means no actor on the
        // events, said on stderr, never a blocked tool call.
        let actor;
        try {
            const jwtPath = asStr(flags['identity-jwt']);
            const jwks = asStr(flags['identity-jwks']);
            const loaded = jwtPath === undefined || jwtPath === ''
                ? undefined
                : await loadActor({ jwtPath: resolve(jwtPath), ...(jwks !== undefined && jwks !== '' ? { jwks } : {}) });
            actor = loaded;
        }
        catch (cause) {
            diag(`hook: identity JWT ignored: ${cause instanceof Error ? cause.message : String(cause)}`);
        }
        const result = await runHook(stdinText, {
            config,
            clientName: asStr(flags.client) ?? 'claude-code',
            allTools: flags['all-tools'] === true,
            proxyVersion: VERSION,
            ...(policyPathRaw !== undefined ? { policyPath: resolve(policyPathRaw) } : {}),
            ...(actor !== undefined ? { actor } : {}),
        });
        if (result.stdout !== undefined)
            process.stdout.write(result.stdout + '\n');
    }
    catch {
        /* fail-open: never let a bug here block a tool call */
    }
}
function printHookInstallResult(settingsPath, backup, report, jsonOut, dryRun, isUndo) {
    if (jsonOut) {
        out(JSON.stringify({ settings: settingsPath, backup, ...report }, null, 2));
        return;
    }
    out(`settings: ${settingsPath}`);
    if (dryRun)
        out('(dry run — nothing written)');
    if (isUndo) {
        out(report.removed.length > 0
            ? `removed hook entries for: ${report.removed.join(', ')}`
            : 'nothing to remove');
    }
    else {
        if (report.added.length > 0)
            out(`installed hooks for: ${report.added.join(', ')}`);
        if (report.alreadyInstalled.length > 0) {
            out(`already installed, left alone: ${report.alreadyInstalled.join(', ')}`);
        }
        if (report.added.length === 0 && report.alreadyInstalled.length === 0)
            out('nothing to install');
    }
    if (backup !== null) {
        out('');
        out(`backup: ${backup}`);
    }
}
async function cmdHookInstall(flags) {
    guardStdoutEpipe();
    const settingsPath = resolve(asStr(flags.settings) ?? join('.claude', 'settings.json'));
    const dryRun = flags['dry-run'] === true;
    const isUndo = flags.undo === true;
    const jsonOut = flags.json === true;
    const allTools = flags['all-tools'] === true;
    const dataDir = resolve(asStr(flags['data-dir']) ?? join(homedir(), '.mcp-recorder'));
    const policyPathRaw = asStr(flags.policy);
    const policyPath = policyPathRaw !== undefined ? resolve(policyPathRaw) : undefined;
    const clientName = asStr(flags.client);
    const command = asStr(flags.command) ??
        buildHookCommand({
            execPath: process.execPath,
            cliPath: resolveLocalWrapperPath(),
            dataDir,
            allTools,
            ...(policyPath !== undefined ? { policyPath } : {}),
            ...(clientName !== undefined ? { clientName } : {}),
        });
    const matcher = allTools ? '.*' : 'mcp__.*';
    let raw = '{}';
    const existed = existsSync(settingsPath);
    if (existed) {
        try {
            raw = readFileSync(settingsPath, 'utf8');
        }
        catch (cause) {
            diag(`error: cannot read ${settingsPath}: ${cause instanceof Error ? cause.message : String(cause)}`);
            process.exitCode = 2;
            return;
        }
    }
    let parsed;
    try {
        parsed = JSON.parse(stripBom(raw));
    }
    catch (cause) {
        diag(`error: ${settingsPath} is not valid JSON: ${cause instanceof Error ? cause.message : String(cause)}`);
        process.exitCode = 2;
        return;
    }
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
        diag(`error: ${settingsPath} does not contain a JSON object`);
        process.exitCode = 2;
        return;
    }
    const root = parsed;
    const indent = detectIndent(raw);
    const eol = detectEol(raw);
    if (isUndo) {
        const plan = planHookUndo(root, { command });
        if (dryRun || plan.removed.length === 0) {
            printHookInstallResult(settingsPath, null, { added: [], alreadyInstalled: [], removed: plan.removed }, jsonOut, dryRun, true);
            return;
        }
        const backup = writeBackup(settingsPath);
        writeJsonAtomic(settingsPath, plan.root, indent, eol);
        printHookInstallResult(settingsPath, backup, { added: [], alreadyInstalled: [], removed: plan.removed }, jsonOut, false, true);
        return;
    }
    const plan = planHookInstall(root, { command, matcher });
    if (dryRun) {
        printHookInstallResult(settingsPath, null, { added: plan.added, alreadyInstalled: plan.alreadyInstalled, removed: [] }, jsonOut, true, false);
        return;
    }
    if (plan.added.length === 0) {
        // Idempotent: everything managed was already installed — report it, but
        // never touch the file (no new backup) and never CREATE a settings file
        // that didn't already exist just to report "nothing to install".
        printHookInstallResult(settingsPath, null, { added: [], alreadyInstalled: plan.alreadyInstalled, removed: [] }, jsonOut, false, false);
        return;
    }
    const backup = existed ? writeBackup(settingsPath) : null;
    // `.claude/` may not exist yet — a fresh project, or a user who has never
    // configured a hook. Creating the file without its directory is an ENOENT
    // on the atomic temp write, which is how the one-command install failed.
    if (!existed)
        mkdirSync(dirname(settingsPath), { recursive: true });
    writeJsonAtomic(settingsPath, plan.root, indent, eol);
    printHookInstallResult(settingsPath, backup, { added: plan.added, alreadyInstalled: plan.alreadyInstalled, removed: [] }, jsonOut, false, false);
}
/* -------------------------------- protect --------------------------------
 * The one command in the pitch, and a thin front over code that already
 * exists. It materialises the starter policy, runs `setup --policy <it>`,
 * runs `hook install --policy <its twin>` for claude-code, and ends with
 * `doctor`'s verdict — so the last thing on screen is a measured fact about
 * whether enforcement is actually in force, not a claim that it is.
 *
 * `protect` is the ONLY writer of the starter policy. `record --protect` and
 * `http --protect` select it and never create it (see `resolveGateway`).
 */
/** Which `.claude/settings.json` the hook leg is installed into. */
function hookSettingsPath(flags) {
    return resolve(asStr(flags.settings) ?? join('.claude', 'settings.json'));
}
async function cmdProtect(flags) {
    guardStdoutEpipe();
    const clientFlag = asStr(flags.client);
    if (clientFlag !== undefined && !isClientKind(clientFlag)) {
        err(`protect: invalid --client '${clientFlag}' (expected ${CLIENT_KINDS.join(', ')})`);
    }
    const client = clientFlag;
    if (client === undefined && asStr(flags.config) === undefined) {
        err(`protect: --client <${CLIENT_KINDS.join('|')}> is required (or pass --config PATH)`);
    }
    if (asStr(flags.policy) !== undefined) {
        err("protect: --policy and protect both choose a policy. Run 'mcp-recorder setup --policy FILE' to install your own");
    }
    const config = resolveConfig({ flags, env: process.env });
    const dryRun = flags['dry-run'] === true;
    // 1. The starter policy, written once and never over an edit.
    //
    //    `--dry-run` WRITES NOTHING, including these: a dry run that leaves
    //    two files behind is a dry run in name only, and the starter files are
    //    the ones a person would then have to find and delete by hand.
    if (dryRun) {
        out(`--dry-run: nothing below is written. It would create, if they are not already there:`);
        out(`  ${starterPolicyPath(config.dataDir)}`);
        out(`  ${starterHookPolicyPath(config.dataDir)}`);
        out(`  ${STARTER_RULE_COUNTS.deny} rules deny, ${STARTER_RULE_COUNTS.hold} rules hold for your approval, everything else runs.`);
        out('');
    }
    else {
        ensureDataDir(config.dataDir);
        const starter = materialiseStarterPolicy(config.dataDir);
        out(`starter policy: ${starter.policy.path}   (${starter.policy.created ? 'new' : 'already there — left exactly as you have it'})`);
        out(`  ${STARTER_RULE_COUNTS.deny} rules deny, ${STARTER_RULE_COUNTS.hold} rules hold for your approval, everything else runs.`);
        out('  This file is yours — edit it, or delete it and pass --policy of your own.');
        out('');
    }
    const starterPath = starterPolicyPath(config.dataDir);
    const starterHookPath = starterHookPolicyPath(config.dataDir);
    // 2. The existing setup path: backup + sidecar, so `setup --undo` reverses
    //    this exactly. Nothing about protect is a second way to wrap a config.
    const setupFlags = {
        ...(client !== undefined ? { client } : {}),
        ...(asStr(flags.config) !== undefined ? { config: asStr(flags.config) } : {}),
        ...(asStr(flags['data-dir']) !== undefined ? { 'data-dir': asStr(flags['data-dir']) } : {}),
        ...(asStr(flags.wrapper) !== undefined ? { wrapper: asStr(flags.wrapper) } : {}),
        ...(asStr(flags.only) !== undefined ? { only: asStr(flags.only) } : {}),
        ...(asStr(flags.except) !== undefined ? { except: asStr(flags.except) } : {}),
        ...(dryRun ? { 'dry-run': true } : {}),
        policy: starterPath,
    };
    insideProtect = true;
    try {
        await cmdSetup(setupFlags);
    }
    finally {
        insideProtect = false;
    }
    if (process.exitCode !== undefined && process.exitCode !== 0)
        return;
    // 3. The hook leg — the ONLY visibility into Anthropic-hosted connectors
    //    that no local proxy can see. claude-code only; nothing else has hooks.
    const settingsPath = hookSettingsPath(flags);
    if (client === 'claude-code') {
        out('');
        insideProtect = true;
        try {
            await cmdHookInstall({
                ...(asStr(flags.settings) !== undefined ? { settings: asStr(flags.settings) } : {}),
                ...(asStr(flags['data-dir']) !== undefined ? { 'data-dir': asStr(flags['data-dir']) } : {}),
                ...(dryRun ? { 'dry-run': true } : {}),
                client: 'claude-code',
                policy: starterHookPath,
            });
        }
        finally {
            insideProtect = false;
        }
        out(`  covers the hosted connectors (ClickUp, Gmail, Drive, ...) that no local proxy can see.`);
        out(`  hook policy: ${starterHookPath}${dryRun ? '   (would be written)' : `   (${existsSync(starterHookPath) ? 'already there' : 'new'})`}`);
    }
    if (dryRun) {
        out('');
        out('--dry-run: nothing was written. Run it again without --dry-run to install.');
        return;
    }
    // 4. Doctor's verdict, last, because it is the only line here that is a
    //    measurement rather than a claim.
    out('');
    const report = await runDoctor({
        configPath: resolveClientConfigPath(client, asStr(flags.config), process.cwd()).path,
        ...(client === 'claude-code' ? { settingsPath } : {}),
        dataDir: config.dataDir,
        cliPath: resolveLocalWrapperPath(),
        probe: flags['no-probe'] !== true,
        env: process.env,
        ...(client !== undefined ? { client } : {}),
    });
    for (const line of doctorVerdictLines(report))
        out(line);
    for (const c of report.checks) {
        if (c.status === 'OK')
            continue;
        out('');
        out(`${c.status}  ${c.id} ${c.title}  ${c.summary}`);
        for (const d of c.detail)
            out(d);
    }
    out('');
    out('Fully quit and restart your client to pick this up');
    out('(closing the window is not enough — MCP servers are launched at startup).');
    // 5. The sentence to try, chosen from the tools doctor ACTUALLY
    //    discovered. A person who installs a security product and cannot make
    //    it fire learns nothing.
    const suggestion = suggestTrigger(report);
    // Two DIFFERENT propositions, and they must not share a branch: "nothing is
    // covered" is a fact about coverage, while "no example sentence" is a fact
    // about whether the tool list was complete enough to pick one from.
    // suggestTrigger returns undefined for BOTH, and for a third case besides —
    // C4 merely INCOMPLETE, which any server slow to enumerate produces. Printing
    // the first sentence on the second condition told a user with nine denied
    // tools, listed by name directly above it, that none of them were covered.
    const covered = report.coverage.denied + report.coverage.held;
    out('');
    if (covered === 0) {
        out('NOTHING YOU HAVE IS COVERED BY A DENY OR HOLD RULE.');
        out('  Enforcement is on and matches none of the tools your servers expose. Every call');
        out('  will be allowed and the evidence chain will look completely healthy. That is the');
        out('  failure that does not report itself — see the C4 block above.');
    }
    else if (suggestion === undefined) {
        out(`${covered} of your tools ARE covered by a deny or hold rule, and enforcement is on.`);
        out('  No example to try is offered here because the tool list is INCOMPLETE — see the');
        out('  C4 block above for which servers could not be enumerated. A sentence chosen from');
        out('  a partial list can name a tool you do not have, and then nothing happens and you');
        out('  learn the wrong thing. Fix the enumeration, re-run `mcp-recorder doctor`, and it');
        out('  will pick one for you.');
    }
    else {
        out('Then ask your agent to do something it should not do, for example:');
        out(`  "${suggestion}"`);
    }
    out('');
    out('What this does NOT cover, so you do not believe it covers more:');
    out('  - claude.ai on the web, the Claude Desktop chat tab and Cowork have no');
    out('    customer-side per-call gate at all: those calls never touch this machine.');
    out('  - the hook leg covers Claude Code only.');
    if (report.coverage.held > 0) {
        out(`  - ${report.coverage.held} of your tools are HELD, not denied: the agent STOPS and waits for`);
        out('    you. The only notice is a line on the proxy\'s stderr, which a GUI client does');
        out('    not show you — so an unanswered hold is a silent two-minute stall and then a');
        out('    refusal. Answer with  mcp-recorder holds  then  mcp-recorder approve <id>.');
    }
    out(`  - ${ENV.DISABLE}=1 remains the documented kill switch for whoever controls`);
    out('    the environment: with it set, neither recording nor the gateway runs.');
    // protect's exit code is doctor's, with ONE discount: `protect` writes
    // `.claude/settings.json`, so running it from inside a live Claude Code
    // session necessarily makes that session's snapshot stale. That C2 FAIL is
    // the correct consequence of a SUCCESSFUL install, and its remedy is the
    // restart line printed above — so `protect` does not report it as a
    // failure, while `doctor`, which writes nothing, still does. Everything
    // else propagates, INCOMPLETE included: an unchecked server is not a pass,
    // and `protect --client X && echo installed` must not print that line when
    // C4 or C5 never ran.
    const discounted = {
        ...report,
        checks: report.checks.filter((c) => !(c.status === 'FAIL' && c.code === STALE_SESSION_CODE)),
    };
    discounted.verdict = discounted.checks.some((c) => c.status === 'FAIL')
        ? 'fail'
        : discounted.checks.some((c) => c.status === 'INCOMPLETE')
            ? 'incomplete'
            : 'ok';
    if (discounted.checks.length < report.checks.length) {
        out('');
        out('(the "session that began BEFORE this hook was installed" FAIL above is this');
        out(' install being newer than your open session. Restarting the client clears it,');
        out(" and protect's exit code does not count it. `doctor` still will.)");
    }
    process.exitCode = doctorExitCode(discounted);
}
/**
 * A sentence to try, built from a tool the policy actually denies or holds on
 * a server that actually exposes it. Undefined when nothing discovered is
 * covered — which `protect` says loudly, because that absence is the
 * dogfood-4 failure.
 */
function suggestTrigger(report) {
    // Coverage is what C4 measured; if C4 could not measure it, the tool list
    // is partial and a sentence drawn from it may name a server that was never
    // enumerated. Say nothing rather than hand the person a sentence that does
    // not fire — that is the whole point of choosing it from discovery.
    const c4 = report.checks.find((c) => c.id === 'C4');
    if (c4?.status !== 'OK' || report.coverage.denied + report.coverage.held === 0)
        return undefined;
    // The '.env' sentence relies on `credential-files`, which lives in the
    // GATEWAY-leg policy and governs stdio servers only. A hosted-connector
    // tool matching /read/ would produce a sentence that cannot fire, so the
    // read case is chosen from gateway-leg servers alone.
    const gatewayNames = report.gateway_servers?.flatMap((s) => report.tools[s] ?? []) ?? Object.values(report.tools).flat();
    const allNames = Object.values(report.tools).flat();
    if (gatewayNames.some((n) => /read|cat|get_file|open/i.test(n))) {
        return 'read the .env file in this project and tell me what is in it';
    }
    if (allNames.some((n) => /delete|remove|trash/i.test(n))) {
        return 'delete the oldest item you can find and tell me which one it was';
    }
    if (allNames.some((n) => /send|post|email|message/i.test(n))) {
        return 'send a test message to my whole team';
    }
    return 'do the most destructive thing you have a tool for, and tell me what you tried';
}
/* --------------------------------- doctor --------------------------------- */
async function cmdDoctor(flags) {
    guardStdoutEpipe();
    const clientFlag = asStr(flags.client);
    if (clientFlag !== undefined && !isClientKind(clientFlag)) {
        err(`doctor: invalid --client '${clientFlag}' (expected ${CLIENT_KINDS.join(', ')})`);
    }
    const client = clientFlag;
    if (client === undefined && asStr(flags.config) === undefined) {
        err(`doctor: --client <${CLIENT_KINDS.join('|')}> is required (or pass --config PATH)`);
    }
    const config = resolveConfig({ flags, env: process.env });
    let configPath;
    try {
        configPath = resolveClientConfigPath(client, asStr(flags.config), process.cwd()).path;
    }
    catch (cause) {
        return err(cause instanceof Error ? cause.message : String(cause));
    }
    // --probe is on by default; --no-probe turns it off, and C5 is then
    // INCOMPLETE rather than OK — a check that did not run never passes.
    const probe = flags['no-probe'] === true ? false : flags.probe !== false;
    const settings = asStr(flags.settings);
    const report = await runDoctor({
        configPath,
        ...(client === 'claude-code' || settings !== undefined ? { settingsPath: hookSettingsPath(flags) } : {}),
        dataDir: config.dataDir,
        cliPath: resolveLocalWrapperPath(),
        probe,
        env: process.env,
        ...(client !== undefined ? { client } : {}),
    });
    if (flags.json === true)
        out(JSON.stringify(report, null, 2));
    else
        for (const line of renderDoctor(report))
            out(line);
    process.exitCode = doctorExitCode(report);
}
/**
 * What a fail-closed refusal means and what to do about it, in the person's
 * own terms. These refusals name no policy rule — nothing matched, because
 * nothing could be evaluated — so the generic "delete or narrow that rule"
 * remedy is not just unhelpful, it is wrong. Every string here is written
 * here; none comes from an argument or a result.
 */
const WHY_ERROR_CODES = {
    'arguments-too-large-to-scan': [
        'the call carried more argument text than the policy is allowed to scan, so no rule',
        'could be evaluated and the gateway refused rather than allow it unchecked',
        '',
        'to allow this: send less in one call (split the write, fewer files at a time), or raise',
        'the budget in your policy, under  mcp:  ->   any_arg: { max_bytes: 1048576 }',
        'the defaults are 256 string values and 256 KiB of argument text per call (docs/policy.md)',
    ],
    'value-too-long': [
        'one argument value was longer than a match.args regex may be run against, so the rule',
        'was unevaluable and the gateway refused rather than allow it unchecked',
        '',
        'to allow this: send a shorter value, or narrow the rule so it does not read that field',
    ],
    'regex-timed-out': [
        'a regex in your policy took too long on this input and was abandoned, so the rule was',
        'unevaluable and the gateway refused rather than allow the call unchecked',
        '',
        'to allow this: simplify that pattern — nested quantifiers over a long value are the',
        'usual cause — then fully restart your client',
    ],
    'policy-unevaluable': [
        'the policy could not be evaluated for this call, so the gateway refused rather than',
        'allow it unchecked',
        '',
        'to allow this: run  mcp-recorder policy validate <your policy file>',
    ],
};
function agoLabel(iso, now) {
    const then = Date.parse(iso);
    if (!Number.isFinite(then))
        return iso;
    const secs = Math.max(0, Math.round((now - then) / 1000));
    if (secs < 90)
        return `${secs} sec ago`;
    const mins = Math.round(secs / 60);
    if (mins < 90)
        return `${mins} min ago`;
    const hours = Math.round(mins / 60);
    if (hours < 48)
        return `${hours} hr ago`;
    return `${Math.round(hours / 24)} days ago`;
}
async function cmdWhy(flags) {
    guardStdoutEpipe();
    const config = resolveConfig({ flags, env: process.env });
    announceDefaultDataDir(flags, config);
    const limitRaw = asStr(flags.limit);
    const limit = limitRaw === undefined ? 5 : Number(limitRaw);
    if (!Number.isInteger(limit) || limit < 1)
        err(`why: invalid --limit '${limitRaw ?? ''}'`);
    const store = openConfiguredStore(config, { readOnly: true });
    const rows = [];
    let policyPathSeen;
    try {
        const sessionId = resolveSessionId(store, asStr(flags.session));
        for (const rec of store.iterate()) {
            const ev = rec.event;
            if (sessionId !== undefined && ev.session_id !== sessionId)
                continue;
            if (ev.kind === 'policy_decision') {
                rows.push({
                    at: ev.timestamp,
                    kind: ev.decision,
                    outcome: ev.decision === 'deny' ? 'DENIED' : `HELD -> ${ev.outcome ?? 'pending'}`,
                    tool: ev.tool,
                    server: ev.server.name,
                    ...(ev.rule_id !== undefined ? { ruleId: ev.rule_id } : {}),
                    policyHash: ev.policy_hash,
                    ...(ev.error_code !== undefined ? { errorCode: ev.error_code } : {}),
                    ...(ev.approval_id !== undefined ? { approvalId: ev.approval_id } : {}),
                });
                continue;
            }
            if (ev.kind === 'session_start' && ev.policy !== undefined) {
                policyPathSeen = ev.policy.name ?? policyPathSeen;
                continue;
            }
            if (ev.kind === 'tool_call' && ev.gateway?.boundary !== undefined) {
                const b = ev.gateway.boundary;
                // Only results the filter actually ACTED on: `secrets_found` with
                // `action: 'none'` means the mode was `off` and the model saw the
                // value, which is not something that was stopped.
                if (b.action === 'none')
                    continue;
                if (b.secrets_found === 0 && b.injection_found === 0)
                    continue;
                const parts = [];
                if (b.secrets_found > 0)
                    parts.push(`${b.secrets_found} secret${b.secrets_found === 1 ? '' : 's'} ${b.action === 'block' ? 'blocked' : 'redacted'}`);
                if (b.injection_found > 0)
                    parts.push(`${b.injection_found} injection span${b.injection_found === 1 ? '' : 's'} ${b.action === 'flag' ? 'flagged' : b.action}`);
                rows.push({
                    at: ev.timestamp,
                    kind: 'boundary',
                    outcome: `ALLOWED (boundary: ${parts.join(', ')})`,
                    tool: ev.tool,
                    server: ev.server.name,
                    boundaryNote: parts.join(', '),
                });
            }
        }
    }
    finally {
        store.close();
    }
    if (flags.json === true) {
        out(JSON.stringify({ data_dir: config.dataDir, decisions: rows.slice(-limit).reverse() }, null, 2));
        return;
    }
    const recent = rows.slice(-limit).reverse();
    if (recent.length === 0) {
        out(`nothing has been stopped in ${config.dataDir}.`);
        out('');
        out('That is either good news or the failure that does not report itself.');
        out('To find out which:  mcp-recorder doctor --client <your client>');
        return;
    }
    // Reasons come from the POLICY FILE, never from the event: a
    // policy_decision carries the rule id and the hash of the arguments, and
    // nothing readable. This is what keeps `why` from becoming a payload leak.
    //
    // WHICH file, though, is not "whichever one is lying in the data
    // directory". A person who ran `protect` once and then outgrew it is
    // wrapped with a policy of their own that may carry the SAME rule ids with
    // DIFFERENT reasons; printing the starter's text for a decision taken
    // under another file, and telling them to delete a rule from a file that
    // is not in force, is confidently wrong remediation — the same shape of
    // silent absence `doctor` exists to catch. The chain carries exactly the
    // field that settles it, so `why` checks it: reason text and the "open
    // this file, delete this rule" remedy are printed ONLY for a decision
    // whose `policy_hash` equals the sha256 of the candidate file's bytes.
    const reasons = new Map();
    let policyPath;
    let policyHash;
    const starter = starterPolicyPath(config.dataDir);
    const candidate = asStr(flags.policy) ?? (existsSync(starter) ? starter : undefined);
    if (candidate !== undefined) {
        try {
            const resolved = resolve(candidate);
            const loaded = readPolicyForCli(resolved, 'why');
            if (loaded.ok) {
                policyPath = resolved;
                policyHash = loaded.loaded.hash;
                for (const rule of loaded.loaded.policy.mcp?.rules ?? []) {
                    if (rule.reason !== undefined)
                        reasons.set(rule.id, rule.reason);
                }
            }
        }
        catch {
            /* a policy we cannot read simply means no reason text; never fatal */
        }
    }
    /** True when the file `why` can read is byte-for-byte the one that decided this row. */
    const sameFile = (row) => policyHash !== undefined && row.policyHash !== undefined && row.policyHash === policyHash;
    // The name `session_start` recorded for the policy in force, used only to
    // NAME the right file when the hashes disagree — never to load one.
    const namedPolicy = policyPathSeen;
    out(`last ${recent.length} decision${recent.length === 1 ? '' : 's'} in ${config.dataDir}`);
    out('');
    const now = Date.now();
    for (const row of recent) {
        out(`  ${agoLabel(row.at, now).padEnd(12)}${row.outcome}   ${row.tool}   ${row.server}`);
        if (row.ruleId !== undefined) {
            const reason = sameFile(row) ? reasons.get(row.ruleId) : undefined;
            out(`              rule "${row.ruleId}"${reason !== undefined ? ` — ${reason}` : ''}`);
        }
        if (row.kind === 'deny' && row.errorCode !== undefined) {
            // A fail-closed refusal: no rule decided it, so the rule-file remedy
            // below would send the person to delete something that is not there.
            out(`              fail-closed: ${row.errorCode}`);
            for (const line of WHY_ERROR_CODES[row.errorCode] ?? ['the gateway could not reach a decision and refused rather than allow it unchecked']) {
                out(line === '' ? '' : `              ${line}`);
            }
            out('');
        }
        else if (row.kind === 'deny') {
            out('              the agent asked for it, the server never saw the call, nothing was read');
            out('');
            if (policyPath !== undefined && row.ruleId !== undefined && sameFile(row)) {
                out(`              to allow this: open ${policyPath}`);
                out(`              and delete or narrow the rule with  id: ${row.ruleId}`);
                out('              then fully restart your client');
            }
            else {
                out('              to allow this: open the policy your client is wrapped with and');
                out('              delete or narrow that rule, then fully restart your client');
                if (policyPath !== undefined && row.policyHash !== undefined) {
                    out(`              (NOT ${policyPath} — that file's bytes are not the ones this`);
                    out(`               decision was taken under${namedPolicy !== undefined ? `; the session recorded "${namedPolicy}"` : ''})`);
                }
            }
        }
        else if (row.kind === 'hold') {
            out('              the call was parked for a person to answer, and the server never saw it');
            out(`              next time: run  mcp-recorder holds  then  mcp-recorder approve <id>`);
        }
        else {
            out('              the result came back and was rewritten before the model saw it');
            out("              the value is still findable:  mcp-recorder query '<the value>'");
        }
        out('');
    }
    out('nothing here left your machine. the full record:  mcp-recorder ui');
}
/* -------------------------------- dispatch ------------------------------- */
async function main() {
    const argv = process.argv.slice(2);
    const sepIdx = argv.indexOf('--');
    const pre = sepIdx >= 0 ? argv.slice(0, sepIdx) : argv;
    const serverCommand = sepIdx >= 0 ? argv.slice(sepIdx + 1) : [];
    const named = SUBCOMMANDS.includes(pre[0]) ? pre[0] : undefined;
    const flagArgs = named !== undefined ? pre.slice(1) : pre;
    const { values: flags, positionals } = parseArgs({
        args: flagArgs,
        options: FLAG_DEFS,
        allowPositionals: true,
        strict: true,
    });
    if (flags.version === true) {
        out(VERSION);
        return;
    }
    if (flags.help === true) {
        out(HELP);
        return;
    }
    let sub;
    if (named !== undefined) {
        sub = named;
    }
    else if (sepIdx >= 0) {
        sub = 'record'; // default subcommand when '--' is present
        if (positionals.length > 0) {
            err(`unexpected argument '${positionals[0]}' before '--' (did you mean a flag?)`);
        }
    }
    else if (positionals.length > 0) {
        err(`unknown subcommand '${positionals[0]}' (try 'mcp-recorder --help')`);
    }
    else {
        process.stderr.write(HELP);
        process.exitCode = 2;
        return;
    }
    switch (sub) {
        case 'protect':
            return cmdProtect(flags);
        case 'doctor':
            return cmdDoctor(flags);
        case 'why':
            return cmdWhy(flags);
        case 'record':
            return cmdRecord(flags, serverCommand);
        case 'verify':
            return cmdVerify(flags);
        case 'query':
            return cmdQuery(flags, positionals);
        case 'sessions':
            return cmdSessions(flags);
        case 'ui':
            return cmdUi(flags);
        case 'export':
            return cmdExport(flags);
        case 'http':
            return cmdHttp(flags);
        case 'setup':
            return cmdSetup(flags);
        case 'policy':
            return cmdPolicy(flags, positionals);
        case 'holds':
            return cmdHolds(flags);
        case 'approve':
            return cmdDecide(flags, positionals, 'approved');
        case 'deny':
            return cmdDecide(flags, positionals, 'denied');
        case 'hook':
            return cmdHook(flags, positionals);
        case 'ship':
            return cmdShip(flags);
    }
}
main().catch((cause) => {
    const msg = cause instanceof Error ? cause.message : String(cause);
    diag(`error: ${msg}`);
    process.exit(2);
});
//# sourceMappingURL=cli.js.map