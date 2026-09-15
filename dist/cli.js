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
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';
import { Recorder } from './capture/recorder.js';
import { sha256Hex } from './chain/hash.js';
import { Signer, publicKeyHexFromPem } from './chain/keys.js';
import { ensureDataDir, resolveConfig, resolveConfigLenient } from './config.js';
import { BUNDLE_FILES, exportBundle } from './export/bundle.js';
import { readZipEntries } from './export/unzip.js';
import { HoldError, HoldStore } from './gateway/holds.js';
import { PolicyLoadError, parsePolicyText, sourceForPath } from './policy/load.js';
import { bundleFileOrder, compileToRego } from './policy/rego.js';
import { formatPolicyErrors, validatePolicyObject } from './policy/validate.js';
import { runHttpProxy } from './proxy/http.js';
import { runStdioProxy } from './proxy/stdio.js';
import { queryStore } from './query/touched.js';
import { Redactor } from './redact/redactor.js';
import { renderTimelineHtml } from './replay/render.js';
import { serveUi } from './replay/serve.js';
import { CLIENT_KINDS, isClientKind, resolveClientConfigPath } from './setup/client-config.js';
import { detectEol, detectIndent, readSidecarStrict, removeSidecar, sidecarPath, stripBom, writeBackup, writeJsonAtomic, writeSidecarAtomic, } from './setup/io.js';
import { chooseWrapper, detectWsl, isWindowsMountPath, windowsHomeCandidates } from './setup/wsl.js';
import { planWrap, structuralUnwrap } from './setup/wrap.js';
import { openStore, openStoreReadOnly } from './store/index.js';
import { ENV, FILES } from './types.js';
import { verifyRecords, verifyStore } from './verify/verify.js';
import { VERSION } from './version.js';
const SUBCOMMANDS = [
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
];
const HELP = `@edut/mcp-recorder v${VERSION} — black-box flight recorder for MCP

Usage:
  mcp-recorder [record] [flags] [--policy FILE] -- <server command...>
      transparent stdio proxy: forwards bytes unchanged, records redacted events.
      With --policy FILE (or MCP_RECORDER_POLICY) it becomes a GATEWAY: every
      tools/call is allowed / held / denied per the policy and tool results
      pass through the boundary filter (see docs/gateway.md). A policy that
      cannot be loaded exits 2 before the server is spawned (fail closed)
  mcp-recorder policy validate FILE [--json]
      check a policy.yaml against schema v1 (exit 0 valid, 1 invalid, 2 unreadable)
  mcp-recorder policy compile FILE [--target rego] [--out DIR]
      compile a policy.yaml to an OPA bundle for the Cresec control plane;
      without --out the MCP module (cresec/mcp/...) is printed to stdout
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
  mcp-recorder ui       [--data-dir D] [--session ID] [--port N] [--out FILE] [--no-open]
                        [--public-key K] [--allow-unsigned]
      replay timeline (local web UI, opened in your browser unless --no-open
      or --out is given; or --out FILE for a static page). The integrity
      banner uses the same pin as 'verify' (identity.pub by default)
  mcp-recorder export   [--data-dir D] [--session ID] [--out FILE.zip] [--dir DIR]
      signed evidence bundle a stranger can verify with plain Node.js
  mcp-recorder http     --target URL [--port N] [flags]
      transparent streamable-HTTP proxy in front of an HTTP MCP server
  mcp-recorder setup    --client <claude-desktop|claude-code|cursor> [--config PATH]
                        [--wrapper local|npx|wsl] [--only N,...] [--except N,...]
                        [--data-dir D] [--policy FILE] [--dry-run] [--undo] [--json]
      wrap every stdio MCP server in a client's config behind this recorder,
      safely (timestamped backup + sidecar) and reversibly (--undo). --config
      overrides the resolved path and makes --client optional. --policy FILE
      bakes '--policy <absolute path>' into every wrapped entry (gateway
      mode). Inside WSL, when the resolved config belongs to a Windows-side
      client, --wrapper wsl is auto-selected (spawns the wrapped server via
      wsl.exe so a Windows client can actually launch it) unless --wrapper
      is given
  mcp-recorder --help | --version

Flags:
  --data-dir D    evidence directory (default ~/.mcp-recorder; env MCP_RECORDER_DATA_DIR)
  --store B       evidence backend: sqlite | jsonl     (env MCP_RECORDER_STORE)
  --redact M      redaction mode: allowlist | off      (env MCP_RECORDER_REDACT)
  --name NAME     logical server name stamped on events
  --identity L    operator identity label stamped on events
  --policy FILE   record: policy.yaml to enforce (gateway mode; env MCP_RECORDER_POLICY)
                   setup: bake '--policy <absolute FILE>' into every wrapped entry
                   (stdio only: 'http --policy' is rejected)
  --target T      policy compile: output target, only 'rego' (default)
                   http: the upstream MCP server URL
  --all           holds: include decided / expired holds, not just pending ones
  --session ID    select a session (query / ui / export); a unique prefix of
                   the id works too, same as the ids 'sessions' prints
  --public-key K  pin verify to this ed25519 key instead of the default
                   (64-hex, or a path to a file holding hex or a PEM)
  --allow-unsigned
                   verify: downgrade an unsigned chain/tail to a warning
                   instead of a failure (still reported, never silent)
  --json          machine-readable output (verify / query / sessions / setup / policy validate / holds)
  --client C      setup: claude-desktop | claude-code | cursor
  --config PATH   setup: config file to edit (overrides --client's default)
  --wrapper W     setup: local (default, this install) | npx (published form) |
                   wsl (wsl.exe, auto-selected for a Windows-side config in WSL)
  --only N,...    setup: wrap only these server names
  --except N,...  setup: wrap every server except these names
  --dry-run       setup: print what would change; write nothing
  --undo          setup: restore the servers this tool wrapped
  --help, -h      show this help and exit
  --version, -V   show the version and exit

Environment:
  MCP_RECORDER_DISABLE=1   pure passthrough, nothing recorded — and no gateway
                           enforcement either (it is the kill switch)
  MCP_RECORDER_POLICY=F    same as 'record --policy F' when the flag is absent
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
    'dry-run': { type: 'boolean' },
    undo: { type: 'boolean' },
    policy: { type: 'string' },
    all: { type: 'boolean' },
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
 * `readOnly: true` (used by the inspection commands — verify/query/sessions/
 * ui/export) resolves the backend without ever creating a store file as a
 * side effect of merely looking: on a data dir where nothing has recorded
 * yet, it returns an empty store instead of the write path's "create
 * whichever backend is available" behavior (see src/store/index.ts).
 */
function openConfiguredStore(config, opts = {}) {
    const storeOpts = config.storeBackend !== undefined
        ? { dataDir: config.dataDir, backend: config.storeBackend }
        : { dataDir: config.dataDir };
    return opts.readOnly === true ? openStoreReadOnly(storeOpts) : openStore(storeOpts);
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
/** Wrap a recorder so the CLI learns the session id of the first event. */
function tapSessionId(recorder) {
    let sessionId;
    const wrapped = {
        record(event) {
            if (sessionId === undefined)
                sessionId = event.session_id;
            recorder.record(event);
        },
        flush: () => recorder.flush(),
        close: () => recorder.close(),
        stats: () => recorder.stats(),
    };
    return { recorder: wrapped, sessionId: () => sessionId };
}
/**
 * Build redactor/store/signer/recorder for a proxy run. ANY init failure is
 * fail-open: warn on stderr and continue as a pure passthrough. This is also
 * where the data directory gets created (moved out of config resolution —
 * see config.ts) so a bad --data-dir/MCP_RECORDER_DATA_DIR degrades to pure
 * passthrough here instead of throwing before the wrapped server can spawn.
 *
 * Store and signer failures are handled separately: a store that can't be
 * opened means nothing can be recorded (full passthrough). A signer that
 * can't be loaded (e.g. a corrupt identity.key) still leaves the store
 * usable — recording continues, just without head signatures.
 */
async function setupProxyRecording(config) {
    const redactor = new Redactor({ mode: config.redactMode });
    let store = null;
    let signer = null;
    if (config.disabled) {
        diag('MCP_RECORDER_DISABLE=1 — recording disabled, pure passthrough');
    }
    else {
        try {
            ensureDataDir(config.dataDir);
            store = openConfiguredStore(config);
        }
        catch (cause) {
            const msg = cause instanceof Error ? cause.message : String(cause);
            diag(`recording disabled (init failed, traffic unaffected): ${msg}`);
            try {
                store?.close();
            }
            catch {
                /* fail-open */
            }
            store = null;
        }
        if (store !== null) {
            try {
                signer = await Signer.load(config.dataDir);
            }
            catch (cause) {
                const msg = cause instanceof Error ? cause.message : String(cause);
                diag(`recording without head signatures (identity key init failed): ${msg}`);
                signer = null;
            }
        }
    }
    const inner = new Recorder({ store, signer });
    const { recorder, sessionId } = tapSessionId(inner);
    return {
        recorder,
        redactor,
        sessionId,
        storePath: store?.path,
        stats: () => inner.stats(),
    };
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
function resolvePolicyPath(flags, env) {
    const flag = asStr(flags.policy);
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
    // Gateway mode is the ONE deliberate exception to fail-open, and it is
    // decided here, before any store is opened or any process spawned: an
    // operator who asked for enforcement gets enforcement or a clear exit 2.
    // MCP_RECORDER_DISABLE=1 is the documented kill switch — it turns the
    // gateway off along with recording (pure passthrough, said out loud).
    const policyPath = resolvePolicyPath(flags, process.env);
    let gateway;
    if (policyPath !== undefined) {
        if (config.disabled) {
            diag(`MCP_RECORDER_DISABLE=1 — gateway disabled too (kill switch): policy ${policyPath} is NOT enforced, ` +
                'pure passthrough');
        }
        else {
            const policy = loadGatewayPolicy(policyPath);
            // The holds dir is created lazily by HoldStore (0700) on the first
            // hold, independent of the evidence store: a store that fails to open
            // degrades recording to passthrough but never enforcement.
            gateway = { policy, holdStore: new HoldStore(config.dataDir) };
        }
    }
    const setup = await setupProxyRecording(config);
    const exitCode = await runStdioProxy({
        command: serverCommand,
        recorder: setup.recorder,
        redactor: setup.redactor,
        ...(config.serverName !== undefined ? { serverName: config.serverName } : {}),
        ...(config.identityLabel !== undefined ? { identityLabel: config.identityLabel } : {}),
        ...(gateway !== undefined ? { gateway } : {}),
        proxyVersion: VERSION,
    });
    writeRunSummary(setup);
    process.exit(exitCode);
}
async function cmdHttp(flags) {
    const targetUrl = asStr(flags.target) ?? err('http: --target URL is required');
    const port = parsePort(flags.port);
    // Gateway mode is stdio-only in v1. Refusing (rather than ignoring the
    // flag) keeps an operator from believing enforcement is on when it is not.
    if (resolvePolicyPath(flags, process.env) !== undefined) {
        err('http: gateway mode is available for the stdio transport only (drop --policy / MCP_RECORDER_POLICY)');
    }
    installUncaughtExceptionGuard();
    // Lenient: nothing about recording configuration may prevent the proxy
    // from standing up. Bad --redact/--store values fall back to defaults.
    const { config, warnings } = resolveConfigLenient({ flags, env: process.env });
    for (const w of warnings)
        diag(w);
    const setup = await setupProxyRecording(config);
    const proxy = await runHttpProxy({
        targetUrl,
        ...(port !== undefined ? { port } : {}),
        recorder: setup.recorder,
        redactor: setup.redactor,
        ...(config.serverName !== undefined ? { serverName: config.serverName } : {}),
        ...(config.identityLabel !== undefined ? { identityLabel: config.identityLabel } : {}),
        proxyVersion: VERSION,
    });
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
    diag(`http proxy listening at ${proxy.url} -> ${targetOrigin} (Ctrl-C to stop)`);
    await waitForShutdownSignal();
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
async function cmdSessions(flags) {
    guardStdoutEpipe();
    const config = resolveConfig({ flags, env: process.env });
    const store = openConfiguredStore(config, { readOnly: true });
    try {
        const sessions = store.sessions();
        if (flags.json === true) {
            out(JSON.stringify(sessions, null, 2));
            return;
        }
        if (sessions.length === 0) {
            out('no sessions recorded');
            return;
        }
        out(formatTable(['SESSION', 'STARTED', 'ENDED', 'SERVER', 'EVENTS', 'TOOL_CALLS', 'ERRORS'], sessions.map((s) => [
            id8(s.session_id),
            s.started_at,
            s.ended_at ?? '(open)',
            s.server_name,
            String(s.event_count),
            String(s.tool_call_count),
            String(s.error_count),
        ])));
    }
    finally {
        store.close();
    }
}
async function cmdUi(flags) {
    guardStdoutEpipe();
    const config = resolveConfig({ flags, env: process.env });
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
        diag(`replay UI at ${ui.url} (Ctrl-C to stop)`);
        if (flags['no-open'] !== true)
            tryOpenBrowser(ui.url);
        await waitForShutdownSignal();
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
function policyRuleCounts(loaded) {
    return {
        mcp: loaded.policy.mcp?.rules.length ?? 0,
        egress: loaded.policy.egress?.rules.length ?? 0,
    };
}
async function cmdPolicy(flags, positionals) {
    guardStdoutEpipe();
    const usage = 'usage: mcp-recorder policy validate <file> [--json] | mcp-recorder policy compile <file> [--target rego] [--out DIR]';
    const verb = positionals[0] ?? err(`policy: missing <validate|compile> (${usage})`);
    if (verb !== 'validate' && verb !== 'compile') {
        err(`policy: unknown verb '${verb}' (expected 'validate' or 'compile'; ${usage})`);
    }
    const fileArg = positionals[1] ?? err(`policy ${verb}: missing <file> (${usage})`);
    if (positionals.length > 2) {
        err(`policy ${verb}: unexpected argument '${positionals[2]}' (${usage})`);
    }
    const jsonOut = flags.json === true;
    const path = resolve(fileArg);
    if (verb === 'validate') {
        const read = readPolicyForCli(path, 'policy validate');
        if (!read.ok) {
            printPolicyInvalid(path, read.errors, jsonOut);
            return;
        }
        const counts = policyRuleCounts(read.loaded);
        if (jsonOut) {
            out(JSON.stringify({
                path,
                valid: true,
                ...(read.loaded.name !== undefined ? { name: read.loaded.name } : {}),
                hash: read.loaded.hash,
                source: read.loaded.source,
                mcp_rules: counts.mcp,
                egress_rules: counts.egress,
            }, null, 2));
            return;
        }
        out(`${path}: valid (${counts.mcp} mcp rules, ${counts.egress} egress rules)`);
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
    else {
        out('');
        out('nothing to wrap');
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
    if (!dryRun && plan.wrapped.length > 0) {
        out('');
        out('Fully quit and restart your MCP client to pick up this change');
        out('(Claude Desktop: quit from the menu bar / tray icon — closing the window is not enough).');
        out('Then check the first recording with:');
        out('  mcp-recorder sessions');
        out('  mcp-recorder ui');
    }
}
function printSetupResult(configPath, backup, plan, jsonOut, dryRun) {
    if (jsonOut) {
        const payload = {
            config: configPath,
            backup,
            wrapped: plan.wrapped,
            skipped: plan.skipped,
            already_wrapped: plan.alreadyWrapped,
            notes: plan.notes,
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
    const plan = planWrap(servers, wrapOpts);
    if (dryRun) {
        printSetupResult(configPath, null, plan, jsonOut, true);
        return;
    }
    if (plan.wrapped.length === 0) {
        // Idempotent: every candidate was already wrapped (or filtered/skipped)
        // — report it, but never touch the file (no new backup, no sidecar).
        printSetupResult(configPath, null, plan, jsonOut, false);
        return;
    }
    // Validate any existing sidecar BEFORE writing anything, so a corrupt
    // sidecar aborts cleanly (exit 2, config untouched) instead of partially
    // applying the wrap.
    let existingSidecar;
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
    const backup = writeBackup(configPath);
    root.mcpServers = plan.next;
    writeJsonAtomic(configPath, root, indent, eol);
    writeSidecarAtomic(configPath, existingSidecar, indent);
    printSetupResult(configPath, backup, plan, jsonOut, false);
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
    }
}
main().catch((cause) => {
    const msg = cause instanceof Error ? cause.message : String(cause);
    diag(`error: ${msg}`);
    process.exit(2);
});
//# sourceMappingURL=cli.js.map