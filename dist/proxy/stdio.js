/**
 * Transparent stdio passthrough proxy (M0) + capture tap (M1) + opt-in
 * gateway mode (P2-7).
 *
 * FORWARDING IS SACRED: client<->server bytes flow through plain .pipe()
 * with backpressure and are never mutated, delayed, or filtered. The tap
 * attaches separate 'data' listeners feeding a LineScanner; everything the
 * tap does is wrapped fail-open — a recorder/tap failure is logged once to
 * stderr and traffic continues.
 *
 * GATEWAY MODE (`opts.gateway` present, i.e. `record --policy`) is the ONE
 * sanctioned exception, and only for `tools/call` requests and their
 * results: the two raw pipes are replaced by two Transform streams that
 * line-split, JSON.parse each line exactly once (the tap's parse is folded
 * in), and
 *  - client->server: evaluate every `tools/call` request against the policy
 *    (allow = forward the ORIGINAL bytes; deny = synthesize an isError
 *    result, forward nothing; hold = park the bytes until `approve`/`deny`,
 *    timeout, `notifications/cancelled` or shutdown). Every other line is
 *    forwarded byte-for-byte (oversized and unparseable lines included).
 *  - server->client: run the boundary filter over the result of a
 *    tools/call the gateway saw; forward the original bytes when nothing
 *    changed, else the re-serialized message.
 * Enforcement fails CLOSED (an evaluation throw or an unwritable hold is a
 * deny); recording stays fail-open exactly as in record mode. Known v1
 * limits, on purpose: a `hold` inside a JSON-RPC batch is treated as deny,
 * a `tools/call` without an id (a notification) is forwarded unevaluated,
 * and a line over the 32 MiB tap cap cannot be parsed so it is forwarded
 * unchanged and recorded as `protocol_error` — as in record mode.
 */
import { constants as osConstants, hostname as osHostname, userInfo } from 'node:os';
import { basename } from 'node:path';
import { performance } from 'node:perf_hooks';
import { randomUUID } from 'node:crypto';
import { Transform } from 'node:stream';
import { canonicalJson, sha256Ref } from '../chain/hash.js';
import { applyBoundary, defaultSecretPatterns, deniedText, synthesizeDeniedResult, } from '../gateway/boundary.js';
import { evaluateMcp } from '../policy/engine.js';
import { normalizePolicy } from '../policy/types.js';
import { planSpawn, spawnWrapped, terminateChild, withNodeDirOnPath } from './spawn.js';
import { SCHEMA } from '../schema/events.js';
import { scrubArgv, scrubToolArguments, structuralString } from '../redact/redactor.js';
import { LineScanner } from './framing.js';
const NL = 0x0a;
/** Explicit rule ids (`ID_PATTERN`) and the auto-assigned `rule[<i>]` survive as-is. */
const RULE_ID_SHAPE = /^(?:[A-Za-z0-9_.:/-]{1,64}|rule\[[0-9]+\])$/;
/**
 * Line framing for the gateway Transforms. The chunk is walked newline by
 * newline so every segment's bytes are known: a complete line under the tap
 * cap reaches `onLine` with its exact bytes (`ScannedLine.raw`) and is
 * forwarded by the handler's decision; an empty line goes straight through;
 * a line that grows past the cap cannot be buffered, so its bytes are
 * forwarded as they arrive (`forward`) while the scanner only counts and
 * hashes it. `carry` references the chunks the scanner is already
 * buffering, so nothing is copied twice.
 */
class GatewayLineSplitter {
    forward;
    onLine;
    scanner = new LineScanner();
    /** Segments of the current partial line, in case it turns out oversized (or empty). */
    carry = [];
    /** True while streaming an oversized line straight through. */
    passthrough = false;
    constructor(forward, onLine) {
        this.forward = forward;
        this.onLine = onLine;
    }
    hasPartialLine() {
        return this.scanner.hasPartialLine();
    }
    chunk(chunk) {
        let start = 0;
        while (start < chunk.length) {
            const nl = chunk.indexOf(NL, start);
            if (nl === -1) {
                this.partial(chunk.subarray(start));
                return;
            }
            this.segment(chunk.subarray(start, nl + 1));
            start = nl + 1;
        }
    }
    /** Trailing bytes with no newline yet. */
    partial(bytes) {
        this.scanner.push(bytes);
        if (this.passthrough) {
            this.forward(bytes);
            return;
        }
        this.carry.push(bytes);
        if (this.scanner.partialLineOversized())
            this.flushCarry(true);
    }
    /** A segment ending in '\n' — completes exactly one (possibly empty) line. */
    segment(bytes) {
        const lines = this.scanner.push(bytes);
        const line = lines[0];
        if (this.passthrough) {
            this.forward(bytes); // the oversized line's tail
            this.passthrough = false;
            this.carry = [];
        }
        else if (line === undefined || line.oversized) {
            // Empty line (nothing to evaluate) or a line that crossed the cap
            // inside this very segment: its bytes exist only here — forward them.
            this.flushCarry(false);
            this.forward(bytes);
        }
        else {
            this.carry = []; // a normal line: the handler forwards `line.raw` or not
        }
        if (line !== undefined)
            this.onLine(line);
    }
    flushCarry(enterPassthrough) {
        for (const bytes of this.carry)
            this.forward(bytes);
        this.carry = [];
        this.passthrough = enterPassthrough;
    }
    end() {
        this.carry = [];
        this.passthrough = false;
        for (const line of this.scanner.end())
            this.onLine(line);
    }
}
/** Rule ids come from the validated policy file, so only an off-shape one is hashed. */
function cappedRuleId(id) {
    return RULE_ID_SHAPE.test(id) ? id : sha256Ref(id);
}
function isRpcId(v) {
    return typeof v === 'string' || typeof v === 'number';
}
/** A `tools/call` REQUEST (has an id) naming a tool — the only thing the policy evaluates. */
function isToolsCallRequest(msg) {
    if (!isPlainObject(msg) || msg.method !== 'tools/call' || !isRpcId(msg.id))
        return false;
    return isPlainObject(msg.params) && typeof msg.params.name === 'string';
}
function asBuffer(chunk) {
    return Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk));
}
const CREDENTIAL_NAME_RE = /(TOKEN|SECRET|PASSW|API[_-]?KEY|CREDENTIAL|AUTH)/i;
const RUNNERS = new Set(['node', 'npx', 'tsx', 'bun', 'deno', 'bunx']);
// Runner flags with no value (skipped outright) vs. flags that consume the
// next argv token as their value (that token is skipped too).
const RUNNER_BARE_FLAGS = new Set(['-y', '--yes', '-q', '--quiet']);
const RUNNER_VALUE_FLAGS = new Set(['-p', '--package']);
const MAX_PENDING = 10_000;
// Must cover the recorder's full retry run (~6s, src/capture/recorder.ts) so a
// contended store delays session_end rather than losing it.
const CLOSE_TIMEOUT_MS = 8_000;
/**
 * Credential-fingerprint caps (P2 fix): env-derived fingerprints are capped
 * on their own so a wrapped server with many credential-shaped env vars
 * cannot fill the whole budget and silently crowd out argv/URL-derived
 * fingerprints pushed afterward — those must always have room to append, up
 * to the overall total below.
 */
const ENV_CREDENTIAL_FINGERPRINT_CAP = 32;
const MAX_CREDENTIAL_FINGERPRINTS = 64;
/** result_hash for a synthesized "unanswered" event: sha256 of canonical `null`. */
const NULL_RESULT_HASH = sha256Ref(canonicalJson(null));
/** Exit code for a child terminated by a signal: 128 + signal number (POSIX convention). */
function signalExitCode(signal) {
    const num = osConstants.signals[signal];
    return num !== undefined ? 128 + num : 1;
}
/** Exit code for a command that failed to spawn at all. */
function spawnErrorExitCode(code) {
    if (code === 'ENOENT')
        return 127;
    if (code === 'EACCES')
        return 126;
    return 1;
}
/**
 * Best-effort logical server name from argv. For a bare command this is just
 * its basename; for a runner (`npx`, `node`, `tsx`, ...) it walks past known
 * runner flags (e.g. the `-y` in the README's own `npx -y <pkg>` wrapping)
 * to find the first positional argument, which is the actual server.
 */
function deriveServerName(command) {
    const first = basename(command[0] ?? '');
    // Strips script/executable extensions before the RUNNERS check, so a
    // Windows-installed runner shim (`npx.cmd`, `node.exe`, `tsx.bat`, ...) is
    // still recognized as `npx`/`node`/`tsx` the same way a bare POSIX name is.
    const firstNoExt = first.replace(/\.(?:[cm]?(?:js|ts)|exe|cmd|bat)$/i, '');
    if (!RUNNERS.has(firstNoExt.toLowerCase()))
        return first;
    for (let i = 1; i < command.length; i++) {
        const tok = command[i] ?? '';
        if (RUNNER_BARE_FLAGS.has(tok) || tok.startsWith('--package='))
            continue;
        if (RUNNER_VALUE_FLAGS.has(tok)) {
            i++; // skip the flag's value too
            continue;
        }
        return basename(tok);
    }
    return first;
}
function round2(n) {
    return Math.round(n * 100) / 100;
}
function isPlainObject(v) {
    return typeof v === 'object' && v !== null && !Array.isArray(v);
}
/**
 * Pending-request map key. JSON-RPC ids may be a number or a string, and
 * `1` and `"1"` are distinct ids — String(id) alone would collapse them, so
 * the id's type is folded into the key too.
 */
function pendingKey(prefix, id) {
    return prefix + (typeof id === 'number' ? 'n:' : 's:') + String(id);
}
export async function runStdioProxy(opts) {
    const proxyStdin = opts.stdin ?? process.stdin;
    const proxyStdout = opts.stdout ?? process.stdout;
    const proxyStderr = opts.stderr ?? process.stderr;
    const env = opts.env ?? process.env;
    const { recorder, redactor } = opts;
    const diag = (msg) => {
        try {
            proxyStderr.write(`[mcp-recorder] ${msg}\n`);
        }
        catch {
            /* even diagnostics are fail-open */
        }
    };
    let tapErrorLogged = false;
    const tapError = (err) => {
        if (tapErrorLogged)
            return;
        tapErrorLogged = true;
        diag(`tap error (recording degraded, traffic unaffected): ${err instanceof Error ? err.stack ?? err.message : String(err)}`);
    };
    /* ----------------------- identity & server context ---------------------- */
    let osUser = '';
    let host = '';
    try {
        osUser = userInfo().username;
    }
    catch {
        /* keep empty */
    }
    try {
        host = osHostname();
    }
    catch {
        /* keep empty */
    }
    const initialServerName = opts.serverName || deriveServerName(opts.command);
    const fingerprint = sha256Ref(`${osUser}\0${host}\0${opts.identityLabel || ''}\0${initialServerName}`);
    // P2 fix: env-derived fingerprints are capped at ENV_CREDENTIAL_FINGERPRINT_CAP
    // on their own (not the shared total), reserving room below the overall
    // MAX_CREDENTIAL_FINGERPRINTS cap for argv/URL-derived fingerprints so
    // those are never silently dropped just because env filled the budget
    // first.
    const credentialFingerprints = [];
    try {
        for (const [name, value] of Object.entries(env)) {
            if (credentialFingerprints.length >= ENV_CREDENTIAL_FINGERPRINT_CAP)
                break;
            if (typeof value !== 'string' || value.length < 8)
                continue;
            if (!CREDENTIAL_NAME_RE.test(name))
                continue;
            credentialFingerprints.push({ name, ref: redactor.hashString(value) });
        }
    }
    catch (err) {
        tapError(err);
    }
    // Wrapped command argv leak fix (P1): a raw argv.join(' ') stamped on every
    // event verbatim would leak `--api-key sk-...` / `--token ...` / DSNs with
    // userinfo. scrubArgv() hashes credential-shaped elements and strips URL
    // userinfo; every replaced piece is also fingerprinted so `query` finds it.
    let scrubbedCommand = opts.command.join(' ');
    try {
        const scrubbedArgv = scrubArgv(opts.command, redactor);
        scrubbedCommand = scrubbedArgv.command;
        for (const fp of scrubbedArgv.fingerprints) {
            if (credentialFingerprints.length >= MAX_CREDENTIAL_FINGERPRINTS)
                break;
            credentialFingerprints.push(fp);
        }
    }
    catch (err) {
        tapError(err);
    }
    // Mutable bits learned from the initialize handshake.
    let clientName;
    let clientVersion;
    let learnedServerName;
    let learnedServerVersion;
    const currentIdentity = () => {
        const id = { fingerprint };
        if (osUser)
            id.os_user = osUser;
        if (host)
            id.hostname = host;
        if (clientName !== undefined)
            id.client_name = clientName;
        if (clientVersion !== undefined)
            id.client_version = clientVersion;
        if (opts.identityLabel)
            id.label = opts.identityLabel;
        if (credentialFingerprints.length > 0) {
            id.credential_fingerprints = credentialFingerprints.map((c) => ({ ...c }));
        }
        return id;
    };
    const currentServer = () => {
        const server = {
            name: opts.serverName || learnedServerName || initialServerName,
            command: scrubbedCommand,
            transport: 'stdio',
        };
        if (learnedServerVersion !== undefined)
            server.version = learnedServerVersion;
        return server;
    };
    const sessionId = randomUUID();
    const base = (kind, attributes) => ({
        schema: SCHEMA,
        event_id: randomUUID(),
        session_id: sessionId,
        timestamp: new Date().toISOString(),
        kind,
        identity: currentIdentity(),
        server: currentServer(),
        attributes,
    });
    const record = (event) => {
        recorder.record(event);
    };
    /* ------------------------------- spawn ---------------------------------- */
    // Child PATH: add the directory of the Node binary running this proxy, on
    // every platform, when it isn't already there. A wrapped command like
    // "npx" needs to resolve to a sibling npx/npx.cmd even when this proxy
    // itself was launched by an absolute path to Node with a thin PATH
    // (nvm/fnm shims, `wsl.exe -e`, some Windows MCP client launchers). It is
    // appended, so it never shadows something the operator put earlier on
    // PATH on purpose — except on WSL, where it goes ahead of the Windows
    // interop entries (see withNodeDirOnPath).
    const spawnEnv = withNodeDirOnPath(env, process.execPath);
    // On win32, a .cmd/.bat shim (npx, npm, uvx, ... installed as such) can't
    // be exec'd directly without `shell: true` (Node's CVE-2024-27980
    // hardening throws EINVAL) — see src/proxy/spawn.ts. spawnWrapped routes
    // that case through cmd.exe. The event schema's recorded command/server
    // name (scrubbedCommand/deriveServerName, above) always stays the
    // operator's original argv, never cmd.exe — this diagnostic line is purely
    // informational.
    const spawnPlan = planSpawn(opts.command, spawnEnv, process.platform);
    if (spawnPlan.options.windowsVerbatimArguments) {
        diag(`spawning "${opts.command[0]}" via cmd.exe (resolved to a .cmd/.bat shim)`);
    }
    const child = spawnWrapped(opts.command, spawnEnv, spawnPlan);
    // Gateway mode (record --policy) is wired further down, once the tap
    // closures it shares exist; nothing flows before this function returns,
    // so attaching its Transforms later loses no bytes. Without a policy the
    // forwarding below is exactly the M0 recorder.
    const gateway = opts.gateway;
    /** Gateway mode's server->client Transform (the EPIPE handler unpipes it). */
    let s2cTransform;
    /** Gateway mode: set once the client's read end is gone; synthesized writes stop. */
    let clientGone = false;
    /** Gateway mode: resolve every parked hold as `session_end` (idempotent). */
    let resolveAllHolds;
    if (gateway === undefined) {
        // Forwarding: plain pipes, untouched. (pipe() ends child.stdin when
        // proxyStdin ends, which is exactly the MCP stdio shutdown convention.)
        proxyStdin.pipe(child.stdin);
        child.stdout.pipe(proxyStdout, { end: false });
    }
    child.stderr.pipe(proxyStderr, { end: false });
    // A dying child can EPIPE its stdin while the client is still writing;
    // that must never crash the proxy.
    child.stdin.on('error', (err) => {
        if (err.code !== 'EPIPE' && err.code !== 'ERR_STREAM_DESTROYED') {
            diag(`child stdin error: ${err.message}`);
        }
    });
    proxyStdin.on('error', (err) => diag(`stdin error: ${err.message}`));
    child.stdout.on('error', (err) => diag(`child stdout error: ${err.message}`));
    child.stderr.on('error', (err) => diag(`child stderr error: ${err.message}`));
    // The MCP client can close its read end of our stdout/stderr at any time
    // (it exited, it stopped reading, a downstream pipe broke). .pipe()'s
    // destination gets no default 'error' listener, so without one an EPIPE
    // here is an unhandled 'error' event — it crashes the whole proxy, drops
    // whatever was queued, and session_end never gets written. Both directions
    // must survive it.
    const isEpipeLike = (err) => err.code === 'EPIPE' || err.code === 'ERR_STREAM_DESTROYED';
    proxyStdout.on('error', (err) => {
        if (!isEpipeLike(err)) {
            diag(`stdout error: ${err.message}`);
            return;
        }
        // The client is gone. Stop feeding it, and end the child's stdin per the
        // stdio shutdown convention so the server winds down on its own; the
        // normal child 'close' -> finalize path then seals the session.
        // unpipe() can leave child.stdout paused even though the tap's own
        // 'data' listener is still attached (and Node's ChildProcess delays its
        // 'close' event until every stdio stream is drained) — resume() keeps
        // it flowing into the tap and lets 'close' fire normally.
        try {
            if (gateway === undefined) {
                child.stdout.unpipe(proxyStdout);
                child.stdout.resume();
            }
            else if (s2cTransform !== undefined) {
                // Same idea one hop upstream: keep the Transform draining (it still
                // records) while nothing reaches the client any more.
                s2cTransform.unpipe(proxyStdout);
                s2cTransform.resume();
            }
        }
        catch {
            /* fail-open */
        }
        clientGone = true;
        try {
            resolveAllHolds?.();
        }
        catch (err) {
            tapError(err);
        }
        try {
            if (!child.stdin.writableEnded)
                child.stdin.end();
        }
        catch {
            /* fail-open */
        }
    });
    proxyStderr.on('error', (err) => {
        if (!isEpipeLike(err)) {
            diag(`stderr error: ${err.message}`);
            return;
        }
        // Diagnostics/child stderr have nowhere to go; stop piping and keep
        // draining the child's stderr so it never blocks on a full pipe.
        try {
            child.stderr.unpipe(proxyStderr);
        }
        catch {
            /* fail-open */
        }
        try {
            child.stderr.resume();
        }
        catch {
            /* fail-open */
        }
    });
    /* ------------------------------ tap state ------------------------------- */
    // Pending requests keyed direction-aware: 'c2s:<id>' for client-initiated,
    // 's2c:<id>' for server-initiated. Responses always arrive on the opposite
    // stream from the request that opened them.
    const pending = new Map();
    let pendingEvictWarned = false;
    const registerPending = (key, entry) => {
        if (pending.size >= MAX_PENDING) {
            const oldest = pending.keys().next().value;
            if (oldest !== undefined)
                pending.delete(oldest);
            if (!pendingEvictWarned) {
                pendingEvictWarned = true;
                diag(`pending request map exceeded ${MAX_PENDING} entries; evicting oldest`);
            }
        }
        pending.set(key, entry);
    };
    const protocolError = (direction, reason, bytesLen, lineHashHex) => {
        const ev = {
            ...base('protocol_error', { 'rpc.system': 'jsonrpc' }),
            kind: 'protocol_error',
            direction,
            reason,
            bytes_len: bytesLen,
            line_hash: 'sha256:' + lineHashHex,
        };
        record(ev);
    };
    const errorInfo = (rawError) => {
        const out = {
            type: 'jsonrpc_error',
        };
        if (isPlainObject(rawError)) {
            if (typeof rawError.code === 'number')
                out.code = rawError.code;
            if (typeof rawError.message === 'string') {
                out.message_ref = redactor.hashString(rawError.message);
            }
        }
        return out;
    };
    const handleResponse = (msg, arrivedOn, line, 
    /** Gateway mode: what the boundary filter did to this tools/call result. */
    boundary) => {
        const id = msg.id;
        // Client-initiated requests are answered server->client and vice versa.
        const key = pendingKey(arrivedOn === 'server_to_client' ? 'c2s:' : 's2c:', id);
        const entry = pending.get(key);
        if (!entry) {
            protocolError(arrivedOn, 'orphan_response', line.bytesLen, line.lineHashHex);
            return;
        }
        pending.delete(key);
        const rawResult = 'result' in msg ? msg.result : undefined;
        const rawError = 'error' in msg ? msg.error : undefined;
        const isError = rawError !== undefined ||
            (isPlainObject(rawResult) && rawResult.isError === true);
        const resultHash = sha256Ref(canonicalJson(rawResult ?? rawError ?? null));
        const durationMs = round2(performance.now() - entry.t0);
        if (entry.method === 'initialize') {
            const reqParams = isPlainObject(entry.params) ? entry.params : {};
            const clientInfo = isPlainObject(reqParams.clientInfo) ? reqParams.clientInfo : {};
            const res = isPlainObject(rawResult) ? rawResult : {};
            const serverInfo = isPlainObject(res.serverInfo) ? res.serverInfo : {};
            // Remember for subsequent events' identity/server context. Capped here
            // (P0): these are copied verbatim off the wire and reused on every
            // later event, so an oversized/malformed value is capped once, at the
            // point it's learned — every downstream use (this event's own
            // client_name/server_name below, plus identity/server context on every
            // later event) inherits the capped value for free.
            if (typeof clientInfo.name === 'string') {
                clientName = structuralString(clientInfo.name, 'identifier');
            }
            if (typeof clientInfo.version === 'string') {
                clientVersion = structuralString(clientInfo.version, 'version');
            }
            if (typeof serverInfo.name === 'string') {
                learnedServerName = structuralString(serverInfo.name, 'identifier');
            }
            if (typeof serverInfo.version === 'string') {
                learnedServerVersion = structuralString(serverInfo.version, 'version');
            }
            const ev = {
                ...base('initialize', {
                    'mcp.method.name': 'initialize',
                    'rpc.system': 'jsonrpc',
                    'rpc.jsonrpc.request_id': String(id),
                }),
                kind: 'initialize',
                request_id: id,
                duration_ms: durationMs,
            };
            const protoVersion = reqParams.protocolVersion ?? res.protocolVersion;
            if (typeof protoVersion === 'string') {
                ev.protocol_version = structuralString(protoVersion, 'protocol_version');
            }
            if (clientName !== undefined)
                ev.client_name = clientName;
            if (clientVersion !== undefined)
                ev.client_version = clientVersion;
            if (learnedServerName !== undefined)
                ev.server_name = learnedServerName;
            if (learnedServerVersion !== undefined)
                ev.server_version = learnedServerVersion;
            record(ev);
            return;
        }
        if (entry.method === 'tools/call') {
            const tool = entry.toolName ?? '';
            const reqParams = isPlainObject(entry.params) ? entry.params : {};
            const attributes = {
                'gen_ai.operation.name': 'execute_tool',
                'gen_ai.tool.name': tool,
                'gen_ai.tool.call.id': String(id),
                'mcp.method.name': 'tools/call',
                'rpc.system': 'jsonrpc',
            };
            if (rawError !== undefined)
                attributes['error.type'] = 'jsonrpc_error';
            // Gateway mode (additive): the decision taken at request time plus the
            // boundary report. `result`/`result_hash` stay the RAW server result;
            // a rewritten delivery is only ever described by
            // `gateway.boundary.delivered_result_hash`.
            let gatewayOutcome = entry.gateway !== undefined ? { ...entry.gateway } : undefined;
            if (boundary !== undefined) {
                gatewayOutcome = gatewayOutcome ?? { decision: 'allow' };
                gatewayOutcome.boundary = boundary;
            }
            if (gatewayOutcome !== undefined) {
                attributes['cresec.policy.decision'] = gatewayOutcome.decision;
                if (gatewayOutcome.rule_id !== undefined) {
                    attributes['cresec.policy.rule_id'] = gatewayOutcome.rule_id;
                }
            }
            const ev = {
                ...base('tool_call', attributes),
                kind: 'tool_call',
                tool,
                request_id: id,
                args: scrubToolArguments(redactor, reqParams.arguments ?? {}),
                result_hash: resultHash,
                result: redactor.scrub(rawResult ?? null),
                is_error: isError,
                duration_ms: durationMs,
            };
            if (rawError !== undefined)
                ev.error = errorInfo(rawError);
            if (gatewayOutcome !== undefined)
                ev.gateway = gatewayOutcome;
            record(ev);
            return;
        }
        const ev = {
            ...base('rpc', {
                'mcp.method.name': entry.method,
                'rpc.system': 'jsonrpc',
                'rpc.jsonrpc.request_id': String(id),
            }),
            kind: 'rpc',
            method: entry.method,
            request_id: id,
            params: redactor.scrub(entry.params ?? null),
            result_hash: resultHash,
            is_error: isError,
            duration_ms: durationMs,
        };
        if (rawError !== undefined)
            ev.error = errorInfo(rawError);
        record(ev);
    };
    const handleMessage = (msg, direction, line) => {
        if (Array.isArray(msg)) {
            // JSON-RPC batch — handle each element independently.
            for (const el of msg)
                handleMessage(el, direction, line);
            return;
        }
        if (!isPlainObject(msg))
            return; // not a JSON-RPC message; ignore quietly
        const hasMethod = typeof msg.method === 'string';
        const id = msg.id;
        const hasId = id !== undefined && id !== null;
        if (hasMethod && hasId) {
            // Request: register pending under the direction it was sent on. The
            // method/tool name is capped HERE (P0), once, at capture time: every
            // downstream event built from this entry (the eventual response event
            // AND the synthetic 'unanswered' event sealed at shutdown, see
            // emitUnanswered below) reads `entry.method`/`entry.toolName`, so
            // capping the source field once covers both for free.
            const keyPrefix = direction === 'client_to_server' ? 'c2s:' : 's2c:';
            const reqId = id;
            const params = msg.params;
            const entry = {
                method: structuralString(msg.method, 'identifier'),
                params,
                t0: performance.now(),
                id: reqId,
            };
            if (isPlainObject(params) && typeof params.name === 'string') {
                entry.toolName = structuralString(params.name, 'identifier');
            }
            registerPending(pendingKey(keyPrefix, reqId), entry);
            return;
        }
        if (hasMethod) {
            const method = structuralString(msg.method, 'identifier');
            const ev = {
                ...base('notification', {
                    'mcp.method.name': method,
                    'rpc.system': 'jsonrpc',
                }),
                kind: 'notification',
                method,
                direction,
                params: redactor.scrub(msg.params ?? null),
            };
            record(ev);
            return;
        }
        if (hasId && ('result' in msg || 'error' in msg)) {
            handleResponse(msg, direction, line);
        }
    };
    const handleLine = (line, direction) => {
        if (line.oversized) {
            protocolError(direction, 'oversized', line.bytesLen, line.lineHashHex);
            return;
        }
        if (line.text === null)
            return;
        let msg;
        try {
            msg = JSON.parse(line.text);
        }
        catch {
            protocolError(direction, 'unparseable', line.bytesLen, line.lineHashHex);
            return;
        }
        handleMessage(msg, direction, line);
    };
    const c2sScanner = new LineScanner();
    const s2cScanner = new LineScanner();
    const tap = (scanner, direction) => (chunk) => {
        try {
            for (const line of scanner.push(chunk))
                handleLine(line, direction);
        }
        catch (err) {
            tapError(err);
        }
    };
    if (gateway === undefined) {
        proxyStdin.on('data', tap(c2sScanner, 'client_to_server'));
        child.stdout.on('data', tap(s2cScanner, 'server_to_client'));
    }
    /* ------------------------------- gateway -------------------------------- */
    if (gateway !== undefined) {
        const { holdStore } = gateway;
        const loaded = gateway.policy;
        // A policy without an `mcp` section behaves like `mcp: {}` (allow all,
        // default boundary); the CLI refuses such a policy before spawning.
        const mcp = loaded.policy.mcp ?? normalizePolicy({ version: 1, mcp: {} }).mcp;
        const boundaryDeps = {
            secretPatterns: defaultSecretPatterns(),
            hashString: (value) => redactor.hashString(value),
        };
        const holds = new Map();
        /** Synthesized client lines waiting for the server's partial line to complete. */
        const deferredClientWrites = [];
        let c2sOpen = true;
        let s2cState = 'open';
        /** Recording-side work stays fail-open: a throw is logged once, traffic unaffected. */
        const guarded = (fn) => {
            try {
                fn();
            }
            catch (err) {
                tapError(err);
            }
        };
        /* ---- client-side writes (synthesized responses) ---- */
        const s2c = new Transform({
            transform(chunk, _enc, cb) {
                try {
                    s2cSplitter.chunk(asBuffer(chunk));
                    // A chunk boundary is where a server line can have just ended:
                    // deferred synthesized lines go out right after it, never inside.
                    if (!s2cSplitter.hasPartialLine())
                        flushDeferred();
                }
                catch (err) {
                    tapError(err);
                }
                cb();
            },
            flush(cb) {
                try {
                    s2cSplitter.end();
                    flushDeferred();
                }
                catch (err) {
                    tapError(err);
                }
                s2cState = 'ending';
                cb();
            },
        });
        s2c.on('end', () => {
            // Everything the Transform ever pushed has been handed to proxyStdout;
            // late synthesized lines (holds resolved at shutdown) go direct.
            s2cState = 'ended';
            flushDeferred();
        });
        s2c.on('error', (err) => diag(`gateway stream error (server_to_client): ${err.message}`));
        s2cTransform = s2c;
        /**
         * The one path for synthesized lines to the client. Ordered with the
         * server's own lines by riding the s2c Transform while it is open;
         * deferred while a server line is partially forwarded (never split a
         * line); dropped once the client is gone or stdout is closed.
         */
        const writeToClient = (bytes) => {
            if (clientGone || proxyStdout.destroyed || proxyStdout.writableEnded)
                return;
            if (s2cState === 'open') {
                if (s2cSplitter.hasPartialLine()) {
                    deferredClientWrites.push(bytes);
                    return;
                }
                try {
                    s2c.push(bytes);
                }
                catch {
                    /* fail-open */
                }
                return;
            }
            if (s2cState === 'ending') {
                deferredClientWrites.push(bytes);
                return;
            }
            try {
                proxyStdout.write(bytes);
            }
            catch {
                /* fail-open */
            }
        };
        const flushDeferred = () => {
            if (deferredClientWrites.length === 0)
                return;
            for (const bytes of deferredClientWrites.splice(0))
                writeToClient(bytes);
        };
        /* ---- policy evaluation (fail-closed) ---- */
        const evaluate = (rawTool, args) => {
            try {
                const canonical = canonicalJson(args);
                const decision = evaluateMcp(loaded.policy, {
                    server: currentServer().name,
                    tool: rawTool,
                    args,
                    argsBytes: Buffer.byteLength(canonical),
                });
                return { decision, argsHash: sha256Ref(canonical) };
            }
            catch (err) {
                // evaluateMcp never throws by contract; anything else on this path
                // (a hostile args tree, a broken server name) still denies.
                const message = err instanceof Error ? err.message : String(err);
                return {
                    decision: { action: 'deny', matched: false, reason: `policy evaluation error: ${message}` },
                    argsHash: NULL_RESULT_HASH,
                };
            }
        };
        const buildCall = (msg) => {
            const args = msg.params.arguments ?? {};
            const { decision, argsHash } = evaluate(msg.params.name, args);
            const call = {
                id: msg.id,
                params: msg.params,
                rawTool: msg.params.name,
                tool: structuralString(msg.params.name, 'identifier'),
                args,
                argsHash,
            };
            if (decision.ruleId !== undefined) {
                call.rawRuleId = decision.ruleId;
                call.ruleId = cappedRuleId(decision.ruleId);
            }
            if (decision.reason !== undefined)
                call.reason = decision.reason;
            return { call, action: decision.action };
        };
        /* ---- events ---- */
        const policyAttributes = (call, decision) => {
            const attributes = {
                'gen_ai.tool.name': call.tool,
                'gen_ai.tool.call.id': String(call.id),
                'mcp.method.name': 'tools/call',
                'rpc.system': 'jsonrpc',
                'cresec.policy.decision': decision,
            };
            if (call.ruleId !== undefined)
                attributes['cresec.policy.rule_id'] = call.ruleId;
            return attributes;
        };
        const recordPolicyDecision = (call, hold) => {
            const decision = hold === undefined ? 'deny' : 'hold';
            const ev = {
                ...base('policy_decision', policyAttributes(call, decision)),
                kind: 'policy_decision',
                decision,
                tool: call.tool,
                request_id: call.id,
                policy_hash: loaded.hash,
                args_hash: call.argsHash,
            };
            if (call.ruleId !== undefined)
                ev.rule_id = call.ruleId;
            if (hold !== undefined) {
                ev.outcome = hold.outcome;
                ev.approval_id = hold.approvalId;
                ev.waited_ms = hold.waitedMs;
                if (hold.approver !== undefined)
                    ev.approver = hold.approver;
            }
            record(ev);
        };
        /** The `gateway` field a forwarded (allowed / approved) call carries into handleResponse. */
        const gatewayOutcomeFor = (call, hold) => {
            const out = { decision: hold === undefined ? 'allow' : 'hold' };
            if (call.ruleId !== undefined)
                out.rule_id = call.ruleId;
            if (hold !== undefined) {
                out.outcome = hold.outcome;
                out.approval_id = hold.approvalId;
                out.waited_ms = hold.waitedMs;
            }
            return out;
        };
        /** A call the gateway did not forward: is_error, error.type policy_denied, result = what the model got. */
        const recordSyntheticToolCall = (call, result, hold) => {
            const gatewayOutcome = gatewayOutcomeFor(call, hold);
            if (hold === undefined)
                gatewayOutcome.decision = 'deny';
            const attributes = {
                'gen_ai.operation.name': 'execute_tool',
                ...policyAttributes(call, gatewayOutcome.decision === 'deny' ? 'deny' : 'hold'),
                'error.type': 'policy_denied',
            };
            const ev = {
                ...base('tool_call', attributes),
                kind: 'tool_call',
                tool: call.tool,
                request_id: call.id,
                args: scrubToolArguments(redactor, call.args),
                result_hash: sha256Ref(canonicalJson(result)),
                result: redactor.scrub(result),
                is_error: true,
                duration_ms: 0,
                error: { type: 'policy_denied' },
                gateway: gatewayOutcome,
            };
            record(ev);
        };
        /**
         * Refuse a call: record `policy_decision` FIRST, then the synthetic
         * `tool_call`, and return the isError response the client gets.
         */
        const synthesizeDeny = (call, hold) => {
            const input = { tool: call.rawTool };
            if (call.rawRuleId !== undefined)
                input.ruleId = call.rawRuleId;
            if (call.reason !== undefined)
                input.reason = call.reason;
            if (hold !== undefined) {
                input.approvalId = hold.approvalId;
                input.outcome = hold.outcome === 'approved' ? 'session_end' : hold.outcome;
            }
            const response = synthesizeDeniedResult(call.id, deniedText(input));
            guarded(() => {
                recordPolicyDecision(call, hold);
                recordSyntheticToolCall(call, response.result, hold);
            });
            return response;
        };
        const denyCall = (call, hold) => {
            const response = synthesizeDeny(call, hold);
            writeToClient(Buffer.from(JSON.stringify(response) + '\n'));
            if (hold === undefined) {
                diag(`gateway: denied tools/call "${call.tool}" (rule ${call.ruleId ?? 'default'})`);
            }
        };
        /** Register a forwarded tools/call in `pending` so its response becomes the tool_call event. */
        const registerCall = (call, gatewayOutcome) => {
            const entry = {
                method: 'tools/call',
                params: call.params,
                t0: performance.now(),
                toolName: call.tool,
                id: call.id,
                gateway: gatewayOutcome,
            };
            registerPending(pendingKey('c2s:', call.id), entry);
        };
        /* ---- holds ---- */
        const settleHold = (entry, status, decided) => {
            if (entry.settled)
                return;
            entry.settled = true;
            if (holds.get(entry.key) === entry)
                holds.delete(entry.key);
            entry.abort.abort(); // stops the poller if it is still running
            const resolution = {
                outcome: status,
                approvalId: entry.approvalId,
                waitedMs: round2(performance.now() - entry.t0),
            };
            if (decided?.decided_by !== undefined)
                resolution.approver = decided.decided_by;
            if (status === 'timeout' || status === 'cancelled' || status === 'session_end') {
                holdStore.finalize(entry.approvalId, status);
            }
            const forward = status === 'approved' || (status === 'timeout' && mcp.hold.on_timeout === 'allow');
            if (forward && c2sOpen && !clientGone) {
                guarded(() => recordPolicyDecision(entry, resolution));
                registerCall(entry, gatewayOutcomeFor(entry, resolution));
                forwardC2s(entry.raw);
                diag(`gateway: hold ${entry.approvalId} ${status}; forwarding tools/call "${entry.tool}" after ${resolution.waitedMs} ms`);
                return;
            }
            if (forward)
                resolution.outcome = 'session_end'; // approved, but the server is already gone
            denyCall(entry, resolution);
            diag(`gateway: hold ${entry.approvalId} ${resolution.outcome} after ${resolution.waitedMs} ms; tools/call "${entry.tool}" not forwarded`);
        };
        const startHold = (call, raw) => {
            const timeoutMs = mcp.hold.timeout_ms;
            let created;
            try {
                const input = {
                    session_id: sessionId,
                    server: currentServer().name,
                    tool: call.tool,
                    args: scrubToolArguments(redactor, call.args),
                    args_hash: call.argsHash,
                    timeout_at: new Date(Date.now() + timeoutMs).toISOString(),
                };
                if (call.rawRuleId !== undefined)
                    input.rule_id = call.rawRuleId;
                if (call.reason !== undefined)
                    input.reason = call.reason;
                created = holdStore.create(input);
            }
            catch (err) {
                // Fail closed: a hold that cannot be written is a deny.
                const message = err instanceof Error ? err.message : String(err);
                diag(`gateway: cannot write hold for tools/call "${call.tool}" (${message}); denying`);
                denyCall({ ...call, reason: 'hold unavailable' });
                return;
            }
            const entry = {
                ...call,
                approvalId: created.approval_id,
                key: pendingKey('c2s:', call.id),
                raw,
                t0: performance.now(),
                abort: new AbortController(),
                settled: false,
            };
            holds.set(entry.key, entry);
            diag(`gateway: holding tools/call "${call.tool}" (rule ${call.ruleId ?? 'default'}) as ${created.approval_id}` +
                ` — mcp-recorder approve|deny ${created.approval_id}`);
            const waitOpts = { timeoutMs, signal: entry.abort.signal };
            if (gateway.pollMs !== undefined)
                waitOpts.pollMs = gateway.pollMs;
            holdStore.waitForDecision(created.approval_id, waitOpts).then((res) => {
                if (!entry.settled)
                    settleHold(entry, res.status, res.record);
            }, (err) => {
                // waitForDecision never rejects by contract; deny if it ever does.
                tapError(err);
                if (!entry.settled)
                    settleHold(entry, 'denied');
            });
        };
        const cancelHold = (msg) => {
            const params = isPlainObject(msg.params) ? msg.params : {};
            if (!isRpcId(params.requestId))
                return;
            const entry = holds.get(pendingKey('c2s:', params.requestId));
            if (entry !== undefined)
                settleHold(entry, 'cancelled');
        };
        resolveAllHolds = () => {
            for (const entry of [...holds.values()])
                settleHold(entry, 'session_end');
        };
        /* ---- client -> server ---- */
        const c2s = new Transform({
            transform(chunk, _enc, cb) {
                try {
                    c2sSplitter.chunk(asBuffer(chunk));
                }
                catch (err) {
                    tapError(err);
                }
                cb();
            },
            flush(cb) {
                // Runs when the client closed its write end, BEFORE child.stdin is
                // ended: the trailing line is handled and every parked hold resolved
                // synchronously (never await here, or the server never sees EOF).
                try {
                    c2sSplitter.end();
                }
                catch (err) {
                    tapError(err);
                }
                try {
                    resolveAllHolds?.();
                }
                catch (err) {
                    tapError(err);
                }
                c2sOpen = false;
                cb();
            },
        });
        c2s.on('error', (err) => diag(`gateway stream error (client_to_server): ${err.message}`));
        const forwardC2s = (bytes) => {
            // Once the client's read end is gone the server is being wound down
            // (child.stdin ended by the EPIPE handler): nothing more goes to it.
            if (c2sOpen && !clientGone)
                c2s.push(bytes);
        };
        const c2sToolsCall = (msg, raw) => {
            const { call, action } = buildCall(msg);
            if (action === 'allow') {
                forwardC2s(raw);
                guarded(() => registerCall(call, gatewayOutcomeFor(call)));
                return;
            }
            if (action === 'deny') {
                denyCall(call);
                return;
            }
            startHold(call, raw);
        };
        /**
         * JSON-RPC batch: each tools/call element is evaluated; allowed ones and
         * every non-tools/call element are re-serialized and forwarded as a
         * batch; refused ones (deny, and hold — not supported inside a batch)
         * get their isError results back as a batch response.
         */
        const c2sBatch = (batch, raw, line) => {
            if (!batch.some(isToolsCallRequest)) {
                forwardC2s(raw);
                guarded(() => handleMessage(batch, 'client_to_server', line));
                return;
            }
            const kept = [];
            const forwardedCalls = [];
            const responses = [];
            for (const el of batch) {
                if (!isToolsCallRequest(el)) {
                    kept.push(el);
                    continue;
                }
                const { call, action } = buildCall(el);
                if (action === 'allow') {
                    kept.push(el);
                    forwardedCalls.push(call);
                    continue;
                }
                if (action === 'hold') {
                    diag(`gateway: hold inside a JSON-RPC batch is treated as deny (tools/call "${call.tool}")`);
                }
                responses.push(synthesizeDeny(call));
                diag(`gateway: denied tools/call "${call.tool}" (rule ${call.ruleId ?? 'default'})`);
            }
            if (kept.length > 0)
                forwardC2s(Buffer.from(JSON.stringify(kept) + '\n'));
            guarded(() => {
                for (const call of forwardedCalls)
                    registerCall(call, gatewayOutcomeFor(call));
                for (const el of kept) {
                    if (!isToolsCallRequest(el))
                        handleMessage(el, 'client_to_server', line);
                }
            });
            if (responses.length > 0)
                writeToClient(Buffer.from(JSON.stringify(responses) + '\n'));
        };
        const c2sLine = (line) => {
            if (line.oversized) {
                // Bytes already streamed through by the splitter; only the record remains.
                guarded(() => protocolError('client_to_server', 'oversized', line.bytesLen, line.lineHashHex));
                return;
            }
            const raw = line.raw;
            if (raw === undefined || line.text === null)
                return; // unreachable: non-oversized lines carry raw
            let msg;
            try {
                msg = JSON.parse(line.text);
            }
            catch {
                forwardC2s(raw);
                guarded(() => protocolError('client_to_server', 'unparseable', line.bytesLen, line.lineHashHex));
                return;
            }
            if (Array.isArray(msg)) {
                c2sBatch(msg, raw, line);
                return;
            }
            if (isToolsCallRequest(msg)) {
                c2sToolsCall(msg, raw);
                return;
            }
            forwardC2s(raw);
            if (isPlainObject(msg) && msg.method === 'notifications/cancelled')
                cancelHold(msg);
            guarded(() => handleMessage(msg, 'client_to_server', line));
        };
        const c2sSplitter = new GatewayLineSplitter(forwardC2s, c2sLine);
        /* ---- server -> client ---- */
        const forwardS2c = (bytes) => {
            s2c.push(bytes);
        };
        const s2cLine = (line) => {
            if (line.oversized) {
                guarded(() => protocolError('server_to_client', 'oversized', line.bytesLen, line.lineHashHex));
                return;
            }
            const raw = line.raw;
            if (raw === undefined || line.text === null)
                return;
            let msg;
            try {
                msg = JSON.parse(line.text);
            }
            catch {
                forwardS2c(raw);
                guarded(() => protocolError('server_to_client', 'unparseable', line.bytesLen, line.lineHashHex));
                return;
            }
            if (isPlainObject(msg) && isRpcId(msg.id) && ('result' in msg || 'error' in msg)) {
                // Look the request up BEFORE handleResponse deletes it.
                const entry = pending.get(pendingKey('c2s:', msg.id));
                if (entry !== undefined && entry.method === 'tools/call') {
                    const outcome = applyBoundary(msg, mcp.boundary, boundaryDeps, { rawBytes: line.bytesLen });
                    const report = { ...outcome.report };
                    if (outcome.changed) {
                        forwardS2c(Buffer.from(JSON.stringify(outcome.message) + '\n'));
                        const delivered = isPlainObject(outcome.message) ? outcome.message.result : null;
                        report.delivered_result_hash = sha256Ref(canonicalJson(delivered ?? null));
                        diag(`gateway: ${report.action === 'block' ? 'blocked' : 'redacted'} tool result of tools/call "${entry.toolName ?? ''}"` +
                            ` (${report.secrets_found} secret-shaped, ${report.injection_found} injection marker(s))`);
                    }
                    else {
                        forwardS2c(raw);
                    }
                    guarded(() => handleResponse(msg, 'server_to_client', line, report));
                    return;
                }
            }
            forwardS2c(raw);
            guarded(() => handleMessage(msg, 'server_to_client', line));
        };
        const s2cSplitter = new GatewayLineSplitter(forwardS2c, s2cLine);
        proxyStdin.pipe(c2s).pipe(child.stdin);
        child.stdout.pipe(s2c).pipe(proxyStdout, { end: false });
        const ruleCount = mcp.rules.length;
        diag(`gateway: policy ${loaded.name ?? loaded.path} (${ruleCount} rule${ruleCount === 1 ? '' : 's'})`);
    }
    /* ---------------------------- session events ---------------------------- */
    const sessionStart = {
        ...base('session_start', { 'rpc.system': 'jsonrpc' }),
        kind: 'session_start',
        proxy_version: opts.proxyVersion,
        cwd: process.cwd(),
        redaction_mode: redactor.mode,
    };
    if (gateway !== undefined) {
        sessionStart.policy = { hash: gateway.policy.hash };
        if (gateway.policy.name !== undefined) {
            sessionStart.policy.name = structuralString(gateway.policy.name, 'identifier');
        }
    }
    record(sessionStart);
    /* ------------------------------ lifecycle ------------------------------- */
    let stdinEnded = false;
    proxyStdin.on('end', () => {
        stdinEnded = true;
        // Gateway mode: the c2s Transform's flush handles the trailing line and
        // the parked holds, and its own end propagates to child.stdin after.
        if (gateway !== undefined)
            return;
        try {
            // pipe() already propagates end; this is belt-and-braces.
            if (!child.stdin.writableEnded)
                child.stdin.end();
        }
        catch {
            /* fail-open */
        }
        try {
            for (const line of c2sScanner.end())
                handleLine(line, 'client_to_server');
        }
        catch (err) {
            tapError(err);
        }
    });
    child.stdout.on('end', () => {
        if (gateway !== undefined)
            return; // the s2c Transform's flush does this
        try {
            for (const line of s2cScanner.end())
                handleLine(line, 'server_to_client');
        }
        catch (err) {
            tapError(err);
        }
    });
    // Forward terminal signals to the child only when we own the real stdin.
    const signalHandlers = [];
    let signalForwarded = false;
    if (proxyStdin === process.stdin) {
        for (const sig of ['SIGINT', 'SIGTERM', 'SIGHUP']) {
            const handler = () => {
                signalForwarded = true;
                // On win32 this reaches the whole process tree (taskkill /T), not
                // just the immediate child — necessary when the child is cmd.exe
                // wrapping a .cmd/.bat shim, whose real work happens in a
                // grandchild process. See src/proxy/spawn.ts:terminateChild.
                terminateChild(child, sig);
            };
            process.on(sig, handler);
            signalHandlers.push([sig, handler]);
        }
    }
    const removeSignalHandlers = () => {
        for (const [sig, handler] of signalHandlers)
            process.removeListener(sig, handler);
    };
    return await new Promise((resolve) => {
        let finished = false;
        /** errno code from the child 'error' event, when spawning failed outright. */
        let spawnErrorCode;
        // A request still pending at session end (server crashed or was killed
        // mid-call, or the client disconnected mid-handshake) would otherwise
        // vanish from the chain with no trace. Seal one synthetic event per
        // pending entry before session_end: a tools/call becomes a tool_call
        // event, everything else (including an unanswered initialize) becomes
        // an rpc event — both is_error, error.type 'unanswered'.
        const emitUnanswered = () => {
            if (pending.size === 0)
                return;
            const shutdownT0 = performance.now();
            for (const entry of pending.values()) {
                const durationMs = round2(shutdownT0 - entry.t0);
                if (entry.method === 'tools/call') {
                    const tool = entry.toolName ?? '';
                    const reqParams = isPlainObject(entry.params) ? entry.params : {};
                    const attributes = {
                        'gen_ai.operation.name': 'execute_tool',
                        'gen_ai.tool.name': tool,
                        'gen_ai.tool.call.id': String(entry.id),
                        'mcp.method.name': 'tools/call',
                        'rpc.system': 'jsonrpc',
                        'error.type': 'unanswered',
                    };
                    if (entry.gateway !== undefined) {
                        attributes['cresec.policy.decision'] = entry.gateway.decision;
                        if (entry.gateway.rule_id !== undefined) {
                            attributes['cresec.policy.rule_id'] = entry.gateway.rule_id;
                        }
                    }
                    const ev = {
                        ...base('tool_call', attributes),
                        kind: 'tool_call',
                        tool,
                        request_id: entry.id,
                        args: scrubToolArguments(redactor, reqParams.arguments ?? {}),
                        result_hash: NULL_RESULT_HASH,
                        result: null,
                        is_error: true,
                        duration_ms: durationMs,
                        error: { type: 'unanswered' },
                    };
                    if (entry.gateway !== undefined)
                        ev.gateway = { ...entry.gateway };
                    record(ev);
                }
                else {
                    const attributes = {
                        'mcp.method.name': entry.method,
                        'rpc.system': 'jsonrpc',
                        'rpc.jsonrpc.request_id': String(entry.id),
                        'error.type': 'unanswered',
                    };
                    const ev = {
                        ...base('rpc', attributes),
                        kind: 'rpc',
                        method: entry.method,
                        request_id: entry.id,
                        params: redactor.scrub(entry.params ?? null),
                        result_hash: NULL_RESULT_HASH,
                        is_error: true,
                        duration_ms: durationMs,
                        error: { type: 'unanswered' },
                    };
                    record(ev);
                }
            }
            pending.clear();
        };
        const finalize = async (reason, exitCode, signal) => {
            if (finished)
                return;
            finished = true;
            removeSignalHandlers();
            try {
                // Gateway mode: a call still held when the session ends is refused
                // (session_end) and sealed here, before the unanswered sweep.
                resolveAllHolds?.();
            }
            catch (err) {
                tapError(err);
            }
            try {
                emitUnanswered();
            }
            catch (err) {
                tapError(err);
            }
            try {
                await recorder.flush();
            }
            catch {
                /* recorder is fail-open; flush never rejects, but be safe */
            }
            try {
                const stats = recorder.stats();
                const ev = {
                    ...base('session_end', { 'rpc.system': 'jsonrpc' }),
                    kind: 'session_end',
                    reason,
                    child_exit_code: exitCode,
                    events_recorded: stats.written,
                    events_dropped: stats.dropped,
                };
                if (spawnErrorCode !== undefined)
                    ev.spawn_error = spawnErrorCode;
                if (signal !== null)
                    ev.child_signal = signal;
                record(ev);
            }
            catch (err) {
                tapError(err);
            }
            try {
                await Promise.race([
                    recorder.close(),
                    new Promise((res) => setTimeout(res, CLOSE_TIMEOUT_MS).unref?.()),
                ]);
            }
            catch {
                /* fail-open */
            }
            let code;
            if (exitCode !== null) {
                code = exitCode;
            }
            else if (signal !== null) {
                code = signalExitCode(signal);
            }
            else if (spawnErrorCode !== undefined) {
                code = spawnErrorExitCode(spawnErrorCode);
            }
            else {
                code = 0;
            }
            resolve(code);
        };
        child.on('error', (err) => {
            diag(`failed to run ${opts.command[0]}: ${err.message}`);
            spawnErrorCode = err.code ?? 'UNKNOWN';
            void finalize('error', null, null);
        });
        // 'close' (not 'exit') so the child's stdio has fully drained through the
        // pipes before we seal the session.
        child.on('close', (code, signal) => {
            const reason = signalForwarded
                ? 'signal'
                : stdinEnded
                    ? 'stdin_closed'
                    : 'child_exit';
            void finalize(reason, code, signal);
        });
    });
}
//# sourceMappingURL=stdio.js.map