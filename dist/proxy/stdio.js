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
 *    tools/call the gateway saw — element by element when the server
 *    answers a batch with a JSON-RPC array, and over an uncorrelated
 *    ("orphan") result that still looks like a tool result; forward the
 *    original bytes when nothing changed, else the re-serialized message.
 * Enforcement fails CLOSED (an evaluation throw or an unwritable hold is a
 * deny); recording stays fail-open exactly as in record mode. Every
 * `tools/call` REQUEST (one carrying an id) is evaluated, including one
 * whose `params.name` is missing or not a string: it is evaluated as the
 * tool name '' so the section default — and any glob matching the empty
 * string — applies. Known v1 limits, on purpose: a `hold` inside a
 * JSON-RPC batch is treated as deny, a `tools/call` with no `id` property
 * at all (a notification) is forwarded unevaluated, and a line over the
 * 32 MiB tap cap cannot be parsed so it is forwarded unchanged and
 * recorded as `protocol_error` — as in record mode.
 *
 * DUPLICATE REQUEST IDS. `pending` and `holds` are both keyed by the
 * request id, and a held call sits on its key for as long as a human takes
 * to answer. A second `tools/call` reusing an id that is still in flight
 * (JSON-RPC forbids it) would take that key over, so the first call's real
 * response would arrive uncorrelated — delivered to the client but recorded
 * as an orphan `protocol_error`, with no tool_call, no args hash and no
 * gateway outcome for a call that did execute. Gateway mode therefore fails
 * CLOSED on id reuse: a `tools/call` whose id is currently held, or already
 * pending, is refused immediately with a synthesized isError result and
 * recorded as a `policy_decision` (deny) plus a synthetic `tool_call` with
 * `error.type: 'duplicate_id'` — it is never forwarded, so the in-flight
 * call keeps its slot. Belt and braces, an approved hold that still finds a
 * pending entry on its key (one that slipped in through a path with no such
 * check) seals that entry as `duplicate_id` before taking the slot back, so
 * nothing is ever silently overwritten. Record mode is untouched: without a
 * policy the tap keeps its last-writer-wins `pending` map.
 *
 * NULL REQUEST IDS. `{"id": null}` is not a valid MCP request (the official
 * SDK rejects it) and is not a notification either, so a `tools/call`
 * carrying it is refused, fail-closed, whatever the policy says — a `hold`
 * rule matching it is a deny like any other decision, and the call is not
 * even evaluated. It is NEVER forwarded; the client gets
 * `{"jsonrpc":"2.0","id":null,"error":{"code":-32600,...}}` (JSON-RPC
 * permits a null id on an error response). It is recorded exactly as the
 * tap has always recorded an id-less message — one `notification` event —
 * because the frozen schema's `request_id` is `string | number` and cannot
 * describe it; the refusal itself is visible on stderr. Without `--policy`
 * it is forwarded unevaluated, as before.
 */
import { constants as osConstants, hostname as osHostname, userInfo } from 'node:os';
import { basename } from 'node:path';
import { performance } from 'node:perf_hooks';
import { randomUUID } from 'node:crypto';
import { Transform } from 'node:stream';
import { canonicalJson, sha256Ref } from '../chain/hash.js';
import { applyBoundary, boundarySecretPatterns, deniedText, synthesizeDeniedResult, } from '../gateway/boundary.js';
import { evaluateMcp } from '../policy/engine.js';
import { setRegexGuardDiag, warmRegexGuard } from '../policy/regex-guard.js';
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
/** A `tools/call` REQUEST (has an id) — the only thing the policy evaluates. */
function isToolsCallRequest(msg) {
    return isPlainObject(msg) && msg.method === 'tools/call' && isRpcId(msg.id);
}
/**
 * A `tools/call` carrying an explicit `id: null`. Neither a request (MCP
 * forbids a null id and the official SDK rejects it) nor a notification, so
 * gateway mode refuses it instead of forwarding it — see the module header.
 */
function isNullIdToolsCall(msg) {
    return isPlainObject(msg) && msg.method === 'tools/call' && msg.id === null;
}
/**
 * The `params` object and tool name of a `tools/call` request. A missing or
 * non-string `params.name` (and a non-object `params`) yields '': the call
 * is evaluated like any other, so `mcp.default` applies and tool globs match
 * as they do for an empty string, instead of crossing unevaluated.
 */
function toolsCallParts(msg) {
    const params = isPlainObject(msg.params) ? msg.params : {};
    return { params, name: typeof params.name === 'string' ? params.name : '' };
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
/**
 * Gateway mode: cap on concurrently parked holds. The map is keyed by
 * request id and only shrinks when a hold is resolved, so a client that
 * fires hold-matching calls it never answers for would otherwise grow it
 * without bound. Beyond the cap a hold-matching call is refused (deny),
 * fail-closed — documented in docs/gateway.md.
 */
export const MAX_HOLDS = 256;
/** Reason a call is refused instead of held because the cap above is reached. */
const TOO_MANY_HOLDS_REASON = 'too many pending holds';
/** Reason a call is refused instead of held because finalize() already began. */
const SESSION_END_HOLD_REASON = 'session_end (hold not started)';
const DUPLICATE_ID_REASON = {
    held: 'a tools/call with this id is already held for approval',
    pending: 'a tools/call with this id is already in flight',
};
/** `error.type` of both events recorded for a refused duplicate id (free-form string, v1). */
const DUPLICATE_ID_ERROR_TYPE = 'duplicate_id';
/**
 * The text the model sees for a `tools/call` refused because its id is
 * still in use. Like every other synthesized text it names the tool as the
 * CLIENT wrote it (and the id it chose); events carry the capped forms.
 */
export function duplicateIdText(tool, id, state) {
    return (`mcp-recorder gateway: tools/call "${tool}" refused: ${DUPLICATE_ID_REASON[state]}.` +
        ` JSON-RPC request id ${JSON.stringify(id)} must be unique while in flight; retry with a fresh id.`);
}
/**
 * A `tools/call` with `id: null` is refused with this JSON-RPC error
 * (-32600 Invalid Request); JSON-RPC permits a null id on an error
 * response. See the module header (NULL REQUEST IDS).
 */
export const NULL_ID_TOOLS_CALL_MESSAGE = 'mcp-recorder gateway: tools/call with a null id is not a valid request';
const NULL_ID_ERROR_RESPONSE = {
    jsonrpc: '2.0',
    id: null,
    error: { code: -32600, message: NULL_ID_TOOLS_CALL_MESSAGE },
};
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
    /**
     * Gateway mode: set at the TOP of finalize(), before the holds are
     * resolved. From then on a `tools/call` that would be parked is refused
     * instead — a hold started after finalize() began would never be
     * resolved (its file would stay pending, its poller would outlive the
     * session, and nothing would be recorded for the call).
     */
    let sessionClosing = false;
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
    /**
     * Make room for one entry. A gateway-forwarded `tools/call` is the entry
     * the s2c side MUST still find: its response carries the tool result the
     * boundary filter has to scan before the client sees it, and its
     * `tool_call` event. So the OLDEST NON-GATEWAY entry is evicted first —
     * a flood of server->client requests (10 000 `ping`s, say) can no longer
     * push an in-flight gateway call out of the map and let its result cross
     * unfiltered. Only when every entry is a gateway call does the oldest one
     * go. The scan is O(n) in the worst case, which needs MAX_PENDING
     * concurrent gateway tool calls to reach at all; the common case stops at
     * the first entry.
     */
    const evictOnePending = () => {
        let victim;
        for (const [key, entry] of pending) {
            if (entry.gateway === undefined) {
                victim = key;
                break;
            }
        }
        if (victim === undefined)
            victim = pending.keys().next().value;
        if (victim !== undefined)
            pending.delete(victim);
        if (!pendingEvictWarned) {
            pendingEvictWarned = true;
            diag(`pending request map exceeded ${MAX_PENDING} entries; evicting oldest`);
        }
    };
    const registerPending = (key, entry) => {
        if (pending.size >= MAX_PENDING)
            evictOnePending();
        pending.set(key, entry);
    };
    /**
     * Seal one pending request that will never get its real response, so the
     * chain never silently drops in-flight work: a `tools/call` becomes a
     * `tool_call` event, everything else (including an unanswered
     * `initialize`) an `rpc` event — both `is_error: true` with
     * `error.type` = `errorType` (a free-form string under the frozen
     * schema), `result_hash` the hash of canonical `null` and, for a
     * `tool_call`, `result: null`. The shutdown sweep passes 'unanswered';
     * gateway mode passes 'duplicate_id' when an approved hold reclaims a
     * pending slot a same-id call had taken (see the module header). The
     * caller owns removing the entry from `pending`.
     */
    const sealPending = (entry, errorType, durationMs) => {
        if (entry.method === 'tools/call') {
            const tool = entry.toolName ?? '';
            const reqParams = isPlainObject(entry.params) ? entry.params : {};
            const attributes = {
                'gen_ai.operation.name': 'execute_tool',
                'gen_ai.tool.name': tool,
                'gen_ai.tool.call.id': String(entry.id),
                'mcp.method.name': 'tools/call',
                'rpc.system': 'jsonrpc',
                'error.type': errorType,
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
                error: { type: errorType },
            };
            if (entry.gateway !== undefined)
                ev.gateway = { ...entry.gateway };
            record(ev);
            return;
        }
        const ev = {
            ...base('rpc', {
                'mcp.method.name': entry.method,
                'rpc.system': 'jsonrpc',
                'rpc.jsonrpc.request_id': String(entry.id),
                'error.type': errorType,
            }),
            kind: 'rpc',
            method: entry.method,
            request_id: entry.id,
            params: redactor.scrub(entry.params ?? null),
            result_hash: NULL_RESULT_HASH,
            is_error: true,
            duration_ms: durationMs,
            error: { type: errorType },
        };
        record(ev);
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
            secretPatterns: boundarySecretPatterns(),
            hashString: (value) => redactor.hashString(value),
        };
        const holds = new Map();
        /** Synthesized client lines waiting for the server's partial line to complete. */
        const deferredClientWrites = [];
        /** Approved hold lines waiting for a partially forwarded client line to complete. */
        const deferredServerWrites = [];
        let c2sOpen = true;
        let s2cState = 'open';
        /** One shared '\n' for the line terminators the gateway has to insert. */
        const NEWLINE = Buffer.from('\n');
        /**
         * True while everything forwarded to the client so far ended a line.
         * A server that dies mid-line leaves an UNTERMINATED line behind (the
         * s2c flush path forwards it as-is, byte-for-byte); a synthesized line
         * glued onto it would make both unparseable, so one '\n' is emitted
         * first. Same idea for the server side (`serverAtLineStart`) when a
         * parked hold is released after an unterminated client line.
         */
        let clientAtLineStart = true;
        let serverAtLineStart = true;
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
                emitToClient(bytes, (out) => {
                    try {
                        s2c.push(out);
                    }
                    catch {
                        /* fail-open */
                    }
                });
                return;
            }
            if (s2cState === 'ending') {
                deferredClientWrites.push(bytes);
                return;
            }
            emitToClient(bytes, (out) => {
                try {
                    proxyStdout.write(out);
                }
                catch {
                    /* fail-open */
                }
            });
        };
        /** Emit one synthesized line, terminating an unfinished server line first. */
        const emitToClient = (bytes, write) => {
            if (!clientAtLineStart) {
                clientAtLineStart = true;
                write(NEWLINE);
            }
            if (bytes.length > 0)
                clientAtLineStart = bytes[bytes.length - 1] === NL;
            write(bytes);
        };
        const flushDeferred = () => {
            if (deferredClientWrites.length === 0)
                return;
            for (const bytes of deferredClientWrites.splice(0))
                writeToClient(bytes);
        };
        /* ---- policy evaluation (fail-closed) ---- */
        /** The fail-closed decision for a throw anywhere on the evaluation path. */
        const evaluationFailed = (err) => ({
            action: 'deny',
            matched: false,
            reason: `policy evaluation error: ${err instanceof Error ? err.message : String(err)}`,
            // Same marker `evaluateMcp` sets for its own internal errors: nothing
            // was decided here, so the model is told it may retry.
            failClosed: true,
        });
        /**
         * Canonical JSON of a call's arguments, plus its hash. The canonical
         * JSON gets its OWN guard: when it succeeds, args_hash is the real hash
         * of the arguments even if whatever follows blows up (the refusal is
         * recorded, the evidence still points at the exact arguments). Only a
         * canonicalJson/sha256Ref throw — a hostile args tree — yields
         * `canonical: null` and the hash of `null`.
         */
        const argsCanonical = (args) => {
            try {
                const canonical = canonicalJson(args);
                return { canonical, argsHash: sha256Ref(canonical) };
            }
            catch (err) {
                return { canonical: null, argsHash: NULL_RESULT_HASH, err };
            }
        };
        const evaluate = (rawTool, args) => {
            const { canonical, argsHash, err } = argsCanonical(args);
            if (canonical === null)
                return { decision: evaluationFailed(err), argsHash };
            try {
                const decision = evaluateMcp(loaded.policy, {
                    server: currentServer().name,
                    tool: rawTool,
                    args,
                    argsBytes: Buffer.byteLength(canonical),
                });
                return { decision, argsHash };
            }
            catch (err) {
                // evaluateMcp never throws by contract; anything else on this path
                // (a broken server name, a poisoned policy object) still denies.
                return { decision: evaluationFailed(err), argsHash };
            }
        };
        /** The policy-independent half of a GatewayCall. */
        const newCall = (id, params, name, args, argsHash) => ({
            id,
            params,
            rawTool: name,
            // '' stays '': structuralString would hash the empty string, and ''
            // is what a nameless call's tool_call event has always carried.
            tool: name === '' ? '' : structuralString(name, 'identifier'),
            args,
            argsHash,
        });
        /**
         * A call refused on PROTOCOL grounds (a duplicate request id): the
         * policy is not consulted at all — no rule could allow an id that is
         * already in flight — so the call carries no rule id and no reason, just
         * the evidence (tool, id, args and their hash).
         */
        const unevaluatedCall = (msg) => {
            const { params, name } = toolsCallParts(msg);
            const args = params.arguments ?? {};
            return newCall(msg.id, params, name, args, argsCanonical(args).argsHash);
        };
        const buildCall = (msg) => {
            const { params, name } = toolsCallParts(msg);
            const args = params.arguments ?? {};
            const { decision, argsHash } = evaluate(name, args);
            const call = newCall(msg.id, params, name, args, argsHash);
            if (decision.ruleId !== undefined) {
                call.rawRuleId = decision.ruleId;
                call.ruleId = cappedRuleId(decision.ruleId);
            }
            if (decision.reason !== undefined)
                call.reason = decision.reason;
            if (decision.failClosed === true)
                call.failClosed = true;
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
                if (hold.approvalId !== undefined)
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
                if (hold.approvalId !== undefined)
                    out.approval_id = hold.approvalId;
                out.waited_ms = hold.waitedMs;
            }
            return out;
        };
        /**
         * A call the gateway did not forward: is_error, result = what the model
         * got. `errorType` is 'policy_denied' for a policy refusal and
         * 'duplicate_id' for one refused on protocol grounds (see the header).
         */
        const recordSyntheticToolCall = (call, result, hold, errorType = 'policy_denied') => {
            const gatewayOutcome = gatewayOutcomeFor(call, hold);
            if (hold === undefined)
                gatewayOutcome.decision = 'deny';
            const attributes = {
                'gen_ai.operation.name': 'execute_tool',
                ...policyAttributes(call, gatewayOutcome.decision === 'deny' ? 'deny' : 'hold'),
                'error.type': errorType,
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
                error: { type: errorType },
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
            if (call.failClosed === true)
                input.failClosed = true;
            if (hold !== undefined && hold.approvalId !== undefined) {
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
        const denyCall = (call, hold, diagLine) => {
            const response = synthesizeDeny(call, hold);
            writeToClient(Buffer.from(JSON.stringify(response) + '\n'));
            if (diagLine !== undefined) {
                diag(diagLine); // a caller-specific line REPLACES the generic one
                return;
            }
            if (hold === undefined) {
                diag(`gateway: denied tools/call "${call.tool}" (rule ${call.ruleId ?? 'default'})`);
            }
        };
        /**
         * Refuse a `tools/call` whose JSON-RPC id is still in use. It is never
         * forwarded, so the call already sitting on that id keeps its pending
         * slot (and its hold, if it has one) and its own response still
         * correlates. Recorded like any other refusal, `policy_decision` first:
         * a deny with NO rule id (the policy was never consulted), then the
         * synthetic `tool_call` carrying `error.type: 'duplicate_id'`. The
         * reason travels in the text the model sees and in the diagnostic line;
         * the events carry hashes only, never arguments.
         */
        const refuseDuplicateId = (msg, state) => {
            const call = unevaluatedCall(msg);
            const response = synthesizeDeniedResult(call.id, duplicateIdText(call.rawTool, call.id, state));
            guarded(() => {
                recordPolicyDecision(call);
                recordSyntheticToolCall(call, response.result, undefined, DUPLICATE_ID_ERROR_TYPE);
            });
            writeToClient(Buffer.from(JSON.stringify(response) + '\n'));
            // The id is client-supplied, so it is capped like any other protocol
            // string before it reaches a diagnostic line.
            diag(`gateway: refused tools/call "${call.tool}" — ${DUPLICATE_ID_REASON[state]}` +
                ` (id ${structuralString(String(call.id), 'identifier')})`);
        };
        /**
         * A `tools/call` carrying `id: null` (see the module header): refused
         * with a JSON-RPC -32600 error and NOT forwarded, whatever the policy
         * says. There is no request id to record a `policy_decision` or a
         * `tool_call` against, so it is recorded exactly as the tap records any
         * id-less message — one `notification` event — and the refusal itself
         * is visible on stderr.
         */
        const refuseNullIdToolsCall = (msg, line) => {
            writeToClient(Buffer.from(JSON.stringify(NULL_ID_ERROR_RESPONSE) + '\n'));
            diag('gateway: refused a tools/call with a null id (not a valid request); not forwarded');
            guarded(() => handleMessage(msg, 'client_to_server', line));
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
        /**
         * A hold sits on its `pending` key for as long as a human takes to
         * answer, so by approval time another request may have taken that key
         * over (a path with no duplicate-id check of its own: a
         * non-`tools/call` request, or a `tools/call` inside a JSON-RPC batch).
         * Overwriting it silently would lose a call that DID execute — its real
         * response would land as an orphan `protocol_error` with no tool_call,
         * args hash or gateway outcome. Seal it first, as `duplicate_id`, then
         * hand the slot back to the held call.
         */
        const reclaimPendingSlot = (key) => {
            const displaced = pending.get(key);
            if (displaced === undefined)
                return;
            pending.delete(key);
            guarded(() => sealPending(displaced, DUPLICATE_ID_ERROR_TYPE, round2(performance.now() - displaced.t0)));
            diag(`gateway: a "${displaced.method}" request was still in flight on the held id;` +
                ` sealed as ${DUPLICATE_ID_ERROR_TYPE} before the approved tools/call took the slot back`);
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
            // The hold file is operator-writable and only structurally checked:
            // `decided_by` is whatever it says. Anything but a string is ignored,
            // and a string is capped like any identifier copied off the wire, so
            // an over-long or off-shape value lands as its sha256 ref instead of
            // stamping arbitrary text on an event.
            const decidedBy = decided?.decided_by;
            if (typeof decidedBy === 'string') {
                resolution.approver = structuralString(decidedBy, 'identifier');
            }
            if (status === 'timeout' || status === 'cancelled' || status === 'session_end') {
                holdStore.finalize(entry.approvalId, status);
            }
            const forward = status === 'approved' || (status === 'timeout' && mcp.hold.on_timeout === 'allow');
            if (forward && c2sOpen && !clientGone && !sessionClosing) {
                guarded(() => recordPolicyDecision(entry, resolution));
                reclaimPendingSlot(entry.key);
                registerCall(entry, gatewayOutcomeFor(entry, resolution));
                forwardHeldC2s(entry.raw);
                diag(`gateway: hold ${entry.approvalId} ${status}; forwarding tools/call "${entry.tool}" after ${resolution.waitedMs} ms`);
                return;
            }
            if (forward)
                resolution.outcome = 'session_end'; // approved, but the server is already gone
            // `session_end` means the session ended under the hold, not that anyone
            // refused it: either shutdown swept a hold nobody had answered, or an
            // answer arrived too late to act on. The sharpest case is a hold the
            // operator APPROVED that still did not run — telling that agent "this
            // is a policy decision by the operator" would invert what happened.
            const failedClosed = resolution.outcome === 'session_end';
            denyCall(failedClosed ? { ...entry, failClosed: true } : entry, resolution);
            diag(`gateway: hold ${entry.approvalId} ${resolution.outcome} after ${resolution.waitedMs} ms; tools/call "${entry.tool}" not forwarded`);
        };
        const startHold = (call, raw) => {
            if (holds.size >= MAX_HOLDS) {
                // Fail closed: the holds map is bounded, so a client that parks
                // holds nobody ever resolves cannot grow it without limit.
                denyCall({ ...call, reason: TOO_MANY_HOLDS_REASON, failClosed: true }, undefined, `gateway: ${MAX_HOLDS} holds already pending; denying tools/call "${call.tool}"` +
                    ` (rule ${call.ruleId ?? 'default'})`);
                return;
            }
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
                denyCall({ ...call, reason: 'hold unavailable', failClosed: true });
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
                // That deny is the gateway failing to learn the operator's answer,
                // not a human giving one, so it must not read as a human's refusal.
                tapError(err);
                if (!entry.settled) {
                    entry.failClosed = true;
                    settleHold(entry, 'denied');
                }
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
                    // A chunk boundary is where a client line can have just ended:
                    // a released hold goes out right after it, never inside it.
                    if (!c2sSplitter.hasPartialLine())
                        flushDeferredC2s();
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
                    flushDeferredC2s();
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
            if (!c2sOpen || clientGone)
                return;
            if (bytes.length > 0)
                serverAtLineStart = bytes[bytes.length - 1] === NL;
            c2s.push(bytes);
        };
        /**
         * A parked hold re-entering the client->server stream. The splitter
         * streams an OVERSIZED line's bytes through as they arrive, so pushing
         * a held request while one is in flight would splice it into the middle
         * of that line — exactly what the s2c side avoids for synthesized
         * responses. Defer it to the end of the current line instead (and
         * terminate an unfinished one first, for the trailing line `end()`
         * forwards without a '\n').
         */
        const forwardHeldC2s = (bytes) => {
            if (c2sSplitter.hasPartialLine()) {
                deferredServerWrites.push(bytes);
                return;
            }
            if (!serverAtLineStart)
                forwardC2s(NEWLINE);
            forwardC2s(bytes);
        };
        const flushDeferredC2s = () => {
            if (deferredServerWrites.length === 0)
                return;
            for (const bytes of deferredServerWrites.splice(0))
                forwardHeldC2s(bytes);
        };
        const c2sToolsCall = (msg, raw) => {
            // Fail closed on id reuse BEFORE the policy is consulted (see the
            // module header): a `tools/call` on an id that is currently held, or
            // that belongs to a request the server has not answered yet, is
            // refused instead of forwarded — otherwise it would take over the
            // other call's `pending`/`holds` slot and that call's real response
            // would be recorded as an orphan. `pendingKey` folds the id's TYPE in,
            // so the number 7 and the string "7" are different ids here too.
            const key = pendingKey('c2s:', msg.id);
            if (holds.has(key)) {
                refuseDuplicateId(msg, 'held');
                return;
            }
            if (pending.has(key)) {
                refuseDuplicateId(msg, 'pending');
                return;
            }
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
            if (sessionClosing) {
                // finalize() has already resolved every parked hold: a new one
                // would leave a pending hold file and a live poller behind and
                // would never be recorded. Refuse it now, with the same outcome a
                // hold parked a moment earlier gets.
                denyCall({ ...call, reason: SESSION_END_HOLD_REASON, failClosed: true }, { outcome: 'session_end', waitedMs: 0 }, `gateway: session ending; tools/call "${call.tool}" refused instead of held` +
                    ` (rule ${call.ruleId ?? 'default'})`);
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
                // A `hold` inside a batch is a deny because a batch element has
                // nowhere to park — so no operator is ever asked about it, and the
                // retry the policy clause forbids (the same call sent on its own) is
                // the only thing that reaches an approver. That makes it the gateway
                // failing closed, not the operator deciding.
                const refused = action === 'hold' ? { ...call, failClosed: true } : call;
                if (action === 'hold') {
                    diag(`gateway: hold inside a JSON-RPC batch is treated as deny (tools/call "${call.tool}")`);
                }
                responses.push(synthesizeDeny(refused));
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
            if (isNullIdToolsCall(msg)) {
                refuseNullIdToolsCall(msg, line);
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
            if (bytes.length > 0)
                clientAtLineStart = bytes[bytes.length - 1] === NL;
            s2c.push(bytes);
        };
        /** A result shaped like a tools/call result (MCP content blocks). */
        const looksLikeToolResult = (msg) => {
            const result = msg['result'];
            return isPlainObject(result) && Array.isArray(result['content']);
        };
        /**
         * Whether one server->client message must go through the boundary
         * filter, and the tool name for the diagnostic. Must be called for
         * EVERY element BEFORE handleResponse deletes the pending entry.
         */
        const boundaryTarget = (msg) => {
            const id = msg['id'];
            if (!isRpcId(id) || !('result' in msg || 'error' in msg))
                return undefined;
            const entry = pending.get(pendingKey('c2s:', id));
            if (entry !== undefined) {
                return entry.method === 'tools/call' ? { kind: 'correlated', tool: entry.toolName ?? '' } : undefined;
            }
            // Fail closed for the BOUNDARY: a result the gateway can no longer
            // correlate (its pending entry was evicted, or the server answered a
            // request it was never sent) is still scanned before the client sees
            // it. Recording is unchanged — handleResponse records the usual
            // protocol_error orphan_response.
            return looksLikeToolResult(msg) ? { kind: 'orphan', tool: '' } : undefined;
        };
        /**
         * Run the boundary filter over one response message. `rawBytes` is the
         * byte length of the whole LINE the message arrived on; for a batch
         * that is the length of the entire array, so `max_scan_bytes` keeps
         * applying to the line as it crossed the wire (docs/gateway.md).
         */
        const filterResult = (msg, rawBytes, tool) => {
            const outcome = applyBoundary(msg, mcp.boundary, boundaryDeps, { rawBytes });
            const report = { ...outcome.report };
            if (outcome.changed) {
                const delivered = isPlainObject(outcome.message) ? outcome.message['result'] : null;
                report.delivered_result_hash = sha256Ref(canonicalJson(delivered ?? null));
                diag(`gateway: ${report.action === 'block' ? 'blocked' : 'redacted'} tool result of tools/call "${tool}"` +
                    ` (${report.secrets_found} secret-shaped, ${report.injection_found} injection marker(s))`);
            }
            return { message: outcome.message, changed: outcome.changed, report };
        };
        /**
         * A JSON-RPC BATCH answer. A spec-compliant server answers a batch the
         * gateway forwarded with an ARRAY, so every element that answers a
         * tools/call must be filtered individually — otherwise the whole array
         * would cross unscanned and its tool_call events would carry no
         * boundary report. The array is re-serialized only when at least one
         * element changed; an untouched batch still crosses byte-for-byte.
         */
        const s2cBatch = (batch, raw, line) => {
            const out = [...batch];
            const reports = new Map();
            let changed = false;
            let orphans = 0;
            batch.forEach((el, index) => {
                if (!isPlainObject(el))
                    return;
                const target = boundaryTarget(el);
                if (target === undefined)
                    return;
                const filtered = filterResult(el, line.bytesLen, target.tool);
                if (filtered.changed) {
                    changed = true;
                    out[index] = filtered.message;
                }
                if (target.kind === 'orphan')
                    orphans++;
                reports.set(index, filtered.report);
            });
            forwardS2c(changed ? Buffer.from(JSON.stringify(out) + '\n') : raw);
            if (orphans > 0) {
                diag(`gateway: boundary-filtered ${orphans} batched tool result(s) with no pending request`);
            }
            guarded(() => {
                batch.forEach((el, index) => {
                    const report = reports.get(index);
                    if (report === undefined) {
                        handleMessage(el, 'server_to_client', line);
                        return;
                    }
                    handleResponse(el, 'server_to_client', line, report);
                });
            });
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
            if (Array.isArray(msg)) {
                s2cBatch(msg, raw, line);
                return;
            }
            if (isPlainObject(msg)) {
                // Look the request up BEFORE handleResponse deletes it.
                const target = boundaryTarget(msg);
                if (target !== undefined) {
                    const filtered = filterResult(msg, line.bytesLen, target.tool);
                    forwardS2c(filtered.changed ? Buffer.from(JSON.stringify(filtered.message) + '\n') : raw);
                    if (target.kind === 'orphan') {
                        // The id is the server's, so it is capped like any other
                        // protocol string before it reaches a diagnostic line.
                        diag('gateway: boundary-filtered a tool result with no pending request' +
                            ` (id ${structuralString(String(msg['id']), 'identifier')})`);
                    }
                    guarded(() => handleResponse(msg, 'server_to_client', line, filtered.report));
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
        // `match.args` regexes run on the regex-guard worker under a hard
        // deadline (see ../policy/regex-guard.ts). Route its diagnostics (a
        // poisoned pattern, a degraded guard) to stderr with everything else, and
        // pay the one-time worker handshake here, at startup, rather than on the
        // first tools/call that hits a rule with `args`. Both are best-effort:
        // enforcement is correct (fail-closed) whether or not the worker is warm.
        setRegexGuardDiag(diag);
        if (mcp.rules.some((r) => r.match.args !== undefined))
            warmRegexGuard();
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
                sealPending(entry, 'unanswered', round2(shutdownT0 - entry.t0));
            }
            pending.clear();
        };
        const finalize = async (reason, exitCode, signal) => {
            if (finished)
                return;
            finished = true;
            // Gateway mode: from here on a tools/call that would be HELD is
            // refused synchronously instead (see c2sToolsCall) — a hold started
            // after this point could never be resolved.
            sessionClosing = true;
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
                // The flush above is the one place finalize() yields: anything that
                // parked a hold in that window is resolved here, before session_end
                // seals the session.
                resolveAllHolds?.();
            }
            catch (err) {
                tapError(err);
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