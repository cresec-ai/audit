/**
 * Transparent stdio passthrough proxy (M0) + capture tap (M1).
 *
 * FORWARDING IS SACRED: client<->server bytes flow through plain .pipe()
 * with backpressure and are never mutated, delayed, or filtered. The tap
 * attaches separate 'data' listeners feeding a LineScanner; everything the
 * tap does is wrapped fail-open — a recorder/tap failure is logged once to
 * stderr and traffic continues.
 */

import { spawn } from 'node:child_process';
import { constants as osConstants, hostname as osHostname, userInfo } from 'node:os';
import { basename } from 'node:path';
import { performance } from 'node:perf_hooks';
import { randomUUID } from 'node:crypto';
import type { Readable, Writable } from 'node:stream';

import { canonicalJson, sha256Ref } from '../chain/hash.js';
import type {
  AnyEvent,
  Attributes,
  IdentityContext,
  InitializeEvent,
  NotificationEvent,
  ProtocolErrorEvent,
  RpcEvent,
  ServerContext,
  SessionEndEvent,
  SessionStartEvent,
  ToolCallEvent,
} from '../schema/events.js';
import { SCHEMA } from '../schema/events.js';
import { scrubArgv, scrubToolArguments } from '../redact/redactor.js';
import type { RecorderLike, RedactorLike } from '../types.js';
import { LineScanner, type ScannedLine } from './framing.js';

export interface StdioProxyOpts {
  /** argv of the wrapped server, e.g. ['npx','@modelcontextprotocol/server-foo']. */
  command: string[];
  recorder: RecorderLike;
  redactor: RedactorLike;
  serverName?: string;
  identityLabel?: string;
  proxyVersion: string;
  stdin?: Readable;
  stdout?: Writable;
  stderr?: Writable;
  env?: NodeJS.ProcessEnv;
}

interface PendingEntry {
  method: string;
  params: unknown;
  t0: number;
  toolName?: string;
  /** The JSON-RPC request id, preserved with its original type. */
  id: string | number;
}

type Direction = 'client_to_server' | 'server_to_client';

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
/** result_hash for a synthesized "unanswered" event: sha256 of canonical `null`. */
const NULL_RESULT_HASH = sha256Ref(canonicalJson(null));

/** Exit code for a child terminated by a signal: 128 + signal number (POSIX convention). */
function signalExitCode(signal: NodeJS.Signals): number {
  const num = (osConstants.signals as Partial<Record<NodeJS.Signals, number>>)[signal];
  return num !== undefined ? 128 + num : 1;
}

/** Exit code for a command that failed to spawn at all. */
function spawnErrorExitCode(code: string | undefined): number {
  if (code === 'ENOENT') return 127;
  if (code === 'EACCES') return 126;
  return 1;
}

/**
 * Best-effort logical server name from argv. For a bare command this is just
 * its basename; for a runner (`npx`, `node`, `tsx`, ...) it walks past known
 * runner flags (e.g. the `-y` in the README's own `npx -y <pkg>` wrapping)
 * to find the first positional argument, which is the actual server.
 */
function deriveServerName(command: string[]): string {
  const first = basename(command[0] ?? '');
  const firstNoExt = first.replace(/\.(c|m)?(js|ts|exe)$/i, '');
  if (!RUNNERS.has(firstNoExt.toLowerCase())) return first;
  for (let i = 1; i < command.length; i++) {
    const tok = command[i] ?? '';
    if (RUNNER_BARE_FLAGS.has(tok) || tok.startsWith('--package=')) continue;
    if (RUNNER_VALUE_FLAGS.has(tok)) {
      i++; // skip the flag's value too
      continue;
    }
    return basename(tok);
  }
  return first;
}

function round2(n: number): number {
  return Math.round(n * 100) / 100;
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/**
 * Pending-request map key. JSON-RPC ids may be a number or a string, and
 * `1` and `"1"` are distinct ids — String(id) alone would collapse them, so
 * the id's type is folded into the key too.
 */
function pendingKey(prefix: 'c2s:' | 's2c:', id: string | number): string {
  return prefix + (typeof id === 'number' ? 'n:' : 's:') + String(id);
}

export async function runStdioProxy(opts: StdioProxyOpts): Promise<number> {
  const proxyStdin: Readable = opts.stdin ?? process.stdin;
  const proxyStdout: Writable = opts.stdout ?? process.stdout;
  const proxyStderr: Writable = opts.stderr ?? process.stderr;
  const env = opts.env ?? process.env;
  const { recorder, redactor } = opts;

  const diag = (msg: string): void => {
    try {
      proxyStderr.write(`[mcp-recorder] ${msg}\n`);
    } catch {
      /* even diagnostics are fail-open */
    }
  };
  let tapErrorLogged = false;
  const tapError = (err: unknown): void => {
    if (tapErrorLogged) return;
    tapErrorLogged = true;
    diag(`tap error (recording degraded, traffic unaffected): ${err instanceof Error ? err.stack ?? err.message : String(err)}`);
  };

  /* ----------------------- identity & server context ---------------------- */

  let osUser = '';
  let host = '';
  try {
    osUser = userInfo().username;
  } catch {
    /* keep empty */
  }
  try {
    host = osHostname();
  } catch {
    /* keep empty */
  }

  const initialServerName = opts.serverName || deriveServerName(opts.command);
  const fingerprint = sha256Ref(
    `${osUser}\0${host}\0${opts.identityLabel || ''}\0${initialServerName}`,
  );

  const credentialFingerprints: { name: string; ref: string }[] = [];
  try {
    for (const [name, value] of Object.entries(env)) {
      if (credentialFingerprints.length >= 32) break;
      if (typeof value !== 'string' || value.length < 8) continue;
      if (!CREDENTIAL_NAME_RE.test(name)) continue;
      credentialFingerprints.push({ name, ref: redactor.hashString(value) });
    }
  } catch (err) {
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
      if (credentialFingerprints.length >= 32) break;
      credentialFingerprints.push(fp);
    }
  } catch (err) {
    tapError(err);
  }

  // Mutable bits learned from the initialize handshake.
  let clientName: string | undefined;
  let clientVersion: string | undefined;
  let learnedServerName: string | undefined;
  let learnedServerVersion: string | undefined;

  const currentIdentity = (): IdentityContext => {
    const id: IdentityContext = { fingerprint };
    if (osUser) id.os_user = osUser;
    if (host) id.hostname = host;
    if (clientName !== undefined) id.client_name = clientName;
    if (clientVersion !== undefined) id.client_version = clientVersion;
    if (opts.identityLabel) id.label = opts.identityLabel;
    if (credentialFingerprints.length > 0) {
      id.credential_fingerprints = credentialFingerprints.map((c) => ({ ...c }));
    }
    return id;
  };

  const currentServer = (): ServerContext => {
    const server: ServerContext = {
      name: opts.serverName || learnedServerName || initialServerName,
      command: scrubbedCommand,
      transport: 'stdio',
    };
    if (learnedServerVersion !== undefined) server.version = learnedServerVersion;
    return server;
  };

  const sessionId = randomUUID();
  const base = (kind: AnyEvent['kind'], attributes: Attributes) => ({
    schema: SCHEMA,
    event_id: randomUUID(),
    session_id: sessionId,
    timestamp: new Date().toISOString(),
    kind,
    identity: currentIdentity(),
    server: currentServer(),
    attributes,
  });

  const record = (event: AnyEvent): void => {
    recorder.record(event);
  };

  /* ------------------------------- spawn ---------------------------------- */

  const child = spawn(opts.command[0], opts.command.slice(1), {
    stdio: ['pipe', 'pipe', 'pipe'],
    env,
  });

  // Forwarding: plain pipes, untouched. (pipe() ends child.stdin when
  // proxyStdin ends, which is exactly the MCP stdio shutdown convention.)
  proxyStdin.pipe(child.stdin);
  child.stdout.pipe(proxyStdout, { end: false });
  child.stderr.pipe(proxyStderr, { end: false });

  // A dying child can EPIPE its stdin while the client is still writing;
  // that must never crash the proxy.
  child.stdin.on('error', (err: NodeJS.ErrnoException) => {
    if (err.code !== 'EPIPE' && err.code !== 'ERR_STREAM_DESTROYED') {
      diag(`child stdin error: ${err.message}`);
    }
  });
  proxyStdin.on('error', (err: Error) => diag(`stdin error: ${err.message}`));
  child.stdout.on('error', (err: Error) => diag(`child stdout error: ${err.message}`));
  child.stderr.on('error', (err: Error) => diag(`child stderr error: ${err.message}`));

  // The MCP client can close its read end of our stdout/stderr at any time
  // (it exited, it stopped reading, a downstream pipe broke). .pipe()'s
  // destination gets no default 'error' listener, so without one an EPIPE
  // here is an unhandled 'error' event — it crashes the whole proxy, drops
  // whatever was queued, and session_end never gets written. Both directions
  // must survive it.
  const isEpipeLike = (err: NodeJS.ErrnoException): boolean =>
    err.code === 'EPIPE' || err.code === 'ERR_STREAM_DESTROYED';
  proxyStdout.on('error', (err: NodeJS.ErrnoException) => {
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
      child.stdout.unpipe(proxyStdout);
      child.stdout.resume();
    } catch {
      /* fail-open */
    }
    try {
      if (!child.stdin.writableEnded) child.stdin.end();
    } catch {
      /* fail-open */
    }
  });
  proxyStderr.on('error', (err: NodeJS.ErrnoException) => {
    if (!isEpipeLike(err)) {
      diag(`stderr error: ${err.message}`);
      return;
    }
    // Diagnostics/child stderr have nowhere to go; stop piping and keep
    // draining the child's stderr so it never blocks on a full pipe.
    try {
      child.stderr.unpipe(proxyStderr);
    } catch {
      /* fail-open */
    }
    try {
      child.stderr.resume();
    } catch {
      /* fail-open */
    }
  });

  /* ------------------------------ tap state ------------------------------- */

  // Pending requests keyed direction-aware: 'c2s:<id>' for client-initiated,
  // 's2c:<id>' for server-initiated. Responses always arrive on the opposite
  // stream from the request that opened them.
  const pending = new Map<string, PendingEntry>();
  let pendingEvictWarned = false;
  const registerPending = (key: string, entry: PendingEntry): void => {
    if (pending.size >= MAX_PENDING) {
      const oldest = pending.keys().next().value as string | undefined;
      if (oldest !== undefined) pending.delete(oldest);
      if (!pendingEvictWarned) {
        pendingEvictWarned = true;
        diag(`pending request map exceeded ${MAX_PENDING} entries; evicting oldest`);
      }
    }
    pending.set(key, entry);
  };

  const protocolError = (
    direction: Direction,
    reason: ProtocolErrorEvent['reason'],
    bytesLen: number,
    lineHashHex: string,
  ): void => {
    const ev: ProtocolErrorEvent = {
      ...base('protocol_error', { 'rpc.system': 'jsonrpc' }),
      kind: 'protocol_error',
      direction,
      reason,
      bytes_len: bytesLen,
      line_hash: 'sha256:' + lineHashHex,
    };
    record(ev);
  };

  const errorInfo = (
    rawError: unknown,
  ): { code?: number; type?: string; message_ref?: string } => {
    const out: { code?: number; type?: string; message_ref?: string } = {
      type: 'jsonrpc_error',
    };
    if (isPlainObject(rawError)) {
      if (typeof rawError.code === 'number') out.code = rawError.code;
      if (typeof rawError.message === 'string') {
        out.message_ref = redactor.hashString(rawError.message);
      }
    }
    return out;
  };

  const handleResponse = (
    msg: Record<string, unknown>,
    arrivedOn: Direction,
    line: ScannedLine,
  ): void => {
    const id = msg.id as string | number;
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
    const isError =
      rawError !== undefined ||
      (isPlainObject(rawResult) && rawResult.isError === true);
    const resultHash = sha256Ref(canonicalJson(rawResult ?? rawError ?? null));
    const durationMs = round2(performance.now() - entry.t0);

    if (entry.method === 'initialize') {
      const reqParams = isPlainObject(entry.params) ? entry.params : {};
      const clientInfo = isPlainObject(reqParams.clientInfo) ? reqParams.clientInfo : {};
      const res = isPlainObject(rawResult) ? rawResult : {};
      const serverInfo = isPlainObject(res.serverInfo) ? res.serverInfo : {};
      // Remember for subsequent events' identity/server context.
      if (typeof clientInfo.name === 'string') clientName = clientInfo.name;
      if (typeof clientInfo.version === 'string') clientVersion = clientInfo.version;
      if (typeof serverInfo.name === 'string') learnedServerName = serverInfo.name;
      if (typeof serverInfo.version === 'string') learnedServerVersion = serverInfo.version;

      const ev: InitializeEvent = {
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
      if (typeof protoVersion === 'string') ev.protocol_version = protoVersion;
      if (clientName !== undefined) ev.client_name = clientName;
      if (clientVersion !== undefined) ev.client_version = clientVersion;
      if (learnedServerName !== undefined) ev.server_name = learnedServerName;
      if (learnedServerVersion !== undefined) ev.server_version = learnedServerVersion;
      record(ev);
      return;
    }

    if (entry.method === 'tools/call') {
      const tool = entry.toolName ?? '';
      const reqParams = isPlainObject(entry.params) ? entry.params : {};
      const attributes: Attributes = {
        'gen_ai.operation.name': 'execute_tool',
        'gen_ai.tool.name': tool,
        'gen_ai.tool.call.id': String(id),
        'mcp.method.name': 'tools/call',
        'rpc.system': 'jsonrpc',
      };
      if (rawError !== undefined) attributes['error.type'] = 'jsonrpc_error';
      const ev: ToolCallEvent = {
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
      if (rawError !== undefined) ev.error = errorInfo(rawError);
      record(ev);
      return;
    }

    const ev: RpcEvent = {
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
    if (rawError !== undefined) ev.error = errorInfo(rawError);
    record(ev);
  };

  const handleMessage = (msg: unknown, direction: Direction, line: ScannedLine): void => {
    if (Array.isArray(msg)) {
      // JSON-RPC batch — handle each element independently.
      for (const el of msg) handleMessage(el, direction, line);
      return;
    }
    if (!isPlainObject(msg)) return; // not a JSON-RPC message; ignore quietly
    const hasMethod = typeof msg.method === 'string';
    const id = msg.id;
    const hasId = id !== undefined && id !== null;

    if (hasMethod && hasId) {
      // Request: register pending under the direction it was sent on.
      const keyPrefix = direction === 'client_to_server' ? 'c2s:' : 's2c:';
      const reqId = id as string | number;
      const params = msg.params;
      const entry: PendingEntry = {
        method: msg.method as string,
        params,
        t0: performance.now(),
        id: reqId,
      };
      if (isPlainObject(params) && typeof params.name === 'string') {
        entry.toolName = params.name;
      }
      registerPending(pendingKey(keyPrefix, reqId), entry);
      return;
    }
    if (hasMethod) {
      const ev: NotificationEvent = {
        ...base('notification', {
          'mcp.method.name': msg.method as string,
          'rpc.system': 'jsonrpc',
        }),
        kind: 'notification',
        method: msg.method as string,
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

  const handleLine = (line: ScannedLine, direction: Direction): void => {
    if (line.oversized) {
      protocolError(direction, 'oversized', line.bytesLen, line.lineHashHex);
      return;
    }
    if (line.text === null) return;
    let msg: unknown;
    try {
      msg = JSON.parse(line.text);
    } catch {
      protocolError(direction, 'unparseable', line.bytesLen, line.lineHashHex);
      return;
    }
    handleMessage(msg, direction, line);
  };

  const c2sScanner = new LineScanner();
  const s2cScanner = new LineScanner();
  const tap = (scanner: LineScanner, direction: Direction) => (chunk: Buffer): void => {
    try {
      for (const line of scanner.push(chunk)) handleLine(line, direction);
    } catch (err) {
      tapError(err);
    }
  };
  proxyStdin.on('data', tap(c2sScanner, 'client_to_server'));
  child.stdout.on('data', tap(s2cScanner, 'server_to_client'));

  /* ---------------------------- session events ---------------------------- */

  const sessionStart: SessionStartEvent = {
    ...base('session_start', { 'rpc.system': 'jsonrpc' }),
    kind: 'session_start',
    proxy_version: opts.proxyVersion,
    cwd: process.cwd(),
    redaction_mode: redactor.mode,
  };
  record(sessionStart);

  /* ------------------------------ lifecycle ------------------------------- */

  let stdinEnded = false;
  proxyStdin.on('end', () => {
    stdinEnded = true;
    try {
      // pipe() already propagates end; this is belt-and-braces.
      if (!child.stdin.writableEnded) child.stdin.end();
    } catch {
      /* fail-open */
    }
    try {
      for (const line of c2sScanner.end()) handleLine(line, 'client_to_server');
    } catch (err) {
      tapError(err);
    }
  });
  child.stdout.on('end', () => {
    try {
      for (const line of s2cScanner.end()) handleLine(line, 'server_to_client');
    } catch (err) {
      tapError(err);
    }
  });

  // Forward terminal signals to the child only when we own the real stdin.
  const signalHandlers: Array<[NodeJS.Signals, () => void]> = [];
  let signalForwarded = false;
  if (proxyStdin === process.stdin) {
    for (const sig of ['SIGINT', 'SIGTERM', 'SIGHUP'] as NodeJS.Signals[]) {
      const handler = (): void => {
        signalForwarded = true;
        try {
          child.kill(sig);
        } catch {
          /* child already gone */
        }
      };
      process.on(sig, handler);
      signalHandlers.push([sig, handler]);
    }
  }
  const removeSignalHandlers = (): void => {
    for (const [sig, handler] of signalHandlers) process.removeListener(sig, handler);
  };

  return await new Promise<number>((resolve) => {
    let finished = false;
    /** errno code from the child 'error' event, when spawning failed outright. */
    let spawnErrorCode: string | undefined;

    // A request still pending at session end (server crashed or was killed
    // mid-call, or the client disconnected mid-handshake) would otherwise
    // vanish from the chain with no trace. Seal one synthetic event per
    // pending entry before session_end: a tools/call becomes a tool_call
    // event, everything else (including an unanswered initialize) becomes
    // an rpc event — both is_error, error.type 'unanswered'.
    const emitUnanswered = (): void => {
      if (pending.size === 0) return;
      const shutdownT0 = performance.now();
      for (const entry of pending.values()) {
        const durationMs = round2(shutdownT0 - entry.t0);
        if (entry.method === 'tools/call') {
          const tool = entry.toolName ?? '';
          const reqParams = isPlainObject(entry.params) ? entry.params : {};
          const attributes: Attributes = {
            'gen_ai.operation.name': 'execute_tool',
            'gen_ai.tool.name': tool,
            'gen_ai.tool.call.id': String(entry.id),
            'mcp.method.name': 'tools/call',
            'rpc.system': 'jsonrpc',
            'error.type': 'unanswered',
          };
          const ev: ToolCallEvent = {
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
          record(ev);
        } else {
          const attributes: Attributes = {
            'mcp.method.name': entry.method,
            'rpc.system': 'jsonrpc',
            'rpc.jsonrpc.request_id': String(entry.id),
            'error.type': 'unanswered',
          };
          const ev: RpcEvent = {
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

    const finalize = async (
      reason: SessionEndEvent['reason'],
      exitCode: number | null,
      signal: NodeJS.Signals | null,
    ): Promise<void> => {
      if (finished) return;
      finished = true;
      removeSignalHandlers();
      try {
        emitUnanswered();
      } catch (err) {
        tapError(err);
      }
      try {
        await recorder.flush();
      } catch {
        /* recorder is fail-open; flush never rejects, but be safe */
      }
      try {
        const stats = recorder.stats();
        const ev: SessionEndEvent = {
          ...base('session_end', { 'rpc.system': 'jsonrpc' }),
          kind: 'session_end',
          reason,
          child_exit_code: exitCode,
          events_recorded: stats.written,
          events_dropped: stats.dropped,
        };
        if (spawnErrorCode !== undefined) ev.spawn_error = spawnErrorCode;
        if (signal !== null) ev.child_signal = signal;
        record(ev);
      } catch (err) {
        tapError(err);
      }
      try {
        await Promise.race([
          recorder.close(),
          new Promise<void>((res) => setTimeout(res, CLOSE_TIMEOUT_MS).unref?.()),
        ]);
      } catch {
        /* fail-open */
      }
      let code: number;
      if (exitCode !== null) {
        code = exitCode;
      } else if (signal !== null) {
        code = signalExitCode(signal);
      } else if (spawnErrorCode !== undefined) {
        code = spawnErrorExitCode(spawnErrorCode);
      } else {
        code = 0;
      }
      resolve(code);
    };

    child.on('error', (err: NodeJS.ErrnoException) => {
      diag(`failed to run ${opts.command[0]}: ${err.message}`);
      spawnErrorCode = err.code ?? 'UNKNOWN';
      void finalize('error', null, null);
    });

    // 'close' (not 'exit') so the child's stdio has fully drained through the
    // pipes before we seal the session.
    child.on('close', (code: number | null, signal: NodeJS.Signals | null) => {
      const reason: SessionEndEvent['reason'] = signalForwarded
        ? 'signal'
        : stdinEnded
          ? 'stdin_closed'
          : 'child_exit';
      void finalize(reason, code, signal);
    });
  });
}
