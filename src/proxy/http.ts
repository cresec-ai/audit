/**
 * Streamable-HTTP passthrough proxy + capture tap.
 *
 * FORWARDING IS SACRED: incoming requests are streamed to the target with
 * method/headers preserved (hop-by-hop headers excepted) and the target's
 * response is streamed back verbatim — status, headers, body chunks as they
 * arrive, so SSE flows untouched. The tap keeps a bounded COPY of bodies and
 * scans them for JSON-RPC traffic; every tap failure is swallowed (fail-open).
 */

import { createServer, request as httpRequest } from 'node:http';
import type { IncomingMessage, OutgoingHttpHeaders, ServerResponse } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { hostname as osHostname, userInfo } from 'node:os';
import { performance } from 'node:perf_hooks';
import { randomUUID } from 'node:crypto';
import type { AddressInfo } from 'node:net';

import { canonicalJson, sha256Hex, sha256Ref } from '../chain/hash.js';
import { looksSecret, scrubToolArguments } from '../redact/redactor.js';
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
import type { RecorderLike, RedactorLike } from '../types.js';

export interface HttpProxyOpts {
  /** Base URL of the wrapped streamable-HTTP MCP server. */
  targetUrl: string;
  /** Local port; default 0 = ephemeral. Binds 127.0.0.1 only. */
  port?: number;
  recorder: RecorderLike;
  redactor: RedactorLike;
  serverName?: string;
  identityLabel?: string;
  proxyVersion: string;
  /**
   * Optional cap (ms) on how long to wait for the upstream to begin
   * responding (status + headers) to one exchange. Cleared the instant
   * headers arrive, so it never applies to a slow-but-healthy streaming
   * response (SSE, or a tool call that is merely slow) — forwarding must
   * never be torn down for inactivity once it is under way. Default:
   * disabled (no cap at all), opt-in only.
   */
  upstreamHeadersTimeoutMs?: number;
}

export interface HttpProxyHandle {
  /** http://127.0.0.1:<port>/ */
  url: string;
  /** Stop listening, seal the session, close the recorder. Idempotent. */
  close(): Promise<void>;
}

interface PendingEntry {
  method: string;
  params: unknown;
  t0: number;
  toolName?: string;
  id: string | number;
  /** Unique key this entry is stored under in `allPending` (close()-time bookkeeping). */
  allKey: string;
  /** Session-scoped fallback key, if also registered there (best-effort cleanup). */
  sessionFallbackKey?: string;
}

type Direction = 'client_to_server' | 'server_to_client';

const MAX_TAP_BODY = 32 * 1024 * 1024; // 32 MiB cap on tapped body copies
const MAX_PENDING = 10_000;

/** Hop-by-hop headers that must not be forwarded in either direction. */
const HOP_BY_HOP = new Set([
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'proxy-connection',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
]);

function round2(n: number): number {
  return Math.round(n * 100) / 100;
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/** Key a JSON-RPC id by value AND type, so numeric 1 and string "1" never collide. */
function idKeyOf(id: string | number): string {
  return (typeof id === 'number' ? 'n:' : 's:') + String(id);
}

/**
 * Incremental SSE scanner: feed raw body chunks, get every complete `data:`
 * payload (multi-line data fields joined per the SSE spec). Bounded so a
 * pathological stream cannot grow memory without limit.
 */
class SseScanner {
  private buf = '';
  private dataLines: string[] = [];
  private overflowed = false;

  push(chunk: Buffer): string[] {
    if (this.overflowed) return [];
    this.buf += chunk.toString('utf8');
    if (this.buf.length > MAX_TAP_BODY) {
      this.overflowed = true;
      this.buf = '';
      this.dataLines = [];
      return [];
    }
    const out: string[] = [];
    let nl: number;
    while ((nl = this.buf.indexOf('\n')) !== -1) {
      const line = this.buf.slice(0, nl).replace(/\r$/, '');
      this.buf = this.buf.slice(nl + 1);
      if (line === '') {
        if (this.dataLines.length > 0) {
          out.push(this.dataLines.join('\n'));
          this.dataLines = [];
        }
        continue;
      }
      if (line.startsWith('data:')) {
        this.dataLines.push(line.slice(5).replace(/^ /, ''));
      }
      // other SSE fields (event:, id:, retry:, comments) are irrelevant here
    }
    return out;
  }

  end(): string[] {
    if (this.overflowed) return [];
    const out: string[] = [];
    const tail = this.buf.replace(/\r$/, '');
    this.buf = '';
    if (tail.startsWith('data:')) this.dataLines.push(tail.slice(5).replace(/^ /, ''));
    if (this.dataLines.length > 0) {
      out.push(this.dataLines.join('\n'));
      this.dataLines = [];
    }
    return out;
  }
}

export async function runHttpProxy(opts: HttpProxyOpts): Promise<HttpProxyHandle> {
  const target = new URL(opts.targetUrl);
  if (target.protocol !== 'http:' && target.protocol !== 'https:') {
    throw new Error(`mcp-recorder: unsupported target protocol '${target.protocol}'`);
  }
  const requester = target.protocol === 'https:' ? httpsRequest : httpRequest;
  const { recorder, redactor } = opts;

  const diag = (msg: string): void => {
    try {
      process.stderr.write(`[mcp-recorder] ${msg}\n`);
    } catch {
      /* even diagnostics are fail-open */
    }
  };
  let tapErrorLogged = false;
  const tapError = (err: unknown): void => {
    if (tapErrorLogged) return;
    tapErrorLogged = true;
    diag(
      `tap error (recording degraded, traffic unaffected): ${
        err instanceof Error ? err.stack ?? err.message : String(err)
      }`,
    );
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

  const initialServerName = opts.serverName || target.host;
  const fingerprint = sha256Ref(
    `${osUser}\0${host}\0${opts.identityLabel || ''}\0${initialServerName}`,
  );

  // `--target http://user:pass@host/path?query...`: no part of this URL that
  // can carry a credential may ever be stored readable (command string or
  // any event) — `target` itself (used for the actual upstream connection
  // below) is untouched, so auth to the wrapped server is unaffected. Three
  // distinct leak shapes are covered here:
  //  - userinfo (`user:pass@host`) — stripped;
  //  - a hosted-MCP credential embedded in the PATH
  //    (`https://host/mcp/sk-.../sse`) — each secret-shaped path segment is
  //    replaced by its hash, in place;
  //  - a credential in the QUERY STRING (`?api_key=...`, `?token=...`) — the
  //    entire query string (and fragment) is dropped from the recorded URL;
  //    there is no safe subset to keep once any single param can be a bearer
  //    credential.
  // Every stripped/replaced piece is also fingerprinted so a blast-radius
  // `query` for the leaked value still finds the event that carried it.
  const credentialFingerprints: { name: string; ref: string }[] = [];
  let targetUrlForRecording = opts.targetUrl;
  try {
    const clean = new URL(target.href);

    if (clean.username !== '' || clean.password !== '') {
      const decode = (s: string): string => {
        try {
          return decodeURIComponent(s);
        } catch {
          return s;
        }
      };
      const user = decode(clean.username);
      const pass = decode(clean.password);
      const raw = clean.password ? `${user}:${pass}` : user;
      credentialFingerprints.push({ name: 'target_url_userinfo', ref: redactor.hashString(raw) });
      // P2: also fingerprint the password (and user) separately, so a query
      // for the leaked password ALONE — without knowing the username —
      // still finds it.
      if (pass) {
        credentialFingerprints.push({
          name: 'target_url_userinfo',
          ref: redactor.hashString(pass),
        });
      }
      if (user) {
        credentialFingerprints.push({
          name: 'target_url_userinfo',
          ref: redactor.hashString(user),
        });
      }
      clean.username = '';
      clean.password = '';
    }

    const segments = clean.pathname.split('/');
    for (let i = 0; i < segments.length; i++) {
      const seg = segments[i]!;
      if (seg !== '' && looksSecret(seg)) {
        const ref = redactor.hashString(seg);
        credentialFingerprints.push({ name: `target_url_path[${i}]`, ref });
        segments[i] = ref;
      }
    }
    clean.pathname = segments.join('/');

    for (const [qk, qv] of clean.searchParams) {
      if (looksSecret(qv)) {
        credentialFingerprints.push({
          name: `target_url_query.${qk}`,
          ref: redactor.hashString(qv),
        });
      }
    }
    clean.search = '';
    clean.hash = '';

    targetUrlForRecording = clean.toString();
  } catch (err) {
    tapError(err);
  }

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
      command: targetUrlForRecording,
      transport: 'http',
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

  /* ------------------------------ tap logic -------------------------------- */

  /**
   * Correlation is scoped per client, not process-wide — many client
   * connections share this proxy and every MCP client starts its JSON-RPC
   * ids at 1, so a single global map would attribute one client's response
   * to another's pending request (or worse, record it as an orphan).
   *
   * `ExchangeScope.local` is fresh per HTTP request/response exchange: a
   * client-initiated request registered in a POST's body is looked up
   * against that SAME exchange's upstream response first — the response
   * belongs to the request that carried it, per the streamable-HTTP
   * transport, so this needs no session id at all and cannot collide with a
   * concurrent client's identical id.
   *
   * `sessionPending` is the fallback: keyed by the `Mcp-Session-Id` header
   * (when present) plus direction plus the id (value AND type, so numeric 1
   * and string "1" never collide). It is consulted for responses delivered
   * over the standalone SSE stream — either a server-initiated request
   * (whose answer can only ever arrive on a later, different exchange) or a
   * client request the target chose to answer asynchronously instead of on
   * the originating POST.
   */
  interface ExchangeScope {
    local: Map<string, PendingEntry>;
    sessionKey: string;
    exchangeId: string;
  }

  const sessionPending = new Map<string, PendingEntry>();
  /** Every currently-unanswered entry, local or session-scoped, for close()-time bookkeeping. */
  const allPending = new Map<string, PendingEntry>();
  let pendingEvictWarned = false;
  const evictOldest = (map: Map<string, PendingEntry>): void => {
    if (map.size < MAX_PENDING) return;
    const oldest = map.keys().next().value as string | undefined;
    if (oldest !== undefined) map.delete(oldest);
    if (!pendingEvictWarned) {
      pendingEvictWarned = true;
      diag(`pending request map exceeded ${MAX_PENDING} entries; evicting oldest`);
    }
  };

  const protocolError = (
    direction: Direction,
    reason: ProtocolErrorEvent['reason'],
    bytesLen: number,
    raw: string,
  ): void => {
    const ev: ProtocolErrorEvent = {
      ...base('protocol_error', { 'rpc.system': 'jsonrpc' }),
      kind: 'protocol_error',
      direction,
      reason,
      bytes_len: bytesLen,
      line_hash: 'sha256:' + sha256Hex(raw),
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

  const finishEntry = (entry: PendingEntry, scope: ExchangeScope): void => {
    scope.local.delete(idKeyOf(entry.id));
    if (
      entry.sessionFallbackKey !== undefined &&
      sessionPending.get(entry.sessionFallbackKey) === entry
    ) {
      sessionPending.delete(entry.sessionFallbackKey);
    }
    allPending.delete(entry.allKey);
  };

  const emitFromEntry = (
    entry: PendingEntry,
    id: string | number,
    rawResult: unknown,
    rawError: unknown,
  ): void => {
    const isError =
      rawError !== undefined || (isPlainObject(rawResult) && rawResult.isError === true);
    const resultHash = sha256Ref(canonicalJson(rawResult ?? rawError ?? null));
    const durationMs = round2(performance.now() - entry.t0);

    if (entry.method === 'initialize') {
      const reqParams = isPlainObject(entry.params) ? entry.params : {};
      const clientInfo = isPlainObject(reqParams.clientInfo) ? reqParams.clientInfo : {};
      const res = isPlainObject(rawResult) ? rawResult : {};
      const serverInfo = isPlainObject(res.serverInfo) ? res.serverInfo : {};
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

  const handleResponse = (
    msg: Record<string, unknown>,
    arrivedOn: Direction,
    raw: string,
    scope: ExchangeScope,
  ): void => {
    const id = msg.id as string | number;
    const key = idKeyOf(id);
    let entry: PendingEntry | undefined;

    if (arrivedOn === 'server_to_client') {
      // Answers a client-initiated request. The common case: it was
      // registered within THIS same exchange (the request that carried it).
      entry = scope.local.get(key);
      if (!entry) {
        // Fallback: the target answered asynchronously over the standalone
        // SSE stream instead of on the originating POST's own response.
        const fallbackKey = scope.sessionKey + 'c2s' + key;
        entry = sessionPending.get(fallbackKey);
      }
    } else {
      // The client is answering a request the server initiated earlier —
      // that request can only ever live in the session-scoped map, since
      // its answer necessarily arrives on a different exchange.
      const fallbackKey = scope.sessionKey + 's2c' + key;
      entry = sessionPending.get(fallbackKey);
    }

    if (!entry) {
      protocolError(arrivedOn, 'orphan_response', Buffer.byteLength(raw), raw);
      return;
    }
    finishEntry(entry, scope);

    const rawResult = 'result' in msg ? msg.result : undefined;
    const rawError = 'error' in msg ? msg.error : undefined;
    emitFromEntry(entry, id, rawResult, rawError);
  };

  const handleMessage = (
    msg: unknown,
    direction: Direction,
    raw: string,
    scope: ExchangeScope,
  ): void => {
    if (Array.isArray(msg)) {
      for (const el of msg) handleMessage(el, direction, raw, scope);
      return;
    }
    if (!isPlainObject(msg)) return;
    const hasMethod = typeof msg.method === 'string';
    const idRaw = msg.id;
    const hasId = idRaw !== undefined && idRaw !== null;

    if (hasMethod && hasId) {
      const id = idRaw as string | number;
      const key = idKeyOf(id);
      const params = msg.params;
      const entry: PendingEntry = {
        method: msg.method as string,
        params,
        t0: performance.now(),
        id,
        allKey: scope.exchangeId + '|' + key,
      };
      if (isPlainObject(params) && typeof params.name === 'string') {
        entry.toolName = params.name;
      }
      if (direction === 'client_to_server') {
        // Common case: the target answers within this same HTTP exchange.
        scope.local.set(key, entry);
        // Rare/deferred case: some targets accept the POST and deliver the
        // response later, over the standalone SSE stream. Register a
        // session-scoped fallback too, so that path can still find it.
        entry.sessionFallbackKey = scope.sessionKey + 'c2s' + key;
      } else {
        // Server-initiated request: its answer always arrives on a
        // different exchange (a later client POST), so only the
        // session-scoped map can ever resolve it.
        entry.sessionFallbackKey = scope.sessionKey + 's2c' + key;
      }
      evictOldest(sessionPending);
      sessionPending.set(entry.sessionFallbackKey, entry);
      evictOldest(allPending);
      allPending.set(entry.allKey, entry);
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
      handleResponse(msg, direction, raw, scope);
    }
  };

  /** Parse a (possibly batch) JSON-RPC body and feed the tap. Never throws. */
  const tapJsonBody = (body: string, direction: Direction, scope: ExchangeScope): void => {
    try {
      let msg: unknown;
      try {
        msg = JSON.parse(body);
      } catch {
        protocolError(direction, 'unparseable', Buffer.byteLength(body), body);
        return;
      }
      handleMessage(msg, direction, body, scope);
    } catch (err) {
      tapError(err);
    }
  };

  /** A pending entry with no response by the time the proxy closes: recorded, never silently dropped. */
  const emitUnanswered = (entry: PendingEntry): void => {
    try {
      const durationMs = round2(performance.now() - entry.t0);
      const nullHash = sha256Ref(canonicalJson(null));
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
          result_hash: nullHash,
          result: null,
          is_error: true,
          duration_ms: durationMs,
          error: { type: 'unanswered' },
        };
        record(ev);
        return;
      }
      const ev: RpcEvent = {
        ...base('rpc', {
          'mcp.method.name': entry.method,
          'rpc.system': 'jsonrpc',
          'rpc.jsonrpc.request_id': String(entry.id),
          'error.type': 'unanswered',
        }),
        kind: 'rpc',
        method: entry.method,
        request_id: entry.id,
        params: redactor.scrub(entry.params ?? null),
        result_hash: nullHash,
        is_error: true,
        duration_ms: durationMs,
        error: { type: 'unanswered' },
      };
      record(ev);
    } catch (err) {
      tapError(err);
    }
  };

  /* ----------------------------- forwarding -------------------------------- */

  const isJsonContentType = (ct: string | undefined): boolean =>
    typeof ct === 'string' && /\bjson\b/i.test(ct);
  const isSseContentType = (ct: string | undefined): boolean =>
    typeof ct === 'string' && /text\/event-stream/i.test(ct);

  const forwardHeaders = (
    incoming: NodeJS.Dict<string | string[]>,
    alsoDrop?: string,
  ): OutgoingHttpHeaders => {
    const out: OutgoingHttpHeaders = {};
    for (const [k, v] of Object.entries(incoming)) {
      const lk = k.toLowerCase();
      if (HOP_BY_HOP.has(lk)) continue;
      if (alsoDrop !== undefined && lk === alsoDrop) continue;
      if (v !== undefined) out[k] = v;
    }
    return out;
  };

  const handleRequest = (req: IncomingMessage, res: ServerResponse): void => {
    // Resolve the upstream URL: '/' means "the configured endpoint"; any
    // other path is grafted onto the target origin (sub-endpoints).
    let upstreamUrl: URL;
    try {
      upstreamUrl =
        req.url === undefined || req.url === '/' ? target : new URL(req.url, target);
    } catch {
      upstreamUrl = target;
    }

    const sessionHeader = req.headers['mcp-session-id'];
    const sessionKey =
      typeof sessionHeader === 'string'
        ? sessionHeader
        : Array.isArray(sessionHeader) && sessionHeader.length > 0
          ? sessionHeader[0]
          : '';
    const scope: ExchangeScope = { local: new Map(), sessionKey, exchangeId: randomUUID() };

    const upReq = requester(
      upstreamUrl,
      { method: req.method, headers: forwardHeaders(req.headers, 'host') },
      (upRes) => {
        // Headers are in: any header-wait timeout no longer applies. A
        // streaming (or merely slow) response must never be torn down for
        // inactivity once the exchange is under way.
        upReq.setTimeout(0);
        try {
          res.writeHead(
            upRes.statusCode ?? 502,
            upRes.statusMessage,
            forwardHeaders(upRes.headers),
          );
          res.flushHeaders();
        } catch (err) {
          tapError(err);
          try {
            res.destroy();
          } catch {
            /* already gone */
          }
          upRes.destroy();
          return;
        }

        // Per-response tap state, chosen by content-type.
        const ct = upRes.headers['content-type'];
        const sse = isSseContentType(ct) ? new SseScanner() : null;
        const tapJson = sse === null && isJsonContentType(ct);
        const jsonChunks: Buffer[] = [];
        let jsonLen = 0;
        let jsonOver = false;

        upRes.on('data', (chunk: Buffer) => {
          // Forward first — the tap must never delay or reorder bytes.
          res.write(chunk);
          try {
            if (sse !== null) {
              for (const data of sse.push(chunk)) {
                try {
                  handleMessage(JSON.parse(data), 'server_to_client', data, scope);
                } catch {
                  /* non-JSON SSE data (pings etc.) — ignore quietly */
                }
              }
            } else if (tapJson && !jsonOver) {
              jsonLen += chunk.length;
              if (jsonLen > MAX_TAP_BODY) {
                jsonOver = true;
                jsonChunks.length = 0;
              } else {
                jsonChunks.push(chunk);
              }
            }
          } catch (err) {
            tapError(err);
          }
        });
        upRes.on('end', () => {
          try {
            res.end();
          } catch {
            /* client already gone */
          }
          try {
            if (sse !== null) {
              for (const data of sse.end()) {
                try {
                  handleMessage(JSON.parse(data), 'server_to_client', data, scope);
                } catch {
                  /* ignore */
                }
              }
            } else if (tapJson && !jsonOver && jsonChunks.length > 0) {
              tapJsonBody(Buffer.concat(jsonChunks).toString('utf8'), 'server_to_client', scope);
            }
          } catch (err) {
            tapError(err);
          }
        });
        upRes.on('error', () => {
          try {
            res.destroy();
          } catch {
            /* already gone */
          }
        });
      },
    );

    // Optional, opt-in cap on the wait for the FIRST byte of the response.
    // Cleared in the response callback above the instant headers arrive —
    // it never applies to a streaming or merely slow body.
    const headersTimeoutMs = opts.upstreamHeadersTimeoutMs;
    if (headersTimeoutMs !== undefined && headersTimeoutMs > 0) {
      upReq.setTimeout(headersTimeoutMs, () => {
        upReq.destroy(new Error(`target did not respond within ${headersTimeoutMs}ms`));
      });
    }
    upReq.on('error', (err: Error) => {
      if (res.headersSent) {
        try {
          res.destroy();
        } catch {
          /* already gone */
        }
        return;
      }
      const body = JSON.stringify({
        jsonrpc: '2.0',
        id: null,
        error: {
          code: -32001,
          message: `mcp-recorder proxy: upstream request failed: ${err.message}`,
        },
      });
      try {
        res.writeHead(502, {
          'content-type': 'application/json',
          'content-length': Buffer.byteLength(body),
        });
        res.end(body);
      } catch {
        /* response already unusable */
      }
    });

    // The upstream connection must not outlive the client's interest in the
    // response: if the client goes away mid-exchange (aborted fetch, closed
    // socket), tear down the upstream request/response too instead of
    // leaking it. Safe to call after a normal completion — destroy() on an
    // already-finished request is a no-op.
    let upstreamAborted = false;
    const abortUpstream = (): void => {
      if (upstreamAborted) return;
      upstreamAborted = true;
      try {
        if (!upReq.destroyed) upReq.destroy();
      } catch {
        /* already gone */
      }
    };
    // `req`'s 'close' fires once its body has been fully read too, not only
    // on a premature disconnect — `req.complete` tells them apart. `res`'s
    // 'close' can likewise fire after a normal `res.end()`, so only treat it
    // as an abort signal when the response never actually finished.
    req.on('close', () => {
      if (!req.complete) abortUpstream();
    });
    res.on('close', () => {
      if (!res.writableEnded) abortUpstream();
    });

    // Request body: stream straight through; keep a bounded COPY for the tap.
    const reqIsJson = isJsonContentType(req.headers['content-type']);
    const reqChunks: Buffer[] = [];
    let reqLen = 0;
    let reqOver = false;
    req.on('data', (chunk: Buffer) => {
      try {
        if (!reqIsJson || reqOver) return;
        reqLen += chunk.length;
        if (reqLen > MAX_TAP_BODY) {
          reqOver = true;
          reqChunks.length = 0;
        } else {
          reqChunks.push(chunk);
        }
      } catch (err) {
        tapError(err);
      }
    });
    req.on('end', () => {
      try {
        if (reqIsJson && !reqOver && reqChunks.length > 0) {
          tapJsonBody(Buffer.concat(reqChunks).toString('utf8'), 'client_to_server', scope);
        }
      } catch (err) {
        tapError(err);
      }
    });
    req.on('error', () => {
      upReq.destroy();
    });
    req.pipe(upReq);
  };

  /* ------------------------------ lifecycle -------------------------------- */

  const server = createServer(handleRequest);
  server.on('clientError', (_err, socket) => {
    try {
      socket.destroy();
    } catch {
      /* already gone */
    }
  });

  await new Promise<void>((resolveListen, rejectListen) => {
    server.once('error', rejectListen);
    server.listen(opts.port ?? 0, '127.0.0.1', () => {
      server.removeListener('error', rejectListen);
      resolveListen();
    });
  });
  const address = server.address() as AddressInfo;
  const url = `http://127.0.0.1:${address.port}/`;

  try {
    const sessionStart: SessionStartEvent = {
      ...base('session_start', { 'rpc.system': 'jsonrpc' }),
      kind: 'session_start',
      proxy_version: opts.proxyVersion,
      cwd: process.cwd(),
      redaction_mode: redactor.mode,
    };
    record(sessionStart);
  } catch (err) {
    tapError(err);
  }

  let closed = false;
  const close = async (): Promise<void> => {
    if (closed) return;
    closed = true;
    try {
      // Requests still in flight when the proxy closes get no response —
      // record that explicitly rather than silently dropping them.
      for (const entry of allPending.values()) emitUnanswered(entry);
      allPending.clear();
      sessionPending.clear();
    } catch (err) {
      tapError(err);
    }
    try {
      await recorder.flush();
    } catch {
      /* fail-open */
    }
    try {
      const stats = recorder.stats();
      const ev: SessionEndEvent = {
        ...base('session_end', { 'rpc.system': 'jsonrpc' }),
        kind: 'session_end',
        reason: 'signal',
        child_exit_code: null,
        events_recorded: stats.written,
        events_dropped: stats.dropped,
      };
      record(ev);
    } catch (err) {
      tapError(err);
    }
    await new Promise<void>((resolveClose) => {
      server.close(() => resolveClose());
      server.closeAllConnections();
    });
    try {
      await recorder.close();
    } catch {
      /* fail-open */
    }
  };

  return { url, close };
}
