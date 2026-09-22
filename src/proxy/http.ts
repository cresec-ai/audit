/**
 * Streamable-HTTP passthrough proxy + capture tap.
 *
 * FORWARDING IS SACRED: incoming requests are streamed to the target with
 * method/headers preserved (hop-by-hop headers excepted) and the target's
 * response is streamed back verbatim — status, headers, body chunks as they
 * arrive, so SSE flows untouched. The tap keeps a bounded COPY of bodies and
 * scans them for JSON-RPC traffic; every tap failure is swallowed (fail-open).
 *
 * GATEWAY MODE (`opts.gateway` present, i.e. `http --policy`) is the ONE
 * place the above is set aside, and only for `tools/call` requests and
 * their results — the same rule the stdio gateway follows (./stdio.ts):
 *
 *  - EVERY POST — whatever its content-type header says, or none — is
 *    BUFFERED (up to MAX_GATEWAY_BODY) and parsed as JSON before anything
 *    reaches the upstream; a `tools/call` in it is
 *    evaluated against the policy and allowed (forwarded as written, or
 *    with a brokered credential spliced in at a declared site), denied (a
 *    tool-error result the model can read, written by the proxy itself, the
 *    upstream never sees the call) or held (the exchange is parked until
 *    `mcp-recorder approve|deny`, the timeout, a `notifications/cancelled`
 *    from the client, or the client going away). A body the gateway cannot
 *    evaluate — too large to buffer, not JSON — is refused with a JSON-RPC
 *    error and never forwarded (enforcement fails closed);
 *  - a JSON response body is buffered and every tools/call result in it
 *    goes through the boundary filter; an SSE response (on the POST, or on
 *    the standalone GET stream) is split into EVENTS, each held only until
 *    the blank line that ends it, and a tools/call result carried by a
 *    `data:` line is filtered before the event is re-emitted. Nothing else
 *    about the response is touched; an event the filter did not change goes
 *    out from its original bytes;
 *  - `accept-encoding: identity` is forced on the upstream request, and a
 *    response that arrives compressed anyway is refused (502): a result the
 *    filter cannot read must not reach the client unread;
 *  - a JSON-RPC batch is all or nothing: forwarded when every tools/call in
 *    it is allowed and needs no credential, answered locally otherwise
 *    (each refused call gets its deny result, every other element a
 *    -32600 asking for it to be resent on its own). MCP dropped batching
 *    in 2025-06-18; this keeps the gate closed for a client that still
 *    sends one.
 *
 * Every other exchange — GET, DELETE — streams exactly as it does without a
 * policy. A POST body that is not JSON does not: it is refused (400), never
 * forwarded, because the gate cannot know it carries no tools/call. The
 * correlation is per exchange, so a JSON-RPC id reused by another client
 * cannot take over a held call's slot; the
 * stdio gateway's duplicate-id gate has no HTTP counterpart and needs none.
 * Recording stays fail-open inside gateway mode (a store failure never
 * becomes a deny); enforcement fails closed (an unevaluable policy or an
 * unwritable hold is a deny).
 */

import { createServer, request as httpRequest } from 'node:http';
import type { IncomingMessage, OutgoingHttpHeaders, ServerResponse } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { hostname as osHostname, userInfo } from 'node:os';
import { performance } from 'node:perf_hooks';
import { randomUUID } from 'node:crypto';
import type { AddressInfo } from 'node:net';

import { canonicalJson, sha256Hex, sha256Ref } from '../chain/hash.js';
import { looksSecret, scrubToolArguments, structuralString } from '../redact/redactor.js';
import type {
  AnyEvent,
  Attributes,
  BoundaryReport,
  GatewayOutcome,
  HoldOutcome,
  IdentityContext,
  InitializeEvent,
  NotificationEvent,
  PolicyDecisionEvent,
  ProtocolErrorEvent,
  RpcEvent,
  ServerContext,
  SessionEndEvent,
  SessionStartEvent,
  ToolCallEvent,
} from '../schema/events.js';
import { SCHEMA } from '../schema/events.js';
import type { RecorderLike, RedactorLike } from '../types.js';
import type { GatewayOptions } from '../gateway/options.js';
import {
  FAIL_CLOSED_REFUSAL_GUIDANCE,
  applyBoundary,
  boundarySecretPatterns,
  deniedText,
  synthesizeDeniedResult,
  type BoundaryDeps,
  type DeniedTextInput,
} from '../gateway/boundary.js';
import {
  MAX_INFLIGHT_SWAPS,
  SWAP_DENY,
  swapDenyReason,
  unplannableSwap,
  type PlannedSwap,
  type SwapOutcome,
} from '../gateway/credentials.js';
import type { HoldRecord, HoldWaitResult } from '../gateway/holds.js';
import { PolicyEvalError, evaluateMcp, type McpDecision, type PolicyErrorCode } from '../policy/engine.js';
import { stampActor, type ActorStamp } from '../identity/stamp.js';
import {
  INVALID_ID_TOOLS_CALL_MESSAGE,
  MAX_HOLDS,
  NESTED_BATCH_MESSAGE,
  NULL_ID_TOOLS_CALL_MESSAGE,
  OVERSIZED_LINE_MESSAGE,
  UNPARSEABLE_LINE_MESSAGE,
  spliceRewrittenText,
} from './stdio.js';
import {
  MAX_GATEWAY_BODY,
  SseEventSplitter,
  invalidRequestResponse,
  isInvalidIdToolsCall,
  isRpcId,
  isRpcResponse,
  isToolsCallNotification,
  isToolsCallRequest,
  looksLikeToolResult,
  rewriteSseEvent,
  toolsCallParts,
} from './http-gateway.js';

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
  /**
   * Additive: present ONLY for `http --policy`. Switches the proxy into
   * gateway mode (see the module header); absent = byte-for-byte recorder.
   */
  gateway?: GatewayOptions;
  /**
   * Additive: the ADR 012 actor claim decoded from `--identity-jwt`, stamped
   * on the `identity` block of every event.
   */
  actor?: ActorStamp;
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
  /** Gateway mode: the decision already taken for this tools/call (no boundary yet). */
  gateway?: GatewayOutcome;
  /** Gateway mode: request-time attributes (the credential swap's ids), merged onto the event. */
  attributes?: Attributes;
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
    if (opts.actor !== undefined) stampActor(id, opts.actor);
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
      // Capped here (P0): these are copied verbatim off the wire and reused
      // on every later event, so an oversized/malformed value is capped
      // once, at the point it's learned — every downstream use (this event's
      // own client_name/server_name below, plus identity/server context on
      // every later event) inherits the capped value for free.
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
      if (typeof protoVersion === 'string') {
        ev.protocol_version = structuralString(protoVersion, 'protocol_version');
      }
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
      // Gateway mode: the request-time decision and the boundary report the
      // response filter attached to the entry. Same merge as the stdio
      // gateway's handleResponse.
      if (entry.gateway !== undefined) {
        attributes['cresec.policy.decision'] = entry.gateway.decision;
        if (entry.gateway.rule_id !== undefined) attributes['cresec.policy.rule_id'] = entry.gateway.rule_id;
      }
      if (entry.attributes !== undefined) Object.assign(attributes, entry.attributes);
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
      if (entry.gateway !== undefined) ev.gateway = { ...entry.gateway };
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
      // The method/tool name is capped HERE (P0), once, at capture time:
      // every downstream event built from this entry (the eventual response
      // event AND the synthetic 'unanswered' event sealed at close(), see
      // emitUnanswered below) reads `entry.method`/`entry.toolName`, so
      // capping the source field once covers both for free.
      const id = idRaw as string | number;
      const key = idKeyOf(id);
      const params = msg.params;
      const entry: PendingEntry = {
        method: structuralString(msg.method as string, 'identifier'),
        params,
        t0: performance.now(),
        id,
        allKey: scope.exchangeId + '|' + key,
      };
      if (isPlainObject(params) && typeof params.name === 'string') {
        entry.toolName = structuralString(params.name, 'identifier');
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
      const method = structuralString(msg.method as string, 'identifier');
      const ev: NotificationEvent = {
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

  /* ------------------------------ gateway ---------------------------------- */

  const gateway = opts.gateway;
  const swap = gateway?.credentials;
  /** Set by close(): nothing new may be held or forwarded. */
  let sessionClosing = false;
  /** Gateway mode: resolve every parked hold as `session_end`; a no-op otherwise. */
  let resolveAllHolds = (): void => undefined;

  /** A parsed `tools/call` request the gateway evaluated (the stdio gateway's GatewayCall). */
  interface GatewayCall {
    id: string | number;
    params: Record<string, unknown>;
    rawTool: string;
    tool: string;
    args: unknown;
    argsHash: string;
    rawRuleId?: string;
    ruleId?: string;
    reason?: string;
    swapAttributes?: Attributes;
    decisionId?: string;
    failClosed?: true;
    /** The engine's stable code for a fail-closed refusal; see the stdio leg. */
    errorCode?: PolicyErrorCode;
  }
  interface HoldResolution {
    outcome: HoldOutcome;
    approvalId?: string;
    waitedMs: number;
    approver?: string;
  }
  /** A parked exchange: the response object the refusal or the forward eventually goes to. */
  interface HoldEntry extends GatewayCall {
    approvalId: string;
    key: string;
    t0: number;
    abort: AbortController;
    settled: boolean;
    forward: () => void;
    refuse: (call: GatewayCall, hold: HoldResolution) => void;
  }

  const NULL_RESULT_HASH = sha256Ref(canonicalJson(null));
  const RULE_ID_SHAPE = /^(?:[A-Za-z0-9_.:/-]{1,64}|rule\[[0-9]+\])$/;
  const cappedRuleId = (id: string): string => (RULE_ID_SHAPE.test(id) ? id : structuralString(id, 'identifier'));

  /** One JSON body, written whole: content-length set, nothing else about the response touched. */
  const respondJson = (res: ServerResponse, status: number, payload: unknown): void => {
    const body = Buffer.from(JSON.stringify(payload), 'utf8');
    try {
      res.writeHead(status, { 'content-type': 'application/json', 'content-length': body.length });
      res.end(body);
    } catch {
      /* client already gone */
    }
  };

  /**
   * Everything below exists only in gateway mode; `gw` is undefined otherwise
   * and `handleRequest` never reaches it.
   */
  const gw =
    gateway === undefined
      ? undefined
      : (() => {
          const loaded = gateway.policy;
          const mcp = loaded.policy.mcp;
          if (mcp === undefined) throw new Error('mcp-recorder: http gateway needs a policy with an `mcp` section');
          const holdStore = gateway.holdStore;
          const boundaryDeps: BoundaryDeps = {
            secretPatterns: boundarySecretPatterns(),
            hashString: (v: string) => redactor.hashString(v),
          };
          const holds = new Map<string, HoldEntry>();
          const swapping = new Set<string>();

          const guarded = (fn: () => void): void => {
            try {
              fn();
            } catch (err) {
              tapError(err); // recording is fail-open even inside gateway mode
            }
          };

          /* ---- evaluation ---- */

          const evaluationFailed = (err: unknown): McpDecision => ({
            action: 'deny',
            matched: false,
            reason: `policy evaluation error: ${err instanceof Error ? err.message : String(err)}`,
            failClosed: true,
            errorCode: err instanceof PolicyEvalError ? err.code : 'policy-unevaluable',
          });

          const evaluate = (rawTool: string, args: unknown): { decision: McpDecision; argsHash: string } => {
            let canonical: string;
            let argsHash: string;
            try {
              canonical = canonicalJson(args);
              argsHash = sha256Ref(canonical);
            } catch (err) {
              return { decision: evaluationFailed(err), argsHash: NULL_RESULT_HASH };
            }
            if (rawTool.length > 128) {
              // Fail closed WITHOUT consulting the policy: the glob engine is a
              // backtracking regex, so an uncapped name is a denial of service.
              return {
                decision: {
                  action: 'deny',
                  matched: false,
                  reason: `tools/call params.name is ${rawTool.length} characters; the gateway evaluates at most 128 (the name is refused, never truncated)`,
                  failClosed: true,
                },
                argsHash,
              };
            }
            try {
              return {
                decision: evaluateMcp(loaded.policy, {
                  server: currentServer().name,
                  tool: rawTool,
                  args,
                  argsBytes: Buffer.byteLength(canonical),
                }),
                argsHash,
              };
            } catch (err) {
              return { decision: evaluationFailed(err), argsHash };
            }
          };

          const buildCall = (msg: Record<string, unknown> & { id: string | number }): { call: GatewayCall; action: McpDecision['action'] } => {
            const { params, name } = toolsCallParts(msg);
            const args: unknown = params['arguments'] ?? {};
            const { decision, argsHash } = evaluate(name, args);
            const tool = name === '' ? '' : structuralString(name, 'identifier');
            const call: GatewayCall = { id: msg.id, params, rawTool: name.length > 128 ? tool : name, tool, args, argsHash };
            if (decision.ruleId !== undefined) {
              call.rawRuleId = decision.ruleId;
              call.ruleId = cappedRuleId(decision.ruleId);
            }
            if (decision.reason !== undefined) call.reason = decision.reason;
            if (decision.failClosed === true) call.failClosed = true;
            if (decision.errorCode !== undefined) call.errorCode = decision.errorCode;
            return { call, action: decision.action };
          };

          /* ---- events ---- */

          const policyAttributes = (call: GatewayCall, decision: 'deny' | 'hold'): Attributes => {
            const attributes: Attributes = {
              'gen_ai.tool.name': call.tool,
              'gen_ai.tool.call.id': String(call.id),
              'mcp.method.name': 'tools/call',
              'rpc.system': 'jsonrpc',
              'cresec.policy.decision': decision,
            };
            if (call.ruleId !== undefined) attributes['cresec.policy.rule_id'] = call.ruleId;
            if (call.swapAttributes !== undefined) Object.assign(attributes, call.swapAttributes);
            if (call.decisionId !== undefined) attributes['cresec.policy.decision_id'] = call.decisionId;
            return attributes;
          };

          const recordPolicyDecision = (call: GatewayCall, hold?: HoldResolution): void => {
            const decision = hold === undefined ? 'deny' : 'hold';
            if (call.decisionId === undefined) call.decisionId = randomUUID();
            const ev: PolicyDecisionEvent = {
              ...base('policy_decision', policyAttributes(call, decision)),
              kind: 'policy_decision',
              decision,
              tool: call.tool,
              request_id: call.id,
              policy_hash: loaded.hash,
              args_hash: call.argsHash,
              decision_id: call.decisionId,
            };
            if (call.ruleId !== undefined) ev.rule_id = call.ruleId;
            if (call.errorCode !== undefined) ev.error_code = call.errorCode;
            if (hold !== undefined) {
              ev.outcome = hold.outcome;
              if (hold.approvalId !== undefined) ev.approval_id = hold.approvalId;
              ev.waited_ms = hold.waitedMs;
              if (hold.approver !== undefined) ev.approver = hold.approver;
            }
            record(ev);
          };

          const gatewayOutcomeFor = (call: GatewayCall, hold?: HoldResolution): GatewayOutcome => {
            const out: GatewayOutcome = { decision: hold === undefined ? 'allow' : 'hold' };
            if (call.ruleId !== undefined) out.rule_id = call.ruleId;
            if (hold !== undefined) {
              out.outcome = hold.outcome;
              if (hold.approvalId !== undefined) out.approval_id = hold.approvalId;
              out.waited_ms = hold.waitedMs;
            }
            return out;
          };

          const recordSyntheticToolCall = (call: GatewayCall, result: unknown, hold?: HoldResolution, errorType = 'policy_denied', refusal?: string): void => {
            const gatewayOutcome = gatewayOutcomeFor(call, hold);
            if (hold === undefined) gatewayOutcome.decision = 'deny';
            if (refusal !== undefined) gatewayOutcome.refusal = refusal;
            const attributes: Attributes = {
              'gen_ai.operation.name': 'execute_tool',
              ...policyAttributes(call, gatewayOutcome.decision === 'deny' ? 'deny' : 'hold'),
              'error.type': errorType,
            };
            const ev: ToolCallEvent = {
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

          /** The deny result for one call: events first (policy_decision, then the synthetic tool_call), then the response. */
          const synthesizeDeny = (call: GatewayCall, hold?: HoldResolution): Record<string, unknown> => {
            const input: DeniedTextInput = { tool: call.rawTool };
            if (call.rawRuleId !== undefined) input.ruleId = call.rawRuleId;
            if (call.reason !== undefined) input.reason = call.reason;
            if (call.failClosed === true) input.failClosed = true;
            if (call.errorCode !== undefined) input.errorCode = call.errorCode;
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

          const denyCall = (res: ServerResponse, call: GatewayCall, hold?: HoldResolution, diagLine?: string): void => {
            const response = synthesizeDeny(call, hold);
            respondJson(res, 200, response);
            if (diagLine !== undefined) diag(diagLine);
            else if (hold === undefined) diag(`gateway: denied tools/call "${call.tool}" (rule ${call.ruleId ?? call.errorCode ?? 'default'})`);
          };

          /** Register a forwarded tools/call so its response becomes the tool_call event. */
          const registerCall = (scope: ExchangeScope, call: GatewayCall, gatewayOutcome: GatewayOutcome, attributes?: Attributes): void => {
            const key = idKeyOf(call.id);
            const entry: PendingEntry = {
              method: 'tools/call',
              // PRE-swap params: the event's `args` are scrubbed from these,
              // so the chain records the synthetic, never the brokered value.
              params: call.params,
              t0: performance.now(),
              toolName: call.tool,
              id: call.id,
              allKey: scope.exchangeId + '|' + key,
              gateway: gatewayOutcome,
            };
            if (attributes !== undefined) entry.attributes = attributes;
            scope.local.set(key, entry);
            entry.sessionFallbackKey = scope.sessionKey + 'c2s' + key;
            evictOldest(sessionPending);
            sessionPending.set(entry.sessionFallbackKey, entry);
            evictOldest(allPending);
            allPending.set(entry.allKey, entry);
          };

          /* ---- the swap ---- */

          const planSwap = (tool: string, args: unknown): PlannedSwap[] => {
            if (swap === undefined || !swap.hasSites) return [];
            try {
              return swap.plan({ server: currentServer().name, tool, args });
            } catch (err) {
              tapError(err);
              return [unplannableSwap(SWAP_DENY.unavailable)];
            }
          };

          const clientUserAgent = (): string | undefined => {
            if (clientName === undefined) return undefined;
            return clientVersion === undefined ? clientName : `${clientName}/${clientVersion}`;
          };

          /**
           * Exchange the planned synthetics, then either forward the rewritten
           * message or refuse. `forward(message)` receives the message to put
           * on the wire — the original object when nothing was swapped.
           */
          const withSwap = (
            res: ServerResponse,
            call: GatewayCall,
            msg: Record<string, unknown> & { id: string | number },
            plan: PlannedSwap[],
            forward: (message: unknown, attributes?: Attributes) => void,
            hold?: HoldResolution,
          ): void => {
            if (plan.length === 0 || swap === undefined) {
              forward(msg);
              return;
            }
            if (swapping.size >= MAX_INFLIGHT_SWAPS) {
              denyCall(
                res,
                { ...call, reason: swapDenyReason(SWAP_DENY.tooMany), failClosed: true },
                undefined,
                `gateway: ${MAX_INFLIGHT_SWAPS} credential swaps already in flight; denying tools/call "${call.tool}"`,
              );
              return;
            }
            const key = randomUUID();
            swapping.add(key);
            const ctx: Parameters<typeof swap.exchange>[2] = { server: currentServer().name, tool: call.rawTool };
            const ua = clientUserAgent();
            if (ua !== undefined) ctx.userAgent = ua;
            const settle = (outcome: SwapOutcome): void => {
              const refuse = (code: string, failClosed: boolean): void => {
                const decided = [...outcome.decisions].reverse().find((d) => d.decisionId !== '');
                denyCall(
                  res,
                  {
                    ...call,
                    reason: swapDenyReason(code),
                    swapAttributes: outcome.attributes,
                    ...(decided !== undefined ? { decisionId: decided.decisionId } : {}),
                    ...(failClosed ? { failClosed: true as const } : {}),
                  },
                  hold,
                  `gateway: credential swap refused tools/call "${call.tool}" (${code})`,
                );
              };
              if (outcome.kind === 'deny') {
                refuse(outcome.code, outcome.failClosed);
                return;
              }
              if (outcome.message === msg) {
                // An allow that changed nothing would forward the SYNTHETIC.
                refuse(SWAP_DENY.noToken, true);
                return;
              }
              if (sessionClosing) {
                refuse(SWAP_DENY.sessionEnd, true);
                return;
              }
              for (const d of outcome.decisions) {
                diag(
                  `gateway: swapped credential "${structuralString(d.credential, 'identifier')}" into tools/call` +
                    ` "${call.tool}" for ${structuralString(d.host, 'identifier')}` +
                    `${d.hostSource === 'server_name' ? ' (host is the server name, not a checked destination)' : ''}` +
                    ` (decision ${structuralString(d.decisionId, 'identifier')}, ttl ${d.ttlSeconds}s)`,
                );
              }
              forward(outcome.message, outcome.attributes);
            };
            swap.exchange(msg, plan, ctx).then(
              (outcome) => {
                swapping.delete(key);
                settle(outcome);
              },
              (err: unknown) => {
                swapping.delete(key);
                tapError(err);
                denyCall(res, { ...call, reason: swapDenyReason(SWAP_DENY.unavailable), failClosed: true }, hold);
              },
            );
          };

          /* ---- holds ---- */

          const settleHold = (entry: HoldEntry, status: HoldWaitResult['status'] | 'session_end', decided?: HoldRecord): void => {
            if (entry.settled) return;
            entry.settled = true;
            if (holds.get(entry.key) === entry) holds.delete(entry.key);
            entry.abort.abort();
            const resolution: HoldResolution = {
              outcome: status,
              approvalId: entry.approvalId,
              waitedMs: round2(performance.now() - entry.t0),
            };
            const decidedBy: unknown = decided?.decided_by;
            if (typeof decidedBy === 'string') resolution.approver = structuralString(decidedBy, 'identifier');
            if (status === 'timeout' || status === 'cancelled' || status === 'session_end') {
              holdStore.finalize(entry.approvalId, status);
            }
            const forward = status === 'approved' || (status === 'timeout' && mcp.hold.on_timeout === 'allow');
            if (forward && !sessionClosing) {
              guarded(() => recordPolicyDecision(entry, resolution));
              diag(`gateway: hold ${entry.approvalId} ${status}; forwarding tools/call "${entry.tool}" after ${resolution.waitedMs} ms`);
              entry.forward();
              return;
            }
            if (forward) resolution.outcome = 'session_end';
            const failedClosed = resolution.outcome === 'session_end';
            entry.refuse(failedClosed ? { ...entry, failClosed: true } : entry, resolution);
            diag(`gateway: hold ${entry.approvalId} ${resolution.outcome} after ${resolution.waitedMs} ms; tools/call "${entry.tool}" not forwarded`);
          };

          const startHold = (
            res: ServerResponse,
            scope: ExchangeScope,
            call: GatewayCall,
            forward: (hold: HoldResolution) => void,
          ): void => {
            if (holds.size >= MAX_HOLDS) {
              denyCall(
                res,
                { ...call, reason: 'too many pending holds', failClosed: true },
                undefined,
                `gateway: ${MAX_HOLDS} holds already pending; denying tools/call "${call.tool}" (rule ${call.ruleId ?? 'default'})`,
              );
              return;
            }
            const timeoutMs = mcp.hold.timeout_ms;
            let created: HoldRecord;
            try {
              const input: Parameters<typeof holdStore.create>[0] = {
                session_id: sessionId,
                server: currentServer().name,
                tool: call.tool,
                args: scrubToolArguments(redactor, call.args),
                args_hash: call.argsHash,
                timeout_at: new Date(Date.now() + timeoutMs).toISOString(),
              };
              if (call.rawRuleId !== undefined) input.rule_id = call.rawRuleId;
              if (call.reason !== undefined) input.reason = call.reason;
              created = holdStore.create(input);
            } catch (err) {
              const message = err instanceof Error ? err.message : String(err);
              diag(`gateway: cannot write hold for tools/call "${call.tool}" (${message}); denying`);
              denyCall(res, { ...call, reason: 'hold unavailable', failClosed: true });
              return;
            }
            const key = scope.sessionKey + '|' + idKeyOf(call.id);
            const entry: HoldEntry = {
              ...call,
              approvalId: created.approval_id,
              key,
              t0: performance.now(),
              abort: new AbortController(),
              settled: false,
              // Replaced with the real resolution when the decision arrives
              // (below), before settleHold is asked to forward.
              forward: () => undefined,
              refuse: (refused, hold) => denyCall(res, refused, hold, `gateway: hold ${created.approval_id} ${hold.outcome}; tools/call "${call.tool}" refused`),
            };
            holds.set(key, entry);
            diag(
              `gateway: holding tools/call "${call.tool}" (rule ${call.ruleId ?? 'default'}) as ${created.approval_id}` +
                ` — mcp-recorder approve|deny ${created.approval_id}`,
            );
            // The client going away is a cancellation: nobody is waiting for
            // the answer any more, and the hold file says so.
            res.on('close', () => {
              if (!entry.settled && !res.writableEnded) settleHold(entry, 'cancelled');
            });
            const waitOpts: Parameters<typeof holdStore.waitForDecision>[1] = { timeoutMs, signal: entry.abort.signal };
            if (gateway.pollMs !== undefined) waitOpts.pollMs = gateway.pollMs;
            holdStore.waitForDecision(created.approval_id, waitOpts).then(
              (result) => {
                if (entry.settled) return;
                const status = result.status;
                if (status === 'approved' || (status === 'timeout' && mcp.hold.on_timeout === 'allow')) {
                  const resolution: HoldResolution = {
                    outcome: status,
                    approvalId: created.approval_id,
                    waitedMs: round2(performance.now() - entry.t0),
                  };
                  const decidedBy: unknown = result.record?.decided_by;
                  if (typeof decidedBy === 'string') resolution.approver = structuralString(decidedBy, 'identifier');
                  entry.forward = () => forward(resolution);
                }
                settleHold(entry, status, result.record);
              },
              (err: unknown) => {
                tapError(err);
                if (!entry.settled) {
                  entry.failClosed = true;
                  settleHold(entry, 'denied');
                }
              },
            );
          };

          const cancelHold = (scope: ExchangeScope, msg: Record<string, unknown>): void => {
            const params = isPlainObject(msg['params']) ? msg['params'] : {};
            const requestId = params['requestId'];
            if (!isRpcId(requestId)) return;
            const entry = holds.get(scope.sessionKey + '|' + idKeyOf(requestId));
            if (entry !== undefined) settleHold(entry, 'cancelled');
          };

          resolveAllHolds = (): void => {
            for (const entry of [...holds.values()]) settleHold(entry, 'session_end');
          };

          /* ---- server -> client: the boundary filter ---- */

          /** Look up the pending entry a response answers, WITHOUT removing it (handleResponse does that). */
          const pendingFor = (id: string | number, scope: ExchangeScope): PendingEntry | undefined => {
            const key = idKeyOf(id);
            return scope.local.get(key) ?? sessionPending.get(scope.sessionKey + 'c2s' + key);
          };

          /**
           * Filter ONE parsed server->client message: the brokered-token scrub
           * first (so nothing below sees the real value), then the boundary
           * filter over a tools/call result. Returns the message the client
           * gets and the message the chain sees (scrubbed, boundary NOT
           * applied: `result`/`result_hash` describe the raw server result).
           */
          const filterServerMessage = (
            msg: unknown,
            rawBytes: number,
            scope: ExchangeScope,
          ): { delivered: unknown; recorded: unknown; changed: boolean } => {
            let recorded = msg;
            let changed = false;
            if (swap !== undefined) {
              try {
                const text = JSON.stringify(msg);
                if (typeof text === 'string' && swap.scrubber.mightContain(text)) {
                  const scrubbed = swap.scrubber.scrubMessage(msg);
                  if (scrubbed.changed) {
                    recorded = scrubbed.message;
                    changed = true;
                    diag('gateway: a brokered credential came back in a server message; replaced with its placeholder');
                  }
                }
              } catch (err) {
                tapError(err);
              }
            }
            if (!isPlainObject(recorded) || !isRpcResponse(recorded)) return { delivered: recorded, recorded, changed };
            const entry = pendingFor(recorded.id, scope);
            const isToolResult = entry !== undefined ? entry.method === 'tools/call' : looksLikeToolResult(recorded);
            if (!isToolResult) return { delivered: recorded, recorded, changed };
            const outcome = applyBoundary(recorded, mcp.boundary, boundaryDeps, { rawBytes });
            const report: BoundaryReport = { ...outcome.report };
            if (outcome.changed) {
              try {
                const delivered = isPlainObject(outcome.message) ? outcome.message['result'] : null;
                report.delivered_result_hash = sha256Ref(canonicalJson(delivered ?? null));
              } catch (err) {
                tapError(err);
              }
              diag(
                `gateway: ${report.action === 'block' ? 'blocked' : 'redacted'} tool result of tools/call` +
                  ` "${entry?.toolName ?? ''}" (${report.secrets_found} secret-shaped, ${report.injection_found} injection marker(s))`,
              );
            }
            if (entry !== undefined) {
              entry.gateway = { ...(entry.gateway ?? { decision: 'allow' }), boundary: report };
            } else {
              diag('gateway: boundary-filtered a tool result with no pending request');
            }
            return { delivered: outcome.changed ? outcome.message : recorded, recorded, changed: changed || outcome.changed };
          };

          /**
           * A whole JSON response body: filtered element by element, spliced
           * back into the original text when anything changed, then tapped.
           */
          const filterJsonBody = (text: string, scope: ExchangeScope): Buffer => {
            let msg: unknown;
            try {
              msg = JSON.parse(text);
            } catch {
              guarded(() => protocolError('server_to_client', 'unparseable', Buffer.byteLength(text), text));
              return Buffer.from(text, 'utf8');
            }
            const rawBytes = Buffer.byteLength(text);
            if (Array.isArray(msg)) {
              const delivered: unknown[] = [...msg];
              const recorded: unknown[] = [...msg];
              let changed = false;
              msg.forEach((el, i) => {
                const f = filterServerMessage(el, rawBytes, scope);
                delivered[i] = f.delivered;
                recorded[i] = f.recorded;
                if (f.changed) changed = true;
              });
              guarded(() => handleMessage(recorded, 'server_to_client', text, scope));
              return Buffer.from(changed ? (spliceRewrittenText(text, msg, delivered) ?? JSON.stringify(delivered)) : text, 'utf8');
            }
            const f = filterServerMessage(msg, rawBytes, scope);
            guarded(() => handleMessage(f.recorded, 'server_to_client', text, scope));
            return Buffer.from(f.changed ? (spliceRewrittenText(text, msg, f.delivered) ?? JSON.stringify(f.delivered)) : text, 'utf8');
          };

          /** One complete SSE event: its `data:` payload filtered when it is a JSON-RPC message. */
          const filterSseEvent = (raw: Buffer, data: string | undefined, scope: ExchangeScope): Buffer => {
            if (data === undefined) return raw;
            let msg: unknown;
            try {
              msg = JSON.parse(data);
            } catch {
              return raw; // non-JSON SSE data (pings etc.) — forwarded as is
            }
            const f = filterServerMessage(msg, raw.length, scope);
            guarded(() => handleMessage(f.recorded, 'server_to_client', data, scope));
            if (!f.changed) return raw;
            return rewriteSseEvent(raw, spliceRewrittenText(data, msg, f.delivered) ?? JSON.stringify(f.delivered));
          };

          /**
           * What goes out in place of an SSE event whose filtering THREW.
           * A JSON-RPC response (or a batch of them) becomes a blocked
           * tool result for each id, so the client is answered and the
           * secret-shaped bytes are not; any other JSON is dropped (an
           * empty buffer) with a `protocol_error` on the chain; a `data:`
           * payload that is not JSON was never scanned and is re-emitted
           * from its original bytes. Never throws.
           */
          const failClosedSseEvent = (raw: Buffer, data: string | undefined): Buffer => {
            if (data === undefined) return raw;
            let msg: unknown;
            try {
              msg = JSON.parse(data);
            } catch {
              return raw;
            }
            const responses = (Array.isArray(msg) ? msg : [msg]).filter((m): m is Record<string, unknown> & { id: string | number } => isRpcResponse(m));
            const blocked = responses.map((m) =>
              synthesizeDeniedResult(
                m.id,
                'mcp-recorder gateway: the boundary filter failed on this tool result, so the gateway withheld it rather than deliver it unscanned\n' +
                  FAIL_CLOSED_REFUSAL_GUIDANCE,
              ),
            );
            guarded(() => protocolError('server_to_client', 'unparseable', raw.length, raw.toString('utf8')));
            diag(`gateway: boundary filter failed on an SSE event; ${blocked.length > 0 ? `answered ${String(blocked.length)} response(s) with a blocked result` : 'dropped the event'} (fail closed)`);
            if (blocked.length === 0) return Buffer.alloc(0);
            try {
              return rewriteSseEvent(raw, JSON.stringify(Array.isArray(msg) ? blocked : blocked[0]));
            } catch (err) {
              tapError(err);
              return Buffer.alloc(0); // still nothing unscanned crosses
            }
          };

          return {
            mcp,
            buildCall,
            denyCall,
            registerCall,
            planSwap,
            withSwap,
            startHold,
            cancelHold,
            recordPolicyDecision,
            recordSyntheticToolCall,
            gatewayOutcomeFor,
            filterJsonBody,
            filterSseEvent,
            failClosedSseEvent,
            scrubBytes: (bytes: Buffer): Buffer => (swap === undefined ? bytes : swap.scrubber.scrubBytes(bytes)),
          };
        })();

  /* ------------------------------ the exchange ----------------------------- */

  interface ForwardOpts {
    /** A buffered request body to send instead of piping `req` (gateway mode). */
    body?: Buffer;
    /** Gateway mode: this exchange carried a tools/call (or may carry results): filter the response. */
    filterResponse?: boolean;
  }

  const abortable = (req: IncomingMessage, res: ServerResponse, upReq: ReturnType<typeof requester>): void => {
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
  };

  /** Forward one exchange to the upstream and relay its response. */
  const forwardExchange = (
    req: IncomingMessage,
    res: ServerResponse,
    upstreamUrl: URL,
    scope: ExchangeScope,
    fwd: ForwardOpts = {},
  ): void => {
    const headers = forwardHeaders(req.headers, 'host');
    if (gw !== undefined) {
      // A compressed response cannot be scanned; the upstream is told not to.
      delete headers['accept-encoding'];
      delete headers['Accept-Encoding'];
      headers['accept-encoding'] = 'identity';
    }
    if (fwd.body !== undefined) {
      // The body is sent whole: its length is known and any chunked framing
      // the client used no longer applies.
      delete headers['content-length'];
      delete headers['Content-Length'];
      headers['content-length'] = fwd.body.length;
    }

    const upReq = requester(upstreamUrl, { method: req.method, headers }, (upRes) => {
      // Headers are in: any header-wait timeout no longer applies. A
      // streaming (or merely slow) response must never be torn down for
      // inactivity once the exchange is under way.
      upReq.setTimeout(0);
      const ct = upRes.headers['content-type'];
      const encoding = upRes.headers['content-encoding'];
      const compressed = typeof encoding === 'string' && encoding !== '' && encoding.toLowerCase() !== 'identity';
      if (gw !== undefined && compressed) {
        // Fail closed: a result the boundary filter cannot read must not
        // reach the client unread. The upstream was told `identity`.
        upRes.resume();
        diag(`gateway: upstream answered with content-encoding ${encoding}; refused (the boundary filter cannot scan a compressed result)`);
        respondJson(res, 502, invalidRequestResponse(null, 'mcp-recorder gateway: the upstream answered with a compressed body, which the gateway cannot scan; refused'));
        return;
      }

      const sseGateway = gw !== undefined && isSseContentType(ct);
      const jsonGateway = gw !== undefined && !sseGateway && isJsonContentType(ct) && fwd.filterResponse === true;

      if (jsonGateway) {
        // Buffered, filtered, then written whole with its true length.
        const chunks: Buffer[] = [];
        let len = 0;
        let over = false;
        upRes.on('data', (chunk: Buffer) => {
          if (over) return;
          len += chunk.length;
          if (len > MAX_GATEWAY_BODY) {
            // Past the cap the body cannot be parsed or filtered: it is
            // forwarded as it stands and the chain says so (`oversized`),
            // exactly as the stdio gateway treats a line past its cap.
            over = true;
            try {
              res.writeHead(upRes.statusCode ?? 502, upRes.statusMessage, forwardHeaders(upRes.headers));
              for (const c of chunks) res.write(gw.scrubBytes(c));
              res.write(gw.scrubBytes(chunk));
            } catch (err) {
              tapError(err);
            }
            chunks.length = 0;
            upRes.on('data', (c: Buffer) => res.write(gw.scrubBytes(c)));
            guarded(() => protocolError('server_to_client', 'oversized', len, ''));
            return;
          }
          chunks.push(chunk);
        });
        upRes.on('end', () => {
          try {
            if (over) {
              res.end();
              return;
            }
            const body = gw.filterJsonBody(Buffer.concat(chunks).toString('utf8'), scope);
            const outHeaders = forwardHeaders(upRes.headers);
            delete outHeaders['content-length'];
            delete outHeaders['Content-Length'];
            outHeaders['content-length'] = body.length;
            res.writeHead(upRes.statusCode ?? 502, upRes.statusMessage, outHeaders);
            res.end(body);
          } catch (err) {
            tapError(err);
            try {
              res.destroy();
            } catch {
              /* already gone */
            }
          }
        });
        upRes.on('error', () => {
          try {
            res.destroy();
          } catch {
            /* already gone */
          }
        });
        return;
      }

      try {
        res.writeHead(upRes.statusCode ?? 502, upRes.statusMessage, forwardHeaders(upRes.headers));
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

      if (sseGateway) {
        // Event by event: each is held only until the blank line that ends
        // it, filtered if it carries a tools/call result, and re-emitted
        // from its original bytes when the filter changed nothing.
        const splitter = new SseEventSplitter();
        const emit = (ev: { raw: Buffer; data?: string | undefined; oversized?: true }): void => {
          if (ev.oversized === true) {
            res.write(gw.scrubBytes(ev.raw));
            guarded(() => protocolError('server_to_client', 'oversized', ev.raw.length, ''));
            return;
          }
          let out: Buffer;
          try {
            out = gw.filterSseEvent(ev.raw, ev.data, scope);
          } catch (err) {
            // Enforcement fails CLOSED here as it does on the JSON path: a
            // tools/call result the filter blew up on must not reach the
            // client unscanned. What replaces it depends on what the event
            // carried — a JSON-RPC response gets a blocked result the model
            // can read (so the client is not left waiting on the id), any
            // other JSON payload is dropped and the chain says so, and an
            // event that is not JSON at all (a ping, a comment) was never
            // the filter's to touch and crosses as written.
            tapError(err);
            out = gw.failClosedSseEvent(ev.raw, ev.data);
          }
          res.write(gw.scrubBytes(out));
        };
        upRes.on('data', (chunk: Buffer) => {
          try {
            for (const ev of splitter.push(chunk)) emit(ev);
          } catch (err) {
            tapError(err);
          }
        });
        upRes.on('end', () => {
          try {
            const tail = splitter.end();
            if (tail !== undefined) emit(tail);
          } catch (err) {
            tapError(err);
          }
          try {
            res.end();
          } catch {
            /* client already gone */
          }
        });
        upRes.on('error', () => {
          try {
            res.destroy();
          } catch {
            /* already gone */
          }
        });
        return;
      }

      // Per-response tap state, chosen by content-type.
      const sse = isSseContentType(ct) ? new SseScanner() : null;
      const tapJson = sse === null && isJsonContentType(ct);
      const jsonChunks: Buffer[] = [];
      let jsonLen = 0;
      let jsonOver = false;

      upRes.on('data', (chunk: Buffer) => {
        // Forward first — the tap must never delay or reorder bytes.
        res.write(gw === undefined ? chunk : gw.scrubBytes(chunk));
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
    });

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
    abortable(req, res, upReq);

    if (fwd.body !== undefined) {
      upReq.end(fwd.body);
      return;
    }

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

  /* ----------------------- gateway: the request side ----------------------- */

  /** Read a whole request body, bounded. Resolves `undefined` when it grew past the cap. */
  const readBody = (req: IncomingMessage, cap: number): Promise<Buffer | undefined> =>
    new Promise((resolveBody, rejectBody) => {
      const chunks: Buffer[] = [];
      let len = 0;
      let over = false;
      req.on('data', (chunk: Buffer) => {
        if (over) return;
        len += chunk.length;
        if (len > cap) {
          over = true;
          chunks.length = 0;
          return;
        }
        chunks.push(chunk);
      });
      req.on('end', () => resolveBody(over ? undefined : Buffer.concat(chunks)));
      req.on('error', rejectBody);
    });

  /**
   * One tools/call over HTTP: evaluate, then forward (with the swap when a
   * declared site is engaged), deny, or hold. `text` is the body as the
   * client wrote it; a rewritten body is spliced so untouched bytes cross
   * as written.
   */
  const gatewayToolsCall = (
    g: NonNullable<typeof gw>,
    req: IncomingMessage,
    res: ServerResponse,
    upstreamUrl: URL,
    scope: ExchangeScope,
    text: string,
    msg: Record<string, unknown> & { id: string | number },
  ): void => {
    const { call, action } = g.buildCall(msg);
    const forward = (hold?: HoldResolutionLike): void => {
      const plan = g.planSwap(call.rawTool, call.args);
      g.withSwap(
        res,
        call,
        msg,
        plan,
        (message, attributes) => {
          const body =
            message === msg ? Buffer.from(text, 'utf8') : Buffer.from(spliceRewrittenText(text, msg, message) ?? JSON.stringify(message), 'utf8');
          try {
            g.registerCall(scope, call, g.gatewayOutcomeFor(call, hold), attributes);
          } catch (err) {
            tapError(err);
          }
          forwardExchange(req, res, upstreamUrl, scope, { body, filterResponse: true });
        },
        hold,
      );
    };
    if (action === 'allow') {
      forward();
      return;
    }
    if (action === 'deny') {
      g.denyCall(res, call);
      return;
    }
    if (sessionClosing) {
      g.denyCall(
        res,
        { ...call, reason: 'session_end (hold not started)', failClosed: true },
        { outcome: 'session_end', waitedMs: 0 },
        `gateway: session ending; tools/call "${call.tool}" refused instead of held (rule ${call.ruleId ?? 'default'})`,
      );
      return;
    }
    g.startHold(res, scope, call, (hold) => forward(hold));
  };
  type HoldResolutionLike = { outcome: HoldOutcome; approvalId?: string; waitedMs: number; approver?: string };

  /**
   * A JSON-RPC batch: all or nothing (module header). Every element is
   * evaluated; when each tools/call is allowed and needs no credential the
   * batch crosses as written, otherwise it is answered here.
   */
  const gatewayBatch = (
    g: NonNullable<typeof gw>,
    req: IncomingMessage,
    res: ServerResponse,
    upstreamUrl: URL,
    scope: ExchangeScope,
    text: string,
    batch: unknown[],
  ): void => {
    const calls = new Map<number, ReturnType<typeof g.buildCall>>();
    let clean = true;
    batch.forEach((el, i) => {
      if (Array.isArray(el)) {
        clean = false;
        return;
      }
      if (isInvalidIdToolsCall(el) || isToolsCallNotification(el)) {
        clean = false;
        return;
      }
      if (!isToolsCallRequest(el)) return;
      const built = g.buildCall(el);
      calls.set(i, built);
      if (built.action !== 'allow' || g.planSwap(built.call.rawTool, built.call.args).length > 0) clean = false;
    });
    if (clean) {
      for (const [, built] of calls) {
        try {
          g.registerCall(scope, built.call, g.gatewayOutcomeFor(built.call));
        } catch (err) {
          tapError(err);
        }
      }
      // The other elements register through the ordinary tap.
      guarded(() => {
        batch.forEach((el, i) => {
          if (!calls.has(i)) handleMessage(el, 'client_to_server', text, scope);
        });
      });
      forwardExchange(req, res, upstreamUrl, scope, { body: Buffer.from(text, 'utf8'), filterResponse: true });
      return;
    }
    const responses: unknown[] = [];
    batch.forEach((el, i) => {
      if (Array.isArray(el)) {
        responses.push(invalidRequestResponse(null, NESTED_BATCH_MESSAGE));
        return;
      }
      if (isInvalidIdToolsCall(el)) {
        responses.push(invalidRequestResponse(null, el['id'] === null ? NULL_ID_TOOLS_CALL_MESSAGE : INVALID_ID_TOOLS_CALL_MESSAGE));
        return;
      }
      const built = calls.get(i);
      if (built !== undefined) {
        const { call, action } = built;
        let refused: GatewayCallLike;
        let refusal: string | undefined;
        if (action === 'deny') refused = call;
        else if (action === 'hold') {
          refused = { ...call, reason: 'hold is not available inside a JSON-RPC batch; send the call on its own', failClosed: true };
        } else {
          refused = { ...call, reason: 'batched with a call the policy refused; send it on its own', failClosed: true };
          refusal = 'batch_refused';
        }
        const input: DeniedTextInput = { tool: refused.rawTool };
        if (refused.rawRuleId !== undefined) input.ruleId = refused.rawRuleId;
        if (refused.reason !== undefined) input.reason = refused.reason;
        if (refused.failClosed === true) input.failClosed = true;
        const response = synthesizeDeniedResult(refused.id, deniedText(input));
        guarded(() => {
          g.recordPolicyDecision(refused);
          g.recordSyntheticToolCall(refused, response.result, undefined, refusal ?? 'policy_denied', refusal);
        });
        responses.push(response);
        return;
      }
      if (isPlainObject(el) && isRpcId(el['id'])) {
        responses.push(
          invalidRequestResponse(el['id'], 'mcp-recorder gateway: this request was batched with a tools/call the policy refused and was not forwarded; send it on its own'),
        );
      }
      // A notification in a refused batch gets no response, like any notification.
    });
    diag(`gateway: refused a JSON-RPC batch of ${batch.length} (a tools/call in it was denied, held or needed a credential)`);
    respondJson(res, 200, responses);
  };
  type GatewayCallLike = ReturnType<NonNullable<typeof gw>['buildCall']>['call'];

  /** Gateway mode: a POST with a JSON body. Buffered, parsed, gated. */
  const gatewayPost = async (
    g: NonNullable<typeof gw>,
    req: IncomingMessage,
    res: ServerResponse,
    upstreamUrl: URL,
    scope: ExchangeScope,
  ): Promise<void> => {
    let body: Buffer | undefined;
    try {
      body = await readBody(req, MAX_GATEWAY_BODY);
    } catch {
      return; // the client went away mid-body; nothing to answer
    }
    if (body === undefined) {
      diag('gateway: refused a request body larger than the gateway can buffer');
      respondJson(res, 413, invalidRequestResponse(null, OVERSIZED_LINE_MESSAGE));
      return;
    }
    const text = body.toString('utf8');
    let msg: unknown;
    try {
      msg = JSON.parse(text);
    } catch {
      guarded(() => protocolError('client_to_server', 'unparseable', body.length, text));
      diag('gateway: refused a request body that is not JSON');
      respondJson(res, 400, invalidRequestResponse(null, UNPARSEABLE_LINE_MESSAGE));
      return;
    }
    if (Array.isArray(msg)) {
      gatewayBatch(g, req, res, upstreamUrl, scope, text, msg);
      return;
    }
    if (isToolsCallRequest(msg)) {
      gatewayToolsCall(g, req, res, upstreamUrl, scope, text, msg);
      return;
    }
    if (isInvalidIdToolsCall(msg)) {
      // Refused whatever the policy says (a response could not be
      // correlated); recorded on a notification event, like the stdio gateway.
      const { params, name } = toolsCallParts(msg);
      const tool = name === '' ? '' : structuralString(name, 'identifier');
      guarded(() => {
        const ev: NotificationEvent = {
          ...base('notification', { 'mcp.method.name': 'tools/call', 'rpc.system': 'jsonrpc', 'gen_ai.tool.name': tool, 'cresec.policy.decision': 'deny' }),
          kind: 'notification',
          method: 'tools/call',
          direction: 'client_to_server',
          params: redactor.scrub(params),
          gateway: { decision: 'deny', refusal: 'invalid_request_id' },
        };
        record(ev);
      });
      diag(`gateway: refused tools/call "${tool}" with an unusable id`);
      respondJson(res, 400, invalidRequestResponse(null, msg['id'] === null ? NULL_ID_TOOLS_CALL_MESSAGE : INVALID_ID_TOOLS_CALL_MESSAGE));
      return;
    }
    if (isToolsCallNotification(msg)) {
      // Evaluated like a request; a refusal has no response to carry it
      // (202, per the streamable-HTTP transport) so it rides the
      // notification event's `gateway` field.
      const { params, name } = toolsCallParts(msg);
      const args: unknown = params['arguments'] ?? {};
      const { call, action } = g.buildCall({ ...msg, id: '' });
      const tool = name === '' ? '' : structuralString(name, 'identifier');
      if (action === 'allow' && g.planSwap(call.rawTool, args).length === 0) {
        guarded(() => handleMessage(msg, 'client_to_server', text, scope));
        forwardExchange(req, res, upstreamUrl, scope, { body, filterResponse: true });
        return;
      }
      const outcome: GatewayOutcome = { decision: 'deny' };
      if (call.ruleId !== undefined) outcome.rule_id = call.ruleId;
      guarded(() => {
        const attributes: Attributes = { 'mcp.method.name': 'tools/call', 'rpc.system': 'jsonrpc', 'gen_ai.tool.name': tool, 'cresec.policy.decision': 'deny' };
        if (call.ruleId !== undefined) attributes['cresec.policy.rule_id'] = call.ruleId;
        const ev: NotificationEvent = {
          ...base('notification', attributes),
          kind: 'notification',
          method: 'tools/call',
          direction: 'client_to_server',
          params: redactor.scrub(params),
          gateway: outcome,
        };
        record(ev);
      });
      diag(`gateway: refused tools/call notification "${tool}" (rule ${call.ruleId ?? 'default'}; a notification cannot be held or answered)`);
      try {
        res.writeHead(202);
        res.end();
      } catch {
        /* client gone */
      }
      return;
    }
    if (isPlainObject(msg) && msg['method'] === 'notifications/cancelled') {
      try {
        g.cancelHold(scope, msg);
      } catch (err) {
        tapError(err);
      }
    }
    // Everything else — initialize, tools/list, notifications, client
    // responses — crosses as written and is recorded by the ordinary tap.
    guarded(() => handleMessage(msg, 'client_to_server', text, scope));
    forwardExchange(req, res, upstreamUrl, scope, { body, filterResponse: true });
  };

  const guarded = (fn: () => void): void => {
    try {
      fn();
    } catch (err) {
      tapError(err);
    }
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

    // EVERY POST is gated, whatever its content-type says. The gate parses
    // the body itself (a body that is not JSON is refused there), so a
    // tools/call sent as text/plain, or with no content-type at all, is
    // evaluated exactly like one sent as application/json — keying the gate
    // on the header would let a client name its way past the policy.
    if (gw !== undefined && req.method === 'POST') {
      gatewayPost(gw, req, res, upstreamUrl, scope).catch((err: unknown) => {
        // Enforcement fails closed: an exchange the gateway could not
        // evaluate is refused, never forwarded.
        tapError(err);
        respondJson(res, 500, invalidRequestResponse(null, 'mcp-recorder gateway: internal error while evaluating the request; refused'));
      });
      return;
    }
    forwardExchange(req, res, upstreamUrl, scope);
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
    if (opts.gateway !== undefined) {
      sessionStart.policy = { hash: opts.gateway.policy.hash };
      if (opts.gateway.policy.name !== undefined) {
        sessionStart.policy.name = structuralString(opts.gateway.policy.name, 'identifier');
      }
    }
    record(sessionStart);
  } catch (err) {
    tapError(err);
  }

  let closed = false;
  const close = async (): Promise<void> => {
    if (closed) return;
    closed = true;
    sessionClosing = true;
    try {
      // Gateway mode: a hold nobody answered is recorded as `session_end`
      // and the client, if still waiting, gets the refusal.
      resolveAllHolds();
    } catch (err) {
      tapError(err);
    }
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
