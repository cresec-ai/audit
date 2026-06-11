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
}

type Direction = 'client_to_server' | 'server_to_client';

const MAX_TAP_BODY = 32 * 1024 * 1024; // 32 MiB cap on tapped body copies
const MAX_PENDING = 10_000;
const TARGET_TIMEOUT_MS = 120_000;

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
    return id;
  };

  const currentServer = (): ServerContext => {
    const server: ServerContext = {
      name: opts.serverName || learnedServerName || initialServerName,
      command: opts.targetUrl,
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

  const handleResponse = (
    msg: Record<string, unknown>,
    arrivedOn: Direction,
    raw: string,
  ): void => {
    const id = msg.id as string | number;
    // Client-initiated requests are answered server->client and vice versa.
    const key = (arrivedOn === 'server_to_client' ? 'c2s:' : 's2c:') + String(id);
    const entry = pending.get(key);
    if (!entry) {
      protocolError(arrivedOn, 'orphan_response', Buffer.byteLength(raw), raw);
      return;
    }
    pending.delete(key);

    const rawResult = 'result' in msg ? msg.result : undefined;
    const rawError = 'error' in msg ? msg.error : undefined;
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
        args: redactor.scrub(reqParams.arguments ?? {}),
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

  const handleMessage = (msg: unknown, direction: Direction, raw: string): void => {
    if (Array.isArray(msg)) {
      for (const el of msg) handleMessage(el, direction, raw);
      return;
    }
    if (!isPlainObject(msg)) return;
    const hasMethod = typeof msg.method === 'string';
    const id = msg.id;
    const hasId = id !== undefined && id !== null;

    if (hasMethod && hasId) {
      const keyPrefix = direction === 'client_to_server' ? 'c2s:' : 's2c:';
      const params = msg.params;
      const entry: PendingEntry = {
        method: msg.method as string,
        params,
        t0: performance.now(),
      };
      if (isPlainObject(params) && typeof params.name === 'string') {
        entry.toolName = params.name;
      }
      registerPending(keyPrefix + String(id as string | number), entry);
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
      handleResponse(msg, direction, raw);
    }
  };

  /** Parse a (possibly batch) JSON-RPC body and feed the tap. Never throws. */
  const tapJsonBody = (body: string, direction: Direction): void => {
    try {
      let msg: unknown;
      try {
        msg = JSON.parse(body);
      } catch {
        protocolError(direction, 'unparseable', Buffer.byteLength(body), body);
        return;
      }
      handleMessage(msg, direction, body);
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

    const upReq = requester(
      upstreamUrl,
      { method: req.method, headers: forwardHeaders(req.headers, 'host') },
      (upRes) => {
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
                  handleMessage(JSON.parse(data), 'server_to_client', data);
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
                  handleMessage(JSON.parse(data), 'server_to_client', data);
                } catch {
                  /* ignore */
                }
              }
            } else if (tapJson && !jsonOver && jsonChunks.length > 0) {
              tapJsonBody(Buffer.concat(jsonChunks).toString('utf8'), 'server_to_client');
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

    upReq.setTimeout(TARGET_TIMEOUT_MS, () => {
      upReq.destroy(new Error(`target did not respond within ${TARGET_TIMEOUT_MS}ms`));
    });
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
          tapJsonBody(Buffer.concat(reqChunks).toString('utf8'), 'client_to_server');
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
