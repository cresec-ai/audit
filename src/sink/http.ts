/**
 * The sink's HTTP transport: node builtins only, no new dependency.
 *
 * Two things here are not optional, because without them a Claude Code cloud
 * session ships nothing at all:
 *
 *   HTTPS_PROXY / NO_PROXY — `node:https` does NOT read them itself. An
 *       https sink behind a proxy is reached by CONNECT-tunnelling through
 *       it and running TLS inside the tunnel, which is what the agent proxy
 *       and every corporate egress gateway expect.
 *   NODE_EXTRA_CA_CERTS — node reads this one on its own, so there is
 *       nothing to implement; it is named here so nobody is ever tempted to
 *       "fix" a proxy CA by disabling verification instead. Certificate
 *       verification is NEVER disabled in this file.
 *
 * Timeouts are split (connect vs total) so a sink that accepts a connection
 * and then goes silent is bounded by the total budget rather than hanging
 * forever. Nothing here runs on the forwarding path, but a wedged shipper
 * still stops shipping, which is its own failure.
 */

import { request as httpRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';
import type { Agent as HttpsAgent, RequestOptions } from 'node:https';
import { Agent } from 'node:https';
import type { Duplex } from 'node:stream';
import { connect as tlsConnect } from 'node:tls';
import type { Socket } from 'node:net';
import { Buffer } from 'node:buffer';
import { CONNECT_TIMEOUT_MS, TOTAL_TIMEOUT_MS } from './protocol.js';

export interface SinkHttpResponse {
  status: number;
  headers: NodeJS.Dict<string | string[]>;
  body: Buffer;
}

export interface SinkHttpRequest {
  method: 'GET' | 'POST';
  url: string;
  headers: Record<string, string>;
  body?: Buffer;
  connectTimeoutMs?: number;
  totalTimeoutMs?: number;
}

/** Cap on a response body we are willing to buffer — a cursor is ~300 bytes. */
const MAX_RESPONSE_BYTES = 256 * 1024;

/* ------------------------------- proxy ---------------------------------- */

function envFirst(env: NodeJS.ProcessEnv, ...names: string[]): string | undefined {
  for (const name of names) {
    const value = env[name];
    if (value !== undefined && value.trim() !== '') return value.trim();
  }
  return undefined;
}

/**
 * NO_PROXY semantics as every other client implements them: a comma-separated
 * list of `*`, `host`, `.suffix` or `host:port` entries, matched
 * case-insensitively against the target's host (and port).
 */
export function noProxyMatches(noProxy: string, hostname: string, port: string): boolean {
  const host = hostname.toLowerCase().replace(/^\[|\]$/g, '');
  for (const rawEntry of noProxy.split(',')) {
    const entry = rawEntry.trim().toLowerCase();
    if (entry === '') continue;
    if (entry === '*') return true;
    const [entryHost, entryPort] = entry.includes(':') && !entry.startsWith('[')
      ? [entry.slice(0, entry.lastIndexOf(':')), entry.slice(entry.lastIndexOf(':') + 1)]
      : [entry, undefined];
    if (entryPort !== undefined && entryPort !== port) continue;
    const bare = entryHost.replace(/^\./, '');
    if (host === bare || host.endsWith(`.${bare}`)) return true;
  }
  return false;
}

/** The proxy to use for `target`, honouring NO_PROXY. Undefined = direct. */
export function proxyUrlFor(target: URL, env: NodeJS.ProcessEnv): URL | undefined {
  const noProxy = envFirst(env, 'NO_PROXY', 'no_proxy');
  const port = target.port !== '' ? target.port : target.protocol === 'https:' ? '443' : '80';
  if (noProxy !== undefined && noProxyMatches(noProxy, target.hostname, port)) return undefined;
  const raw =
    target.protocol === 'https:'
      ? envFirst(env, 'HTTPS_PROXY', 'https_proxy')
      : envFirst(env, 'HTTP_PROXY', 'http_proxy');
  if (raw === undefined) return undefined;
  try {
    return new URL(raw);
  } catch {
    return undefined;
  }
}

/**
 * An https.Agent that reaches the origin through an HTTP CONNECT tunnel.
 * TLS is negotiated INSIDE the tunnel against the origin's own certificate,
 * with `servername` set for SNI — so the proxy sees only the host:port, and
 * verification stays on end to end.
 */
class ProxyTunnelAgent extends Agent {
  readonly #proxy: URL;
  readonly #connectTimeoutMs: number;

  constructor(proxy: URL, connectTimeoutMs: number) {
    super({ keepAlive: false });
    this.#proxy = proxy;
    this.#connectTimeoutMs = connectTimeoutMs;
  }

  override createConnection(
    options: RequestOptions & { servername?: string },
    callback?: (err: Error | null, stream: Duplex) => void,
  ): Duplex | null | undefined {
    const host = options.host ?? options.hostname ?? '';
    const port = typeof options.port === 'number' ? options.port : Number(options.port ?? 443);
    if (callback === undefined) {
      // https.Agent always passes one; a caller that does not is asking for a
      // synchronous socket, which a CONNECT tunnel cannot give.
      throw new Error('mcp-recorder: proxy tunnel requires the async createConnection callback');
    }
    const headers: Record<string, string> = { host: `${host}:${String(port)}` };
    if (this.#proxy.username !== '' || this.#proxy.password !== '') {
      const creds = `${decodeURIComponent(this.#proxy.username)}:${decodeURIComponent(this.#proxy.password)}`;
      headers['proxy-authorization'] = `Basic ${Buffer.from(creds).toString('base64')}`;
    }
    const req = httpRequest({
      host: this.#proxy.hostname,
      port: this.#proxy.port !== '' ? Number(this.#proxy.port) : 80,
      method: 'CONNECT',
      path: `${host}:${String(port)}`,
      headers,
      agent: false,
      timeout: this.#connectTimeoutMs,
    });
    const cb = callback;
    let settled = false;
    const fail = (err: Error): void => {
      if (settled) return;
      settled = true;
      req.destroy();
      cb(err, undefined as unknown as Duplex);
    };
    req.on('error', fail);
    req.on('timeout', () => fail(new Error('proxy CONNECT timed out')));
    req.on('connect', (res, socket: Socket) => {
      if (settled) {
        socket.destroy();
        return;
      }
      if (res.statusCode !== 200) {
        socket.destroy();
        fail(new Error(`proxy CONNECT refused with status ${String(res.statusCode)}`));
        return;
      }
      settled = true;
      // Certificate verification is deliberately left at its default (on).
      const tlsSocket = tlsConnect({ socket, servername: options.servername ?? host });
      tlsSocket.on('error', () => {
        /* surfaced to the request through the socket, not here */
      });
      cb(null, tlsSocket);
    });
    req.end();
    return undefined;
  }
}

/** Build the agent for `target`, or undefined for a direct connection. */
export function agentFor(
  target: URL,
  env: NodeJS.ProcessEnv,
  connectTimeoutMs: number = CONNECT_TIMEOUT_MS,
): HttpsAgent | undefined {
  if (target.protocol !== 'https:') return undefined;
  const proxy = proxyUrlFor(target, env);
  if (proxy === undefined) return undefined;
  return new ProxyTunnelAgent(proxy, connectTimeoutMs);
}

/* ------------------------------- request -------------------------------- */

/**
 * One request. Rejects on transport failure (DNS, TLS, refused, timeout);
 * every HTTP status, including 5xx, resolves — status handling is the
 * caller's job, not the transport's.
 */
export async function sinkFetch(
  req: SinkHttpRequest,
  env: NodeJS.ProcessEnv = process.env,
): Promise<SinkHttpResponse> {
  const target = new URL(req.url);
  const connectTimeoutMs = req.connectTimeoutMs ?? CONNECT_TIMEOUT_MS;
  const totalTimeoutMs = req.totalTimeoutMs ?? TOTAL_TIMEOUT_MS;
  const isHttps = target.protocol === 'https:';
  const doRequest = isHttps ? httpsRequest : httpRequest;
  const agent = agentFor(target, env, connectTimeoutMs);

  return new Promise<SinkHttpResponse>((resolve, reject) => {
    let settled = false;
    let connectTimer: NodeJS.Timeout | undefined;
    const finish = (err: Error | null, value?: SinkHttpResponse): void => {
      if (settled) return;
      settled = true;
      clearTimeout(totalTimer);
      if (connectTimer !== undefined) clearTimeout(connectTimer);
      if (err !== null) reject(err);
      else resolve(value as SinkHttpResponse);
    };

    const clientReq = doRequest(
      {
        protocol: target.protocol,
        hostname: target.hostname,
        port: target.port !== '' ? Number(target.port) : isHttps ? 443 : 80,
        path: `${target.pathname}${target.search}`,
        method: req.method,
        headers: req.headers,
        ...(agent !== undefined ? { agent } : {}),
      },
      (res) => {
        const chunks: Buffer[] = [];
        let total = 0;
        res.on('data', (chunk: Buffer) => {
          total += chunk.length;
          if (total > MAX_RESPONSE_BYTES) {
            res.destroy();
            finish(new Error('sink response exceeded the response budget'));
            return;
          }
          chunks.push(chunk);
        });
        res.on('end', () => {
          finish(null, {
            status: res.statusCode ?? 0,
            headers: res.headers,
            body: Buffer.concat(chunks),
          });
        });
        res.on('error', (err: Error) => finish(err));
      },
    );

    const totalTimer = setTimeout(() => {
      clientReq.destroy(new Error(`sink request exceeded ${String(totalTimeoutMs)}ms`));
    }, totalTimeoutMs);
    totalTimer.unref?.();

    // Connect budget covers establishing the socket ONLY. A sink that
    // accepts and then goes silent is bounded by the total budget instead —
    // conflating the two would cut off a slow-but-working receiver that is
    // fsyncing a large batch before answering 202.
    connectTimer = setTimeout(() => {
      clientReq.destroy(new Error(`sink connect exceeded ${String(connectTimeoutMs)}ms`));
    }, connectTimeoutMs);
    connectTimer.unref?.();
    const connected = (): void => {
      if (connectTimer !== undefined) clearTimeout(connectTimer);
      connectTimer = undefined;
    };
    clientReq.on('socket', (socket: Socket) => {
      if (!socket.connecting) {
        connected();
        return;
      }
      socket.once('connect', connected);
      socket.once('secureConnect', connected);
    });
    clientReq.on('response', connected);
    clientReq.on('error', (err: Error) => {
      connected();
      finish(err);
    });
    if (req.body !== undefined) clientReq.write(req.body);
    clientReq.end();
  });
}
