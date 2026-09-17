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
import type { Agent as HttpsAgent } from 'node:https';
import { Buffer } from 'node:buffer';
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
/**
 * NO_PROXY semantics as every other client implements them: a comma-separated
 * list of `*`, `host`, `.suffix` or `host:port` entries, matched
 * case-insensitively against the target's host (and port).
 */
export declare function noProxyMatches(noProxy: string, hostname: string, port: string): boolean;
/** The proxy to use for `target`, honouring NO_PROXY. Undefined = direct. */
export declare function proxyUrlFor(target: URL, env: NodeJS.ProcessEnv): URL | undefined;
/** Build the agent for `target`, or undefined for a direct connection. */
export declare function agentFor(target: URL, env: NodeJS.ProcessEnv, connectTimeoutMs?: number): HttpsAgent | undefined;
/**
 * One request. Rejects on transport failure (DNS, TLS, refused, timeout);
 * every HTTP status, including 5xx, resolves — status handling is the
 * caller's job, not the transport's.
 */
export declare function sinkFetch(req: SinkHttpRequest, env?: NodeJS.ProcessEnv): Promise<SinkHttpResponse>;
