/**
 * Streamable-HTTP passthrough proxy + capture tap.
 *
 * FORWARDING IS SACRED: incoming requests are streamed to the target with
 * method/headers preserved (hop-by-hop headers excepted) and the target's
 * response is streamed back verbatim — status, headers, body chunks as they
 * arrive, so SSE flows untouched. The tap keeps a bounded COPY of bodies and
 * scans them for JSON-RPC traffic; every tap failure is swallowed (fail-open).
 */
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
export declare function runHttpProxy(opts: HttpProxyOpts): Promise<HttpProxyHandle>;
