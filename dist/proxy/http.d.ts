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
import type { RecorderLike, RedactorLike } from '../types.js';
import type { GatewayOptions } from '../gateway/options.js';
import { type ActorStamp } from '../identity/stamp.js';
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
export declare function runHttpProxy(opts: HttpProxyOpts): Promise<HttpProxyHandle>;
