/**
 * Pure helpers for gateway mode over the streamable-HTTP transport
 * (`mcp-recorder http --policy`). The stateful half — evaluation, holds,
 * the swap, the events — lives inside `runHttpProxy` (./http.ts) next to
 * the tap it shares state with; what is here is what can be tested alone.
 *
 * THE ONE EXCEPTION TO STREAMING. Without `--policy` the HTTP proxy streams
 * every byte of every response as it arrives. With it, a tools/call RESULT
 * has to be scanned before the client sees it (the boundary filter) and a
 * tools/call REQUEST has to be evaluated before the upstream sees it, so
 * gateway mode buffers exactly those: a JSON request body up to
 * MAX_GATEWAY_BODY, a JSON response body up to the same cap, and — for SSE
 * — ONE EVENT at a time (up to the blank line that ends it; the stream is
 * never held past that). AGENTS.md names gateway mode as the only place the
 * proxy may delay or rewrite traffic, and this is where it does.
 *
 * Numbers, whitespace and key order in an untouched message still cross as
 * written: a rewritten JSON body is spliced through `spliceRewrittenText`
 * (the stdio gateway's own mechanism), and an SSE event that the filter did
 * not change is re-emitted from its original bytes.
 */
import { Buffer } from 'node:buffer';
/** Largest request or response body gateway mode will buffer to evaluate. Past it the message is refused (request) or crosses unscanned as an `oversized` protocol_error (response). */
export declare const MAX_GATEWAY_BODY: number;
export declare function isRpcId(v: unknown): v is string | number;
export declare function isPlainObject(v: unknown): v is Record<string, unknown>;
/** A `tools/call` REQUEST: it carries a usable id, so a response can be synthesized for it. */
export declare function isToolsCallRequest(msg: unknown): msg is Record<string, unknown> & {
    id: string | number;
};
/** A `tools/call` carrying an `id` property that is not a usable JSON-RPC id (`null`, `true`, `{}`, `[]`, ...). */
export declare function isInvalidIdToolsCall(msg: unknown): msg is Record<string, unknown>;
/** A `tools/call` NOTIFICATION: no `id` property at all. */
export declare function isToolsCallNotification(msg: unknown): msg is Record<string, unknown>;
/** `params` and `params.name` of a tools/call, tolerating every malformed shape (the name is then ''). */
export declare function toolsCallParts(msg: Record<string, unknown>): {
    params: Record<string, unknown>;
    name: string;
};
/** A response (result or error) with a usable id. */
export declare function isRpcResponse(msg: unknown): msg is Record<string, unknown> & {
    id: string | number;
};
/** A result shaped like a tools/call result (MCP content blocks). */
export declare function looksLikeToolResult(msg: Record<string, unknown>): boolean;
/** `{"jsonrpc":"2.0","id":<id|null>,"error":{"code":-32600,...}}`. */
export declare function invalidRequestResponse(id: string | number | null, message: string): Record<string, unknown>;
/**
 * One SSE event, split into the lines that carry data and everything else.
 * `data` is the joined payload per the SSE spec (data lines joined by "\n",
 * a leading space after the colon stripped); `undefined` when the event
 * carries no data line at all (a comment, a retry hint, a keepalive).
 */
export interface SseEvent {
    /** The exact bytes of the event, blank-line terminator included. */
    raw: Buffer;
    data: string | undefined;
}
/**
 * Re-emit one event with its data replaced. Every non-data line (`event:`,
 * `id:`, `retry:`, comments) is kept verbatim, in place of the first data
 * line; the payload goes out as ONE `data:` line, which is legal SSE for
 * any JSON text (JSON.stringify never emits a raw newline).
 */
export declare function rewriteSseEvent(raw: Buffer, data: string): Buffer;
/**
 * An incremental SSE splitter that hands back COMPLETE events, each with
 * its exact bytes, so a caller can forward an untouched event byte for byte
 * and rewrite only the one it changed. Bounded: an event that grows past
 * `maxEventBytes` without a terminator is flushed as `oversized` — its
 * bytes are handed back unparsed (the caller forwards them and records the
 * fact), exactly as the stdio gateway treats a line past its cap.
 */
export declare class SseEventSplitter {
    private readonly maxEventBytes;
    private pending;
    private pendingLen;
    private overflowed;
    constructor(maxEventBytes?: number);
    /** Feed a chunk; get back every event completed by it. */
    push(chunk: Buffer): Array<SseEvent | {
        raw: Buffer;
        oversized: true;
    }>;
    /** The unterminated tail at end of stream, if any, as one final event. */
    end(): SseEvent | undefined;
}
