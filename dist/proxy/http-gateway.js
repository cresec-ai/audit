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
export const MAX_GATEWAY_BODY = 32 * 1024 * 1024;
export function isRpcId(v) {
    return typeof v === 'string' || (typeof v === 'number' && Number.isFinite(v));
}
export function isPlainObject(v) {
    return typeof v === 'object' && v !== null && !Array.isArray(v);
}
/** A `tools/call` REQUEST: it carries a usable id, so a response can be synthesized for it. */
export function isToolsCallRequest(msg) {
    return isPlainObject(msg) && msg['method'] === 'tools/call' && isRpcId(msg['id']);
}
/** A `tools/call` carrying an `id` property that is not a usable JSON-RPC id (`null`, `true`, `{}`, `[]`, ...). */
export function isInvalidIdToolsCall(msg) {
    return isPlainObject(msg) && msg['method'] === 'tools/call' && 'id' in msg && !isRpcId(msg['id']);
}
/** A `tools/call` NOTIFICATION: no `id` property at all. */
export function isToolsCallNotification(msg) {
    return isPlainObject(msg) && msg['method'] === 'tools/call' && !('id' in msg);
}
/** `params` and `params.name` of a tools/call, tolerating every malformed shape (the name is then ''). */
export function toolsCallParts(msg) {
    const params = isPlainObject(msg['params']) ? msg['params'] : {};
    return { params, name: typeof params['name'] === 'string' ? params['name'] : '' };
}
/** A response (result or error) with a usable id. */
export function isRpcResponse(msg) {
    return isPlainObject(msg) && isRpcId(msg['id']) && ('result' in msg || 'error' in msg);
}
/** A result shaped like a tools/call result (MCP content blocks). */
export function looksLikeToolResult(msg) {
    const result = msg['result'];
    return isPlainObject(result) && Array.isArray(result['content']);
}
/** `{"jsonrpc":"2.0","id":<id|null>,"error":{"code":-32600,...}}`. */
export function invalidRequestResponse(id, message) {
    return { jsonrpc: '2.0', id, error: { code: -32600, message } };
}
/**
 * Re-emit one event with its data replaced. Every non-data line (`event:`,
 * `id:`, `retry:`, comments) is kept verbatim, in place of the first data
 * line; the payload goes out as ONE `data:` line, which is legal SSE for
 * any JSON text (JSON.stringify never emits a raw newline).
 */
export function rewriteSseEvent(raw, data) {
    const text = raw.toString('utf8');
    const eol = text.includes('\r\n') ? '\r\n' : '\n';
    const lines = text.split(/\r?\n/);
    // The event ends with an empty line (and the split leaves one more empty
    // element after the terminator); everything up to the terminator is kept.
    const out = [];
    let dataWritten = false;
    for (const line of lines) {
        if (line.startsWith('data:')) {
            if (!dataWritten) {
                out.push('data: ' + data);
                dataWritten = true;
            }
            continue;
        }
        out.push(line);
    }
    if (!dataWritten)
        out.unshift('data: ' + data);
    return Buffer.from(out.join(eol), 'utf8');
}
/**
 * An incremental SSE splitter that hands back COMPLETE events, each with
 * its exact bytes, so a caller can forward an untouched event byte for byte
 * and rewrite only the one it changed. Bounded: an event that grows past
 * `maxEventBytes` without a terminator is flushed as `oversized` — its
 * bytes are handed back unparsed (the caller forwards them and records the
 * fact), exactly as the stdio gateway treats a line past its cap.
 */
export class SseEventSplitter {
    maxEventBytes;
    pending = [];
    pendingLen = 0;
    overflowed = false;
    constructor(maxEventBytes = MAX_GATEWAY_BODY) {
        this.maxEventBytes = maxEventBytes;
    }
    /** Feed a chunk; get back every event completed by it. */
    push(chunk) {
        const out = [];
        if (this.overflowed) {
            // Past the cap the stream is passed through until the next event
            // boundary, then parsing resumes.
            const end = findEventEnd(chunk, 0);
            if (end === -1) {
                out.push({ raw: chunk, oversized: true });
                return out;
            }
            out.push({ raw: chunk.subarray(0, end), oversized: true });
            this.overflowed = false;
            chunk = chunk.subarray(end);
        }
        const buf = this.pendingLen === 0 ? chunk : Buffer.concat([...this.pending, chunk]);
        this.pending = [];
        this.pendingLen = 0;
        let start = 0;
        for (;;) {
            const end = findEventEnd(buf, start);
            if (end === -1)
                break;
            const raw = buf.subarray(start, end);
            out.push({ raw, data: eventData(raw) });
            start = end;
        }
        const rest = buf.subarray(start);
        if (rest.length > this.maxEventBytes) {
            this.overflowed = true;
            out.push({ raw: rest, oversized: true });
            return out;
        }
        if (rest.length > 0) {
            this.pending.push(Buffer.from(rest));
            this.pendingLen = rest.length;
        }
        return out;
    }
    /** The unterminated tail at end of stream, if any, as one final event. */
    end() {
        if (this.pendingLen === 0)
            return undefined;
        const raw = Buffer.concat(this.pending);
        this.pending = [];
        this.pendingLen = 0;
        return { raw, data: eventData(raw) };
    }
}
/** Index just past the blank line that ends the event starting at `from`, or -1. */
function findEventEnd(buf, from) {
    let i = from;
    while (i < buf.length) {
        const nl = buf.indexOf(0x0a, i);
        if (nl === -1)
            return -1;
        // A line is empty when the newline is at the line start, allowing one \r.
        const lineStart = i;
        const lineEnd = nl > lineStart && buf[nl - 1] === 0x0d ? nl - 1 : nl;
        if (lineEnd === lineStart)
            return nl + 1;
        i = nl + 1;
    }
    return -1;
}
function eventData(raw) {
    const lines = raw.toString('utf8').split(/\r?\n/);
    const data = [];
    for (const line of lines) {
        if (line.startsWith('data:'))
            data.push(line.slice(5).replace(/^ /, ''));
    }
    return data.length === 0 ? undefined : data.join('\n');
}
//# sourceMappingURL=http-gateway.js.map