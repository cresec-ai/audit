/**
 * Transparent stdio passthrough proxy (M0) + capture tap (M1) + opt-in
 * gateway mode (P2-7).
 *
 * FORWARDING IS SACRED: client<->server bytes flow through plain .pipe()
 * with backpressure and are never mutated, delayed, or filtered. The tap
 * attaches separate 'data' listeners feeding a LineScanner; everything the
 * tap does is wrapped fail-open — a recorder/tap failure is logged once to
 * stderr and traffic continues.
 *
 * GATEWAY MODE (`opts.gateway` present, i.e. `record --policy`) is the ONE
 * sanctioned exception, and only for `tools/call` requests and their
 * results: the two raw pipes are replaced by two Transform streams that
 * line-split, JSON.parse each line exactly once (the tap's parse is folded
 * in), and
 *  - client->server: evaluate every `tools/call` request against the policy
 *    (allow = forward the ORIGINAL bytes; deny = synthesize an isError
 *    result, forward nothing; hold = park the bytes until `approve`/`deny`,
 *    timeout, `notifications/cancelled` or shutdown). Every other line is
 *    forwarded byte-for-byte (oversized and unparseable lines included).
 *  - server->client: run the boundary filter over the result of a
 *    tools/call the gateway saw — element by element when the server
 *    answers a batch with a JSON-RPC array, and over an uncorrelated
 *    ("orphan") result that still looks like a tool result; forward the
 *    original bytes when nothing changed, else the re-serialized message.
 * Enforcement fails CLOSED (an evaluation throw or an unwritable hold is a
 * deny); recording stays fail-open exactly as in record mode. Every
 * `tools/call` REQUEST (one carrying an id) is evaluated, including one
 * whose `params.name` is missing or not a string: it is evaluated as the
 * tool name '' so the section default — and any glob matching the empty
 * string — applies. Known v1 limits, on purpose: a `hold` inside a
 * JSON-RPC batch is treated as deny, a `tools/call` without an id (a
 * notification) is forwarded unevaluated, and a line over the 32 MiB tap
 * cap cannot be parsed so it is forwarded unchanged and recorded as
 * `protocol_error` — as in record mode.
 */
import { type Readable, type Writable } from 'node:stream';
import type { GatewayOptions } from '../gateway/options.js';
import type { RecorderLike, RedactorLike } from '../types.js';
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
    /**
     * Additive: present ONLY for `record --policy`. Switches the proxy into
     * gateway mode (see the module header); absent = byte-for-byte recorder.
     */
    gateway?: GatewayOptions;
}
/**
 * Gateway mode: cap on concurrently parked holds. The map is keyed by
 * request id and only shrinks when a hold is resolved, so a client that
 * fires hold-matching calls it never answers for would otherwise grow it
 * without bound. Beyond the cap a hold-matching call is refused (deny),
 * fail-closed — documented in docs/gateway.md.
 */
export declare const MAX_HOLDS = 256;
export declare function runStdioProxy(opts: StdioProxyOpts): Promise<number>;
