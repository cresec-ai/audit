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
 * JSON-RPC batch is treated as deny, a `tools/call` with no `id` property
 * at all (a notification) is forwarded unevaluated, and a line over the
 * 32 MiB tap cap cannot be parsed so it is forwarded unchanged and
 * recorded as `protocol_error` — as in record mode.
 *
 * DUPLICATE REQUEST IDS. `pending` and `holds` are both keyed by the
 * request id, and a held call sits on its key for as long as a human takes
 * to answer. A second `tools/call` reusing an id that is still in flight
 * (JSON-RPC forbids it) would take that key over, so the first call's real
 * response would arrive uncorrelated — delivered to the client but recorded
 * as an orphan `protocol_error`, with no tool_call, no args hash and no
 * gateway outcome for a call that did execute. Gateway mode therefore fails
 * CLOSED on id reuse: a `tools/call` whose id is currently held, or already
 * pending, is refused immediately with a synthesized isError result and
 * recorded as a `policy_decision` (deny) plus a synthetic `tool_call` with
 * `error.type: 'duplicate_id'` — it is never forwarded, so the in-flight
 * call keeps its slot. Belt and braces, an approved hold that still finds a
 * pending entry on its key (one that slipped in through a path with no such
 * check) seals that entry as `duplicate_id` before taking the slot back, so
 * nothing is ever silently overwritten. Record mode is untouched: without a
 * policy the tap keeps its last-writer-wins `pending` map.
 *
 * NULL REQUEST IDS. `{"id": null}` is not a valid MCP request (the official
 * SDK rejects it) and is not a notification either, so a `tools/call`
 * carrying it is refused, fail-closed, whatever the policy says — a `hold`
 * rule matching it is a deny like any other decision, and the call is not
 * even evaluated. It is NEVER forwarded; the client gets
 * `{"jsonrpc":"2.0","id":null,"error":{"code":-32600,...}}` (JSON-RPC
 * permits a null id on an error response). It is recorded exactly as the
 * tap has always recorded an id-less message — one `notification` event —
 * because the frozen schema's `request_id` is `string | number` and cannot
 * describe it; the refusal itself is visible on stderr. Without `--policy`
 * it is forwarded unevaluated, as before.
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
/**
 * Why a `tools/call` is refused for reusing a JSON-RPC id that is still in
 * flight: the id is parked as a hold, or it belongs to a request the server
 * has not answered yet. See the module header (DUPLICATE REQUEST IDS).
 */
export type DuplicateIdState = 'held' | 'pending';
/**
 * The text the model sees for a `tools/call` refused because its id is
 * still in use. Like every other synthesized text it names the tool as the
 * CLIENT wrote it (and the id it chose); events carry the capped forms.
 */
export declare function duplicateIdText(tool: string, id: string | number, state: DuplicateIdState): string;
/**
 * A `tools/call` with `id: null` is refused with this JSON-RPC error
 * (-32600 Invalid Request); JSON-RPC permits a null id on an error
 * response. See the module header (NULL REQUEST IDS).
 */
export declare const NULL_ID_TOOLS_CALL_MESSAGE = "mcp-recorder gateway: tools/call with a null id is not a valid request";
export declare function runStdioProxy(opts: StdioProxyOpts): Promise<number>;
