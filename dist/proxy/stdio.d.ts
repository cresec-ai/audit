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
 *    original bytes when nothing changed, else the original line with ONLY
 *    the rewritten subtrees spliced back into it (see
 *    `spliceRewrittenLine`: re-serializing a whole message to redact one
 *    string would silently rewrite unrelated numbers in it).
 * Enforcement fails CLOSED (an evaluation throw or an unwritable hold is a
 * deny); recording stays fail-open exactly as in record mode. Every
 * `tools/call` the client sends is evaluated — REQUEST or NOTIFICATION,
 * standalone or inside a batch — including one whose `params.name` is
 * missing or not a string: it is evaluated as the tool name '' so the
 * section default (and any glob matching the empty string) applies, and one
 * whose `params.name` is longer than `MAX_EVALUATED_TOOL_NAME_LEN`, which
 * is a fail-closed deny WITHOUT consulting the policy (the engine's tool
 * globs are backtracking regexes on this thread; an uncapped name off the
 * wire is a remote freeze). Known v1 limit, on purpose: a `hold` that has
 * nowhere to park — inside a JSON-RPC batch, or on a notification — is
 * treated as a fail-closed deny.
 *
 * THE CREDENTIAL SWAP IS THE SECOND SANCTIONED EXCEPTION to byte
 * transparency, and the only one that rewrites a CLIENT line. When the
 * policy declares a `credentials` site (see ../gateway/credentials.ts) and
 * the argument at that site holds a synthetic placeholder, the gateway
 * exchanges it at the broker and splices the real token into the outbound
 * bytes — at the declared (server, tool, dot-path) site and nowhere else,
 * never wherever the placeholder string happens to occur. Four orders matter
 * and are load-bearing:
 *  - the tap records the PRE-swap message, always, because the swap is
 *    applied to a COPY and the entry the event is built from keeps the
 *    synthetic. Record-then-swap is a pipeline order, not a check;
 *  - a broker that cannot authorise the call DENIES it (invariant 1); the
 *    synthetic is never forwarded on to the upstream and the failure path
 *    never returns the request unmodified;
 *  - the exchange is asynchronous, so the call is parked exactly as a hold
 *    is (its id stays in flight for the duplicate-id gate) and released on
 *    the next line boundary. Inside a JSON-RPC batch, and on a `tools/call`
 *    NOTIFICATION, there is nowhere to park it and nothing to answer on, so
 *    it is a fail-closed deny — the same v1 limit a `hold` carries;
 *  - on the way back, every server line is swept for the exact resolved
 *    token and any occurrence is replaced by the synthetic BEFORE the result
 *    is hashed into an event or reaches the client. That is the seatbelt for
 *    a tool that reflects its own arguments; the real control is that the
 *    swap only ever fires at a declared site.
 *
 * NO CLIENT BYTE REACHES THE SERVER UNEVALUATED. That is the whole promise,
 * and every shape that used to get around it is now gated:
 *
 * LINES TOO BIG TO EVALUATE. A line past the scanner's cap cannot be
 * buffered, so it cannot be parsed, so the policy cannot see it. Record mode
 * streams it through untouched and records a `protocol_error` `oversized`,
 * which is right for a recorder. Gateway mode must not: padding a batch past
 * the cap was enough to run a policy-DENIED tool, with nothing but an
 * `oversized` protocol_error in the chain to show for it. In gateway mode
 * the client->server splitter therefore DROPS an oversized line's bytes
 * instead of forwarding them, records the same `protocol_error`, and
 * answers the client with `{"jsonrpc":"2.0","id":null,"error":{"code":
 * -32600,...}}` — wrapped in an array when the line started with '[', so a
 * batch gets a batch response. The server->client direction is unchanged:
 * an oversized server line still streams through.
 *
 * A JSON-RPC BATCH IS NOT A WAY IN. Every element of a batch goes through
 * the same gate its standalone form does, in the same order. That includes
 * an element that is ITSELF AN ARRAY — not a request at all, but a server
 * that flattens nested arrays would run whatever is inside it, so it is
 * refused — and a `tools/call` NOTIFICATION, which is evaluated like any
 * other. A refused element is never forwarded and its refusal comes back as
 * an element of the batch response; the elements that ARE forwarded travel
 * as the client wrote them, and a batch with nothing refused crosses
 * byte-for-byte. Ids taken by earlier elements of the same batch count as in
 * flight — both the ones being forwarded and the ones the GATEWAY ANSWERED
 * ON, so a batch that denies id 5 and then allows id 5 does not send the
 * client two responses for one request id.
 *
 * DUPLICATE REQUEST IDS. `pending` and `holds` are both keyed by the
 * request id, and a held call sits on its key for as long as a human takes
 * to answer. A second request reusing an id that is still in flight
 * (JSON-RPC forbids it) would take that key over, so the first call's real
 * response would arrive uncorrelated — delivered to the client but recorded
 * as an orphan `protocol_error`, with no tool_call, no args hash and no
 * gateway outcome for a call that did execute. Gateway mode therefore fails
 * CLOSED on id reuse, for EVERY c2s request and not only `tools/call`: a
 * same-id `tools/list` clobbering an in-flight tool call's slot loses that
 * call from the chain just as thoroughly. A `tools/call` on a live id is
 * refused with a synthesized isError result and recorded as a
 * `policy_decision` (deny) plus a synthetic `tool_call` with
 * `error.type: 'duplicate_id'`; any other method is refused with a plain
 * JSON-RPC -32600 and recorded as an `rpc` event with the same error type.
 * Neither is forwarded, so the in-flight call keeps its slot. Both gates run
 * for a batch element too, routed exactly as the standalone path routes
 * them. Belt and braces, `registerPending` itself seals a live entry it
 * would displace (and an approved hold reclaiming its key does the same), so
 * nothing is ever silently overwritten; those seals are a last resort, not
 * the mitigation — they write a record for a call whose real result was
 * lost, so the refusals above must happen first. Record mode is untouched:
 * without a policy the tap keeps its last-writer-wins `pending` map.
 *
 * UNUSABLE REQUEST IDS. `{"id": null}` is not a valid MCP request (the
 * official SDK rejects it) and is not a notification either — and neither is
 * `{"id": true}`, `{"id": {}}` or `{"id": []}`. A `tools/call` carrying ANY
 * id that is not a string or a number is refused, fail-closed, whatever the
 * policy says — a `hold` rule matching it is a deny like any other decision,
 * and the call is not even evaluated. It is NEVER forwarded; the client gets
 * `{"jsonrpc":"2.0","id":null,"error":{"code":-32600,...}}` (JSON-RPC
 * permits a null id on an error response, and is the only honest answer when
 * the request's own id cannot be echoed). It is recorded exactly as the tap
 * has always recorded an id-less message — one `notification` event —
 * because the frozen schema's `request_id` is `string | number` and cannot
 * describe it; the refusal itself is visible on stderr. Testing `id === null`
 * alone left every other shape crossing unevaluated AND landing in the chain
 * with a `request_id` that violated the schema, so the tap's own id test is
 * `isRpcId` too, in record mode as well: a message whose id is not a string
 * or a number is recorded as id-less rather than writing an impossible
 * `request_id`. This holds inside a JSON-RPC batch as well. Without
 * `--policy` such a line is still forwarded unevaluated, as before.
 *
 * `tools/call` NOTIFICATIONS. A `tools/call` with no `id` property at all
 * asks the server to run a tool and expects nothing back. Forwarding it
 * unevaluated was the same hole the id refusals close, one shape over, so it
 * is evaluated too — standalone and inside a batch. A deny simply DROPS it,
 * which is precisely what "notification" already promises its sender: no
 * response either way. Nothing can be answered on it and the frozen schema's
 * `request_id` is `string | number`, so no `policy_decision` can be written
 * for it; the attempt is recorded as the one `notification` event the tap
 * has always written for an id-less message, and the decision is on stderr.
 */
import { type Readable, type Writable } from 'node:stream';
import type { GatewayOptions } from '../gateway/options.js';
import type { RecorderLike, RedactorLike } from '../types.js';
import { type ActorStamp } from '../identity/stamp.js';
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
    /**
     * Additive: the ADR 012 actor claim decoded from `--identity-jwt`, stamped
     * on the `identity` block of every event. Absent = no `actor` field, the
     * events read exactly as before the field existed.
     */
    actor?: ActorStamp;
}
/**
 * The text-level half of {@link spliceRewrittenLine}, shared with the HTTP
 * gateway (src/proxy/http.ts): the ORIGINAL text with only the subtrees
 * that differ between `before` and `after` spliced in, or `undefined` when
 * the edits cannot be located exactly (the caller then re-serializes).
 */
export declare function spliceRewrittenText(text: string | null, before: unknown, after: unknown): string | undefined;
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
 * response. See the module header (UNUSABLE REQUEST IDS).
 */
export declare const NULL_ID_TOOLS_CALL_MESSAGE = "mcp-recorder gateway: tools/call with a null id is not a valid request";
/**
 * The same refusal for every OTHER unusable `id` value — `true`, `{}`, `[]`
 * and anything else JSON can carry that is not a string or a number.
 */
export declare const INVALID_ID_TOOLS_CALL_MESSAGE = "mcp-recorder gateway: tools/call with an id that is neither a string nor a number is not a valid request";
/**
 * A client line the gateway could not evaluate — it grew past the line cap,
 * so it was never buffered and never parsed — is REFUSED with this
 * -32600 error and none of its bytes reach the server. See the module
 * header (LINES TOO BIG TO EVALUATE).
 */
export declare const OVERSIZED_LINE_MESSAGE: string;
/**
 * The sibling case: a line that IS small enough to buffer but is not JSON, so
 * the policy cannot be shown it either. Refused for the same reason and in
 * the same way — a line that skips the parser also skips every id gate below
 * it, so forwarding one reopens the duplicate-id holes as well.
 */
export declare const UNPARSEABLE_LINE_MESSAGE: string;
/**
 * A non-`tools/call` request refused for reusing a JSON-RPC id that is still
 * in flight. A tool call gets an isError tool RESULT (the model reads it);
 * every other method gets a plain JSON-RPC error, which is what its caller
 * is waiting for.
 */
export declare const DUPLICATE_REQUEST_ID_MESSAGE: string;
/**
 * A JSON-RPC batch element that is ITSELF an array is not a request, and a
 * server that flattens nested arrays would run whatever is inside it — past
 * a gateway that never looked. Refused.
 */
export declare const NESTED_BATCH_MESSAGE = "mcp-recorder gateway: a nested array inside a JSON-RPC batch is not a valid request and was refused";
export declare function runStdioProxy(opts: StdioProxyOpts): Promise<number>;
