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

import { constants as osConstants, hostname as osHostname, userInfo } from 'node:os';
import { basename } from 'node:path';
import { performance } from 'node:perf_hooks';
import { randomUUID } from 'node:crypto';
import { Transform, type Readable, type Writable } from 'node:stream';

import { canonicalJson, sha256Ref } from '../chain/hash.js';
import {
  applyBoundary,
  boundarySecretPatterns,
  deniedText,
  synthesizeDeniedResult,
  type BoundaryDeps,
} from '../gateway/boundary.js';
import {
  MAX_INFLIGHT_SWAPS,
  SWAP_DENY,
  swapDenyReason,
  unplannableSwap,
  type PlannedSwap,
  type SwapOutcome,
} from '../gateway/credentials.js';
import type { HoldRecord, HoldWaitResult } from '../gateway/holds.js';
import type { GatewayOptions } from '../gateway/options.js';
import { evaluateMcp, type McpDecision } from '../policy/engine.js';
import { setRegexGuardDiag, warmRegexGuard } from '../policy/regex-guard.js';
import { normalizePolicy, type McpPolicy } from '../policy/types.js';
import { planSpawn, spawnWrapped, terminateChild, withNodeDirOnPath } from './spawn.js';
import type {
  AnyEvent,
  Attributes,
  BoundaryReport,
  GatewayOutcome,
  HoldOutcome,
  IdentityContext,
  InitializeEvent,
  NotificationEvent,
  PolicyDecisionEvent,
  ProtocolErrorEvent,
  RpcEvent,
  ServerContext,
  SessionEndEvent,
  SessionStartEvent,
  ToolCallEvent,
} from '../schema/events.js';
import { SCHEMA } from '../schema/events.js';
import {
  STRUCTURAL_STRING_MAX_LEN,
  collectEnvCredentialFingerprints,
  scrubArgv,
  scrubToolArguments,
  structuralString,
} from '../redact/redactor.js';
import type { RecorderLike, RedactorLike } from '../types.js';
import { LineScanner, type ScannedLine } from './framing.js';
import { stampActor, type ActorStamp } from '../identity/stamp.js';

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

interface PendingEntry {
  method: string;
  params: unknown;
  t0: number;
  toolName?: string;
  /** The JSON-RPC request id, preserved with its original type. */
  id: string | number;
  /** Gateway mode: the decision already taken for this tools/call (no boundary yet). */
  gateway?: GatewayOutcome;
  /**
   * Gateway mode: extra attributes the request-time decision produced, merged
   * onto the event this entry eventually becomes. Today only the credential
   * swap writes them (which credential, which decision id, which destination
   * — never the value). `attributes` is an open map on the frozen v1 schema,
   * so this adds no field to any event type.
   */
  attributes?: Attributes;
}

/* ------------------------------ gateway types ----------------------------- */

/** A parsed `tools/call` request the gateway evaluated. */
interface GatewayCall {
  id: string | number;
  params: Record<string, unknown>;
  /** The tool name exactly as the client sent it (used in the text the model sees). */
  rawTool: string;
  /** Capped tool name (structuralString) — what every event carries. */
  tool: string;
  args: unknown;
  /** sha256 ref of the canonical JSON of `args` (never the args). */
  argsHash: string;
  /** Matching rule id as written in the policy (text the model sees) and capped (events). */
  rawRuleId?: string;
  ruleId?: string;
  reason?: string;
  /**
   * Credential-swap attributes for the events this call produces: which
   * credential, which `decision_id`, which destination the broker was asked
   * about. Never the resolved value and never a hash of it — refs are
   * unsalted, so a ref of a brokered token is a copy of it.
   */
  swapAttributes?: Attributes;
  /**
   * The id of the decision the `policy_decision` event for this call
   * carries (`decision_id`, additive). Set from the control plane's
   * `decision_id` when the remote broker decided; minted per decision
   * otherwise. Internal; `recordPolicyDecision` fills it in when absent.
   */
  decisionId?: string;
  /**
   * True when this refusal is the gateway FAILING CLOSED, not the operator
   * deciding: the policy could not be evaluated, the hold file could not be
   * written, `MAX_HOLDS` was already reached, finalize() had begun, a `hold`
   * rule matched inside a JSON-RPC batch (nowhere to park it, so nobody is
   * asked), or a parked hold ended because the session did rather than
   * because a human answered — including one the operator had already
   * APPROVED. The test is who decided, not what the outcome was: a human's
   * `deny` and a `timeout` the policy configured are both policy decisions.
   * It only picks which guidance clause `deniedText` appends — the refusal,
   * the events and the diagnostics are unchanged. Internal to the proxy; no
   * event carries it.
   */
  failClosed?: true;
}

/** A held tools/call: parked bytes + everything needed to resolve it later. */
interface HoldEntry extends GatewayCall {
  approvalId: string;
  /** pendingKey('c2s:', id) — so `notifications/cancelled` can find it. */
  key: string;
  raw: Buffer;
  /**
   * The parsed request and the line it arrived on, kept only so an APPROVED
   * hold can still have its credential swapped in: the swap splices into the
   * original line exactly as the boundary rewrite does, and it deliberately
   * runs after the human answers, so no real token is resident in memory
   * while a hold waits.
   */
  msg?: ToolsCallRequest;
  line?: ScannedLine;
  /** When the hold started (performance.now()); `waited_ms` = now - t0. */
  t0: number;
  abort: AbortController;
  settled: boolean;
}

/** How a hold ended without the call being forwarded (or after being forwarded, for the record). */
interface HoldResolution {
  outcome: HoldOutcome;
  /** Absent only when the call was refused BEFORE a hold file existed (session_end). */
  approvalId?: string;
  waitedMs: number;
  approver?: string;
}

/**
 * A `tools/call` REQUEST: it carries an id, so a response can be
 * synthesized for it. `params`/`params.name` are deliberately NOT part of
 * the shape — a request without a usable name is still evaluated (as the
 * tool name ''), never waved through; see `toolsCallParts`.
 */
type ToolsCallRequest = Record<string, unknown> & { id: string | number };

const NL = 0x0a;
/** Explicit rule ids (`ID_PATTERN`) and the auto-assigned `rule[<i>]` survive as-is. */
const RULE_ID_SHAPE = /^(?:[A-Za-z0-9_.:/-]{1,64}|rule\[[0-9]+\])$/;

/**
 * Line framing for the gateway Transforms. The chunk is walked newline by
 * newline so every segment's bytes are known: a complete line under the tap
 * cap reaches `onLine` with its exact bytes (`ScannedLine.raw`) and is
 * forwarded by the handler's decision; an empty line goes straight through;
 * a line that grows past the cap cannot be buffered, so its bytes are
 * forwarded as they arrive (`forward`) while the scanner only counts and
 * hashes it. `carry` references the chunks the scanner is already
 * buffering, so nothing is copied twice.
 */
class GatewayLineSplitter {
  private readonly scanner = new LineScanner();
  /** Segments of the current partial line, in case it turns out oversized (or empty). */
  private carry: Buffer[] = [];
  /** True while an oversized line is in flight (streamed through, or dropped). */
  private passthrough = false;

  constructor(
    private readonly forward: (bytes: Buffer) => void,
    private readonly onLine: (line: ScannedLine) => void,
    /**
     * `refuseOversized` (client->server only): a line past the cap cannot be
     * parsed, so the policy cannot see it — and enforcement fails CLOSED, so
     * NONE of its bytes may reach the server. They are dropped here and
     * `onLine` refuses the line. Without it (server->client, and record
     * mode's own tap) an oversized line streams straight through as before.
     */
    private readonly refuseOversized = false,
  ) {}

  hasPartialLine(): boolean {
    return this.scanner.hasPartialLine();
  }

  chunk(chunk: Buffer): void {
    let start = 0;
    while (start < chunk.length) {
      const nl = chunk.indexOf(NL, start);
      if (nl === -1) {
        this.partial(chunk.subarray(start));
        return;
      }
      this.segment(chunk.subarray(start, nl + 1));
      start = nl + 1;
    }
  }

  /** Trailing bytes with no newline yet. */
  private partial(bytes: Buffer): void {
    this.scanner.push(bytes);
    if (this.passthrough) {
      this.oversizedBytes(bytes);
      return;
    }
    this.carry.push(bytes);
    if (this.scanner.partialLineOversized()) this.enterOversized();
  }

  /** A segment ending in '\n' — completes exactly one (possibly empty) line. */
  private segment(bytes: Buffer): void {
    const lines = this.scanner.push(bytes);
    const line = lines[0];
    if (this.passthrough) {
      this.oversizedBytes(bytes); // the oversized line's tail
      this.passthrough = false;
      this.carry = [];
    } else if (line === undefined) {
      // An empty line (or a bare "\r"): nothing to evaluate, and its bytes
      // exist only here — they cross exactly as the peer wrote them.
      this.flushCarry();
      this.forward(bytes);
    } else if (line.oversized) {
      // A line that crossed the cap inside this very segment.
      this.enterOversized();
      this.passthrough = false;
      this.oversizedBytes(bytes);
    } else {
      this.carry = []; // a normal line: the handler forwards `line.raw` or not
    }
    if (line !== undefined) this.onLine(line);
  }

  /** Bytes belonging to an oversized line: streamed through, or dropped when refusing. */
  private oversizedBytes(bytes: Buffer): void {
    if (this.refuseOversized) return;
    this.forward(bytes);
  }

  /** The current line just crossed the cap: release (or drop) what is buffered. */
  private enterOversized(): void {
    if (!this.refuseOversized) for (const bytes of this.carry) this.forward(bytes);
    this.carry = [];
    this.passthrough = true;
  }

  private flushCarry(): void {
    for (const bytes of this.carry) this.forward(bytes);
    this.carry = [];
  }

  end(): void {
    this.carry = [];
    this.passthrough = false;
    for (const line of this.scanner.end()) this.onLine(line);
  }
}

/** Rule ids come from the validated policy file, so only an off-shape one is hashed. */
function cappedRuleId(id: string): string {
  return RULE_ID_SHAPE.test(id) ? id : sha256Ref(id);
}

/**
 * A usable JSON-RPC request id, and the ONLY thing that may ever be written
 * to a frozen-schema `request_id` (`string | number`). Everything the proxy
 * keys, correlates or records an id by goes through this predicate first:
 * `true`, `{}`, `[]` and a bare `null` are not ids, and a message carrying
 * one is treated as id-less rather than smuggled into an event.
 */
/**
 * A usable JSON-RPC id, and therefore a legal `request_id` under the frozen
 * schema.
 *
 * Numbers must be FINITE: `1e999` parses to `Infinity`, which
 * `JSON.stringify` writes back as `null` — outside `string | number` — and
 * every such id collapses onto one pending key. A `tools/call` carrying one
 * falls into the invalid-id refusal; anything else is recorded id-less.
 *
 * Finite is the whole test. Requiring a SAFE INTEGER was tried and reverted:
 * it would also reject `1.5`, which JSON-RPC discourages but permits, which
 * this proxy has always evaluated, and which is schema-legal as a
 * `request_id`. Ids beyond 2^53 do lose precision, but that happens in
 * `JSON.parse` before any of this runs — two such ids are already the same
 * double by the time the proxy sees them, so there is nothing here to fix.
 */
function isRpcId(v: unknown): v is string | number {
  if (typeof v === 'string') return true;
  return typeof v === 'number' && Number.isFinite(v);
}

/** A `tools/call` REQUEST (has a usable id) — the only thing the policy answers on. */
function isToolsCallRequest(msg: unknown): msg is ToolsCallRequest {
  return isPlainObject(msg) && msg.method === 'tools/call' && isRpcId(msg.id);
}

/**
 * A `tools/call` carrying an `id` PROPERTY whose value is not a usable
 * JSON-RPC id — `null`, but equally `true`, `1`-less shapes like `{}` and
 * `[]`. None of them is a request (MCP forbids them and the official SDK
 * rejects them) and none is a notification either, so gateway mode refuses
 * them instead of forwarding them — see the module header. Testing only
 * `=== null` left every other shape crossing UNEVALUATED and then landing
 * in the chain with a `request_id` the frozen schema cannot describe.
 */
function isInvalidIdToolsCall(msg: unknown): msg is Record<string, unknown> {
  return isPlainObject(msg) && msg.method === 'tools/call' && 'id' in msg && !isRpcId(msg.id);
}

/**
 * A `tools/call` NOTIFICATION: no `id` property at all, so nothing can be
 * answered on it. Gateway mode still evaluates it against the policy — a
 * deny simply drops it, which is exactly what "no response" already
 * promises the client. See the module header.
 */
function isToolsCallNotification(msg: unknown): msg is Record<string, unknown> {
  return isPlainObject(msg) && msg.method === 'tools/call' && !('id' in msg);
}

/** A c2s REQUEST of any method that takes a `pending` slot (gateway duplicate-id gate). */
function isRpcRequest(msg: unknown): msg is Record<string, unknown> & { method: string; id: string | number } {
  return isPlainObject(msg) && typeof msg.method === 'string' && isRpcId(msg.id);
}

/**
 * The `params` object and tool name of a `tools/call` request. A missing or
 * non-string `params.name` (and a non-object `params`) yields '': the call
 * is evaluated like any other, so `mcp.default` applies and tool globs match
 * as they do for an empty string, instead of crossing unevaluated.
 */
function toolsCallParts(msg: ToolsCallRequest): { params: Record<string, unknown>; name: string } {
  const params = isPlainObject(msg.params) ? msg.params : {};
  return { params, name: typeof params.name === 'string' ? params.name : '' };
}

function asBuffer(chunk: unknown): Buffer {
  return Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk));
}

/* ------------------- minimal-edit line re-serialization ------------------- */

/**
 * WHY THIS EXISTS. Gateway mode is the only place that ever puts different
 * bytes on the wire from the ones it read, and it may only do that for what
 * it deliberately rewrote. `JSON.parse` -> edit -> `JSON.stringify` does
 * NOT satisfy that: every JSON number becomes an IEEE-754 double on the way
 * in and is re-printed on the way out, so re-serializing a whole message to
 * redact one string silently rewrites unrelated numbers elsewhere in it —
 * `12345678901234567890` becomes `12345678901234567000`, `1e400` becomes
 * `null`, a `progressToken` of `9007199254740993` comes out `...992`. The
 * same payload with nothing to redact crosses byte-for-byte, so the filter
 * itself would be the corruption.
 *
 * Instead the ORIGINAL line text is kept and only the subtrees the filter
 * actually replaced are spliced into it, located by scanning the line for
 * the exact character span of each one. Everything the gateway did not
 * touch — numbers above all, but also key order, whitespace and duplicate
 * keys — crosses exactly as the peer wrote it.
 *
 * `JSON.parse` source access (Node 22+) would preserve numbers too, but
 * this package supports Node 20, so a version-independent splice it is.
 * Every step falls back to whole-message re-serialization if it cannot be
 * done exactly; forwarding is never blocked by it.
 */

/** A JSON location inside a message: object keys and array indexes, outermost first. */
type JsonPath = readonly (string | number)[];

/**
 * Structural guard on the number of separate edits collected for one line.
 *
 * It is NOT a work bound: the spans of every edit are resolved in a single
 * walk of the line (`jsonValueSpans`), so the cost of splicing is bounded by
 * the SIZE OF THE LINE, not by how many edits it carries. It only stops
 * `collectDivergences` from building an unbounded path list for a message
 * whose every leaf changed, and it is far above anything the boundary filter
 * produces (one edit per rewritten `content[].text`).
 *
 * The old bound was 32 EDITS, and past it the splice fell back to
 * re-serializing the whole message — which reintroduced exactly the number
 * corruption the splice exists to prevent (`12345678901234567890` ->
 * `...567000`, `1e400` -> `null`, `9007199254740993` -> `...992`) on any
 * result with 33 redactable strings in it. A result that busy is precisely
 * the one most likely to also carry a big integer.
 */
const MAX_LINE_EDIT_PATHS = 100_000;

/** Thrown internally by the span scanner; never escapes `jsonValueSpans`. */
class JsonScanError extends Error {}

/**
 * Locates the exact character span of a value inside a JSON document that
 * has ALREADY been parsed successfully, so it can assume well-formed input
 * and only has to be accurate. Skipping a value is iterative — a deeply
 * nested message costs a counter, never stack frames.
 */
class JsonSpanScanner {
  i = 0;

  constructor(private readonly s: string) {}

  private fail(): never {
    throw new JsonScanError('json span scan failed');
  }

  private ws(): void {
    for (;;) {
      const c = this.s.charCodeAt(this.i);
      // space, \t, \n, \r — the only JSON whitespace
      if (c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d) this.i++;
      else return;
    }
  }

  /**
   * Advance past a string token starting at `i`. Nothing is copied: a big
   * message is mostly strings, and only the KEYS of the object actually
   * being searched are ever materialized (`keyToken`).
   */
  private skipString(): void {
    if (this.s.charCodeAt(this.i) !== 0x22) this.fail(); // '"'
    this.i++;
    for (;;) {
      const c = this.s.charCodeAt(this.i);
      if (Number.isNaN(c)) this.fail();
      this.i++;
      if (c === 0x22) return; // '"'
      if (c === 0x5c) {
        // backslash: the next character is part of the escape
        if (this.i >= this.s.length) this.fail();
        this.i++;
      }
    }
  }

  /** Like `skipString`, but returns the token's RAW text (quotes included). */
  private keyToken(): string {
    const start = this.i;
    this.skipString();
    return this.s.slice(start, this.i);
  }

  /** Advance past a number / true / false / null literal. */
  private primitive(): void {
    const start = this.i;
    for (;;) {
      const c = this.s.charCodeAt(this.i);
      // end of input, ',' '}' ']', or whitespace ends the literal
      if (Number.isNaN(c) || c === 0x2c || c === 0x7d || c === 0x5d) break;
      if (c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d) break;
      this.i++;
    }
    if (this.i === start) this.fail();
  }

  /** Advance past exactly one complete JSON value (containers included). */
  skipValue(): void {
    let depth = 0;
    for (;;) {
      this.ws();
      const c = this.s[this.i];
      if (c === undefined) this.fail();
      if (c === '{' || c === '[') {
        this.i++;
        depth++;
        continue; // read this container's first key/element (or its close)
      }
      if (c === '}' || c === ']') {
        if (depth === 0) this.fail(); // an empty container is closed here
        this.i++;
        depth--;
      } else if (c === '"') {
        this.skipString();
      } else {
        this.primitive();
      }
      // A value (or a whole container) just ended: close every container
      // that ends here, and stop as soon as the outermost one is done.
      for (;;) {
        if (depth === 0) return;
        this.ws();
        const d = this.s[this.i];
        if (d === ',' || d === ':') {
          this.i++;
          break; // more to read at this level
        }
        if (d === '}' || d === ']') {
          this.i++;
          depth--;
          continue;
        }
        this.fail();
      }
    }
  }

  /**
   * Spans of SEVERAL keys of the object starting at `i`, in ONE pass. The
   * last member with a given key wins, exactly as `JSON.parse` resolves
   * duplicate keys. This is what makes the number of edits on a line
   * irrelevant to the cost of splicing them in.
   */
  members(keys: ReadonlySet<string>): Map<string, [number, number]> {
    const wanted = new Map<string, string>();
    for (const k of keys) wanted.set(JSON.stringify(k), k);
    const found = new Map<string, [number, number]>();
    this.ws();
    if (this.s[this.i] !== '{') this.fail();
    this.i++;
    this.ws();
    if (this.s[this.i] === '}') return found;
    for (;;) {
      this.ws();
      const raw = this.keyToken();
      this.ws();
      if (this.s[this.i] !== ':') this.fail();
      this.i++;
      this.ws();
      const start = this.i;
      this.skipValue();
      let key = wanted.get(raw);
      // `raw` covers every unescaped key; only an escaped one needs decoding.
      if (key === undefined && raw.includes('\\')) {
        const decoded = JSON.parse(raw) as string;
        if (keys.has(decoded)) key = decoded;
      }
      if (key !== undefined) found.set(key, [start, this.i]);
      this.ws();
      const c = this.s[this.i];
      if (c === ',') {
        this.i++;
        continue;
      }
      if (c === '}') {
        this.i++;
        return found;
      }
      this.fail();
    }
  }

  /** Spans of EVERY element of the array starting at `i`, in order. */
  elements(): [number, number][] {
    const out: [number, number][] = [];
    this.ws();
    if (this.s[this.i] !== '[') this.fail();
    this.i++;
    this.ws();
    if (this.s[this.i] === ']') return out;
    for (;;) {
      this.ws();
      const start = this.i;
      this.skipValue();
      out.push([start, this.i]);
      this.ws();
      const c = this.s[this.i];
      if (c === ',') {
        this.i++;
        continue;
      }
      if (c === ']') return out;
      this.fail();
    }
  }
}

/** Node of the prefix tree `jsonValueSpans` walks: one container to scan. */
interface SpanTrieNode {
  children: Map<string | number, SpanTrieNode>;
  /** Indexes into the caller's `paths` array that end exactly here. */
  terminals: number[];
}

function newSpanTrieNode(): SpanTrieNode {
  return { children: new Map(), terminals: [] };
}

/**
 * Character spans of MANY paths at once, resolved in a single walk.
 *
 * Locating each path on its own re-scans the line from the start, so N edits
 * cost N x line — which is why the splice used to give up past a fixed edit
 * count and re-serialize the whole message instead (silently rewriting every
 * number in it). Here the paths are merged into a prefix tree and each
 * container is scanned ONCE for all of the children wanted inside it, so the
 * cost is bounded by the size of the line and the number of edits stops
 * mattering. Entries that cannot be located exactly come back undefined; the
 * caller decides what to do about them.
 */
function jsonValueSpans(text: string, paths: readonly JsonPath[]): ([number, number] | undefined)[] {
  const out: ([number, number] | undefined)[] = paths.map(() => undefined);
  const root = newSpanTrieNode();
  paths.forEach((path, index) => {
    let node = root;
    for (const seg of path) {
      let child = node.children.get(seg);
      if (child === undefined) {
        child = newSpanTrieNode();
        node.children.set(seg, child);
      }
      node = child;
    }
    node.terminals.push(index);
  });
  try {
    const sc = new JsonSpanScanner(text);
    const walk = (node: SpanTrieNode, span: [number, number]): void => {
      for (const index of node.terminals) out[index] = span;
      if (node.children.size === 0) return;
      // A JSON value is either an array or an object, so every child key of
      // one node has the same kind.
      const first = node.children.keys().next().value as string | number;
      sc.i = span[0];
      if (typeof first === 'number') {
        const all = sc.elements();
        for (const [seg, child] of node.children) {
          const found = typeof seg === 'number' ? all[seg] : undefined;
          if (found !== undefined) walk(child, found);
        }
      } else {
        const keys = new Set<string>();
        for (const seg of node.children.keys()) if (typeof seg === 'string') keys.add(seg);
        const found = sc.members(keys);
        for (const [seg, child] of node.children) {
          const at = typeof seg === 'string' ? found.get(seg) : undefined;
          if (at !== undefined) walk(child, at);
        }
      }
    };
    walk(root, [0, text.length]);
  } catch {
    /* whatever was resolved before the failure stands; the rest stay undefined */
  }
  return out;
}

/** Character spans of every top-level array element, or undefined. */
function jsonElementSpans(text: string): [number, number][] | undefined {
  try {
    return new JsonSpanScanner(text).elements();
  } catch {
    return undefined;
  }
}

/**
 * The SHORTEST disjoint set of paths at which `next` differs from `prev`.
 *
 * `applyBoundary` promises a changed message is a fresh tree sharing every
 * untouched subtree BY REFERENCE, so `===` is an exact "unchanged" test and
 * the walk only ever descends the spine the filter actually rewrote.
 * Returns false when there are too many edits to splice (the caller then
 * re-serializes the whole message).
 */
function collectDivergences(prev: unknown, next: unknown, path: JsonPath, out: JsonPath[]): boolean {
  if (prev === next) return true;
  if (out.length >= MAX_LINE_EDIT_PATHS) return false;
  if (Array.isArray(prev) && Array.isArray(next) && prev.length === next.length) {
    for (let i = 0; i < prev.length; i++) {
      if (!collectDivergences(prev[i], next[i], [...path, i], out)) return false;
    }
    return true;
  }
  if (isPlainObject(prev) && isPlainObject(next)) {
    const keys = Object.keys(prev);
    const nextKeys = Object.keys(next);
    if (keys.length === nextKeys.length && keys.every((k, i) => nextKeys[i] === k)) {
      for (const k of keys) {
        if (!collectDivergences(prev[k], next[k], [...path, k], out)) return false;
      }
      return true;
    }
  }
  out.push(path);
  return true;
}

/** The value at `path`, or undefined when the path does not resolve. */
function valueAtPath(root: unknown, path: JsonPath): unknown {
  let cur: unknown = root;
  for (const seg of path) {
    if (typeof seg === 'number') {
      if (!Array.isArray(cur)) return undefined;
      cur = cur[seg];
    } else {
      if (!isPlainObject(cur)) return undefined;
      cur = cur[seg];
    }
  }
  return cur;
}

/** `JSON.stringify` that reports failure instead of throwing. */
function tryStringify(value: unknown): string | undefined {
  try {
    const s = JSON.stringify(value);
    return typeof s === 'string' ? s : undefined;
  } catch {
    return undefined;
  }
}

/** The line terminator the line arrived with: '\r\n', '\n', or '' for an unterminated trailing line. */
function lineTerminator(line: ScannedLine): string {
  const raw = line.raw;
  if (raw === undefined) return '\n';
  const cr = line.bytesLen > 0 && raw[line.bytesLen - 1] === 0x0d ? '\r' : '';
  return cr + (raw.length > line.bytesLen ? '\n' : '');
}

/**
 * The bytes to forward for a line whose parsed message the gateway
 * rewrote: the ORIGINAL line with only the rewritten subtrees spliced in.
 * Falls back to re-serializing the whole message when the edits cannot be
 * located exactly — correctness of the FILTER never depends on this, only
 * the fidelity of everything around it.
 */
function spliceRewrittenLine(line: ScannedLine, before: unknown, after: unknown): Buffer {
  const terminator = lineTerminator(line);
  const spliced = spliceRewrittenText(line.text, before, after);
  return Buffer.from((spliced ?? JSON.stringify(after)) + terminator, 'utf8');
}

/**
 * The text-level half of {@link spliceRewrittenLine}, shared with the HTTP
 * gateway (src/proxy/http.ts): the ORIGINAL text with only the subtrees
 * that differ between `before` and `after` spliced in, or `undefined` when
 * the edits cannot be located exactly (the caller then re-serializes).
 */
export function spliceRewrittenText(text: string | null, before: unknown, after: unknown): string | undefined {
  const paths: JsonPath[] = [];
  if (text !== null && collectDivergences(before, after, [], paths) && paths.length > 0) {
    const edits: { start: number; end: number; json: string }[] = [];
    let ok = true;
    // One walk of the line for EVERY edit: the number of edits does not
    // change the cost, so there is no edit count past which the splice has
    // to give up and re-serialize (and thereby corrupt) the whole message.
    const spans = jsonValueSpans(text, paths);
    for (let i = 0; i < paths.length; i++) {
      const path = paths[i]!;
      const span = path.length === 0 ? undefined : spans[i];
      const json = span === undefined ? undefined : tryStringify(valueAtPath(after, path));
      if (span === undefined || json === undefined) {
        ok = false;
        break;
      }
      edits.push({ start: span[0], end: span[1], json });
    }
    if (ok) {
      edits.sort((a, b) => a.start - b.start);
      let out = '';
      let cursor = 0;
      for (const e of edits) {
        if (e.start < cursor) {
          ok = false; // overlapping spans: not the disjoint set we expect
          break;
        }
        out += text.slice(cursor, e.start) + e.json;
        cursor = e.end;
      }
      if (ok) return out + text.slice(cursor);
    }
  }
  return undefined;
}

/**
 * The bytes of a client->server JSON-RPC batch with the refused elements
 * dropped. Same rule as above: the kept elements travel as the CLIENT wrote
 * them, so a refusal elsewhere in the batch cannot silently rewrite the
 * arguments of a call that IS forwarded. When nothing was refused the
 * original line crosses byte-for-byte.
 */
function keptBatchBytes(line: ScannedLine, raw: Buffer, batch: unknown[], keptIndexes: number[]): Buffer {
  if (keptIndexes.length === batch.length) return raw;
  const text = line.text;
  if (text !== null) {
    const spans = jsonElementSpans(text);
    if (spans !== undefined && spans.length === batch.length) {
      const parts = keptIndexes.map((i) => text.slice(spans[i]![0], spans[i]![1]));
      return Buffer.from('[' + parts.join(',') + ']' + lineTerminator(line), 'utf8');
    }
  }
  return Buffer.from(JSON.stringify(keptIndexes.map((i) => batch[i])) + lineTerminator(line), 'utf8');
}

/* ---------------------------- bounded hashing ----------------------------- */

/**
 * Depth past which the proxy stops descending a tree it read off the wire
 * when hashing it.
 *
 * `canonicalJson` recurses, and a result nested a few thousand levels deep
 * overflows the stack. That throw used to take the WHOLE `tool_call` event
 * with it: `handleResponse` hashes before it records, the throw escaped into
 * the fail-open `guarded()` wrapper, the pending entry had already been
 * deleted, and the call vanished from the chain while `verify` still
 * reported PASS — evidence gone, silently, for a hash. A depth-bounded
 * hasher removes the throw: it is byte-identical to `canonicalJson` for
 * every tree within the cap (so `result_hash` still equals
 * `sha256Ref(canonicalJson(result))` for anything an MCP server really
 * sends), and substitutes one marker string for a subtree deeper than this.
 * The recursion is therefore bounded by the constant, not by the wire.
 *
 * 256 is far below Node's stack limit and far above any real MCP payload.
 */
const MAX_HASH_DEPTH = 256;

/** What a subtree deeper than `MAX_HASH_DEPTH` hashes as. Not a payload string: a fixed marker. */
const HASH_DEPTH_CAPPED_MARKER = '[mcp-recorder:hash-depth-capped]';

/**
 * `canonicalJson` with a hard depth bound (see `MAX_HASH_DEPTH`). Identical
 * output for every value within the bound; a deeper subtree becomes
 * `HASH_DEPTH_CAPPED_MARKER`.
 */
function boundedCanonicalJson(value: unknown, depth = 0, capped?: { hit: boolean }): string {
  if (value === null || value === undefined) return 'null';
  const t = typeof value;
  if (t === 'number') return Number.isFinite(value as number) ? JSON.stringify(value) : 'null';
  if (t === 'string' || t === 'boolean') return JSON.stringify(value);
  const container = Array.isArray(value) || t === 'object';
  if (container && depth >= MAX_HASH_DEPTH) {
    // Report it: past this point the hash no longer distinguishes subtrees,
    // and the event has to say so rather than look like an ordinary one.
    if (capped !== undefined) capped.hit = true;
    return JSON.stringify(HASH_DEPTH_CAPPED_MARKER);
  }
  if (Array.isArray(value)) {
    return (
      '[' +
      value.map((v) => (v === undefined ? 'null' : boundedCanonicalJson(v, depth + 1, capped))).join(',') +
      ']'
    );
  }
  if (t === 'object') {
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj)
      .filter((k) => obj[k] !== undefined)
      .sort();
    return (
      '{' +
      keys.map((k) => JSON.stringify(k) + ':' + boundedCanonicalJson(obj[k], depth + 1, capped)).join(',') +
      '}'
    );
  }
  throw new TypeError(`boundedCanonicalJson: unsupported type ${t}`);
}

type Direction = 'client_to_server' | 'server_to_client';

const RUNNERS = new Set(['node', 'npx', 'tsx', 'bun', 'deno', 'bunx']);
// Runner flags with no value (skipped outright) vs. flags that consume the
// next argv token as their value (that token is skipped too).
const RUNNER_BARE_FLAGS = new Set(['-y', '--yes', '-q', '--quiet']);
const RUNNER_VALUE_FLAGS = new Set(['-p', '--package']);
const MAX_PENDING = 10_000;
/**
 * Gateway mode: cap on concurrently parked holds. The map is keyed by
 * request id and only shrinks when a hold is resolved, so a client that
 * fires hold-matching calls it never answers for would otherwise grow it
 * without bound. Beyond the cap a hold-matching call is refused (deny),
 * fail-closed — documented in docs/gateway.md.
 */
export const MAX_HOLDS = 256;
/** Reason a call is refused instead of held because the cap above is reached. */
const TOO_MANY_HOLDS_REASON = 'too many pending holds';
/** Reason a call is refused instead of held because finalize() already began. */
const SESSION_END_HOLD_REASON = 'session_end (hold not started)';
/**
 * Why a `tools/call` is refused for reusing a JSON-RPC id that is still in
 * flight: the id is parked as a hold, or it belongs to a request the server
 * has not answered yet. See the module header (DUPLICATE REQUEST IDS).
 */
export type DuplicateIdState = 'held' | 'pending';
const DUPLICATE_ID_REASON: Record<DuplicateIdState, string> = {
  held: 'a tools/call with this id is already held for approval',
  pending: 'a tools/call with this id is already in flight',
};
/** `error.type` of both events recorded for a refused duplicate id (free-form string, v1). */
const DUPLICATE_ID_ERROR_TYPE = 'duplicate_id';

/** `GatewayOutcome.refusal` for a `tools/call` whose id is not a usable one. */
const INVALID_ID_REFUSAL = 'invalid_request_id';
/**
 * `error.type` for an in-flight request dropped because `pending` hit
 * MAX_PENDING. Additive and free-form under the frozen schema, like
 * `duplicate_id` and `unanswered`: the point is that the chain says the
 * request was dropped rather than losing it silently.
 */
const EVICTED_ERROR_TYPE = 'evicted';

/**
 * `error.type` on an event whose `result_hash` could not be computed (free-
 * form string, v1). The event is recorded anyway with `result_hash` set to
 * the hash of canonical `null`; this marker is what tells a reader that the
 * hash does not describe the result. Losing the whole event instead is the
 * bug this exists to prevent.
 */
const RESULT_HASH_FAILED_ERROR_TYPE = 'result_hash_failed';

/**
 * Cap on the `params.name` a `tools/call` may carry INTO the policy engine.
 *
 * `mcpRuleMatches` runs every `match.tool` glob against this string with
 * `globMatch`, which compiles the glob to a V8 RegExp — a BACKTRACKING
 * engine — and matches it ON THE PROXY THREAD. A policy that validates
 * clean (`tool: "*read*write*exec*"` is three legal wildcards) is cubic in
 * the length of the subject when it fails to match, so an uncapped
 * `params.name` straight off the wire is a remote freeze of the whole
 * gateway: forwarding, holds, the boundary filter and every concurrent
 * call stop until the regex returns. `match.args` values are already capped
 * (`REGEX_VALUE_CAP`) and matched off-thread under a deadline
 * (`../policy/regex-guard.ts`), and the server name reaching the engine is
 * `structuralString`-capped where it is learned, so the tool name was the
 * one uncapped wire value left on an in-thread matcher.
 *
 * The cap is `STRUCTURAL_STRING_MAX_LEN` — the same 128 characters above
 * which `structuralString` already refuses to keep a tool name verbatim in
 * an event — so the engine never sees a name the evidence store would not
 * have kept either.
 *
 * An over-long name is REFUSED, never truncated: truncating would hand the
 * engine a DIFFERENT tool name from the one the server would execute, which
 * is a policy bypass (a 200-character name whose first 128 characters read
 * `safe_read...` is not the tool that runs). The refusal is a fail-closed
 * deny — the gateway declining to guess, not an operator decision.
 */
const MAX_EVALUATED_TOOL_NAME_LEN = STRUCTURAL_STRING_MAX_LEN;

/** True for a `params.name` the policy engine must not be handed (see above). */
function toolNameTooLong(name: string): boolean {
  return name.length > MAX_EVALUATED_TOOL_NAME_LEN;
}

/**
 * Reason of the fail-closed deny an over-long tool name gets. It carries the
 * LENGTH, never the name: the text travels back to the client and, scrubbed,
 * into the evidence store.
 */
function toolNameTooLongReason(length: number): string {
  return (
    `tools/call params.name is ${length} characters; the gateway evaluates at most` +
    ` ${MAX_EVALUATED_TOOL_NAME_LEN} (the name is refused, never truncated)`
  );
}

/**
 * The text the model sees for a `tools/call` refused because its id is
 * still in use. Like every other synthesized text it names the tool as the
 * CLIENT wrote it (and the id it chose); events carry the capped forms.
 */
export function duplicateIdText(tool: string, id: string | number, state: DuplicateIdState): string {
  return (
    `mcp-recorder gateway: tools/call "${tool}" refused: ${DUPLICATE_ID_REASON[state]}.` +
    ` JSON-RPC request id ${JSON.stringify(id)} must be unique while in flight; retry with a fresh id.`
  );
}

/**
 * A `tools/call` with `id: null` is refused with this JSON-RPC error
 * (-32600 Invalid Request); JSON-RPC permits a null id on an error
 * response. See the module header (UNUSABLE REQUEST IDS).
 */
export const NULL_ID_TOOLS_CALL_MESSAGE =
  'mcp-recorder gateway: tools/call with a null id is not a valid request';

/**
 * The same refusal for every OTHER unusable `id` value — `true`, `{}`, `[]`
 * and anything else JSON can carry that is not a string or a number.
 */
export const INVALID_ID_TOOLS_CALL_MESSAGE =
  'mcp-recorder gateway: tools/call with an id that is neither a string nor a number is not a valid request';

/**
 * The -32600 response for a `tools/call` whose id is unusable. The response
 * id is ALWAYS `null`: the request carried no id JSON-RPC could answer on,
 * and echoing the offending value back would put it on the wire again.
 */
function invalidIdErrorResponse(id: unknown): Record<string, unknown> {
  return {
    jsonrpc: '2.0',
    id: null,
    error: {
      code: -32600,
      message: id === null ? NULL_ID_TOOLS_CALL_MESSAGE : INVALID_ID_TOOLS_CALL_MESSAGE,
    },
  };
}

/**
 * A client line the gateway could not evaluate — it grew past the line cap,
 * so it was never buffered and never parsed — is REFUSED with this
 * -32600 error and none of its bytes reach the server. See the module
 * header (LINES TOO BIG TO EVALUATE).
 */
export const OVERSIZED_LINE_MESSAGE =
  'mcp-recorder gateway: this line is larger than the gateway can buffer, so it could not be' +
  ' evaluated against the policy and was refused (enforcement fails closed); send a smaller request';

/**
 * The sibling case: a line that IS small enough to buffer but is not JSON, so
 * the policy cannot be shown it either. Refused for the same reason and in
 * the same way — a line that skips the parser also skips every id gate below
 * it, so forwarding one reopens the duplicate-id holes as well.
 */
export const UNPARSEABLE_LINE_MESSAGE =
  'mcp-recorder gateway: this line is not valid JSON, so it could not be evaluated against the ' +
  'policy and was refused (enforcement fails closed); send a valid JSON-RPC message';

/**
 * A non-`tools/call` request refused for reusing a JSON-RPC id that is still
 * in flight. A tool call gets an isError tool RESULT (the model reads it);
 * every other method gets a plain JSON-RPC error, which is what its caller
 * is waiting for.
 */
export const DUPLICATE_REQUEST_ID_MESSAGE =
  'mcp-recorder gateway: a request with this id is already in flight; JSON-RPC request ids must be' +
  ' unique while in flight — retry with a fresh id';

/**
 * A JSON-RPC batch element that is ITSELF an array is not a request, and a
 * server that flattens nested arrays would run whatever is inside it — past
 * a gateway that never looked. Refused.
 */
export const NESTED_BATCH_MESSAGE =
  'mcp-recorder gateway: a nested array inside a JSON-RPC batch is not a valid request and was refused';

/** `{"jsonrpc":"2.0","id":<id|null>,"error":{"code":-32600,...}}`. */
function invalidRequestResponse(id: string | number | null, message: string): Record<string, unknown> {
  return { jsonrpc: '2.0', id, error: { code: -32600, message } };
}

// Must cover the recorder's full retry run (~6s, src/capture/recorder.ts) so a
// contended store delays session_end rather than losing it.
const CLOSE_TIMEOUT_MS = 8_000;
/**
 * Overall credential-fingerprint cap. Env-derived fingerprints are capped on
 * their own, and lower (`ENV_CREDENTIAL_FINGERPRINT_CAP` in the redactor),
 * so a wrapped server with many credential-shaped env vars cannot fill the
 * whole budget and silently crowd out the argv/URL-derived fingerprints
 * pushed afterward — those must always have room to append, up to this total
 * (P2 fix).
 */
const MAX_CREDENTIAL_FINGERPRINTS = 64;
/** result_hash for a synthesized "unanswered" event: sha256 of canonical `null`. */
const NULL_RESULT_HASH = sha256Ref(canonicalJson(null));

/** Exit code for a child terminated by a signal: 128 + signal number (POSIX convention). */
function signalExitCode(signal: NodeJS.Signals): number {
  const num = (osConstants.signals as Partial<Record<NodeJS.Signals, number>>)[signal];
  return num !== undefined ? 128 + num : 1;
}

/** Exit code for a command that failed to spawn at all. */
function spawnErrorExitCode(code: string | undefined): number {
  if (code === 'ENOENT') return 127;
  if (code === 'EACCES') return 126;
  return 1;
}

/**
 * Best-effort logical server name from argv. For a bare command this is just
 * its basename; for a runner (`npx`, `node`, `tsx`, ...) it walks past known
 * runner flags (e.g. the `-y` in the README's own `npx -y <pkg>` wrapping)
 * to find the first positional argument, which is the actual server.
 */
function deriveServerName(command: string[]): string {
  const first = basename(command[0] ?? '');
  // Strips script/executable extensions before the RUNNERS check, so a
  // Windows-installed runner shim (`npx.cmd`, `node.exe`, `tsx.bat`, ...) is
  // still recognized as `npx`/`node`/`tsx` the same way a bare POSIX name is.
  const firstNoExt = first.replace(/\.(?:[cm]?(?:js|ts)|exe|cmd|bat)$/i, '');
  if (!RUNNERS.has(firstNoExt.toLowerCase())) return first;
  for (let i = 1; i < command.length; i++) {
    const tok = command[i] ?? '';
    if (RUNNER_BARE_FLAGS.has(tok) || tok.startsWith('--package=')) continue;
    if (RUNNER_VALUE_FLAGS.has(tok)) {
      i++; // skip the flag's value too
      continue;
    }
    return basename(tok);
  }
  return first;
}

function round2(n: number): number {
  return Math.round(n * 100) / 100;
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/**
 * Pending-request map key. JSON-RPC ids may be a number or a string, and
 * `1` and `"1"` are distinct ids — String(id) alone would collapse them, so
 * the id's type is folded into the key too.
 */
function pendingKey(prefix: 'c2s:' | 's2c:', id: string | number): string {
  return prefix + (typeof id === 'number' ? 'n:' : 's:') + String(id);
}

export async function runStdioProxy(opts: StdioProxyOpts): Promise<number> {
  const proxyStdin: Readable = opts.stdin ?? process.stdin;
  const proxyStdout: Writable = opts.stdout ?? process.stdout;
  const proxyStderr: Writable = opts.stderr ?? process.stderr;
  const env = opts.env ?? process.env;
  const { recorder, redactor } = opts;

  const diag = (msg: string): void => {
    try {
      proxyStderr.write(`[mcp-recorder] ${msg}\n`);
    } catch {
      /* even diagnostics are fail-open */
    }
  };
  let tapErrorLogged = false;
  const tapError = (err: unknown): void => {
    if (tapErrorLogged) return;
    tapErrorLogged = true;
    diag(`tap error (recording degraded, traffic unaffected): ${err instanceof Error ? err.stack ?? err.message : String(err)}`);
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

  const initialServerName = opts.serverName || deriveServerName(opts.command);
  const fingerprint = sha256Ref(
    `${osUser}\0${host}\0${opts.identityLabel || ''}\0${initialServerName}`,
  );

  // Env-derived fingerprints come from the redactor's single collector, which
  // owns the whole policy: the credential-name shape, the value-length floor,
  // its own cap (reserving room below MAX_CREDENTIAL_FINGERPRINTS for the
  // argv/URL-derived fingerprints pushed afterward, P2 fix), and the
  // exclusion of the recorder's OWN configuration variables —
  // MCP_RECORDER_SINK_TOKEN and its family are never fingerprinted, because
  // the agent never sees them and the sink would otherwise be shipped a
  // reversible copy of its own bearer token on every event.
  const credentialFingerprints: { name: string; ref: string }[] = [];
  try {
    credentialFingerprints.push(...collectEnvCredentialFingerprints(env, redactor));
  } catch (err) {
    tapError(err);
  }

  // Wrapped command argv leak fix (P1): a raw argv.join(' ') stamped on every
  // event verbatim would leak `--api-key sk-...` / `--token ...` / DSNs with
  // userinfo. scrubArgv() hashes credential-shaped elements and strips URL
  // userinfo; every replaced piece is also fingerprinted so `query` finds it.
  let scrubbedCommand = opts.command.join(' ');
  try {
    const scrubbedArgv = scrubArgv(opts.command, redactor);
    scrubbedCommand = scrubbedArgv.command;
    for (const fp of scrubbedArgv.fingerprints) {
      if (credentialFingerprints.length >= MAX_CREDENTIAL_FINGERPRINTS) break;
      credentialFingerprints.push(fp);
    }
  } catch (err) {
    tapError(err);
  }

  // Mutable bits learned from the initialize handshake.
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
    if (credentialFingerprints.length > 0) {
      id.credential_fingerprints = credentialFingerprints.map((c) => ({ ...c }));
    }
    if (opts.actor !== undefined) stampActor(id, opts.actor);
    return id;
  };

  const currentServer = (): ServerContext => {
    const server: ServerContext = {
      name: opts.serverName || learnedServerName || initialServerName,
      command: scrubbedCommand,
      transport: 'stdio',
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

  /* ------------------------------- spawn ---------------------------------- */

  // Child PATH: add the directory of the Node binary running this proxy, on
  // every platform, when it isn't already there. A wrapped command like
  // "npx" needs to resolve to a sibling npx/npx.cmd even when this proxy
  // itself was launched by an absolute path to Node with a thin PATH
  // (nvm/fnm shims, `wsl.exe -e`, some Windows MCP client launchers). It is
  // appended, so it never shadows something the operator put earlier on
  // PATH on purpose — except on WSL, where it goes ahead of the Windows
  // interop entries (see withNodeDirOnPath).
  const spawnEnv = withNodeDirOnPath(env, process.execPath);

  // On win32, a .cmd/.bat shim (npx, npm, uvx, ... installed as such) can't
  // be exec'd directly without `shell: true` (Node's CVE-2024-27980
  // hardening throws EINVAL) — see src/proxy/spawn.ts. spawnWrapped routes
  // that case through cmd.exe. The event schema's recorded command/server
  // name (scrubbedCommand/deriveServerName, above) always stays the
  // operator's original argv, never cmd.exe — this diagnostic line is purely
  // informational.
  const spawnPlan = planSpawn(opts.command, spawnEnv, process.platform);
  if (spawnPlan.options.windowsVerbatimArguments) {
    diag(`spawning "${opts.command[0]}" via cmd.exe (resolved to a .cmd/.bat shim)`);
  }
  const child = spawnWrapped(opts.command, spawnEnv, spawnPlan);

  // Gateway mode (record --policy) is wired further down, once the tap
  // closures it shares exist; nothing flows before this function returns,
  // so attaching its Transforms later loses no bytes. Without a policy the
  // forwarding below is exactly the M0 recorder.
  const gateway = opts.gateway;
  /** Gateway mode's server->client Transform (the EPIPE handler unpipes it). */
  let s2cTransform: Transform | undefined;
  /** Gateway mode: set once the client's read end is gone; synthesized writes stop. */
  let clientGone = false;
  /**
   * Gateway mode: set at the TOP of finalize(), before the holds are
   * resolved. From then on a `tools/call` that would be parked is refused
   * instead — a hold started after finalize() began would never be
   * resolved (its file would stay pending, its poller would outlive the
   * session, and nothing would be recorded for the call).
   */
  let sessionClosing = false;
  /** Gateway mode: resolve every parked hold as `session_end` (idempotent). */
  let resolveAllHolds: (() => void) | undefined;
  /**
   * Gateway mode with credential brokering: drop every resolved token the
   * reverse scrub is holding. Residency ends with the session rather than
   * with the retention window. JS strings cannot be reliably zeroed, so the
   * claim is that nothing references them any more, not that the bytes are
   * gone from the heap.
   */
  let forgetBrokeredTokens: (() => void) | undefined;

  if (gateway === undefined) {
    // Forwarding: plain pipes, untouched. (pipe() ends child.stdin when
    // proxyStdin ends, which is exactly the MCP stdio shutdown convention.)
    proxyStdin.pipe(child.stdin);
    child.stdout.pipe(proxyStdout, { end: false });
  }
  child.stderr.pipe(proxyStderr, { end: false });

  // A dying child can EPIPE its stdin while the client is still writing;
  // that must never crash the proxy.
  child.stdin.on('error', (err: NodeJS.ErrnoException) => {
    if (err.code !== 'EPIPE' && err.code !== 'ERR_STREAM_DESTROYED') {
      diag(`child stdin error: ${err.message}`);
    }
  });
  proxyStdin.on('error', (err: Error) => diag(`stdin error: ${err.message}`));
  child.stdout.on('error', (err: Error) => diag(`child stdout error: ${err.message}`));
  child.stderr.on('error', (err: Error) => diag(`child stderr error: ${err.message}`));

  // The MCP client can close its read end of our stdout/stderr at any time
  // (it exited, it stopped reading, a downstream pipe broke). .pipe()'s
  // destination gets no default 'error' listener, so without one an EPIPE
  // here is an unhandled 'error' event — it crashes the whole proxy, drops
  // whatever was queued, and session_end never gets written. Both directions
  // must survive it.
  const isEpipeLike = (err: NodeJS.ErrnoException): boolean =>
    err.code === 'EPIPE' || err.code === 'ERR_STREAM_DESTROYED';
  proxyStdout.on('error', (err: NodeJS.ErrnoException) => {
    if (!isEpipeLike(err)) {
      diag(`stdout error: ${err.message}`);
      return;
    }
    // The client is gone. Stop feeding it, and end the child's stdin per the
    // stdio shutdown convention so the server winds down on its own; the
    // normal child 'close' -> finalize path then seals the session.
    // unpipe() can leave child.stdout paused even though the tap's own
    // 'data' listener is still attached (and Node's ChildProcess delays its
    // 'close' event until every stdio stream is drained) — resume() keeps
    // it flowing into the tap and lets 'close' fire normally.
    try {
      if (gateway === undefined) {
        child.stdout.unpipe(proxyStdout);
        child.stdout.resume();
      } else if (s2cTransform !== undefined) {
        // Same idea one hop upstream: keep the Transform draining (it still
        // records) while nothing reaches the client any more.
        s2cTransform.unpipe(proxyStdout);
        s2cTransform.resume();
      }
    } catch {
      /* fail-open */
    }
    clientGone = true;
    try {
      resolveAllHolds?.();
    } catch (err) {
      tapError(err);
    }
    try {
      if (!child.stdin.writableEnded) child.stdin.end();
    } catch {
      /* fail-open */
    }
  });
  proxyStderr.on('error', (err: NodeJS.ErrnoException) => {
    if (!isEpipeLike(err)) {
      diag(`stderr error: ${err.message}`);
      return;
    }
    // Diagnostics/child stderr have nowhere to go; stop piping and keep
    // draining the child's stderr so it never blocks on a full pipe.
    try {
      child.stderr.unpipe(proxyStderr);
    } catch {
      /* fail-open */
    }
    try {
      child.stderr.resume();
    } catch {
      /* fail-open */
    }
  });

  /* ------------------------------ tap state ------------------------------- */

  // Pending requests keyed direction-aware: 'c2s:<id>' for client-initiated,
  // 's2c:<id>' for server-initiated. Responses always arrive on the opposite
  // stream from the request that opened them.
  const pending = new Map<string, PendingEntry>();
  let pendingEvictWarned = false;
  /**
   * Make room for one entry. A gateway-forwarded `tools/call` is the entry
   * the s2c side MUST still find: its response carries the tool result the
   * boundary filter has to scan before the client sees it, and its
   * `tool_call` event. So the OLDEST NON-GATEWAY entry is evicted first —
   * a flood of server->client requests (10 000 `ping`s, say) can no longer
   * push an in-flight gateway call out of the map and let its result cross
   * unfiltered. Only when every entry is a gateway call does the oldest one
   * go. The scan is O(n) in the worst case, which needs MAX_PENDING
   * concurrent gateway tool calls to reach at all; the common case stops at
   * the first entry.
   */
  const evictOnePending = (): void => {
    let victim: string | undefined;
    for (const [key, entry] of pending) {
      if (entry.gateway === undefined) {
        victim = key;
        break;
      }
    }
    if (victim === undefined) victim = pending.keys().next().value as string | undefined;
    if (victim !== undefined) {
      // Seal before dropping. This is the same failure `registerPending`
      // guards against — an in-flight request vanishing from the chain while
      // its real response lands as an orphan — on the one path that guard
      // does not cover.
      const entry = pending.get(victim);
      pending.delete(victim);
      if (entry !== undefined) {
        try {
          sealPending(entry, EVICTED_ERROR_TYPE, round2(performance.now() - entry.t0));
        } catch (err) {
          tapError(err);
        }
      }
    }
    if (!pendingEvictWarned) {
      pendingEvictWarned = true;
      diag(`pending request map exceeded ${MAX_PENDING} entries; evicting oldest`);
    }
  };
  const registerPending = (key: string, entry: PendingEntry): void => {
    if (pending.size >= MAX_PENDING) evictOnePending();
    // Gateway mode NEVER silently overwrites a live pending slot. The
    // duplicate-id refusals upstream mean this should be unreachable; if a
    // path ever does reach it, the displaced request is sealed as
    // `duplicate_id` rather than vanishing from the chain with its real
    // response left to land as an orphan. Record mode keeps its documented
    // last-writer-wins map.
    if (gateway !== undefined) {
      const displaced = pending.get(key);
      if (displaced !== undefined && displaced !== entry) {
        pending.delete(key);
        try {
          sealPending(displaced, DUPLICATE_ID_ERROR_TYPE, round2(performance.now() - displaced.t0));
        } catch (err) {
          tapError(err);
        }
        diag(
          `gateway: a "${displaced.method}" request was still in flight on id` +
            ` ${structuralString(String(displaced.id), 'identifier')}; sealed as` +
            ` ${DUPLICATE_ID_ERROR_TYPE} before the slot was reused`,
        );
      }
    }
    pending.set(key, entry);
  };

  /**
   * Seal one pending request that will never get its real response, so the
   * chain never silently drops in-flight work: a `tools/call` becomes a
   * `tool_call` event, everything else (including an unanswered
   * `initialize`) an `rpc` event — both `is_error: true` with
   * `error.type` = `errorType` (a free-form string under the frozen
   * schema), `result_hash` the hash of canonical `null` and, for a
   * `tool_call`, `result: null`. The shutdown sweep passes 'unanswered';
   * gateway mode passes 'duplicate_id' when an approved hold reclaims a
   * pending slot a same-id call had taken (see the module header). The
   * caller owns removing the entry from `pending`.
   */
  const sealPending = (entry: PendingEntry, errorType: string, durationMs: number): void => {
    if (entry.method === 'tools/call') {
      const tool = entry.toolName ?? '';
      const reqParams = isPlainObject(entry.params) ? entry.params : {};
      const attributes: Attributes = {
        'gen_ai.operation.name': 'execute_tool',
        'gen_ai.tool.name': tool,
        'gen_ai.tool.call.id': String(entry.id),
        'mcp.method.name': 'tools/call',
        'rpc.system': 'jsonrpc',
        'error.type': errorType,
      };
      if (entry.gateway !== undefined) {
        attributes['cresec.policy.decision'] = entry.gateway.decision;
        if (entry.gateway.rule_id !== undefined) {
          attributes['cresec.policy.rule_id'] = entry.gateway.rule_id;
        }
      }
      const ev: ToolCallEvent = {
        ...base('tool_call', attributes),
        kind: 'tool_call',
        tool,
        request_id: entry.id,
        args: scrubToolArguments(redactor, reqParams.arguments ?? {}),
        result_hash: NULL_RESULT_HASH,
        result: null,
        is_error: true,
        duration_ms: durationMs,
        error: { type: errorType },
      };
      if (entry.gateway !== undefined) ev.gateway = { ...entry.gateway };
      record(ev);
      return;
    }
    const ev: RpcEvent = {
      ...base('rpc', {
        'mcp.method.name': entry.method,
        'rpc.system': 'jsonrpc',
        'rpc.jsonrpc.request_id': String(entry.id),
        'error.type': errorType,
      }),
      kind: 'rpc',
      method: entry.method,
      request_id: entry.id,
      params: redactor.scrub(entry.params ?? null),
      result_hash: NULL_RESULT_HASH,
      is_error: true,
      duration_ms: durationMs,
      error: { type: errorType },
    };
    record(ev);
  };

  const protocolError = (
    direction: Direction,
    reason: ProtocolErrorEvent['reason'],
    bytesLen: number,
    lineHashHex: string,
  ): void => {
    const ev: ProtocolErrorEvent = {
      ...base('protocol_error', { 'rpc.system': 'jsonrpc' }),
      kind: 'protocol_error',
      direction,
      reason,
      bytes_len: bytesLen,
      line_hash: 'sha256:' + lineHashHex,
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
    line: ScannedLine,
    /** Gateway mode: what the boundary filter did to this tools/call result. */
    boundary?: BoundaryReport,
  ): void => {
    const id = msg.id as string | number; // guaranteed by the isRpcId gate in handleMessage
    // Client-initiated requests are answered server->client and vice versa.
    const key = pendingKey(arrivedOn === 'server_to_client' ? 'c2s:' : 's2c:', id);
    const entry = pending.get(key);
    if (!entry) {
      protocolError(arrivedOn, 'orphan_response', line.bytesLen, line.lineHashHex);
      return;
    }
    pending.delete(key);

    const rawResult = 'result' in msg ? msg.result : undefined;
    const rawError = 'error' in msg ? msg.error : undefined;
    const isError =
      rawError !== undefined ||
      (isPlainObject(rawResult) && rawResult.isError === true);
    // The hash must never cost us the event. `boundedCanonicalJson` cannot
    // overflow the stack on a deep tree, and if hashing fails anyway the
    // event is still recorded — with `error.type` saying the hash is a
    // placeholder — instead of disappearing from the chain behind a
    // fail-open catch while `verify` reports PASS.
    let resultHash: string;
    let hashFailed = false;
    const hashCapped = { hit: false };
    try {
      resultHash = sha256Ref(boundedCanonicalJson(rawResult ?? rawError ?? null, 0, hashCapped));
    } catch (err) {
      resultHash = NULL_RESULT_HASH;
      hashFailed = true;
      tapError(err);
    }
    const durationMs = round2(performance.now() - entry.t0);

    if (entry.method === 'initialize') {
      const reqParams = isPlainObject(entry.params) ? entry.params : {};
      const clientInfo = isPlainObject(reqParams.clientInfo) ? reqParams.clientInfo : {};
      const res = isPlainObject(rawResult) ? rawResult : {};
      const serverInfo = isPlainObject(res.serverInfo) ? res.serverInfo : {};
      // Remember for subsequent events' identity/server context. Capped here
      // (P0): these are copied verbatim off the wire and reused on every
      // later event, so an oversized/malformed value is capped once, at the
      // point it's learned — every downstream use (this event's own
      // client_name/server_name below, plus identity/server context on every
      // later event) inherits the capped value for free.
      if (typeof clientInfo.name === 'string') {
        clientName = structuralString(clientInfo.name, 'identifier');
      }
      if (typeof clientInfo.version === 'string') {
        clientVersion = structuralString(clientInfo.version, 'version');
      }
      if (typeof serverInfo.name === 'string') {
        learnedServerName = structuralString(serverInfo.name, 'identifier');
      }
      if (typeof serverInfo.version === 'string') {
        learnedServerVersion = structuralString(serverInfo.version, 'version');
      }

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
      if (typeof protoVersion === 'string') {
        ev.protocol_version = structuralString(protoVersion, 'protocol_version');
      }
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
      else if (hashFailed) attributes['error.type'] = RESULT_HASH_FAILED_ERROR_TYPE;
      // Gateway mode (additive): the decision taken at request time plus the
      // boundary report. `result`/`result_hash` stay the RAW server result;
      // a rewritten delivery is only ever described by
      // `gateway.boundary.delivered_result_hash`.
      let gatewayOutcome: GatewayOutcome | undefined =
        entry.gateway !== undefined ? { ...entry.gateway } : undefined;
      if (boundary !== undefined) {
        gatewayOutcome = gatewayOutcome ?? { decision: 'allow' };
        gatewayOutcome.boundary = boundary;
      }
      if (gatewayOutcome !== undefined) {
        attributes['cresec.policy.decision'] = gatewayOutcome.decision;
        if (gatewayOutcome.rule_id !== undefined) {
          attributes['cresec.policy.rule_id'] = gatewayOutcome.rule_id;
        }
      }
      // Request-time decisions that have no field on the frozen schema: today
      // the credential swap's id/decision_id/destination. Namespaced, so they
      // cannot collide with the keys set above.
      if (entry.attributes !== undefined) Object.assign(attributes, entry.attributes);
      const ev: ToolCallEvent = {
        ...base('tool_call', attributes),
        kind: 'tool_call',
        tool,
        request_id: id,
        args: scrubToolArguments(redactor, reqParams.arguments ?? {}),
        result_hash: resultHash,
        result: redactor.scrub(rawResult ?? null),
        is_error: isError,
        duration_ms: durationMs,
        ...(hashCapped.hit ? { result_hash_depth_capped: true as const } : {}),
      };
      if (rawError !== undefined) ev.error = errorInfo(rawError);
      else if (hashFailed) ev.error = { type: RESULT_HASH_FAILED_ERROR_TYPE };
      if (gatewayOutcome !== undefined) ev.gateway = gatewayOutcome;
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
      ...(hashCapped.hit ? { result_hash_depth_capped: true as const } : {}),
      is_error: isError,
      duration_ms: durationMs,
    };
    if (rawError !== undefined) ev.error = errorInfo(rawError);
    else if (hashFailed) ev.error = { type: RESULT_HASH_FAILED_ERROR_TYPE };
    record(ev);
  };

  const handleMessage = (
    msg: unknown,
    direction: Direction,
    line: ScannedLine,
    gateway?: GatewayOutcome,
  ): void => {
    if (Array.isArray(msg)) {
      // JSON-RPC batch — handle each element independently.
      for (const el of msg) handleMessage(el, direction, line);
      return;
    }
    if (!isPlainObject(msg)) return; // not a JSON-RPC message; ignore quietly
    const hasMethod = typeof msg.method === 'string';
    const id = msg.id;
    // `isRpcId`, not `!= null`: the frozen schema's `request_id` is
    // `string | number`, so a message carrying `true`, `{}` or `[]` there is
    // recorded as an id-LESS message (one `notification` event) rather than
    // writing a value into `request_id` the schema cannot describe. This is
    // the recording half of the gateway's unusable-id refusal, and it holds
    // in record mode too — where nothing is refused, but nothing invalid is
    // written either.
    const hasId = isRpcId(id);

    if (hasMethod && hasId) {
      // Request: register pending under the direction it was sent on. The
      // method/tool name is capped HERE (P0), once, at capture time: every
      // downstream event built from this entry (the eventual response event
      // AND the synthetic 'unanswered' event sealed at shutdown, see
      // emitUnanswered below) reads `entry.method`/`entry.toolName`, so
      // capping the source field once covers both for free.
      const keyPrefix = direction === 'client_to_server' ? 'c2s:' : 's2c:';
      const reqId = id;
      const params = msg.params;
      const entry: PendingEntry = {
        method: structuralString(msg.method as string, 'identifier'),
        params,
        t0: performance.now(),
        id: reqId,
      };
      if (isPlainObject(params) && typeof params.name === 'string') {
        entry.toolName = structuralString(params.name, 'identifier');
      }
      registerPending(pendingKey(keyPrefix, reqId), entry);
      return;
    }
    if (hasMethod) {
      const method = structuralString(msg.method as string, 'identifier');
      const ev: NotificationEvent = {
        ...base('notification', {
          'mcp.method.name': method,
          'rpc.system': 'jsonrpc',
        }),
        kind: 'notification',
        method,
        direction,
        params: redactor.scrub(msg.params ?? null),
        // Only a refused `tools/call` notification carries this; see the
        // field's comment in the schema for why it cannot be a
        // `policy_decision` event instead.
        ...(gateway === undefined ? {} : { gateway }),
      };
      record(ev);
      return;
    }
    if (hasId && ('result' in msg || 'error' in msg)) {
      handleResponse(msg, direction, line);
    }
  };

  const handleLine = (line: ScannedLine, direction: Direction): void => {
    if (line.oversized) {
      protocolError(direction, 'oversized', line.bytesLen, line.lineHashHex);
      return;
    }
    if (line.text === null) return;
    let msg: unknown;
    try {
      msg = JSON.parse(line.text);
    } catch {
      protocolError(direction, 'unparseable', line.bytesLen, line.lineHashHex);
      return;
    }
    handleMessage(msg, direction, line);
  };

  const c2sScanner = new LineScanner();
  const s2cScanner = new LineScanner();
  const tap = (scanner: LineScanner, direction: Direction) => (chunk: Buffer): void => {
    try {
      for (const line of scanner.push(chunk)) handleLine(line, direction);
    } catch (err) {
      tapError(err);
    }
  };
  if (gateway === undefined) {
    proxyStdin.on('data', tap(c2sScanner, 'client_to_server'));
    child.stdout.on('data', tap(s2cScanner, 'server_to_client'));
  }

  /* ------------------------------- gateway -------------------------------- */

  if (gateway !== undefined) {
    const { holdStore } = gateway;
    const loaded = gateway.policy;
    // A policy without an `mcp` section behaves like `mcp: {}` (allow all,
    // default boundary); the CLI refuses such a policy before spawning.
    const mcp: McpPolicy =
      loaded.policy.mcp ?? (normalizePolicy({ version: 1, mcp: {} }).mcp as McpPolicy);
    const boundaryDeps: BoundaryDeps = {
      secretPatterns: boundarySecretPatterns(),
      hashString: (value) => redactor.hashString(value),
    };
    const holds = new Map<string, HoldEntry>();
    /**
     * Credential brokering, or undefined when no `credentials` section is in
     * force. Every swap path below is gated on this, so a policy without one
     * leaves the proxy byte-for-byte as it was.
     */
    const swap = gateway.credentials;
    /**
     * `pending` keys of calls whose credential exchange is in flight.
     *
     * They are in flight from the client's point of view — the request has
     * been sent and no response has come back — so the duplicate-id gate has
     * to see them. Without this, a second request reusing the id would take
     * the slot while the first was still at the broker, and the first call's
     * real response would land as an orphan.
     */
    const swapping = new Set<string>();
    /** Synthesized client lines waiting for the server's partial line to complete. */
    const deferredClientWrites: Buffer[] = [];
    /** Approved hold lines waiting for a partially forwarded client line to complete. */
    const deferredServerWrites: Buffer[] = [];
    let c2sOpen = true;
    let s2cState: 'open' | 'ending' | 'ended' = 'open';
    /** One shared '\n' for the line terminators the gateway has to insert. */
    const NEWLINE = Buffer.from('\n');
    /**
     * True while everything forwarded to the client so far ended a line.
     * A server that dies mid-line leaves an UNTERMINATED line behind (the
     * s2c flush path forwards it as-is, byte-for-byte); a synthesized line
     * glued onto it would make both unparseable, so one '\n' is emitted
     * first. Same idea for the server side (`serverAtLineStart`) when a
     * parked hold is released after an unterminated client line.
     */
    let clientAtLineStart = true;
    let serverAtLineStart = true;

    /** Recording-side work stays fail-open: a throw is logged once, traffic unaffected. */
    const guarded = (fn: () => void): void => {
      try {
        fn();
      } catch (err) {
        tapError(err);
      }
    };

    /* ---- client-side writes (synthesized responses) ---- */

    const s2c = new Transform({
      transform(chunk, _enc, cb) {
        try {
          s2cSplitter.chunk(asBuffer(chunk));
          // A chunk boundary is where a server line can have just ended:
          // deferred synthesized lines go out right after it, never inside.
          if (!s2cSplitter.hasPartialLine()) flushDeferred();
        } catch (err) {
          tapError(err);
        }
        cb();
      },
      flush(cb) {
        try {
          s2cSplitter.end();
          flushDeferred();
        } catch (err) {
          tapError(err);
        }
        s2cState = 'ending';
        cb();
      },
    });
    s2c.on('end', () => {
      // Everything the Transform ever pushed has been handed to proxyStdout;
      // late synthesized lines (holds resolved at shutdown) go direct.
      s2cState = 'ended';
      flushDeferred();
    });
    s2c.on('error', (err: Error) => diag(`gateway stream error (server_to_client): ${err.message}`));
    s2cTransform = s2c;

    /**
     * The one path for synthesized lines to the client. Ordered with the
     * server's own lines by riding the s2c Transform while it is open;
     * deferred while a server line is partially forwarded (never split a
     * line); dropped once the client is gone or stdout is closed.
     */
    const writeToClient = (bytes: Buffer): void => {
      if (clientGone || proxyStdout.destroyed || proxyStdout.writableEnded) return;
      if (s2cState === 'open') {
        if (s2cSplitter.hasPartialLine()) {
          deferredClientWrites.push(bytes);
          return;
        }
        emitToClient(bytes, (out) => {
          try {
            s2c.push(out);
          } catch {
            /* fail-open */
          }
        });
        return;
      }
      if (s2cState === 'ending') {
        deferredClientWrites.push(bytes);
        return;
      }
      emitToClient(bytes, (out) => {
        try {
          proxyStdout.write(out);
        } catch {
          /* fail-open */
        }
      });
    };
    /** Emit one synthesized line, terminating an unfinished server line first. */
    const emitToClient = (bytes: Buffer, write: (out: Buffer) => void): void => {
      if (!clientAtLineStart) {
        clientAtLineStart = true;
        write(NEWLINE);
      }
      if (bytes.length > 0) clientAtLineStart = bytes[bytes.length - 1] === NL;
      write(bytes);
    };
    const flushDeferred = (): void => {
      if (deferredClientWrites.length === 0) return;
      for (const bytes of deferredClientWrites.splice(0)) writeToClient(bytes);
    };

    /* ---- policy evaluation (fail-closed) ---- */

    /** The fail-closed decision for a throw anywhere on the evaluation path. */
    const evaluationFailed = (err: unknown): McpDecision => ({
      action: 'deny',
      matched: false,
      reason: `policy evaluation error: ${err instanceof Error ? err.message : String(err)}`,
      // Same marker `evaluateMcp` sets for its own internal errors: nothing
      // was decided here, so the model is told it may retry.
      failClosed: true,
    });

    /**
     * Canonical JSON of a call's arguments, plus its hash. The canonical
     * JSON gets its OWN guard: when it succeeds, args_hash is the real hash
     * of the arguments even if whatever follows blows up (the refusal is
     * recorded, the evidence still points at the exact arguments). Only a
     * canonicalJson/sha256Ref throw — a hostile args tree — yields
     * `canonical: null` and the hash of `null`.
     */
    const argsCanonical = (args: unknown): { canonical: string | null; argsHash: string; err?: unknown } => {
      try {
        const canonical = canonicalJson(args);
        return { canonical, argsHash: sha256Ref(canonical) };
      } catch (err) {
        return { canonical: null, argsHash: NULL_RESULT_HASH, err };
      }
    };

    const evaluate = (rawTool: string, args: unknown): { decision: McpDecision; argsHash: string } => {
      const { canonical, argsHash, err } = argsCanonical(args);
      if (canonical === null) return { decision: evaluationFailed(err), argsHash };
      if (toolNameTooLong(rawTool)) {
        // Fail closed WITHOUT consulting the policy: the engine's tool globs
        // are backtracking regexes on this thread, so an uncapped name is a
        // denial of service on the whole gateway. See
        // MAX_EVALUATED_TOOL_NAME_LEN — refused, never truncated.
        return {
          decision: {
            action: 'deny',
            matched: false,
            reason: toolNameTooLongReason(rawTool.length),
            failClosed: true,
          },
          argsHash,
        };
      }
      try {
        const decision = evaluateMcp(loaded.policy, {
          server: currentServer().name,
          tool: rawTool,
          args,
          argsBytes: Buffer.byteLength(canonical),
        });
        return { decision, argsHash };
      } catch (err) {
        // evaluateMcp never throws by contract; anything else on this path
        // (a broken server name, a poisoned policy object) still denies.
        return { decision: evaluationFailed(err), argsHash };
      }
    };

    /** The policy-independent half of a GatewayCall. */
    const newCall = (
      id: string | number,
      params: Record<string, unknown>,
      name: string,
      args: unknown,
      argsHash: string,
    ): GatewayCall => {
      // '' stays '': structuralString would hash the empty string, and ''
      // is what a nameless call's tool_call event has always carried.
      const tool = name === '' ? '' : structuralString(name, 'identifier');
      return {
        id,
        params,
        // `rawTool` is the name as the CLIENT wrote it, quoted back in the
        // synthesized text. A name past MAX_EVALUATED_TOOL_NAME_LEN is one
        // the gateway refused to even look at, so it does not travel
        // verbatim either — the capped form stands in, and the refusal
        // reason says how long the real one was.
        rawTool: toolNameTooLong(name) ? tool : name,
        tool,
        args,
        argsHash,
      };
    };

    /**
     * A call refused on PROTOCOL grounds (a duplicate request id): the
     * policy is not consulted at all — no rule could allow an id that is
     * already in flight — so the call carries no rule id and no reason, just
     * the evidence (tool, id, args and their hash).
     */
    const unevaluatedCall = (msg: ToolsCallRequest): GatewayCall => {
      const { params, name } = toolsCallParts(msg);
      const args: unknown = params.arguments ?? {};
      return newCall(msg.id, params, name, args, argsCanonical(args).argsHash);
    };

    const buildCall = (msg: ToolsCallRequest): { call: GatewayCall; action: McpDecision['action'] } => {
      const { params, name } = toolsCallParts(msg);
      const args: unknown = params.arguments ?? {};
      const { decision, argsHash } = evaluate(name, args);
      const call = newCall(msg.id, params, name, args, argsHash);
      if (decision.ruleId !== undefined) {
        call.rawRuleId = decision.ruleId;
        call.ruleId = cappedRuleId(decision.ruleId);
      }
      if (decision.reason !== undefined) call.reason = decision.reason;
      if (decision.failClosed === true) call.failClosed = true;
      return { call, action: decision.action };
    };

    /* ---- events ---- */

    const policyAttributes = (call: GatewayCall, decision: 'deny' | 'hold'): Attributes => {
      const attributes: Attributes = {
        'gen_ai.tool.name': call.tool,
        'gen_ai.tool.call.id': String(call.id),
        'mcp.method.name': 'tools/call',
        'rpc.system': 'jsonrpc',
        'cresec.policy.decision': decision,
      };
      if (call.ruleId !== undefined) attributes['cresec.policy.rule_id'] = call.ruleId;
      if (call.swapAttributes !== undefined) Object.assign(attributes, call.swapAttributes);
      return attributes;
    };

    const recordPolicyDecision = (call: GatewayCall, hold?: HoldResolution): void => {
      const decision = hold === undefined ? 'deny' : 'hold';
      // One id per decision: the control plane's when the remote broker
      // decided (it already sits in `cresec.broker.decision_id`), a fresh
      // uuid when the local engine did. Set on the call so the synthetic
      // `tool_call` written next carries the same value as an attribute.
      if (call.decisionId === undefined) call.decisionId = randomUUID();
      const attributes = policyAttributes(call, decision);
      attributes['cresec.policy.decision_id'] = call.decisionId;
      const ev: PolicyDecisionEvent = {
        ...base('policy_decision', attributes),
        kind: 'policy_decision',
        decision,
        tool: call.tool,
        request_id: call.id,
        policy_hash: loaded.hash,
        args_hash: call.argsHash,
        decision_id: call.decisionId,
      };
      if (call.ruleId !== undefined) ev.rule_id = call.ruleId;
      if (hold !== undefined) {
        ev.outcome = hold.outcome;
        if (hold.approvalId !== undefined) ev.approval_id = hold.approvalId;
        ev.waited_ms = hold.waitedMs;
        if (hold.approver !== undefined) ev.approver = hold.approver;
      }
      record(ev);
    };

    /** The `gateway` field a forwarded (allowed / approved) call carries into handleResponse. */
    const gatewayOutcomeFor = (call: GatewayCall, hold?: HoldResolution): GatewayOutcome => {
      const out: GatewayOutcome = { decision: hold === undefined ? 'allow' : 'hold' };
      if (call.ruleId !== undefined) out.rule_id = call.ruleId;
      if (hold !== undefined) {
        out.outcome = hold.outcome;
        if (hold.approvalId !== undefined) out.approval_id = hold.approvalId;
        out.waited_ms = hold.waitedMs;
      }
      return out;
    };

    /**
     * A call the gateway did not forward: is_error, result = what the model
     * got. `errorType` is 'policy_denied' for a policy refusal and
     * 'duplicate_id' for one refused on protocol grounds (see the header).
     */
    const recordSyntheticToolCall = (
      call: GatewayCall,
      result: unknown,
      hold?: HoldResolution,
      errorType: string = 'policy_denied',
    ): void => {
      const gatewayOutcome = gatewayOutcomeFor(call, hold);
      if (hold === undefined) gatewayOutcome.decision = 'deny';
      const attributes: Attributes = {
        'gen_ai.operation.name': 'execute_tool',
        ...policyAttributes(call, gatewayOutcome.decision === 'deny' ? 'deny' : 'hold'),
        'error.type': errorType,
      };
      if (call.decisionId !== undefined) attributes['cresec.policy.decision_id'] = call.decisionId;
      const ev: ToolCallEvent = {
        ...base('tool_call', attributes),
        kind: 'tool_call',
        tool: call.tool,
        request_id: call.id,
        args: scrubToolArguments(redactor, call.args),
        result_hash: sha256Ref(boundedCanonicalJson(result)),
        result: redactor.scrub(result),
        is_error: true,
        duration_ms: 0,
        error: { type: errorType },
        gateway: gatewayOutcome,
      };
      record(ev);
    };

    /**
     * Refuse a call: record `policy_decision` FIRST, then the synthetic
     * `tool_call`, and return the isError response the client gets.
     */
    const synthesizeDeny = (call: GatewayCall, hold?: HoldResolution): Record<string, unknown> => {
      const input: Parameters<typeof deniedText>[0] = { tool: call.rawTool };
      if (call.rawRuleId !== undefined) input.ruleId = call.rawRuleId;
      if (call.reason !== undefined) input.reason = call.reason;
      if (call.failClosed === true) input.failClosed = true;
      if (hold !== undefined && hold.approvalId !== undefined) {
        input.approvalId = hold.approvalId;
        input.outcome = hold.outcome === 'approved' ? 'session_end' : hold.outcome;
      }
      const response = synthesizeDeniedResult(call.id, deniedText(input));
      guarded(() => {
        recordPolicyDecision(call, hold);
        recordSyntheticToolCall(call, response.result, hold);
      });
      return response;
    };

    const denyCall = (call: GatewayCall, hold?: HoldResolution, diagLine?: string): void => {
      const response = synthesizeDeny(call, hold);
      writeToClient(Buffer.from(JSON.stringify(response) + '\n'));
      if (diagLine !== undefined) {
        diag(diagLine); // a caller-specific line REPLACES the generic one
        return;
      }
      if (hold === undefined) {
        diag(`gateway: denied tools/call "${call.tool}" (rule ${call.ruleId ?? 'default'})`);
      }
    };

    /**
     * Refuse a `tools/call` whose JSON-RPC id is still in use. It is never
     * forwarded, so the call already sitting on that id keeps its pending
     * slot (and its hold, if it has one) and its own response still
     * correlates. Recorded like any other refusal, `policy_decision` first:
     * a deny with NO rule id (the policy was never consulted), then the
     * synthetic `tool_call` carrying `error.type: 'duplicate_id'`. The
     * reason travels in the text the model sees and in the diagnostic line;
     * the events carry hashes only, never arguments.
     *
     * Returns the response the client must get; the caller decides HOW it
     * travels — on its own line for a standalone request, or as one element
     * of the batch response array when the refused call came from a batch.
     */
    const refuseDuplicateId = (msg: ToolsCallRequest, state: DuplicateIdState): Record<string, unknown> => {
      const call = unevaluatedCall(msg);
      const response = synthesizeDeniedResult(call.id, duplicateIdText(call.rawTool, call.id, state));
      guarded(() => {
        recordPolicyDecision(call);
        recordSyntheticToolCall(call, response.result, undefined, DUPLICATE_ID_ERROR_TYPE);
      });
      // The id is client-supplied, so it is capped like any other protocol
      // string before it reaches a diagnostic line.
      diag(
        `gateway: refused tools/call "${call.tool}" — ${DUPLICATE_ID_REASON[state]}` +
          ` (id ${structuralString(String(call.id), 'identifier')})`,
      );
      return response;
    };

    /**
     * The `id` state of a c2s request: which map is already sitting on it.
     */
    const idInUse = (id: string | number, claimed?: ReadonlySet<string>): DuplicateIdState | undefined => {
      const key = pendingKey('c2s:', id);
      if (holds.has(key)) return 'held';
      // `swapping`: sent by the client, not yet forwarded because its
      // credential is still being exchanged. In flight either way.
      if (pending.has(key) || swapping.has(key) || claimed?.has(key) === true) return 'pending';
      return undefined;
    };

    /**
     * THE protocol gate every `tools/call` REQUEST passes before the policy
     * is consulted, whether it arrived on its own line or as an element of
     * a JSON-RPC batch. `pendingKey` folds the id's TYPE in, so the number
     * 7 and the string "7" are different ids here too.
     *
     * `claimed` carries the ids taken by EARLIER elements of the same batch
     * — both the ones forwarded together at the end of the loop (`pending`
     * does not know about them yet) and the ones the gateway ANSWERED on
     * itself. Without the second kind, a batch that denies element 1 on id 5
     * and allows element 2 on id 5 sends the client TWO responses for one
     * request id.
     *
     * Returns the refusal response when the id is not usable, `undefined`
     * when the call may proceed to the policy.
     */
    const refuseReusedId = (
      msg: ToolsCallRequest,
      claimed?: ReadonlySet<string>,
    ): Record<string, unknown> | undefined => {
      const state = idInUse(msg.id, claimed);
      return state === undefined ? undefined : refuseDuplicateId(msg, state);
    };

    /**
     * The same fail-closed gate for a c2s request that is NOT a
     * `tools/call`. It used to be missing entirely, and that was a way to
     * make an EXECUTED tool call vanish: a same-id `tools/list` overwrote
     * the in-flight call's `pending` slot, so the tool's real result was
     * recorded as that other request's response (or landed as an orphan)
     * with no `tool_call`, no args hash and no gateway outcome. The
     * reclaim-seal on the hold path is the last resort the source always
     * said it was; this is the mitigation.
     *
     * The refusal is a plain JSON-RPC -32600 (no model reads it, so an
     * isError tool result would be the wrong shape), and the attempt is
     * recorded as an `rpc` event with `error.type: 'duplicate_id'` — the
     * same seal `sealPending` writes for a request that never got an answer.
     */
    const refuseReusedRequestId = (
      msg: Record<string, unknown> & { method: string; id: string | number },
      claimed?: ReadonlySet<string>,
    ): Record<string, unknown> | undefined => {
      const state = idInUse(msg.id, claimed);
      if (state === undefined) return undefined;
      const entry: PendingEntry = {
        method: structuralString(msg.method, 'identifier'),
        params: msg.params,
        t0: performance.now(),
        id: msg.id,
      };
      guarded(() => sealPending(entry, DUPLICATE_ID_ERROR_TYPE, 0));
      diag(
        `gateway: refused a "${entry.method}" request — ${DUPLICATE_ID_REASON[state]}` +
          ` (id ${structuralString(String(msg.id), 'identifier')})`,
      );
      return invalidRequestResponse(msg.id, DUPLICATE_REQUEST_ID_MESSAGE);
    };

    /**
     * A `tools/call` whose `id` property is not a usable JSON-RPC id — the
     * `null` the module header describes, and equally `true`, `{}` or `[]`
     * (see the module header): refused with a JSON-RPC -32600 error and NOT
     * forwarded, whatever the policy says. There is no request id to record
     * a `policy_decision` or a `tool_call` against — and writing one anyway
     * would put a value in `request_id` the frozen schema cannot describe —
     * so it is recorded the way the tap records any id-less message, as one
     * `notification` event, carrying the outcome on the same additive
     * `gateway` field a refused `tools/call` notification uses.
     *
     * Without that field this was the last place enforcement happened and
     * the chain said so nowhere: `sessions` reported DECISIONS 0 and an
     * exported bundle held one ordinary `notification` event, structurally
     * indistinguishable from a forwarded one, with a stderr line as the only
     * trace. `refusal` says the gateway refused the message itself, so the
     * absent `rule_id` is not read as the section default denying it.
     *
     * Returns the error response, which the caller delivers on its own line
     * or inside the batch response array (a batch element gets exactly the
     * same treatment as a standalone one).
     */
    const refuseInvalidIdToolsCall = (
      msg: Record<string, unknown>,
      line: ScannedLine,
      inBatch = false,
    ): Record<string, unknown> => {
      const shape = msg['id'] === null ? 'a null id' : 'an id that is neither a string nor a number';
      diag(
        `gateway: refused a tools/call with ${shape}${inBatch ? ' inside a JSON-RPC batch' : ''}` +
          ' (not a valid request); not forwarded',
      );
      guarded(() =>
        handleMessage(msg, 'client_to_server', line, { decision: 'deny', refusal: INVALID_ID_REFUSAL }),
      );
      return invalidIdErrorResponse(msg['id']);
    };

    /**
     * Whether a `tools/call` NOTIFICATION may be forwarded, and — when it may
     * not — the outcome to record on its `notification` event. It is
     * evaluated against the policy exactly like a request; a deny simply
     * DROPS it, which is what "notification" already promises the caller.
     * Forwarding it unevaluated was the same hole the null-id refusal
     * closed, one shape over, and the refusal used to leave nothing but a
     * stderr line in its wake: enforcement happened and the chain said so
     * nowhere.
     */
    const evaluateToolsCallNotification = (
      msg: Record<string, unknown>,
      inBatch: boolean,
    ): { allowed: boolean; gateway?: GatewayOutcome } => {
      const params = isPlainObject(msg['params']) ? msg['params'] : {};
      const name = typeof params['name'] === 'string' ? params['name'] : '';
      const args: unknown = params['arguments'] ?? {};
      const { decision } = evaluate(name, args);
      const swapPlan = decision.action === 'allow' && swap !== undefined ? planSwap(name, args) : [];
      if (decision.action === 'allow' && swapPlan.length === 0) return { allowed: true };
      const tool = name === '' ? '' : structuralString(name, 'identifier');
      if (swapPlan.length > 0) {
        // A notification cannot be answered and has no request id, so it can
        // neither be parked for the exchange nor carry a `policy_decision`.
        // Forwarding it would send the SYNTHETIC to the upstream. Dropped —
        // which is exactly what "notification" promises its sender — and
        // recorded on the `notification` event's additive gateway field.
        diag(
          `gateway: denied tools/call NOTIFICATION "${tool}" — a credential swap cannot be parked on a` +
            ` notification (${SWAP_DENY.onNotification})${inBatch ? ' inside a JSON-RPC batch' : ''}; not forwarded`,
        );
        // No `refusal`: that field says the gateway refused the MESSAGE
        // rather than evaluating it, and this one WAS evaluated and allowed
        // before its credential proved unparkable. Recorded as the plain deny
        // a `hold` on a notification already produces.
        return { allowed: false, gateway: { decision: 'deny' } };
      }
      // A `hold` has nowhere to park and nothing to answer on, so it is a
      // deny — the gateway failing closed, exactly as a hold inside a batch.
      diag(
        `gateway: denied tools/call NOTIFICATION "${tool}"` +
          ` (rule ${decision.ruleId === undefined ? 'default' : cappedRuleId(decision.ruleId)})` +
          `${decision.action === 'hold' ? ' — a hold cannot be parked on a notification' : ''}` +
          `${inBatch ? ' inside a JSON-RPC batch' : ''}; not forwarded`,
      );
      // A `hold` is recorded as the deny it became: nothing was parked, and
      // no approver was ever asked.
      const gateway: GatewayOutcome = {
        decision: 'deny',
        ...(decision.ruleId === undefined ? {} : { rule_id: cappedRuleId(decision.ruleId) }),
      };
      return { allowed: false, gateway };
    };

    /** Register a forwarded tools/call in `pending` so its response becomes the tool_call event. */
    const registerCall = (call: GatewayCall, gatewayOutcome: GatewayOutcome, attributes?: Attributes): void => {
      const entry: PendingEntry = {
        method: 'tools/call',
        // The PRE-swap params: this is what the `tool_call` event's `args`
        // are scrubbed from, so the chain records the synthetic and never the
        // brokered value. The swap builds a separate tree (see `beginSwap`).
        params: call.params,
        t0: performance.now(),
        toolName: call.tool,
        id: call.id,
        gateway: gatewayOutcome,
      };
      if (attributes !== undefined) entry.attributes = attributes;
      registerPending(pendingKey('c2s:', call.id), entry);
    };

    /**
     * A hold sits on its `pending` key for as long as a human takes to
     * answer, so by approval time another request may have taken that key
     * over (a path with no duplicate-id check of its own: a
     * non-`tools/call` request, or a `tools/call` inside a JSON-RPC batch).
     * Overwriting it silently would lose a call that DID execute — its real
     * response would land as an orphan `protocol_error` with no tool_call,
     * args hash or gateway outcome. Seal it first, as `duplicate_id`, then
     * hand the slot back to the held call.
     */
    const reclaimPendingSlot = (key: string): void => {
      const displaced = pending.get(key);
      if (displaced === undefined) return;
      pending.delete(key);
      guarded(() =>
        sealPending(displaced, DUPLICATE_ID_ERROR_TYPE, round2(performance.now() - displaced.t0)),
      );
      diag(
        `gateway: a "${displaced.method}" request was still in flight on the held id;` +
          ` sealed as ${DUPLICATE_ID_ERROR_TYPE} before the approved tools/call took the slot back`,
      );
    };

    /* ---- holds ---- */

    const settleHold = (
      entry: HoldEntry,
      status: HoldWaitResult['status'] | 'session_end',
      decided?: HoldRecord,
    ): void => {
      if (entry.settled) return;
      entry.settled = true;
      if (holds.get(entry.key) === entry) holds.delete(entry.key);
      entry.abort.abort(); // stops the poller if it is still running
      const resolution: HoldResolution = {
        outcome: status,
        approvalId: entry.approvalId,
        waitedMs: round2(performance.now() - entry.t0),
      };
      // The hold file is operator-writable and only structurally checked:
      // `decided_by` is whatever it says. Anything but a string is ignored,
      // and a string is capped like any identifier copied off the wire, so
      // an over-long or off-shape value lands as its sha256 ref instead of
      // stamping arbitrary text on an event.
      const decidedBy: unknown = decided?.decided_by;
      if (typeof decidedBy === 'string') {
        resolution.approver = structuralString(decidedBy, 'identifier');
      }
      if (status === 'timeout' || status === 'cancelled' || status === 'session_end') {
        holdStore.finalize(entry.approvalId, status);
      }
      const forward = status === 'approved' || (status === 'timeout' && mcp.hold.on_timeout === 'allow');
      if (forward && c2sOpen && !clientGone && !sessionClosing) {
        guarded(() => recordPolicyDecision(entry, resolution));
        reclaimPendingSlot(entry.key);
        // The credential is resolved HERE, after the human answered — not
        // when the hold was parked. A hold nobody answers therefore leaves no
        // real token resident in memory at all. If the exchange then denies,
        // both events are written and both are true: the operator approved
        // the call and the broker refused the credential.
        const plan = entry.msg === undefined || entry.line === undefined ? [] : planSwap(entry.rawTool, entry.args);
        if (plan.length > 0) {
          diag(`gateway: hold ${entry.approvalId} ${status}; resolving credential for tools/call "${entry.tool}" after ${resolution.waitedMs} ms`);
          beginSwap(
            swap as NonNullable<typeof swap>,
            entry,
            entry.msg as ToolsCallRequest,
            entry.line as ScannedLine,
            plan,
            resolution,
          );
          return;
        }
        registerCall(entry, gatewayOutcomeFor(entry, resolution));
        forwardHeldC2s(entry.raw);
        diag(`gateway: hold ${entry.approvalId} ${status}; forwarding tools/call "${entry.tool}" after ${resolution.waitedMs} ms`);
        return;
      }
      if (forward) resolution.outcome = 'session_end'; // approved, but the server is already gone
      // `session_end` means the session ended under the hold, not that anyone
      // refused it: either shutdown swept a hold nobody had answered, or an
      // answer arrived too late to act on. The sharpest case is a hold the
      // operator APPROVED that still did not run — telling that agent "this
      // is a policy decision by the operator" would invert what happened.
      const failedClosed = resolution.outcome === 'session_end';
      denyCall(failedClosed ? { ...entry, failClosed: true } : entry, resolution);
      diag(`gateway: hold ${entry.approvalId} ${resolution.outcome} after ${resolution.waitedMs} ms; tools/call "${entry.tool}" not forwarded`);
    };

    const startHold = (call: GatewayCall, raw: Buffer, msg: ToolsCallRequest, line: ScannedLine): void => {
      if (holds.size >= MAX_HOLDS) {
        // Fail closed: the holds map is bounded, so a client that parks
        // holds nobody ever resolves cannot grow it without limit.
        denyCall(
          { ...call, reason: TOO_MANY_HOLDS_REASON, failClosed: true },
          undefined,
          `gateway: ${MAX_HOLDS} holds already pending; denying tools/call "${call.tool}"` +
            ` (rule ${call.ruleId ?? 'default'})`,
        );
        return;
      }
      const timeoutMs = mcp.hold.timeout_ms;
      let created: HoldRecord;
      try {
        const input: Parameters<typeof holdStore.create>[0] = {
          session_id: sessionId,
          server: currentServer().name,
          tool: call.tool,
          args: scrubToolArguments(redactor, call.args),
          args_hash: call.argsHash,
          timeout_at: new Date(Date.now() + timeoutMs).toISOString(),
        };
        if (call.rawRuleId !== undefined) input.rule_id = call.rawRuleId;
        if (call.reason !== undefined) input.reason = call.reason;
        created = holdStore.create(input);
      } catch (err) {
        // Fail closed: a hold that cannot be written is a deny.
        const message = err instanceof Error ? err.message : String(err);
        diag(`gateway: cannot write hold for tools/call "${call.tool}" (${message}); denying`);
        denyCall({ ...call, reason: 'hold unavailable', failClosed: true });
        return;
      }
      const entry: HoldEntry = {
        ...call,
        approvalId: created.approval_id,
        key: pendingKey('c2s:', call.id),
        raw,
        // Kept for the swap on the approved path only; see HoldEntry.
        msg,
        line,
        t0: performance.now(),
        abort: new AbortController(),
        settled: false,
      };
      holds.set(entry.key, entry);
      diag(
        `gateway: holding tools/call "${call.tool}" (rule ${call.ruleId ?? 'default'}) as ${created.approval_id}` +
          ` — mcp-recorder approve|deny ${created.approval_id}`,
      );
      const waitOpts: Parameters<typeof holdStore.waitForDecision>[1] = { timeoutMs, signal: entry.abort.signal };
      if (gateway.pollMs !== undefined) waitOpts.pollMs = gateway.pollMs;
      holdStore.waitForDecision(created.approval_id, waitOpts).then(
        (res) => {
          if (!entry.settled) settleHold(entry, res.status, res.record);
        },
        (err: unknown) => {
          // waitForDecision never rejects by contract; deny if it ever does.
          // That deny is the gateway failing to learn the operator's answer,
          // not a human giving one, so it must not read as a human's refusal.
          tapError(err);
          if (!entry.settled) {
            entry.failClosed = true;
            settleHold(entry, 'denied');
          }
        },
      );
    };

    const cancelHold = (msg: Record<string, unknown>): void => {
      const params = isPlainObject(msg.params) ? msg.params : {};
      if (!isRpcId(params.requestId)) return;
      const entry = holds.get(pendingKey('c2s:', params.requestId));
      if (entry !== undefined) settleHold(entry, 'cancelled');
    };

    resolveAllHolds = (): void => {
      for (const entry of [...holds.values()]) settleHold(entry, 'session_end');
    };

    forgetBrokeredTokens = (): void => {
      swap?.scrubber.clear();
    };

    /* ---- client -> server ---- */

    const c2s = new Transform({
      transform(chunk, _enc, cb) {
        try {
          c2sSplitter.chunk(asBuffer(chunk));
          // A chunk boundary is where a client line can have just ended:
          // a released hold goes out right after it, never inside it.
          if (!c2sSplitter.hasPartialLine()) flushDeferredC2s();
        } catch (err) {
          tapError(err);
        }
        cb();
      },
      flush(cb) {
        // Runs when the client closed its write end, BEFORE child.stdin is
        // ended: the trailing line is handled and every parked hold resolved
        // synchronously (never await here, or the server never sees EOF).
        try {
          c2sSplitter.end();
        } catch (err) {
          tapError(err);
        }
        try {
          flushDeferredC2s();
        } catch (err) {
          tapError(err);
        }
        try {
          resolveAllHolds?.();
        } catch (err) {
          tapError(err);
        }
        c2sOpen = false;
        cb();
      },
    });
    c2s.on('error', (err: Error) => diag(`gateway stream error (client_to_server): ${err.message}`));
    const forwardC2s = (bytes: Buffer): void => {
      // Once the client's read end is gone the server is being wound down
      // (child.stdin ended by the EPIPE handler): nothing more goes to it.
      if (!c2sOpen || clientGone) return;
      if (bytes.length > 0) serverAtLineStart = bytes[bytes.length - 1] === NL;
      c2s.push(bytes);
    };

    /**
     * A parked hold re-entering the client->server stream. The splitter
     * streams an OVERSIZED line's bytes through as they arrive, so pushing
     * a held request while one is in flight would splice it into the middle
     * of that line — exactly what the s2c side avoids for synthesized
     * responses. Defer it to the end of the current line instead (and
     * terminate an unfinished one first, for the trailing line `end()`
     * forwards without a '\n').
     */
    const forwardHeldC2s = (bytes: Buffer): void => {
      if (c2sSplitter.hasPartialLine()) {
        deferredServerWrites.push(bytes);
        return;
      }
      if (!serverAtLineStart) forwardC2s(NEWLINE);
      forwardC2s(bytes);
    };
    const flushDeferredC2s = (): void => {
      if (deferredServerWrites.length === 0) return;
      for (const bytes of deferredServerWrites.splice(0)) forwardHeldC2s(bytes);
    };

    /* ---- credential swap (client -> server) ---- */

    /**
     * The swaps a `tools/call` asks for, or [] when the policy declares no
     * `credentials` site that this call engages. Reads the SAME parsed
     * arguments the policy was evaluated against — never a re-parse, never
     * the raw text.
     */
    const planSwap = (tool: string, args: unknown): PlannedSwap[] => {
      if (swap === undefined || !swap.hasSites) return [];
      try {
        return swap.plan({ server: currentServer().name, tool, args });
      } catch (err) {
        // Planning is pure and must not throw; if it ever does, the call is
        // NOT forwarded unevaluated — this plan refuses, so the caller's
        // ordinary deny path runs rather than a second failure mode.
        tapError(err);
        return [unplannableSwap(SWAP_DENY.unavailable)];
      }
    };

    /** `user_agent` for the broker request: the MCP client from `initialize`. */
    const clientUserAgent = (): string | undefined => {
      if (clientName === undefined) return undefined;
      return clientVersion === undefined ? clientName : `${clientName}/${clientVersion}`;
    };

    /**
     * What the gateway does once the broker has answered.
     *
     * ALLOW forwards the original line with ONLY the credential spans
     * spliced into it — the same mechanism the boundary rewrite uses, and for
     * the same reason: re-serializing the whole message to rewrite one string
     * silently rewrites unrelated numbers in it. DENY refuses the call
     * exactly as a policy deny does, with a reason that is a CODE.
     *
     * The `pending` entry is registered from the PRE-swap call, so the
     * `tool_call` event this eventually becomes carries the synthetic in its
     * args and the credential's id + decision id in its attributes.
     */
    const settleSwap = (
      call: GatewayCall,
      msg: ToolsCallRequest,
      line: ScannedLine,
      outcome: SwapOutcome,
      hold?: HoldResolution,
    ): void => {
      const refuse = (code: string, failClosed: boolean): void => {
        // The broker's decision id, when it reached one (a remote 403 carries
        // the control plane's), is THE decision id of this refusal.
        const decided = [...outcome.decisions].reverse().find((d) => d.decisionId !== '');
        const refused: GatewayCall = {
          ...call,
          reason: swapDenyReason(code),
          swapAttributes: outcome.attributes,
          ...(decided !== undefined ? { decisionId: decided.decisionId } : {}),
          ...(failClosed ? { failClosed: true as const } : {}),
        };
        denyCall(refused, undefined, `gateway: credential swap refused tools/call "${call.tool}" (${code})`);
      };
      if (outcome.kind === 'deny') {
        refuse(outcome.code, outcome.failClosed);
        return;
      }
      if (outcome.message === msg) {
        // An allow that changed nothing would forward the SYNTHETIC to the
        // upstream, which invariant 1 forbids outright. Unreachable by
        // construction; refused rather than trusted.
        refuse(SWAP_DENY.noToken, true);
        return;
      }
      if (!c2sOpen || clientGone || sessionClosing) {
        // The session ended while the broker was answering. Nothing can be
        // forwarded, and nobody decided this, so it reads as fail-closed.
        refuse(SWAP_DENY.sessionEnd, true);
        return;
      }
      guarded(() => registerCall(call, gatewayOutcomeFor(call, hold), outcome.attributes));
      forwardHeldC2s(spliceRewrittenLine(line, msg, outcome.message));
      for (const d of outcome.decisions) {
        // Host and path come off the wire, so they are capped like every
        // other client-supplied string before reaching a diagnostic line.
        diag(
          `gateway: swapped credential "${structuralString(d.credential, 'identifier')}" into tools/call` +
            ` "${call.tool}" for ${structuralString(d.host, 'identifier')}` +
            `${d.hostSource === 'server_name' ? ' (host is the server name, not a checked destination)' : ''}` +
            ` (decision ${structuralString(d.decisionId, 'identifier')}, ttl ${d.ttlSeconds}s)`,
        );
      }
    };

    /**
     * Park a `tools/call` while its credential is exchanged.
     *
     * The exchange is I/O — a local `exec`, an OpenBao round-trip, an STS
     * call — so the call waits exactly as a hold does: its id stays in flight
     * for the duplicate-id gate, and the rewritten line is released on the
     * next line boundary rather than spliced into a partial one. The engine
     * bounds every exchange with its own deadline
     * (BROKER_EXCHANGE_DEADLINE_MS, 5 s — the same bound NHI's Go client
     * carries), so this can park for that long at worst and then denies.
     */
    const beginSwap = (
      engine: NonNullable<typeof swap>,
      call: GatewayCall,
      msg: ToolsCallRequest,
      line: ScannedLine,
      plan: PlannedSwap[],
      hold?: HoldResolution,
    ): void => {
      if (swapping.size >= MAX_INFLIGHT_SWAPS) {
        // Fail closed, exactly as MAX_HOLDS does: a client that opens swaps
        // faster than the broker answers them must not grow this without
        // limit.
        denyCall(
          { ...call, reason: swapDenyReason(SWAP_DENY.tooMany), failClosed: true },
          undefined,
          `gateway: ${MAX_INFLIGHT_SWAPS} credential swaps already in flight; denying tools/call "${call.tool}"`,
        );
        return;
      }
      const key = pendingKey('c2s:', call.id);
      swapping.add(key);
      const ctx: Parameters<typeof engine.exchange>[2] = { server: currentServer().name, tool: call.rawTool };
      const ua = clientUserAgent();
      if (ua !== undefined) ctx.userAgent = ua;
      engine.exchange(msg, plan, ctx).then(
        (outcome) => {
          swapping.delete(key);
          settleSwap(call, msg, line, outcome, hold);
        },
        (err: unknown) => {
          // `exchange` never rejects by contract; deny if it ever does. The
          // error text is NOT quoted anywhere: it can carry a command line,
          // a vault path or an upstream body.
          swapping.delete(key);
          tapError(err);
          denyCall({ ...call, reason: swapDenyReason(SWAP_DENY.unavailable), failClosed: true });
        },
      );
    };

    const c2sToolsCall = (msg: ToolsCallRequest, raw: Buffer, line: ScannedLine): void => {
      // Fail closed on id reuse BEFORE the policy is consulted (see the
      // module header): a `tools/call` on an id that is currently held, or
      // that belongs to a request the server has not answered yet, is
      // refused instead of forwarded — otherwise it would take over the
      // other call's `pending`/`holds` slot and that call's real response
      // would be recorded as an orphan.
      const reused = refuseReusedId(msg);
      if (reused !== undefined) {
        writeToClient(Buffer.from(JSON.stringify(reused) + '\n'));
        return;
      }
      const { call, action } = buildCall(msg);
      if (action === 'allow') {
        // The swap runs AFTER the policy allowed the call and only at a
        // declared site: the policy decides, the broker resolves.
        const plan = swap === undefined ? [] : planSwap(call.rawTool, call.args);
        if (plan.length > 0) {
          beginSwap(swap as NonNullable<typeof swap>, call, msg, line, plan);
          return;
        }
        forwardC2s(raw);
        guarded(() => registerCall(call, gatewayOutcomeFor(call)));
        return;
      }
      if (action === 'deny') {
        denyCall(call);
        return;
      }
      if (sessionClosing) {
        // finalize() has already resolved every parked hold: a new one
        // would leave a pending hold file and a live poller behind and
        // would never be recorded. Refuse it now, with the same outcome a
        // hold parked a moment earlier gets.
        denyCall(
          { ...call, reason: SESSION_END_HOLD_REASON, failClosed: true },
          { outcome: 'session_end', waitedMs: 0 },
          `gateway: session ending; tools/call "${call.tool}" refused instead of held` +
            ` (rule ${call.ruleId ?? 'default'})`,
        );
        return;
      }
      startHold(call, raw, msg, line);
    };

    /**
     * JSON-RPC batch: EVERY element goes through the same gate its
     * standalone form does, in the same order — the protocol checks first
     * (an element that is itself an array, an unusable id, a reused request
     * id), then the policy. Allowed elements are forwarded as a batch, as
     * the client wrote them; refused ones (a nested array, an unusable id, a
     * duplicate id, a deny, and a hold — not supported inside a batch) get
     * their refusal back as elements of the batch response and are never
     * forwarded.
     *
     * A batch is NOT a way in. Every element kind that used to slip past
     * here is now gated:
     *  - a `tools/call` REQUEST — the duplicate-id and policy gates;
     *  - a `tools/call` with an unusable `id` (`null`, `true`, `{}`, `[]`);
     *  - a `tools/call` NOTIFICATION, which has no id but is still evaluated;
     *  - a NESTED ARRAY, which is not a request at all but which a server
     *    that flattens its input would happily run;
     *  - any OTHER request, which takes a `pending` slot and could therefore
     *    clobber an in-flight tool call's slot.
     * There is no fast path around this loop: when nothing is refused
     * `keptBatchBytes` returns the ORIGINAL bytes, so an untouched batch
     * still crosses byte-for-byte.
     */
    const c2sBatch = (batch: unknown[], raw: Buffer, line: ScannedLine): void => {
      if (batch.length === 0) {
        // An empty array carries nothing to evaluate. JSON-RPC calls it an
        // invalid request and the server may answer it however it likes;
        // the gateway has no opinion, so it crosses as the client wrote it.
        forwardC2s(raw);
        return;
      }
      const kept: unknown[] = [];
      const keptIndexes: number[] = [];
      const forwardedCalls: GatewayCall[] = [];
      const responses: unknown[] = [];
      /**
       * Request ids THIS batch has already taken — whether by an element
       * that is being forwarded (`registerCall`/`handleMessage` only run
       * once the whole batch has gone out, so `pending` cannot answer for
       * them yet) or by one the gateway ANSWERED on itself. Both count: a
       * batch that denies id 5 and then allows id 5 would otherwise send the
       * client two responses for one request id.
       */
      const claimed = new Set<string>();
      /**
       * Ids the gateway has already ANSWERED on in this batch. Claiming an
       * id stops a later element being forwarded; it does not stop the
       * refusal itself being written, and a refusal IS a response — so a
       * batch that denied id 5 and then reused it sent the client the deny
       * AND a duplicate-id error, two responses for one request id, which is
       * the thing the claim set exists to prevent. The second refusal is
       * still recorded and still logged; it just is not answered twice.
       */
      const answered = new Set<string>();
      const answer = (id: string | number, response: unknown): void => {
        answered.add(pendingKey('c2s:', id));
        responses.push(response);
      };
      const claim = (el: unknown): void => {
        if (isRpcRequest(el)) claimed.add(pendingKey('c2s:', el.id));
      };
      const keep = (el: unknown, index: number): void => {
        kept.push(el);
        keptIndexes.push(index);
        claim(el);
      };
      batch.forEach((el, index) => {
        if (Array.isArray(el)) {
          // Not a JSON-RPC request. A server that flattens nested arrays
          // would execute whatever is inside it, so it never crosses.
          //
          // It is recorded as `protocol_error` `unparseable`, which is the
          // same event the refused oversized and non-JSON client lines get:
          // a nested array is not a JSON-RPC message, it has no `method` to
          // record a `notification` against and no id to record anything
          // else against, and the alternative is the third enforcement path
          // whose only trace is a line on stderr. The `line_hash` still
          // identifies the artifact.
          diag('gateway: refused a nested array inside a JSON-RPC batch; not forwarded');
          guarded(() => protocolError('client_to_server', 'unparseable', line.bytesLen, line.lineHashHex));
          responses.push(invalidRequestResponse(null, NESTED_BATCH_MESSAGE));
          return;
        }
        if (isInvalidIdToolsCall(el)) {
          responses.push(refuseInvalidIdToolsCall(el, line, true));
          return;
        }
        if (isToolsCallNotification(el)) {
          const verdict = evaluateToolsCallNotification(el, true);
          if (verdict.allowed) keep(el, index);
          else guarded(() => handleMessage(el, 'client_to_server', line, verdict.gateway));
          return;
        }
        if (!isToolsCallRequest(el)) {
          if (isRpcRequest(el)) {
            const reused = refuseReusedRequestId(el, claimed);
            if (reused !== undefined) {
              claimed.add(pendingKey('c2s:', el.id));
              if (!answered.has(pendingKey('c2s:', el.id))) answer(el.id, reused);
              return;
            }
          }
          keep(el, index);
          return;
        }
        const reused = refuseReusedId(el, claimed);
        if (reused !== undefined) {
          if (!answered.has(pendingKey('c2s:', el.id))) answer(el.id, reused);
          return;
        }
        const { call, action } = buildCall(el);
        if (action === 'allow') {
          const plan = swap === undefined ? [] : planSwap(call.rawTool, call.args);
          if (plan.length > 0) {
            // A credential swap inside a batch is a deny for the same reason
            // a `hold` is: the exchange is asynchronous and a batch element
            // has nowhere to park — the other elements travel now, as the
            // client wrote them. Forwarding it unswapped would put the
            // SYNTHETIC on the wire, which invariant 1 forbids, so the only
            // honest answer is a refusal, and the gateway failed closed
            // rather than the operator deciding. Same v1 limit, documented
            // in the module header.
            claimed.add(pendingKey('c2s:', call.id));
            answer(
              call.id,
              synthesizeDeny({ ...call, reason: swapDenyReason(SWAP_DENY.inBatch), failClosed: true as const }),
            );
            diag(`gateway: credential swap inside a JSON-RPC batch is treated as deny (tools/call "${call.tool}")`);
            return;
          }
          keep(el, index);
          forwardedCalls.push(call);
          return;
        }
        // A `hold` inside a batch is a deny because a batch element has
        // nowhere to park — so no operator is ever asked about it, and the
        // retry the policy clause forbids (the same call sent on its own) is
        // the only thing that reaches an approver. That makes it the gateway
        // failing closed, not the operator deciding.
        const refused = action === 'hold' ? { ...call, failClosed: true as const } : call;
        if (action === 'hold') {
          diag(`gateway: hold inside a JSON-RPC batch is treated as deny (tools/call "${call.tool}")`);
        }
        // The gateway has now answered on this id: a later element reusing
        // it is refused and recorded, but not answered a second time.
        claimed.add(pendingKey('c2s:', call.id));
        answer(call.id, synthesizeDeny(refused));
        diag(`gateway: denied tools/call "${call.tool}" (rule ${call.ruleId ?? 'default'})`);
      });
      if (kept.length > 0) forwardC2s(keptBatchBytes(line, raw, batch, keptIndexes));
      // A `notifications/cancelled` settles its hold wherever it arrives.
      // This loop is the batch's half of that: `cancelHold` had one call
      // site, on the standalone path, so a batched cancel was forwarded to
      // the server while the gateway kept the call parked — and under
      // `on_timeout: allow` the call the client had cancelled then EXECUTED
      // when the hold timed out. Outside `guarded`, like the standalone
      // path: settling a hold is enforcement, not recording.
      for (const el of kept) {
        if (isPlainObject(el) && el.method === 'notifications/cancelled') cancelHold(el);
      }
      guarded(() => {
        for (const call of forwardedCalls) registerCall(call, gatewayOutcomeFor(call));
        for (const el of kept) {
          if (!isToolsCallRequest(el)) handleMessage(el, 'client_to_server', line);
        }
      });
      if (responses.length > 0) writeToClient(Buffer.from(JSON.stringify(responses) + '\n'));
    };

    /**
     * A client line the gateway could not evaluate because it grew past the
     * line cap. NONE of its bytes reached the server (the splitter drops
     * them, see `GatewayLineSplitter`'s `refuseOversized`), so the client is
     * answered here instead of being left waiting: enforcement fails CLOSED,
     * and an unparseable line is by definition unevaluated.
     *
     * The line's content was never buffered, so its request id is unknown —
     * the refusal carries `id: null`, which is exactly what JSON-RPC
     * prescribes for a request whose id could not be determined. The one
     * thing the scanner does keep is the line's first non-whitespace byte,
     * so a batch ('[') is answered with a batch, as a client that sent one
     * expects.
     */
    /**
     * Refuse a client line the policy could not be shown, and say why.
     *
     * TWO things stop the policy seeing a line: it is larger than the gateway
     * can buffer, or it is not JSON. Both fail closed, and for the same two
     * reasons. A line the policy never saw could carry anything, including
     * the tool a rule denies. And a line that skips the parser also skips
     * every id gate below it, so forwarding one reopens the duplicate-id
     * holes as well: the server's answer to it correlates onto whatever call
     * owns that id, and one `tool_call` ends up carrying one call's arguments
     * with another call's result.
     *
     * Only the oversized branch was fixed first, and the unparseable branch
     * five lines below it went on forwarding — which is why this is one
     * helper both call rather than two similar blocks.
     *
     * Record mode forwards both, unchanged: it promises byte-for-byte and
     * enforces nothing.
     */
    const refuseUnevaluatableC2sLine = (line: ScannedLine, why: 'oversized' | 'unparseable'): void => {
      const message = why === 'oversized' ? OVERSIZED_LINE_MESSAGE : UNPARSEABLE_LINE_MESSAGE;
      const response = invalidRequestResponse(null, message);
      // The line was never parsed, so its first non-whitespace byte is all we
      // know of its shape: a batch gets a batch-shaped refusal.
      const body = line.firstByte === 0x5b ? [response] : response;
      // Name the cause, not just the class: an operator reading stderr needs
      // to know whether to send less or to send valid JSON.
      const cause = why === 'oversized' ? 'too large to buffer' : 'not valid JSON';
      diag(
        `gateway: refused a ${line.bytesLen}-byte client line: ${cause}, so the policy could not` +
          ' see it; not forwarded',
      );
      writeToClient(Buffer.from(JSON.stringify(body) + '\n'));
    };

    const c2sLine = (line: ScannedLine): void => {
      if (line.oversized) {
        // Fail closed: the splitter dropped the bytes rather than streaming
        // them to the server, so nothing crossed unevaluated. Record the
        // line exactly as record mode does, then answer the client.
        guarded(() => protocolError('client_to_server', 'oversized', line.bytesLen, line.lineHashHex));
        refuseUnevaluatableC2sLine(line, 'oversized');
        return;
      }
      const raw = line.raw;
      if (raw === undefined || line.text === null) return; // unreachable: non-oversized lines carry raw
      if (line.text.trim() === '') {
        // A blank or whitespace-only line carries no request and cannot
        // carry a tool call, so there is nothing for the policy to see and
        // nothing to refuse. Clients send them as separators and keepalives;
        // answering one with -32600 would be the gateway inventing an error
        // for a question nobody asked. It crosses as written, and is
        // recorded exactly as record mode records it, so the two modes'
        // chains still say the same thing about the same bytes.
        guarded(() => protocolError('client_to_server', 'unparseable', line.bytesLen, line.lineHashHex));
        forwardC2s(raw);
        return;
      }
      let msg: unknown;
      try {
        msg = JSON.parse(line.text);
      } catch {
        // Not JSON, so the policy cannot be shown it — refused, not forwarded.
        guarded(() => protocolError('client_to_server', 'unparseable', line.bytesLen, line.lineHashHex));
        refuseUnevaluatableC2sLine(line, 'unparseable');
        return;
      }
      if (Array.isArray(msg)) {
        c2sBatch(msg, raw, line);
        return;
      }
      if (isToolsCallRequest(msg)) {
        c2sToolsCall(msg, raw, line);
        return;
      }
      if (isInvalidIdToolsCall(msg)) {
        writeToClient(Buffer.from(JSON.stringify(refuseInvalidIdToolsCall(msg, line)) + '\n'));
        return;
      }
      if (isToolsCallNotification(msg)) {
        const verdict = evaluateToolsCallNotification(msg, false);
        if (verdict.allowed) forwardC2s(raw);
        guarded(() => handleMessage(msg, 'client_to_server', line, verdict.gateway));
        return;
      }
      if (isRpcRequest(msg)) {
        // Every request takes a `pending` slot, so every request goes
        // through the duplicate-id gate — not just `tools/call`. Letting a
        // same-id `tools/list` take the slot of an in-flight tool call is
        // how an executed call disappears from the chain.
        const reused = refuseReusedRequestId(msg);
        if (reused !== undefined) {
          writeToClient(Buffer.from(JSON.stringify(reused) + '\n'));
          return;
        }
      }
      forwardC2s(raw);
      if (isPlainObject(msg) && msg.method === 'notifications/cancelled') cancelHold(msg);
      guarded(() => handleMessage(msg, 'client_to_server', line));
    };
    // `true`: a client line the policy could not see never reaches the
    // server (BLOCKING A). The s2c splitter keeps streaming an oversized
    // server line through — buffering the server's output has no bearing on
    // what the client is allowed to ask for.
    const c2sSplitter = new GatewayLineSplitter(forwardC2s, c2sLine, true);

    /* ---- server -> client ---- */

    const forwardS2c = (rawBytes: Buffer): void => {
      // LAST-RESORT sweep at the one point server bytes leave for the client.
      // The structural scrub in `s2cLine`/`s2cBatch` is the one that matters
      // — it runs before the result is hashed into an event — and this
      // catches what never becomes a parsed message: an unparseable line, a
      // line forwarded verbatim, the chunks of an oversized one. It cannot
      // catch a token straddling two chunks of an oversized line (those are
      // streamed as they arrive), which is the same class of gap as an
      // encoding transform and is documented, not papered over.
      const bytes = swap === undefined ? rawBytes : swap.scrubber.scrubBytes(rawBytes);
      if (bytes.length > 0) clientAtLineStart = bytes[bytes.length - 1] === NL;
      s2c.push(bytes);
    };

    /**
     * Replace every occurrence of a live brokered token in one parsed server
     * message with the synthetic the client sent.
     *
     * This runs BEFORE the boundary filter and before `handleResponse`, so a
     * reflected token is gone from the tree that gets hashed, scrubbed into
     * `tool_call.result` and fingerprinted into `secret_refs`. That ordering
     * is the whole point: `RedactedRef`s are unsalted sha256 by design, so a
     * ref of a real token is a brute-forceable copy of it — the boundary
     * filter finding a reflected credential and writing its ref into the
     * chain would be the leak, not the fix.
     *
     * Copy-on-write, so an untouched message comes back by reference and the
     * original bytes still cross byte-for-byte.
     */
    const scrubBrokered = (msg: unknown, text: string | null): { message: unknown; changed: boolean } => {
      if (swap === undefined || text === null || !swap.scrubber.mightContain(text)) {
        return { message: msg, changed: false };
      }
      try {
        return swap.scrubber.scrubMessage(msg);
      } catch (err) {
        // Never let the seatbelt break the line: the byte-level sweep in
        // forwardS2c still catches the value on its way out, and the event
        // for this response is the only thing at risk.
        tapError(err);
        return { message: msg, changed: false };
      }
    };

    /** A result shaped like a tools/call result (MCP content blocks). */
    const looksLikeToolResult = (msg: Record<string, unknown>): boolean => {
      const result = msg['result'];
      return isPlainObject(result) && Array.isArray(result['content']);
    };

    /**
     * Whether one server->client message must go through the boundary
     * filter, and the tool name for the diagnostic. Must be called for
     * EVERY element BEFORE handleResponse deletes the pending entry.
     */
    const boundaryTarget = (
      msg: Record<string, unknown>,
    ): { kind: 'correlated' | 'orphan'; tool: string } | undefined => {
      const id: unknown = msg['id'];
      if (!isRpcId(id) || !('result' in msg || 'error' in msg)) return undefined;
      const entry = pending.get(pendingKey('c2s:', id));
      if (entry !== undefined) {
        return entry.method === 'tools/call' ? { kind: 'correlated', tool: entry.toolName ?? '' } : undefined;
      }
      // Fail closed for the BOUNDARY: a result the gateway can no longer
      // correlate (its pending entry was evicted, or the server answered a
      // request it was never sent) is still scanned before the client sees
      // it. Recording is unchanged — handleResponse records the usual
      // protocol_error orphan_response.
      return looksLikeToolResult(msg) ? { kind: 'orphan', tool: '' } : undefined;
    };

    /**
     * Run the boundary filter over one response message. `rawBytes` is the
     * byte length of the whole LINE the message arrived on; for a batch
     * that is the length of the entire array, so `max_scan_bytes` keeps
     * applying to the line as it crossed the wire (docs/gateway.md).
     */
    const filterResult = (
      msg: Record<string, unknown>,
      rawBytes: number,
      tool: string,
    ): { message: unknown; changed: boolean; report: BoundaryReport } => {
      const outcome = applyBoundary(msg, mcp.boundary, boundaryDeps, { rawBytes });
      const report: BoundaryReport = { ...outcome.report };
      if (outcome.changed) {
        // The hash of what the client actually receives. `spliceRewrittenLine`
        // puts the ORIGINAL source text of every untouched value back on the
        // wire, but those bytes parse to exactly the values in
        // `outcome.message` — they are the very values this line parsed to —
        // so the canonical JSON of the delivered result, and therefore this
        // hash, is the same either way.
        //
        // This is RECORDING, and it runs on the forwarding path, so it must
        // not throw: `canonicalJson` recurses and a pathological result tree
        // overflows the stack. Unguarded, that throw escaped `s2cLine` into
        // the Transform's catch and the client lost the line — and the rest
        // of the chunk it arrived in — for a hash.
        //
        // `boundedCanonicalJson` removes the overflow (a subtree past
        // MAX_HASH_DEPTH hashes as a fixed marker), so the hash is normally
        // present even for a hostile tree. The catch below is now the last
        // resort it always claimed to be — and it costs only this ONE FIELD:
        // `handleResponse` records the `tool_call` either way, carrying
        // `error.type: 'result_hash_failed'`. The earlier arrangement lost
        // the whole event and left `verify` reporting PASS over the gap.
        try {
          const delivered = isPlainObject(outcome.message) ? outcome.message['result'] : null;
          report.delivered_result_hash = sha256Ref(boundedCanonicalJson(delivered ?? null));
        } catch (err) {
          // The report carries no `delivered_result_hash` (its absence on a
          // changed result IS the signal, and `scanned`/`action` still say
          // what the client got), and `tapError` puts it on stderr and in
          // the recorder's error accounting.
          tapError(err);
        }
        diag(
          `gateway: ${report.action === 'block' ? 'blocked' : 'redacted'} tool result of tools/call "${tool}"` +
            ` (${report.secrets_found} secret-shaped, ${report.injection_found} injection marker(s))`,
        );
      }
      return { message: outcome.message, changed: outcome.changed, report };
    };

    /**
     * A JSON-RPC BATCH answer. A spec-compliant server answers a batch the
     * gateway forwarded with an ARRAY, so every element that answers a
     * tools/call must be filtered individually — otherwise the whole array
     * would cross unscanned and its tool_call events would carry no
     * boundary report. The array is re-serialized only when at least one
     * element changed; an untouched batch still crosses byte-for-byte.
     */
    const s2cBatch = (batch: unknown[], raw: Buffer, line: ScannedLine): void => {
      const out: unknown[] = [...batch];
      /**
       * The elements as the CHAIN must see them: brokered tokens replaced,
       * boundary rewrites NOT applied. `out` carries both rewrites because it
       * is what the client receives; `recorded` carries only the first,
       * because `tool_call.result`/`result_hash` are defined as the RAW
       * server result and only `gateway.boundary.delivered_result_hash`
       * describes the delivered variant. A brokered token is the one thing
       * that must not survive into either.
       */
      const recorded: unknown[] = [...batch];
      const reports = new Map<number, BoundaryReport>();
      let changed = false;
      let orphans = 0;
      batch.forEach((el, index) => {
        // Same order as the standalone path: the brokered-token scrub first,
        // so nothing below this line ever sees the real value — including an
        // element that is not a tool result and is otherwise forwarded and
        // recorded verbatim.
        const unbrokered = scrubBrokered(el, line.text);
        if (unbrokered.changed) {
          changed = true;
          out[index] = unbrokered.message;
          recorded[index] = unbrokered.message;
          diag('gateway: a brokered credential came back in a batched server message; replaced with its placeholder');
        }
        const scrubbed = unbrokered.message;
        if (!isPlainObject(scrubbed)) return;
        const target = boundaryTarget(scrubbed);
        if (target === undefined) return;
        const filtered = filterResult(scrubbed, line.bytesLen, target.tool);
        if (filtered.changed) {
          changed = true;
          out[index] = filtered.message;
        }
        if (target.kind === 'orphan') orphans++;
        reports.set(index, filtered.report);
      });
      forwardS2c(changed ? spliceRewrittenLine(line, batch, out) : raw);
      if (orphans > 0) {
        diag(`gateway: boundary-filtered ${orphans} batched tool result(s) with no pending request`);
      }
      guarded(() => {
        batch.forEach((el, index) => {
          const el2 = recorded[index];
          const report = reports.get(index);
          if (report === undefined) {
            handleMessage(el2, 'server_to_client', line);
            return;
          }
          handleResponse(el2 as Record<string, unknown>, 'server_to_client', line, report);
        });
      });
    };

    const s2cLine = (line: ScannedLine): void => {
      if (line.oversized) {
        guarded(() => protocolError('server_to_client', 'oversized', line.bytesLen, line.lineHashHex));
        return;
      }
      const raw = line.raw;
      if (raw === undefined || line.text === null) return;
      let msg: unknown;
      try {
        msg = JSON.parse(line.text);
      } catch {
        forwardS2c(raw);
        guarded(() => protocolError('server_to_client', 'unparseable', line.bytesLen, line.lineHashHex));
        return;
      }
      if (Array.isArray(msg)) {
        s2cBatch(msg, raw, line);
        return;
      }
      // The reverse scrub comes FIRST, so every step below — the boundary
      // filter, the result hash, the recorded result tree — sees the
      // synthetic where the server echoed the real token. `arrived` is kept
      // so the splice still measures its edits against the bytes that came
      // off the wire.
      const arrived = msg;
      const unbrokered = scrubBrokered(msg, line.text);
      msg = unbrokered.message;
      if (unbrokered.changed) {
        diag('gateway: a brokered credential came back in a server message; replaced with its placeholder');
      }
      if (isPlainObject(msg)) {
        // Look the request up BEFORE handleResponse deletes it.
        const target = boundaryTarget(msg);
        if (target !== undefined) {
          const filtered = filterResult(msg, line.bytesLen, target.tool);
          const delivered = filtered.changed ? filtered.message : msg;
          forwardS2c(delivered === arrived ? raw : spliceRewrittenLine(line, arrived, delivered));
          if (target.kind === 'orphan') {
            // The id is the server's, so it is capped like any other
            // protocol string before it reaches a diagnostic line.
            diag(
              'gateway: boundary-filtered a tool result with no pending request' +
                ` (id ${structuralString(String((msg as Record<string, unknown>)['id']), 'identifier')})`,
            );
          }
          guarded(() => handleResponse(msg as Record<string, unknown>, 'server_to_client', line, filtered.report));
          return;
        }
      }
      forwardS2c(unbrokered.changed ? spliceRewrittenLine(line, arrived, msg) : raw);
      guarded(() => handleMessage(msg, 'server_to_client', line));
    };
    const s2cSplitter = new GatewayLineSplitter(forwardS2c, s2cLine);

    proxyStdin.pipe(c2s).pipe(child.stdin);
    child.stdout.pipe(s2c).pipe(proxyStdout, { end: false });

    const ruleCount = mcp.rules.length;
    diag(`gateway: policy ${loaded.name ?? loaded.path} (${ruleCount} rule${ruleCount === 1 ? '' : 's'})`);
    // `match.args` regexes run on the regex-guard worker under a hard
    // deadline (see ../policy/regex-guard.ts). Route its diagnostics (a
    // poisoned pattern, a degraded guard) to stderr with everything else, and
    // pay the one-time worker handshake here, at startup, rather than on the
    // first tools/call that hits a rule with `args`. Both are best-effort:
    // enforcement is correct (fail-closed) whether or not the worker is warm.
    setRegexGuardDiag(diag);
    if (mcp.rules.some((r) => r.match.args !== undefined)) warmRegexGuard();
  }

  /* ---------------------------- session events ---------------------------- */

  const sessionStart: SessionStartEvent = {
    ...base('session_start', { 'rpc.system': 'jsonrpc' }),
    kind: 'session_start',
    proxy_version: opts.proxyVersion,
    cwd: process.cwd(),
    redaction_mode: redactor.mode,
  };
  if (gateway !== undefined) {
    sessionStart.policy = { hash: gateway.policy.hash };
    if (gateway.policy.name !== undefined) {
      sessionStart.policy.name = structuralString(gateway.policy.name, 'identifier');
    }
  }
  record(sessionStart);

  /* ------------------------------ lifecycle ------------------------------- */

  let stdinEnded = false;
  proxyStdin.on('end', () => {
    stdinEnded = true;
    // Gateway mode: the c2s Transform's flush handles the trailing line and
    // the parked holds, and its own end propagates to child.stdin after.
    if (gateway !== undefined) return;
    try {
      // pipe() already propagates end; this is belt-and-braces.
      if (!child.stdin.writableEnded) child.stdin.end();
    } catch {
      /* fail-open */
    }
    try {
      for (const line of c2sScanner.end()) handleLine(line, 'client_to_server');
    } catch (err) {
      tapError(err);
    }
  });
  child.stdout.on('end', () => {
    if (gateway !== undefined) return; // the s2c Transform's flush does this
    try {
      for (const line of s2cScanner.end()) handleLine(line, 'server_to_client');
    } catch (err) {
      tapError(err);
    }
  });

  // Forward terminal signals to the child only when we own the real stdin.
  const signalHandlers: Array<[NodeJS.Signals, () => void]> = [];
  let signalForwarded = false;
  if (proxyStdin === process.stdin) {
    for (const sig of ['SIGINT', 'SIGTERM', 'SIGHUP'] as NodeJS.Signals[]) {
      const handler = (): void => {
        signalForwarded = true;
        // On win32 this reaches the whole process tree (taskkill /T), not
        // just the immediate child — necessary when the child is cmd.exe
        // wrapping a .cmd/.bat shim, whose real work happens in a
        // grandchild process. See src/proxy/spawn.ts:terminateChild.
        terminateChild(child, sig);
      };
      process.on(sig, handler);
      signalHandlers.push([sig, handler]);
    }
  }
  const removeSignalHandlers = (): void => {
    for (const [sig, handler] of signalHandlers) process.removeListener(sig, handler);
  };

  return await new Promise<number>((resolve) => {
    let finished = false;
    /** errno code from the child 'error' event, when spawning failed outright. */
    let spawnErrorCode: string | undefined;

    // A request still pending at session end (server crashed or was killed
    // mid-call, or the client disconnected mid-handshake) would otherwise
    // vanish from the chain with no trace. Seal one synthetic event per
    // pending entry before session_end: a tools/call becomes a tool_call
    // event, everything else (including an unanswered initialize) becomes
    // an rpc event — both is_error, error.type 'unanswered'.
    const emitUnanswered = (): void => {
      if (pending.size === 0) return;
      const shutdownT0 = performance.now();
      for (const entry of pending.values()) {
        sealPending(entry, 'unanswered', round2(shutdownT0 - entry.t0));
      }
      pending.clear();
    };

    const finalize = async (
      reason: SessionEndEvent['reason'],
      exitCode: number | null,
      signal: NodeJS.Signals | null,
    ): Promise<void> => {
      if (finished) return;
      finished = true;
      // Gateway mode: from here on a tools/call that would be HELD is
      // refused synchronously instead (see c2sToolsCall) — a hold started
      // after this point could never be resolved.
      sessionClosing = true;
      removeSignalHandlers();
      try {
        // Gateway mode: a call still held when the session ends is refused
        // (session_end) and sealed here, before the unanswered sweep.
        resolveAllHolds?.();
      } catch (err) {
        tapError(err);
      }
      try {
        emitUnanswered();
      } catch (err) {
        tapError(err);
      }
      try {
        await recorder.flush();
      } catch {
        /* recorder is fail-open; flush never rejects, but be safe */
      }
      try {
        // The flush above is the one place finalize() yields: anything that
        // parked a hold in that window is resolved here, before session_end
        // seals the session.
        resolveAllHolds?.();
      } catch (err) {
        tapError(err);
      }
      try {
        forgetBrokeredTokens?.();
      } catch (err) {
        tapError(err);
      }
      try {
        const stats = recorder.stats();
        const ev: SessionEndEvent = {
          ...base('session_end', { 'rpc.system': 'jsonrpc' }),
          kind: 'session_end',
          reason,
          child_exit_code: exitCode,
          events_recorded: stats.written,
          events_dropped: stats.dropped,
        };
        if (spawnErrorCode !== undefined) ev.spawn_error = spawnErrorCode;
        if (signal !== null) ev.child_signal = signal;
        record(ev);
      } catch (err) {
        tapError(err);
      }
      try {
        await Promise.race([
          recorder.close(),
          new Promise<void>((res) => setTimeout(res, CLOSE_TIMEOUT_MS).unref?.()),
        ]);
      } catch {
        /* fail-open */
      }
      let code: number;
      if (exitCode !== null) {
        code = exitCode;
      } else if (signal !== null) {
        code = signalExitCode(signal);
      } else if (spawnErrorCode !== undefined) {
        code = spawnErrorExitCode(spawnErrorCode);
      } else {
        code = 0;
      }
      resolve(code);
    };

    child.on('error', (err: NodeJS.ErrnoException) => {
      diag(`failed to run ${opts.command[0]}: ${err.message}`);
      spawnErrorCode = err.code ?? 'UNKNOWN';
      void finalize('error', null, null);
    });

    // 'close' (not 'exit') so the child's stdio has fully drained through the
    // pipes before we seal the session.
    child.on('close', (code: number | null, signal: NodeJS.Signals | null) => {
      const reason: SessionEndEvent['reason'] = signalForwarded
        ? 'signal'
        : stdinEnded
          ? 'stdin_closed'
          : 'child_exit';
      void finalize(reason, code, signal);
    });
  });
}
