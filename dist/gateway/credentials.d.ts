/**
 * Credential swap — the gateway half of the broker path.
 *
 * WHAT THIS IS. A declared site in the policy's `credentials` section says
 * "the argument at this dot-path, of this tool, on this server, holds a
 * synthetic placeholder". On an outbound `tools/call` the gateway exchanges
 * that placeholder for a real token at `broker.exchange()` — NHI's
 * `/broker/exchange` wire shape, byte for byte (see
 * apps/api/src/routes/broker.ts in cresec-ai/nhi) — and splices the real
 * token into the outbound bytes. On the way back it replaces any occurrence
 * of that token with the synthetic again, before the client sees it.
 *
 * WHAT IT BUYS, STATED HONESTLY. The real credential is absent from the
 * model's context and from the transcript, and every use of it is a recorded,
 * policy-checked decision carrying a decision id that can be revoked. It is
 * NOT hidden from anything that can run code as the same OS user: on a
 * single-uid developer machine the agent can read the broker config and the
 * source it names (an env var, a file, an `exec`), so the swap is a context
 * and audit control there, and a confidentiality control only when the
 * resolver runs as a principal the agent is not. Nothing in this file should
 * be read as claiming otherwise.
 *
 * THE SWAP IS DESTINATION-BOUND, NEVER VALUE-BOUND. It fires at declared
 * (server, tool, dot-path) sites and nowhere else — NOT wherever the
 * synthetic string happens to appear. That is the control that stops the
 * obvious attack on a value-bound swap: ask a tool to hand the argument
 * back (`http_post(body=<synthetic>)`, an echo tool, an error message that
 * quotes the offending argument) and read the real token out of the result.
 * An echo tool is not a declared site, so it receives the synthetic and the
 * upstream rejects it. {@link TokenScrubber} is the seatbelt for the case
 * where a DECLARED site's server reflects the token anyway; it is defeated
 * by any encoding transform (base64, splitting the value across two fields,
 * one character per line), which is why destination binding is the control
 * and the scrub is not.
 *
 * AND THE DESTINATION IS PART OF THE DECISION. `request.host` /
 * `request.path_template` are derived from the CALL's own arguments (the
 * `url` argument of a generic egress tool), not from the static server
 * identity, because authorising `http_post` without authorising where it
 * posts to authorises `http_post` to attacker.example just as happily as to
 * api.github.com. A site must declare `allow_host`; one that does not is a
 * configuration error, refused at load (see {@link normalizeCredentialsConfig}).
 * Where the upstream genuinely is fixed (a stdio server that talks to one
 * place) a site may say `host_from: server`, and the decision then records
 * `host_source: server_name` so the chain distinguishes "the host was
 * checked" from "the host was the server's name".
 *
 * WHAT NEVER HAPPENS HERE. The resolved token is never hashed, never
 * fingerprinted, never logged and never put in a diagnostic: refs are
 * unsalted sha256 by design (`Redactor.hashString`), so a ref of a real
 * token is a brute-forceable copy of it — the same reasoning as
 * `isRecorderOwnEnvVar` in ../redact/redactor.ts, one layer down. Deny
 * reasons are CODES only, exactly as NHI's exchange.ts returns them
 * (`unknown_synthetic`, `vault_missing_token`), never the underlying error
 * text, a command line or a response body. What IS recorded is which
 * credential was used (its label) and under which `decision_id`.
 */
import { type Broker } from '../broker/index.js';
import type { Attributes } from '../schema/events.js';
/**
 * How long ONE `broker.exchange()` may take before the gateway gives up and
 * denies the call.
 *
 * 5 s, the same bound NHI's own client carries (`packages/brokerclient`'s
 * default `&http.Client{Timeout: 5 * time.Second}`), so a local resolver and
 * the hosted control plane behave alike from the proxy's side. The deadline
 * exists because enforcement is fail-closed AND on the forwarding path: an
 * `exec` source that hangs or a dead OpenBao would otherwise stall the
 * thread the client is waiting on, and the client would see a hung MCP
 * server instead of a refusal. Expiry denies; it never forwards.
 */
export declare const BROKER_EXCHANGE_DEADLINE_MS = 5000;
/**
 * Most credential swaps the gateway will have in flight at once. Beyond this
 * a swap is refused (fail-closed), the way `MAX_HOLDS` bounds parked holds:
 * each in-flight swap pins a request id and a timer, and a client that opens
 * them faster than the broker answers must not be able to grow either
 * without limit.
 */
export declare const MAX_INFLIGHT_SWAPS = 64;
/** Most resolved tokens held for the reverse scrub at once. */
export declare const MAX_LIVE_TOKENS = 32;
/**
 * Floor on how long a resolved token stays in the scrub table after the
 * exchange that produced it.
 *
 * 30 s, matching `BROKER_DEFAULT_TTL_SECONDS` in NHI's exchange.ts — the TTL
 * its data plane caches a positive decision for. The scrub must outlive the
 * call that used the token (a slow tool answers late, and a server can echo
 * the value in a later notification), and the token is redeemable upstream
 * for at least its own TTL anyway, so this window costs nothing that the
 * credential's own validity has not already granted. It is still residency:
 * the value sits in this process's heap for the window, and JS strings
 * cannot be reliably zeroed, so the claim is SHORT residency, not erasure.
 */
export declare const SCRUB_MIN_RETENTION_MS = 30000;
/** Ceiling on the same window, so a broker returning a huge TTL cannot pin a token for the session. */
export declare const SCRUB_MAX_RETENTION_MS = 300000;
/**
 * Deny codes this module decides for itself. Everything else comes back from
 * the broker in `deny_reason` and is passed through, shape-checked (see
 * {@link sanitizeDenyCode}) so a remote broker cannot write prose into the
 * text an agent reads.
 */
export declare const SWAP_DENY: {
    /** The exchange did not answer inside {@link BROKER_EXCHANGE_DEADLINE_MS}. */
    readonly timeout: "broker_timeout";
    /** `exchange()` threw or answered with a shape that is not the contract. */
    readonly unavailable: "broker_unavailable";
    /** 200 without a `real_token`: nothing to swap in, so nothing is forwarded. */
    readonly noToken: "broker_no_token";
    /** The site derives the destination from an argument, and that argument is missing or not a URL/host. */
    readonly hostUnderivable: "host_underivable";
    /** The derived host is not in the site's `allow_host`. */
    readonly hostNotAllowed: "host_not_allowed";
    /** The derived path is not in the site's `allow_path`. */
    readonly pathNotAllowed: "path_not_allowed";
    /** Two placeholders in one argument: no issuance produces that, so it is refused rather than guessed at. */
    readonly multiplePlaceholders: "multiple_placeholders";
    /** A declared site was hit by a batch element; a batch has no place to park the async exchange. */
    readonly inBatch: "swap_in_batch";
    /** A declared site was hit by a `tools/call` NOTIFICATION; nothing can be answered on it. */
    readonly onNotification: "swap_on_notification";
    /** {@link MAX_INFLIGHT_SWAPS} already in flight. */
    readonly tooMany: "too_many_swaps";
    /** The session ended while the exchange was in flight. */
    readonly sessionEnd: "session_end";
};
/** A glob or a non-empty list of globs, as the policy author writes it. */
export type GlobOrList = string | string[];
/** Where a site's destination comes from. `server` = the MCP server's own name. */
/**
 * Where the destination comes from. `fixed` exists because a policy may
 * declare the host outright (`host: { fixed: api.stripe.com }`) for a server
 * whose upstream is not named in any argument — without it such a site has no
 * expressible destination, and a site with no destination constraint is the
 * failure the red team named: authorising a tool without authorising where it
 * points.
 */
export type HostFrom = 'arg' | 'server' | 'fixed';
/** One declared swap site, as authored. */
export interface CredentialSiteInput {
    id?: string;
    /**
     * The credential's LABEL in the broker config. Never a source, a path or a
     * command: the config names where a secret lives, the policy names only
     * which one, and a CALL names neither.
     */
    credential: string;
    server?: GlobOrList;
    tool: GlobOrList;
    /** Dot-path of the argument holding the synthetic, in `McpMatch.args` vocabulary. */
    arg: string;
    /** Default `arg`: derive the destination from a call argument. */
    host_from?: HostFrom;
    /** Dot-path of the argument the host (and by default the path) is derived from. */
    host_arg?: string;
    /** The destination itself, when `host_from` is "fixed". */
    host_fixed?: string;
    /** Dot-path of the argument the path template is derived from, when it is not `host_arg`. */
    path_arg?: string;
    /** REQUIRED. Globs on the derived host, `.` delimiter — the destination constraint. */
    allow_host: GlobOrList;
    /** Globs on the derived path template, `/` delimiter. Absent = any path. */
    allow_path?: GlobOrList;
}
export interface CredentialsConfigInput {
    sites: CredentialSiteInput[];
    /**
     * sha256 of the normalized policy and broker config, stamped on every
     * decision so a mid-session edit of either is EVIDENT in the chain. It
     * cannot be prevented on a machine where the agent's uid can write those
     * files; the chain is tamper-evident, which is the property to lean on.
     */
    config_hash?: string;
}
/** Normalized site: every default filled in, every glob a list. */
export interface CredentialSite {
    id: string;
    credential: string;
    server: string[];
    tool: string[];
    arg: string;
    argSegments: (string | number)[];
    hostFrom: HostFrom;
    /** Set only when `hostFrom` is "fixed". */
    hostFixed?: string;
    hostArg?: string;
    pathArg?: string;
    allowHost: string[];
    allowPath?: string[];
}
export interface CredentialsConfig {
    sites: CredentialSite[];
    config_hash?: string;
}
export declare class CredentialsConfigError extends Error {
}
/**
 * Validate and normalize the `credentials` section.
 *
 * Throws rather than degrading: a site the gateway cannot read exactly is a
 * site that would otherwise swap a real credential somewhere nobody meant,
 * and enforcement fails closed. The two refusals worth naming:
 *
 *  - **no `allow_host`** — a swap site with an unconstrained destination is
 *    a full-privilege credential with extra steps: the policy would authorise
 *    the TOOL and leave the agent to choose where it points. It is a
 *    configuration error, not a default-allow.
 *  - **`host_from: arg` with no `host_arg`** — same hole, reached by leaving
 *    the derivation unsaid.
 */
export declare function normalizeCredentialsConfig(input: CredentialsConfigInput): CredentialsConfig;
/** One swap the gateway intends to perform, decided from the parsed message alone. */
export interface PlannedSwap {
    site: CredentialSite;
    /** Path from the MESSAGE root to the leaf, e.g. ['params','arguments','headers','Authorization']. */
    path: (string | number)[];
    /** The leaf exactly as the client wrote it. */
    leaf: string;
    /** The synthetic token inside that leaf. */
    synthetic: string;
    host: string;
    hostSource: 'argument' | 'server_name' | 'declared';
    pathTemplate: string;
    /** Set when the destination already fails the site's own constraint: a deny decided before any exchange. */
    refusal?: string;
}
export interface PlanInput {
    server: string;
    tool: string;
    /** `params.arguments` of the parsed request — the SAME object the policy was evaluated against. */
    args: unknown;
}
/**
 * A plan entry that refuses before any exchange, for a caller that could not
 * plan at all. It exists so the "we could not work out what to do" path lands
 * in the same deny the rest of the module produces, rather than in a throw
 * somebody has to remember to catch.
 */
export declare function unplannableSwap(code: string): PlannedSwap;
/**
 * The swaps a call asks for: one per declared site whose argument actually
 * carries a synthetic. A site that matches the tool but whose argument holds
 * something else is simply not engaged — the call is ordinary traffic and is
 * forwarded as written.
 *
 * Everything here reads the ONE parsed object the policy was evaluated
 * against. Deriving the destination from a re-parse, or finding the
 * placeholder by searching the raw line, is how the two halves end up acting
 * on different things — `spliceRewrittenLine` in ../proxy/stdio.ts exists
 * because this codebase already learned that lesson once.
 */
export declare function planSwaps(config: CredentialsConfig, input: PlanInput): PlannedSwap[];
/**
 * The server->client seatbelt: for as long as a decision is live, every
 * occurrence of its real token in anything coming back is replaced by the
 * synthetic before the client sees it.
 *
 * It runs over the WHOLE message, not the two text fields the boundary
 * filter scans, because `structuredContent`, `_meta` and resource blobs are
 * otherwise forwarded verbatim — and it can, because unlike the boundary's
 * secret-SHAPED families this is one exact high-entropy needle.
 *
 * It is defeated by any encoding transform: base64, the value split across
 * two fields, a tool that returns it one character per line. Destination
 * binding is the control; this is the seatbelt.
 */
export declare class TokenScrubber {
    private readonly live;
    /** Hold `token` for the lifetime of its decision. */
    retain(token: string, synthetic: string, ttlSeconds: number, now?: number): void;
    /** Drop everything whose retention window has passed. */
    sweep(now?: number): void;
    /** Forget every token immediately (session end). */
    clear(): void;
    /** True when at least one token is live; the cheap gate before any scan. */
    active(now?: number): boolean;
    /**
     * Cheap needle test over raw text. One `includes` per live token beats
     * walking a parsed tree for the overwhelmingly common case of a result
     * that does not contain one.
     */
    mightContain(text: string, now?: number): boolean;
    /** Replace every live token in `text` with its synthetic. */
    scrubText(text: string, now?: number): string;
    /**
     * Copy-on-write scrub of a parsed message. Untouched subtrees come back BY
     * REFERENCE, which is what lets `spliceRewrittenLine` put the original
     * bytes of everything else back on the wire and rewrite only the spans
     * that changed.
     *
     * Object KEYS are scrubbed too: a server that answers `{"<token>": 1}`
     * would otherwise hand the value straight to the model.
     */
    scrubMessage(message: unknown, now?: number): {
        message: unknown;
        changed: boolean;
    };
    /**
     * Last-resort byte sweep at the single point where bytes leave for the
     * client. The structural scrub above is the one that matters — it runs
     * before the result is hashed into an event — but this catches the paths
     * that never become a parsed message: an unparseable server line, a line
     * the gateway forwarded verbatim, bytes written by another layer.
     *
     * It cannot catch a token split across two chunks of an OVERSIZED line,
     * which the splitter streams through as it arrives; that is the same class
     * of gap as the encoding transforms above, and is documented rather than
     * papered over.
     */
    scrubBytes(bytes: Buffer, now?: number): Buffer;
}
export interface ExchangeContext {
    /** Logical MCP server name — the `server` the policy matched on. */
    server: string;
    /** Tool name, which is what `path_template` carries for a fixed-upstream site. */
    tool: string;
    /** MCP client name/version from `initialize`, mapped onto `user_agent`. */
    userAgent?: string;
}
/** What one exchange decided, for the diagnostics and the event attributes. */
export interface SwapDecision {
    siteId: string;
    credential: string;
    decisionId: string;
    host: string;
    hostSource: 'argument' | 'server_name' | 'declared';
    pathTemplate: string;
    ttlSeconds: number;
    denyCode?: string;
}
export type SwapOutcome = {
    kind: 'allow';
    message: unknown;
    decisions: SwapDecision[];
    attributes: Attributes;
} | {
    kind: 'deny';
    code: string;
    failClosed: boolean;
    decisions: SwapDecision[];
    attributes: Attributes;
};
export interface CredentialSwapDeps {
    broker: Broker;
    config: CredentialsConfig;
    /** Identity the broker knows this proxy by; NHI resolves it to a tenant. */
    dataPlaneInstanceId: string;
    scrubber?: TokenScrubber;
    deadlineMs?: number;
    now?: () => number;
}
/** True when a deny means "no decision was reached", not "the answer was no". */
export declare function isResolutionFailure(code: string): boolean;
/**
 * The swap engine. One per session; holds the live-token table the reverse
 * scrub reads.
 */
export declare class CredentialSwap {
    readonly scrubber: TokenScrubber;
    private readonly broker;
    private readonly config;
    private readonly dataPlaneInstanceId;
    private readonly deadlineMs;
    private readonly now;
    constructor(deps: CredentialSwapDeps);
    /** Declared sites this call engages. Empty = ordinary traffic, forwarded as written. */
    plan(input: PlanInput): PlannedSwap[];
    /** True when the config declares any site at all (lets the caller skip the walk entirely). */
    get hasSites(): boolean;
    /**
     * Exchange every planned synthetic and return the message to forward.
     *
     * NEVER resolves to the original message on failure: invariant 1 says a
     * broker that cannot authorise a call denies it, and the synthetic must
     * never travel on to the upstream. The two ways out of here are a message
     * with the real tokens spliced in, and a deny.
     *
     * Never rejects: a throw from `exchange()` becomes `broker_unavailable`,
     * so the caller has one shape to handle on the forwarding path.
     */
    exchange(message: unknown, plan: readonly PlannedSwap[], ctx: ExchangeContext): Promise<SwapOutcome>;
    private deny;
    private withDeadline;
}
/**
 * The decision, as event attributes. Everything here is an id, a label or a
 * destination — never the resolved value, and never a hash of it, because a
 * ref of a real token is a brute-forceable copy of it. `attributes` is an
 * open map on the frozen v1 schema, so this adds no field to any event type.
 */
export declare function swapAttributes(decisions: readonly SwapDecision[], config?: CredentialsConfig): Attributes;
/** The refusal reason an agent reads. A CODE, never the underlying error. */
export declare function swapDenyReason(code: string): string;
