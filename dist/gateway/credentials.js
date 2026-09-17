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
import { SYNTHETIC_PREFIX } from '../broker/index.js';
import { dotPathSegments, getPath } from '../policy/engine.js';
import { globMatch } from '../policy/glob.js';
import { structuralString } from '../redact/redactor.js';
/* -------------------------------------------------------------------- */
/* Constants                                                              */
/* -------------------------------------------------------------------- */
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
export const BROKER_EXCHANGE_DEADLINE_MS = 5_000;
/**
 * Most credential swaps the gateway will have in flight at once. Beyond this
 * a swap is refused (fail-closed), the way `MAX_HOLDS` bounds parked holds:
 * each in-flight swap pins a request id and a timer, and a client that opens
 * them faster than the broker answers must not be able to grow either
 * without limit.
 */
export const MAX_INFLIGHT_SWAPS = 64;
/** Most resolved tokens held for the reverse scrub at once. */
export const MAX_LIVE_TOKENS = 32;
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
export const SCRUB_MIN_RETENTION_MS = 30_000;
/** Ceiling on the same window, so a broker returning a huge TTL cannot pin a token for the session. */
export const SCRUB_MAX_RETENTION_MS = 300_000;
/**
 * Deny codes this module decides for itself. Everything else comes back from
 * the broker in `deny_reason` and is passed through, shape-checked (see
 * {@link sanitizeDenyCode}) so a remote broker cannot write prose into the
 * text an agent reads.
 */
export const SWAP_DENY = {
    /** The exchange did not answer inside {@link BROKER_EXCHANGE_DEADLINE_MS}. */
    timeout: 'broker_timeout',
    /** `exchange()` threw or answered with a shape that is not the contract. */
    unavailable: 'broker_unavailable',
    /** 200 without a `real_token`: nothing to swap in, so nothing is forwarded. */
    noToken: 'broker_no_token',
    /** The site derives the destination from an argument, and that argument is missing or not a URL/host. */
    hostUnderivable: 'host_underivable',
    /** The derived host is not in the site's `allow_host`. */
    hostNotAllowed: 'host_not_allowed',
    /** The derived path is not in the site's `allow_path`. */
    pathNotAllowed: 'path_not_allowed',
    /** Two placeholders in one argument: no issuance produces that, so it is refused rather than guessed at. */
    multiplePlaceholders: 'multiple_placeholders',
    /** A declared site was hit by a batch element; a batch has no place to park the async exchange. */
    inBatch: 'swap_in_batch',
    /** A declared site was hit by a `tools/call` NOTIFICATION; nothing can be answered on it. */
    onNotification: 'swap_on_notification',
    /** {@link MAX_INFLIGHT_SWAPS} already in flight. */
    tooMany: 'too_many_swaps',
    /** The session ended while the exchange was in flight. */
    sessionEnd: 'session_end',
};
/**
 * Deny codes that mean the gateway could not LEARN a decision, as opposed to
 * a decision having been taken. They pick `FAIL_CLOSED_REFUSAL_GUIDANCE`
 * over `POLICY_REFUSAL_GUIDANCE` in the text the model reads: telling an
 * agent "the operator refused this" when in truth OpenBao was unreachable
 * inverts what happened, and the retry that is often the right fix is only
 * permitted by the fail-closed clause. `vault_missing_token` is NHI's own
 * code for the same class and is listed for that reason.
 */
const RESOLUTION_FAILURE_CODES = new Set([
    SWAP_DENY.timeout,
    SWAP_DENY.unavailable,
    SWAP_DENY.noToken,
    SWAP_DENY.multiplePlaceholders,
    SWAP_DENY.inBatch,
    SWAP_DENY.onNotification,
    SWAP_DENY.tooMany,
    SWAP_DENY.sessionEnd,
    'vault_missing_token',
    'source_unavailable',
    'source_timeout',
    'resolve_failed',
]);
/** A deny code shape: lower-case identifier, so nothing a broker returns becomes prose in the model's context. */
const DENY_CODE_SHAPE = /^[a-z][a-z0-9_]{0,63}$/;
/** Bare host (with optional port) for a site whose destination argument is not a full URL. */
const BARE_HOST = /^[A-Za-z0-9._-]{1,253}(?::[0-9]{1,5})?$/;
/**
 * The synthetic as it appears inside an argument. NHI mints
 * `cresec_synth_v1_<base64url(32 bytes)>` (43 characters of payload); the
 * bound here is generous on both sides so a future issuance format does not
 * silently stop being recognised — the swap is bound to the declared SITE,
 * not to this pattern, so the pattern only has to find the token inside a
 * leaf like `"Bearer cresec_synth_v1_..."`.
 */
function syntheticPattern() {
    const prefix = SYNTHETIC_PREFIX.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    return new RegExp(prefix + '[A-Za-z0-9_-]{8,256}', 'g');
}
export class CredentialsConfigError extends Error {
}
function toList(v) {
    return typeof v === 'string' ? [v] : [...v];
}
function nonEmptyGlobs(v, what, siteId) {
    const list = v === undefined ? [] : toList(v);
    if (list.length === 0 || list.some((g) => typeof g !== 'string' || g === '')) {
        throw new CredentialsConfigError(`credentials site "${siteId}": ${what} must be a non-empty glob or list of globs`);
    }
    return list;
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
export function normalizeCredentialsConfig(input) {
    const sites = (input.sites ?? []).map((raw, index) => {
        const id = raw.id ?? `credential[${index}]`;
        if (typeof raw.credential !== 'string' || raw.credential === '') {
            throw new CredentialsConfigError(`credentials site "${id}": credential (the label in the broker config) is required`);
        }
        if (typeof raw.arg !== 'string' || raw.arg === '') {
            throw new CredentialsConfigError(`credentials site "${id}": arg (the dot-path holding the synthetic) is required`);
        }
        const hostFrom = raw.host_from ?? 'arg';
        if (hostFrom !== 'arg' && hostFrom !== 'server') {
            throw new CredentialsConfigError(`credentials site "${id}": host_from must be "arg" or "server"`);
        }
        if (hostFrom === 'arg' && (typeof raw.host_arg !== 'string' || raw.host_arg === '')) {
            throw new CredentialsConfigError(`credentials site "${id}": host_arg is required unless host_from is "server"` +
                ' — the destination must come from the call, or be declared fixed');
        }
        const site = {
            id,
            credential: raw.credential,
            server: nonEmptyGlobs(raw.server ?? '*', 'server', id),
            tool: nonEmptyGlobs(raw.tool, 'tool', id),
            arg: raw.arg,
            argSegments: dotPathSegments(raw.arg),
            hostFrom,
            allowHost: nonEmptyGlobs(raw.allow_host, 'allow_host', id),
        };
        if (raw.host_arg !== undefined)
            site.hostArg = raw.host_arg;
        if (raw.path_arg !== undefined)
            site.pathArg = raw.path_arg;
        if (raw.allow_path !== undefined)
            site.allowPath = nonEmptyGlobs(raw.allow_path, 'allow_path', id);
        return site;
    });
    const out = { sites };
    if (input.config_hash !== undefined)
        out.config_hash = input.config_hash;
    return out;
}
/**
 * A plan entry that refuses before any exchange, for a caller that could not
 * plan at all. It exists so the "we could not work out what to do" path lands
 * in the same deny the rest of the module produces, rather than in a throw
 * somebody has to remember to catch.
 */
export function unplannableSwap(code) {
    return {
        site: {
            id: 'unplannable',
            credential: '',
            server: [],
            tool: [],
            arg: '',
            argSegments: [],
            hostFrom: 'server',
            allowHost: [],
        },
        path: [],
        leaf: '',
        synthetic: '',
        host: '',
        hostSource: 'server_name',
        pathTemplate: '',
        refusal: code,
    };
}
/** Derive host and path template from one argument value. */
function deriveDestination(value) {
    if (typeof value !== 'string' || value === '')
        return undefined;
    try {
        const url = new URL(value);
        // `url.host` keeps a non-default port (api.example:8443) and drops the
        // default one, which is what an author writing allow_host expects to
        // match. Hostnames are case-insensitive and globs here are not, so the
        // comparison is done on the lower-cased form.
        return { host: url.host.toLowerCase(), pathTemplate: url.pathname || '/' };
    }
    catch {
        /* not a URL: fall through to the bare-host reading */
    }
    if (BARE_HOST.test(value))
        return { host: value.toLowerCase(), pathTemplate: '/' };
    return undefined;
}
function siteMatches(site, input) {
    if (!site.server.some((g) => globMatch(g, '/', input.server)))
        return false;
    return site.tool.some((g) => globMatch(g, '/', input.tool));
}
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
export function planSwaps(config, input) {
    const out = [];
    for (const site of config.sites) {
        if (!siteMatches(site, input))
            continue;
        const leaf = getPath(input.args, site.arg);
        if (typeof leaf !== 'string')
            continue;
        const found = leaf.match(syntheticPattern());
        if (found === null || found.length === 0)
            continue;
        // Exactly one placeholder per site, and it must be the whole leaf or a
        // substring of it (`"Bearer <synthetic>"`). Two in one leaf is not a
        // shape any issuance produces, so it is refused rather than guessed at.
        const synthetic = found[0];
        const planned = {
            site,
            path: ['params', 'arguments', ...site.argSegments],
            leaf,
            synthetic,
            host: '',
            hostSource: site.hostFrom === 'server' ? 'server_name' : 'argument',
            pathTemplate: '',
        };
        if (found.length > 1) {
            planned.refusal = SWAP_DENY.multiplePlaceholders;
        }
        if (site.hostFrom === 'server') {
            planned.host = input.server.toLowerCase();
            planned.pathTemplate = input.tool;
        }
        else {
            const derived = deriveDestination(getPath(input.args, site.hostArg));
            if (derived === undefined) {
                planned.refusal = planned.refusal ?? SWAP_DENY.hostUnderivable;
                planned.host = '';
                planned.pathTemplate = '';
            }
            else {
                planned.host = derived.host;
                planned.pathTemplate =
                    site.pathArg === undefined
                        ? derived.pathTemplate
                        : (deriveDestination(getPath(input.args, site.pathArg))?.pathTemplate ?? derived.pathTemplate);
            }
        }
        if (planned.refusal === undefined) {
            // The gateway's own floor under the broker's decision. OPA sees `host`
            // and `path_template` too and may refuse for its own reasons; this
            // check is what makes the destination part of the decision even when
            // the broker behind the seam ignores it.
            if (!site.allowHost.some((g) => globMatch(g, '.', planned.host))) {
                planned.refusal = SWAP_DENY.hostNotAllowed;
            }
            else if (site.allowPath !== undefined && !site.allowPath.some((g) => globMatch(g, '/', planned.pathTemplate))) {
                planned.refusal = SWAP_DENY.pathNotAllowed;
            }
        }
        out.push(planned);
    }
    return out;
}
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
export class TokenScrubber {
    live = [];
    /** Hold `token` for the lifetime of its decision. */
    retain(token, synthetic, ttlSeconds, now = Date.now()) {
        if (token === '' || token === synthetic)
            return;
        this.sweep(now);
        const ttlMs = Math.min(SCRUB_MAX_RETENTION_MS, Math.max(SCRUB_MIN_RETENTION_MS, Number.isFinite(ttlSeconds) ? ttlSeconds * 1000 : 0));
        const existing = this.live.find((t) => t.token === token);
        if (existing !== undefined) {
            existing.expiresAt = Math.max(existing.expiresAt, now + ttlMs);
            existing.synthetic = synthetic;
            return;
        }
        // Bounded: the oldest expiry goes first, so a session that swaps many
        // credentials keeps the most recently used ones covered rather than
        // growing the table without limit.
        if (this.live.length >= MAX_LIVE_TOKENS) {
            let oldest = 0;
            for (let i = 1; i < this.live.length; i++) {
                if (this.live[i].expiresAt < this.live[oldest].expiresAt)
                    oldest = i;
            }
            this.live.splice(oldest, 1);
        }
        this.live.push({ token, synthetic, expiresAt: now + ttlMs });
    }
    /** Drop everything whose retention window has passed. */
    sweep(now = Date.now()) {
        for (let i = this.live.length - 1; i >= 0; i--) {
            if (this.live[i].expiresAt <= now)
                this.live.splice(i, 1);
        }
    }
    /** Forget every token immediately (session end). */
    clear() {
        this.live.length = 0;
    }
    /** True when at least one token is live; the cheap gate before any scan. */
    active(now = Date.now()) {
        this.sweep(now);
        return this.live.length > 0;
    }
    /**
     * Cheap needle test over raw text. One `includes` per live token beats
     * walking a parsed tree for the overwhelmingly common case of a result
     * that does not contain one.
     */
    mightContain(text, now = Date.now()) {
        this.sweep(now);
        return this.live.some((t) => text.includes(t.token));
    }
    /** Replace every live token in `text` with its synthetic. */
    scrubText(text, now = Date.now()) {
        this.sweep(now);
        let out = text;
        // Longest first: one token that is a prefix of another must not eat the
        // longer one's bytes and leave a tail of the real value behind.
        for (const t of [...this.live].sort((a, b) => b.token.length - a.token.length)) {
            if (out.includes(t.token))
                out = out.split(t.token).join(t.synthetic);
        }
        return out;
    }
    /**
     * Copy-on-write scrub of a parsed message. Untouched subtrees come back BY
     * REFERENCE, which is what lets `spliceRewrittenLine` put the original
     * bytes of everything else back on the wire and rewrite only the spans
     * that changed.
     *
     * Object KEYS are scrubbed too: a server that answers `{"<token>": 1}`
     * would otherwise hand the value straight to the model.
     */
    scrubMessage(message, now = Date.now()) {
        this.sweep(now);
        if (this.live.length === 0)
            return { message, changed: false };
        let changed = false;
        const walk = (v, depth) => {
            if (depth > 256)
                return v; // same bound the hashers use; a deeper tree is not one a server really sends
            if (typeof v === 'string') {
                const s = this.scrubText(v, now);
                if (s !== v)
                    changed = true;
                return s;
            }
            if (Array.isArray(v)) {
                let touched = false;
                const out = v.map((x) => {
                    const y = walk(x, depth + 1);
                    if (y !== x)
                        touched = true;
                    return y;
                });
                return touched ? out : v;
            }
            if (typeof v === 'object' && v !== null) {
                let touched = false;
                const out = {};
                for (const [k, val] of Object.entries(v)) {
                    const nk = this.scrubText(k, now);
                    const nv = walk(val, depth + 1);
                    if (nk !== k || nv !== val)
                        touched = true;
                    out[nk] = nv;
                }
                if (touched)
                    changed = true;
                return touched ? out : v;
            }
            return v;
        };
        const out = walk(message, 0);
        return { message: out, changed };
    }
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
    scrubBytes(bytes, now = Date.now()) {
        this.sweep(now);
        if (this.live.length === 0)
            return bytes;
        const text = bytes.toString('utf8');
        const scrubbed = this.scrubText(text, now);
        return scrubbed === text ? bytes : Buffer.from(scrubbed, 'utf8');
    }
}
/** Shape-check a code off the broker before it reaches a refusal message or an event. */
function sanitizeDenyCode(reason) {
    return typeof reason === 'string' && DENY_CODE_SHAPE.test(reason) ? reason : 'denied_by_policy';
}
/** True when a deny means "no decision was reached", not "the answer was no". */
export function isResolutionFailure(code) {
    return RESOLUTION_FAILURE_CODES.has(code);
}
/** Copy-on-write write of one leaf, sharing every untouched subtree by reference. */
function replaceAt(root, path, value) {
    if (path.length === 0)
        return value;
    const [head, ...rest] = path;
    if (typeof head === 'number') {
        if (!Array.isArray(root) || head >= root.length)
            return root;
        const out = [...root];
        out[head] = replaceAt(root[head], rest, value);
        return out;
    }
    if (typeof root !== 'object' || root === null || Array.isArray(root))
        return root;
    const obj = root;
    if (!Object.prototype.hasOwnProperty.call(obj, head))
        return root;
    return { ...obj, [head]: replaceAt(obj[head], rest, value) };
}
/**
 * The swap engine. One per session; holds the live-token table the reverse
 * scrub reads.
 */
export class CredentialSwap {
    scrubber;
    broker;
    config;
    dataPlaneInstanceId;
    deadlineMs;
    now;
    constructor(deps) {
        this.broker = deps.broker;
        this.config = deps.config;
        this.dataPlaneInstanceId = deps.dataPlaneInstanceId;
        this.deadlineMs = deps.deadlineMs ?? BROKER_EXCHANGE_DEADLINE_MS;
        this.now = deps.now ?? Date.now;
        this.scrubber = deps.scrubber ?? new TokenScrubber();
    }
    /** Declared sites this call engages. Empty = ordinary traffic, forwarded as written. */
    plan(input) {
        return planSwaps(this.config, input);
    }
    /** True when the config declares any site at all (lets the caller skip the walk entirely). */
    get hasSites() {
        return this.config.sites.length > 0;
    }
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
    async exchange(message, plan, ctx) {
        const decisions = [];
        let out = message;
        for (const planned of plan) {
            const decision = {
                siteId: planned.site.id,
                credential: planned.site.credential,
                decisionId: '',
                host: planned.host,
                hostSource: planned.hostSource,
                pathTemplate: planned.pathTemplate,
                ttlSeconds: 0,
            };
            if (planned.refusal !== undefined) {
                decision.denyCode = planned.refusal;
                decisions.push(decision);
                return this.deny(planned.refusal, decisions);
            }
            const req = {
                synthetic: planned.synthetic,
                data_plane_instance_id: this.dataPlaneInstanceId,
                request: {
                    // MCP's mapping onto the wire's request summary, as the contract
                    // fixes it: the JSON-RPC method, the destination this call is
                    // actually aimed at, and the tool name as the path template when
                    // the upstream is the server itself.
                    method: 'tools/call',
                    host: planned.host,
                    path_template: planned.pathTemplate,
                },
            };
            if (ctx.userAgent !== undefined && ctx.userAgent !== '')
                req.request.user_agent = ctx.userAgent;
            let res;
            try {
                res = await this.withDeadline(this.broker.exchange(req));
            }
            catch (err) {
                // CODES only: the underlying message may quote a command line, a
                // vault path with a token in it, or an upstream 401 body.
                const code = err instanceof DeadlineError ? SWAP_DENY.timeout : SWAP_DENY.unavailable;
                decision.denyCode = code;
                decisions.push(decision);
                return this.deny(code, decisions);
            }
            decision.decisionId = typeof res?.decision_id === 'string' ? res.decision_id : '';
            if (res === null || typeof res !== 'object') {
                decision.denyCode = SWAP_DENY.unavailable;
                decisions.push(decision);
                return this.deny(SWAP_DENY.unavailable, decisions);
            }
            if (res.denied === true || typeof res.real_token !== 'string' || res.real_token === '') {
                const code = res.denied === true ? sanitizeDenyCode(res.deny_reason) : SWAP_DENY.noToken;
                decision.denyCode = code;
                decisions.push(decision);
                return this.deny(code, decisions);
            }
            decision.ttlSeconds = typeof res.ttl_seconds === 'number' && Number.isFinite(res.ttl_seconds) ? res.ttl_seconds : 0;
            decisions.push(decision);
            this.scrubber.retain(res.real_token, planned.synthetic, decision.ttlSeconds, this.now());
            // Splice the real value into a COPY: `message` is the object the tap
            // records from, and it keeps the synthetic. Record-then-swap is the
            // pipeline order, not a check a later edit can forget.
            out = replaceAt(out, planned.path, planned.leaf.split(planned.synthetic).join(res.real_token));
        }
        return { kind: 'allow', message: out, decisions, attributes: swapAttributes(decisions, this.config) };
    }
    deny(code, decisions) {
        return {
            kind: 'deny',
            code,
            failClosed: isResolutionFailure(code),
            decisions,
            attributes: { ...swapAttributes(decisions, this.config), 'cresec.credential.deny_reason': code },
        };
    }
    withDeadline(p) {
        return new Promise((resolve, reject) => {
            // unref'd: a proxy that is shutting down must not be held open for the
            // remainder of a deadline nobody is waiting on any more.
            const timer = setTimeout(() => reject(new DeadlineError()), this.deadlineMs);
            timer.unref?.();
            p.then((v) => {
                clearTimeout(timer);
                resolve(v);
            }, (err) => {
                clearTimeout(timer);
                reject(err instanceof Error ? err : new Error('broker exchange failed'));
            });
        });
    }
}
class DeadlineError extends Error {
}
/**
 * The decision, as event attributes. Everything here is an id, a label or a
 * destination — never the resolved value, and never a hash of it, because a
 * ref of a real token is a brute-forceable copy of it. `attributes` is an
 * open map on the frozen v1 schema, so this adds no field to any event type.
 */
export function swapAttributes(decisions, config) {
    if (decisions.length === 0)
        return {};
    const join = (xs) => structuralString(xs.filter((x) => x !== '').join(','), 'identifier');
    const attributes = {
        'cresec.credential.id': join(decisions.map((d) => d.credential)),
        'cresec.credential.site': join(decisions.map((d) => d.siteId)),
        'cresec.credential.host': join(decisions.map((d) => d.host)),
        'cresec.credential.host_source': join(decisions.map((d) => d.hostSource)),
        'cresec.credential.path_template': join(decisions.map((d) => d.pathTemplate)),
    };
    const ids = decisions.map((d) => d.decisionId).filter((d) => d !== '');
    if (ids.length > 0)
        attributes['cresec.broker.decision_id'] = join(ids);
    const ttl = decisions.reduce((acc, d) => Math.max(acc, d.ttlSeconds), 0);
    if (ttl > 0)
        attributes['cresec.broker.ttl_seconds'] = ttl;
    // Both hashes on every decision: a policy or broker-config edit mid-session
    // cannot be prevented where the agent's uid can write those files, but it
    // is EVIDENT in a tamper-evident chain that records what was in force.
    if (config?.config_hash !== undefined)
        attributes['cresec.credential.config_hash'] = config.config_hash;
    return attributes;
}
/** The refusal reason an agent reads. A CODE, never the underlying error. */
export function swapDenyReason(code) {
    return `credential broker denied the swap (${code})`;
}
//# sourceMappingURL=credentials.js.map