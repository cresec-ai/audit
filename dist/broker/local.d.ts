/**
 * LocalBroker — NHI's exchange, resolved on this machine.
 *
 * It answers the same two JSON objects NHI's `/broker/exchange` answers, in
 * the same order of checks (synthetic -> credential -> policy -> resolve ->
 * decide), and differs only in where each answer comes from: a config array
 * instead of postgres, glob rules instead of OPA, a {@link CredentialSource}
 * instead of OpenBao. Swapping it for {@link RemoteBroker} is a config change
 * because nothing above it knows which one it holds.
 *
 * THE FOUR THINGS THIS FILE IS CAREFUL ABOUT
 *
 * 1. FAIL CLOSED, ALWAYS. Every path that cannot produce an authorised real
 *    credential returns a DENIAL — never the request unmodified, never the
 *    synthetic passed through, never a partial answer. `exchange()` does not
 *    throw: a throw on the forwarding path is an ambiguous outcome, and the
 *    caller would have to decide what an exception means about
 *    authorisation. There is exactly one return shape for "no", and it
 *    carries a code.
 *
 * 2. THE DESTINATION IS PART OF THE DECISION. A rule that constrains only the
 *    tool authorises `http_post` to attacker.example exactly as happily as to
 *    api.github.com, and the agent chooses the argument. So every credential
 *    MUST carry at least one rule with a non-empty `host`, the validator
 *    refuses one that does not, and the decision record says whether that
 *    host came from the CALL's own arguments or was the static server name —
 *    "host was checked" and "host was assumed" must not read alike in a log.
 *    NHI's OPA input carries `host` and `path_template` separately for the
 *    same reason (exchange.ts, step 6).
 *
 * 3. THE CACHE IS KEYED ON THE WHOLE TUPLE. NHI's data plane caches a
 *    positive decision for 30 s and busts it over NATS. A local cache keyed
 *    on the synthetic alone would turn one allow for `github/create_issue`
 *    into 30 s of allow for `github/delete_repo`, so the key is
 *    (synthetic hash, method, host, path_template) and it holds the RESOLVED
 *    VALUE only. The policy is re-evaluated on EVERY call, cache hit or not:
 *    it is a handful of anchored globs, measured at ~1.5 us for a three-rule
 *    credential inside a ~10 us cache-hit exchange (Node 22, this repo's
 *    CI-class hardware), where the rest is one HMAC and one UUID. There is
 *    nothing worth saving by caching a verdict, and a verdict cached under
 *    any key is the same bug wearing a different hat.
 *
 * 4. THE REAL VALUE NEVER BECOMES A REF. Before a resolved credential is
 *    returned it is registered with `registerBrokeredSecret`, so every
 *    fingerprinting surface in the recorder excludes it. Registration is a
 *    precondition of returning, not a step afterwards: if it fails the call
 *    is DENIED (`exclusion_capacity`). The decision record carries the
 *    credential's id, label, provider and scopes and never its value — and
 *    never the synthetic either, because a synthetic is redeemable on this
 *    machine and the id answers every question the value would.
 */
import { Buffer } from 'node:buffer';
import type { Broker, BrokerExchangeHint, BrokerExchangeRequest, BrokerExchangeResponse, DenyReason } from './protocol.js';
import type { CredentialSource, CredentialSourceSpec, SourceSeams } from './sources.js';
/**
 * Where a swap-site's `host` / `path_template` are taken from.
 *
 * `argument` is the only binding worth having for a generic egress tool: the
 * `url` of an `http_post`, the `repo` of a GitHub tool. `server` is the
 * honest fallback for a stdio server that talks to one fixed upstream — the
 * decision then records `host_binding: "server"` so the chain distinguishes a
 * host that was checked from a host that was the server's name.
 */
export type FieldBinding = {
    kind: 'argument';
    arg: string;
} | {
    kind: 'server';
} | {
    kind: 'tool';
};
/**
 * A declared swap site: the ONE place a synthetic may be replaced.
 *
 * The swap is destination-bound, never value-bound. Replacing the synthetic
 * "wherever it appears" is defeated by any tool that returns its input — an
 * `echo`, a `create_issue` whose body the agent reads back, a malformed call
 * whose error quotes the offending argument — and the real token comes back
 * in the model's context, which is the one place this design exists to keep
 * it out of. An undeclared site therefore receives the SYNTHETIC and the
 * upstream rejects it, which is the correct outcome and a visible one.
 *
 * This type lives here rather than in the policy so that the broker, which
 * has to authorise a call, and the gateway, which has to perform the swap,
 * agree on one vocabulary — the same dot-paths `McpMatch.args` already uses.
 */
export interface CredentialSwapSite {
    /** Stable id for the decision record; defaults to `<server>/<tool>#<arg>`. */
    id?: string;
    /** Globs on the logical server name, delimiter "/". */
    server: string[];
    /** Globs on the tool name, delimiter "/". */
    tool: string[];
    /** Dot-path under `params.arguments` holding the synthetic. */
    arg: string;
    /** Where `request.host` comes from for a call at this site. */
    host_from: FieldBinding;
    /** Where `request.path_template` comes from. Defaults to the tool name. */
    path_from?: FieldBinding;
}
/** What a credential is allowed to be used FOR. At least one, each with a host. */
export interface CredentialRule {
    /** Globs on `request.method`, delimiter "/". Default: any. */
    method?: string[];
    /** Globs on `request.host`, delimiter ".". REQUIRED and non-empty. */
    host: string[];
    /** Globs on `request.path_template`, delimiter "/". Default: any. */
    path_template?: string[];
}
export interface CredentialEntry {
    /** Stable id recorded on every decision. Not a secret. */
    id: string;
    /** Human label, e.g. "github ci token (issues only)". */
    label?: string;
    /** Provider key, e.g. "github". Recorded so blast radius is answerable. */
    provider?: string;
    /** What the REAL credential can do. Recorded, never enforced by us. */
    scopes?: string[];
    status?: 'active' | 'revoked' | 'disabled';
    /**
     * HMAC-SHA256(synthetic, pepper), hex. This is what a config file should
     * carry: NHI stores the hash and shows the raw value once, and the same
     * argument holds locally — a config full of raw synthetics is a config full
     * of values that are redeemable on this machine.
     */
    synthetic_hash?: string;
    /**
     * The raw synthetic, for the laptop case where nothing has minted one yet.
     * Hashed at construction and dropped; still, prefer `synthetic_hash`.
     */
    synthetic?: string;
    source: CredentialSourceSpec;
    /** Declared swap sites. The gateway may swap at these and nowhere else. */
    sites: CredentialSwapSite[];
    /** Destination constraints. Empty or host-less is a validation error. */
    allow: CredentialRule[];
    /** Cap the TTL below the 30 s default. Never raises it. */
    ttl_seconds?: number;
}
/**
 * The trust the operator has in the files that name all of the above.
 *
 * `configWritableByUs` comes from `assessConfigTrust`. When it is true, an
 * `exec` source is refused — `exec` is arbitrary code execution by
 * configuration, running as the recorder, on every brokered call — unless the
 * operator explicitly opts in for the single-uid laptop case. The hashes are
 * stamped on every decision record so that a mid-session edit is EVIDENT in a
 * tamper-evident chain. Evident, not impossible: anything that can write
 * these files controls the swap, and only an OS boundary or the hosted
 * control plane changes that.
 */
export interface ConfigTrust {
    configWritableByUs: boolean;
    allowExecFromWritableConfig?: boolean;
    /** sha256 of the normalized policy document. */
    policy_hash?: string;
    /** sha256 of the normalized credentials config; computed here when absent. */
    config_hash?: string;
}
/** Local-only context the caller knows and the wire shape has no field for. */
export interface ExchangeContext {
    /** Which declared site produced this call. */
    site_id?: string;
    /** How `request.host` was obtained. Recorded, so an assumption reads as one. */
    host_binding?: 'argument' | 'server';
}
/**
 * What the recorder writes as a `broker.decision` event. Never the real
 * token, never the synthetic — an id and a decision id, per invariant 4.
 */
export interface BrokerDecisionRecord {
    decision_id: string;
    allowed: boolean;
    deny_reason?: DenyReason;
    credential_id?: string;
    credential_label?: string;
    provider?: string;
    scopes?: string[];
    source_kind?: string;
    site_id?: string;
    host_binding: 'argument' | 'server' | 'unknown';
    request: {
        method: string;
        host: string;
        path_template: string;
    };
    cache: 'hit' | 'miss' | 'none';
    ttl_seconds: number;
    policy_hash?: string;
    config_hash?: string;
}
export interface LocalBrokerOptions {
    credentials: CredentialEntry[];
    /** Local pepper for the synthetic HMAC — NHI's per-tenant pepper, locally. */
    pepper: Buffer;
    seams?: SourceSeams;
    /** Source factory override. Tests inject fakes here; nothing else should. */
    makeSource?: (spec: CredentialSourceSpec, seams: SourceSeams) => CredentialSource;
    now?: () => number;
    /** Cap on a positive decision's TTL. Defaults to NHI's 30 s. */
    ttlSeconds?: number;
    configTrust?: ConfigTrust;
    /** Called once per exchange, allow or deny. Must not throw; see `exchange`. */
    onDecision?: (record: BrokerDecisionRecord) => void;
    /** Operator-facing diagnostics. Defaults to stderr. */
    warn?: (line: string) => void;
}
/**
 * How long a source stays unhealthy after it overruns its deadline.
 *
 * The point is not to punish the source, it is that a brokered call sits on
 * the forwarding path: paying a 5 s timeout on every call to a black-holed
 * OpenBao turns one dead dependency into a client that thinks the MCP server
 * has hung. After one overrun the next calls deny at the cost of an ordinary
 * exchange (~8 us, measured) until the window passes, then one call probes
 * again.
 */
export declare const SOURCE_UNHEALTHY_MS = 30000;
/**
 * Cap on cached resolutions.
 *
 * The cache key is the full tuple, which is the right key and also an
 * unbounded one: a rule allowing `*.github.com` allows an unbounded number of
 * distinct hosts, and the agent writes the host. Without a cap, a loop of
 * allowed calls to invented subdomains grows a map of live tokens for as long
 * as it runs. 256 is well past any real session's working set (a session uses
 * a handful of destinations) and eviction costs only a re-resolution, never a
 * weaker decision — the policy is re-evaluated on every call regardless.
 */
export declare const MAX_DECISION_CACHE = 256;
/**
 * Problems that make a credential entry unusable. Returned rather than
 * thrown so a policy validator can report every one of them at once.
 *
 * The host rule is the one to read twice: a swap site with no host
 * constraint is a full-privilege credential with extra steps, so it is an
 * ERROR and not a permissive default. "Least privilege" is not claimable
 * from a policy that constrains the tool and leaves the destination to the
 * agent.
 */
export declare function validateCredentialEntry(entry: CredentialEntry): string[];
/** Validate a whole credentials map, including duplicate ids and synthetics. */
export declare function validateCredentials(entries: CredentialEntry[]): string[];
/** sha256 over the canonical JSON of the credentials config, for the chain. */
export declare function credentialsConfigHash(entries: CredentialEntry[]): string;
export declare class LocalBroker implements Broker {
    #private;
    constructor(opts: LocalBrokerOptions);
    /**
     * One exchange. Mirrors NHI's handler step for step, and NEVER throws: a
     * throw would leave the caller deciding what an exception means about
     * authorisation, and the answer has to be "no" in one shape only.
     */
    exchange(req: BrokerExchangeRequest, ctx?: ExchangeContext & Partial<BrokerExchangeHint>): Promise<BrokerExchangeResponse>;
    /**
     * Every declared swap site, so the gateway can bind the swap to a site.
     *
     * Copies, not references: these objects decide where a credential may be
     * substituted, and a caller that mutated one would be editing the policy at
     * runtime without touching the config the decision records hash.
     */
    sites(): Array<{
        credential_id: string;
        site: CredentialSwapSite;
    }>;
    /** Drop every cached resolution — a rotation, a revocation, or a test. */
    invalidate(): void;
}
/**
 * First rule that matches wins, as everywhere else in this codebase; nothing
 * matching is a deny. Returns the deny CODE, or undefined when allowed.
 *
 * The code names the field that failed on the LAST rule tried, which is the
 * one an operator wants when a single rule is the obvious intended one. Globs
 * come from `policy/glob.ts` — the same matcher the engine and the emitted
 * Rego share, so a credential rule cannot read a glob differently from the
 * rule that allowed the tool call in the first place.
 */
export declare function matchRules(rules: CredentialRule[], request: {
    method: string;
    host: string;
    path_template: string;
}): DenyReason | undefined;
