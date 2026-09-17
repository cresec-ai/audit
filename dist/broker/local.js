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
import { canonicalJson, sha256Hex } from '../chain/hash.js';
import { globMatch } from '../policy/glob.js';
import { registerBrokeredSecret } from '../redact/redactor.js';
import { BROKER_DEFAULT_TTL_SECONDS, denyResponse, hashSynthetic, isSyntheticShaped, newDecisionId, syntheticHashesEqual, } from './protocol.js';
import { CredentialSourceError, SOURCE_DEADLINE_MS, defaultSeams, makeSource, sourceKinds, } from './sources.js';
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
export const SOURCE_UNHEALTHY_MS = 30_000;
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
export const MAX_DECISION_CACHE = 256;
/* -------------------------------------------------------------------- */
/* validation                                                           */
/* -------------------------------------------------------------------- */
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
export function validateCredentialEntry(entry) {
    const problems = [];
    const at = `credential ${entry.id || '<unnamed>'}`;
    if (!entry.id)
        problems.push('credential has no id');
    if (entry.synthetic_hash === undefined && entry.synthetic === undefined) {
        problems.push(`${at}: needs synthetic_hash (preferred) or synthetic`);
    }
    if (entry.synthetic_hash !== undefined && !/^[0-9a-f]{64}$/.test(entry.synthetic_hash)) {
        problems.push(`${at}: synthetic_hash must be 64 lowercase hex characters`);
    }
    if (!Array.isArray(entry.sites) || entry.sites.length === 0) {
        problems.push(`${at}: needs at least one swap site`);
    }
    for (const site of entry.sites ?? []) {
        if (!site.arg)
            problems.push(`${at}: a swap site has no arg dot-path`);
        if (!site.tool || site.tool.length === 0)
            problems.push(`${at}: swap site ${site.arg} has no tool glob`);
        if (!site.server || site.server.length === 0) {
            problems.push(`${at}: swap site ${site.arg} has no server glob`);
        }
        if (site.host_from === undefined) {
            problems.push(`${at}: swap site ${site.arg} must declare host_from (argument or server)`);
        }
        else if (site.host_from.kind === 'argument' && !site.host_from.arg) {
            problems.push(`${at}: swap site ${site.arg} has host_from.kind=argument with no arg`);
        }
    }
    if (!Array.isArray(entry.allow) || entry.allow.length === 0) {
        problems.push(`${at}: needs at least one allow rule, each constraining host`);
    }
    for (const rule of entry.allow ?? []) {
        if (!Array.isArray(rule.host) || rule.host.length === 0) {
            problems.push(`${at}: an allow rule has no host constraint — a swap site with an unconstrained host is a full-privilege credential`);
        }
        for (const h of rule.host ?? []) {
            if (h === '**' || h === '*') {
                problems.push(`${at}: host "${h}" constrains nothing; name the destinations`);
            }
        }
    }
    return problems;
}
/** Validate a whole credentials map, including duplicate ids and synthetics. */
export function validateCredentials(entries) {
    const problems = [];
    const seenIds = new Set();
    const seenHashes = new Set();
    for (const entry of entries) {
        if (entry.id) {
            if (seenIds.has(entry.id))
                problems.push(`duplicate credential id ${entry.id}`);
            seenIds.add(entry.id);
        }
        // Two credentials behind one synthetic would make "which credential does
        // this synthetic redeem" a question about array order, and the answer
        // would decide which real secret leaves the machine. Refuse it. (Hashes
        // only: the raw-`synthetic` form is hashed at construction, so the same
        // value written two ways is caught there as the same hash.)
        if (entry.synthetic_hash !== undefined) {
            if (seenHashes.has(entry.synthetic_hash)) {
                problems.push(`two credentials share one synthetic (${entry.id})`);
            }
            seenHashes.add(entry.synthetic_hash);
        }
        problems.push(...validateCredentialEntry(entry));
    }
    return problems;
}
/** sha256 over the canonical JSON of the credentials config, for the chain. */
export function credentialsConfigHash(entries) {
    // Canonical JSON so key order in the YAML cannot change the hash, and the
    // raw `synthetic` (when a laptop config carries one) is dropped first: the
    // hash is stamped on events, and a hash whose input includes a redeemable
    // value is a confirmation oracle for that value.
    const stripped = entries.map((e) => {
        const rest = { ...e };
        delete rest.synthetic;
        return rest;
    });
    return sha256Hex(canonicalJson(stripped));
}
export class LocalBroker {
    #entries;
    #pepper;
    #seams;
    #now;
    #ttlSeconds;
    #trust;
    #configHash;
    #onDecision;
    #warn;
    #cache = new Map();
    #health = new Map();
    constructor(opts) {
        const problems = validateCredentials(opts.credentials);
        if (problems.length > 0) {
            // Construction is the last moment a misconfiguration can be loud. A
            // broker built from an invalid config would deny every call at runtime
            // with a code that says nothing about the config being wrong.
            throw new Error(`mcp-recorder: invalid broker credentials:\n  ${problems.join('\n  ')}`);
        }
        this.#pepper = opts.pepper;
        this.#seams = opts.seams ?? defaultSeams();
        this.#now = opts.now ?? (() => Date.now());
        this.#ttlSeconds = opts.ttlSeconds ?? BROKER_DEFAULT_TTL_SECONDS;
        this.#trust = opts.configTrust ?? { configWritableByUs: true };
        this.#configHash = this.#trust.config_hash ?? credentialsConfigHash(opts.credentials);
        this.#onDecision = opts.onDecision;
        this.#warn =
            opts.warn ??
                ((line) => {
                    process.stderr.write(`mcp-recorder: ${line}\n`);
                });
        const factory = opts.makeSource ?? makeSource;
        const execRefused = this.#trust.configWritableByUs && this.#trust.allowExecFromWritableConfig !== true;
        this.#entries = opts.credentials.map((entry) => {
            const hash = entry.synthetic_hash !== undefined
                ? Buffer.from(entry.synthetic_hash, 'hex')
                : hashSynthetic(entry.synthetic, opts.pepper);
            const kinds = sourceKinds(entry.source);
            const usesExec = kinds.includes('exec');
            if (usesExec && execRefused) {
                // Refused, not merely warned about: the config that names the command
                // is writable by the uid the agent runs as, so `exec` there is a
                // standing offer of code execution as the recorder. The opt-in exists
                // because the single-user laptop is a real deployment, not because
                // the risk is theoretical.
                this.#warn(`broker: credential ${entry.id} uses an exec source while the broker config is writable by this uid — refusing it. ` +
                    `Make the config root-owned, or opt in explicitly.`);
            }
            return {
                entry,
                hash,
                source: factory(entry.source, this.#seams),
                sourceKind: entry.source.type,
                ...(usesExec && execRefused ? { blocked: 'source_untrusted_config' } : {}),
            };
        });
        if (this.#trust.configWritableByUs) {
            this.#warn('broker: the policy/broker config is writable by this uid, so credential brokering here is a context and ' +
                'audit control, not a confidentiality one — anything that can write those files aims the credential. ' +
                'Both config hashes are stamped on every decision, so a change is evident in the chain.');
        }
    }
    /**
     * One exchange. Mirrors NHI's handler step for step, and NEVER throws: a
     * throw would leave the caller deciding what an exception means about
     * authorisation, and the answer has to be "no" in one shape only.
     */
    async exchange(req, ctx = {}) {
        const decisionId = newDecisionId();
        try {
            return await this.#exchange(req, ctx, decisionId);
        }
        catch (err) {
            // Nothing below is expected to throw; this is the backstop that keeps
            // invariant 1 true whatever happens inside it.
            this.#warn(`broker: exchange failed: ${err instanceof Error ? err.message : String(err)}`);
            this.#emit({
                decision_id: decisionId,
                allowed: false,
                deny_reason: 'broker_error',
                host_binding: ctx.host_binding ?? 'unknown',
                request: summarize(req),
                cache: 'none',
                ttl_seconds: 0,
                ...(ctx.site_id !== undefined ? { site_id: ctx.site_id } : {}),
                ...this.#hashes(),
            });
            return denyResponse(decisionId, 'broker_error');
        }
    }
    async #exchange(req, ctx, decisionId) {
        const request = summarize(req);
        const hostBinding = ctx.host_binding ?? 'unknown';
        const deny = (reason, prepared, cache = 'none') => {
            this.#emit({
                decision_id: decisionId,
                allowed: false,
                deny_reason: reason,
                host_binding: hostBinding,
                request,
                cache,
                ttl_seconds: 0,
                ...(ctx.site_id !== undefined ? { site_id: ctx.site_id } : {}),
                ...(prepared !== undefined ? describe(prepared) : {}),
                ...this.#hashes(),
            });
            return denyResponse(decisionId, reason);
        };
        // 1. Resolve the synthetic. Shape and membership answer the same code:
        //    a distinct "malformed" reason is a free hint towards a valid one.
        if (typeof req.synthetic !== 'string' || !isSyntheticShaped(req.synthetic)) {
            return deny('unknown_synthetic');
        }
        const incoming = hashSynthetic(req.synthetic, this.#pepper);
        let prepared;
        for (const candidate of this.#entries) {
            // No early exit: every entry is compared, and each comparison is
            // constant-time (NHI's `syntheticHashesEqual`). The number of entries
            // is in the operator's config and is not a secret; the values are.
            if (syntheticHashesEqual(candidate.hash, incoming))
                prepared = candidate;
        }
        if (prepared === undefined)
            return deny('unknown_synthetic');
        const entry = prepared.entry;
        const status = entry.status ?? 'active';
        if (status === 'revoked')
            return deny('synthetic_revoked', prepared);
        if (status !== 'active')
            return deny('synthetic_disabled', prepared);
        if (prepared.blocked !== undefined)
            return deny(prepared.blocked, prepared);
        // 2. Authorise the DESTINATION, not just the tool. Re-evaluated on every
        //    call, cache hit included — see the header, point 3.
        const verdict = matchRules(entry.allow, request);
        if (verdict !== undefined)
            return deny(verdict, prepared);
        // 3. Resolve — from the tuple-keyed cache, or from the source under a
        //    deadline. Anything unresolvable DENIES; nothing here can fall
        //    through to "forward anyway".
        const cacheKey = tupleKey(prepared.hash, request);
        const nowMs = this.#now();
        const slot = this.#cache.get(cacheKey);
        let value;
        let expiresAtMs;
        let cache;
        if (slot !== undefined && slot.expiresAtMs > nowMs) {
            value = slot.value;
            expiresAtMs = slot.expiresAtMs;
            cache = 'hit';
        }
        else {
            cache = 'miss';
            const health = this.#health.get(entry.id);
            if (health !== undefined && health.unhealthyUntilMs > nowMs) {
                // Deny at once rather than pay the timeout again. The client sees a
                // refusal in microseconds instead of a server that looks hung.
                return deny('source_unhealthy', prepared, cache);
            }
            let resolved;
            try {
                resolved = await this.#resolve(prepared);
            }
            catch (err) {
                const code = err instanceof CredentialSourceError ? err.code : 'source_unavailable';
                const detail = err instanceof CredentialSourceError ? err.detail : errText(err);
                this.#warn(`broker: credential ${entry.id} did not resolve (${code}): ${detail ?? 'no detail'}`);
                if (code === 'source_timeout') {
                    this.#health.set(entry.id, { unhealthyUntilMs: nowMs + SOURCE_UNHEALTHY_MS });
                }
                return deny(code, prepared, cache);
            }
            if (resolved.value === '')
                return deny('source_empty', prepared, cache);
            // The value becomes un-fingerprintable BEFORE it can be returned. A
            // failure here is a denial, never a hand-over: see header point 4.
            if (!registerBrokeredSecret(resolved.value)) {
                this.#warn(`broker: brokered-secret exclusion set is full; refusing to hand out ${entry.id}`);
                return deny('exclusion_capacity', prepared, cache);
            }
            const ttlCapSeconds = Math.min(this.#ttlSeconds, entry.ttl_seconds ?? this.#ttlSeconds);
            expiresAtMs = nowMs + ttlCapSeconds * 1000;
            if (resolved.expiresAtMs !== undefined && resolved.expiresAtMs < expiresAtMs) {
                // The provider's own expiry wins when it is sooner: an STS session of
                // 900 s is not the bound here, but a 5-second-old one is.
                expiresAtMs = resolved.expiresAtMs;
            }
            value = resolved.value;
            this.#health.delete(entry.id);
            this.#remember(cacheKey, { value, expiresAtMs }, nowMs);
        }
        const ttlSeconds = Math.max(0, Math.floor((expiresAtMs - nowMs) / 1000));
        if (ttlSeconds === 0) {
            // Expired between the cap and here (a provider expiry in the past, or a
            // clock jump). Fail closed rather than hand out a token with no life.
            this.#cache.delete(cacheKey);
            return deny('source_unavailable', prepared, cache);
        }
        this.#emit({
            decision_id: decisionId,
            allowed: true,
            host_binding: hostBinding,
            request,
            cache,
            ttl_seconds: ttlSeconds,
            ...(ctx.site_id !== undefined ? { site_id: ctx.site_id } : {}),
            ...describe(prepared),
            ...this.#hashes(),
        });
        return { real_token: value, ttl_seconds: ttlSeconds, decision_id: decisionId };
    }
    /**
     * Every declared swap site, so the gateway can bind the swap to a site.
     *
     * Copies, not references: these objects decide where a credential may be
     * substituted, and a caller that mutated one would be editing the policy at
     * runtime without touching the config the decision records hash.
     */
    sites() {
        return this.#entries.flatMap((p) => p.entry.sites.map((site) => ({
            credential_id: p.entry.id,
            site: structuredClone(site),
        })));
    }
    /** Drop every cached resolution — a rotation, a revocation, or a test. */
    invalidate() {
        this.#cache.clear();
    }
    /* ----------------------------- internals ---------------------------- */
    /**
     * Resolve under a hard deadline.
     *
     * The precedent is `match.args` regexes, which run on a worker thread with
     * a 25 ms deadline because the proxy is single-threaded and a hostile
     * pattern would freeze all traffic. A source cannot be moved off the thread
     * — it IS I/O — but the same rule applies to the outcome: overrunning the
     * budget denies THIS call and marks the source unhealthy, it never waits
     * indefinitely and it never falls through to an allow.
     */
    async #resolve(prepared) {
        const kind = prepared.entry.source.type;
        const deadlineMs = SOURCE_DEADLINE_MS[kind];
        let timer;
        try {
            return await Promise.race([
                prepared.source.resolve(),
                new Promise((_resolve, reject) => {
                    timer = setTimeout(() => reject(new CredentialSourceError('source_timeout', `${kind} exceeded ${String(deadlineMs)}ms`)), deadlineMs);
                    timer.unref?.();
                }),
            ]);
        }
        finally {
            if (timer !== undefined)
                clearTimeout(timer);
        }
    }
    /**
     * Cache a resolution, dropping what has expired and then the oldest entry
     * if the map is still at its cap. `Map` iteration is insertion order, so
     * "oldest" here is oldest-inserted rather than least-recently-used — the
     * difference does not matter for a map whose entries all expire within
     * `BROKER_DEFAULT_TTL_SECONDS` anyway.
     */
    #remember(key, slot, nowMs) {
        if (this.#cache.size >= MAX_DECISION_CACHE) {
            for (const [k, v] of this.#cache) {
                if (v.expiresAtMs <= nowMs)
                    this.#cache.delete(k);
            }
            while (this.#cache.size >= MAX_DECISION_CACHE) {
                const oldest = this.#cache.keys().next();
                if (oldest.done)
                    break;
                this.#cache.delete(oldest.value);
            }
        }
        this.#cache.set(key, slot);
    }
    #hashes() {
        return {
            ...(this.#trust.policy_hash !== undefined ? { policy_hash: this.#trust.policy_hash } : {}),
            config_hash: this.#configHash,
        };
    }
    /** Recording is fail-OPEN: a sink that throws must not turn into a deny. */
    #emit(record) {
        if (this.#onDecision === undefined)
            return;
        try {
            this.#onDecision(record);
        }
        catch (err) {
            this.#warn(`broker: decision sink threw: ${err instanceof Error ? err.message : String(err)}`);
        }
    }
}
/* -------------------------------------------------------------------- */
/* helpers                                                              */
/* -------------------------------------------------------------------- */
function summarize(req) {
    const r = req.request ?? { method: '', host: '', path_template: '' };
    return {
        method: typeof r.method === 'string' ? r.method : '',
        host: typeof r.host === 'string' ? r.host : '',
        path_template: typeof r.path_template === 'string' ? r.path_template : '',
    };
}
function describe(prepared) {
    const e = prepared.entry;
    return {
        credential_id: e.id,
        ...(e.label !== undefined ? { credential_label: e.label } : {}),
        ...(e.provider !== undefined ? { provider: e.provider } : {}),
        ...(e.scopes !== undefined ? { scopes: e.scopes } : {}),
        source_kind: prepared.sourceKind,
    };
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
export function matchRules(rules, request) {
    let last = 'denied_by_policy';
    for (const rule of rules) {
        if (!Array.isArray(rule.host) || rule.host.length === 0) {
            // Defence in depth: the validator refuses this at load, so reaching it
            // means a caller built rules by hand. It denies, it does not default.
            last = 'no_host_constraint';
            continue;
        }
        if (rule.method !== undefined && rule.method.length > 0) {
            if (!rule.method.some((g) => globMatch(g, '/', request.method))) {
                last = 'method_not_permitted';
                continue;
            }
        }
        if (!rule.host.some((g) => globMatch(g, '.', request.host))) {
            last = 'host_not_permitted';
            continue;
        }
        if (rule.path_template !== undefined && rule.path_template.length > 0) {
            if (!rule.path_template.some((g) => globMatch(g, '/', request.path_template))) {
                last = 'path_not_permitted';
                continue;
            }
        }
        return undefined;
    }
    return last;
}
/**
 * The cache key: the full tuple, never the synthetic alone.
 *
 * Built from the synthetic's HASH rather than its value so the key material
 * in memory is not itself redeemable, and joined with NUL so a host of
 * "a\0b" cannot impersonate a different tuple.
 */
function tupleKey(hash, request) {
    return [hash.toString('hex'), request.method, request.host, request.path_template].join('\u0000');
}
function errText(err) {
    return err instanceof Error ? err.message : String(err);
}
//# sourceMappingURL=local.js.map