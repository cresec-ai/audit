/**
 * RemoteBroker — the same exchange, answered by a real control plane.
 *
 * Two wire shapes, one class, one fail-closed rule:
 *
 *  - **`/broker/exchange`** (the default): the TypeScript twin of
 *    `packages/brokerclient/client.go`, which both NHI data planes use, down
 *    to the rule that decides allow from deny — the HTTP STATUS is the
 *    source of truth, not the body's `denied` field, because a 403's body
 *    is the only one guaranteed to carry it. Keyed by (data-plane instance,
 *    synthetic).
 *  - **`/v1/broker/user-token`** (`userToken` option; what `credentials[].
 *    broker: { kind: remote }` wires): the per-user token endpoint of
 *    cresec-ai/nhi `docs/internal/contracts/user-token.md`, keyed by (user,
 *    connector, tool, action class, target). Request and response fields
 *    are copied from that page and from `packages/contracts/src/user-token.ts`
 *    byte for byte; the synthetic never leaves this process (it is what is
 *    swapped, not what is sent) and is checked here against the credential
 *    the site named, so a placeholder for one credential cannot buy another
 *    credential's token.
 *
 * Transport is the sink's `sinkFetch` by default: HTTPS_PROXY/NO_PROXY
 * CONNECT tunnelling and split connect/total timeouts, with certificate
 * verification never disabled. A control plane reachable only through a
 * corporate proxy would otherwise fail closed on every call, and "the broker
 * denies everything" is a worse failure than it sounds — it is indistinguishable
 * from a policy that says no.
 *
 * Fail-closed, like everything else on this path: a transport failure, an
 * unparseable body or an unexpected status is a DENIAL with a locally minted
 * decision id, never an exception for the caller to interpret and never a
 * pass-through. The Go client returns an error there and leaves the choice to
 * its caller; we do not have that luxury on a forwarding path, so the choice
 * is made here and it is "no". On the per-user path the code for "the
 * control plane could not decide" is `control_plane_unavailable`, and the
 * credential is absent: invariant 8 as C1 (cresec-ai/nhi docs/decisions.md,
 * 2026-09-23; recorded in https://github.com/cresec-ai/nhi/pull/10, not yet
 * merged) words it, fail closed and retryable, reads included.
 *
 * What is never logged, recorded or quoted: the access token, the internal
 * token, a response body. The token is registered as a brokered secret
 * before it is returned, so no fingerprinting surface can hash it.
 */
import { Buffer } from 'node:buffer';
import { sinkFetch } from '../sink/http.js';
import { registerBrokeredSecret } from '../redact/redactor.js';
import { denyResponse, hashSynthetic, mintPepper, newDecisionId, syntheticHashesEqual } from './protocol.js';
/** Default round-trip budget: 5 s, the same the Go client's http.Client uses. */
export const REMOTE_TIMEOUT_MS = 5_000;
/**
 * How long an observed control-plane outage refuses per-user token requests
 * without asking, before one probe is let through (the corrected outage
 * contract of ClickUp z8n6b5z9fd, 2026-09-21; invariant 8 as C1 words it).
 * See {@link RemoteBroker}.
 */
export const OUTAGE_COOLDOWN_MS = 5_000;
/** The endpoint path of user-token.md, relative to the control plane base. */
export const USER_TOKEN_PATH = '/v1/broker/user-token';
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
/** A reason code as policy-decide.md spells them; anything else is not copied onto an event. */
const REASON_CODE = /^[a-z][a-z0-9_]{0,63}$/;
/** A path segment that names one thing rather than one kind of thing. */
const UUID_SEGMENT = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const NUMERIC_SEGMENT = /^\d+$/;
const HEX_SEGMENT = /^[0-9a-f]{12,}$/i;
/** 16+ opaque characters with at least one digit: message ids, record ids, base64url handles. */
const OPAQUE_SEGMENT = /^(?=.*\d)[A-Za-z0-9_.=-]{16,}$/;
/**
 * `target.path_template` "with identifiers replaced" (user-token.md; ADR 015
 * in cresec-ai/nhi): every path segment that looks like an identifier —
 * a uuid, a run of digits, long hex, or a long opaque token carrying a
 * digit — becomes `{id}`, so a message id, a record id or a draft id in a
 * URL argument never reaches the control plane's `policy_decision` row. A
 * template says what KIND of thing was touched, not which. The tool name
 * (a site with no URL argument) has no segments to replace and crosses as
 * it is. Conservative by design: a segment this misses is one the
 * operator's `path.allow` globs can still constrain, and the control plane
 * records what it was given.
 */
export function templatePath(pathTemplate) {
    if (pathTemplate === '' || !pathTemplate.startsWith('/'))
        return pathTemplate;
    return pathTemplate
        .split('/')
        .map((seg) => seg !== '' && (UUID_SEGMENT.test(seg) || NUMERIC_SEGMENT.test(seg) || HEX_SEGMENT.test(seg) || OPAQUE_SEGMENT.test(seg)) ? '{id}' : seg)
        .join('/');
}
/**
 * ## Degrade: fail closed, fast, and say so
 *
 * The per-user path has no fallback. The agent holds only a synthetic, and
 * nothing here keeps a stored credential or a cached token to serve a read
 * with (invariant 8 as C1 words it: nothing falls back to a stored
 * credential or a cached decision, reads included; ADR 013's cached-read
 * forward was never built here), so a control plane that cannot be reached
 * means the call is refused with `control_plane_unavailable` — never forwarded,
 * never forwarded with the synthetic.
 *
 * What an outage must not do is cost every call the full round-trip budget.
 * The first failure opens an outage window: for {@link OUTAGE_COOLDOWN_MS}
 * every call that needs the control plane is refused at once, with the same
 * code, without a request. After the window ONE call probes; the others are
 * still refused until it answers. Any answer that shows the control plane is
 * up (an allow, a deny, a 4xx, a 503 naming the vault or a connector) closes
 * the window; a failed probe reopens it. Only admission is affected: a call
 * already swapped and forwarded to the vendor is not recalled or cancelled.
 *
 * The outage is logged twice, at its start and its end, each line marked as
 * this process's own observation — nothing here claims a complete outage
 * history, and the chain holds exactly what happened to each call: a
 * `policy_decision` whose `cresec.credential.deny_reason` is
 * `control_plane_unavailable`.
 */
export class RemoteBroker {
    #opts;
    #warn;
    #now;
    #outage;
    /** Per-credential synthetic hashes, peppered per process, for the user-token path. */
    #credentials = new Map();
    #pepper;
    constructor(opts) {
        if (!opts.baseUrl)
            throw new Error('mcp-recorder: RemoteBroker needs a baseUrl');
        if (!opts.dataPlaneInstanceId) {
            throw new Error('mcp-recorder: RemoteBroker needs a dataPlaneInstanceId');
        }
        this.#opts = opts;
        this.#now = opts.now ?? Date.now;
        this.#pepper = mintPepper();
        this.#warn =
            opts.warn ??
                ((line) => {
                    process.stderr.write(`mcp-recorder: ${line}\n`);
                });
        if (opts.userToken !== undefined) {
            const ut = opts.userToken;
            if (ut.tenant === '')
                throw new Error('mcp-recorder: RemoteBroker user-token mode needs a tenant');
            if (!UUID.test(ut.userId))
                throw new Error('mcp-recorder: RemoteBroker user-token mode needs a uuid user id');
            if (ut.tool.id === '' || ut.tool.version === '')
                throw new Error('mcp-recorder: RemoteBroker user-token mode needs a tool id and version');
            for (const [id, cred] of Object.entries(ut.credentials)) {
                if (cred.synthetic === '')
                    throw new Error(`mcp-recorder: credential "${id}" has no synthetic bound`);
                this.#credentials.set(id, {
                    syntheticHash: hashSynthetic(cred.synthetic, this.#pepper),
                    connector: cred.connector,
                    sites: cred.sites,
                });
            }
        }
    }
    async exchange(req, hint) {
        if (this.#opts.userToken !== undefined)
            return this.#userToken(req, hint);
        return this.#brokerExchange(req);
    }
    /* ----------------------- /v1/broker/user-token ---------------------- */
    async #userToken(req, hint) {
        const ut = this.#opts.userToken;
        // The site names the credential; the synthetic must be the one bound to
        // it. Both "unknown credential" and "wrong synthetic" answer the same
        // code, so a caller learns nothing from the difference.
        const cred = hint === undefined ? undefined : this.#credentials.get(hint.credential);
        if (cred === undefined || hint === undefined)
            return denyResponse(newDecisionId(), 'unknown_synthetic');
        if (!syntheticHashesEqual(hashSynthetic(req.synthetic, this.#pepper), cred.syntheticHash)) {
            return denyResponse(newDecisionId(), 'unknown_synthetic');
        }
        const site = cred.sites[hint.site];
        if (site === undefined)
            return denyResponse(newDecisionId(), 'denied_by_policy');
        if (!this.#admit())
            return denyResponse(newDecisionId(), 'control_plane_unavailable');
        let res;
        try {
            res = await this.#userTokenRequest(ut, cred, site, req);
        }
        catch (err) {
            // Not expected — the request path turns every failure into a deny —
            // but a probe that threw must not leave the window stuck on "probing",
            // which would refuse every later call for the life of the process.
            this.#observeDown();
            throw err;
        }
        if (res.denied === true && res.deny_reason === 'control_plane_unavailable')
            this.#observeDown();
        else
            this.#observeUp();
        return res;
    }
    /**
     * May a request go to the control plane now? Closed window: yes. Open
     * window: no, until it expires; then exactly one probe goes, and every
     * other call is refused until that probe has answered.
     */
    #admit() {
        const o = this.#outage;
        if (o === undefined)
            return true;
        if (o.probing || this.#now() < o.retryAt) {
            o.refused += 1;
            return false;
        }
        o.probing = true;
        return true;
    }
    #observeDown() {
        const now = this.#now();
        const cooldown = this.#opts.outageCooldownMs ?? OUTAGE_COOLDOWN_MS;
        const o = this.#outage;
        if (o === undefined) {
            this.#outage = { since: now, retryAt: now + cooldown, probing: false, refused: 0 };
            this.#warn(`broker: control plane unavailable (observed by this process at ${new Date(now).toISOString()}); ` +
                `calls that need it are refused as control_plane_unavailable, with no credential fallback, ` +
                `and one is let through every ${String(cooldown)} ms to probe`);
            return;
        }
        o.retryAt = now + cooldown;
        o.probing = false;
    }
    #observeUp() {
        const o = this.#outage;
        if (o === undefined)
            return;
        this.#outage = undefined;
        const now = this.#now();
        this.#warn(`broker: control plane reachable again at ${new Date(now).toISOString()} — unavailable for ` +
            `${String(now - o.since)} ms as observed by this process, ${String(o.refused)} call(s) refused without asking it`);
    }
    async #userTokenRequest(ut, cred, site, req) {
        const url = `${this.#opts.baseUrl.replace(/\/+$/, '')}${USER_TOKEN_PATH}`;
        const headers = {
            'content-type': 'application/json',
            accept: 'application/json',
            'x-cresec-tenant': ut.tenant,
        };
        if (this.#opts.authToken !== undefined)
            headers.authorization = `Bearer ${this.#opts.authToken}`;
        // user-token.md, "Request": every field under the contract's name.
        // `host` lowercase and `method` uppercase are the contract's rules.
        const body = JSON.stringify({
            user_id: ut.userId,
            connector: cred.connector,
            tool: { id: ut.tool.id, version: ut.tool.version },
            action_class: site.action_class,
            target: { host: req.request.host.toLowerCase(), path_template: templatePath(req.request.path_template), method: site.method.toUpperCase() },
            run_as: ut.runAs,
            job_token: ut.jobToken ?? null,
            run_id: ut.runId ?? null,
        });
        let res;
        try {
            res = await this.#fetch({ method: 'POST', url, headers, body, timeoutMs: this.#opts.timeoutMs ?? REMOTE_TIMEOUT_MS });
        }
        catch (err) {
            // Invariant 8 (C1): a connect error or a timeout means the control
            // plane could not decide; the credential is absent and the call is denied.
            this.#warn(`broker: ${USER_TOKEN_PATH} unreachable: ${err instanceof Error ? err.message : String(err)}`);
            return denyResponse(newDecisionId(), 'control_plane_unavailable');
        }
        let parsed = undefined;
        try {
            parsed = JSON.parse(res.body);
        }
        catch {
            parsed = undefined;
        }
        const obj = typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed) ? parsed : undefined;
        const decisionId = obj !== undefined && typeof obj.decision_id === 'string' && UUID.test(obj.decision_id) ? obj.decision_id : newDecisionId();
        const reasonOf = (fallback) => {
            const reason = obj?.reason;
            return typeof reason === 'string' && REASON_CODE.test(reason) ? reason : fallback;
        };
        if (res.status === 403) {
            // The control plane's deny, with its reason; the status wins over the body.
            return { decision_id: decisionId, ttl_seconds: 0, denied: true, deny_reason: reasonOf('policy_denied') };
        }
        if (res.status === 503) {
            // "the decision was allow but the token could not be produced; the
            // caller records a deny with the same reason" — vault_unavailable or
            // connector_unavailable. Anything else on a 503 is the control plane
            // being unavailable as a whole.
            const reason = reasonOf('control_plane_unavailable');
            const code = reason === 'vault_unavailable' || reason === 'connector_unavailable' ? reason : 'control_plane_unavailable';
            this.#warn(`broker: ${USER_TOKEN_PATH} answered 503 (${code})`);
            return denyResponse(decisionId, code);
        }
        if (res.status !== 200) {
            this.#warn(`broker: ${USER_TOKEN_PATH} answered ${String(res.status)}`);
            return denyResponse(decisionId, res.status >= 500 ? 'control_plane_unavailable' : 'broker_error');
        }
        if (obj === undefined) {
            this.#warn(`broker: ${USER_TOKEN_PATH} body is not a JSON object`);
            return denyResponse(decisionId, 'broker_error');
        }
        const token = obj.token;
        const accessToken = typeof token === 'object' && token !== null && !Array.isArray(token)
            ? token.access_token
            : undefined;
        if (typeof accessToken !== 'string' || accessToken === '') {
            // A 200 with no token is not an allow. Fail closed rather than forward
            // a call with nothing swapped into it.
            this.#warn(`broker: ${USER_TOKEN_PATH} answered 200 with no token.access_token`);
            return denyResponse(decisionId, 'broker_error');
        }
        // Registered BEFORE it is handed back, exactly as LocalBroker does: no
        // fingerprinting surface may ever hash this value.
        if (!registerBrokeredSecret(accessToken)) {
            this.#warn('broker: brokered-secret exclusion set is full; denying rather than risk a fingerprint');
            return denyResponse(decisionId, 'exclusion_capacity');
        }
        // `ttl_ms` is min(expires_at - now, 300000). user-token.md introduced it
        // as the bound of ADR 013's degrade cache, which nhi's M1.18 will drop
        // (C1: fail closed, no cached decision); it stays on the wire because this
        // broker needs it, and the swap engine only uses it to size the
        // reverse-scrub window. The contract's mapping is
        // `ttl_seconds: floor(ttl_ms / 1000)`, and an allow whose ttl is missing,
        // not a number, or under one second is a malformed allow — exactly as
        // the /broker/exchange path treats a zero `ttl_seconds` — not a token to
        // forward with a made-up lifetime.
        const ttlMs = obj.ttl_ms;
        const ttl = typeof ttlMs === 'number' && Number.isFinite(ttlMs) && ttlMs > 0 ? Math.floor(ttlMs / 1000) : 0;
        if (ttl === 0) {
            this.#warn(`broker: ${USER_TOKEN_PATH} answered 200 with no usable ttl_ms`);
            return denyResponse(decisionId, 'broker_error');
        }
        return { real_token: accessToken, ttl_seconds: ttl, decision_id: decisionId };
    }
    /* --------------------------- /broker/exchange ------------------------ */
    async #brokerExchange(req) {
        const url = `${this.#opts.baseUrl.replace(/\/+$/, '')}/broker/exchange`;
        const headers = {
            'content-type': 'application/json',
            accept: 'application/json',
        };
        if (this.#opts.authToken !== undefined) {
            headers.authorization = `Bearer ${this.#opts.authToken}`;
        }
        // The instance id belongs to the broker, not to the caller: a request
        // that named its own data plane would let anything reaching the gateway
        // choose which tenant's credentials to be measured against.
        const body = JSON.stringify({
            synthetic: req.synthetic,
            data_plane_instance_id: this.#opts.dataPlaneInstanceId,
            request: req.request,
        });
        let res;
        try {
            res = await this.#fetch({
                method: 'POST',
                url,
                headers,
                body,
                timeoutMs: this.#opts.timeoutMs ?? REMOTE_TIMEOUT_MS,
            });
        }
        catch (err) {
            // The error text can quote the request body, which carries the
            // synthetic; it goes to the operator, and the caller gets a code.
            this.#warn(`broker: /broker/exchange unreachable: ${err instanceof Error ? err.message : String(err)}`);
            return denyResponse(newDecisionId(), 'broker_unreachable');
        }
        if (res.status !== 200 && res.status !== 403) {
            this.#warn(`broker: /broker/exchange answered ${String(res.status)}`);
            return denyResponse(newDecisionId(), 'broker_error');
        }
        let parsed;
        try {
            parsed = JSON.parse(res.body);
        }
        catch {
            this.#warn('broker: /broker/exchange body is not JSON');
            return denyResponse(newDecisionId(), 'broker_error');
        }
        if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
            return denyResponse(newDecisionId(), 'broker_error');
        }
        const obj = parsed;
        const decisionId = typeof obj.decision_id === 'string' ? obj.decision_id : newDecisionId();
        if (res.status === 403) {
            // Status wins over the body, exactly as the Go client decides it.
            const reason = typeof obj.deny_reason === 'string' ? obj.deny_reason : 'denied_by_policy';
            return { decision_id: decisionId, ttl_seconds: 0, denied: true, deny_reason: reason };
        }
        const realToken = obj.real_token;
        if (typeof realToken !== 'string' || realToken === '') {
            // A 200 with no token is not an allow. Fail closed rather than forward
            // a call with nothing swapped into it.
            this.#warn('broker: /broker/exchange answered 200 with no real_token');
            return denyResponse(decisionId, 'broker_error');
        }
        const ttl = typeof obj.ttl_seconds === 'number' && obj.ttl_seconds > 0 ? Math.floor(obj.ttl_seconds) : 0;
        if (ttl === 0)
            return denyResponse(decisionId, 'broker_error');
        return { real_token: realToken, ttl_seconds: ttl, decision_id: decisionId };
    }
    async #fetch(req) {
        if (this.#opts.fetch !== undefined)
            return await this.#opts.fetch(req);
        const res = await sinkFetch({
            method: 'POST',
            url: req.url,
            headers: req.headers,
            body: Buffer.from(req.body, 'utf8'),
            totalTimeoutMs: req.timeoutMs,
        });
        return { status: res.status, body: res.body.toString('utf8') };
    }
}
//# sourceMappingURL=remote.js.map