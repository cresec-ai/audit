/**
 * RemoteBroker — the same exchange, answered by a real control plane.
 *
 * This is the reason the wire shape in `protocol.ts` is copied field for
 * field instead of being "inspired by": with a control plane reachable, the
 * gateway holds one of these instead of a `LocalBroker` and nothing above it
 * changes. It is the TypeScript twin of `packages/brokerclient/client.go`,
 * which both NHI data planes use, down to the rule that decides allow from
 * deny — the HTTP STATUS is the source of truth, not the body's `denied`
 * field, because a 403's body is the only one guaranteed to carry it.
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
 * is made here and it is "no".
 */
import { Buffer } from 'node:buffer';
import { sinkFetch } from '../sink/http.js';
import { denyResponse, newDecisionId } from './protocol.js';
/** Default round-trip budget: 5 s, the same the Go client's http.Client uses. */
export const REMOTE_TIMEOUT_MS = 5_000;
export class RemoteBroker {
    #opts;
    #warn;
    constructor(opts) {
        if (!opts.baseUrl)
            throw new Error('mcp-recorder: RemoteBroker needs a baseUrl');
        if (!opts.dataPlaneInstanceId) {
            throw new Error('mcp-recorder: RemoteBroker needs a dataPlaneInstanceId');
        }
        this.#opts = opts;
        this.#warn =
            opts.warn ??
                ((line) => {
                    process.stderr.write(`mcp-recorder: ${line}\n`);
                });
    }
    async exchange(req) {
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