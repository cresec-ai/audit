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
import type { Broker, BrokerExchangeRequest, BrokerExchangeResponse } from './protocol.js';
export interface RemoteBrokerOptions {
    /** Control plane base, e.g. `https://api.cresec.internal`. No trailing path. */
    baseUrl: string;
    /** The data-plane identity the control plane resolves to a tenant. */
    dataPlaneInstanceId: string;
    /** Bearer credential for the control plane itself, when it wants one. */
    authToken?: string;
    /** Budget for the whole round trip. NHI targets p99 < 150 ms cache-miss. */
    timeoutMs?: number;
    /** Transport seam. Tests inject; production gets `sinkFetch`. */
    fetch?: (req: {
        method: 'POST';
        url: string;
        headers: Record<string, string>;
        body: string;
        timeoutMs: number;
    }) => Promise<{
        status: number;
        body: string;
    }>;
    warn?: (line: string) => void;
}
/** Default round-trip budget: 5 s, the same the Go client's http.Client uses. */
export declare const REMOTE_TIMEOUT_MS = 5000;
export declare class RemoteBroker implements Broker {
    #private;
    constructor(opts: RemoteBrokerOptions);
    exchange(req: BrokerExchangeRequest): Promise<BrokerExchangeResponse>;
}
