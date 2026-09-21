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
 * control plane could not decide" is `control_plane_unavailable` (ADR 013),
 * and the credential is absent — invariant 1 wins over invariant 8.
 *
 * What is never logged, recorded or quoted: the access token, the internal
 * token, a response body. The token is registered as a brokered secret
 * before it is returned, so no fingerprinting surface can hash it.
 */
import type { ActionClass } from '../policy/types.js';
import type { Broker, BrokerExchangeHint, BrokerExchangeRequest, BrokerExchangeResponse } from './protocol.js';
/** One declared swap site of a remote credential, as the token request describes it. */
export interface UserTokenSite {
    action_class: ActionClass;
    /** Upper-case HTTP method. */
    method: string;
}
/** One remotely brokered credential. */
export interface UserTokenCredential {
    /** The synthetic bound to this credential in the agent's environment. Hashed at construction, never kept. */
    synthetic: string;
    /** `credentials[].provider`: the control plane's connector name. */
    connector: string;
    /** Keyed by `credentials[].use[].id`. */
    sites: Record<string, UserTokenSite>;
}
/**
 * The per-user token endpoint's configuration: who is asking, through what,
 * for which tenant. Every field is copied onto the wire under the name the
 * contract gives it.
 */
export interface UserTokenConfig {
    /** `X-Cresec-Tenant`: slug or uuid. */
    tenant: string;
    /** `user_id`: the JWT `sub`, or `$<user_env>`. */
    userId: string;
    /** `tool`: the JWT `tool` claim, or `credentials[].broker.tool_id/tool_version`. */
    tool: {
        id: string;
        version: string;
    };
    /** `run_as`: from the JWT, else `user`. */
    runAs: 'user' | 'owner';
    /** `job_token`: required by the control plane when `run_as` is `owner`. */
    jobToken?: string;
    /** `run_id`: copied onto the control plane's `policy_decision` row when set. */
    runId?: string;
    credentials: Record<string, UserTokenCredential>;
}
export interface RemoteBrokerOptions {
    /** Control plane base, e.g. `https://api.cresec.internal`. No trailing path. */
    baseUrl: string;
    /** The data-plane identity the control plane resolves to a tenant (`/broker/exchange` only). */
    dataPlaneInstanceId: string;
    /** Bearer credential for the control plane itself, when it wants one. */
    authToken?: string;
    /** Budget for the whole round trip. NHI targets p99 < 150 ms cache-miss. */
    timeoutMs?: number;
    /** Present = speak `/v1/broker/user-token` (user-token.md) instead of `/broker/exchange`. */
    userToken?: UserTokenConfig;
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
/** The endpoint path of user-token.md, relative to the control plane base. */
export declare const USER_TOKEN_PATH = "/v1/broker/user-token";
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
export declare function templatePath(pathTemplate: string): string;
export declare class RemoteBroker implements Broker {
    #private;
    constructor(opts: RemoteBrokerOptions);
    exchange(req: BrokerExchangeRequest, hint?: BrokerExchangeHint): Promise<BrokerExchangeResponse>;
}
