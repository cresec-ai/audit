/**
 * FROM A POLICY FILE TO A LIVE SWAP — the last mile.
 *
 * Everything else in src/broker/ is reachable only from a test until
 * something builds a broker out of an operator's policy and hands the gateway
 * a `CredentialSwap`. That is what this module does, and it is deliberately
 * the only place the three pieces meet:
 *
 *   policy.credentials[]  ->  CredentialEntry[]      (what LocalBroker resolves)
 *                         ->  CredentialsConfigInput (where the gateway may splice)
 *
 * The two shapes overlap but are not the same, and the split is the point.
 * The gateway knows only about SITES — (server, tool, argument dot-path) — so
 * that a leaked synthetic in some other argument is inert. The broker knows
 * about SOURCES and DESTINATIONS, so that a site which matched still has to
 * satisfy a host rule before a real token is handed back. Neither half can
 * authorise a call on its own.
 *
 * WHERE THE SYNTHETIC COMES FROM. The policy deliberately does not carry it.
 * A policy file is meant to be readable evidence of the rules — shareable,
 * diffable, committed — and a file full of raw synthetics is a file full of
 * values that are redeemable on this machine. So each credential's synthetic
 * is supplied out of band, in the environment, under a name derived from its
 * id:
 *
 *   credential id "github-issues"  ->  MCP_RECORDER_SYNTHETIC_GITHUB_ISSUES
 *
 * That variable is set in the AGENT's environment (it is what the agent
 * holds) and in the recorder's, because the recorder is the agent's child.
 * `mcp-recorder credentials issue <id>` mints one in NHI's format.
 *
 * The pepper is per process and never persisted. It can be, because the raw
 * synthetic is supplied on every start: the broker hashes it at construction
 * with the same pepper it hashes incoming requests with, so the binding holds
 * for the life of the process and nothing on disk is worth stealing. A
 * persisted pepper would be one more file on the agent's side of the boundary.
 *
 * WHAT THIS DOES NOT DO. It does not make the credential confidential from
 * the agent. On a single-uid developer machine the agent can read the same
 * environment and the same policy this function reads. What it buys is that
 * the real credential is absent from the model's context, absent from the
 * transcript and absent from the evidence chain, and that every use of it is
 * a recorded, policy-checked decision. docs/pov.md carries the full claim.
 */
import type { Credential, Policy } from '../policy/types.js';
import { CredentialSwap } from '../gateway/credentials.js';
import type { IdentityJwtClaims } from '../identity/actor.js';
import type { Broker, BrokerExchangeHint, BrokerExchangeRequest, BrokerExchangeResponse } from './protocol.js';
import { type RemoteBrokerOptions } from './remote.js';
/** Raised when a policy expresses something the local broker cannot resolve. */
export declare class CredentialWiringError extends Error {
}
/**
 * One `Broker` over two: a credential whose policy entry carries `broker:
 * { kind: remote }` is answered by the control plane, every other one by
 * the local resolver. Routing is by the SITE's credential id (the hint the
 * swap engine passes), never by the synthetic — the remote path is keyed on
 * (user, connector, tool, action class, target), which are properties of
 * the declared site, and a request that arrives with no hint at all cannot
 * name a remote credential and falls to the local broker, which knows
 * nothing about it and denies `unknown_synthetic`.
 */
export declare class CompositeBroker implements Broker {
    #private;
    constructor(local: Broker | undefined, remote: Broker | undefined, remoteCredentialIds: Iterable<string>);
    exchange(req: BrokerExchangeRequest, hint?: BrokerExchangeHint): Promise<BrokerExchangeResponse>;
}
/**
 * Register the real credentials a policy points at, so that nothing hashes
 * them. Returns the variables it could not register because the exclusion set
 * was full — a condition the caller must treat as fatal rather than continue
 * through, since past that point a real token can reach the chain.
 */
export declare function registerPolicyEnvSecrets(credentials: readonly Credential[], env: NodeJS.ProcessEnv): string[];
/** Environment variable carrying the synthetic bound to a credential id. */
export declare function syntheticEnvVar(credentialId: string): string;
export interface CredentialSwapWiring {
    swap: CredentialSwap;
    /** Credential ids with no synthetic in the environment; reported, not fatal. */
    unbound: string[];
}
export interface WireOptions {
    policy: Policy;
    env: NodeJS.ProcessEnv;
    /** Identity the broker knows this proxy by. Ephemeral unless supplied. */
    dataPlaneInstanceId?: string;
    /**
     * The identity JWT's claims (`--identity-jwt`, or the env var a remote
     * credential's `identity_jwt_env` names — see `identityJwtFromPolicy`).
     * Supplies `user_id`, the tenant and the tool claim of every per-user
     * token request; without it those come from `user_env`, `tenant` and
     * `tool_id`/`tool_version` on the `broker` block, and a remote credential
     * that has neither is a wiring error (exit 2), not a silent deny.
     */
    identity?: IdentityJwtClaims;
    /**
     * The compact JWS the claims came from. Needed only for a JOB token
     * (`kind: job`, `run_as: owner`): user-token.md requires `job_token` when
     * `run_as = owner`, and identity-jwt.md says the job token IS the identity
     * JWT with `kind: job` — so it is sent as given. Never recorded.
     */
    identityJwt?: string;
    /** Transport seam for the remote broker (tests inject; production gets `sinkFetch`). */
    remoteFetch?: RemoteBrokerOptions['fetch'];
    /** Operator diagnostics; the caller routes these to stderr. */
    warn?: (line: string) => void;
}
/**
 * The env var, if any, a policy says holds the identity JWT: the first
 * remote credential's `identity_jwt_env`. Read by the CLI BEFORE wiring, so
 * the same claims stamp the actor on every event and key the token requests.
 */
export declare function identityJwtEnvFromPolicy(policy: Policy): string | undefined;
/**
 * Build the swap for a policy, or `undefined` when there is nothing to build.
 *
 * `undefined` means the proxy behaves exactly as it did before credential
 * brokering existed — that is the property worth protecting, so the bar for
 * returning a swap is high: the policy must declare credentials AND at least
 * one of them must have a synthetic bound in the environment. A policy that
 * declares credentials whose synthetics are all absent is a live
 * misconfiguration; it warns loudly and swaps nothing, because the
 * alternative is a gateway that silently forwards synthetics to an upstream
 * that rejects them and leaves the operator reading tool errors.
 *
 * Throws only on a config the broker itself rejects (an unusable site, a
 * credential with no reachable destination). Gateway mode is the one
 * deliberate exception to fail-open, and a credentials section that cannot
 * be turned into a broker is exactly that case: the caller exits 2 rather
 * than running with enforcement the operator believes is on.
 */
export declare function credentialSwapFromPolicy(opts: WireOptions): CredentialSwapWiring | undefined;
