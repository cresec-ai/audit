/**
 * The /broker/exchange contract — NHI's wire shape, kept byte-identical.
 *
 * WHY BYTE-IDENTICAL. The credential swap is built here, in the recorder,
 * because the control plane it mirrors (cresec-ai/nhi) needs postgres,
 * OpenBao, OPA and NATS to answer a single call, and a developer laptop has
 * none of those. What it does NOT need is a second protocol: the request
 * body, the response body and the synthetic format below are copied field for
 * field from `apps/api/src/routes/broker.ts` (the snake_case HTTP body),
 * `apps/api/src/broker/exchange.ts` (the handler) and
 * `apps/api/src/synthetic/issuer.ts` (the synthetic). So pointing the gateway
 * at a real control plane is a config change — swapping {@link Broker}
 * implementations — and not a rewrite of everything that calls it. The Go
 * client both NHI data planes use (`packages/brokerclient/client.go`) parses
 * exactly these two JSON objects, which is the practical test of "identical":
 * our `RemoteBroker` and that client must be interchangeable against the same
 * server.
 *
 * Deliberate differences, all local-only and none of them on the wire:
 *
 *   - NHI's handler works in camelCase internally and its ROUTE renames the
 *     fields to snake_case. We skip the internal shape and speak snake_case
 *     throughout, because the only consumers here are the wire and a local
 *     resolver.
 *   - `denied` is optional in the response type. NHI answers 403 with a body
 *     carrying `denied: true` and 200 without the field at all; a type that
 *     required it could not describe a genuine 200 body.
 *   - Anything the local broker wants to say about a decision that NHI has no
 *     field for (which credential, which source, whether the host was checked
 *     or assumed) travels out of band through `onDecision` — never as an
 *     extra key on these two objects.
 */
import type { Buffer } from 'node:buffer';
/**
 * Synthetic format, exactly NHI's: `cresec_synth_v1_` + base64url of 32
 * random bytes. Shared literally rather than by convention — a synthetic
 * minted here is redeemable against a real control plane once the row exists
 * there, and one minted there is redeemable here, which is the point of
 * building the local path against this contract instead of inventing a token.
 */
export declare const SYNTHETIC_PREFIX = "cresec_synth_v1_";
/** Wire shape — snake_case, byte-identical to NHI's POST /broker/exchange body. */
export interface BrokerExchangeRequest {
    synthetic: string;
    data_plane_instance_id: string;
    request: {
        method: string;
        host: string;
        path_template: string;
        user_agent?: string;
        src_ip?: string;
    };
}
/** Wire shape — NHI returns real_token+ttl_seconds on 200, denied+deny_reason on 403. */
export interface BrokerExchangeResponse {
    real_token?: string;
    ttl_seconds: number;
    decision_id: string;
    denied?: boolean;
    deny_reason?: string;
}
export interface Broker {
    exchange(req: BrokerExchangeRequest): Promise<BrokerExchangeResponse>;
}
/**
 * TTL a positive decision may be cached for, in seconds.
 *
 * 30 is NHI's `BROKER_DEFAULT_TTL_SECONDS` (apps/api/src/broker/exchange.ts).
 * It is a bound on STALENESS, not a promise about the token: NHI busts its
 * data-plane cache over NATS on revoke/rotate, we have no such channel
 * locally, so a decision taken now stays usable for up to 30 s after the
 * credential is revoked in the config — and a call already in flight is not
 * recalled at all. Quote the number; never write "revocation is instant".
 */
export declare const BROKER_DEFAULT_TTL_SECONDS = 30;
/**
 * Deny reason CODES. A closed set, and the ONLY thing that may travel back
 * from a failed exchange.
 *
 * NHI's exchange.ts answers in codes for the same reason (`unknown_synthetic`,
 * `vault_missing_token`, `synthetic_<status>`), and the codes below that also
 * exist there are spelled the way they are spelled there. The prohibition is
 * the point: an underlying error text carries the vault path, the exec
 * command line, or an upstream 401 body that quotes the very token we are
 * protecting, and every one of those ends up in a recorded event or on the
 * recorder's stderr — which a stdio client captures and sometimes surfaces
 * back to the model. Diagnostics go to the operator through the `warn` seam,
 * never into a response the agent reads.
 */
export type DenyReason = 'unknown_synthetic' | 'synthetic_revoked' | 'synthetic_disabled' | 'unknown_cred' | 'cred_revoked' | 'cred_disabled' | 'denied_by_policy' | 'vault_missing_token' | 'method_not_permitted' | 'host_not_permitted' | 'path_not_permitted' | 'no_host_constraint' | 'source_timeout' | 'source_unhealthy' | 'source_unavailable' | 'source_empty' | 'source_file_mode_too_open' | 'source_exec_failed' | 'source_untrusted_config' | 'github_app_rejected' | 'aws_sts_rejected' | 'vault_unreachable' | 'clickup_token_rejected' | 'exclusion_capacity' | 'broker_unreachable' | 'broker_error';
/** Mint a fresh synthetic. 32 random bytes, base64url, prefixed — NHI's `mintSyntheticValue`. */
export declare function mintSynthetic(): string;
/**
 * Cheap shape test. NOT an authorisation check, and never its own deny
 * reason: answering "well formed but unknown" differently from "malformed"
 * tells a caller when it has the format right, which is a free step towards
 * guessing a value. Both deny `unknown_synthetic`.
 */
export declare function isSyntheticShaped(value: string): boolean;
/** HMAC-SHA256(value, pepper) — NHI's `hashSynthetic`. */
export declare function hashSynthetic(value: string, pepper: Buffer): Buffer;
/**
 * Constant-time comparison of two synthetic hashes — NHI's
 * `syntheticHashesEqual`. The local path must not acquire a comparison
 * weakness the remote one does not have: `Buffer.equals` returns early on the
 * first differing byte, and the exchange is callable in a loop by anything
 * that can reach the gateway.
 */
export declare function syntheticHashesEqual(a: Buffer, b: Buffer): boolean;
/** A fresh local pepper. 32 bytes, the size NHI's per-tenant pepper is. */
export declare function mintPepper(): Buffer;
/** A denial in NHI's exact shape: no token, zero TTL, a code, a decision id. */
export declare function denyResponse(decisionId: string, reason: DenyReason): BrokerExchangeResponse;
/** A decision id for a decision taken locally (NHI uses a UUID per exchange). */
export declare function newDecisionId(): string;
