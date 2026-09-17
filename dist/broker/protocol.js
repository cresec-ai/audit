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
import { createHmac, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
/**
 * Synthetic format, exactly NHI's: `cresec_synth_v1_` + base64url of 32
 * random bytes. Shared literally rather than by convention — a synthetic
 * minted here is redeemable against a real control plane once the row exists
 * there, and one minted there is redeemable here, which is the point of
 * building the local path against this contract instead of inventing a token.
 */
export const SYNTHETIC_PREFIX = 'cresec_synth_v1_';
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
export const BROKER_DEFAULT_TTL_SECONDS = 30;
/** Mint a fresh synthetic. 32 random bytes, base64url, prefixed — NHI's `mintSyntheticValue`. */
export function mintSynthetic() {
    return SYNTHETIC_PREFIX + randomBytes(32).toString('base64url');
}
/**
 * Cheap shape test. NOT an authorisation check, and never its own deny
 * reason: answering "well formed but unknown" differently from "malformed"
 * tells a caller when it has the format right, which is a free step towards
 * guessing a value. Both deny `unknown_synthetic`.
 */
export function isSyntheticShaped(value) {
    if (!value.startsWith(SYNTHETIC_PREFIX))
        return false;
    return /^[A-Za-z0-9_-]{16,}$/.test(value.slice(SYNTHETIC_PREFIX.length));
}
/** HMAC-SHA256(value, pepper) — NHI's `hashSynthetic`. */
export function hashSynthetic(value, pepper) {
    return createHmac('sha256', pepper).update(value).digest();
}
/**
 * Constant-time comparison of two synthetic hashes — NHI's
 * `syntheticHashesEqual`. The local path must not acquire a comparison
 * weakness the remote one does not have: `Buffer.equals` returns early on the
 * first differing byte, and the exchange is callable in a loop by anything
 * that can reach the gateway.
 */
export function syntheticHashesEqual(a, b) {
    if (a.length !== b.length)
        return false;
    return timingSafeEqual(a, b);
}
/** A fresh local pepper. 32 bytes, the size NHI's per-tenant pepper is. */
export function mintPepper() {
    return randomBytes(32);
}
/** A denial in NHI's exact shape: no token, zero TTL, a code, a decision id. */
export function denyResponse(decisionId, reason) {
    return { decision_id: decisionId, ttl_seconds: 0, denied: true, deny_reason: reason };
}
/** A decision id for a decision taken locally (NHI uses a UUID per exchange). */
export function newDecisionId() {
    return randomUUID();
}
//# sourceMappingURL=protocol.js.map