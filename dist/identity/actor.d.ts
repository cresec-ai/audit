/**
 * The ADR 012 actor claim: from an identity JWT to the `identity.actor`
 * block on every event.
 *
 * The control plane (cresec-ai/nhi, docs/internal/contracts/identity-jwt.md)
 * mints one compact JWS per signed-in person: EdDSA (Ed25519), claims
 * `iss=cresec`, `aud=cresec-gateway`, `sub=<user id>`, `tenant_id`, `tenant`,
 * `email`, `idp`, `idp_sub`, `role`, `tool {id,name,version}`, `host
 * {origin,kind}`, `kind`, `run_as`, `iat`, `exp`, `jti`. The actor is a PURE
 * FUNCTION of those claims (`actorFromClaims`, the reference derivation in
 * `@cresec/contracts/identity-jwt`), so nothing here looks anything up.
 *
 * Verification is OPTIONAL and explicit. With `--identity-jwks <path-or-url>`
 * the signature is checked against the JWKS document (`{ keys: [ { kty:
 * "OKP", crv: "Ed25519", x, kid, alg: "EdDSA" } ] }`) and a token that does
 * not verify is a startup error — the operator asked for verification and
 * must not get an unverified claim stamped on the chain. Without it the
 * claims are DECODED only and every event says so (`identity.actor_verified:
 * false`): the record then carries what the token said, no more, and the
 * docs say exactly that (docs/event-schema.md, "Actor claim"). `exp` and
 * `iat` are checked in BOTH modes: they are claims, not signatures, and an
 * expired token is refused at start rather than stamped on every record.
 *
 * What is never recorded: the token itself, its signature, `jti`, `role`,
 * `iat`/`exp`. Only the four actor sub-objects (ADR 012's shape, byte for
 * byte) and, beside them, the verified flag.
 */
import type { KeyObject } from 'node:crypto';
import type { ActorClaim, ActorHost, ActorTool, ActorUser } from '../schema/events.js';
export declare const JWT_ISSUER = "cresec";
export declare const JWT_AUDIENCE = "cresec-gateway";
/** The claims this module reads. Every one is required by the contract. */
export interface IdentityJwtClaims {
    iss: string;
    aud: string;
    sub: string;
    jti: string;
    iat: number;
    exp: number;
    kind: 'human' | 'job';
    run_as: 'user' | 'owner';
    tenant_id: string;
    tenant: string;
    email: string;
    idp: ActorUser['idp'];
    idp_sub: string;
    role: string;
    tool: ActorTool;
    host: ActorHost;
}
export declare class IdentityJwtError extends Error {
}
/** Shape-check the payload against the contract. Throws naming the first bad claim. */
export declare function parseIdentityJwtClaims(payload: unknown): IdentityJwtClaims;
/**
 * ADR 012: the actor is a pure function of the claims — the four fields the
 * control plane's `actorFromClaims` derives, and nothing else, so a record's
 * `actor` compares equal to the control plane's byte for byte. Whether the
 * signature was checked rides beside it (`identity.actor_verified`).
 */
export declare function actorFromClaims(claims: IdentityJwtClaims): ActorClaim;
export interface DecodedIdentityJwt {
    header: {
        alg: string;
        kid?: string;
        typ?: string;
    };
    claims: IdentityJwtClaims;
    /** `<header>.<payload>` — what the signature covers. */
    signingInput: string;
    signature: Buffer;
    /** The compact JWS as given, trimmed. */
    raw: string;
}
/** Decode WITHOUT verifying. The caller decides whether to verify. */
export declare function decodeIdentityJwt(token: string): DecodedIdentityJwt;
export interface JwksKey {
    kty: string;
    crv?: string;
    x?: string;
    kid?: string;
    alg?: string;
}
/** Parse a JWKS document; keeps only the Ed25519 keys it can use. */
export declare function parseJwks(doc: unknown): Map<string, KeyObject>;
/** Verify the EdDSA signature against the key the header's `kid` names. Throws on any failure. */
export declare function verifyIdentityJwt(decoded: DecodedIdentityJwt, keys: Map<string, KeyObject>, now?: number): void;
/**
 * The contract's time checks (identity-jwt.md, verification step 4):
 * `exp > now - 30 s` and `iat <= now + 30 s`. These are CLAIM checks, not
 * signature checks, so they run in decode-only mode too: a token that
 * expired days ago must not attribute every record to its subject just
 * because nobody asked for the signature. Throws on failure.
 */
export declare function checkIdentityJwtTimes(claims: Pick<IdentityJwtClaims, 'exp' | 'iat'>, now?: number): void;
export interface LoadActorOptions {
    /** `--identity-jwt PATH`: a file holding the compact JWS. */
    jwtPath?: string;
    /** The raw JWT (e.g. from the env var a policy's `identity_jwt_env` names). `jwtPath` wins. */
    jwt?: string;
    /** `--identity-jwks PATH|URL`: verify against this JWKS. Absent = decode only. */
    jwks?: string;
    /** Test seam for the JWKS fetch. */
    fetchJwks?: (url: string) => Promise<unknown>;
    /** Test seam for the clock (ms since the epoch). */
    now?: number;
}
export interface LoadedActor {
    actor: ActorClaim;
    claims: IdentityJwtClaims;
    /** Whether the EdDSA signature was checked (`--identity-jwks`). Stamped as `identity.actor_verified`. */
    verified: boolean;
    /**
     * The compact JWS itself. Kept in memory for one use only: a job token
     * (`kind: job`) is sent as `job_token` on the per-user token request
     * (user-token.md). Never recorded, never logged.
     */
    token: string;
}
/**
 * Resolve the actor the recorder will stamp on every event, or `undefined`
 * when no JWT was supplied. Throws `IdentityJwtError` (the CLI exits 2) when
 * a JWT was supplied and cannot be decoded, or when verification was asked
 * for and fails.
 */
export declare function loadActor(opts: LoadActorOptions): Promise<LoadedActor | undefined>;
