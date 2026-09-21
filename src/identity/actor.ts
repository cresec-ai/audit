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

import { createPublicKey, verify as cryptoVerify } from 'node:crypto';
import { readFileSync } from 'node:fs';
import type { KeyObject } from 'node:crypto';
import type { ActorClaim, ActorHost, ActorTool, ActorUser } from '../schema/events.js';
import { sinkFetch } from '../sink/http.js';

export const JWT_ISSUER = 'cresec';
export const JWT_AUDIENCE = 'cresec-gateway';

const IDP_KINDS = new Set(['okta', 'entra', 'google', 'test']);
const HOST_KINDS = new Set(['vercel', 'lambda', 'other', 'local']);
const RUN_AS = new Set(['user', 'owner']);
const JWT_KINDS = new Set(['human', 'job']);
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** Generous ceiling: a real identity JWT is under 2 KiB. */
const MAX_JWT_BYTES = 16 * 1024;
/** How long a JWKS fetch may take at startup before the recorder gives up (exit 2). */
const JWKS_FETCH_TIMEOUT_MS = 10_000;

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

export class IdentityJwtError extends Error {}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function b64url(segment: string): Buffer {
  return Buffer.from(segment.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
}

function parseSegment(segment: string, what: string): Record<string, unknown> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(b64url(segment).toString('utf8'));
  } catch {
    throw new IdentityJwtError(`identity JWT: ${what} is not base64url JSON`);
  }
  if (!isRecord(parsed)) throw new IdentityJwtError(`identity JWT: ${what} is not a JSON object`);
  return parsed;
}

/** Shape-check the payload against the contract. Throws naming the first bad claim. */
export function parseIdentityJwtClaims(payload: unknown): IdentityJwtClaims {
  if (!isRecord(payload)) throw new IdentityJwtError('identity JWT: payload is not an object');
  const str = (k: string): string => {
    const v = payload[k];
    if (typeof v !== 'string' || v === '') throw new IdentityJwtError(`identity JWT: claim "${k}" is missing or not a string`);
    return v;
  };
  const num = (k: string): number => {
    const v = payload[k];
    if (typeof v !== 'number' || !Number.isFinite(v)) throw new IdentityJwtError(`identity JWT: claim "${k}" is missing or not a number`);
    return v;
  };
  const iss = str('iss');
  if (iss !== JWT_ISSUER) throw new IdentityJwtError(`identity JWT: iss is "${iss}", expected "${JWT_ISSUER}"`);
  const aud = str('aud');
  if (aud !== JWT_AUDIENCE) throw new IdentityJwtError(`identity JWT: aud is "${aud}", expected "${JWT_AUDIENCE}"`);
  const sub = str('sub');
  if (!UUID.test(sub)) throw new IdentityJwtError('identity JWT: sub is not a uuid');
  const tenantId = str('tenant_id');
  if (!UUID.test(tenantId)) throw new IdentityJwtError('identity JWT: tenant_id is not a uuid');
  const kind = str('kind');
  if (!JWT_KINDS.has(kind)) throw new IdentityJwtError(`identity JWT: kind "${kind}" is not human|job`);
  const runAs = str('run_as');
  if (!RUN_AS.has(runAs)) throw new IdentityJwtError(`identity JWT: run_as "${runAs}" is not user|owner`);
  const idp = str('idp');
  if (!IDP_KINDS.has(idp)) throw new IdentityJwtError(`identity JWT: idp "${idp}" is not okta|entra|google|test`);
  const idpSub = payload.idp_sub;
  if (typeof idpSub !== 'string') throw new IdentityJwtError('identity JWT: idp_sub is missing or not a string');
  const tool = payload.tool;
  if (
    !isRecord(tool) ||
    typeof tool.id !== 'string' ||
    !UUID.test(tool.id) ||
    typeof tool.name !== 'string' ||
    tool.name === '' ||
    typeof tool.version !== 'string' ||
    tool.version === ''
  ) {
    throw new IdentityJwtError('identity JWT: tool must be { id: uuid, name, version }');
  }
  const host = payload.host;
  if (!isRecord(host) || typeof host.origin !== 'string' || host.origin === '' || typeof host.kind !== 'string' || !HOST_KINDS.has(host.kind)) {
    throw new IdentityJwtError('identity JWT: host must be { origin, kind: vercel|lambda|other|local }');
  }
  return {
    iss: JWT_ISSUER,
    aud: JWT_AUDIENCE,
    sub,
    jti: str('jti'),
    iat: num('iat'),
    exp: num('exp'),
    kind: kind as IdentityJwtClaims['kind'],
    run_as: runAs as IdentityJwtClaims['run_as'],
    tenant_id: tenantId,
    tenant: str('tenant'),
    email: str('email'),
    idp: idp as ActorUser['idp'],
    idp_sub: idpSub,
    role: str('role'),
    tool: { id: tool.id, name: tool.name, version: tool.version },
    host: { origin: host.origin, kind: host.kind as ActorHost['kind'] },
  };
}

/**
 * ADR 012: the actor is a pure function of the claims — the four fields the
 * control plane's `actorFromClaims` derives, and nothing else, so a record's
 * `actor` compares equal to the control plane's byte for byte. Whether the
 * signature was checked rides beside it (`identity.actor_verified`).
 */
export function actorFromClaims(claims: IdentityJwtClaims): ActorClaim {
  return {
    user: { id: claims.sub, email: claims.email, idp: claims.idp, idp_sub: claims.idp_sub },
    tool: { id: claims.tool.id, name: claims.tool.name, version: claims.tool.version },
    host: { origin: claims.host.origin, kind: claims.host.kind },
    run_as: claims.run_as,
  };
}

export interface DecodedIdentityJwt {
  header: { alg: string; kid?: string; typ?: string };
  claims: IdentityJwtClaims;
  /** `<header>.<payload>` — what the signature covers. */
  signingInput: string;
  signature: Buffer;
  /** The compact JWS as given, trimmed. */
  raw: string;
}

/** Decode WITHOUT verifying. The caller decides whether to verify. */
export function decodeIdentityJwt(token: string): DecodedIdentityJwt {
  const trimmed = token.trim();
  if (trimmed === '') throw new IdentityJwtError('identity JWT: empty');
  if (Buffer.byteLength(trimmed) > MAX_JWT_BYTES) throw new IdentityJwtError('identity JWT: larger than 16 KiB');
  const parts = trimmed.split('.');
  if (parts.length !== 3) throw new IdentityJwtError('identity JWT: not a compact JWS (expected three dot-separated segments)');
  const header = parseSegment(parts[0] as string, 'header');
  if (header.alg !== 'EdDSA') throw new IdentityJwtError(`identity JWT: alg "${String(header.alg)}" is not EdDSA`);
  const claims = parseIdentityJwtClaims(parseSegment(parts[1] as string, 'payload'));
  const out: DecodedIdentityJwt = {
    header: { alg: 'EdDSA' },
    claims,
    signingInput: `${parts[0]}.${parts[1]}`,
    signature: b64url(parts[2] as string),
    raw: trimmed,
  };
  if (typeof header.kid === 'string') out.header.kid = header.kid;
  if (typeof header.typ === 'string') out.header.typ = header.typ;
  return out;
}

export interface JwksKey {
  kty: string;
  crv?: string;
  x?: string;
  kid?: string;
  alg?: string;
}

/** Parse a JWKS document; keeps only the Ed25519 keys it can use. */
export function parseJwks(doc: unknown): Map<string, KeyObject> {
  if (!isRecord(doc) || !Array.isArray(doc.keys)) throw new IdentityJwtError('JWKS: expected { keys: [...] }');
  const out = new Map<string, KeyObject>();
  for (const raw of doc.keys as unknown[]) {
    if (!isRecord(raw)) continue;
    const key = raw as unknown as JwksKey;
    if (key.kty !== 'OKP' || key.crv !== 'Ed25519' || typeof key.x !== 'string' || typeof key.kid !== 'string') continue;
    try {
      out.set(key.kid, createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: key.x }, format: 'jwk' }));
    } catch {
      /* a malformed key is skipped; an unknown kid fails below, loudly */
    }
  }
  return out;
}

/** Verify the EdDSA signature against the key the header's `kid` names. Throws on any failure. */
export function verifyIdentityJwt(decoded: DecodedIdentityJwt, keys: Map<string, KeyObject>, now: number = Date.now()): void {
  const kid = decoded.header.kid;
  if (kid === undefined) throw new IdentityJwtError('identity JWT: header has no kid');
  const key = keys.get(kid);
  if (key === undefined) throw new IdentityJwtError(`identity JWT: unknown_kid (${kid} is not in the JWKS)`);
  let ok = false;
  try {
    ok = cryptoVerify(null, Buffer.from(decoded.signingInput, 'utf8'), key, decoded.signature);
  } catch {
    ok = false;
  }
  if (!ok) throw new IdentityJwtError('identity JWT: jwt_invalid (signature does not verify)');
  checkIdentityJwtTimes(decoded.claims, now);
}

/**
 * The contract's time checks (identity-jwt.md, verification step 4):
 * `exp > now - 30 s` and `iat <= now + 30 s`. These are CLAIM checks, not
 * signature checks, so they run in decode-only mode too: a token that
 * expired days ago must not attribute every record to its subject just
 * because nobody asked for the signature. Throws on failure.
 */
export function checkIdentityJwtTimes(claims: Pick<IdentityJwtClaims, 'exp' | 'iat'>, now: number = Date.now()): void {
  const nowSec = Math.floor(now / 1000);
  if (claims.exp <= nowSec - 30) throw new IdentityJwtError('identity JWT: jwt_expired');
  if (claims.iat > nowSec + 30) throw new IdentityJwtError('identity JWT: iat is in the future');
}

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

async function fetchJwksDocument(url: string): Promise<unknown> {
  const res = await sinkFetch({ method: 'GET', url, headers: { accept: 'application/json' }, totalTimeoutMs: JWKS_FETCH_TIMEOUT_MS });
  if (res.status !== 200) throw new IdentityJwtError(`JWKS: ${url} answered ${String(res.status)}`);
  return JSON.parse(res.body.toString('utf8')) as unknown;
}

/**
 * Resolve the actor the recorder will stamp on every event, or `undefined`
 * when no JWT was supplied. Throws `IdentityJwtError` (the CLI exits 2) when
 * a JWT was supplied and cannot be decoded, or when verification was asked
 * for and fails.
 */
export async function loadActor(opts: LoadActorOptions): Promise<LoadedActor | undefined> {
  let token: string | undefined;
  if (opts.jwtPath !== undefined && opts.jwtPath !== '') {
    try {
      token = readFileSync(opts.jwtPath, 'utf8');
    } catch (cause) {
      throw new IdentityJwtError(`identity JWT: cannot read ${opts.jwtPath}: ${cause instanceof Error ? cause.message : String(cause)}`);
    }
  } else if (opts.jwt !== undefined && opts.jwt.trim() !== '') {
    token = opts.jwt;
  }
  if (token === undefined) return undefined;
  const decoded = decodeIdentityJwt(token);
  // Expiry is a claim, not a signature: checked whether or not a JWKS was
  // given. (verifyIdentityJwt checks it again after the signature, so the
  // failure named first when both are wrong is the one that matters more.)
  if (opts.jwks === undefined || opts.jwks === '') checkIdentityJwtTimes(decoded.claims, opts.now ?? Date.now());
  let verified = false;
  if (opts.jwks !== undefined && opts.jwks !== '') {
    let doc: unknown;
    if (/^https?:\/\//i.test(opts.jwks)) {
      doc = await (opts.fetchJwks ?? fetchJwksDocument)(opts.jwks);
    } else {
      try {
        doc = JSON.parse(readFileSync(opts.jwks, 'utf8')) as unknown;
      } catch (cause) {
        throw new IdentityJwtError(`JWKS: cannot read ${opts.jwks}: ${cause instanceof Error ? cause.message : String(cause)}`);
      }
    }
    verifyIdentityJwt(decoded, parseJwks(doc), opts.now ?? Date.now());
    verified = true;
  }
  return { actor: actorFromClaims(decoded.claims), claims: decoded.claims, verified, token: decoded.raw };
}
