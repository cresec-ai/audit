/**
 * The identity JWT and the actor claim (ADR 012, cresec-ai/nhi
 * docs/internal/contracts/identity-jwt.md).
 *
 * The claims here are the contract's example values; the keys are minted per
 * test run with node:crypto (Ed25519), never checked in. Every token is
 * obviously fake: the user is the contract's own example uuid.
 */

import { generateKeyPairSync, sign as cryptoSign } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import {
  IdentityJwtError,
  actorFromClaims,
  decodeIdentityJwt,
  loadActor,
  parseJwks,
  verifyIdentityJwt,
} from '../src/identity/actor.js';

const CLAIMS = {
  iss: 'cresec',
  aud: 'cresec-gateway',
  sub: '3c9f2d0e-4b1a-4f7e-9d21-6a0b1c2d3e4f',
  jti: '11111111-2222-4333-8444-555555555555',
  // Minted "a minute ago", so the real clock accepts it (iat <= now + 30 s).
  iat: Math.floor(Date.now() / 1000) - 60,
  exp: Math.floor(Date.now() / 1000) - 60 + 28_800,
  kind: 'human',
  run_as: 'user',
  tenant_id: '0b7b4e5a-0c1d-4e2f-8a3b-4c5d6e7f8a9b',
  tenant: 'e2e',
  email: 'dana@cresec.ai',
  idp: 'okta',
  idp_sub: '00u1abcXYZ',
  role: 'rep',
  tool: { id: '9e1d7c3a-2f4b-4c6d-8e0f-1a2b3c4d5e6f', name: 'outreach-tool', version: '3' },
  host: { origin: 'https://tool.staging.cresec.ai', kind: 'vercel' },
};

const b64url = (v: unknown): string => Buffer.from(JSON.stringify(v), 'utf8').toString('base64url');

/** A real EdDSA signer for the tests: the tenant key the control plane would hold. */
function signer(kid = 'e2e-1') {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const jwk = publicKey.export({ format: 'jwk' }) as { x: string };
  const mint = (claims: Record<string, unknown> = CLAIMS, header: Record<string, unknown> = { alg: 'EdDSA', kid, typ: 'JWT' }): string => {
    const input = `${b64url(header)}.${b64url(claims)}`;
    const sig = cryptoSign(null, Buffer.from(input, 'utf8'), privateKey);
    return `${input}.${sig.toString('base64url')}`;
  };
  const jwks = { keys: [{ kty: 'OKP', crv: 'Ed25519', x: jwk.x, kid, alg: 'EdDSA', use: 'sig' }] };
  return { mint, jwks };
}

const NOW = (CLAIMS.iat + 60) * 1000;

describe('identity JWT: decode and derive the actor', () => {
  it('decodes without verifying and derives the ADR 012 actor as a pure function of the claims', () => {
    const { mint } = signer();
    const decoded = decodeIdentityJwt(mint());
    expect(decoded.header).toEqual({ alg: 'EdDSA', kid: 'e2e-1', typ: 'JWT' });
    expect(decoded.claims.sub).toBe(CLAIMS.sub);
    // EXACTLY the control plane's four fields (nhi packages/contracts/src/actor.ts):
    // nothing about verification lives inside the claim.
    expect(actorFromClaims(decoded.claims)).toEqual({
      user: { id: CLAIMS.sub, email: 'dana@cresec.ai', idp: 'okta', idp_sub: '00u1abcXYZ' },
      tool: CLAIMS.tool,
      host: CLAIMS.host,
      run_as: 'user',
    });
    expect(Object.keys(actorFromClaims(decoded.claims)).sort()).toEqual(['host', 'run_as', 'tool', 'user']);
    expect(decoded.raw).toBe(mint());
  });

  it('refuses every off-contract shape by name', () => {
    const { mint } = signer();
    const bad = (over: Record<string, unknown>, header?: Record<string, unknown>) => mint({ ...CLAIMS, ...over }, header);
    expect(() => decodeIdentityJwt('not.a.jwt.at.all')).toThrow(IdentityJwtError);
    expect(() => decodeIdentityJwt(mint(CLAIMS, { alg: 'HS256', kid: 'x' }))).toThrow(/alg "HS256"/);
    expect(() => decodeIdentityJwt(bad({ iss: 'someone-else' }))).toThrow(/iss/);
    expect(() => decodeIdentityJwt(bad({ aud: 'cresec' }))).toThrow(/aud/);
    expect(() => decodeIdentityJwt(bad({ sub: 'not-a-uuid' }))).toThrow(/sub/);
    expect(() => decodeIdentityJwt(bad({ idp: 'facebook' }))).toThrow(/idp/);
    expect(() => decodeIdentityJwt(bad({ run_as: 'root' }))).toThrow(/run_as/);
    expect(() => decodeIdentityJwt(bad({ tool: { id: 'x', name: 'y', version: '1' } }))).toThrow(/tool/);
    expect(() => decodeIdentityJwt(bad({ host: { origin: 'https://x', kind: 'mainframe' } }))).toThrow(/host/);
    expect(() => decodeIdentityJwt(bad({ email: undefined }))).toThrow(/email/);
  });
});

describe('identity JWT: verification against a JWKS', () => {
  it('verifies a token signed by the kid the JWKS lists, and rejects a wrong key, an unknown kid, a tampered payload and an expired token', () => {
    const good = signer('e2e-1');
    const other = signer('e2e-1'); // same kid, DIFFERENT key
    const keys = parseJwks(good.jwks);
    expect(() => verifyIdentityJwt(decodeIdentityJwt(good.mint()), keys, NOW)).not.toThrow();
    expect(() => verifyIdentityJwt(decodeIdentityJwt(other.mint()), keys, NOW)).toThrow(/jwt_invalid/);
    expect(() => verifyIdentityJwt(decodeIdentityJwt(good.mint(CLAIMS, { alg: 'EdDSA', kid: 'e2e-test-1' })), keys, NOW)).toThrow(/unknown_kid/);
    // Tamper with the payload: the email changes, the signature does not.
    const token = good.mint();
    const [h, , s] = token.split('.') as [string, string, string];
    const tampered = `${h}.${b64url({ ...CLAIMS, email: 'mallory@cresec.ai' })}.${s}`;
    expect(() => verifyIdentityJwt(decodeIdentityJwt(tampered), keys, NOW)).toThrow(/jwt_invalid/);
    expect(() => verifyIdentityJwt(decodeIdentityJwt(good.mint()), keys, (CLAIMS.exp + 3600) * 1000)).toThrow(/jwt_expired/);
  });

  it('a JWKS with several keys (the staging test signer beside the primary) resolves by kid', () => {
    const primary = signer('e2e-1');
    const test = signer('e2e-test-1');
    const keys = parseJwks({ keys: [...primary.jwks.keys, ...test.jwks.keys] });
    expect(keys.size).toBe(2);
    expect(() => verifyIdentityJwt(decodeIdentityJwt(test.mint()), keys, NOW)).not.toThrow();
    expect(() => verifyIdentityJwt(decodeIdentityJwt(primary.mint()), keys, NOW)).not.toThrow();
  });
});

describe('loadActor: what the CLI does with --identity-jwt / --identity-jwks', () => {
  const dir = mkdtempSync(join(tmpdir(), 'mcp-recorder-identity-'));
  afterAll(() => rmSync(dir, { recursive: true, force: true }));

  it('returns undefined with no JWT, an unverified actor with a JWT alone, and a verified one with a JWKS file or URL', async () => {
    const { mint, jwks } = signer();
    const jwtPath = join(dir, 'identity.jwt');
    writeFileSync(jwtPath, mint() + '\n');
    const jwksPath = join(dir, 'jwks.json');
    writeFileSync(jwksPath, JSON.stringify(jwks));

    expect(await loadActor({})).toBeUndefined();
    const unverified = await loadActor({ jwtPath });
    expect(unverified?.verified).toBe(false);
    expect(unverified?.actor.user.email).toBe('dana@cresec.ai');
    expect(unverified?.token).toBe(mint());
    expect('verified' in (unverified?.actor ?? {})).toBe(false);

    const fromFile = await loadActor({ jwtPath, jwks: jwksPath });
    expect(fromFile?.verified).toBe(true);

    let fetched: string | undefined;
    const fromUrl = await loadActor({
      jwt: mint(),
      jwks: 'https://api.cresec.test/.well-known/jwks.json?tenant=e2e',
      fetchJwks: (url) => {
        fetched = url;
        return Promise.resolve(jwks);
      },
    });
    expect(fetched).toBe('https://api.cresec.test/.well-known/jwks.json?tenant=e2e');
    expect(fromUrl?.verified).toBe(true);
  });

  it('an expired token, or one minted in the future, is refused in decode-only mode too: exp and iat are claims, not signatures', async () => {
    const { mint } = signer();
    // NEGATIVE CONTROL: the same token, with the clock inside its window, loads.
    expect((await loadActor({ jwt: mint(), now: NOW }))?.actor.user.email).toBe('dana@cresec.ai');
    // 8 h + the 30 s skew, and one second more: what a token reused the next day looks like.
    await expect(loadActor({ jwt: mint(), now: (CLAIMS.exp + 31) * 1000 })).rejects.toThrow(/jwt_expired/);
    // Inside the skew it is still accepted (identity-jwt.md: exp > now - 30 s).
    expect((await loadActor({ jwt: mint(), now: (CLAIMS.exp + 29) * 1000 }))?.verified).toBe(false);
    await expect(loadActor({ jwt: mint({ ...CLAIMS, iat: CLAIMS.iat + 3600, exp: CLAIMS.exp + 3600 }), now: NOW })).rejects.toThrow(/iat is in the future/);
  });

  it('a JWT that does not verify against the JWKS is an error, never an unverified actor (fail closed when verification was asked for)', async () => {
    const { mint } = signer('e2e-1');
    const impostor = signer('e2e-1');
    const jwksPath = join(dir, 'jwks-impostor.json');
    writeFileSync(jwksPath, JSON.stringify(impostor.jwks));
    await expect(loadActor({ jwt: mint(), jwks: jwksPath })).rejects.toThrow(/jwt_invalid/);
    await expect(loadActor({ jwtPath: join(dir, 'missing.jwt') })).rejects.toThrow(/cannot read/);
    await expect(loadActor({ jwt: 'garbage' })).rejects.toThrow(IdentityJwtError);
  });
});
