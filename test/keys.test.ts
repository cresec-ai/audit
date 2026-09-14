import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, rmSync, existsSync, readFileSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createPublicKey, verify as nodeVerify } from 'node:crypto';
import { Buffer } from 'node:buffer';
import * as ed from '@noble/ed25519';
import { Signer, publicKeyPem } from '../src/chain/keys.js';
import { signedPayload, sha256Hex } from '../src/chain/hash.js';
import { FILES } from '../src/types.js';

const HEX64 = /^[0-9a-f]{64}$/;
const HEX128 = /^[0-9a-f]{128}$/;

describe('Signer', () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'mcp-recorder-keys-'));
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('creates a keypair on first load, including a missing dataDir', async () => {
    const nested = join(dir, 'a', 'b', 'data');
    const signer = await Signer.load(nested);
    expect(signer.publicKeyHex).toMatch(HEX64);
    expect(existsSync(join(nested, FILES.PRIVATE_KEY))).toBe(true);
    expect(existsSync(join(nested, FILES.PUBLIC_KEY))).toBe(true);
    expect(readFileSync(join(nested, FILES.PUBLIC_KEY), 'utf8').trim()).toBe(signer.publicKeyHex);
  });

  it('private key file is mode 0600', async () => {
    await Signer.load(dir);
    const mode = statSync(join(dir, FILES.PRIVATE_KEY)).mode & 0o777;
    expect(mode).toBe(0o600);
  });

  it('persists the keypair across loads (deterministic public key)', async () => {
    const first = await Signer.load(dir);
    const second = await Signer.load(dir);
    expect(second.publicKeyHex).toBe(first.publicKeyHex);
    // And a fresh dir yields a different key.
    const otherDir = mkdtempSync(join(tmpdir(), 'mcp-recorder-keys2-'));
    try {
      const other = await Signer.load(otherDir);
      expect(other.publicKeyHex).not.toBe(first.publicKeyHex);
    } finally {
      rmSync(otherDir, { recursive: true, force: true });
    }
  });

  it('rejects a malformed private key file', async () => {
    const bad = join(dir, 'badkeys');
    const signer = await Signer.load(bad);
    expect(signer.publicKeyHex).toMatch(HEX64);
    const { writeFileSync } = await import('node:fs');
    writeFileSync(join(bad, FILES.PRIVATE_KEY), 'not-hex\n');
    await expect(Signer.load(bad)).rejects.toThrow(/malformed private key/);
  });

  it('sign() produces a well-formed HeadSignature', async () => {
    const signer = await Signer.load(dir);
    const chainHash = sha256Hex('some-event');
    const sig = await signer.sign(42, chainHash);
    expect(sig.seq).toBe(42);
    expect(sig.chain_hash).toBe(chainHash);
    expect(sig.algo).toBe('ed25519');
    expect(sig.public_key).toBe(signer.publicKeyHex);
    expect(sig.signature).toMatch(HEX128);
    // ISO-8601 UTC, parseable, close to now.
    expect(sig.signed_at).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/);
    expect(Math.abs(Date.parse(sig.signed_at) - Date.now())).toBeLessThan(60_000);
  });

  it('signature verifies with @noble/ed25519', async () => {
    const signer = await Signer.load(dir);
    const chainHash = sha256Hex('head-7');
    const sig = await signer.sign(7, chainHash);
    const payload = signedPayload(7, chainHash);
    const ok = await ed.verifyAsync(sig.signature, payload, sig.public_key);
    expect(ok).toBe(true);
    // Tampered payload must not verify.
    const wrong = await ed.verifyAsync(sig.signature, signedPayload(8, chainHash), sig.public_key);
    expect(wrong).toBe(false);
  });

  it('signature verifies with node:crypto via publicKeyPem (no @noble needed)', async () => {
    const signer = await Signer.load(dir);
    const chainHash = sha256Hex('head-99');
    const sig = await signer.sign(99, chainHash);
    const pem = publicKeyPem(sig.public_key);
    expect(pem).toContain('-----BEGIN PUBLIC KEY-----');
    expect(pem).toContain('-----END PUBLIC KEY-----');
    const keyObject = createPublicKey(pem);
    expect(keyObject.asymmetricKeyType).toBe('ed25519');
    const payload = signedPayload(99, chainHash);
    const sigBytes = Buffer.from(sig.signature, 'hex');
    expect(nodeVerify(null, payload, keyObject, sigBytes)).toBe(true);
    // Tampered payload must not verify.
    expect(nodeVerify(null, signedPayload(100, chainHash), keyObject, sigBytes)).toBe(false);
  });

  it('publicKeyPem rejects non-hex input', () => {
    expect(() => publicKeyPem('zz')).toThrow(/64-hex/);
  });

  it('parallel Signer.load calls on an empty dir agree on one identity', async () => {
    // Several `mcp-recorder record` processes normally share one data dir
    // and can all hit Signer.load on the very first run — they must not
    // race into creating (and then signing under) different keys.
    const N = 8;
    const signers = await Promise.all(Array.from({ length: N }, () => Signer.load(dir)));

    const pubKeys = new Set(signers.map((s) => s.publicKeyHex));
    expect(pubKeys.size).toBe(1);
    for (const s of signers) expect(s.publicKeyHex).toMatch(HEX64);

    const privOnDisk = readFileSync(join(dir, FILES.PRIVATE_KEY), 'utf8').trim().toLowerCase();
    const pubOnDisk = readFileSync(join(dir, FILES.PUBLIC_KEY), 'utf8').trim().toLowerCase();
    expect(privOnDisk).toMatch(HEX64);
    expect(pubOnDisk).toBe([...pubKeys][0]);

    const mode = statSync(join(dir, FILES.PRIVATE_KEY)).mode & 0o777;
    expect(mode).toBe(0o600);

    // And the winning key actually signs correctly.
    const chainHash = sha256Hex('race-head');
    const sig = await signers[0]!.sign(1, chainHash);
    const ok = await ed.verifyAsync(sig.signature, signedPayload(1, chainHash), sig.public_key);
    expect(ok).toBe(true);
  });
});
