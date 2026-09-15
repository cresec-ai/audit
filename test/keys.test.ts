import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, rmSync, existsSync, readFileSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createPublicKey, verify as nodeVerify } from 'node:crypto';
import { Buffer } from 'node:buffer';
import * as ed from '@noble/ed25519';
import { spawnTsx } from './helpers/tsx.js';
import { Signer, publicKeyPem, publicKeyHexFromPem } from '../src/chain/keys.js';
import { signedPayload, sha256Hex } from '../src/chain/hash.js';
import { FILES } from '../src/types.js';

const HEX64 = /^[0-9a-f]{64}$/;
const HEX128 = /^[0-9a-f]{128}$/;

const TEST_DIR = dirname(fileURLToPath(import.meta.url));
const LOAD_SIGNER_FIXTURE = join(TEST_DIR, 'fixtures', 'load-signer.ts');

interface ChildResult {
  code: number | null;
  stdout: string;
  stderr: string;
}

interface SpawnedSigner {
  /** Resolves once the child has printed "ready" (blocked on the barrier). */
  ready: Promise<void>;
  /** Releases the child past its barrier. */
  go: () => void;
  /** Resolves with the child's full output once it exits. */
  result: Promise<ChildResult>;
}

/**
 * Spawn one `load-signer.ts <dataDir>` child process. It prints "ready" and
 * then blocks until `go()` unblocks it (see load-signer.ts) — process
 * spawn/startup jitter alone is enough that N children left to race freely
 * rarely actually contend on the same empty dir, so the caller collects
 * every child's `ready` first and only then calls every `go()`, lining up
 * their Signer.load calls as tightly as the OS will schedule them.
 */
function spawnSigner(dataDir: string): SpawnedSigner {
  const child = spawnTsx([LOAD_SIGNER_FIXTURE, dataDir], {
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  let stdout = '';
  let stderr = '';
  let sawReady = false;
  let resolveReady: () => void;
  const ready = new Promise<void>((resolve) => {
    resolveReady = resolve;
  });
  child.stdout.on('data', (c: Buffer) => {
    stdout += c.toString('utf8');
    if (!sawReady && stdout.includes('ready\n')) {
      sawReady = true;
      resolveReady();
    }
  });
  child.stderr.on('data', (c: Buffer) => {
    stderr += c.toString('utf8');
  });
  const result = new Promise<ChildResult>((resolve, reject) => {
    child.on('error', reject);
    child.on('close', (code) => resolve({ code, stdout, stderr }));
  });
  return {
    ready,
    go: () => {
      child.stdin.write('go\n');
      child.stdin.end();
    },
    result,
  };
}

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

  // File modes are a POSIX concept; Windows reports 0o666 for every file.
  it.skipIf(process.platform === 'win32')('private key file is mode 0600', async () => {
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
    // Sync ed.verify, not verifyAsync — this whole suite proves the Node 18
    // (no globalThis.crypto) path, and verifyAsync needs crypto.subtle.
    // sha512Sync is wired by src/chain/keys.ts's module-level side effect.
    const ok = ed.verify(sig.signature, payload, sig.public_key);
    expect(ok).toBe(true);
    // Tampered payload must not verify.
    const wrong = ed.verify(sig.signature, signedPayload(8, chainHash), sig.public_key);
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
    //
    // This has to be a REAL cross-process race: within a single process,
    // `Promise.all([Signer.load(dir), ...])` never actually contends on the
    // filesystem — `Signer.load` has no `await` before its synchronous
    // `mkdirSync`/`existsSync`/`writeFileSync({flag:'wx'})` sequence, so the
    // first call's synchronous section (including the exclusive-create
    // write) always finishes before the second call's synchronous section
    // even starts. That means an in-process version of this test passes
    // identically against the pre-fix code (plain `existsSync` +
    // `writeFileSync`, no `wx`), which is exactly the TOCTOU race this test
    // exists to catch — see test/fixtures/load-signer.ts for the full
    // explanation. Spawning N real OS processes against the same brand-new
    // dir is the only way to actually exercise the race — and even then,
    // process-startup jitter (spawn + TS-transform time) can spread the
    // children's calls out over tens of milliseconds, wider than the race
    // window itself. The barrier below (see spawnSigner/load-signer.ts)
    // fixes that: every child signals "ready" and blocks; only once ALL N
    // are ready do we release them, all in one tight loop, so their
    // Signer.load calls land as close together as the OS will schedule
    // them.
    const N = 8;
    const children = Array.from({ length: N }, () => spawnSigner(dir));
    await Promise.all(children.map((c) => c.ready));
    for (const c of children) c.go(); // tight loop: release them all at once
    const results = await Promise.all(children.map((c) => c.result));

    for (const r of results) {
      expect(r.code, `child stderr:\n${r.stderr}`).toBe(0);
    }
    const pubKeys = results.map((r) => {
      // stdout is "ready\n<hex>\n" — the public key is the last non-empty line.
      const lines = r.stdout.split('\n').filter((l) => l.trim().length > 0);
      return lines[lines.length - 1]!.trim().toLowerCase();
    });
    for (const k of pubKeys) expect(k).toMatch(HEX64);
    expect(new Set(pubKeys).size).toBe(1);
    const winner = pubKeys[0]!;

    const privOnDisk = readFileSync(join(dir, FILES.PRIVATE_KEY), 'utf8').trim().toLowerCase();
    const pubOnDisk = readFileSync(join(dir, FILES.PUBLIC_KEY), 'utf8').trim().toLowerCase();
    expect(privOnDisk).toMatch(HEX64);
    expect(pubOnDisk).toBe(winner);
    // The private key on disk is the one every child actually agreed on,
    // not merely well-formed: re-derive its public key straight from the
    // raw bytes (not via Signer, so this holds regardless of which
    // Signer.load variant is under test) and compare.
    const derivedPub = ed.etc.bytesToHex(ed.getPublicKey(ed.etc.hexToBytes(privOnDisk)));
    expect(derivedPub).toBe(winner);

    // Windows has no POSIX file-mode bits to check.
    if (process.platform !== 'win32') {
      const mode = statSync(join(dir, FILES.PRIVATE_KEY)).mode & 0o777;
      expect(mode).toBe(0o600);
    }

    // And the winning key actually signs correctly (a fresh in-process load
    // of the now-settled on-disk key — no race left to hit here).
    const signer = await Signer.load(dir);
    expect(signer.publicKeyHex).toBe(winner);
    const chainHash = sha256Hex('race-head');
    const sig = await signer.sign(1, chainHash);
    const ok = ed.verify(sig.signature, signedPayload(1, chainHash), sig.public_key);
    expect(ok).toBe(true);
  }, 30_000);

  it('publicKeyHexFromPem round-trips with publicKeyPem', async () => {
    const signer = await Signer.load(dir);
    const pem = publicKeyPem(signer.publicKeyHex);
    expect(publicKeyHexFromPem(pem)).toBe(signer.publicKeyHex);
  });

  it('publicKeyHexFromPem rejects a non-ed25519 PEM', () => {
    // An RSA-shaped SPKI PEM structure is invalid input for this function
    // (crypto.createPublicKey itself throws on this truncated fixture).
    expect(() => publicKeyHexFromPem('not a pem at all')).toThrow();
  });

  describe('Node >= 18.17 without a WebCrypto global', () => {
    // globalThis.crypto is a default global from Node 19 on; on the declared
    // minimum (18.17) it is undefined unless the process was started with
    // --experimental-global-webcrypto. @noble/ed25519 v2's ASYNC entry
    // points (getPublicKeyAsync/signAsync/utils.randomPrivateKey) read
    // globalThis.crypto and throw when it's missing — this suite proves
    // Signer never calls them (see src/chain/keys.ts's sync-only contract).
    let hadCrypto: boolean;
    let original: Crypto | undefined;

    beforeEach(() => {
      hadCrypto = Object.prototype.hasOwnProperty.call(globalThis, 'crypto');
      original = (globalThis as { crypto?: Crypto }).crypto;
      Object.defineProperty(globalThis, 'crypto', {
        value: undefined,
        configurable: true,
        writable: true,
      });
    });

    afterEach(() => {
      if (hadCrypto) {
        Object.defineProperty(globalThis, 'crypto', {
          value: original,
          configurable: true,
          writable: true,
        });
      } else {
        delete (globalThis as { crypto?: Crypto }).crypto;
      }
    });

    it('generates a fresh keypair and signs with globalThis.crypto undefined', async () => {
      expect(globalThis.crypto).toBeUndefined();
      const signer = await Signer.load(dir);
      expect(signer.publicKeyHex).toMatch(HEX64);
      expect(existsSync(join(dir, FILES.PRIVATE_KEY))).toBe(true);
      const sig = await signer.sign(1, sha256Hex('node18-fresh'));
      expect(sig.signature).toMatch(HEX128);
      expect(sig.public_key).toBe(signer.publicKeyHex);
    });

    it('loads an existing keypair and signs with globalThis.crypto undefined', async () => {
      // Create the key with crypto present (as a prior run of the tool
      // would), then reload/sign with it absent — the load-existing-key and
      // sign paths must not touch the async/WebCrypto API either.
      Object.defineProperty(globalThis, 'crypto', {
        value: original,
        configurable: true,
        writable: true,
      });
      const seeded = await Signer.load(dir);
      Object.defineProperty(globalThis, 'crypto', {
        value: undefined,
        configurable: true,
        writable: true,
      });

      const reloaded = await Signer.load(dir);
      expect(reloaded.publicKeyHex).toBe(seeded.publicKeyHex);
      const sig = await reloaded.sign(7, sha256Hex('node18-reload'));
      expect(sig.signature).toMatch(HEX128);
      const payload = signedPayload(7, sha256Hex('node18-reload'));
      // Verified with plain node:crypto, itself independent of noble/webcrypto.
      const keyObject = createPublicKey(publicKeyPem(reloaded.publicKeyHex));
      expect(nodeVerify(null, payload, keyObject, Buffer.from(sig.signature, 'hex'))).toBe(true);
    });
  });
});
