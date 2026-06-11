/**
 * ed25519 keypair management + chain-head signing.
 *
 * The keypair lives in the data dir as two hex files (FILES.PRIVATE_KEY /
 * FILES.PUBLIC_KEY). The private key never leaves the machine; the public key
 * is embedded in every HeadSignature and exported (as SPKI PEM) in evidence
 * bundles so a stranger can verify with nothing but node:crypto / openssl.
 */

import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { Buffer } from 'node:buffer';
import * as ed from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha512';
import { signedPayload } from './hash.js';
import type { HeadSignature } from '../schema/events.js';
import { FILES, type SignerLike } from '../types.js';

// @noble/ed25519 v2 ships hash-less; wire sha512 so sync ops work everywhere.
ed.etc.sha512Sync = (...m: Uint8Array[]) => sha512(ed.etc.concatBytes(...m));

const HEX64 = /^[0-9a-f]{64}$/;

export class Signer implements SignerLike {
  /** 64-hex raw ed25519 public key. */
  readonly publicKeyHex: string;
  readonly #privateKey: Uint8Array;

  private constructor(privateKey: Uint8Array, publicKeyHex: string) {
    this.#privateKey = privateKey;
    this.publicKeyHex = publicKeyHex;
  }

  /**
   * Load the keypair from `dataDir`, creating it (and the directory) on first
   * use. The private key file is written with mode 0o600.
   */
  static async load(dataDir: string): Promise<Signer> {
    mkdirSync(dataDir, { recursive: true });
    const privPath = join(dataDir, FILES.PRIVATE_KEY);
    const pubPath = join(dataDir, FILES.PUBLIC_KEY);

    let priv: Uint8Array;
    if (existsSync(privPath)) {
      const hex = readFileSync(privPath, 'utf8').trim().toLowerCase();
      if (!HEX64.test(hex)) {
        throw new Error(
          `mcp-recorder: malformed private key file at ${privPath} (expected 64 hex chars)`,
        );
      }
      priv = ed.etc.hexToBytes(hex);
    } else {
      priv = ed.utils.randomPrivateKey();
      writeFileSync(privPath, ed.etc.bytesToHex(priv) + '\n', { mode: 0o600 });
    }

    const pubHex = ed.etc.bytesToHex(await ed.getPublicKeyAsync(priv));
    // (Re)write the public key file if missing or stale — it is derived state.
    if (!existsSync(pubPath) || readFileSync(pubPath, 'utf8').trim().toLowerCase() !== pubHex) {
      writeFileSync(pubPath, pubHex + '\n');
    }
    return new Signer(priv, pubHex);
  }

  /** Sign the chain head; the exact bytes are signedPayload(seq, chainHash). */
  async sign(seq: number, chainHash: string): Promise<HeadSignature> {
    const payload = signedPayload(seq, chainHash);
    const signature = await ed.signAsync(payload, this.#privateKey);
    return {
      seq,
      chain_hash: chainHash,
      algo: 'ed25519',
      public_key: this.publicKeyHex,
      signature: ed.etc.bytesToHex(signature),
      signed_at: new Date().toISOString(),
    };
  }
}

/**
 * SPKI DER prefix for a raw ed25519 public key:
 * SEQUENCE(42) { SEQUENCE(5) { OID 1.3.101.112 }, BIT STRING(33) { 00, key } }
 */
const SPKI_ED25519_PREFIX_HEX = '302a300506032b6570032100';

/**
 * Wrap a 64-hex raw ed25519 public key as an SPKI PEM block, verifiable with
 * plain node:crypto (`crypto.verify(null, payload, createPublicKey(pem), sig)`)
 * or openssl — no third-party dependency required.
 */
export function publicKeyPem(publicKeyHex: string): string {
  const hex = publicKeyHex.trim().toLowerCase();
  if (!HEX64.test(hex)) {
    throw new Error('mcp-recorder: publicKeyPem expects a 64-hex raw ed25519 public key');
  }
  const der = Buffer.from(SPKI_ED25519_PREFIX_HEX + hex, 'hex');
  const b64 = der.toString('base64');
  const lines: string[] = [];
  for (let i = 0; i < b64.length; i += 64) lines.push(b64.slice(i, i + 64));
  return `-----BEGIN PUBLIC KEY-----\n${lines.join('\n')}\n-----END PUBLIC KEY-----\n`;
}
