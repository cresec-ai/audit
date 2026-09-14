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

/** A real synchronous sleep, without a native dependency. */
function sleepSync(ms: number): void {
  const sab = new SharedArrayBuffer(4);
  Atomics.wait(new Int32Array(sab), 0, 0, ms);
}

/**
 * Read and validate the private key file, tolerating the brief window where
 * a concurrent winner of the `wx` create race has created the file but not
 * yet finished writing its content (open/write/close are separate syscalls
 * even though writeFileSync looks atomic from the caller's side).
 */
function readPrivateKey(path: string): Uint8Array {
  const deadline = Date.now() + 250;
  for (;;) {
    const hex = readFileSync(path, 'utf8').trim().toLowerCase();
    if (HEX64.test(hex)) return ed.etc.hexToBytes(hex);
    if (Date.now() >= deadline) {
      throw new Error(
        `mcp-recorder: malformed private key file at ${path} (expected 64 hex chars)`,
      );
    }
    sleepSync(5);
  }
}

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
   *
   * Several `mcp-recorder record` processes normally share one data dir (one
   * wrapper per MCP server) and can race here on a brand-new dir: the private
   * key is created with the exclusive `wx` flag, so at most one process's
   * `writeFileSync` wins the file and every other one gets EEXIST — at which
   * point it just re-reads whichever key won, rather than clobbering it with
   * its own (which would leave two processes signing under different
   * identities).
   */
  static async load(dataDir: string): Promise<Signer> {
    mkdirSync(dataDir, { recursive: true });
    const privPath = join(dataDir, FILES.PRIVATE_KEY);
    const pubPath = join(dataDir, FILES.PUBLIC_KEY);

    let priv: Uint8Array;
    if (existsSync(privPath)) {
      priv = readPrivateKey(privPath);
    } else {
      const candidate = ed.utils.randomPrivateKey();
      try {
        writeFileSync(privPath, ed.etc.bytesToHex(candidate) + '\n', { flag: 'wx', mode: 0o600 });
        priv = candidate;
      } catch (err) {
        if ((err as NodeJS.ErrnoException).code !== 'EEXIST') throw err;
        // Another process won the race and created the file first — use it.
        priv = readPrivateKey(privPath);
      }
    }

    const pubHex = ed.etc.bytesToHex(await ed.getPublicKeyAsync(priv));
    // (Re)write the public key file if missing or stale — it is derived
    // state, and rewriting is idempotent even if another process races us
    // to it with the SAME key (both derive an identical pubHex from priv).
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
