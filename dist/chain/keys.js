/**
 * ed25519 keypair management + chain-head signing.
 *
 * The keypair lives in the data dir as two hex files (FILES.PRIVATE_KEY /
 * FILES.PUBLIC_KEY). The private key never leaves the machine; the public key
 * is embedded in every HeadSignature and exported (as SPKI PEM) in evidence
 * bundles so a stranger can verify with nothing but node:crypto / openssl.
 *
 * Invariant: this module deliberately uses ONLY the SYNC @noble/ed25519 API
 * (getPublicKey / sign, both wired to sha512Sync below) and node:crypto's
 * randomBytes for key generation, so signing never depends on
 * globalThis.crypto being present. The v2 ASYNC entry points
 * (getPublicKeyAsync / signAsync / utils.randomPrivateKey) go through
 * globalThis.crypto.subtle / getRandomValues, which can be absent or
 * disabled (--no-experimental-global-webcrypto, hardened embedders) — then
 * those calls throw and `record`/`export` fail. Keep this file on the sync
 * API; test/keys.test.ts proves it with the global removed.
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { randomBytes as nodeRandomBytes, createPublicKey } from 'node:crypto';
import { join } from 'node:path';
import { Buffer } from 'node:buffer';
import * as ed from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha512';
import { signedPayload } from './hash.js';
import { FILES } from '../types.js';
import { sleepSync } from '../util/sleep-sync.js';
// @noble/ed25519 v2 ships hash-less; wire sha512 so sync ops work everywhere.
ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));
const HEX64 = /^[0-9a-f]{64}$/;
/**
 * Read and validate the private key file, tolerating the brief window where
 * a concurrent winner of the `wx` create race has created the file but not
 * yet finished writing its content (open/write/close are separate syscalls
 * even though writeFileSync looks atomic from the caller's side).
 */
function readPrivateKey(path) {
    const deadline = Date.now() + 250;
    for (;;) {
        const hex = readFileSync(path, 'utf8').trim().toLowerCase();
        if (HEX64.test(hex))
            return ed.etc.hexToBytes(hex);
        if (Date.now() >= deadline) {
            throw new Error(`mcp-recorder: malformed private key file at ${path} (expected 64 hex chars)`);
        }
        sleepSync(5);
    }
}
export class Signer {
    /** 64-hex raw ed25519 public key. */
    publicKeyHex;
    #privateKey;
    constructor(privateKey, publicKeyHex) {
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
    static async load(dataDir) {
        mkdirSync(dataDir, { recursive: true, mode: 0o700 });
        const privPath = join(dataDir, FILES.PRIVATE_KEY);
        const pubPath = join(dataDir, FILES.PUBLIC_KEY);
        let priv;
        if (existsSync(privPath)) {
            priv = readPrivateKey(privPath);
        }
        else {
            // node:crypto.randomBytes, not ed.utils.randomPrivateKey() — the noble
            // helper reads globalThis.crypto.getRandomValues, which may be absent
            // (see the module doc comment above).
            const candidate = new Uint8Array(nodeRandomBytes(32));
            try {
                writeFileSync(privPath, ed.etc.bytesToHex(candidate) + '\n', { flag: 'wx', mode: 0o600 });
                priv = candidate;
            }
            catch (err) {
                if (err.code !== 'EEXIST')
                    throw err;
                // Another process won the race and created the file first — use it.
                priv = readPrivateKey(privPath);
            }
        }
        // Sync getPublicKey (sha512Sync is wired above) — not getPublicKeyAsync,
        // which needs globalThis.crypto.subtle.
        const pubHex = ed.etc.bytesToHex(ed.getPublicKey(priv));
        // (Re)write the public key file if missing or stale — it is derived
        // state, and rewriting is idempotent even if another process races us
        // to it with the SAME key (both derive an identical pubHex from priv).
        if (!existsSync(pubPath) || readFileSync(pubPath, 'utf8').trim().toLowerCase() !== pubHex) {
            writeFileSync(pubPath, pubHex + '\n');
        }
        return new Signer(priv, pubHex);
    }
    /**
     * Load the keypair from `dataDir` WITHOUT ever minting a new one — unlike
     * `load`, which happily creates a fresh identity on a data dir that has
     * none. Used by `export`: it must sign with the SAME key that produced the
     * chain being exported. A store copied to a fresh machine (or a data dir
     * with `identity.key` deleted) has no such key, and silently minting one
     * there (as `load` would) means export "succeeds" signing with an identity
     * that never touched the evidence — and the next `verify`, pinned to the
     * now-rewritten `identity.pub`, then fails a chain that used to pass.
     * Throws instead, and creates nothing.
     */
    static async loadExisting(dataDir) {
        const privPath = join(dataDir, FILES.PRIVATE_KEY);
        if (!existsSync(privPath)) {
            throw new Error(`no signing key in ${dataDir}: export must run on the recording host ` +
                '(or copy identity.key along with the store)');
        }
        const priv = readPrivateKey(privPath);
        const pubHex = ed.etc.bytesToHex(ed.getPublicKey(priv));
        return new Signer(priv, pubHex);
    }
    /** Sign the chain head; the exact bytes are signedPayload(seq, chainHash). */
    async sign(seq, chainHash) {
        const payload = signedPayload(seq, chainHash);
        // Sync ed.sign (sha512Sync is wired above) — not signAsync, which needs
        // globalThis.crypto.subtle and throws when that global is absent.
        const signature = ed.sign(payload, this.#privateKey);
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
export function publicKeyPem(publicKeyHex) {
    const hex = publicKeyHex.trim().toLowerCase();
    if (!HEX64.test(hex)) {
        throw new Error('mcp-recorder: publicKeyPem expects a 64-hex raw ed25519 public key');
    }
    const der = Buffer.from(SPKI_ED25519_PREFIX_HEX + hex, 'hex');
    const b64 = der.toString('base64');
    const lines = [];
    for (let i = 0; i < b64.length; i += 64)
        lines.push(b64.slice(i, i + 64));
    return `-----BEGIN PUBLIC KEY-----\n${lines.join('\n')}\n-----END PUBLIC KEY-----\n`;
}
/**
 * Inverse of publicKeyPem: extract the 64-hex raw ed25519 public key from an
 * SPKI PEM block, via node:crypto (parses/re-derives, doesn't just strip the
 * fixed prefix — rejects a PEM that isn't actually an ed25519 public key).
 * Used by `verify --public-key <PEM path>` so a third party can pin a key
 * they obtained out of band, in either raw-hex or PEM form.
 */
export function publicKeyHexFromPem(pem) {
    const key = createPublicKey(pem);
    if (key.asymmetricKeyType !== 'ed25519') {
        throw new Error(`mcp-recorder: expected an ed25519 public key PEM, got ${String(key.asymmetricKeyType)}`);
    }
    const der = key.export({ format: 'der', type: 'spki' });
    return der.subarray(der.length - 32).toString('hex');
}
//# sourceMappingURL=keys.js.map