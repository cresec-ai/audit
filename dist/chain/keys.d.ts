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
import type { HeadSignature } from '../schema/events.js';
import { type SignerLike } from '../types.js';
export declare class Signer implements SignerLike {
    #private;
    /** 64-hex raw ed25519 public key. */
    readonly publicKeyHex: string;
    private constructor();
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
    static load(dataDir: string): Promise<Signer>;
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
    static loadExisting(dataDir: string): Promise<Signer>;
    /**
     * Sign arbitrary, ALREADY DOMAIN-SEPARATED bytes with this data dir's key,
     * returning the 128-hex raw signature. The evidence sink's per-request
     * signature is the only caller (`sinkSignedPayload`, domain
     * `edut.mcp-recorder.sink.v1`), and it is deliberately NOT part of the
     * `SignerLike` contract in src/types.ts: that interface stays two members
     * wide so a TPM / Secure Enclave / YubiKey signer remains a drop-in.
     *
     * Callers must pass a domain-separated payload. Signing raw caller bytes
     * with no prefix would let a signature made for one purpose be replayed as
     * another — which is exactly what `signedPayload`'s prefix prevents for
     * head signatures.
     */
    signBytes(payload: Uint8Array): string;
    /** Sign the chain head; the exact bytes are signedPayload(seq, chainHash). */
    sign(seq: number, chainHash: string): Promise<HeadSignature>;
}
/**
 * Wrap a 64-hex raw ed25519 public key as an SPKI PEM block, verifiable with
 * plain node:crypto (`crypto.verify(null, payload, createPublicKey(pem), sig)`)
 * or openssl — no third-party dependency required.
 */
export declare function publicKeyPem(publicKeyHex: string): string;
/**
 * Inverse of publicKeyPem: extract the 64-hex raw ed25519 public key from an
 * SPKI PEM block, via node:crypto (parses/re-derives, doesn't just strip the
 * fixed prefix — rejects a PEM that isn't actually an ed25519 public key).
 * Used by `verify --public-key <PEM path>` so a third party can pin a key
 * they obtained out of band, in either raw-hex or PEM form.
 */
export declare function publicKeyHexFromPem(pem: string): string;
