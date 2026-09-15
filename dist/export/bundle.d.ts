/**
 * Signed evidence bundle export (M3).
 *
 * A bundle is five files a stranger can verify with nothing but Node.js:
 *   events.jsonl    — one ChainRecord per line, seq order
 *   manifest.json   — BundleManifest (range, base/head hash, fresh signature)
 *   public_key.pem  — SPKI PEM of the recorder's ed25519 key
 *   verify.cjs      — standalone zero-dependency verifier (node verify.cjs)
 *   README.txt      — what this is / how to verify / what PASS proves / who
 *
 * Written as a plain directory (dirPath), a .zip via yazl (zipPath), or both.
 */
import type { BundleManifest, ExportOpts, SignerLike } from '../types.js';
/** File names inside a bundle (dir entries and zip entries are identical). */
export declare const BUNDLE_FILES: {
    readonly EVENTS: "events.jsonl";
    readonly MANIFEST: "manifest.json";
    readonly PUBLIC_KEY: "public_key.pem";
    readonly VERIFY: "verify.cjs";
    readonly README: "README.txt";
};
/**
 * Export a verifiable evidence bundle. The head of the selected range is
 * re-signed at export time so the bundle carries a fresh attestation even
 * when the store's own signatures cover different seqs.
 */
export declare function exportBundle(opts: ExportOpts & {
    signer: SignerLike;
}): Promise<BundleManifest>;
