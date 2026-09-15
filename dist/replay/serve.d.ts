/**
 * Local replay UI server — node:http only, loopback only, read only.
 *
 * Routes:
 *   GET /                → session picker (or the default session when one
 *                          was passed to serveUi)
 *   GET /?session=<id>   → that session's timeline
 *   GET /healthz         → 200 'ok'
 *
 * Binds 127.0.0.1 exclusively and exposes no write endpoint of any kind.
 */
import type { EvidenceStore, VerifyResult } from '../types.js';
export interface ServeUiOpts {
    store: EvidenceStore;
    /** Default 0 = ephemeral port chosen by the OS. */
    port?: number;
    /** Default session shown at GET / (the picker is shown when omitted). */
    sessionId?: string;
    /** Verification result to show in the integrity banner. */
    verify?: VerifyResult;
}
export interface ServeUiHandle {
    url: string;
    port: number;
    close(): Promise<void>;
}
export declare function serveUi(opts: ServeUiOpts): Promise<ServeUiHandle>;
