/**
 * The sink CLIENT: build one batch, sign it, ship it, classify the answer.
 *
 * Order of operations on the way out is fixed and load-bearing:
 *   canonical body bytes -> sha256 of those DECOMPRESSED bytes -> ed25519
 *   signature over the domain-separated payload -> (optional) gzip -> POST.
 * The receiver mirrors it: decompress under a byte budget -> hash -> compare
 * the header -> verify the signature -> only THEN JSON.parse. Untrusted JSON
 * is never parsed before the signature check, on either side.
 *
 * Nothing in here re-serialises the inside of a record. `records` are the
 * `ChainRecord` objects `iterate()` yields, verbatim; re-serialising the
 * TRANSPORT JSON is fine (the hash is over `canonicalJson(event)`, not over
 * our wire bytes), but adding, removing or rewriting one field inside
 * `event` would stop `computeHash` reproducing `record.hash` and the batch
 * would be rejected. That is exactly the property that makes "no readable
 * payloads on the wire" structural rather than a promise.
 */
import type { ChainRecord, HeadSignature } from '../schema/events.js';
import type { SinkConfig } from './config.js';
import type { SinkBatchBody, SinkCursor, SinkHead, SinkSender } from './protocol.js';
/**
 * Everything the sink needs from a signer. Two members, the same shape
 * `SignerLike` keeps, so a TPM / Secure Enclave / YubiKey signer drops
 * straight in — that is the only thing that would make the private key
 * unexportable, and it is not what ships today.
 */
export interface SinkSigner {
    readonly publicKeyHex: string;
    signBytes(payload: Uint8Array): string;
}
export interface SinkClientOpts {
    sink: SinkConfig;
    signer: SinkSigner;
    chainId: string;
    sender: SinkSender;
    env?: NodeJS.ProcessEnv;
    connectTimeoutMs?: number;
    totalTimeoutMs?: number;
    /** Test seam: below this many bytes, send identity; at or above, gzip. */
    gzipThresholdBytes?: number;
}
export type SinkOutcome = 
/** 202: durably committed. 200: heartbeat / cursor read. */
{
    kind: 'ok';
    status: number;
    cursor?: SinkCursor;
}
/** Permanent for these exact bytes — never retry them unchanged. */
 | {
    kind: 'bad_request';
    detail: string;
}
/** Token missing/expired/revoked, or key not enrolled / chain bound elsewhere. */
 | {
    kind: 'unauthorized';
    status: number;
    detail: string;
}
/** from_seq > next_seq: the receiver cannot link. Rewind. */
 | {
    kind: 'gap';
    cursor?: SinkCursor;
    detail: string;
}
/** A seq we already sent is stored with a DIFFERENT hash. TERMINAL. */
 | {
    kind: 'fork';
    cursor?: SinkCursor;
    detail: string;
} | {
    kind: 'too_large';
    maxRecords?: number;
    maxBytes?: number;
    detail: string;
} | {
    kind: 'rate_limited';
    retryAfterMs?: number;
    detail: string;
}
/** 5xx, DNS, TLS, refused, timeout — retry forever. */
 | {
    kind: 'transient';
    detail: string;
};
export declare class SinkClient {
    #private;
    constructor(opts: SinkClientOpts);
    get chainId(): string;
    /** Compose the wire body. No derived fields: everything the receiver needs
     *  is already inside the sealed records. */
    buildBody(input: {
        fromSeq: number;
        toSeq: number;
        baseHash: string;
        records: ChainRecord[];
        signatures: HeadSignature[];
        head: SinkHead;
    }): SinkBatchBody;
    /** GET the resume oracle. THE authoritative answer to "what do you have". */
    fetchCursor(): Promise<SinkOutcome>;
    /** POST one batch (or a heartbeat: empty records, from_seq = to_seq = 0). */
    postBatch(body: SinkBatchBody): Promise<SinkOutcome>;
}
