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

import { gzip as gzipCb } from 'node:zlib';
import { promisify } from 'node:util';
import { Buffer } from 'node:buffer';
import { sha256Hex } from '../chain/hash.js';
import type { ChainRecord, HeadSignature } from '../schema/events.js';
import type { SinkConfig } from './config.js';
import { sinkFetch } from './http.js';
import {
  CONNECT_TIMEOUT_MS,
  GZIP_THRESHOLD_BYTES,
  SINK_HEADERS,
  SINK_PROTOCOL,
  TOTAL_TIMEOUT_MS,
  cursorPath,
  parseCursor,
  recordsPath,
  sinkSignedPayload,
} from './protocol.js';
import type { SinkBatchBody, SinkCursor, SinkHead, SinkSender } from './protocol.js';

const gzip = promisify(gzipCb);

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
  | { kind: 'ok'; status: number; cursor?: SinkCursor }
  /** Permanent for these exact bytes — never retry them unchanged. */
  | { kind: 'bad_request'; detail: string }
  /** Token missing/expired/revoked, or key not enrolled / chain bound elsewhere. */
  | { kind: 'unauthorized'; status: number; detail: string }
  /** from_seq > next_seq: the receiver cannot link. Rewind. */
  | { kind: 'gap'; cursor?: SinkCursor; detail: string }
  /** A seq we already sent is stored with a DIFFERENT hash. TERMINAL. */
  | { kind: 'fork'; cursor?: SinkCursor; detail: string }
  | { kind: 'too_large'; maxRecords?: number; maxBytes?: number; detail: string }
  | { kind: 'rate_limited'; retryAfterMs?: number; detail: string }
  /** 5xx, DNS, TLS, refused, timeout — retry forever. */
  | { kind: 'transient'; detail: string };

function headerValue(headers: NodeJS.Dict<string | string[]>, name: string): string | undefined {
  const raw = headers[name];
  if (Array.isArray(raw)) return raw[0];
  return raw;
}

function parseRetryAfter(value: string | undefined): number | undefined {
  if (value === undefined) return undefined;
  const seconds = Number(value);
  if (Number.isFinite(seconds) && seconds >= 0) return Math.floor(seconds * 1000);
  const when = Date.parse(value);
  if (Number.isFinite(when)) return Math.max(0, when - Date.now());
  return undefined;
}

function decodeJson(body: Buffer): Record<string, unknown> | undefined {
  if (body.length === 0) return undefined;
  try {
    const parsed: unknown = JSON.parse(body.toString('utf8'));
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) return undefined;
    return parsed as Record<string, unknown>;
  } catch {
    return undefined;
  }
}

function errorDetail(parsed: Record<string, unknown> | undefined, fallback: string): string {
  if (parsed === undefined) return fallback;
  const message = parsed.message ?? parsed.detail ?? parsed.error;
  return typeof message === 'string' && message !== '' ? message : fallback;
}

export class SinkClient {
  readonly #opts: SinkClientOpts;

  constructor(opts: SinkClientOpts) {
    this.#opts = opts;
  }

  get chainId(): string {
    return this.#opts.chainId;
  }

  /** Compose the wire body. No derived fields: everything the receiver needs
   *  is already inside the sealed records. */
  buildBody(input: {
    fromSeq: number;
    toSeq: number;
    baseHash: string;
    records: ChainRecord[];
    signatures: HeadSignature[];
    head: SinkHead;
  }): SinkBatchBody {
    return {
      protocol: SINK_PROTOCOL,
      chain_id: this.#opts.chainId,
      key: this.#opts.signer.publicKeyHex,
      from_seq: input.fromSeq,
      to_seq: input.toSeq,
      base_hash: input.baseHash,
      records: input.records,
      signatures: input.signatures,
      head: input.head,
      sender: this.#opts.sender,
    };
  }

  /** GET the resume oracle. THE authoritative answer to "what do you have". */
  async fetchCursor(): Promise<SinkOutcome> {
    const url = `${this.#opts.sink.url}${cursorPath(this.#opts.chainId)}`;
    try {
      const res = await sinkFetch(
        {
          method: 'GET',
          url,
          headers: this.#baseHeaders(),
          connectTimeoutMs: this.#opts.connectTimeoutMs ?? CONNECT_TIMEOUT_MS,
          totalTimeoutMs: this.#opts.totalTimeoutMs ?? TOTAL_TIMEOUT_MS,
        },
        this.#opts.env ?? process.env,
      );
      return this.#classify(res.status, res.headers, res.body);
    } catch (cause) {
      return { kind: 'transient', detail: cause instanceof Error ? cause.message : String(cause) };
    }
  }

  /** POST one batch (or a heartbeat: empty records, from_seq = to_seq = 0). */
  async postBatch(body: SinkBatchBody): Promise<SinkOutcome> {
    const raw = Buffer.from(JSON.stringify(body), 'utf8');
    const digest = sha256Hex(raw);
    const signature = this.#opts.signer.signBytes(
      sinkSignedPayload(this.#opts.chainId, body.from_seq, body.to_seq, digest),
    );
    const threshold = this.#opts.gzipThresholdBytes ?? GZIP_THRESHOLD_BYTES;
    let payload = raw;
    let encoding: string | undefined;
    if (raw.length >= threshold) {
      try {
        // Async gzip, never gzipSync: a synchronous compress of a 1 MiB body
        // would block this process's event loop for no reason at all.
        payload = await gzip(raw);
        encoding = 'gzip';
      } catch {
        payload = raw;
        encoding = undefined;
      }
    }
    const headers: Record<string, string> = {
      ...this.#baseHeaders(),
      'content-type': 'application/json',
      'content-length': String(payload.length),
      [SINK_HEADERS.CONTENT_SHA256]: digest,
      [SINK_HEADERS.SIGNATURE]: signature,
      [SINK_HEADERS.SENT_AT]: new Date().toISOString(),
      // Same value as the digest: an optimisation for the receiver, never a
      // substitute for it linking the batch to what it already holds.
      [SINK_HEADERS.IDEMPOTENCY]: digest,
    };
    if (encoding !== undefined) headers['content-encoding'] = encoding;

    const url = `${this.#opts.sink.url}${recordsPath(this.#opts.chainId)}`;
    try {
      const res = await sinkFetch(
        {
          method: 'POST',
          url,
          headers,
          body: payload,
          connectTimeoutMs: this.#opts.connectTimeoutMs ?? CONNECT_TIMEOUT_MS,
          totalTimeoutMs: this.#opts.totalTimeoutMs ?? TOTAL_TIMEOUT_MS,
        },
        this.#opts.env ?? process.env,
      );
      return this.#classify(res.status, res.headers, res.body);
    } catch (cause) {
      return { kind: 'transient', detail: cause instanceof Error ? cause.message : String(cause) };
    }
  }

  #baseHeaders(): Record<string, string> {
    const headers: Record<string, string> = {
      accept: 'application/json',
      [SINK_HEADERS.PROTOCOL]: String(SINK_PROTOCOL),
      [SINK_HEADERS.KEY]: this.#opts.signer.publicKeyHex,
    };
    const token = this.#opts.sink.token;
    if (token !== undefined) headers.authorization = `Bearer ${token}`;
    return headers;
  }

  #classify(
    status: number,
    headers: NodeJS.Dict<string | string[]>,
    body: Buffer,
  ): SinkOutcome {
    const parsed = decodeJson(body);
    const cursor = parsed === undefined ? undefined : parseCursor(parsed);
    if (status === 200 || status === 202) {
      return cursor !== undefined ? { kind: 'ok', status, cursor } : { kind: 'ok', status };
    }
    if (status === 400) {
      return { kind: 'bad_request', detail: errorDetail(parsed, 'sink rejected the batch (400)') };
    }
    if (status === 401 || status === 403) {
      return {
        kind: 'unauthorized',
        status,
        detail: errorDetail(parsed, `sink refused the credential (${String(status)})`),
      };
    }
    if (status === 409) {
      // Only an explicit chain_fork is terminal. An unlabelled 409 is treated
      // as a gap and re-resolved against the cursor: declaring a fork — which
      // stops shipping for good — on an ambiguous answer would be the worse
      // mistake of the two.
      const code = typeof parsed?.error === 'string' ? parsed.error : '';
      const detail = errorDetail(parsed, `sink reported a chain conflict (${code || '409'})`);
      if (code === 'chain_fork') {
        return cursor !== undefined ? { kind: 'fork', cursor, detail } : { kind: 'fork', detail };
      }
      return cursor !== undefined ? { kind: 'gap', cursor, detail } : { kind: 'gap', detail };
    }
    if (status === 413) {
      const maxRecords = typeof parsed?.max_records === 'number' ? parsed.max_records : undefined;
      const maxBytes = typeof parsed?.max_bytes === 'number' ? parsed.max_bytes : undefined;
      const outcome: SinkOutcome = {
        kind: 'too_large',
        detail: errorDetail(parsed, 'sink rejected the batch as too large (413)'),
      };
      if (maxRecords !== undefined) outcome.maxRecords = maxRecords;
      if (maxBytes !== undefined) outcome.maxBytes = maxBytes;
      return outcome;
    }
    if (status === 429) {
      const retryAfterMs = parseRetryAfter(headerValue(headers, 'retry-after'));
      const outcome: SinkOutcome = {
        kind: 'rate_limited',
        detail: errorDetail(parsed, 'sink rate limited this sender (429)'),
      };
      if (retryAfterMs !== undefined) outcome.retryAfterMs = retryAfterMs;
      return outcome;
    }
    if (status >= 500) {
      const retryAfterMs = parseRetryAfter(headerValue(headers, 'retry-after'));
      const detail = errorDetail(parsed, `sink returned ${String(status)}`);
      return retryAfterMs !== undefined
        ? { kind: 'rate_limited', retryAfterMs, detail }
        : { kind: 'transient', detail };
    }
    return { kind: 'transient', detail: `sink returned an unexpected status ${String(status)}` };
  }
}
