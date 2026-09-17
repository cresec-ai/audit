/**
 * The receiver's decision layer: everything from "here are the decompressed
 * body bytes and the headers" to "here is the status code and the cursor".
 * No HTTP, no sockets — server.ts owns those — so every rejection path is
 * directly testable.
 *
 * ORDER OF OPERATIONS, and it is load-bearing:
 *   1. bearer token           -> 401   (cheap channel gate, before any crypto)
 *   2. header shapes          -> 400
 *   3. sha256(body) vs header -> 400
 *   4. ed25519 request sig    -> 400   (BEFORE the body is interpreted)
 *   5. JSON.parse + shape     -> 400
 *   6. caps                   -> 413
 *   7. enrolment / binding    -> 403
 *   8. chain link + recompute -> 400 / 409
 *   9. durable commit, THEN 202
 *
 * A receiver that stores what it was told without steps 4 and 8 is worse
 * than no receiver: it launders tampering into apparent evidence.
 */

import { createHash, createPublicKey, timingSafeEqual, verify as cryptoVerify } from 'node:crypto';
import { Buffer } from 'node:buffer';
import { GENESIS_HASH, signedPayload } from '../src/chain/hash.js';
import { publicKeyPem } from '../src/chain/keys.js';
import { verifyRecords } from '../src/verify/verify.js';
import type { ChainRecord, HeadSignature } from '../src/schema/events.js';
import {
  HEADERS,
  HEX128,
  HEX64,
  SINK_PROTOCOL_VERSION,
  isHeartbeat,
  sinkSignedPayload,
} from './protocol.js';
import type { RecordsBatch, SinkCursor, SinkErrorBody, SinkErrorCode, SinkHead } from './protocol.js';
import { authenticate, bearer, loadAuthConfig } from './auth.js';
import type { AuthConfig, TokenConfig } from './auth.js';
import { ReceiverStore } from './store.js';
import type { Alert, ChainState } from './store.js';

/* ----------------------------- defaults ------------------------------ */

/** The contract's receiver floor: MUST accept >= 5000 records. */
export const DEFAULT_MAX_RECORDS = 5000;
/** The contract's receiver floor: MUST accept >= 8 MiB uncompressed. */
export const DEFAULT_MAX_BYTES = 8 * 1024 * 1024;
/** ...and a SINGLE-record batch up to 32 MiB, because a sender may never skip. */
export const DEFAULT_MAX_SINGLE_RECORD_BYTES = 32 * 1024 * 1024;
export const DEFAULT_HEARTBEAT_INTERVAL_S = 60;
/** Missed heartbeats before silence is an incident. */
export const DEFAULT_SILENCE_AFTER_INTERVALS = 3;

export interface ReceiverOptions {
  dataDir: string;
  maxRecords?: number;
  maxBytes?: number;
  maxSingleRecordBytes?: number;
  heartbeatIntervalS?: number;
  silenceAfterIntervals?: number;
  /**
   * Refuse a POST that does not carry `X-MCPR-Range`, rather than reading
   * from_seq/to_seq out of the not-yet-authenticated body. Hardened
   * deployments should set this once their senders send the header.
   */
  requireRangeHeader?: boolean;
  env?: NodeJS.ProcessEnv;
  now?: () => Date;
}

export interface Reply {
  status: number;
  body: unknown;
}

export interface IngestInput {
  chainIdFromPath: string;
  headers: Record<string, string | undefined>;
  /** The DECOMPRESSED body bytes. server.ts has already bounded these. */
  body: Buffer;
  remote: string | null;
}

/* ---------------------------- shape checks --------------------------- */

function isSeq(value: unknown, min: number): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= min;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isHex64(value: unknown): value is string {
  return typeof value === 'string' && HEX64.test(value);
}

/**
 * Structural validation of the parsed body. Returns an error string, or
 * undefined when the value is safe to treat as a RecordsBatch. Deliberately
 * strict: everything downstream indexes these fields without re-checking.
 */
function batchShapeError(value: unknown): string | undefined {
  if (!isPlainObject(value)) return 'body is not a JSON object';
  if (value.protocol !== SINK_PROTOCOL_VERSION) {
    return `unsupported protocol ${String(value.protocol)} (this receiver speaks ${SINK_PROTOCOL_VERSION})`;
  }
  if (!isHex64(value.chain_id)) return 'chain_id must be 64 lowercase hex';
  if (!isHex64(value.key)) return 'key must be 64 lowercase hex';
  if (!isHex64(value.base_hash)) return 'base_hash must be 64 lowercase hex';
  if (!isSeq(value.from_seq, 0)) return 'from_seq must be a non-negative integer';
  if (!isSeq(value.to_seq, 0)) return 'to_seq must be a non-negative integer';
  if (!Array.isArray(value.records)) return 'records must be an array';
  if (!Array.isArray(value.signatures)) return 'signatures must be an array';

  const from = value.from_seq;
  const to = value.to_seq;
  const records = value.records;
  if (from === 0 || to === 0) {
    if (from !== 0 || to !== 0 || records.length !== 0) {
      return 'seq 0 is reserved for the heartbeat (from_seq = to_seq = 0, records = [])';
    }
  } else {
    if (to < from) return `to_seq ${to} is before from_seq ${from}`;
    if (records.length !== to - from + 1) {
      return `records has ${records.length} entr(ies) but the range ${from}..${to} covers ${to - from + 1}`;
    }
  }

  for (let i = 0; i < records.length; i++) {
    const record = records[i];
    if (!isPlainObject(record)) return `records[${i}] is not an object`;
    if (!isSeq(record.seq, 1)) return `records[${i}].seq must be an integer >= 1`;
    if (!isHex64(record.prev_hash)) return `records[${i}].prev_hash must be 64 lowercase hex`;
    if (!isHex64(record.hash)) return `records[${i}].hash must be 64 lowercase hex`;
    if (!isPlainObject(record.event)) return `records[${i}].event must be an object`;
  }
  for (let i = 0; i < value.signatures.length; i++) {
    if (!isPlainObject(value.signatures[i])) return `signatures[${i}] is not an object`;
  }

  const head = value.head;
  if (!isPlainObject(head)) return 'head must be an object';
  if (!isSeq(head.seq, 0)) return 'head.seq must be a non-negative integer';
  if (!isHex64(head.hash)) return 'head.hash must be 64 lowercase hex';
  if (!isPlainObject(head.signature)) return 'head.signature must be an object';
  if (value.sender !== undefined && !isPlainObject(value.sender)) {
    return 'sender, when present, must be an object';
  }
  return undefined;
}

/** Shape check for a HeadSignature, before any cryptography. */
function signatureShapeError(sig: unknown): string | undefined {
  if (!isPlainObject(sig)) return 'not an object';
  if (!isSeq(sig.seq, 1)) return 'seq must be an integer >= 1';
  if (!isHex64(sig.chain_hash)) return 'chain_hash must be 64 lowercase hex';
  if (sig.algo !== 'ed25519') return `unsupported algo ${String(sig.algo)}`;
  if (!isHex64(sig.public_key)) return 'public_key must be 64 lowercase hex';
  if (typeof sig.signature !== 'string' || !HEX128.test(sig.signature)) {
    return 'signature must be 128 lowercase hex';
  }
  return undefined;
}

/**
 * ed25519 verification via node:crypto — no third-party code on the
 * authentication path. (`verifyRecords` independently re-checks every
 * in-range HeadSignature with @noble/ed25519, so two implementations agree
 * before anything is committed.)
 */
function ed25519Verify(publicKeyHex: string, payload: Uint8Array, signatureHex: string): boolean {
  try {
    return cryptoVerify(
      null,
      Buffer.from(payload),
      createPublicKey(publicKeyPem(publicKeyHex)),
      Buffer.from(signatureHex, 'hex'),
    );
  } catch {
    return false;
  }
}

function parseRangeHeader(value: string | undefined): { from: number; to: number } | undefined {
  if (value === undefined) return undefined;
  const match = /^(\d{1,15})-(\d{1,15})$/.exec(value.trim());
  if (match === null) return undefined;
  const from = Number(match[1]);
  const to = Number(match[2]);
  if (!Number.isSafeInteger(from) || !Number.isSafeInteger(to)) return undefined;
  return { from, to };
}

/* ------------------------------ receiver ----------------------------- */

export class Receiver {
  readonly store: ReceiverStore;
  readonly auth: AuthConfig;
  readonly maxRecords: number;
  readonly maxBytes: number;
  readonly maxSingleRecordBytes: number;
  readonly heartbeatIntervalS: number;
  readonly silenceAfterIntervals: number;
  readonly requireRangeHeader: boolean;
  readonly #now: () => Date;

  constructor(opts: ReceiverOptions) {
    this.store = new ReceiverStore(opts.dataDir);
    this.auth = loadAuthConfig(opts.dataDir, opts.env ?? process.env);
    this.maxRecords = opts.maxRecords ?? DEFAULT_MAX_RECORDS;
    this.maxBytes = opts.maxBytes ?? DEFAULT_MAX_BYTES;
    this.maxSingleRecordBytes = opts.maxSingleRecordBytes ?? DEFAULT_MAX_SINGLE_RECORD_BYTES;
    this.heartbeatIntervalS = opts.heartbeatIntervalS ?? DEFAULT_HEARTBEAT_INTERVAL_S;
    this.silenceAfterIntervals = opts.silenceAfterIntervals ?? DEFAULT_SILENCE_AFTER_INTERVALS;
    this.requireRangeHeader = opts.requireRangeHeader ?? false;
    this.#now = opts.now ?? (() => new Date());
  }

  #at(): string {
    return this.#now().toISOString();
  }

  /* ------------------------------ cursor ----------------------------- */

  cursorFor(chainId: string, keyHint?: string): SinkCursor {
    const state = this.store.chain(chainId);
    const attested =
      state === undefined ? { seq: 0, at: null as string | null } : this.#attestedFor(state);
    return {
      chain_id: chainId,
      key: state?.key ?? (keyHint !== undefined && HEX64.test(keyHint) ? keyHint : ''),
      next_seq: state?.next_seq ?? 1,
      head_hash: state?.head_hash ?? GENESIS_HASH,
      attested_seq: attested.seq,
      attested_at: attested.at,
      max_records: this.maxRecords,
      max_bytes: this.maxBytes,
      heartbeat_interval_s: this.heartbeatIntervalS,
    };
  }

  /**
   * A TOFU key an operator has not acknowledged is delivered but NOT
   * attested — that is what the `new_identity` flag means. The signatures
   * are still verified and stored; they just do not count until a human says
   * the key belongs to this install.
   */
  #attestedFor(state: ChainState): { seq: number; at: string | null } {
    const enrolled = this.store.enrolledKey(state.tenant, state.key);
    if (enrolled !== undefined && !enrolled.acknowledged) return { seq: 0, at: null };
    return { seq: state.attested_seq, at: state.attested_at };
  }

  /**
   * GET /v1/chains/{chain_id}/cursor — the resume oracle.
   *
   * Authenticated, because it names how much of an install's chain exists;
   * and scoped to the token's tenant, which is one notch tighter than the
   * contract requires (the contract treats a cursor read for a guessed
   * chain_id as an accepted nuisance). It leaks no content either way:
   * next_seq, a hash, and the caps.
   */
  readCursor(input: Omit<IngestInput, 'body'>): Reply {
    const at = this.#at();
    const chainId = input.chainIdFromPath;
    if (!HEX64.test(chainId)) {
      return {
        status: 400,
        body: {
          error: 'bad_request',
          detail: 'chain_id in the path must be 64 lowercase hex',
        } satisfies SinkErrorBody,
      };
    }
    const token = authenticate(this.auth, bearer(input.headers['authorization']));
    if (token === undefined) {
      this.store.recordRejection({
        received_at: at,
        chain_id: chainId,
        key: null,
        tenant: null,
        status: 401,
        error: 'unauthorized',
        detail: 'cursor read without a valid bearer token',
        from_seq: null,
        to_seq: null,
        remote: input.remote,
      });
      return {
        status: 401,
        body: {
          error: 'unauthorized',
          detail: 'missing, unknown or revoked bearer token',
        } satisfies SinkErrorBody,
      };
    }
    const keyHint = input.headers[HEADERS.KEY]?.trim().toLowerCase();
    const state = this.store.chain(chainId);
    if (state !== undefined) {
      if (state.tenant !== token.tenant) {
        return {
          status: 403,
          body: {
            error: 'forbidden',
            detail: `chain ${chainId} belongs to tenant ${state.tenant}`,
          } satisfies SinkErrorBody,
        };
      }
      if (keyHint !== undefined && HEX64.test(keyHint) && keyHint !== state.key) {
        return {
          status: 403,
          body: {
            error: 'forbidden',
            detail: `chain ${chainId} is bound to key ${state.key}`,
          } satisfies SinkErrorBody,
        };
      }
    }
    return { status: 200, body: this.cursorFor(chainId, keyHint) };
  }

  /* ------------------------------ ingest ----------------------------- */

  /** POST /v1/chains/{chain_id}/records */
  async ingest(input: IngestInput): Promise<Reply> {
    const at = this.#at();
    const chainId = input.chainIdFromPath;
    const header = (name: string): string | undefined => input.headers[name];

    const fail = (
      status: number,
      error: SinkErrorCode,
      detail: string,
      extra: Partial<SinkErrorBody> = {},
      known: { key?: string; tenant?: string; from?: number; to?: number } = {},
    ): Reply => {
      this.store.recordRejection({
        received_at: at,
        chain_id: chainId,
        key: known.key ?? null,
        tenant: known.tenant ?? null,
        status,
        error,
        detail,
        from_seq: known.from ?? null,
        to_seq: known.to ?? null,
        remote: input.remote,
      });
      return { status, body: { error, detail, ...extra } satisfies SinkErrorBody };
    };

    /* 0. path */
    if (!HEX64.test(chainId)) {
      return fail(400, 'bad_request', 'chain_id in the path must be 64 lowercase hex');
    }

    /* 1. bearer token — the channel gate, before any cryptography. */
    const token = authenticate(this.auth, bearer(header('authorization')));
    if (token === undefined) {
      return fail(
        401,
        'unauthorized',
        this.auth.source === 'none'
          ? 'this receiver has no ingest tokens configured (see receiver/README.md)'
          : 'missing, unknown or revoked bearer token',
      );
    }

    /* 2. header shapes */
    const protocolHeader = header(HEADERS.PROTOCOL);
    if (protocolHeader !== undefined && protocolHeader.trim() !== String(SINK_PROTOCOL_VERSION)) {
      return fail(
        400,
        'bad_request',
        `${HEADERS.PROTOCOL}: ${protocolHeader} — this receiver speaks ${SINK_PROTOCOL_VERSION}`,
        {},
        { tenant: token.tenant },
      );
    }
    const key = header(HEADERS.KEY)?.trim().toLowerCase();
    if (key === undefined || !HEX64.test(key)) {
      return fail(400, 'bad_request', `${HEADERS.KEY} must be a 64-hex ed25519 public key`, {}, { tenant: token.tenant });
    }
    const declaredDigest = header(HEADERS.CONTENT_SHA256)?.trim().toLowerCase();
    if (declaredDigest === undefined || !HEX64.test(declaredDigest)) {
      return fail(400, 'bad_request', `${HEADERS.CONTENT_SHA256} must be a 64-hex sha256`, {}, { key, tenant: token.tenant });
    }
    const requestSignature = header(HEADERS.SIGNATURE)?.trim().toLowerCase();
    if (requestSignature === undefined || !HEX128.test(requestSignature)) {
      return fail(400, 'bad_request', `${HEADERS.SIGNATURE} must be a 128-hex ed25519 signature`, {}, { key, tenant: token.tenant });
    }

    /* 3. digest of the DECOMPRESSED bytes must match the header. */
    const actualDigest = createHash('sha256').update(input.body).digest();
    const declared = Buffer.from(declaredDigest, 'hex');
    if (declared.length !== actualDigest.length || !timingSafeEqual(declared, actualDigest)) {
      return fail(
        400,
        'bad_request',
        `${HEADERS.CONTENT_SHA256} does not match the body (declared ${declaredDigest}, got ${actualDigest.toString('hex')})`,
        {},
        { key, tenant: token.tenant },
      );
    }

    /* 4. the signed range, then the request signature — BEFORE interpreting
     *    the body. See receiver/README.md "the one deviation". */
    let range = parseRangeHeader(header(HEADERS.RANGE));
    let parsed: unknown;
    let didPreParse = false;
    if (range === undefined) {
      if (this.requireRangeHeader) {
        return fail(
          400,
          'bad_request',
          `${HEADERS.RANGE} is required by this receiver (<from_seq>-<to_seq>), so the request signature can be checked before the body is parsed`,
          {},
          { key, tenant: token.tenant },
        );
      }
      parsed = tryParseJson(input.body);
      didPreParse = true;
      if (
        isPlainObject(parsed) &&
        isSeq(parsed.from_seq, 0) &&
        isSeq(parsed.to_seq, 0)
      ) {
        range = { from: parsed.from_seq, to: parsed.to_seq };
      }
      if (range === undefined) {
        return fail(
          400,
          'bad_request',
          `cannot determine the signed range: send ${HEADERS.RANGE}, or a body with integer from_seq/to_seq`,
          {},
          { key, tenant: token.tenant },
        );
      }
    }

    if (
      !ed25519Verify(key, sinkSignedPayload(chainId, range.from, range.to, declaredDigest), requestSignature)
    ) {
      return fail(
        400,
        'bad_request',
        `${HEADERS.SIGNATURE} does not verify against ${HEADERS.KEY} over ` +
          `(chain_id, ${range.from}, ${range.to}, content-sha256) — the batch was not signed by the key it claims`,
        {},
        { key, tenant: token.tenant, from: range.from, to: range.to },
      );
    }

    /* 5. only now is the body authenticated data. */
    if (!didPreParse) parsed = tryParseJson(input.body);
    if (parsed === undefined) {
      return fail(400, 'bad_request', 'body is not valid JSON', {}, { key, tenant: token.tenant });
    }
    const shapeError = batchShapeError(parsed);
    if (shapeError !== undefined) {
      return fail(400, 'bad_request', shapeError, {}, { key, tenant: token.tenant });
    }
    const batch = parsed as unknown as RecordsBatch;

    if (batch.chain_id !== chainId) {
      return fail(
        400,
        'bad_request',
        `body chain_id ${batch.chain_id} does not match the path`,
        {},
        { key, tenant: token.tenant, from: batch.from_seq, to: batch.to_seq },
      );
    }
    if (batch.key !== key) {
      return fail(
        400,
        'bad_request',
        `body key ${batch.key} does not match ${HEADERS.KEY}`,
        {},
        { key, tenant: token.tenant, from: batch.from_seq, to: batch.to_seq },
      );
    }
    if (batch.from_seq !== range.from || batch.to_seq !== range.to) {
      return fail(
        400,
        'bad_request',
        `body range ${batch.from_seq}..${batch.to_seq} is not the signed range ${range.from}..${range.to}`,
        {},
        { key, tenant: token.tenant, from: batch.from_seq, to: batch.to_seq },
      );
    }

    /* 6. caps. A one-record batch is allowed the larger ceiling because the
     *    sender must never skip a record it cannot split. */
    const ceiling = batch.records.length <= 1 ? this.maxSingleRecordBytes : this.maxBytes;
    if (batch.records.length > this.maxRecords || input.body.length > ceiling) {
      return fail(
        413,
        'too_large',
        `batch is ${batch.records.length} record(s) / ${input.body.length} byte(s); this receiver accepts ` +
          `${this.maxRecords} record(s) and ${this.maxBytes} bytes (${this.maxSingleRecordBytes} for a single record)`,
        { max_records: this.maxRecords, max_bytes: this.maxBytes },
        { key, tenant: token.tenant, from: batch.from_seq, to: batch.to_seq },
      );
    }

    /* 7. enrolment and binding. */
    const forbidden = this.#authorizeKey(token, key, at);
    if (forbidden !== undefined) {
      return fail(403, 'forbidden', forbidden, {}, { key, tenant: token.tenant, from: batch.from_seq, to: batch.to_seq });
    }

    let state = this.store.chain(chainId);
    if (state !== undefined) {
      if (state.key !== key) {
        return fail(
          403,
          'forbidden',
          `chain ${chainId} is bound to key ${state.key} — a chain_id belongs to exactly one key`,
          { cursor: this.cursorFor(chainId) },
          { key, tenant: token.tenant, from: batch.from_seq, to: batch.to_seq },
        );
      }
      if (state.tenant !== token.tenant) {
        return fail(
          403,
          'forbidden',
          `chain ${chainId} belongs to tenant ${state.tenant}`,
          {},
          { key, tenant: token.tenant, from: batch.from_seq, to: batch.to_seq },
        );
      }
      if (state.status === 'forked') {
        this.store.recordFork(chainId, {
          received_at: at,
          reason: 'batch arrived for a chain already marked forked',
          at_seq: batch.from_seq,
          stored_hash: this.store.hashAt(chainId, batch.from_seq) ?? null,
          offered_hash: batch.records[0]?.hash ?? null,
          offered: batch,
        });
        return fail(
          409,
          'chain_fork',
          `chain ${chainId} is forked; shipping is terminal for it. Both branches are retained for audit.`,
          { cursor: this.cursorFor(chainId) },
          { key, tenant: token.tenant, from: batch.from_seq, to: batch.to_seq },
        );
      }
    } else {
      state = this.store.createChain({
        chain_id: chainId,
        key,
        tenant: token.tenant,
        at,
        ...(batch.sender !== undefined ? { sender: batch.sender } : {}),
      });
      const siblings = this.store.chainsForKey(key).filter((c) => c.chain_id !== chainId);
      if (siblings.length > 0) {
        this.store.raiseAlert({
          at,
          kind: 'second_chain_for_key',
          chain_id: chainId,
          key,
          tenant: token.tenant,
          detail:
            `key ${key} already has ${siblings.length} chain(s) here; a NEW chain_id under an ` +
            'enrolled key means the local evidence store was reset (identity.key survived, evidence.db did not)',
        });
      }
    }

    /* 8-9. the chain itself. */
    return isHeartbeat(batch)
      ? this.#heartbeat(chainId, batch, at, fail, { key, tenant: token.tenant })
      : await this.#records(chainId, batch, at, fail, { key, tenant: token.tenant });
  }

  /* --------------------------- authorization ------------------------- */

  /** Returns a 403 detail string, or undefined when the key may write. */
  #authorizeKey(token: TokenConfig, key: string, at: string): string | undefined {
    if (token.enrolment === 'pinned') {
      if (!(token.keys ?? []).includes(key)) {
        return (
          `key ${key} is not enrolled for tenant ${token.tenant} (pinned enrolment). ` +
          "Add it to tokens.json from the install's identity.pub."
        );
      }
      this.store.enrolKey(token.tenant, key, at, true);
      return undefined;
    }
    // TOFU: the first key on a token is bound to it; later ones are accepted
    // but flagged, and do not count as attested until acknowledged.
    if (this.store.enrolledKey(token.tenant, key) === undefined) {
      const first = Object.keys(this.store.enrolment()[token.tenant] ?? {}).length === 0;
      this.store.enrolKey(token.tenant, key, at, first);
      if (!first) {
        this.store.raiseAlert({
          at,
          kind: 'new_identity',
          chain_id: '',
          key,
          tenant: token.tenant,
          detail:
            'a second ed25519 identity appeared on this token (trust-on-first-use). ' +
            'Records are stored but NOT attested until an operator acknowledges the key.',
        });
      }
    }
    return undefined;
  }

  /* ----------------------------- heartbeat --------------------------- */

  #heartbeat(
    chainId: string,
    batch: RecordsBatch,
    at: string,
    fail: FailFn,
    ctx: { key: string; tenant: string },
  ): Reply {
    const headError = this.#checkHead(chainId, batch.head, ctx.key, new Map());
    if (headError !== undefined) {
      if (headError.fork) {
        return this.#fork(chainId, batch, at, headError.detail, headError.atSeq, headError.stored, headError.offered, fail, ctx);
      }
      return fail(400, 'bad_request', headError.detail, {}, { ...ctx, from: 0, to: 0 });
    }
    this.store.touch(chainId, at, batch.sender);
    this.store.recordHead(chainId, batch.head, at);
    return { status: 200, body: this.cursorFor(chainId, ctx.key) };
  }

  /* ------------------------------ records ---------------------------- */

  async #records(
    chainId: string,
    batch: RecordsBatch,
    at: string,
    fail: FailFn,
    ctx: { key: string; tenant: string },
  ): Promise<Reply> {
    const state = this.store.chain(chainId)!;
    const nextSeq = state.next_seq;
    const span = { from: batch.from_seq, to: batch.to_seq };

    /* GAP: the batch starts past what we hold, so nothing links it to our
     * copy. Never accept-and-reconcile — a skipped record makes everything
     * after it unverifiable here, forever. */
    if (batch.from_seq > nextSeq) {
      return fail(
        409,
        'chain_gap',
        `batch starts at seq ${batch.from_seq} but this receiver holds through ${nextSeq - 1}; ` +
          `rewind to ${nextSeq}`,
        { cursor: this.cursorFor(chainId, ctx.key) },
        { ...ctx, ...span },
      );
    }

    /* The batch must be self-consistent: contiguous, ascending, every
     * prev_hash linking, and every hash recomputing from its own event.
     * This is `src/verify/verify.ts` — the same algorithm `verify` runs — so
     * the two can never drift. */
    const inRangeSigs: HeadSignature[] = [];
    for (let i = 0; i < batch.signatures.length; i++) {
      const sig = batch.signatures[i] as HeadSignature;
      const shape = signatureShapeError(sig);
      if (shape !== undefined) {
        return fail(400, 'bad_request', `signatures[${i}]: ${shape}`, {}, { ...ctx, ...span });
      }
      if (sig.public_key !== ctx.key) {
        return fail(
          400,
          'bad_request',
          `signatures[${i}] is by key ${sig.public_key}, not ${HEADERS.KEY}`,
          {},
          { ...ctx, ...span },
        );
      }
      if (sig.seq >= batch.from_seq && sig.seq <= batch.to_seq) inRangeSigs.push(sig);
    }

    const verification = await verifyBatchChain(batch.records, inRangeSigs, batch.base_hash, ctx.key);
    if (verification !== undefined) {
      return fail(400, 'bad_request', verification, {}, { ...ctx, ...span });
    }

    /* A chain's identity IS the hash of its seq-1 record. When seq 1 is in
     * this batch we can check that the sender addressed the right chain. */
    if (batch.from_seq === 1) {
      if (batch.base_hash !== GENESIS_HASH) {
        return fail(
          400,
          'bad_request',
          `a batch starting at seq 1 must have base_hash = GENESIS_HASH (${GENESIS_HASH})`,
          {},
          { ...ctx, ...span },
        );
      }
      if (batch.records[0]!.hash !== chainId) {
        return fail(
          400,
          'bad_request',
          `chain_id ${chainId} is not the hash of the seq-1 record (${batch.records[0]!.hash}); ` +
            'chain_id is DERIVED, not chosen',
          {},
          { ...ctx, ...span },
        );
      }
    }

    /* The batch's claimed anchor must be what we already hold. */
    const storedPrev = this.store.hashAt(chainId, batch.from_seq - 1);
    if (storedPrev === undefined) {
      // from_seq <= next_seq, so from_seq - 1 is always held. Defensive only.
      return fail(
        409,
        'chain_gap',
        `this receiver does not hold seq ${batch.from_seq - 1}`,
        { cursor: this.cursorFor(chainId, ctx.key) },
        { ...ctx, ...span },
      );
    }
    if (storedPrev !== batch.base_hash) {
      return this.#fork(
        chainId,
        batch,
        at,
        `base_hash ${batch.base_hash} disagrees with this receiver's hash ${storedPrev} at seq ${batch.from_seq - 1}`,
        batch.from_seq - 1,
        storedPrev,
        batch.base_hash,
        fail,
        ctx,
      );
    }

    /* Overlap is legal and expected (a stale sender cursor). It must be
     * IDENTICAL, though — a different hash at a seq we hold is a rewritten
     * history, and that is an incident, not a retry. */
    const overlapEnd = Math.min(batch.to_seq, nextSeq - 1);
    for (let seq = batch.from_seq; seq <= overlapEnd; seq++) {
      const offered = batch.records[seq - batch.from_seq]!;
      const held = this.store.hashAt(chainId, seq)!;
      if (held !== offered.hash) {
        return this.#fork(
          chainId,
          batch,
          at,
          `seq ${seq} is already stored with hash ${held}, but this batch offers ${offered.hash} — history was rewritten`,
          seq,
          held,
          offered.hash,
          fail,
          ctx,
        );
      }
    }

    /* Every signature must name the hash WE recompute at that seq, never the
     * one we were handed. A receiver that skips this stores whatever it was
     * told. Signatures for seqs we cannot place are ignored, not stored. */
    const batchHashes = new Map<number, string>();
    for (const record of batch.records) batchHashes.set(record.seq, record.hash);
    const storable: HeadSignature[] = [];
    for (const sig of batch.signatures as HeadSignature[]) {
      const known = batchHashes.get(sig.seq) ?? this.store.hashAt(chainId, sig.seq);
      if (known === undefined) continue;
      if (known !== sig.chain_hash) {
        if (batchHashes.has(sig.seq)) {
          return fail(
            400,
            'bad_request',
            `signature for seq ${sig.seq} attests hash ${sig.chain_hash}, but this batch recomputes to ${known}`,
            {},
            { ...ctx, ...span },
          );
        }
        return this.#fork(
          chainId,
          batch,
          at,
          `signature for seq ${sig.seq} attests hash ${sig.chain_hash}, but this receiver holds ${known}`,
          sig.seq,
          known,
          sig.chain_hash,
          fail,
          ctx,
        );
      }
      if (!ed25519Verify(sig.public_key, signedPayload(sig.seq, sig.chain_hash), sig.signature)) {
        return fail(
          400,
          'bad_request',
          `signature for seq ${sig.seq} does not verify against ${sig.public_key}`,
          {},
          { ...ctx, ...span },
        );
      }
      storable.push(sig);
    }

    /* The signed head: the anti-withholding device, and a fork detector in
     * its own right when it names a seq we already hold. */
    const headError = this.#checkHead(chainId, batch.head, ctx.key, batchHashes);
    if (headError !== undefined) {
      if (headError.fork) {
        return this.#fork(chainId, batch, at, headError.detail, headError.atSeq, headError.stored, headError.offered, fail, ctx);
      }
      return fail(400, 'bad_request', headError.detail, {}, { ...ctx, ...span });
    }

    /* Commit the suffix only — the overlap is already ours. fsync happens
     * inside commitRecords, before this function returns 202. */
    const suffix = batch.records.filter((r) => r.seq >= nextSeq);
    this.store.commitRecords(chainId, suffix, at);
    this.store.commitSignatures(chainId, storable, at);
    this.store.recordHead(chainId, batch.head, at);
    this.store.touch(chainId, at, batch.sender);
    return { status: 202, body: this.cursorFor(chainId, ctx.key) };
  }

  /* ------------------------------- head ------------------------------ */

  #checkHead(
    chainId: string,
    head: SinkHead,
    key: string,
    batchHashes: Map<number, string>,
  ): HeadProblem | undefined {
    const shape = signatureShapeError(head.signature);
    if (shape !== undefined) {
      return { fork: false, detail: `head.signature: ${shape}`, atSeq: head.seq, stored: null, offered: null };
    }
    const sig = head.signature;
    if (sig.public_key !== key) {
      return {
        fork: false,
        detail: `head.signature is by key ${sig.public_key}, not ${HEADERS.KEY}`,
        atSeq: head.seq,
        stored: null,
        offered: null,
      };
    }
    if (sig.seq !== head.seq || sig.chain_hash !== head.hash) {
      return {
        fork: false,
        detail: `head.signature covers seq ${sig.seq} / ${sig.chain_hash}, not the declared head ${head.seq} / ${head.hash}`,
        atSeq: head.seq,
        stored: null,
        offered: null,
      };
    }
    if (!ed25519Verify(key, signedPayload(head.seq, head.hash), sig.signature)) {
      return {
        fork: false,
        detail: 'head.signature does not verify — the signed head is what makes withholding measurable, so it is not optional',
        atSeq: head.seq,
        stored: null,
        offered: null,
      };
    }
    // The sender's own signature naming a hash we already hold at that seq,
    // and disagreeing with it, is a fork stated in the sender's own key.
    const known = batchHashes.get(head.seq) ?? this.store.hashAt(chainId, head.seq);
    if (known !== undefined && known !== head.hash) {
      return {
        fork: true,
        detail: `the signed head claims hash ${head.hash} at seq ${head.seq}, but this receiver holds ${known}`,
        atSeq: head.seq,
        stored: known,
        offered: head.hash,
      };
    }
    return undefined;
  }

  /* ------------------------------- fork ------------------------------ */

  #fork(
    chainId: string,
    batch: RecordsBatch,
    at: string,
    detail: string,
    atSeq: number,
    stored: string | null,
    offered: string | null,
    fail: FailFn,
    ctx: { key: string; tenant: string },
  ): Reply {
    this.store.recordFork(chainId, {
      received_at: at,
      reason: detail,
      at_seq: atSeq,
      stored_hash: stored,
      offered_hash: offered,
      offered: batch,
    });
    this.store.raiseAlert({
      at,
      kind: 'chain_fork',
      chain_id: chainId,
      key: ctx.key,
      tenant: ctx.tenant,
      detail,
    });
    return fail(
      409,
      'chain_fork',
      detail,
      { cursor: this.cursorFor(chainId, ctx.key) },
      { ...ctx, from: batch.from_seq, to: batch.to_seq },
    );
  }

  /* ---------------------------- absence ------------------------------ */

  /**
   * Alerting on absence is a CONTRACT OBLIGATION, not a feature: killing the
   * shipper, blackholing DNS and revoking a token all look identical at the
   * receiver — nothing arrives. A receiver that does not alert on silence
   * has not implemented this design.
   */
  scanForSilence(): Alert[] {
    const now = this.#now().getTime();
    const threshold = this.heartbeatIntervalS * this.silenceAfterIntervals * 1000;
    const raised: Alert[] = [];
    for (const state of this.store.listChains()) {
      if (state.status === 'forked') continue;
      if ((state.silence_alerted_at ?? null) !== null) continue;
      const last = Date.parse(state.last_seen_at);
      if (!Number.isFinite(last) || now - last < threshold) continue;
      const behind = Math.max(0, state.claimed_head_seq - (state.next_seq - 1));
      const alert: Alert = {
        at: new Date(now).toISOString(),
        kind: 'silent_chain',
        chain_id: state.chain_id,
        key: state.key,
        tenant: state.tenant,
        detail:
          `no traffic for ${Math.round((now - last) / 1000)}s (threshold ${threshold / 1000}s). ` +
          `Last signed head was seq ${state.claimed_head_seq}; ${behind} record(s) were already ` +
          'claimed but not delivered when it went quiet.',
      };
      this.store.raiseAlert(alert);
      this.store.markSilenceAlerted(state.chain_id, alert.at);
      raised.push(alert);
    }
    return raised;
  }
}

type FailFn = (
  status: number,
  error: SinkErrorCode,
  detail: string,
  extra?: Partial<SinkErrorBody>,
  known?: { key?: string; tenant?: string; from?: number; to?: number },
) => Reply;

interface HeadProblem {
  fork: boolean;
  detail: string;
  atSeq: number;
  stored: string | null;
  offered: string | null;
}

function tryParseJson(body: Buffer): unknown {
  try {
    return JSON.parse(body.toString('utf8'));
  } catch {
    return undefined;
  }
}

/**
 * Run the product's own chain verifier over the batch and collapse it to a
 * single error string (or undefined when the batch is sound). This is the
 * SAME function `mcp-recorder verify` runs, called on purpose: a receiver
 * with its own second implementation of the chain rules is a receiver whose
 * verdict can drift from the tool's.
 */
async function verifyBatchChain(
  records: ChainRecord[],
  signatures: HeadSignature[],
  baseHash: string,
  key: string,
): Promise<string | undefined> {
  const result = await verifyRecords(records, signatures, {
    baseHash,
    expectedPublicKeyHex: key,
    // The batch is a SEGMENT: it is not required to carry a signature, and
    // the head signature that matters travels in `head`, checked separately.
    allowUnsigned: true,
  });
  const hard = result.problems.filter((p) => p.warning !== true);
  if (hard.length === 0) return undefined;
  return hard.map((p) => `${p.type} at seq ${p.seq}: ${p.detail}`).join('; ');
}
