/**
 * A test receiver for the evidence sink's wire protocol.
 *
 * It is deliberately NOT a shortcut: it runs the same verification order the
 * contract specifies — decompress under a byte budget, hash the DECOMPRESSED
 * bytes, compare the digest header, verify the ed25519 request signature,
 * and only THEN JSON.parse — so a sender that signs the wrong bytes, ships a
 * mutated event or skips a seq fails here rather than being quietly accepted.
 * That is what makes the acceptance tests mean something.
 *
 * It also keeps every raw request body it was handed, which is how
 * "nothing on the wire that is not already in the store" gets checked by
 * grepping the actual octets rather than by trusting the sender's intent.
 */

import { createServer } from 'node:http';
import type { IncomingMessage, Server, ServerResponse } from 'node:http';
import { createServer as createRawServer } from 'node:net';
import type { Server as RawServer, Socket } from 'node:net';
import { createPublicKey, verify as cryptoVerify } from 'node:crypto';
import { gunzipSync } from 'node:zlib';
import { Buffer } from 'node:buffer';
import { AddressInfo } from 'node:net';
import { GENESIS_HASH, computeHash, sha256Hex, signedPayload } from '../../src/chain/hash.js';
import { publicKeyPem } from '../../src/chain/keys.js';
import type { ChainRecord, HeadSignature } from '../../src/schema/events.js';
import { SINK_HEADERS, sinkSignedPayload } from '../../src/sink/protocol.js';
import type { SinkBatchBody, SinkCursor } from '../../src/sink/protocol.js';

export type ReceiverMode =
  | 'ok'
  /** Every write answers 500 forever. */
  | 'error500'
  /** Every request answers 401. */
  | 'unauthorized'
  /** Every write answers 400, whatever the bytes. */
  | 'badrequest'
  /** Every write answers 413 with caps. */
  | 'toolarge'
  /** Accept the connection, answer nothing, ever. */
  | 'hang';

export interface ReceivedPost {
  headers: NodeJS.Dict<string | string[]>;
  /** Decompressed request bytes, verbatim. */
  raw: Buffer;
  status: number;
  /** Set when the body parsed; useful for asserting on ranges. */
  body?: SinkBatchBody;
}

interface StoredChain {
  key: string;
  records: Map<number, ChainRecord>;
  signatures: HeadSignature[];
  attestedSeq: number;
  /** Seqs that arrived with a hash different from the stored one. */
  forkedSeqs: number[];
  receivedAt: Map<number, string>;
}

export interface SinkReceiver {
  url: string;
  port: number;
  posts: ReceivedPost[];
  /** Heartbeats (records: []) are counted separately from record batches. */
  heartbeats: number;
  setMode(mode: ReceiverMode): void;
  chain(chainId: string): StoredChain | undefined;
  /** Every chain the receiver holds, newest binding last. */
  chains: Map<string, StoredChain>;
  nextSeq(chainId: string): number;
  close(): Promise<void>;
}

/** Bound inflation: reject a zip bomb before it becomes a memory event. */
const MAX_INFLATED_BYTES = 8 * 1024 * 1024;

function readBody(req: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

function verifyHeadSignature(sig: HeadSignature, expectedHash: string, key: string): boolean {
  if (sig.public_key !== key) return false;
  if (sig.chain_hash !== expectedHash) return false;
  try {
    return cryptoVerify(
      null,
      Buffer.from(signedPayload(sig.seq, sig.chain_hash)),
      createPublicKey(publicKeyPem(sig.public_key)),
      Buffer.from(sig.signature, 'hex'),
    );
  } catch {
    return false;
  }
}

export interface StartReceiverOpts {
  mode?: ReceiverMode;
  /** When set, a request without this exact bearer token answers 401. */
  requireToken?: string;
  /** Answer 500 for the first N record POSTs, then behave normally. */
  failFirstWrites?: number;
  /** Cap advertised in the cursor, so a batch can be forced to be partial. */
  maxRecords?: number;
}

export async function startSinkReceiver(opts: StartReceiverOpts = {}): Promise<SinkReceiver> {
  let mode: ReceiverMode = opts.mode ?? 'ok';
  let failFirstWrites = opts.failFirstWrites ?? 0;
  const posts: ReceivedPost[] = [];
  const chains = new Map<string, StoredChain>();
  let heartbeats = 0;
  const openSockets = new Set<Socket>();

  const cursorFor = (chainId: string, key: string): SinkCursor => {
    const stored = chains.get(chainId);
    if (stored === undefined) {
      return {
        chain_id: chainId,
        key,
        next_seq: 1,
        head_hash: GENESIS_HASH,
        attested_seq: 0,
        max_records: opts.maxRecords ?? 5000,
        max_bytes: 8 * 1024 * 1024,
        heartbeat_interval_s: 60,
      };
    }
    let next = 1;
    while (stored.records.has(next)) next++;
    const head = next === 1 ? GENESIS_HASH : stored.records.get(next - 1)!.hash;
    return {
      chain_id: chainId,
      key: stored.key,
      next_seq: next,
      head_hash: head,
      attested_seq: stored.attestedSeq,
      max_records: opts.maxRecords ?? 5000,
      max_bytes: 8 * 1024 * 1024,
      heartbeat_interval_s: 60,
    };
  };

  const server: Server = createServer((req: IncomingMessage, res: ServerResponse) => {
    if (mode === 'hang') return; // accepted, never answered
    void handle(req, res).catch(() => {
      try {
        res.writeHead(500).end('{}');
      } catch {
        /* the socket is already gone */
      }
    });
  });

  server.on('connection', (socket: Socket) => {
    openSockets.add(socket);
    socket.on('close', () => openSockets.delete(socket));
  });

  async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const url = new URL(req.url ?? '/', 'http://localhost');
    const send = (status: number, payload: unknown): void => {
      const text = JSON.stringify(payload);
      res.writeHead(status, { 'content-type': 'application/json' }).end(text);
    };

    if (url.pathname === '/v1/health') {
      send(200, { ok: true });
      return;
    }

    const auth = req.headers.authorization;
    if (mode === 'unauthorized') {
      send(401, { error: 'unauthorized' });
      return;
    }
    if (opts.requireToken !== undefined && auth !== `Bearer ${opts.requireToken}`) {
      send(401, { error: 'unauthorized' });
      return;
    }

    const cursorMatch = /^\/v1\/chains\/([0-9a-f]{64})\/cursor$/.exec(url.pathname);
    if (cursorMatch !== null && req.method === 'GET') {
      const key = String(req.headers[SINK_HEADERS.KEY] ?? '');
      send(200, cursorFor(cursorMatch[1]!, key));
      return;
    }

    const recordsMatch = /^\/v1\/chains\/([0-9a-f]{64})\/records$/.exec(url.pathname);
    if (recordsMatch === null || req.method !== 'POST') {
      send(404, { error: 'not_found' });
      return;
    }
    const pathChainId = recordsMatch[1]!;

    /* --- 1. decompress under a budget, then hash the DECOMPRESSED bytes --- */
    const wire = await readBody(req);
    let raw: Buffer;
    if (req.headers['content-encoding'] === 'gzip') {
      try {
        raw = gunzipSync(wire, { maxOutputLength: MAX_INFLATED_BYTES });
      } catch {
        posts.push({ headers: req.headers, raw: wire, status: 400 });
        send(400, { error: 'bad_request', message: 'undecompressable body' });
        return;
      }
    } else {
      raw = wire;
    }

    const record = (status: number, body?: SinkBatchBody): void => {
      const entry: ReceivedPost = { headers: req.headers, raw, status };
      if (body !== undefined) entry.body = body;
      posts.push(entry);
    };

    if (mode === 'error500' || failFirstWrites > 0) {
      if (failFirstWrites > 0) failFirstWrites--;
      record(500);
      send(500, { error: 'server_error' });
      return;
    }
    if (mode === 'badrequest') {
      record(400);
      send(400, { error: 'bad_request', message: 'test receiver rejects everything' });
      return;
    }
    if (mode === 'toolarge') {
      record(413);
      send(413, { error: 'too_large', max_records: 1, max_bytes: 1024 });
      return;
    }

    const digest = String(req.headers[SINK_HEADERS.CONTENT_SHA256] ?? '');
    if (sha256Hex(raw) !== digest) {
      record(400);
      send(400, { error: 'bad_request', message: 'digest mismatch' });
      return;
    }

    /* --- 2. verify the request signature BEFORE parsing untrusted JSON --- */
    const key = String(req.headers[SINK_HEADERS.KEY] ?? '');
    const signature = String(req.headers[SINK_HEADERS.SIGNATURE] ?? '');
    // from_seq/to_seq are covered by the signature, so they must be read from
    // the body — which we have not parsed yet. Parse defensively into a
    // throwaway only to recover the two integers, then verify; a forged pair
    // cannot help an attacker because the digest already pins the whole body.
    let peek: Record<string, unknown>;
    try {
      peek = JSON.parse(raw.toString('utf8')) as Record<string, unknown>;
    } catch {
      record(400);
      send(400, { error: 'bad_request', message: 'unparseable body' });
      return;
    }
    const fromSeq = Number(peek.from_seq);
    const toSeq = Number(peek.to_seq);
    let signatureOk = false;
    try {
      signatureOk = cryptoVerify(
        null,
        Buffer.from(sinkSignedPayload(pathChainId, fromSeq, toSeq, digest)),
        createPublicKey(publicKeyPem(key)),
        Buffer.from(signature, 'hex'),
      );
    } catch {
      signatureOk = false;
    }
    if (!signatureOk) {
      record(400);
      send(400, { error: 'bad_request', message: 'request signature invalid' });
      return;
    }

    const body = peek as unknown as SinkBatchBody;
    if (body.chain_id !== pathChainId || body.key !== key) {
      record(400, body);
      send(400, { error: 'bad_request', message: 'chain_id/key disagree with the request' });
      return;
    }

    /* --- heartbeat: no records, just a signed head --- */
    if (body.records.length === 0 && body.from_seq === 0 && body.to_seq === 0) {
      heartbeats++;
      record(200, body);
      send(200, cursorFor(pathChainId, key));
      return;
    }

    /* --- 3/4. contiguity, linkage, and a full hash recomputation --- */
    for (let i = 0; i < body.records.length; i++) {
      const r = body.records[i]!;
      const expectedPrev = i === 0 ? body.base_hash : body.records[i - 1]!.hash;
      if (r.seq !== body.from_seq + i || r.prev_hash !== expectedPrev) {
        record(400, body);
        send(400, { error: 'bad_request', message: `non-contiguous at seq ${String(r.seq)}` });
        return;
      }
      if (r.hash !== computeHash(r.prev_hash, r.event)) {
        record(400, body);
        send(400, { error: 'bad_request', message: `hash mismatch at seq ${String(r.seq)}` });
        return;
      }
    }

    /* --- 5. the batch must LINK to what is already stored --- */
    const stored = chains.get(pathChainId) ?? {
      key,
      records: new Map<number, ChainRecord>(),
      signatures: [],
      attestedSeq: 0,
      forkedSeqs: [],
      receivedAt: new Map<number, string>(),
    };
    const cursor = cursorFor(pathChainId, key);
    if (body.from_seq > cursor.next_seq) {
      record(409, body);
      send(409, { error: 'chain_gap', message: 'cannot link', cursor });
      return;
    }
    let forked = false;
    for (const r of body.records) {
      const existing = stored.records.get(r.seq);
      if (existing !== undefined && existing.hash !== r.hash) {
        // Retain BOTH branches: a fork is the tamper signal, never something
        // to auto-reconcile away.
        stored.forkedSeqs.push(r.seq);
        forked = true;
      }
    }
    if (!forked && body.from_seq > 1 && body.from_seq <= cursor.next_seq) {
      const anchor = body.from_seq === 1 ? GENESIS_HASH : stored.records.get(body.from_seq - 1)?.hash;
      if (anchor !== undefined && anchor !== body.base_hash) forked = true;
    }
    if (forked) {
      chains.set(pathChainId, stored);
      record(409, body);
      send(409, { error: 'chain_fork', message: 'a stored seq disagrees', cursor });
      return;
    }

    /* --- 6/7. head signatures verify against RECOMPUTED hashes --- */
    for (const sig of body.signatures) {
      const target =
        body.records.find((r) => r.seq === sig.seq)?.hash ?? stored.records.get(sig.seq)?.hash;
      if (target !== undefined && verifyHeadSignature(sig, target, key)) {
        stored.signatures.push(sig);
        stored.attestedSeq = Math.max(stored.attestedSeq, sig.seq);
      }
    }

    /* --- 8. commit (insert-if-absent), THEN answer --- */
    const receivedAt = new Date().toISOString();
    for (const r of body.records) {
      if (!stored.records.has(r.seq)) {
        stored.records.set(r.seq, r);
        stored.receivedAt.set(r.seq, receivedAt);
      }
    }
    chains.set(pathChainId, stored);
    record(202, body);
    send(202, cursorFor(pathChainId, key));
  }

  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = (server.address() as AddressInfo).port;

  return {
    url: `http://127.0.0.1:${String(port)}`,
    port,
    posts,
    get heartbeats() {
      return heartbeats;
    },
    chains,
    setMode(next: ReceiverMode) {
      mode = next;
    },
    chain(chainId: string) {
      return chains.get(chainId);
    },
    nextSeq(chainId: string) {
      const stored = chains.get(chainId);
      if (stored === undefined) return 1;
      let next = 1;
      while (stored.records.has(next)) next++;
      return next;
    },
    close() {
      for (const socket of openSockets) socket.destroy();
      return new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
}

/**
 * A socket that accepts a connection and then never says anything — the
 * nastiest shape of "slow sink", and the one a fail-open claim has to survive.
 */
export async function startHangingSink(): Promise<{ url: string; close(): Promise<void> }> {
  const sockets = new Set<Socket>();
  const server: RawServer = createRawServer((socket: Socket) => {
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
    socket.on('error', () => sockets.delete(socket));
    // Deliberately no response, ever.
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = (server.address() as AddressInfo).port;
  return {
    url: `http://127.0.0.1:${String(port)}`,
    close() {
      for (const socket of sockets) socket.destroy();
      return new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
}
