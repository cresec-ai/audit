/**
 * The HTTP skin over `Receiver`. node:http / node:https only.
 *
 * INGEST — the whole write surface, and there is no more of it:
 *   POST /v1/chains/{chain_id}/records     the only write
 *   GET  /v1/chains/{chain_id}/cursor      the resume oracle
 *   GET  /v1/health                        unauthenticated liveness, no data
 *
 * OPERATOR (read-only, separate token — see receiver/README.md):
 *   GET  /v1/chains                        what this receiver holds
 *   GET  /v1/chains/{chain_id}             one chain in full, incl. forks
 *   GET  /v1/chains/{chain_id}/export      the replica's signed bundle (zip)
 *   GET  /v1/rejections                    every refusal, newest last
 *   GET  /v1/alerts                        forks, silence, new identities
 *
 * There is deliberately NO DELETE, PUT or PATCH anywhere. That absence is
 * load-bearing: it is what makes "a stolen token cannot delete history" a
 * property of the API surface rather than a promise. Those verbs are
 * answered 405 with an `Allow` header naming only the read/append methods.
 *
 * Body handling follows the contract's order exactly: read under a byte
 * budget -> decompress into a bounded buffer (a zip bomb is rejected before
 * it is a memory event) -> hand the DECOMPRESSED bytes to the receiver,
 * which hashes, checks the signature and only then parses.
 */

import { createServer as createHttpServer } from 'node:http';
import { createServer as createHttpsServer } from 'node:https';
import { gunzip } from 'node:zlib';
import { mkdirSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { Buffer } from 'node:buffer';
import type { IncomingMessage, RequestListener, Server, ServerResponse } from 'node:http';
import { SINK_PROTOCOL_VERSION } from './protocol.js';
import type { SinkErrorBody } from './protocol.js';
import { Receiver } from './ingest.js';
import type { ReceiverOptions } from './ingest.js';
import { matchesOperatorToken, bearer } from './auth.js';
import type { ChainState, ForkEvidence, StoredHead } from './store.js';
import { ReceiverExportError, exportReceivedChain } from './export.js';
import { VERSION } from '../src/version.js';

export interface ServeOptions extends ReceiverOptions {
  /** Default 0 = ephemeral port. */
  port?: number;
  /** Default '127.0.0.1'. Bind 0.0.0.0 only behind a TLS terminator. */
  host?: string;
  /** PEM paths. When both are given the receiver serves https itself. */
  tlsCert?: string;
  tlsKey?: string;
  /** Override the generated operator token (tests). */
  operatorToken?: string;
  /** Run the absence scan on this interval. 0 disables it (tests). */
  silenceScanMs?: number;
}

export interface ServerHandle {
  url: string;
  port: number;
  receiver: Receiver;
  operatorToken: string;
  close(): Promise<void>;
}

/** What an operator sees per chain. Derived, and every field says from what. */
export interface ChainSummary extends ChainState {
  key_acknowledged: boolean;
  /**
   * Sealed records the sender has SIGNED for but not delivered:
   * claimed_head_seq - (next_seq - 1). Attested by the sender's own key, so
   * withholding is a subtraction, not an inference.
   */
  undelivered: number;
  silent_for_s: number;
  silent: boolean;
}

const JSON_HEADERS = {
  'content-type': 'application/json; charset=utf-8',
  'cache-control': 'no-store',
} as const;

function send(res: ServerResponse, status: number, body: unknown): void {
  const text = JSON.stringify(body, null, 2) + '\n';
  res.writeHead(status, { ...JSON_HEADERS, 'content-length': Buffer.byteLength(text) });
  res.end(text);
}

function sendError(res: ServerResponse, status: number, body: SinkErrorBody): void {
  send(res, status, body);
}

/**
 * Read the request body, refusing anything over `limit` bytes without
 * buffering it. Resolves to undefined once it has already answered 413.
 */
function readBody(req: IncomingMessage, res: ServerResponse, limit: number): Promise<Buffer | undefined> {
  return new Promise((resolve) => {
    const chunks: Buffer[] = [];
    let total = 0;
    let done = false;
    const finish = (value: Buffer | undefined): void => {
      if (done) return;
      done = true;
      resolve(value);
    };
    req.on('data', (chunk: Buffer) => {
      if (done) return;
      total += chunk.length;
      if (total > limit) {
        sendError(res, 413, {
          error: 'too_large',
          detail: `request body exceeds ${limit} bytes`,
        });
        req.destroy();
        finish(undefined);
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => finish(Buffer.concat(chunks)));
    req.on('error', () => finish(undefined));
    req.on('aborted', () => finish(undefined));
  });
}

function decompress(
  encoding: string | undefined,
  body: Buffer,
  maxOutputLength: number,
): Promise<{ bytes: Buffer } | { error: string; status: number; code: 'bad_request' | 'too_large' }> {
  const value = (encoding ?? '').trim().toLowerCase();
  if (value === '' || value === 'identity') return Promise.resolve({ bytes: body });
  if (value !== 'gzip') {
    return Promise.resolve({
      status: 400,
      code: 'bad_request' as const,
      error: `unsupported Content-Encoding '${value}'; this receiver accepts identity and gzip`,
    });
  }
  return new Promise((resolve) => {
    // maxOutputLength bounds the INFLATED size, so a zip bomb is refused
    // before it is allocated.
    gunzip(body, { maxOutputLength }, (err, out) => {
      if (err !== null) {
        const tooBig = (err as NodeJS.ErrnoException).code === 'ERR_BUFFER_TOO_LARGE';
        resolve({
          status: tooBig ? 413 : 400,
          code: tooBig ? ('too_large' as const) : ('bad_request' as const),
          error: tooBig
            ? `gzip body inflates past the ${maxOutputLength}-byte budget`
            : `gzip body could not be decompressed: ${err.message}`,
        });
        return;
      }
      resolve({ bytes: out });
    });
  });
}

/**
 * Percent-decode a path segment without letting a malformed escape become a
 * 500. A bad chain id is a client error, and the caller should be told which.
 */
function decodeSegment(value: string): string | undefined {
  try {
    return decodeURIComponent(value);
  } catch {
    return undefined;
  }
}

function headerMap(req: IncomingMessage): Record<string, string | undefined> {
  const out: Record<string, string | undefined> = {};
  for (const [name, value] of Object.entries(req.headers)) {
    out[name] = Array.isArray(value) ? value.join(',') : value;
  }
  return out;
}

export function summarize(
  state: ChainState,
  acknowledged: boolean,
  nowMs: number,
  silenceThresholdMs: number,
): ChainSummary {
  const last = Date.parse(state.last_seen_at);
  const silentForS = Number.isFinite(last) ? Math.max(0, Math.round((nowMs - last) / 1000)) : 0;
  return {
    ...state,
    key_acknowledged: acknowledged,
    undelivered: Math.max(0, state.claimed_head_seq - (state.next_seq - 1)),
    silent_for_s: silentForS,
    silent: Number.isFinite(last) && nowMs - last >= silenceThresholdMs,
  };
}

export async function serveReceiver(opts: ServeOptions): Promise<ServerHandle> {
  const receiver = new Receiver(opts);
  const operatorToken = opts.operatorToken ?? receiver.store.operatorToken();
  const silenceThresholdMs =
    receiver.heartbeatIntervalS * receiver.silenceAfterIntervals * 1000;

  const requireOperator = (req: IncomingMessage, res: ServerResponse): boolean => {
    if (matchesOperatorToken(operatorToken, bearer(req.headers.authorization))) return true;
    sendError(res, 401, {
      error: 'unauthorized',
      detail: 'operator endpoints need the operator token (see <data-dir>/operator-token.txt)',
    });
    return false;
  };

  const handler: RequestListener = (req, res) => {
    void (async () => {
      const method = req.method ?? 'GET';
      const url = new URL(req.url ?? '/', 'http://receiver.invalid');
      const path = url.pathname.replace(/\/+$/, '') || '/';

      if (method === 'DELETE' || method === 'PUT' || method === 'PATCH') {
        // Stated explicitly rather than falling through to a generic 404:
        // "history cannot be mutated through this API" is a property worth
        // being visible in the response.
        res.writeHead(405, { ...JSON_HEADERS, allow: 'GET, HEAD, POST' });
        res.end(
          JSON.stringify({
            error: 'bad_request',
            detail:
              'this API has no DELETE, PUT or PATCH. Stored records are never mutated or removed ' +
              'through it; retention is an operator-side policy, not a client-reachable operation.',
          }) + '\n',
        );
        return;
      }

      if (path === '/v1/health' && (method === 'GET' || method === 'HEAD')) {
        send(res, 200, {
          status: 'ok',
          protocol: SINK_PROTOCOL_VERSION,
          time: new Date().toISOString(),
        });
        return;
      }

      const recordsMatch = /^\/v1\/chains\/([^/]+)\/records$/.exec(path);
      if (recordsMatch !== null) {
        if (method !== 'POST') {
          res.writeHead(405, { ...JSON_HEADERS, allow: 'POST' });
          res.end(JSON.stringify({ error: 'bad_request', detail: 'use POST' }) + '\n');
          return;
        }
        const pathChainId = decodeSegment(recordsMatch[1]!);
        if (pathChainId === undefined) {
          sendError(res, 400, { error: 'bad_request', detail: 'malformed chain_id in the path' });
          return;
        }
        const raw = await readBody(req, res, receiver.maxSingleRecordBytes);
        if (raw === undefined) return; // already answered, or the peer went away
        const decoded = await decompress(
          req.headers['content-encoding'],
          raw,
          receiver.maxSingleRecordBytes,
        );
        if (!('bytes' in decoded)) {
          sendError(res, decoded.status, {
            error: decoded.code,
            detail: decoded.error,
            ...(decoded.code === 'too_large'
              ? { max_records: receiver.maxRecords, max_bytes: receiver.maxBytes }
              : {}),
          });
          return;
        }
        const reply = await receiver.ingest({
          chainIdFromPath: pathChainId,
          headers: headerMap(req),
          body: decoded.bytes,
          remote: req.socket.remoteAddress ?? null,
        });
        send(res, reply.status, reply.body);
        return;
      }

      const cursorMatch = /^\/v1\/chains\/([^/]+)\/cursor$/.exec(path);
      if (cursorMatch !== null) {
        if (method !== 'GET' && method !== 'HEAD') {
          res.writeHead(405, { ...JSON_HEADERS, allow: 'GET, HEAD' });
          res.end(JSON.stringify({ error: 'bad_request', detail: 'use GET' }) + '\n');
          return;
        }
        const reply = receiver.readCursor({
          chainIdFromPath: decodeSegment(cursorMatch[1]!) ?? '',
          headers: headerMap(req),
          remote: req.socket.remoteAddress ?? null,
        });
        send(res, reply.status, reply.body);
        return;
      }

      /* ---------------------- operator, read only ---------------------- */

      if (path === '/v1/chains' && (method === 'GET' || method === 'HEAD')) {
        if (!requireOperator(req, res)) return;
        const now = Date.now();
        send(res, 200, {
          chains: receiver.store.listChains().map((state) =>
            summarize(
              state,
              receiver.store.enrolledKey(state.tenant, state.key)?.acknowledged ?? false,
              now,
              silenceThresholdMs,
            ),
          ),
        });
        return;
      }

      const chainMatch = /^\/v1\/chains\/([0-9a-f]{64})$/.exec(path);
      if (chainMatch !== null && (method === 'GET' || method === 'HEAD')) {
        if (!requireOperator(req, res)) return;
        const chainId = chainMatch[1]!;
        const state = receiver.store.chain(chainId);
        if (state === undefined) {
          send(res, 404, { error: 'bad_request', detail: `no chain ${chainId}` });
          return;
        }
        const heads: StoredHead[] = receiver.store.heads(chainId);
        const forks: ForkEvidence[] = receiver.store.forks(chainId);
        send(res, 200, {
          chain: summarize(
            state,
            receiver.store.enrolledKey(state.tenant, state.key)?.acknowledged ?? false,
            Date.now(),
            silenceThresholdMs,
          ),
          signatures: receiver.store.signatures(chainId),
          recent_heads: heads.slice(Math.max(0, heads.length - 20)),
          forks,
        });
        return;
      }

      const exportMatch = /^\/v1\/chains\/([^/]+)\/export$/.exec(path);
      if (exportMatch !== null) {
        // The replica's bundle over HTTP, so a remote auditor can pull a
        // signed replica without filesystem access to this host. Same
        // bundle `receiver export --chain` writes (export.ts): truncated to
        // attested_seq, carrying the stored verified signature, the
        // product's own verify.cjs inside. Read-only, operator token.
        if (method !== 'GET') {
          res.writeHead(405, { ...JSON_HEADERS, allow: 'GET' });
          res.end(JSON.stringify({ error: 'bad_request', detail: 'use GET' }) + '\n');
          return;
        }
        if (!requireOperator(req, res)) return;
        const chainId = decodeSegment(exportMatch[1]!);
        if (chainId === undefined || receiver.store.chain(chainId) === undefined) {
          sendError(res, 404, { error: 'bad_request', detail: 'no such chain on this receiver' });
          return;
        }
        const scratch = join(tmpdir(), `mcpr-receiver-export-${randomUUID()}`);
        const zipPath = join(scratch, `${chainId}.zip`);
        try {
          mkdirSync(scratch, { recursive: true, mode: 0o700 });
          const result = await exportReceivedChain({
            store: receiver.store,
            chainId,
            zipPath,
            toolVersion: `mcp-recorder-receiver/${VERSION}`,
          });
          const zip = readFileSync(zipPath);
          res.writeHead(200, {
            'content-type': 'application/zip',
            'content-length': zip.length,
            'content-disposition': `attachment; filename="mcp-recorder-replica-${chainId.slice(0, 16)}.zip"`,
            'x-mcpr-attested-seq': String(result.manifest.range.to_seq),
            'x-mcpr-unattested-records': String(result.unattested_records),
          });
          res.end(zip);
        } catch (err) {
          if (err instanceof ReceiverExportError) {
            sendError(res, 409, { error: 'bad_request', detail: err.message });
            return;
          }
          throw err;
        } finally {
          rmSync(scratch, { recursive: true, force: true });
        }
        return;
      }

      if (path === '/v1/rejections' && (method === 'GET' || method === 'HEAD')) {
        if (!requireOperator(req, res)) return;
        const limit = Number(url.searchParams.get('limit') ?? '100');
        send(res, 200, {
          rejections: receiver.store.rejections(Number.isFinite(limit) ? limit : 100),
        });
        return;
      }

      if (path === '/v1/alerts' && (method === 'GET' || method === 'HEAD')) {
        if (!requireOperator(req, res)) return;
        const limit = Number(url.searchParams.get('limit') ?? '100');
        send(res, 200, { alerts: receiver.store.alerts(Number.isFinite(limit) ? limit : 100) });
        return;
      }

      send(res, 404, { error: 'bad_request', detail: `no route ${method} ${path}` });
    })().catch((err: unknown) => {
      process.stderr.write(
        `[mcp-receiver] unhandled error: ${err instanceof Error ? err.stack : String(err)}\n`,
      );
      if (!res.headersSent) {
        sendError(res, 500, { error: 'internal', detail: 'receiver error; the batch was NOT stored' });
      } else {
        res.end();
      }
    });
  };

  const server: Server =
    opts.tlsCert !== undefined && opts.tlsKey !== undefined
      ? createHttpsServer(
          { cert: readFileSync(opts.tlsCert), key: readFileSync(opts.tlsKey) },
          handler,
        )
      : createHttpServer(handler);

  const host = opts.host ?? '127.0.0.1';
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(opts.port ?? 0, host, () => {
      server.removeListener('error', reject);
      resolve();
    });
  });

  const address = server.address();
  const port = typeof address === 'object' && address !== null ? address.port : (opts.port ?? 0);
  const scheme = opts.tlsCert !== undefined && opts.tlsKey !== undefined ? 'https' : 'http';

  const scanMs = opts.silenceScanMs ?? receiver.heartbeatIntervalS * 1000;
  const timer = scanMs > 0 ? setInterval(() => receiver.scanForSilence(), scanMs) : undefined;
  timer?.unref();

  return {
    url: `${scheme}://${host}:${port}`,
    port,
    receiver,
    operatorToken,
    close: () =>
      new Promise<void>((resolve, reject) => {
        if (timer !== undefined) clearInterval(timer);
        server.close((err) => (err !== undefined && err !== null ? reject(err) : resolve()));
        server.closeAllConnections();
      }),
  };
}
