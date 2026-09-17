/**
 * Receiver-side evidence bundle.
 *
 * THE CONSTRAINT: a receiver holds no private key, so it cannot re-sign
 * anything. `exportBundle()` on the recording host signs a FRESH head over
 * the last record in the range; a receiver doing that has nothing to sign
 * with. So the replica's bundle must instead:
 *
 *   - truncate the range to `attested_seq`, the highest seq covered by a
 *     signature this receiver itself verified, and
 *   - use THAT stored signature as `manifest.signature`.
 *
 * Get either half wrong and `verify --bundle` reports
 * `bundle_manifest_mismatch`: the manifest would declare a head no signature
 * covers. Records past `attested_seq` are held and readable, they are simply
 * not in the bundle, because nothing attests them yet.
 *
 * The bundle is produced by the PRODUCT's own `exportBundle()`, driven
 * through two small read-only adapters. That keeps the manifest shape, the
 * README and the shipped `verify.cjs` identical to a recorder-side bundle —
 * a stranger runs `node verify.cjs` and cannot tell (or need to care) which
 * side produced it.
 */

import { GENESIS_HASH } from '../src/chain/hash.js';
import { exportBundle } from '../src/export/bundle.js';
import type { AnyEvent, ChainRecord, HeadSignature } from '../src/schema/events.js';
import type {
  BundleManifest,
  ChainHead,
  EvidenceStore,
  IterateOpts,
  SignerLike,
} from '../src/types.js';
import { ReceiverStore } from './store.js';

export class ReceiverExportError extends Error {}

/** A read-only EvidenceStore over records this receiver already verified. */
function replicaStore(records: ChainRecord[], signatures: HeadSignature[], path: string): EvidenceStore {
  const readOnly = (): never => {
    throw new ReceiverExportError('the receiver holds a replica; it is not writable');
  };
  const last = records[records.length - 1];
  return {
    backend: 'jsonl',
    path,
    head: (): ChainHead =>
      last === undefined ? { seq: 0, hash: GENESIS_HASH } : { seq: last.seq, hash: last.hash },
    append: readOnly,
    appendEvents: readOnly,
    addSignature: readOnly,
    latestSignature: () => signatures[signatures.length - 1] ?? null,
    signatures: () => signatures,
    iterate: (opts: IterateOpts = {}): Iterable<ChainRecord> =>
      records.filter(
        (r) =>
          r.seq >= (opts.fromSeq ?? 1) &&
          r.seq <= (opts.toSeq ?? Number.MAX_SAFE_INTEGER) &&
          (opts.sessionId === undefined || sessionIdOf(r.event) === opts.sessionId),
      ),
    count: () => records.length,
    sessions: () => [],
    close: () => {},
  };
}

function sessionIdOf(event: AnyEvent): string | undefined {
  return (event as { session_id?: string }).session_id;
}

/**
 * A "signer" that signs nothing: it hands back the one stored signature, and
 * throws if asked to attest anything else. That throw is the safety net — it
 * is what stops a future refactor from silently producing a manifest whose
 * declared head no signature covers.
 */
function storedSignatureSigner(publicKeyHex: string, signature: HeadSignature): SignerLike {
  return {
    publicKeyHex,
    sign: (seq: number, chainHash: string): Promise<HeadSignature> => {
      if (seq !== signature.seq || chainHash !== signature.chain_hash) {
        return Promise.reject(
          new ReceiverExportError(
            `the receiver cannot sign: asked to attest seq ${seq} / ${chainHash}, but the only ` +
              `verified signature it holds covers seq ${signature.seq} / ${signature.chain_hash}`,
          ),
        );
      }
      return Promise.resolve(signature);
    },
  };
}

export interface ReceiverExportOpts {
  store: ReceiverStore;
  chainId: string;
  dirPath?: string;
  zipPath?: string;
  toolVersion: string;
}

export interface ReceiverExportResult {
  manifest: BundleManifest;
  /** Records held but NOT in the bundle, because nothing attests them yet. */
  unattested_records: number;
  /** What the sender's newest signed head claimed, whatever was delivered. */
  claimed_head_seq: number;
}

export async function exportReceivedChain(
  opts: ReceiverExportOpts,
): Promise<ReceiverExportResult> {
  const state = opts.store.chain(opts.chainId);
  if (state === undefined) {
    throw new ReceiverExportError(`no chain ${opts.chainId} on this receiver`);
  }
  if (state.attested_seq === 0) {
    throw new ReceiverExportError(
      `chain ${opts.chainId} holds ${state.records_held} record(s) but no verified signature — ` +
        'there is nothing a bundle could attest. The records are readable in ' +
        'chains/<chain_id>/records.jsonl regardless.',
    );
  }

  const stored = opts.store.signatures(opts.chainId);
  const attesting = stored
    .map((s) => s.signature)
    .filter((s) => s.seq === state.attested_seq)
    .at(-1);
  if (attesting === undefined) {
    throw new ReceiverExportError(
      `chain ${opts.chainId} claims attested_seq ${state.attested_seq} but holds no signature at that seq`,
    );
  }

  const records = opts.store
    .records(opts.chainId, 1, state.attested_seq)
    .map((entry) => entry.record);
  if (records.length !== state.attested_seq) {
    throw new ReceiverExportError(
      `chain ${opts.chainId} is missing records below attested_seq ${state.attested_seq} ` +
        `(holds ${records.length}) — refusing to export a bundle with a hole in it`,
    );
  }

  const inRangeSignatures = stored
    .map((s) => s.signature)
    .filter((s) => s.seq <= state.attested_seq);

  const manifest = await exportBundle({
    store: replicaStore(records, inRangeSignatures, `${opts.store.dataDir}/chains/${opts.chainId}`),
    signer: storedSignatureSigner(state.key, attesting),
    toolVersion: opts.toolVersion,
    ...(opts.dirPath !== undefined ? { dirPath: opts.dirPath } : {}),
    ...(opts.zipPath !== undefined ? { zipPath: opts.zipPath } : {}),
  });

  return {
    manifest,
    unattested_records: Math.max(0, state.next_seq - 1 - state.attested_seq),
    claimed_head_seq: state.claimed_head_seq,
  };
}
