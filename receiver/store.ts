/**
 * Receiver persistence: one directory per chain, append-only JSONL inside it.
 *
 * Deliberately boring and inspectable — `cat`, `grep` and `jq` are the whole
 * admin interface. This is a reference receiver, not a database.
 *
 *   <data-dir>/
 *     chains/<chain_id>/meta.json        rebuildable cache of the chain state
 *     chains/<chain_id>/records.jsonl    {"seq","received_at","record"} per line
 *     chains/<chain_id>/signatures.jsonl {"received_at","signature"} per line
 *     chains/<chain_id>/heads.jsonl      every VERIFIED signed head claim
 *     chains/<chain_id>/forks.jsonl      the rejected branch, retained
 *     rejections.jsonl                   every refusal, with its reason
 *     alerts.jsonl                       fork / silence / new_identity
 *     enrolment.json                     which keys a tenant has been seen with
 *
 * `received_at` is stored beside every record because it is the ONLY
 * metadata the sender does not control: event `timestamp` is `Date.now()` on
 * the observed machine, which is a claim, not a clock.
 *
 * Durability: records are appended with one `writeSync` and an `fsyncSync`
 * BEFORE the 202 goes out, so "accepted" means persisted, not enqueued.
 * meta.json is a cache — it is rewritten tmp+rename after the records land,
 * and a crash between the two is repaired at startup by replaying
 * records.jsonl. I/O here is synchronous on purpose: at tool-call rates the
 * simplicity is worth more than the concurrency, and it makes the ordering
 * (append -> fsync -> respond) impossible to get subtly wrong.
 */

import {
  appendFileSync,
  closeSync,
  existsSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readFileSync,
  readdirSync,
  renameSync,
  writeFileSync,
  writeSync,
} from 'node:fs';
import { randomBytes } from 'node:crypto';
import { join } from 'node:path';
import { GENESIS_HASH } from '../src/chain/hash.js';
import type { ChainRecord, HeadSignature } from '../src/schema/events.js';
import { HEX64 } from './protocol.js';
import type { SinkHead, SinkSender } from './protocol.js';

export const FILES = {
  META: 'meta.json',
  RECORDS: 'records.jsonl',
  SIGNATURES: 'signatures.jsonl',
  HEADS: 'heads.jsonl',
  FORKS: 'forks.jsonl',
  REJECTIONS: 'rejections.jsonl',
  ALERTS: 'alerts.jsonl',
  ENROLMENT: 'enrolment.json',
  OPERATOR_TOKEN: 'operator-token.txt',
} as const;

export type ChainStatus = 'active' | 'forked';

/** Everything the receiver knows about one chain. Rebuildable from disk. */
export interface ChainState {
  chain_id: string;
  key: string;
  tenant: string;
  first_seen_at: string;
  /** Last time ANY authenticated traffic arrived for this chain. */
  last_seen_at: string;
  /** Last time a batch carrying records was committed (null if never). */
  last_record_at: string | null;
  /** First seq the receiver does not hold. 1 when empty. */
  next_seq: number;
  /** Hash at next_seq - 1; GENESIS_HASH when empty. */
  head_hash: string;
  /** Highest seq covered by a signature this receiver verified. 0 if none. */
  attested_seq: number;
  attested_at: string | null;
  status: ChainStatus;
  /**
   * False until seq 1 has actually arrived. Until then `chain_id` is the
   * sender's say-so (it can happen when the first thing we see is a
   * heartbeat); once seq 1 lands we check `records[0].hash === chain_id`.
   */
  chain_id_verified: boolean;
  /** The newest signed head the sender has claimed, whatever we hold. */
  claimed_head_seq: number;
  claimed_head_hash: string;
  claimed_head_at: string | null;
  records_held: number;
  /**
   * When the absence alert last fired for this chain, so silence is reported
   * once per outage rather than once per scan. Cleared by any arrival.
   */
  silence_alerted_at?: string | null;
  /** Advisory, from the last batch. Never used for a decision. */
  sender?: SinkSender;
}

export interface StoredRecord {
  seq: number;
  received_at: string;
  record: ChainRecord;
}

export interface StoredSignature {
  received_at: string;
  signature: HeadSignature;
}

export interface StoredHead {
  received_at: string;
  head: SinkHead;
  /** What the receiver held when this claim arrived — the lag, frozen. */
  delivered_next_seq: number;
}

export interface ForkEvidence {
  received_at: string;
  reason: string;
  /** Seq at which the two branches disagree. */
  at_seq: number;
  /** What this receiver already holds at that seq. */
  stored_hash: string | null;
  /** What was offered instead. */
  offered_hash: string | null;
  /** The whole refused payload, verbatim, so the branch is not lost. */
  offered: unknown;
}

export interface Rejection {
  received_at: string;
  chain_id: string;
  key: string | null;
  tenant: string | null;
  status: number;
  error: string;
  detail: string;
  from_seq: number | null;
  to_seq: number | null;
  remote: string | null;
}

export type AlertKind = 'chain_fork' | 'silent_chain' | 'new_identity' | 'second_chain_for_key';

export interface Alert {
  at: string;
  kind: AlertKind;
  chain_id: string;
  key: string;
  tenant: string;
  detail: string;
}

export interface Enrolment {
  /** tenant -> key -> when it was first seen and whether an operator ack'd it. */
  [tenant: string]: { [key: string]: { first_seen_at: string; acknowledged: boolean } };
}

function signatureKey(sig: HeadSignature): string {
  return `${sig.seq}:${sig.signature}`;
}

function assertChainId(chainId: string): void {
  // Never interpolate an unvalidated string into a filesystem path.
  if (!HEX64.test(chainId)) throw new Error(`refusing to touch a non-hex chain id: ${chainId}`);
}

/** Append `lines` and fsync before returning. The durability boundary. */
function appendDurable(path: string, lines: string[]): void {
  if (lines.length === 0) return;
  const fd = openSync(path, 'a');
  try {
    writeSync(fd, lines.map((l) => l + '\n').join(''));
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
}

function writeJsonAtomic(path: string, value: unknown): void {
  const tmp = path + '.tmp';
  const fd = openSync(tmp, 'w');
  try {
    writeSync(fd, JSON.stringify(value, null, 2) + '\n');
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  renameSync(tmp, path);
}

function readJsonl<T>(path: string): T[] {
  if (!existsSync(path)) return [];
  const out: T[] = [];
  const text = readFileSync(path, 'utf8');
  const lines = text.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!.trim();
    if (line === '') continue;
    try {
      out.push(JSON.parse(line) as T);
    } catch {
      // Only the final line can be torn (every append is fsync'd whole);
      // anything else means the file was edited underneath us. Either way,
      // stop here rather than silently reordering what follows.
      process.stderr.write(
        `[mcp-receiver] warning: ${path} line ${i + 1} is unparseable; ignoring it and everything after\n`,
      );
      break;
    }
  }
  return out;
}

/**
 * One chain's on-disk state plus the seq->hash index the ingest path needs.
 * Held in memory for the process lifetime: a reference receiver, not a
 * product, so an unbounded index is an accepted (and documented) limit.
 */
class ChainHandle {
  readonly dir: string;
  state: ChainState;
  readonly hashBySeq = new Map<number, string>();
  /** `<seq>:<signature hex>` of every signature already on disk. */
  readonly sigKeys = new Set<string>();

  constructor(dir: string, state: ChainState) {
    this.dir = dir;
    this.state = state;
  }
}

export class ReceiverStore {
  readonly dataDir: string;
  readonly chainsDir: string;
  #chains = new Map<string, ChainHandle>();
  #enrolment: Enrolment;

  constructor(dataDir: string) {
    this.dataDir = dataDir;
    this.chainsDir = join(dataDir, 'chains');
    mkdirSync(this.chainsDir, { recursive: true, mode: 0o700 });
    this.#enrolment = this.#loadEnrolment();
    this.#loadAllChains();
  }

  /* ------------------------------ chains ------------------------------ */

  #chainDir(chainId: string): string {
    assertChainId(chainId);
    return join(this.chainsDir, chainId);
  }

  #loadAllChains(): void {
    let entries: string[] = [];
    try {
      entries = readdirSync(this.chainsDir);
    } catch {
      return;
    }
    for (const entry of entries) {
      if (!HEX64.test(entry)) continue;
      try {
        this.#loadChain(entry);
      } catch (err) {
        process.stderr.write(
          `[mcp-receiver] warning: chain ${entry} failed to load: ${(err as Error).message}\n`,
        );
      }
    }
  }

  #loadChain(chainId: string): ChainHandle | undefined {
    const dir = this.#chainDir(chainId);
    const metaPath = join(dir, FILES.META);
    if (!existsSync(metaPath)) return undefined;
    const state = JSON.parse(readFileSync(metaPath, 'utf8')) as ChainState;
    const handle = new ChainHandle(dir, state);

    // records.jsonl is the truth; meta.json is a cache. Replay it so a crash
    // between the fsync'd append and the meta rewrite repairs itself.
    let nextSeq = 1;
    let headHash = GENESIS_HASH;
    let held = 0;
    let lastRecordAt: string | null = null;
    for (const stored of readJsonl<StoredRecord>(join(dir, FILES.RECORDS))) {
      if (stored.record.seq !== nextSeq) continue; // duplicate or stray; index by seq below
      handle.hashBySeq.set(stored.record.seq, stored.record.hash);
      headHash = stored.record.hash;
      nextSeq = stored.record.seq + 1;
      held++;
      lastRecordAt = stored.received_at;
    }
    handle.state = {
      ...state,
      next_seq: nextSeq,
      head_hash: headHash,
      records_held: held,
      last_record_at: lastRecordAt,
    };
    // Re-derive attestation from the signatures we hold, against the
    // recomputed index — a stored signature only counts while the hash it
    // names is still the hash at that seq.
    let attestedSeq = 0;
    let attestedAt: string | null = null;
    for (const sig of readJsonl<StoredSignature>(join(dir, FILES.SIGNATURES))) {
      handle.sigKeys.add(signatureKey(sig.signature));
      const at = handle.hashBySeq.get(sig.signature.seq);
      if (at !== undefined && at === sig.signature.chain_hash && sig.signature.seq > attestedSeq) {
        attestedSeq = sig.signature.seq;
        attestedAt = sig.received_at;
      }
    }
    handle.state.attested_seq = attestedSeq;
    handle.state.attested_at = attestedAt;
    this.#chains.set(chainId, handle);
    return handle;
  }

  chain(chainId: string): ChainState | undefined {
    return this.#chains.get(chainId)?.state;
  }

  listChains(): ChainState[] {
    return [...this.#chains.values()]
      .map((h) => h.state)
      .sort((a, b) => (a.last_seen_at < b.last_seen_at ? 1 : -1));
  }

  /** Every chain this key has opened — the "second chain for an enrolled key" probe. */
  chainsForKey(key: string): ChainState[] {
    return [...this.#chains.values()].map((h) => h.state).filter((s) => s.key === key);
  }

  createChain(init: {
    chain_id: string;
    key: string;
    tenant: string;
    at: string;
    sender?: SinkSender;
  }): ChainState {
    const dir = this.#chainDir(init.chain_id);
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    const state: ChainState = {
      chain_id: init.chain_id,
      key: init.key,
      tenant: init.tenant,
      first_seen_at: init.at,
      last_seen_at: init.at,
      last_record_at: null,
      next_seq: 1,
      head_hash: GENESIS_HASH,
      attested_seq: 0,
      attested_at: null,
      status: 'active',
      chain_id_verified: false,
      claimed_head_seq: 0,
      claimed_head_hash: GENESIS_HASH,
      claimed_head_at: null,
      records_held: 0,
      silence_alerted_at: null,
    };
    if (init.sender !== undefined) state.sender = init.sender;
    const handle = new ChainHandle(dir, state);
    this.#chains.set(init.chain_id, handle);
    writeJsonAtomic(join(dir, FILES.META), state);
    return state;
  }

  /** Receiver's hash at `seq`, or undefined when it does not hold that seq. */
  hashAt(chainId: string, seq: number): string | undefined {
    if (seq === 0) return GENESIS_HASH;
    return this.#chains.get(chainId)?.hashBySeq.get(seq);
  }

  #handle(chainId: string): ChainHandle {
    const handle = this.#chains.get(chainId);
    if (handle === undefined) throw new Error(`unknown chain ${chainId}`);
    return handle;
  }

  /**
   * Durably append `records` (which MUST start at the chain's current
   * next_seq and be contiguous) and return the updated state. fsync happens
   * before this returns; the caller may only respond 202 afterwards.
   */
  commitRecords(chainId: string, records: ChainRecord[], receivedAt: string): ChainState {
    const handle = this.#handle(chainId);
    if (records.length === 0) return handle.state;
    if (records[0]!.seq !== handle.state.next_seq) {
      throw new Error(
        `commitRecords called with seq ${records[0]!.seq}, expected ${handle.state.next_seq}`,
      );
    }
    appendDurable(
      join(handle.dir, FILES.RECORDS),
      records.map((record) =>
        JSON.stringify({ seq: record.seq, received_at: receivedAt, record } satisfies StoredRecord),
      ),
    );
    for (const record of records) handle.hashBySeq.set(record.seq, record.hash);
    const last = records[records.length - 1]!;
    handle.state.next_seq = last.seq + 1;
    handle.state.head_hash = last.hash;
    handle.state.records_held += records.length;
    handle.state.last_record_at = receivedAt;
    if (records[0]!.seq === 1) {
      handle.state.chain_id_verified = records[0]!.hash === chainId;
    }
    this.#flushMeta(handle);
    return handle.state;
  }

  /**
   * Store signatures we have already verified against the recomputed chain.
   * Byte-identical signatures already on disk are skipped, so a replayed
   * batch stores no duplicate. Returns the ones actually written.
   */
  commitSignatures(chainId: string, signatures: HeadSignature[], receivedAt: string): HeadSignature[] {
    if (signatures.length === 0) return [];
    const handle = this.#handle(chainId);
    const fresh = signatures.filter((sig) => !handle.sigKeys.has(signatureKey(sig)));
    if (fresh.length === 0) return [];
    appendDurable(
      join(handle.dir, FILES.SIGNATURES),
      fresh.map((signature) =>
        JSON.stringify({ received_at: receivedAt, signature } satisfies StoredSignature),
      ),
    );
    for (const sig of fresh) {
      handle.sigKeys.add(signatureKey(sig));
      if (sig.seq > handle.state.attested_seq) {
        handle.state.attested_seq = sig.seq;
        handle.state.attested_at = receivedAt;
      }
    }
    this.#flushMeta(handle);
    return fresh;
  }

  /**
   * Record the sender's signed head claim. This is the anti-withholding
   * evidence: `head.seq - next_seq` is how much is being held back, said in
   * the sender's own signature.
   */
  recordHead(chainId: string, head: SinkHead, receivedAt: string): void {
    const handle = this.#handle(chainId);
    appendDurable(join(handle.dir, FILES.HEADS), [
      JSON.stringify({
        received_at: receivedAt,
        head,
        delivered_next_seq: handle.state.next_seq,
      } satisfies StoredHead),
    ]);
    if (head.seq >= handle.state.claimed_head_seq) {
      handle.state.claimed_head_seq = head.seq;
      handle.state.claimed_head_hash = head.hash;
      handle.state.claimed_head_at = receivedAt;
    }
    this.#flushMeta(handle);
  }

  touch(chainId: string, receivedAt: string, sender?: SinkSender): void {
    const handle = this.#chains.get(chainId);
    if (handle === undefined) return;
    handle.state.last_seen_at = receivedAt;
    // An arrival ends the outage, so the next silence is alerted afresh.
    handle.state.silence_alerted_at = null;
    if (sender !== undefined) handle.state.sender = sender;
    this.#flushMeta(handle);
  }

  markSilenceAlerted(chainId: string, at: string): void {
    const handle = this.#chains.get(chainId);
    if (handle === undefined) return;
    handle.state.silence_alerted_at = at;
    this.#flushMeta(handle);
  }

  /**
   * Retain the refused branch and mark the chain forked. Terminal: the point
   * is that an auditor gets BOTH histories with their arrival times, never a
   * reconciliation.
   */
  recordFork(chainId: string, evidence: ForkEvidence): void {
    const handle = this.#handle(chainId);
    appendDurable(join(handle.dir, FILES.FORKS), [JSON.stringify(evidence)]);
    handle.state.status = 'forked';
    this.#flushMeta(handle);
  }

  forks(chainId: string): ForkEvidence[] {
    return readJsonl<ForkEvidence>(join(this.#chainDir(chainId), FILES.FORKS));
  }

  heads(chainId: string): StoredHead[] {
    return readJsonl<StoredHead>(join(this.#chainDir(chainId), FILES.HEADS));
  }

  records(chainId: string, fromSeq = 1, toSeq = Number.MAX_SAFE_INTEGER): StoredRecord[] {
    return readJsonl<StoredRecord>(join(this.#chainDir(chainId), FILES.RECORDS)).filter(
      (r) => r.seq >= fromSeq && r.seq <= toSeq,
    );
  }

  signatures(chainId: string): StoredSignature[] {
    return readJsonl<StoredSignature>(join(this.#chainDir(chainId), FILES.SIGNATURES));
  }

  #flushMeta(handle: ChainHandle): void {
    writeJsonAtomic(join(handle.dir, FILES.META), handle.state);
  }

  /* --------------------------- diagnostics --------------------------- */

  recordRejection(rejection: Rejection): void {
    appendFileSync(join(this.dataDir, FILES.REJECTIONS), JSON.stringify(rejection) + '\n');
  }

  rejections(limit = 100): Rejection[] {
    const all = readJsonl<Rejection>(join(this.dataDir, FILES.REJECTIONS));
    return all.slice(Math.max(0, all.length - limit));
  }

  raiseAlert(alert: Alert): void {
    appendFileSync(join(this.dataDir, FILES.ALERTS), JSON.stringify(alert) + '\n');
    process.stderr.write(
      `[mcp-receiver] ALERT ${alert.kind} chain=${alert.chain_id.slice(0, 16)} ` +
        `key=${alert.key.slice(0, 16)} ${alert.detail}\n`,
    );
  }

  alerts(limit = 100): Alert[] {
    const all = readJsonl<Alert>(join(this.dataDir, FILES.ALERTS));
    return all.slice(Math.max(0, all.length - limit));
  }

  /* ---------------------------- enrolment ---------------------------- */

  #loadEnrolment(): Enrolment {
    const path = join(this.dataDir, FILES.ENROLMENT);
    if (!existsSync(path)) return {};
    try {
      return JSON.parse(readFileSync(path, 'utf8')) as Enrolment;
    } catch {
      process.stderr.write('[mcp-receiver] warning: enrolment.json unreadable; starting empty\n');
      return {};
    }
  }

  enrolment(): Enrolment {
    return this.#enrolment;
  }

  enrolledKey(tenant: string, key: string): { first_seen_at: string; acknowledged: boolean } | undefined {
    return this.#enrolment[tenant]?.[key];
  }

  /** TOFU bind. Returns true when this is a key the tenant had not seen. */
  enrolKey(tenant: string, key: string, at: string, acknowledged: boolean): boolean {
    const forTenant = (this.#enrolment[tenant] ??= {});
    if (forTenant[key] !== undefined) return false;
    forTenant[key] = { first_seen_at: at, acknowledged };
    writeJsonAtomic(join(this.dataDir, FILES.ENROLMENT), this.#enrolment);
    return true;
  }

  /**
   * Operator acknowledgement of a trust-on-first-use key. Until this runs,
   * a second identity on a token is stored but not attested. Returns false
   * when the tenant/key pair is unknown.
   */
  acknowledgeKey(tenant: string, key: string): boolean {
    const entry = this.#enrolment[tenant]?.[key];
    if (entry === undefined) return false;
    entry.acknowledged = true;
    writeJsonAtomic(join(this.dataDir, FILES.ENROLMENT), this.#enrolment);
    return true;
  }

  /* ------------------------- operator token -------------------------- */

  /**
   * Read the operator token, minting one on first run. A receiver nobody can
   * query is a receiver nobody checks, and making the operator invent a
   * secret before they can see anything is how that happens.
   */
  operatorToken(): string {
    const path = join(this.dataDir, FILES.OPERATOR_TOKEN);
    if (existsSync(path)) {
      const text = readFileSync(path, 'utf8').trim();
      if (text !== '') return text;
    }
    const token = randomToken();
    writeFileSync(path, token + '\n', { mode: 0o600 });
    return token;
  }
}

/** 256 bits of opaque token, hex. */
export function randomToken(): string {
  return randomBytes(32).toString('hex');
}
