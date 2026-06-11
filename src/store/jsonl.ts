/**
 * JSONL evidence store (fallback backend).
 *
 * Two append-only files in the data dir:
 *   FILES.JSONL_LOG  — one ChainRecord JSON per line
 *   FILES.JSONL_SIGS — one HeadSignature JSON per line
 *
 * The whole log is loaded into memory at open; appends validate chain
 * continuity exactly like the sqlite backend, then appendFileSync the lines.
 * Simple and correct beats clever here — this is the no-native-deps path.
 */

import { appendFileSync, existsSync, mkdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { ChainRecord, HeadSignature } from '../schema/events.js';
import { GENESIS_HASH } from '../chain/hash.js';
import { validateExtendsHead } from './sqlite.js';
import { FILES } from '../types.js';
import type { ChainHead, EvidenceStore, IterateOpts, SessionSummary } from '../types.js';

/**
 * Read a JSONL file into objects. A trailing partial line (e.g. from a crash
 * mid-write) is tolerated with a stderr warning; corruption anywhere else is
 * an error — silent data loss in an evidence store is never acceptable.
 */
function loadJsonlFile<T>(path: string): T[] {
  if (!existsSync(path)) return [];
  const lines = readFileSync(path, 'utf8').split('\n');
  const out: T[] = [];
  for (let i = 0; i < lines.length; i++) {
    const line = (lines[i] ?? '').trim();
    if (line === '') continue;
    try {
      out.push(JSON.parse(line) as T);
    } catch (err) {
      const isLastContent = lines.slice(i + 1).every((rest) => rest.trim() === '');
      if (isLastContent) {
        process.stderr.write(
          `[mcp-recorder] ignoring trailing partial line ${i + 1} in ${path}\n`,
        );
        break;
      }
      throw new Error(
        `mcp-recorder: corrupt JSONL line ${i + 1} in ${path}: ${(err as Error).message}`,
      );
    }
  }
  return out;
}

export class JsonlStore implements EvidenceStore {
  readonly backend = 'jsonl' as const;
  /** Path of the record log (the store's primary file). */
  readonly path: string;
  private readonly sigsPath: string;
  private readonly records: ChainRecord[];
  private readonly sigs: HeadSignature[];

  constructor(dataDir: string) {
    mkdirSync(dataDir, { recursive: true });
    this.path = join(dataDir, FILES.JSONL_LOG);
    this.sigsPath = join(dataDir, FILES.JSONL_SIGS);
    this.records = loadJsonlFile<ChainRecord>(this.path);
    this.sigs = loadJsonlFile<HeadSignature>(this.sigsPath);
  }

  head(): ChainHead {
    const last = this.records[this.records.length - 1];
    return last === undefined ? { seq: 0, hash: GENESIS_HASH } : { seq: last.seq, hash: last.hash };
  }

  append(records: ChainRecord[]): void {
    if (records.length === 0) return;
    let head = this.head();
    for (const record of records) {
      validateExtendsHead(head, record);
      head = { seq: record.seq, hash: record.hash };
    }
    const chunk = records.map((record) => JSON.stringify(record)).join('\n') + '\n';
    appendFileSync(this.path, chunk);
    this.records.push(...records);
  }

  addSignature(sig: HeadSignature): void {
    appendFileSync(this.sigsPath, JSON.stringify(sig) + '\n');
    this.sigs.push(sig);
  }

  latestSignature(): HeadSignature | null {
    return this.sigs.length > 0 ? this.sigs[this.sigs.length - 1]! : null;
  }

  signatures(): HeadSignature[] {
    return [...this.sigs];
  }

  *iterate(opts: IterateOpts = {}): Iterable<ChainRecord> {
    for (const record of this.records) {
      if (opts.fromSeq !== undefined && record.seq < opts.fromSeq) continue;
      if (opts.toSeq !== undefined && record.seq > opts.toSeq) continue;
      if (opts.sessionId !== undefined && record.event.session_id !== opts.sessionId) continue;
      yield record;
    }
  }

  count(): number {
    return this.records.length;
  }

  sessions(): SessionSummary[] {
    const byId = new Map<string, SessionSummary>();
    for (const record of this.records) {
      const ev = record.event;
      let summary = byId.get(ev.session_id);
      if (summary === undefined) {
        // First record of the session in seq order — same semantics as the
        // sqlite backend's "first event JSON of the session" subquery.
        summary = {
          session_id: ev.session_id,
          started_at: ev.timestamp,
          server_name: ev.server?.name ?? '',
          identity_fingerprint: ev.identity?.fingerprint ?? '',
          event_count: 0,
          tool_call_count: 0,
          error_count: 0,
        };
        byId.set(ev.session_id, summary);
      }
      if (ev.timestamp < summary.started_at) summary.started_at = ev.timestamp;
      summary.event_count += 1;
      if (ev.kind === 'tool_call') summary.tool_call_count += 1;
      if ((ev.kind === 'tool_call' || ev.kind === 'rpc') && ev.is_error) {
        summary.error_count += 1;
      }
      if (ev.kind === 'session_end') {
        if (summary.ended_at === undefined || ev.timestamp > summary.ended_at) {
          summary.ended_at = ev.timestamp;
        }
      }
    }
    return [...byId.values()];
  }

  close(): void {
    // Nothing to release: writes are flushed synchronously per append.
  }
}
