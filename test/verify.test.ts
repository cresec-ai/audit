import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { GENESIS_HASH, makeRecord, sha256Hex, sha256Ref } from '../src/chain/hash.js';
import { Signer } from '../src/chain/keys.js';
import { openStore } from '../src/store/index.js';
import { verifyRecords, verifyStore } from '../src/verify/verify.js';
import type { ChainHead, EvidenceStore } from '../src/types.js';
import type {
  AnyEvent,
  ChainRecord,
  IdentityContext,
  ServerContext,
  SessionEndEvent,
  SessionStartEvent,
  ToolCallEvent,
} from '../src/schema/events.js';
import { SCHEMA } from '../src/schema/events.js';

/* ------------------------------ fixtures ------------------------------ */

const IDENTITY: IdentityContext = { fingerprint: sha256Ref('verify-test-identity') };
const SERVER: ServerContext = {
  name: 'verify-test-server',
  command: 'node server.js',
  transport: 'stdio',
};
const SESSION_A = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';

let eventCounter = 0;

function fakeUuid(): string {
  return `00000000-0000-4000-8000-${(eventCounter++).toString(16).padStart(12, '0')}`;
}

function sessionStart(sessionId: string, n: number): SessionStartEvent {
  return {
    schema: SCHEMA,
    event_id: fakeUuid(),
    session_id: sessionId,
    timestamp: new Date(Date.UTC(2026, 5, 11, 10, 0, n)).toISOString(),
    kind: 'session_start',
    identity: IDENTITY,
    server: SERVER,
    attributes: {},
    proxy_version: '0.1.0',
    cwd: '/tmp',
    redaction_mode: 'allowlist',
  };
}

function toolCall(sessionId: string, n: number, tool = 'list_issues'): ToolCallEvent {
  return {
    schema: SCHEMA,
    event_id: fakeUuid(),
    session_id: sessionId,
    timestamp: new Date(Date.UTC(2026, 5, 11, 10, 0, n)).toISOString(),
    kind: 'tool_call',
    identity: IDENTITY,
    server: SERVER,
    attributes: { 'gen_ai.tool.name': tool },
    tool,
    request_id: n,
    args: { repo: { redacted: true, ref: sha256Ref('hello-world'), len: 11 } },
    result_hash: sha256Ref('{"ok":true}'),
    result: { ok: true },
    is_error: false,
    duration_ms: 3,
  };
}

function sessionEnd(sessionId: string, n: number): SessionEndEvent {
  return {
    schema: SCHEMA,
    event_id: fakeUuid(),
    session_id: sessionId,
    timestamp: new Date(Date.UTC(2026, 5, 11, 10, 0, n)).toISOString(),
    kind: 'session_end',
    identity: IDENTITY,
    server: SERVER,
    attributes: {},
    reason: 'child_exit',
    child_exit_code: 0,
    events_recorded: n,
    events_dropped: 0,
  };
}

/** Seal events into a contiguous chain starting at `head`. */
function seal(events: AnyEvent[], head: ChainHead = { seq: 0, hash: GENESIS_HASH }): ChainRecord[] {
  const out: ChainRecord[] = [];
  let h = head;
  for (const event of events) {
    const record = makeRecord(h, event);
    out.push(record);
    h = { seq: record.seq, hash: record.hash };
  }
  return out;
}

function sixEvents(): AnyEvent[] {
  return [
    sessionStart(SESSION_A, 0),
    toolCall(SESSION_A, 1),
    toolCall(SESSION_A, 2, 'create_issue'),
    toolCall(SESSION_A, 3),
    toolCall(SESSION_A, 4, 'search_code'),
    toolCall(SESSION_A, 5),
  ];
}

/* ------------------------- store-backed suites ------------------------- */

const backends: Array<'sqlite' | 'jsonl'> = ['sqlite', 'jsonl'];

describe.each(backends)('verifyStore (%s)', (backend) => {
  let dir: string;
  let opened: EvidenceStore[];

  function open(): EvidenceStore {
    const store = openStore({ dataDir: dir, backend });
    opened.push(store);
    return store;
  }

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), `mcp-recorder-verify-${backend}-`));
    opened = [];
  });

  afterEach(() => {
    for (const store of opened) {
      try {
        store.close();
      } catch {
        /* already closed */
      }
    }
    rmSync(dir, { recursive: true, force: true });
  });

  it('clean signed chain verifies ok with a verified_signature', async () => {
    const signer = await Signer.load(dir);
    const records = seal(sixEvents());
    const store = open();
    store.append(records);
    const head = store.head();
    store.addSignature(await signer.sign(head.seq, head.hash));

    const result = await verifyStore(store);
    expect(result.ok).toBe(true);
    expect(result.problems).toEqual([]);
    expect(result.checked_events).toBe(6);
    expect(result.head).toEqual({ seq: 6, hash: records[5]!.hash });
    expect(result.verified_signature?.seq).toBe(6);
    expect(result.verified_signature?.chain_hash).toBe(records[5]!.hash);
    expect(result.verified_signature?.public_key).toBe(signer.publicKeyHex);
  });

  it('unsigned tail after the newest signature is a warning, not a failure', async () => {
    const signer = await Signer.load(dir);
    const records = seal(sixEvents());
    const store = open();
    store.append(records.slice(0, 3));
    store.addSignature(await signer.sign(3, records[2]!.hash));
    store.append(records.slice(3));

    const result = await verifyStore(store);
    expect(result.ok).toBe(true);
    expect(result.verified_signature?.seq).toBe(3);
    expect(result.problems).toHaveLength(1);
    expect(result.problems[0]).toMatchObject({ type: 'unsigned_tail', seq: 6, warning: true });
  });

  it('a never-signed chain FAILS with no_valid_signature (a chain nobody attests to proves nothing)', async () => {
    const records = seal(sixEvents());
    const store = open();
    store.append(records);

    const result = await verifyStore(store);
    expect(result.ok).toBe(false);
    expect(result.verified_signature).toBeUndefined();
    expect(result.problems).toHaveLength(1);
    expect(result.problems[0]).toMatchObject({ type: 'no_valid_signature', seq: 6 });
    expect(result.problems[0]!.warning).not.toBe(true);
    // Same scenario a corrupt/missing identity.key at record time would
    // produce (setupProxyRecording falls back to signer=null, so nothing
    // ever gets signed) — the detail must say plainly what's wrong and how
    // to proceed, not just "no valid head signature".
    expect(result.problems[0]!.detail).toContain('no valid signature');
    expect(result.problems[0]!.detail).toContain('--allow-unsigned');
  });

  it('--allow-unsigned downgrades a never-signed chain to a warning (ok: true)', async () => {
    const records = seal(sixEvents());
    const store = open();
    store.append(records);

    const result = await verifyStore(store, { allowUnsigned: true });
    expect(result.ok).toBe(true);
    expect(result.problems).toHaveLength(1);
    expect(result.problems[0]).toMatchObject({
      type: 'no_valid_signature',
      seq: 6,
      warning: true,
    });
  });

  it('a session_end in the unsigned tail FAILS even behind an otherwise-valid earlier signature', async () => {
    const signer = await Signer.load(dir);
    const events = sixEvents();
    events.push(sessionEnd(SESSION_A, 6));
    const records = seal(events);
    const store = open();
    store.append(records.slice(0, 3));
    store.addSignature(await signer.sign(3, records[2]!.hash));
    store.append(records.slice(3)); // seq 4..7, seq 7 is session_end, unsigned

    const result = await verifyStore(store);
    expect(result.ok).toBe(false);
    expect(result.verified_signature?.seq).toBe(3);
    expect(result.problems).toHaveLength(1);
    expect(result.problems[0]).toMatchObject({ type: 'unsigned_session_end', seq: 7 });
    expect(result.problems[0]!.warning).not.toBe(true);
  });

  it('--allow-unsigned downgrades an unsigned session_end tail to a warning (ok: true)', async () => {
    const signer = await Signer.load(dir);
    const events = sixEvents();
    events.push(sessionEnd(SESSION_A, 6));
    const records = seal(events);
    const store = open();
    store.append(records.slice(0, 3));
    store.addSignature(await signer.sign(3, records[2]!.hash));
    store.append(records.slice(3));

    const result = await verifyStore(store, { allowUnsigned: true });
    expect(result.ok).toBe(true);
    expect(result.problems).toHaveLength(1);
    expect(result.problems[0]).toMatchObject({
      type: 'unsigned_session_end',
      seq: 7,
      warning: true,
    });
  });

  it('an empty store verifies ok with no problems', async () => {
    const store = open();
    const result = await verifyStore(store);
    expect(result.ok).toBe(true);
    expect(result.checked_events).toBe(0);
    expect(result.head).toEqual({ seq: 0, hash: GENESIS_HASH });
    expect(result.problems).toEqual([]);
    expect(result.verified_signature).toBeUndefined();
  });

  it('multiple signatures: the newest fully-valid one wins', async () => {
    const signer = await Signer.load(dir);
    const records = seal(sixEvents());
    const store = open();
    store.append(records);
    store.addSignature(await signer.sign(2, records[1]!.hash));
    store.addSignature(await signer.sign(4, records[3]!.hash));
    store.addSignature(await signer.sign(6, records[5]!.hash));

    const result = await verifyStore(store);
    expect(result.ok).toBe(true);
    expect(result.problems).toEqual([]);
    expect(result.verified_signature?.seq).toBe(6);
  });
});

/* ------------------------ pure verifyRecords cases ------------------------ */

describe('verifyRecords', () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'mcp-recorder-verify-pure-'));
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('empty input verifies ok against the genesis anchor', async () => {
    const result = await verifyRecords([], []);
    expect(result.ok).toBe(true);
    expect(result.checked_events).toBe(0);
    expect(result.head).toEqual({ seq: 0, hash: GENESIS_HASH });
    expect(result.problems).toEqual([]);
  });

  it('segment verification with a baseHash anchor works', async () => {
    const signer = await Signer.load(dir);
    const records = seal(sixEvents());
    const segment = records.slice(2); // seq 3..6
    const sig = await signer.sign(6, records[5]!.hash);

    const result = await verifyRecords(segment, [sig], { baseHash: records[1]!.hash });
    expect(result.ok).toBe(true);
    expect(result.problems).toEqual([]);
    expect(result.checked_events).toBe(4);
    expect(result.head).toEqual({ seq: 6, hash: records[5]!.hash });
    expect(result.verified_signature?.seq).toBe(6);
  });

  it('the same segment without its anchor reports bad_genesis', async () => {
    const records = seal(sixEvents());
    const segment = records.slice(2);

    const result = await verifyRecords(segment, []);
    expect(result.ok).toBe(false);
    expect(result.problems.some((p) => p.type === 'bad_genesis' && p.seq === 3)).toBe(true);
  });

  it('a wrong baseHash anchor reports bad_genesis at the first record', async () => {
    const records = seal(sixEvents());
    const result = await verifyRecords(records, [], { baseHash: sha256Hex('not-genesis') });
    expect(result.ok).toBe(false);
    expect(result.problems.some((p) => p.type === 'bad_genesis' && p.seq === 1)).toBe(true);
  });

  it('expectedPublicKeyHex accepts the matching key and rejects others', async () => {
    const signer = await Signer.load(dir);
    const records = seal(sixEvents());
    const sig = await signer.sign(6, records[5]!.hash);

    const good = await verifyRecords(records, [sig], {
      expectedPublicKeyHex: signer.publicKeyHex,
    });
    expect(good.ok).toBe(true);
    expect(good.verified_signature?.seq).toBe(6);

    const bad = await verifyRecords(records, [sig], {
      expectedPublicKeyHex: 'ab'.repeat(32),
    });
    expect(bad.ok).toBe(false);
    expect(bad.verified_signature).toBeUndefined();
    expect(bad.problems.some((p) => p.type === 'signature_invalid' && p.seq === 6)).toBe(true);
  });

  it('a chain rewritten and re-signed with a FRESH (foreign) key only fails once pinned', async () => {
    // Attacker forges a self-consistent chain from scratch (own genesis
    // walk) and signs its own head with a key they control — never touching
    // the legitimate signer's key. Without pinning, the forged signature is
    // cryptographically genuine and internally consistent, so it "verifies".
    const events = sixEvents();
    events[2] = toolCall(SESSION_A, 99, 'FORGED_TOOL');
    const forged = seal(events);
    const attacker = await Signer.load(join(dir, 'attacker'));
    const forgedSig = await attacker.sign(6, forged[5]!.hash);

    const unpinned = await verifyRecords(forged, [forgedSig]);
    expect(unpinned.ok).toBe(true);
    expect(unpinned.verified_signature?.public_key).toBe(attacker.publicKeyHex);

    // The legitimate operator's own key (e.g. from identity.pub) rejects it.
    const legitimate = await Signer.load(join(dir, 'legitimate'));
    const pinned = await verifyRecords(forged, [forgedSig], {
      expectedPublicKeyHex: legitimate.publicKeyHex,
    });
    expect(pinned.ok).toBe(false);
    expect(pinned.verified_signature).toBeUndefined();
    expect(pinned.problems.some((p) => p.type === 'signature_invalid' && p.seq === 6)).toBe(true);
    expect(pinned.problems.some((p) => p.type === 'no_valid_signature')).toBe(true);
  });

  it('a malformed record is reported without aborting the walk', async () => {
    const records = seal(sixEvents());
    const mangled = [...records];
    mangled[2] = { ...records[2]!, hash: 'not-hex' } as ChainRecord;

    const result = await verifyRecords(mangled, []);
    expect(result.ok).toBe(false);
    expect(result.problems.some((p) => p.type === 'malformed_record' && p.seq === 3)).toBe(true);
    // The remaining records were still walked (5 well-formed of 6).
    expect(result.checked_events).toBe(5);
  });

  it('a valid signature pointing at a re-written chain is signature_chain_mismatch', async () => {
    const signer = await Signer.load(dir);
    const records = seal(sixEvents());
    const sig = await signer.sign(6, records[5]!.hash);

    // Rebuild the chain from scratch with one different event: every hash
    // from seq 3 on changes, but the chain itself is internally consistent.
    const events = sixEvents();
    events[2] = toolCall(SESSION_A, 99, 'rewritten_history');
    const rewritten = seal(events);

    const result = await verifyRecords(rewritten, [sig]);
    expect(result.ok).toBe(false);
    expect(
      result.problems.some((p) => p.type === 'signature_chain_mismatch' && p.seq === 6),
    ).toBe(true);
    expect(result.verified_signature).toBeUndefined();
  });
});
