/**
 * Signed evidence bundle export (M3).
 *
 * A bundle is five files a stranger can verify with nothing but Node.js:
 *   events.jsonl    — one ChainRecord per line, seq order
 *   manifest.json   — BundleManifest (range, base/head hash, fresh signature)
 *   public_key.pem  — SPKI PEM of the recorder's ed25519 key
 *   verify.cjs      — standalone zero-dependency verifier (node verify.cjs)
 *   README.txt      — what this is / how to verify / what PASS proves / who
 *
 * Written as a plain directory (dirPath), a .zip via yazl (zipPath), or both.
 */

import { createWriteStream, mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { Buffer } from 'node:buffer';
import yazl from 'yazl';
import { publicKeyPem } from '../chain/keys.js';
import type { ChainRecord } from '../schema/events.js';
import type { BundleManifest, EvidenceStore, ExportOpts, SignerLike } from '../types.js';

/** File names inside a bundle (dir entries and zip entries are identical). */
export const BUNDLE_FILES = {
  EVENTS: 'events.jsonl',
  MANIFEST: 'manifest.json',
  PUBLIC_KEY: 'public_key.pem',
  VERIFY: 'verify.cjs',
  README: 'README.txt',
} as const;

/**
 * Pick the records to export.
 *
 * A hash chain only verifies as a CONTIGUOUS run — every record's prev_hash
 * must equal the hash of the record immediately before it. Sessions interleave
 * freely in the chain, so a session-scoped export takes the FULL seq range
 * [min..max] spanned by that session, INCLUDING any interleaved records from
 * other sessions: dropping them would break every prev_hash link they sit on
 * and the bundle could never verify. Interleaved events are already redacted
 * (hashes, not payloads), so including them leaks nothing new.
 */
function selectRecords(store: EvidenceStore, sessionId?: string): ChainRecord[] {
  if (sessionId === undefined) return [...store.iterate()];
  let min: number | undefined;
  let max: number | undefined;
  for (const record of store.iterate({ sessionId })) {
    if (min === undefined) min = record.seq;
    max = record.seq;
  }
  if (min === undefined || max === undefined) return [];
  return [...store.iterate({ fromSeq: min, toSeq: max })];
}

function readmeText(manifest: BundleManifest): string {
  const scope =
    manifest.session_id === undefined
      ? 'the full event chain'
      : `session ${manifest.session_id} (with interleaved chain records)`;
  return [
    `This is a signed evidence bundle from @edut/mcp-recorder: ${manifest.event_count} redacted MCP event(s), seq ${manifest.range.from_seq}..${manifest.range.to_seq} of ${scope}, sealed in a SHA-256 hash chain.`,
    'How to verify (needs only Node.js, no packages):  node verify.cjs',
    'PASS checks the present records against the declared range, hash chain and signed head under the bundled ed25519 public key. It does not prove all real activity was recorded or who controls that key.',
    'Obtain the signer public key and expected head/range independently for stronger assurance; use node verify.cjs --public-key <hex-or-path> to pin the key. A never-recorded action or a self-consistent earlier history need not be detected.',
    'Recording can drop events after failed appends; durable coverage/reconciliation is not complete. Enforcement applies only to mediated calls in explicitly selected gateway mode, never from a valid chain alone.',
    'The generation time and tool version below are unsigned informational metadata, not a trusted timestamp.',
    `Generated ${manifest.created_at} by @edut/mcp-recorder v${manifest.tool_version}; details in manifest.json.`,
  ].join('\n') + '\n';
}

async function writeZip(
  zipPath: string,
  entries: ReadonlyArray<{ name: string; data: Buffer }>,
): Promise<void> {
  mkdirSync(dirname(zipPath), { recursive: true });
  await new Promise<void>((resolve, reject) => {
    const zip = new yazl.ZipFile();
    for (const entry of entries) zip.addBuffer(entry.data, entry.name);
    const out = createWriteStream(zipPath);
    out.on('error', reject);
    out.on('close', resolve);
    zip.outputStream.on('error', reject);
    zip.outputStream.pipe(out);
    zip.end();
  });
}

/**
 * Export a verifiable evidence bundle. The head of the selected range is
 * re-signed at export time so the bundle carries a fresh attestation even
 * when the store's own signatures cover different seqs.
 */
export async function exportBundle(
  opts: ExportOpts & { signer: SignerLike },
): Promise<BundleManifest> {
  if (opts.dirPath === undefined && opts.zipPath === undefined) {
    throw new Error('mcp-recorder: exportBundle requires dirPath and/or zipPath');
  }

  const records = selectRecords(opts.store, opts.sessionId);
  if (records.length === 0) {
    throw new Error(
      opts.sessionId === undefined
        ? 'mcp-recorder: cannot export an empty store'
        : `mcp-recorder: no events recorded for session ${opts.sessionId}`,
    );
  }
  const first = records[0]!;
  const last = records[records.length - 1]!;

  // Fresh signature over the head of the exported range.
  const signature = await opts.signer.sign(last.seq, last.hash);
  const pem = publicKeyPem(opts.signer.publicKeyHex);

  const manifest: BundleManifest = {
    bundle: 'edut.mcp-recorder.bundle.v1',
    created_at: new Date().toISOString(),
    tool_version: opts.toolVersion,
    range: { from_seq: first.seq, to_seq: last.seq },
    base_hash: first.prev_hash,
    head_hash: last.hash,
    event_count: records.length,
    signature,
    public_key_pem: pem,
  };
  if (opts.sessionId !== undefined) manifest.session_id = opts.sessionId;

  const entries: Array<{ name: string; data: Buffer }> = [
    {
      name: BUNDLE_FILES.EVENTS,
      data: Buffer.from(records.map((r) => JSON.stringify(r)).join('\n') + '\n', 'utf8'),
    },
    {
      name: BUNDLE_FILES.MANIFEST,
      data: Buffer.from(JSON.stringify(manifest, null, 2) + '\n', 'utf8'),
    },
    { name: BUNDLE_FILES.PUBLIC_KEY, data: Buffer.from(pem, 'utf8') },
    { name: BUNDLE_FILES.VERIFY, data: Buffer.from(VERIFY_CJS, 'utf8') },
    { name: BUNDLE_FILES.README, data: Buffer.from(readmeText(manifest), 'utf8') },
  ];

  if (opts.dirPath !== undefined) {
    mkdirSync(opts.dirPath, { recursive: true });
    for (const entry of entries) {
      writeFileSync(join(opts.dirPath, entry.name), entry.data);
    }
  }
  if (opts.zipPath !== undefined) {
    await writeZip(opts.zipPath, entries);
  }

  return manifest;
}

/**
 * The standalone verifier shipped inside every bundle. Pure CommonJS, zero
 * dependencies (node:crypto/fs/path only), so "node verify.cjs" works on any
 * stock Node.js >= 12 with no install step.
 *
 * It deliberately REIMPLEMENTS the primitives from src/chain/hash.ts — keep
 * the two in byte-exact sync:
 *   canonicalJson   object keys sorted at every level, no whitespace,
 *                   undefined dropped, non-finite numbers -> null
 *   chain hash      sha256_hex(prev_hash + "\n" + canonical_json(event))
 *   signed payload  "edut.mcp-recorder.head.v1\n<seq>\n<hash>"
 *
 * (String.raw keeps the embedded \n escapes literal in the emitted file.)
 */
const VERIFY_CJS: string = String.raw`#!/usr/bin/env node
/*
 * Standalone verifier for an @edut/mcp-recorder evidence bundle.
 * Usage: node verify.cjs [--public-key <hex|path>]   (run from inside the bundle directory)
 * Zero dependencies: node:crypto, node:fs, node:path only.
 *
 * By default this checks that the bundle is INTERNALLY self-consistent: the
 * chain recomputes, and the shipped public_key.pem matches the key named in
 * manifest.signature. That does NOT prove who signed it — a bundle carries
 * its own key, so an attacker who forges a bundle from scratch ships a key
 * that "verifies" against itself. For real assurance, obtain the signer's
 * public key OUT OF BAND (e.g. from the operator directly, not from this
 * bundle) and pass it as --public-key <64-hex, or a path to a file holding
 * hex or a PEM>: verification then fails unless THAT key made the signature.
 *
 * Reimplements the recipes from src/chain/hash.ts of @edut/mcp-recorder —
 * if that file ever changes, this template must change with it:
 *   canonical JSON : keys sorted at every level, no whitespace,
 *                    undefined dropped, non-finite numbers -> null
 *   chain hash     : sha256_hex(prev_hash + "\n" + canonical_json(event))
 *   signed payload : "edut.mcp-recorder.head.v1\n<seq>\n<hash>"
 */
'use strict';
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

function usageFail(message) {
  console.log('FAIL: ' + message);
  console.log('Usage: node verify.cjs [--public-key <64-hex|path-to-hex-or-PEM>]');
  process.exit(2);
}

/* --public-key <value>: resolve to a 64-hex raw ed25519 public key. Accepts
 * the hex directly, or a path (resolved against the CURRENT working
 * directory, not __dirname — the whole point is a key from OUTSIDE this
 * bundle) to a file holding either hex or an SPKI PEM. */
const HEX64 = /^[0-9a-f]{64}$/i;
function resolvePinnedHex(argv) {
  let value;
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--public-key') { value = argv[i + 1]; break; }
    if (argv[i].indexOf('--public-key=') === 0) { value = argv[i].slice('--public-key='.length); break; }
  }
  if (value === undefined) return null;
  const trimmed = value.trim();
  if (HEX64.test(trimmed)) return trimmed.toLowerCase();
  let content;
  try {
    content = fs.readFileSync(path.resolve(trimmed), 'utf8');
  } catch (err) {
    usageFail("--public-key '" + value + "' is neither 64-hex nor a readable file: " + err.message);
  }
  const text = content.trim();
  if (HEX64.test(text)) return text.toLowerCase();
  if (text.indexOf('BEGIN PUBLIC KEY') !== -1) {
    let key;
    try {
      key = crypto.createPublicKey(text);
    } catch (err) {
      usageFail("--public-key file '" + value + "' is not a valid public key PEM: " + err.message);
    }
    const der = key.export({ format: 'der', type: 'spki' });
    return der.subarray(der.length - 32).toString('hex');
  }
  usageFail("--public-key file '" + value + "' is neither 64-hex nor a PEM public key");
}
const pinnedHex = resolvePinnedHex(process.argv.slice(2));

function canonicalJson(value) {
  if (value === null || value === undefined) return 'null';
  const t = typeof value;
  if (t === 'number') return Number.isFinite(value) ? JSON.stringify(value) : 'null';
  if (t === 'string' || t === 'boolean') return JSON.stringify(value);
  if (Array.isArray(value)) {
    return '[' + value.map(function (v) {
      return v === undefined ? 'null' : canonicalJson(v);
    }).join(',') + ']';
  }
  if (t === 'object') {
    const keys = Object.keys(value).filter(function (k) {
      return value[k] !== undefined;
    }).sort();
    return '{' + keys.map(function (k) {
      return JSON.stringify(k) + ':' + canonicalJson(value[k]);
    }).join(',') + '}';
  }
  throw new TypeError('canonicalJson: unsupported type ' + t);
}

function sha256Hex(data) {
  return crypto.createHash('sha256').update(data).digest('hex');
}

function chainHash(prevHash, event) {
  return sha256Hex(prevHash + '\n' + canonicalJson(event));
}

function signedPayload(seq, hash) {
  return Buffer.from('edut.mcp-recorder.head.v1\n' + seq + '\n' + hash, 'utf8');
}

function fail(message) {
  console.log('FAIL: ' + message);
  console.log('This bundle does NOT verify. Treat its contents as unreliable.');
  process.exit(1);
}

function readBundleFile(name) {
  try {
    return fs.readFileSync(path.join(__dirname, name), 'utf8');
  } catch (err) {
    fail('cannot read ' + name + ' next to verify.cjs: ' + err.message);
  }
}

const manifestText = readBundleFile('manifest.json');
let manifest;
try {
  manifest = JSON.parse(manifestText);
} catch (err) {
  fail('manifest.json is not valid JSON: ' + err.message);
}
if (manifest.bundle !== 'edut.mcp-recorder.bundle.v1') {
  fail('unrecognized bundle id: ' + String(manifest.bundle));
}

const pem = readBundleFile('public_key.pem');
const lines = readBundleFile('events.jsonl').split('\n').filter(function (line) {
  return line.trim() !== '';
});

/* 1. Counts and range must agree with the manifest. */
const expectedCount = manifest.range.to_seq - manifest.range.from_seq + 1;
if (manifest.event_count !== expectedCount) {
  fail('manifest is self-inconsistent: range covers ' + expectedCount +
    ' seq(s) but event_count is ' + manifest.event_count);
}
if (lines.length !== manifest.event_count) {
  fail('events.jsonl has ' + lines.length + ' event(s) but the manifest declares ' +
    manifest.event_count);
}

/* 2. Walk the chain from base_hash, recomputing every hash. */
let prevHash = manifest.base_hash;
let expectSeq = manifest.range.from_seq;
for (let i = 0; i < lines.length; i++) {
  let record;
  try {
    record = JSON.parse(lines[i]);
  } catch (err) {
    fail('events.jsonl line ' + (i + 1) + ' is not valid JSON: ' + err.message);
  }
  if (record.seq !== expectSeq) {
    fail('seq mismatch at line ' + (i + 1) + ': expected seq ' + expectSeq +
      ', found ' + record.seq);
  }
  if (record.prev_hash !== prevHash) {
    fail('broken chain link at seq ' + record.seq +
      ': prev_hash does not match the preceding hash');
  }
  const recomputed = chainHash(prevHash, record.event);
  if (recomputed !== record.hash) {
    fail('hash mismatch at seq ' + record.seq +
      ': the event does not match its chain hash (event was altered)');
  }
  prevHash = recomputed;
  expectSeq += 1;
}
if (prevHash !== manifest.head_hash) {
  fail('recomputed head hash ' + prevHash + ' does not match manifest.head_hash ' +
    manifest.head_hash);
}

/* 3. The manifest signature must cover exactly this head. */
const sig = manifest.signature;
if (!sig || sig.algo !== 'ed25519') {
  fail('manifest.signature is missing or uses an unsupported algorithm');
}
if (sig.seq !== manifest.range.to_seq || sig.chain_hash !== manifest.head_hash) {
  fail('manifest.signature covers seq ' + sig.seq +
    ' / hash ' + sig.chain_hash + ', not this bundle head');
}

/* 4. The bundled PEM and the raw hex key in the signature must be the SAME
 *    key: derive the raw 32 key bytes from the PEM (last 32 bytes of the
 *    SPKI DER encoding) and compare. */
let publicKey;
try {
  publicKey = crypto.createPublicKey(pem);
} catch (err) {
  fail('public_key.pem is not a valid public key: ' + err.message);
}
const der = publicKey.export({ format: 'der', type: 'spki' });
const rawHexFromPem = der.subarray(der.length - 32).toString('hex');
if (rawHexFromPem !== String(sig.public_key).toLowerCase()) {
  fail('public_key.pem does not correspond to manifest.signature.public_key');
}
if (manifest.public_key_pem !== undefined && manifest.public_key_pem !== pem) {
  fail('public_key.pem on disk differs from the PEM embedded in the manifest');
}

/* 5. If --public-key pinned an externally-obtained key, the signature MUST
 *    have been made by THAT key — not merely by whatever key the bundle
 *    itself ships. Without --public-key this step is skipped: the checks
 *    above only prove the bundle is internally self-consistent (see the
 *    header comment), not who produced it. */
if (pinnedHex !== null && String(sig.public_key).toLowerCase() !== pinnedHex) {
  fail('signed by unexpected key ' + String(sig.public_key).slice(0, 16) + '..., expected ' +
    pinnedHex.slice(0, 16) + '... (--public-key) - this signature was not made by the pinned key');
}

/* 6. ed25519 verification of the signed head payload. */
let signatureOk = false;
try {
  signatureOk = crypto.verify(
    null,
    signedPayload(sig.seq, sig.chain_hash),
    publicKey,
    Buffer.from(sig.signature, 'hex')
  );
} catch (err) {
  fail('signature verification errored: ' + err.message);
}
if (!signatureOk) {
  fail('ed25519 signature over the chain head does NOT verify');
}

console.log('PASS: evidence bundle verified');
console.log('  events     : ' + lines.length + ' (seq ' + manifest.range.from_seq +
  '..' + manifest.range.to_seq + ')');
console.log('  base hash  : ' + manifest.base_hash);
console.log('  head hash  : ' + manifest.head_hash);
console.log('  signed by  : ed25519 ' + sig.public_key + ' at ' + sig.signed_at);
console.log('Every event hash recomputes, the chain is contiguous, and the head');
console.log('signature verifies against the bundled public key.');
if (pinnedHex !== null) {
  console.log('  key check  : matches the --public-key you pinned - independently verified.');
} else {
  console.log('  key check  : NOT independently verified - the key came from this bundle');
  console.log('               itself (public_key.pem / manifest.json), which an attacker');
  console.log('               who forged the whole bundle controls too. Re-run with');
  console.log('               --public-key <hex|path> using a key you obtained out of band');
  console.log('               (e.g. from the operator directly) for real assurance.');
}
/* manifest.session_id / created_at / tool_version are NOT covered by the head
 * signature above (it covers only sig.seq + sig.chain_hash, checked in step
 * 3) — they are the exporting tool's own unverified say-so, so they are
 * printed separately and clearly labeled rather than folded into the PASS
 * block above, where a reader could mistake them for verified facts. */
console.log('');
console.log('UNSIGNED metadata (not covered by the signature - informational only):');
if (manifest.session_id !== undefined) {
  console.log('  session_id   : ' + manifest.session_id);
}
console.log('  created_at   : ' + manifest.created_at);
console.log('  tool_version : ' + manifest.tool_version);
process.exit(0);
`;
