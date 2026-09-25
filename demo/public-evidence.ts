/** Public synthetic fixture: real recording/export/verification, no live tool calls. */
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { Recorder } from '../src/capture/recorder.js';
import { canonicalJson, sha256Hex, sha256Ref } from '../src/chain/hash.js';
import { Signer } from '../src/chain/keys.js';
import { BUNDLE_FILES, exportBundle } from '../src/export/bundle.js';
import { Redactor, scrubToolArguments } from '../src/redact/redactor.js';
import { SCHEMA, type ChainRecord, type ToolCallEvent } from '../src/schema/events.js';
import { openStore } from '../src/store/index.js';

const ROOT = fileURLToPath(new URL('../', import.meta.url));
export const FIXTURE_VERSION = '1';
export const SAMPLE_LIMITATIONS = [
  'Synthetic fixture, not production traffic or a real workflow execution.',
  'Integrity: present records match the signed head under the bundled key; signer identity is not independently trusted.',
  'Coverage: a valid chain does not prove every action was recorded. Failed appends can drop events; durable spool/replay/reconciliation is not complete.',
  'Enforcement: these are simulated observation-mode MCP records. No policy, credential broker, remote call or enforcement is exercised.',
  'Identity: unattributed synthetic actor; no enterprise login or verified identity JWT.',
  'Trust: obtain a public key and expected head/range independently for stronger assurance. A never-recorded action or self-consistent earlier history need not be detected.',
  'Provenance and verification timestamps are unsigned metadata, not a signed timestamp or third-party attestation.',
  'A local credential broker hiding a secret from context does not prove credential absence from the agent machine.',
] as const;

/** Stable synthetic input; normal redaction runs before anything enters the store. */
export function sampleEvents(): ToolCallEvent[] {
  const redactor = new Redactor({ mode: 'allowlist' });
  return ['read_summary', 'create_draft'].map((tool, index) => {
    const result = { content: [{ type: 'text', text: `SYNTHETIC_RESULT_${index}` }] };
    return {
      schema: SCHEMA,
      event_id: `00000000-0000-4000-8000-00000000000${index + 1}`,
      session_id: '00000000-0000-4000-8000-000000000010',
      timestamp: `2026-09-25T00:00:0${index}.000Z`,
      kind: 'tool_call',
      identity: { fingerprint: sha256Ref('public-synthetic-unattributed') },
      server: { name: 'synthetic-example', command: 'synthetic-fixture-no-server', transport: 'stdio' },
      attributes: { 'cresec.fixture.synthetic': true, 'gen_ai.tool.name': tool },
      tool,
      request_id: index + 1,
      args: scrubToolArguments(redactor, { reference: `SYNTHETIC_ARGUMENT_${index}` }),
      result_hash: sha256Ref(canonicalJson(result)),
      result: redactor.scrub(result),
      is_error: false,
      duration_ms: 0,
    };
  });
}

function runVerifier(bundle: string) {
  const run = spawnSync(process.execPath, ['verify.cjs'], { cwd: bundle, encoding: 'utf8', timeout: 10_000 });
  if (run.error) throw run.error;
  assert.equal(run.signal, null, 'verifier must finish normally');
  return { exit_code: run.status, stdout: run.stdout, stderr: run.stderr };
}

/** Regenerates the procedure, not identical bytes: every run creates and discards a fresh key. */
export async function generatePublicEvidence(output: string) {
  // Refuse overwrite rather than deleting a directory supplied by a caller.
  mkdirSync(output, { recursive: false });
  const temporary = mkdtempSync(join(tmpdir(), 'cresec-public-evidence-'));
  const store = openStore({ dataDir: temporary, backend: 'jsonl' });
  let recorder: Recorder | undefined;
  try {
    const signer = await Signer.load(temporary);
    recorder = new Recorder({ store, signer });
    for (const event of sampleEvents()) recorder.record(event);
    await recorder.flush();
    assert.equal(recorder.stats().written, 2);
    assert.equal(recorder.stats().dropped, 0);
    const packageInfo = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8')) as { version: string };
    const intact = join(output, 'intact');
    const manifest = await exportBundle({ store, signer, dirPath: intact, toolVersion: packageInfo.version });
    const intactResult = runVerifier(intact);
    assert.equal(intactResult.exit_code, 0, intactResult.stdout + intactResult.stderr);
    assert.match(intactResult.stdout, /PASS: evidence bundle verified/);

    const tampered = join(output, 'tampered');
    cpSync(intact, tampered, { recursive: true });
    const records = readFileSync(join(tampered, BUNDLE_FILES.EVENTS), 'utf8').trim().split('\n')
      .map((line) => JSON.parse(line) as ChainRecord);
    const first = records[0]!;
    assert.equal(first.event.kind, 'tool_call');
    (first.event as ToolCallEvent).tool = 'altered_tool';
    writeFileSync(join(tampered, BUNDLE_FILES.EVENTS), records.map((record) => JSON.stringify(record)).join('\n') + '\n');
    const tamperedResult = runVerifier(tampered);
    assert.equal(tamperedResult.exit_code, 1, 'altered event must fail the unchanged verifier');
    assert.match(tamperedResult.stdout, /hash mismatch at seq 1/);

    const sourceFiles = ['demo/public-evidence.ts', 'src/export/bundle.ts', 'src/capture/recorder.ts',
      'src/chain/keys.ts', 'src/chain/hash.ts', 'src/redact/redactor.ts', 'package-lock.json'];
    const sourceHashes = Object.fromEntries(sourceFiles.map((path) => [path, sha256Hex(readFileSync(join(ROOT, path)))]));
    const artifactHashes = Object.fromEntries(['intact', 'tampered'].flatMap((kind) =>
      Object.values(BUNDLE_FILES).map((name) => [`${kind}/${name}`, sha256Hex(readFileSync(join(output, kind, name)))])));
    const generatedAt = new Date().toISOString();
    const metadata = {
      display_contract: 'cresec.public-evidence-display.v1',
      fixture_version: FIXTURE_VERSION,
      scenario: 'Synthetic summary read and draft creation',
      sample: true,
      mode: 'synthetic-observation',
      actor_status: 'unattributed',
      generated_at: generatedAt,
      generator: {
        command: 'npm run demo:sample -- --out <new-directory>',
        package_version: packageInfo.version,
        source_base_commit: execFileSync('git', ['rev-parse', 'HEAD'], { cwd: ROOT, encoding: 'utf8' }).trim(),
        source_note: 'Source hashes identify the working-tree generator; base commit alone does not identify uncommitted changes.',
        source_sha256: sourceHashes,
      },
      signer: { public_key_hex: signer.publicKeyHex, fingerprint_sha256_raw_key: sha256Hex(Buffer.from(signer.publicKeyHex, 'hex')), independently_trusted: false },
      range: manifest.range,
      head_hash: manifest.head_hash,
      event_count: manifest.event_count,
      safe_records: sampleEvents().map(({ kind, tool, request_id, timestamp }) => ({ kind, tool, request_id, timestamp })),
      verification: {
        kind: 'precomputed',
        observed_at: generatedAt,
        verifier: '@edut/mcp-recorder exported verify.cjs',
        package_version: packageInfo.version,
        intact: { artifact: 'intact/', command: 'node intact/verify.cjs', ...intactResult },
        tampered: { artifact: 'tampered/', command: 'node tampered/verify.cjs', mutation: 'event at seq 1: tool changed to altered_tool, without recomputing hashes or signatures', ...tamperedResult },
      },
      artifact_sha256: artifactHashes,
      limitations: SAMPLE_LIMITATIONS,
    };
    writeFileSync(join(output, 'display.json'), JSON.stringify(metadata, null, 2) + '\n');
    return metadata;
  } finally {
    if (recorder) await recorder.close();
    else store.close();
    // Never copy the store or its private signing key into a public artifact.
    rmSync(temporary, { recursive: true, force: true });
  }
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  const args = process.argv.slice(2);
  if (args.length !== 2 || args[0] !== '--out' || !args[1]) {
    process.stderr.write('Usage: npm run demo:sample -- --out <new-directory>\n');
    process.exitCode = 2;
  } else {
    generatePublicEvidence(resolve(args[1])).then((result) => {
      process.stdout.write(`Synthetic sample: intact PASS; deliberate tamper FAIL (expected).\nObserved ${result.verification.observed_at}; bundled key only, not independently trusted.\n${SAMPLE_LIMITATIONS.join('\n')}\n`);
    }).catch((error: unknown) => {
      process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
      process.exitCode = 1;
    });
  }
}
