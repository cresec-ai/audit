/**
 * demo/run.ts — orchestrates the end-to-end prompt-injection exfiltration demo.
 *
 *   npm run demo            # run the 5-step incident-response story
 *   npm run demo -- --ui    # ...and then launch the HTML replay UI
 *   npm run demo -- --policy docs/examples/policy.demo.yaml
 *                           # same story behind the gateway: http_post denied,
 *                           # the canary redacted before the agent sees it
 *
 * The story (all deterministic, no LLM, no network):
 *   [1/5] run the poisoned agent session through the recorder
 *   [2/5] verify the hash chain (tamper-evident)
 *   [3/5] blast-radius the leaked secret — find who touched it (the money shot)
 *   [4/5] export a signed evidence bundle and verify it standalone
 *   [5/5] print how to open the replay
 *
 * Any failing step — or a blast-radius query that finds ZERO matches — exits
 * nonzero. The demo must prove itself.
 */

import { spawn } from 'node:child_process';
import { rmSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { performance } from 'node:perf_hooks';

/**
 * THE PLANTED SECRET — duplicated verbatim from demo/server.ts on purpose (not
 * imported). The blast-radius query is given only the leaked value, exactly as
 * a real responder would have only a rotated/exposed key. The recorder stores a
 * salted-free SHA-256 of every string leaf, so hashing this needle the same way
 * re-discovers the exfiltration call without ever storing the secret in clear.
 */
const PLANTED_SECRET = 'sk-demo-EXFILTRATION-c4n4ry-9f3a7b2e';

const ROOT = process.cwd();
const DATA_DIR = resolve(ROOT, 'demo-data');
const BUNDLE_DIR = resolve(DATA_DIR, 'bundle');

const WANT_UI = process.argv.includes('--ui');
/** `--policy FILE`: run the recorder in gateway mode (forwarded to demo/agent.ts via DEMO_POLICY). */
const POLICY_IDX = process.argv.indexOf('--policy');
const POLICY = POLICY_IDX >= 0 ? resolve(process.argv[POLICY_IDX + 1] ?? '') : undefined;

function out(msg: string): void {
  process.stderr.write(msg + '\n');
}

interface RunResult {
  code: number;
  stdout: string;
  stderr: string;
}

/** Spawn a command, capturing stdout/stderr; never rejects. */
function run(command: string, args: string[], opts: { cwd?: string; env?: NodeJS.ProcessEnv } = {}): Promise<RunResult> {
  return new Promise((resolveRun) => {
    const child = spawn(command, args, {
      cwd: opts.cwd ?? ROOT,
      env: opts.env ?? process.env,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (c: Buffer) => {
      stdout += c.toString('utf8');
    });
    child.stderr.on('data', (c: Buffer) => {
      stderr += c.toString('utf8');
    });
    child.on('error', (err) => {
      resolveRun({ code: 1, stdout, stderr: stderr + `\n[spawn error] ${err.message}` });
    });
    child.on('close', (code) => {
      resolveRun({ code: code ?? 1, stdout, stderr });
    });
  });
}

/** Indent multi-line tool output so it reads as a quoted block under the step. */
function quote(text: string): string {
  return text
    .split('\n')
    .filter((l) => l.length > 0)
    .map((l) => '    │ ' + l)
    .join('\n');
}

function elapsed(t0: number): string {
  return ((performance.now() - t0) / 1000).toFixed(1) + 's';
}

function fail(t0: number, msg: string): never {
  out(`\n✗ demo failed after ${elapsed(t0)}: ${msg}`);
  process.exit(1);
}

async function main(): Promise<void> {
  const t0 = performance.now();
  if (POLICY_IDX >= 0 && (process.argv[POLICY_IDX + 1] ?? '') === '') fail(t0, '--policy needs a file argument');

  out('=== @edut/mcp-recorder — prompt-injection exfiltration demo ===');
  out('(deterministic · no LLM · no network · the planted secret and leak are fake)\n');

  // Fresh data dir every run.
  if (existsSync(DATA_DIR)) rmSync(DATA_DIR, { recursive: true, force: true });

  /* ---------------------- [1/5] run the poisoned agent --------------------- */
  out(`[1/5] running poisoned agent session${POLICY !== undefined ? ` behind the gateway (policy ${POLICY})` : ''}… (${elapsed(t0)})`);
  const agentEnv = { ...process.env, DEMO_DATA_DIR: DATA_DIR, ...(POLICY !== undefined ? { DEMO_POLICY: POLICY } : {}) };
  const agent = await run('npx', ['tsx', 'demo/agent.ts'], { env: agentEnv });
  if (agent.stderr.trim()) out(quote(agent.stderr));
  if (agent.code !== 0) fail(t0, `agent exited ${agent.code}`);
  out(
    POLICY !== undefined
      ? '  ↳ gateway enforced: http_post denied, canary redacted before the agent saw it — all recorded into demo-data/\n'
      : '  ↳ recorder captured the session into demo-data/\n',
  );

  /* --------------------------- [2/5] verify chain -------------------------- */
  out(`[2/5] verifying the hash chain… (${elapsed(t0)})`);
  const verify = await run('npx', ['tsx', 'src/cli.ts', 'verify', '--data-dir', DATA_DIR]);
  const verifyText = (verify.stdout + verify.stderr).trim();
  if (verifyText) out(quote(verifyText));
  if (verify.code !== 0) fail(t0, `verify exited ${verify.code} (chain did not validate)`);
  out('  ↳ chain intact and signature valid\n');

  /* ----------------------- [3/5] blast-radius the secret ------------------- */
  out(`[3/5] blast-radius: who touched the secret? (${elapsed(t0)})`);
  out(`      needle = ${PLANTED_SECRET}`);
  const query = await run('npx', ['tsx', 'src/cli.ts', 'query', PLANTED_SECRET, '--data-dir', DATA_DIR]);
  const queryText = (query.stdout + query.stderr).trim();
  if (queryText) out(quote(queryText));
  if (query.code !== 0) fail(t0, `query exited ${query.code}`);
  // The demo must prove itself: zero matches means the recorder failed to
  // capture the exfiltration, which would make the whole story a lie.
  if (/\b0\b\s+match|no\s+match|matches?:\s*0|0\s+result/i.test(queryText) || !/match/i.test(queryText)) {
    fail(t0, 'blast-radius query found ZERO matches — the exfiltration was not captured');
  }
  out(
    POLICY !== undefined
      ? '  ↳ the hash of the canary matches the redacted read_file result — the http_post exfil never left the box\n'
      : '  ↳ the hash of the leaked secret matches the http_post exfil call\n',
  );

  /* ------------------- [4/5] export + standalone verification -------------- */
  out(`[4/5] exporting signed evidence bundle… (${elapsed(t0)})`);
  if (existsSync(BUNDLE_DIR)) rmSync(BUNDLE_DIR, { recursive: true, force: true });
  const exp = await run('npx', ['tsx', 'src/cli.ts', 'export', '--data-dir', DATA_DIR, '--dir', BUNDLE_DIR]);
  const expText = (exp.stdout + exp.stderr).trim();
  if (expText) out(quote(expText));
  if (exp.code !== 0) fail(t0, `export exited ${exp.code}`);
  if (!existsSync(BUNDLE_DIR)) fail(t0, `export did not produce a bundle directory at ${BUNDLE_DIR}`);

  // A stranger verifies the bundle with the dependency-free verify.cjs it ships.
  const verifierPath = resolve(BUNDLE_DIR, 'verify.cjs');
  if (!existsSync(verifierPath)) fail(t0, `bundle is missing verify.cjs at ${verifierPath}`);
  out('      verifying the exported bundle with its own verify.cjs…');
  const standalone = await run('node', ['verify.cjs'], { cwd: BUNDLE_DIR });
  const standaloneText = (standalone.stdout + standalone.stderr).trim();
  if (standaloneText) out(quote(standaloneText));
  if (standalone.code !== 0) fail(t0, `standalone bundle verification exited ${standalone.code}`);
  out('  ↳ a stranger can independently verify this bundle\n');

  /* ------------------------------ [5/5] done ------------------------------- */
  out(`[5/5] done in ${elapsed(t0)}.`);
  out('');
  out('Open the interactive replay with:');
  out(`  npx tsx src/cli.ts ui --data-dir ${'demo-data'}`);

  if (WANT_UI) {
    out('\nlaunching replay UI (Ctrl-C to stop)…');
    const ui = spawn('npx', ['tsx', 'src/cli.ts', 'ui', '--data-dir', DATA_DIR], {
      cwd: ROOT,
      env: process.env,
      stdio: 'inherit',
    });
    await new Promise<void>((resolveUi) => {
      ui.on('close', () => resolveUi());
      ui.on('error', () => resolveUi());
    });
  }
}

main().catch((err) => {
  out(`\n✗ demo crashed: ${err instanceof Error ? err.stack ?? err.message : String(err)}`);
  process.exit(1);
});
