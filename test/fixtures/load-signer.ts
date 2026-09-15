/**
 * Cross-process race fixture for test/keys.test.ts's "parallel Signer.load"
 * test.
 *
 * Within a single Node process, `Promise.all([Signer.load(dir), ...])`
 * cannot actually race two calls against the filesystem: `Signer.load`'s
 * only truly async step is the `await` boundary at the top of the function
 * (there is none until the `mkdirSync`/`writeFileSync` calls, which are all
 * synchronous), so the microtask queue serializes every call's synchronous
 * section, and the first call's `writeFileSync(..., { flag: 'wx' })` always
 * completes before the second call's `existsSync` check ever runs. That
 * lets a single-process test pass even against the pre-fix code, which had
 * the same `existsSync` + plain `writeFileSync` TOCTOU race this fixture is
 * meant to expose: several real OS processes calling `Signer.load` on the
 * same brand-new data dir at once.
 *
 * Run standalone (spawned by the test, one process per concurrent
 * `Signer.load`): loads/creates the identity in the given data dir and
 * prints nothing but its public key hex (plus a trailing newline) to
 * stdout.
 */
import { Signer } from '../../src/chain/keys.js';

async function main(): Promise<void> {
  const dataDir = process.argv[2];
  if (!dataDir) {
    process.stderr.write('usage: load-signer.ts <dataDir>\n');
    process.exit(2);
  }

  // Barrier: process spawn + TypeScript-transform startup time (tsx/esbuild)
  // varies a lot between otherwise-identical child processes — far more
  // than Signer.load's own critical section takes. Left alone, that jitter
  // spreads the N children's calls out over tens of milliseconds, so they
  // rarely actually contend on the empty dir. Signal readiness, then block
  // for the test harness's single "go" write, so all children reach
  // Signer.load as close together as the OS can schedule them, regardless
  // of how long each took to start up.
  process.stdout.write('ready\n');
  await new Promise<void>((resolve) => {
    process.stdin.once('data', () => resolve());
  });

  const signer = await Signer.load(dataDir);
  process.stdout.write(signer.publicKeyHex + '\n');
}

main().catch((err: unknown) => {
  process.stderr.write((err instanceof Error ? (err.stack ?? err.message) : String(err)) + '\n');
  process.exit(1);
});
