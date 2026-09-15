#!/usr/bin/env node
/**
 * mcp-recorder CLI — subcommand dispatch.
 *
 * record / http modes NEVER print to stdout (stdout is the MCP wire);
 * diagnostics go to stderr prefixed "[mcp-recorder]". Inspection commands
 * (verify/query/sessions) print human or --json output on stdout.
 *
 * Exit codes: 0 ok (record/http: the wrapped server's code), 1 verification
 * failed / nothing to export, 2 usage or unexpected error.
 */

import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { parseArgs } from 'node:util';

import { Recorder } from './capture/recorder.js';
import { Signer, publicKeyHexFromPem } from './chain/keys.js';
import { ensureDataDir, resolveConfig, resolveConfigLenient } from './config.js';
import { exportBundle } from './export/bundle.js';
import { runHttpProxy } from './proxy/http.js';
import { runStdioProxy } from './proxy/stdio.js';
import { queryStore } from './query/touched.js';
import { Redactor } from './redact/redactor.js';
import { renderTimelineHtml } from './replay/render.js';
import { serveUi } from './replay/serve.js';
import { openStore } from './store/index.js';
import type { AnyEvent, ChainRecord } from './schema/events.js';
import type {
  BundleManifest,
  EvidenceStore,
  RecorderConfig,
  RecorderLike,
  SignerLike,
  VerifyResult,
} from './types.js';
import { FILES } from './types.js';
import { verifyRecords, verifyStore } from './verify/verify.js';
import type { VerifyOpts } from './verify/verify.js';
import { VERSION } from './version.js';

type Flags = Record<string, string | boolean | undefined>;

const SUBCOMMANDS = ['record', 'verify', 'query', 'sessions', 'ui', 'export', 'http'] as const;
type Subcommand = (typeof SUBCOMMANDS)[number];

const HELP = `@edut/mcp-recorder v${VERSION} — black-box flight recorder for MCP

Usage:
  mcp-recorder [record] [flags] -- <server command...>
      transparent stdio proxy: forwards bytes unchanged, records redacted events
  mcp-recorder verify   [--data-dir D] [--bundle PATH] [--public-key K] [--allow-unsigned] [--json]
      verify the hash chain + head signatures (exit 1 on failure)
      by default pins to <data-dir>/identity.pub (store mode) or the
      bundle's own manifest key (bundle mode); --public-key overrides
      either with a key obtained out of band (64-hex, or a path to a
      hex or PEM file)
  mcp-recorder query    <needle> [--data-dir D] [--session ID] [--json]
      blast radius: trace a value through the evidence chain
  mcp-recorder sessions [--data-dir D] [--json]
      list recorded sessions
  mcp-recorder ui       [--data-dir D] [--session ID] [--port N] [--out FILE] [--no-open]
      replay timeline (local web UI, or --out FILE for a static page)
  mcp-recorder export   [--data-dir D] [--session ID] [--out FILE.zip] [--dir DIR]
      signed evidence bundle a stranger can verify with plain Node.js
  mcp-recorder http     --target URL [--port N] [flags]
      transparent streamable-HTTP proxy in front of an HTTP MCP server
  mcp-recorder --help | --version

Flags:
  --data-dir D   evidence directory (default ~/.mcp-recorder; env MCP_RECORDER_DATA_DIR)
  --store B      evidence backend: sqlite | jsonl     (env MCP_RECORDER_STORE)
  --redact M     redaction mode: allowlist | off      (env MCP_RECORDER_REDACT)
  --name NAME    logical server name stamped on events
  --identity L   operator identity label stamped on events
  --public-key K pin verify to this ed25519 key instead of the default
                 (64-hex, or a path to a file holding hex or a PEM)
  --allow-unsigned
                 verify: downgrade an unsigned chain/tail to a warning
                 instead of a failure (still reported, never silent)
  --json         machine-readable output (verify / query / sessions)

Environment:
  MCP_RECORDER_DISABLE=1   pure passthrough, nothing recorded
`;

const FLAG_DEFS = {
  'data-dir': { type: 'string' },
  store: { type: 'string' },
  redact: { type: 'string' },
  name: { type: 'string' },
  identity: { type: 'string' },
  session: { type: 'string' },
  port: { type: 'string' },
  out: { type: 'string' },
  dir: { type: 'string' },
  bundle: { type: 'string' },
  target: { type: 'string' },
  'public-key': { type: 'string' },
  'allow-unsigned': { type: 'boolean' },
  json: { type: 'boolean' },
  'no-open': { type: 'boolean' },
  help: { type: 'boolean', short: 'h' },
  version: { type: 'boolean', short: 'V' },
} as const;

/* -------------------------------- helpers ------------------------------- */

function err(msg: string): never {
  throw new Error(msg);
}

function diag(msg: string): void {
  try {
    process.stderr.write(`[mcp-recorder] ${msg}\n`);
  } catch {
    /* even diagnostics are fail-open */
  }
}

/**
 * Last-resort safety net for record/http mode: an exception that somehow
 * escapes every other fail-open guard must never take the wrapped server's
 * traffic down with it. Logs once, best-effort, and keeps the process alive.
 */
let uncaughtGuardInstalled = false;
let uncaughtLogged = false;
function installUncaughtExceptionGuard(): void {
  if (uncaughtGuardInstalled) return;
  uncaughtGuardInstalled = true;
  process.on('uncaughtException', (error: unknown) => {
    if (uncaughtLogged) return;
    uncaughtLogged = true;
    const detail = error instanceof Error ? (error.stack ?? error.message) : String(error);
    diag(`uncaught exception (recording degraded, traffic unaffected): ${detail}`);
  });
}

function out(msg: string): void {
  process.stdout.write(msg + '\n');
}

function asStr(v: string | boolean | undefined): string | undefined {
  return typeof v === 'string' ? v : undefined;
}

function parsePort(v: string | boolean | undefined): number | undefined {
  const s = asStr(v);
  if (s === undefined) return undefined;
  const n = Number(s);
  if (!Number.isInteger(n) || n < 0 || n > 65535) err(`invalid --port '${s}'`);
  return n;
}

const HEX64 = /^[0-9a-f]{64}$/i;

/**
 * Resolve `verify --public-key <value>` to a 64-hex raw ed25519 public key.
 * `value` is either the hex itself, or a path to a file holding either the
 * hex or an SPKI PEM (the same file identity.pub or public_key.pem already
 * are) — this is how a third party pins a key they obtained out of band,
 * rather than trusting whatever key ships alongside the data being checked.
 */
function resolvePublicKeyArg(value: string): string {
  const trimmed = value.trim();
  if (HEX64.test(trimmed)) return trimmed.toLowerCase();
  let content: string;
  try {
    content = readFileSync(resolve(trimmed), 'utf8');
  } catch (cause) {
    const msg = cause instanceof Error ? cause.message : String(cause);
    return err(`--public-key '${value}' is neither 64-hex nor a readable file: ${msg}`);
  }
  const text = content.trim();
  if (HEX64.test(text)) return text.toLowerCase();
  if (text.includes('BEGIN PUBLIC KEY')) {
    try {
      return publicKeyHexFromPem(text);
    } catch (cause) {
      const msg = cause instanceof Error ? cause.message : String(cause);
      return err(`--public-key file '${value}' is not a valid ed25519 public key PEM: ${msg}`);
    }
  }
  return err(`--public-key file '${value}' is neither 64-hex nor a PEM public key`);
}

function formatTable(headers: string[], rows: string[][]): string {
  const widths = headers.map((h, i) =>
    Math.max(h.length, ...rows.map((r) => (r[i] ?? '').length)),
  );
  const line = (cells: string[]): string =>
    cells.map((c, i) => (c ?? '').padEnd(widths[i] ?? 0)).join('  ').trimEnd();
  return [line(headers), ...rows.map(line)].join('\n');
}

function id8(id: string): string {
  return id.slice(0, 8);
}

function openConfiguredStore(config: RecorderConfig): EvidenceStore {
  return openStore(
    config.storeBackend !== undefined
      ? { dataDir: config.dataDir, backend: config.storeBackend }
      : { dataDir: config.dataDir },
  );
}

/** Wrap a recorder so the CLI learns the session id of the first event. */
function tapSessionId(recorder: Recorder): { recorder: RecorderLike; sessionId(): string | undefined } {
  let sessionId: string | undefined;
  const wrapped: RecorderLike = {
    record(event: AnyEvent): void {
      if (sessionId === undefined) sessionId = event.session_id;
      recorder.record(event);
    },
    flush: () => recorder.flush(),
    close: () => recorder.close(),
    stats: () => recorder.stats(),
  };
  return { recorder: wrapped, sessionId: () => sessionId };
}

interface ProxySetup {
  recorder: RecorderLike;
  redactor: Redactor;
  sessionId(): string | undefined;
  storePath: string | undefined;
  stats(): { written: number; dropped: number };
}

/**
 * Build redactor/store/signer/recorder for a proxy run. ANY init failure is
 * fail-open: warn on stderr and continue as a pure passthrough. This is also
 * where the data directory gets created (moved out of config resolution —
 * see config.ts) so a bad --data-dir/MCP_RECORDER_DATA_DIR degrades to pure
 * passthrough here instead of throwing before the wrapped server can spawn.
 *
 * Store and signer failures are handled separately: a store that can't be
 * opened means nothing can be recorded (full passthrough). A signer that
 * can't be loaded (e.g. a corrupt identity.key) still leaves the store
 * usable — recording continues, just without head signatures.
 */
async function setupProxyRecording(config: RecorderConfig): Promise<ProxySetup> {
  const redactor = new Redactor({ mode: config.redactMode });
  let store: EvidenceStore | null = null;
  let signer: SignerLike | null = null;
  if (config.disabled) {
    diag('MCP_RECORDER_DISABLE=1 — recording disabled, pure passthrough');
  } else {
    try {
      ensureDataDir(config.dataDir);
      store = openConfiguredStore(config);
    } catch (cause) {
      const msg = cause instanceof Error ? cause.message : String(cause);
      diag(`recording disabled (init failed, traffic unaffected): ${msg}`);
      try {
        store?.close();
      } catch {
        /* fail-open */
      }
      store = null;
    }
    if (store !== null) {
      try {
        signer = await Signer.load(config.dataDir);
      } catch (cause) {
        const msg = cause instanceof Error ? cause.message : String(cause);
        diag(`recording without head signatures (identity key init failed): ${msg}`);
        signer = null;
      }
    }
  }
  const inner = new Recorder({ store, signer });
  const { recorder, sessionId } = tapSessionId(inner);
  return {
    recorder,
    redactor,
    sessionId,
    storePath: store?.path,
    stats: () => inner.stats(),
  };
}

function writeRunSummary(setup: ProxySetup): void {
  const stats = setup.stats();
  const sid = setup.sessionId();
  diag(
    `session ${sid !== undefined ? id8(sid) : '--------'} recorded ${stats.written} events ` +
      `(${stats.dropped} dropped) -> ${setup.storePath ?? '(recording disabled)'}`,
  );
}

/**
 * Block until SIGINT/SIGTERM. Holds the event loop open itself (signal
 * listeners alone do not), so it also covers unref()'d servers like the UI's.
 */
function waitForShutdownSignal(): Promise<void> {
  return new Promise((resolveWait) => {
    const keepAlive = setInterval(() => {
      /* keep the event loop alive */
    }, 60_000);
    const onSignal = (): void => {
      clearInterval(keepAlive);
      resolveWait();
    };
    process.once('SIGINT', onSignal);
    process.once('SIGTERM', onSignal);
  });
}

/* ------------------------------ subcommands ------------------------------ */

async function cmdRecord(flags: Flags, serverCommand: string[]): Promise<void> {
  if (serverCommand.length === 0) {
    err("record: missing server command (usage: mcp-recorder [record] [flags] -- <command...>)");
  }
  installUncaughtExceptionGuard();
  // Lenient: nothing about recording configuration may prevent the wrapped
  // server from spawning. Bad --redact/--store values fall back to defaults.
  const { config, warnings } = resolveConfigLenient({ flags, env: process.env });
  for (const w of warnings) diag(w);
  const setup = await setupProxyRecording(config);

  const exitCode = await runStdioProxy({
    command: serverCommand,
    recorder: setup.recorder,
    redactor: setup.redactor,
    ...(config.serverName !== undefined ? { serverName: config.serverName } : {}),
    ...(config.identityLabel !== undefined ? { identityLabel: config.identityLabel } : {}),
    proxyVersion: VERSION,
  });
  writeRunSummary(setup);
  process.exit(exitCode);
}

async function cmdHttp(flags: Flags): Promise<void> {
  const targetUrl = asStr(flags.target) ?? err('http: --target URL is required');
  const port = parsePort(flags.port);
  installUncaughtExceptionGuard();
  // Lenient: nothing about recording configuration may prevent the proxy
  // from standing up. Bad --redact/--store values fall back to defaults.
  const { config, warnings } = resolveConfigLenient({ flags, env: process.env });
  for (const w of warnings) diag(w);
  const setup = await setupProxyRecording(config);

  const proxy = await runHttpProxy({
    targetUrl,
    ...(port !== undefined ? { port } : {}),
    recorder: setup.recorder,
    redactor: setup.redactor,
    ...(config.serverName !== undefined ? { serverName: config.serverName } : {}),
    ...(config.identityLabel !== undefined ? { identityLabel: config.identityLabel } : {}),
    proxyVersion: VERSION,
  });
  diag(`http proxy listening at ${proxy.url} -> ${targetUrl} (Ctrl-C to stop)`);
  await waitForShutdownSignal();
  await proxy.close();
  writeRunSummary(setup);
  process.exit(0);
}

/** Which key `verify` pinned signatures to, and where it came from. */
interface PinnedKey {
  hex: string;
  /** Human-readable provenance, e.g. a file path or '--public-key'. */
  source: string;
}

function printVerifyHuman(result: VerifyResult, source: string, pinned?: PinnedKey): void {
  out(`verify ${source}`);
  if (pinned !== undefined) {
    out(`pinned signer: ed25519 ${pinned.hex.slice(0, 16)}… (${pinned.source})`);
  }
  // A warning-only chain (an unsigned tail we chose to tolerate) still says
  // PASS, but distinctly — it's a weaker guarantee than a fully-signed chain.
  const hasWarning = result.problems.some((p) => p.warning === true);
  if (result.ok) {
    out(
      `${hasWarning ? 'PASS (unsigned tail)' : 'PASS'} — chain intact: ${result.checked_events} event(s), head seq ${result.head.seq}`,
    );
  } else {
    out(`FAIL — evidence does NOT verify: ${result.checked_events} event(s) checked`);
  }
  const sig = result.verified_signature;
  if (sig !== undefined) {
    out(`signed head: seq ${sig.seq} by ed25519 ${sig.public_key.slice(0, 16)}… at ${sig.signed_at}`);
  }
  if (result.problems.length > 0) {
    out('');
    out(
      formatTable(
        ['TYPE', 'SEQ', 'DETAIL'],
        result.problems.map((p) => [
          p.type + (p.warning === true ? ' (warning)' : ''),
          String(p.seq),
          p.detail,
        ]),
      ),
    );
  }
}

/**
 * `pinOpts.expectedPublicKeyHex`, when passed, overrides the tautological
 * default of pinning to the bundle's own manifest key — that only proves the
 * bundle is internally self-consistent, not that it came from anyone in
 * particular. A third party who obtained the real key out of band should
 * pass it via --public-key instead.
 */
async function verifyBundleDir(
  dirPath: string,
  pinOpts: Pick<VerifyOpts, 'expectedPublicKeyHex' | 'allowUnsigned'> = {},
): Promise<{ result: VerifyResult; source: string; pinnedPublicKeyHex: string }> {
  const dir = resolve(dirPath);
  const manifest = JSON.parse(readFileSync(join(dir, 'manifest.json'), 'utf8')) as BundleManifest;
  if (manifest.bundle !== 'edut.mcp-recorder.bundle.v1') {
    err(`unrecognized bundle id in ${join(dir, 'manifest.json')}: ${String(manifest.bundle)}`);
  }
  const records = readFileSync(join(dir, 'events.jsonl'), 'utf8')
    .split('\n')
    .filter((line) => line.trim() !== '')
    .map((line) => JSON.parse(line) as ChainRecord);
  const pinnedPublicKeyHex = pinOpts.expectedPublicKeyHex ?? manifest.signature.public_key;
  const result = await verifyRecords(records, [manifest.signature], {
    baseHash: manifest.base_hash,
    expectedPublicKeyHex: pinnedPublicKeyHex,
    ...(pinOpts.allowUnsigned !== undefined ? { allowUnsigned: pinOpts.allowUnsigned } : {}),
  });
  return { result, source: `bundle ${dir}`, pinnedPublicKeyHex };
}

async function cmdVerify(flags: Flags): Promise<void> {
  const allowUnsigned = flags['allow-unsigned'] === true;
  const publicKeyFlag = asStr(flags['public-key']);
  const explicitPublicKeyHex =
    publicKeyFlag !== undefined ? resolvePublicKeyArg(publicKeyFlag) : undefined;

  let result: VerifyResult;
  let source: string;
  let pinned: PinnedKey | undefined;

  const bundle = asStr(flags.bundle);
  if (bundle !== undefined) {
    const bundleResult = await verifyBundleDir(bundle, {
      ...(explicitPublicKeyHex !== undefined ? { expectedPublicKeyHex: explicitPublicKeyHex } : {}),
      allowUnsigned,
    });
    result = bundleResult.result;
    source = bundleResult.source;
    pinned = {
      hex: bundleResult.pinnedPublicKeyHex,
      source:
        explicitPublicKeyHex !== undefined
          ? '--public-key'
          : "bundle's own manifest.json — self-pinned; pass --public-key with a key " +
            'obtained out of band for independent assurance',
    };
  } else {
    const config = resolveConfig({ flags, env: process.env });
    const store = openConfiguredStore(config);
    try {
      let expectedPublicKeyHex = explicitPublicKeyHex;
      let pinSource = '--public-key';
      if (expectedPublicKeyHex === undefined) {
        // Default pin: this data dir's own identity.pub, so a chain rewritten
        // and re-signed with a fresh, unrelated key is rejected instead of
        // silently accepted — see README "Security model".
        const pubPath = join(config.dataDir, FILES.PUBLIC_KEY);
        if (existsSync(pubPath)) {
          expectedPublicKeyHex = readFileSync(pubPath, 'utf8').trim().toLowerCase();
          pinSource = pubPath;
        }
      }
      const verifyOpts: VerifyOpts = { allowUnsigned };
      if (expectedPublicKeyHex !== undefined) verifyOpts.expectedPublicKeyHex = expectedPublicKeyHex;
      result = await verifyStore(store, verifyOpts);
      source = `store ${store.path} (${store.backend})`;
      if (expectedPublicKeyHex !== undefined) pinned = { hex: expectedPublicKeyHex, source: pinSource };
    } finally {
      store.close();
    }
  }

  if (flags.json === true) {
    const payload =
      pinned !== undefined
        ? { ...result, pinned_public_key: pinned.hex, pinned_public_key_source: pinned.source }
        : result;
    out(JSON.stringify(payload, null, 2));
  } else {
    printVerifyHuman(result, source, pinned);
  }
  if (!result.ok) process.exitCode = 1;
}

async function cmdQuery(flags: Flags, positionals: string[]): Promise<void> {
  const needle = positionals[0] ?? err('query: missing <needle> argument');
  const config = resolveConfig({ flags, env: process.env });
  const store = openConfiguredStore(config);
  try {
    const sessionId = asStr(flags.session);
    const result = queryStore(store, needle, sessionId !== undefined ? { sessionId } : {});
    if (flags.json === true) {
      out(JSON.stringify(result, null, 2));
      return;
    }
    if (result.matches.length > 0) {
      out(
        formatTable(
          ['TIMESTAMP', 'KIND', 'NAME', 'SESSION', 'MATCHED_ON', 'PATH'],
          result.matches.map((m) => [
            m.timestamp,
            m.kind,
            m.name ?? '',
            id8(m.session_id),
            m.matched_on,
            m.path,
          ]),
        ),
      );
      out('');
    }
    out(`${result.matches.length} matches across ${result.sessions.length} sessions`);
  } finally {
    store.close();
  }
}

async function cmdSessions(flags: Flags): Promise<void> {
  const config = resolveConfig({ flags, env: process.env });
  const store = openConfiguredStore(config);
  try {
    const sessions = store.sessions();
    if (flags.json === true) {
      out(JSON.stringify(sessions, null, 2));
      return;
    }
    if (sessions.length === 0) {
      out('no sessions recorded');
      return;
    }
    out(
      formatTable(
        ['SESSION', 'STARTED', 'ENDED', 'SERVER', 'EVENTS', 'TOOL_CALLS', 'ERRORS'],
        sessions.map((s) => [
          id8(s.session_id),
          s.started_at,
          s.ended_at ?? '(open)',
          s.server_name,
          String(s.event_count),
          String(s.tool_call_count),
          String(s.error_count),
        ]),
      ),
    );
  } finally {
    store.close();
  }
}

async function cmdUi(flags: Flags): Promise<void> {
  const config = resolveConfig({ flags, env: process.env });
  const store = openConfiguredStore(config);
  const sessionId = asStr(flags.session);
  const outFile = asStr(flags.out);
  try {
    const verify = await verifyStore(store);
    if (outFile !== undefined) {
      const html = renderTimelineHtml(store, {
        ...(sessionId !== undefined ? { sessionId } : {}),
        verify,
      });
      writeFileSync(outFile, html);
      diag(`wrote replay page to ${resolve(outFile)}`);
      return;
    }
    const port = parsePort(flags.port) ?? 0;
    const ui = await serveUi({
      store,
      verify,
      port,
      ...(sessionId !== undefined ? { sessionId } : {}),
    });
    // --no-open accepted for compat; we never spawn a browser, only print.
    diag(`replay UI at ${ui.url} (Ctrl-C to stop)`);
    await waitForShutdownSignal();
    await ui.close();
  } finally {
    store.close();
  }
}

function exportTimestamp(now: Date): string {
  const p = (n: number): string => String(n).padStart(2, '0');
  return (
    `${now.getFullYear()}${p(now.getMonth() + 1)}${p(now.getDate())}` +
    `-${p(now.getHours())}${p(now.getMinutes())}${p(now.getSeconds())}`
  );
}

async function cmdExport(flags: Flags): Promise<void> {
  const config = resolveConfig({ flags, env: process.env });
  const store = openConfiguredStore(config);
  try {
    if (store.count() === 0) {
      diag('error: nothing to export — the evidence store is empty');
      process.exitCode = 1;
      return;
    }
    const dirPath = asStr(flags.dir);
    const zipPath =
      asStr(flags.out) ??
      (dirPath === undefined
        ? `./mcp-recorder-bundle-${exportTimestamp(new Date())}.zip`
        : undefined);
    const sessionId = asStr(flags.session);
    const signer = await Signer.load(config.dataDir);

    const manifest = await exportBundle({
      store,
      signer,
      toolVersion: VERSION,
      ...(sessionId !== undefined ? { sessionId } : {}),
      ...(zipPath !== undefined ? { zipPath } : {}),
      ...(dirPath !== undefined ? { dirPath } : {}),
    });

    diag(
      `exported ${manifest.event_count} event(s) (seq ${manifest.range.from_seq}..${manifest.range.to_seq})` +
        (manifest.session_id !== undefined ? ` of session ${id8(manifest.session_id)}` : '') +
        `, head ${manifest.head_hash.slice(0, 16)}… signed by ed25519 ${manifest.signature.public_key.slice(0, 16)}…`,
    );
    if (zipPath !== undefined) diag(`bundle zip: ${resolve(zipPath)}`);
    if (dirPath !== undefined) diag(`bundle dir: ${resolve(dirPath)}`);
    diag('verify anywhere with: node verify.cjs (inside the bundle)');
  } finally {
    store.close();
  }
}

/* -------------------------------- dispatch ------------------------------- */

async function main(): Promise<void> {
  const argv = process.argv.slice(2);
  const sepIdx = argv.indexOf('--');
  const pre = sepIdx >= 0 ? argv.slice(0, sepIdx) : argv;
  const serverCommand = sepIdx >= 0 ? argv.slice(sepIdx + 1) : [];

  const named = SUBCOMMANDS.includes(pre[0] as Subcommand) ? (pre[0] as Subcommand) : undefined;
  const flagArgs = named !== undefined ? pre.slice(1) : pre;

  const { values: flags, positionals } = parseArgs({
    args: flagArgs,
    options: FLAG_DEFS,
    allowPositionals: true,
    strict: true,
  });

  if (flags.version === true) {
    out(VERSION);
    return;
  }
  if (flags.help === true) {
    out(HELP);
    return;
  }

  let sub: Subcommand;
  if (named !== undefined) {
    sub = named;
  } else if (sepIdx >= 0) {
    sub = 'record'; // default subcommand when '--' is present
    if (positionals.length > 0) {
      err(`unexpected argument '${positionals[0]}' before '--' (did you mean a flag?)`);
    }
  } else if (positionals.length > 0) {
    err(`unknown subcommand '${positionals[0]}' (try 'mcp-recorder --help')`);
  } else {
    process.stderr.write(HELP);
    process.exitCode = 2;
    return;
  }

  switch (sub) {
    case 'record':
      return cmdRecord(flags, serverCommand);
    case 'verify':
      return cmdVerify(flags);
    case 'query':
      return cmdQuery(flags, positionals);
    case 'sessions':
      return cmdSessions(flags);
    case 'ui':
      return cmdUi(flags);
    case 'export':
      return cmdExport(flags);
    case 'http':
      return cmdHttp(flags);
  }
}

main().catch((cause: unknown) => {
  const msg = cause instanceof Error ? cause.message : String(cause);
  diag(`error: ${msg}`);
  process.exit(2);
});
