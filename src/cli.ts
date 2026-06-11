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

import { readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { parseArgs } from 'node:util';

import { Recorder } from './capture/recorder.js';
import { Signer } from './chain/keys.js';
import { resolveConfig } from './config.js';
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
import { verifyRecords, verifyStore } from './verify/verify.js';
import { VERSION } from './version.js';

type Flags = Record<string, string | boolean | undefined>;

const SUBCOMMANDS = ['record', 'verify', 'query', 'sessions', 'ui', 'export', 'http'] as const;
type Subcommand = (typeof SUBCOMMANDS)[number];

const HELP = `@edut/mcp-recorder v${VERSION} — black-box flight recorder for MCP

Usage:
  mcp-recorder [record] [flags] -- <server command...>
      transparent stdio proxy: forwards bytes unchanged, records redacted events
  mcp-recorder verify   [--data-dir D] [--bundle PATH] [--json]
      verify the hash chain + head signatures (exit 1 on failure)
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
  process.stderr.write(`[mcp-recorder] ${msg}\n`);
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
 * fail-open: warn on stderr and continue as a pure passthrough.
 */
async function setupProxyRecording(config: RecorderConfig): Promise<ProxySetup> {
  const redactor = new Redactor({ mode: config.redactMode });
  let store: EvidenceStore | null = null;
  let signer: SignerLike | null = null;
  if (config.disabled) {
    diag('MCP_RECORDER_DISABLE=1 — recording disabled, pure passthrough');
  } else {
    try {
      store = openConfiguredStore(config);
      signer = await Signer.load(config.dataDir);
    } catch (cause) {
      const msg = cause instanceof Error ? cause.message : String(cause);
      diag(`recording disabled (init failed, traffic unaffected): ${msg}`);
      try {
        store?.close();
      } catch {
        /* fail-open */
      }
      store = null;
      signer = null;
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
  const config = resolveConfig({ flags, env: process.env });
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
  const config = resolveConfig({ flags, env: process.env });
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

function printVerifyHuman(result: VerifyResult, source: string): void {
  out(`verify ${source}`);
  if (result.ok) {
    out(`PASS — chain intact: ${result.checked_events} event(s), head seq ${result.head.seq}`);
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

async function verifyBundleDir(dirPath: string): Promise<{ result: VerifyResult; source: string }> {
  const dir = resolve(dirPath);
  const manifest = JSON.parse(readFileSync(join(dir, 'manifest.json'), 'utf8')) as BundleManifest;
  if (manifest.bundle !== 'edut.mcp-recorder.bundle.v1') {
    err(`unrecognized bundle id in ${join(dir, 'manifest.json')}: ${String(manifest.bundle)}`);
  }
  const records = readFileSync(join(dir, 'events.jsonl'), 'utf8')
    .split('\n')
    .filter((line) => line.trim() !== '')
    .map((line) => JSON.parse(line) as ChainRecord);
  const result = await verifyRecords(records, [manifest.signature], {
    baseHash: manifest.base_hash,
    expectedPublicKeyHex: manifest.signature.public_key,
  });
  return { result, source: `bundle ${dir}` };
}

async function cmdVerify(flags: Flags): Promise<void> {
  let result: VerifyResult;
  let source: string;
  const bundle = asStr(flags.bundle);
  if (bundle !== undefined) {
    ({ result, source } = await verifyBundleDir(bundle));
  } else {
    const config = resolveConfig({ flags, env: process.env });
    const store = openConfiguredStore(config);
    try {
      result = await verifyStore(store);
      source = `store ${store.path} (${store.backend})`;
    } finally {
      store.close();
    }
  }
  if (flags.json === true) {
    out(JSON.stringify(result, null, 2));
  } else {
    printVerifyHuman(result, source);
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
  process.stderr.write(`[mcp-recorder] error: ${msg}\n`);
  process.exit(2);
});
