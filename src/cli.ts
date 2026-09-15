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

import { spawn } from 'node:child_process';
import { existsSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';

import { Recorder } from './capture/recorder.js';
import { Signer, publicKeyHexFromPem } from './chain/keys.js';
import { ensureDataDir, resolveConfig, resolveConfigLenient } from './config.js';
import { BUNDLE_FILES, exportBundle } from './export/bundle.js';
import { readZipEntries } from './export/unzip.js';
import { runHttpProxy } from './proxy/http.js';
import { runStdioProxy } from './proxy/stdio.js';
import { queryStore } from './query/touched.js';
import { Redactor } from './redact/redactor.js';
import { renderTimelineHtml } from './replay/render.js';
import { serveUi } from './replay/serve.js';
import { CLIENT_KINDS, isClientKind, resolveClientConfigPath } from './setup/client-config.js';
import type { ClientKind } from './setup/client-config.js';
import {
  detectEol,
  detectIndent,
  readSidecarStrict,
  removeSidecar,
  sidecarPath,
  stripBom,
  writeBackup,
  writeJsonAtomic,
  writeSidecarAtomic,
} from './setup/io.js';
import type { SetupSidecar } from './setup/io.js';
import { chooseWrapper, detectWsl, isWindowsMountPath, windowsHomeCandidates } from './setup/wsl.js';
import type { WrapperChoice } from './setup/wsl.js';
import {
  bridgeEntry,
  isAlreadyWrapped,
  isSameBridgeEntry,
  parseBridgeSpecs,
  planWrap,
  structuralUnwrap,
} from './setup/wrap.js';
import type { BridgeSpec, McpServersMap, SkipEntry, WrapOpts, WrapPlan } from './setup/wrap.js';
import { openStore, openStoreReadOnly } from './store/index.js';
import type { AnyEvent, ChainRecord } from './schema/events.js';
import type {
  BundleManifest,
  EvidenceStore,
  RecorderConfig,
  RecorderLike,
  SignerLike,
  VerifyProblem,
  VerifyResult,
} from './types.js';
import { FILES } from './types.js';
import { verifyRecords, verifyStore } from './verify/verify.js';
import type { VerifyOpts } from './verify/verify.js';
import { VERSION } from './version.js';

type Flags = Record<string, string | boolean | string[] | undefined>;

const SUBCOMMANDS = ['record', 'verify', 'query', 'sessions', 'ui', 'export', 'http', 'setup'] as const;
type Subcommand = (typeof SUBCOMMANDS)[number];

const HELP = `@edut/mcp-recorder v${VERSION} — black-box flight recorder for MCP

Usage:
  mcp-recorder [record] [flags] -- <server command...>
      transparent stdio proxy: forwards bytes unchanged, records redacted events
  mcp-recorder verify   [--data-dir D] [--bundle PATH] [--public-key K] [--allow-unsigned] [--json]
      verify the hash chain + head signatures (exit 1 on failure); --bundle
      accepts a .zip or a bundle directory. By default pins to
      <data-dir>/identity.pub (store mode) or the bundle's own manifest key
      (bundle mode); --public-key overrides either with a key obtained out
      of band (64-hex, or a path to a hex or PEM file)
  mcp-recorder query    <needle> [--data-dir D] [--session ID] [--json]
      blast radius: trace a value through the evidence chain
  mcp-recorder sessions [--data-dir D] [--json]
      list recorded sessions
  mcp-recorder ui       [--data-dir D] [--session ID] [--port N] [--out FILE] [--no-open]
                        [--public-key K] [--allow-unsigned]
      replay timeline (local web UI, opened in your browser unless --no-open
      or --out is given; or --out FILE for a static page). The integrity
      banner uses the same pin as 'verify' (identity.pub by default)
  mcp-recorder export   [--data-dir D] [--session ID] [--out FILE.zip] [--dir DIR]
      signed evidence bundle a stranger can verify with plain Node.js
  mcp-recorder http     --target URL [--port N] [flags]
      transparent streamable-HTTP proxy in front of an HTTP MCP server
  mcp-recorder setup    --client <claude-desktop|claude-code|cursor> [--config PATH]
                        [--wrapper local|npx|wsl] [--only N,...] [--except N,...]
                        [--bridge NAME=URL,...] [--data-dir D] [--dry-run] [--undo] [--json]
      wrap every stdio MCP server in a client's config behind this recorder,
      safely (timestamped backup + sidecar) and reversibly (--undo). --config
      overrides the resolved path and makes --client optional. For
      claude-desktop this also finds a Microsoft Store (MSIX) install when
      the ordinary %APPDATA%\\Claude\\... config doesn't exist. Inside WSL,
      when the resolved config belongs to a Windows-side client, --wrapper
      wsl is auto-selected (spawns the wrapped server via wsl.exe so a
      Windows client can actually launch it) unless --wrapper is given.
      --bridge NAME=URL turns a remote MCP connector (one Claude Desktop
      would otherwise reach from Anthropic's own servers, never touching
      this machine) into a local entry via 'npx -y mcp-remote URL', then
      wraps that like any other stdio server
  mcp-recorder --help | --version

Flags:
  --data-dir D    evidence directory (default ~/.mcp-recorder; env MCP_RECORDER_DATA_DIR)
  --store B       evidence backend: sqlite | jsonl     (env MCP_RECORDER_STORE)
  --redact M      redaction mode: allowlist | off      (env MCP_RECORDER_REDACT)
  --name NAME     logical server name stamped on events
  --identity L    operator identity label stamped on events
  --session ID    select a session (query / ui / export); a unique prefix of
                   the id works too, same as the ids 'sessions' prints
  --public-key K  pin verify to this ed25519 key instead of the default
                   (64-hex, or a path to a file holding hex or a PEM)
  --allow-unsigned
                   verify: downgrade an unsigned chain/tail to a warning
                   instead of a failure (still reported, never silent)
  --json          machine-readable output (verify / query / sessions / setup)
  --client C      setup: claude-desktop | claude-code | cursor
  --config PATH   setup: config file to edit (overrides --client's default)
  --wrapper W     setup: local (default, this install) | npx (published form) |
                   wsl (wsl.exe, auto-selected for a Windows-side config in WSL)
  --only N,...    setup: wrap only these server names
  --except N,...  setup: wrap every server except these names
  --bridge NAME=URL[,...]
                   setup: bridge a remote MCP connector as a local NAME
                   entry (via npx -y mcp-remote URL), repeatable
  --dry-run       setup: print what would change; write nothing
  --undo          setup: restore the servers this tool wrapped
  --help, -h      show this help and exit
  --version, -V   show the version and exit

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
  client: { type: 'string' },
  config: { type: 'string' },
  wrapper: { type: 'string' },
  only: { type: 'string' },
  except: { type: 'string' },
  bridge: { type: 'string', multiple: true },
  'dry-run': { type: 'boolean' },
  undo: { type: 'boolean' },
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

function asStr(v: string | boolean | string[] | undefined): string | undefined {
  return typeof v === 'string' ? v : undefined;
}

/** `--bridge` collects into a string[] (`multiple: true`); every other flag
 * this returns undefined for, same as `asStr` does for a non-string. */
function asStrArr(v: string | boolean | string[] | undefined): string[] {
  return Array.isArray(v) ? v : [];
}

function parsePort(v: string | boolean | string[] | undefined): number | undefined {
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

/**
 * `readOnly: true` (used by the inspection commands — verify/query/sessions/
 * ui/export) resolves the backend without ever creating a store file as a
 * side effect of merely looking: on a data dir where nothing has recorded
 * yet, it returns an empty store instead of the write path's "create
 * whichever backend is available" behavior (see src/store/index.ts).
 */
function openConfiguredStore(config: RecorderConfig, opts: { readOnly?: boolean } = {}): EvidenceStore {
  const storeOpts =
    config.storeBackend !== undefined
      ? { dataDir: config.dataDir, backend: config.storeBackend }
      : { dataDir: config.dataDir };
  return opts.readOnly === true ? openStoreReadOnly(storeOpts) : openStore(storeOpts);
}

/**
 * Resolve `--session` against the store's session list: an exact id, or a
 * unique prefix of the kind `sessions`/`query`/run summaries print (8 chars
 * onward). An ambiguous or unmatched prefix is a usage error (exit 2) that
 * names the candidates, rather than export's exact-match ENOTFOUND or
 * query's silent zero matches.
 */
function resolveSessionId(store: EvidenceStore, raw: string | undefined): string | undefined {
  if (raw === undefined) return undefined;
  const sessions = store.sessions();
  const exact = sessions.find((s) => s.session_id === raw);
  if (exact !== undefined) return exact.session_id;
  const matches = sessions.filter((s) => s.session_id.startsWith(raw));
  if (matches.length === 1) return matches[0]!.session_id;
  if (matches.length > 1) {
    err(
      `--session '${raw}' is ambiguous — it matches ${matches.length} sessions: ` +
        matches.map((s) => id8(s.session_id)).join(', '),
    );
  }
  err(`--session '${raw}' matches no recorded session`);
}

/**
 * Quiet exit on EPIPE (e.g. `mcp-recorder verify | head -1`) instead of the
 * default uncaught-exception stack trace — the reader going away early isn't
 * a failure of the command that was writing to it.
 */
function guardStdoutEpipe(): void {
  process.stdout.on('error', (cause: NodeJS.ErrnoException) => {
    // Exit with whatever code the command had already decided on (e.g.
    // cmdVerify sets process.exitCode = 1 for a FAILing chain BEFORE it
    // prints) rather than hardcoding 0 — otherwise `verify | head -1` on a
    // failing store would report success just because the reader went away
    // mid-write.
    if (cause.code === 'EPIPE') process.exit(process.exitCode ?? 0);
    throw cause;
  });
}

/**
 * Best-effort browser open for `ui`'s served URL. Fire-and-forget: never
 * awaited, and any failure (missing opener, spawn error) is swallowed — it
 * must never affect the command's behavior or exit code. Skipped outright on
 * a headless Linux host (no DISPLAY/WAYLAND_DISPLAY), since spawning
 * xdg-open there has nothing to open and would just error.
 */
function tryOpenBrowser(url: string): void {
  if (
    process.platform !== 'darwin' &&
    process.platform !== 'win32' &&
    process.env.DISPLAY === undefined &&
    process.env.WAYLAND_DISPLAY === undefined
  ) {
    return;
  }
  const [cmd, args]: [string, string[]] =
    process.platform === 'darwin'
      ? ['open', [url]]
      : process.platform === 'win32'
        ? ['cmd', ['/c', 'start', '""', url]]
        : ['xdg-open', [url]];
  try {
    const child = spawn(cmd, args, { detached: true, stdio: 'ignore' });
    child.on('error', () => {
      /* best-effort: no opener available on this host — nothing to do */
    });
    child.unref();
  } catch {
    /* best-effort: never fatal to the ui command */
  }
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
  // Only the origin: the target may carry credentials in its userinfo, path
  // or query, and this line lands in terminals, scrollback and log capture.
  let targetOrigin = '<target>';
  try {
    const u = new URL(targetUrl);
    targetOrigin = `${u.protocol}//${u.host}`;
  } catch {
    /* leave the placeholder */
  }
  diag(`http proxy listening at ${proxy.url} -> ${targetOrigin} (Ctrl-C to stop)`);
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

/**
 * `manifest.json` fields NOT covered by the head signature (which covers
 * only `signature.seq` + `signature.chain_hash`) — printed for context, but
 * clearly labeled unsigned so they are never mistaken for verified evidence.
 */
interface UnsignedBundleMetadata {
  session_id?: string;
  created_at: string;
  tool_version: string;
}

function printVerifyHuman(
  result: VerifyResult,
  source: string,
  pinned?: PinnedKey,
  unsignedMetadata?: UnsignedBundleMetadata,
): void {
  out(`verify ${source}`);
  // pinned is undefined ONLY for the store-mode branch that found neither
  // --public-key nor <data-dir>/identity.pub — bundle mode always pins to
  // something (the manifest's own key, at minimum). That's a silent downgrade
  // from "this PASS proves who signed it" to "this PASS accepts a signature
  // from ANY key" — deleting identity.pub (or copying a store without it)
  // must not look identical to a normal pinned PASS, so this is a loud
  // warning, never a quiet omission.
  const unpinned = pinned === undefined;
  if (pinned !== undefined) {
    out(`pinned signer: ed25519 ${pinned.hex.slice(0, 16)}… (${pinned.source})`);
  } else {
    out(
      'WARNING: no public key to pin against — neither <data-dir>/identity.pub nor ' +
        '--public-key is available, so a signature from ANY key is accepted. This does ' +
        'NOT prove who signed the chain. Pass --public-key with a key obtained out of ' +
        'band for real assurance.',
    );
  }
  // A warning-only chain (an unsigned tail we chose to tolerate) still says
  // PASS, but distinctly — it's a weaker guarantee than a fully-signed chain.
  const hasWarning = result.problems.some((p) => p.warning === true);
  if (result.ok) {
    const labels = [...(unpinned ? ['unpinned'] : []), ...(hasWarning ? ['unsigned tail'] : [])];
    const label = labels.length > 0 ? `PASS (${labels.join(', ')})` : 'PASS';
    out(
      `${label} — chain intact: ${result.checked_events} event(s), head seq ${result.head.seq}`,
    );
  } else {
    out(`FAIL — evidence does NOT verify: ${result.checked_events} event(s) checked`);
  }
  const sig = result.verified_signature;
  if (sig !== undefined) {
    out(`signed head: seq ${sig.seq} by ed25519 ${sig.public_key.slice(0, 16)}… at ${sig.signed_at}`);
  }
  if (unsignedMetadata !== undefined) {
    out('');
    out('UNSIGNED metadata (not covered by the signature - informational only):');
    if (unsignedMetadata.session_id !== undefined) {
      out(`  session_id  : ${unsignedMetadata.session_id}`);
    }
    out(`  created_at  : ${unsignedMetadata.created_at}`);
    out(`  tool_version: ${unsignedMetadata.tool_version}`);
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
 * Bundle pinning: by default a bundle is checked against its own manifest
 * key, which only proves it is internally self-consistent — an attacker who
 * forged the whole bundle ships a matching key. A third party who obtained
 * the real key out of band passes it via --public-key, which overrides that
 * default; --allow-unsigned is threaded through as well.
 */
type BundlePinOpts = Pick<VerifyOpts, 'expectedPublicKeyHex' | 'allowUnsigned'>;

interface BundleVerification {
  result: VerifyResult;
  source: string;
  pinnedPublicKeyHex: string;
  /** manifest.json fields not covered by the signature — see printVerifyHuman. */
  unsignedMetadata: UnsignedBundleMetadata;
}

/* ------------------------------- bundle reading ------------------------------- */

const BUNDLE_REQUIRED_FILES = [BUNDLE_FILES.MANIFEST, BUNDLE_FILES.EVENTS, BUNDLE_FILES.PUBLIC_KEY] as const;

function assertBundleId(manifest: BundleManifest, where: string): void {
  if (manifest.bundle !== 'edut.mcp-recorder.bundle.v1') {
    err(`unrecognized bundle id in ${where}: ${String(manifest.bundle)}`);
  }
}

/** Extract the manifest fields the head signature does not cover (see UnsignedBundleMetadata). */
function unsignedMetadataOf(manifest: BundleManifest): UnsignedBundleMetadata {
  const out: UnsignedBundleMetadata = {
    created_at: manifest.created_at,
    tool_version: manifest.tool_version,
  };
  if (manifest.session_id !== undefined) out.session_id = manifest.session_id;
  return out;
}

function parseEventsJsonl(text: string): ChainRecord[] {
  return text
    .split('\n')
    .filter((line) => line.trim() !== '')
    .map((line) => JSON.parse(line) as ChainRecord);
}

/**
 * A bundle is a sealed, self-declared range: manifest.json's range/
 * event_count/head_hash/signature must exactly match what events.jsonl (and
 * public_key.pem) actually contain, or a forged tail chained onto a genuine
 * signed head — self-consistent, no key needed — would otherwise slip past
 * verifyRecords as a mere "unsigned tail" warning (that check only walks the
 * chain it's given; it has no notion of the manifest's own claims). Every
 * mismatch here is an unconditional failure, never downgradable by
 * --allow-unsigned: a bundle is an exported, sealed artifact, not an
 * in-flight recording. This mirrors verify.cjs's checks 1-4 exactly — keep
 * the two in sync.
 */
function checkBundleManifestConsistency(
  manifest: BundleManifest,
  records: ChainRecord[],
  publicKeyPemText: string,
): VerifyProblem[] {
  const problems: VerifyProblem[] = [];
  const push = (seq: number, detail: string): void => {
    problems.push({ type: 'bundle_manifest_mismatch', seq, detail });
  };

  const first = records[0];
  const last = records[records.length - 1];
  if (records.length !== manifest.event_count) {
    push(
      last?.seq ?? 0,
      `events.jsonl has ${records.length} record(s) but manifest.event_count declares ${manifest.event_count}`,
    );
  }
  if (first !== undefined && first.seq !== manifest.range.from_seq) {
    push(
      first.seq,
      `first record seq ${first.seq} does not match manifest.range.from_seq ${manifest.range.from_seq}`,
    );
  }
  if (last !== undefined && last.seq !== manifest.range.to_seq) {
    push(
      last.seq,
      `last record seq ${last.seq} does not match manifest.range.to_seq ${manifest.range.to_seq}`,
    );
  }
  if (last !== undefined && last.hash !== manifest.head_hash) {
    push(
      last.seq,
      `last record hash ${last.hash} does not match manifest.head_hash ${manifest.head_hash} — events were appended or removed after export`,
    );
  }
  if (manifest.signature.seq !== manifest.range.to_seq) {
    push(
      manifest.signature.seq,
      `manifest.signature.seq ${manifest.signature.seq} does not match manifest.range.to_seq ${manifest.range.to_seq}`,
    );
  }
  if (manifest.signature.chain_hash !== manifest.head_hash) {
    push(
      manifest.signature.seq,
      `manifest.signature.chain_hash ${manifest.signature.chain_hash} does not match manifest.head_hash ${manifest.head_hash}`,
    );
  }

  // The shipped public_key.pem must be the SAME key manifest.signature names
  // — mirrors verify.cjs step 4. A forgery re-signed with an attacker key
  // that ships the operator's genuine PEM (or vice versa) is caught here even
  // though the chain/signature math above is internally self-consistent.
  let pemHex: string | undefined;
  try {
    pemHex = publicKeyHexFromPem(publicKeyPemText);
  } catch (cause) {
    const msg = cause instanceof Error ? cause.message : String(cause);
    problems.push({
      type: 'signature_invalid',
      seq: manifest.signature.seq,
      detail: `public_key.pem is not a valid ed25519 public key: ${msg}`,
    });
  }
  if (pemHex !== undefined && pemHex !== manifest.signature.public_key.toLowerCase()) {
    problems.push({
      type: 'signature_invalid',
      seq: manifest.signature.seq,
      detail: 'public_key.pem does not match the manifest signing key',
    });
  }
  if (manifest.public_key_pem !== publicKeyPemText) {
    push(
      manifest.signature.seq,
      'public_key.pem on disk differs from the PEM embedded in manifest.json (manifest.public_key_pem)',
    );
  }

  return problems;
}

async function verifyManifestAgainst(
  manifest: BundleManifest,
  records: ChainRecord[],
  publicKeyPemText: string,
  pinOpts: BundlePinOpts,
): Promise<{ result: VerifyResult; pinnedPublicKeyHex: string }> {
  const pinnedPublicKeyHex = pinOpts.expectedPublicKeyHex ?? manifest.signature.public_key;
  const chainResult = await verifyRecords(records, [manifest.signature], {
    baseHash: manifest.base_hash,
    expectedPublicKeyHex: pinnedPublicKeyHex,
    ...(pinOpts.allowUnsigned !== undefined ? { allowUnsigned: pinOpts.allowUnsigned } : {}),
  });

  // Bundle mode: an unsigned tail is never a mere warning — a bundle is a
  // sealed artifact, never in-flight. Unconditional, same as the
  // manifest-consistency checks below: neither is gated on --allow-unsigned.
  // In practice the consistency checks already reject any tail that could
  // produce this, but strip the warning flag here too as defense in depth.
  const chainProblems = chainResult.problems.map((p) =>
    p.type === 'unsigned_tail' ? ({ type: p.type, seq: p.seq, detail: p.detail } satisfies VerifyProblem) : p,
  );
  const manifestProblems = checkBundleManifestConsistency(manifest, records, publicKeyPemText);
  const problems = [...chainProblems, ...manifestProblems];
  const result: VerifyResult = {
    ...chainResult,
    problems,
    ok: problems.every((p) => p.warning === true),
  };
  return { result, pinnedPublicKeyHex };
}

async function verifyBundleFromDir(dir: string, pinOpts: BundlePinOpts): Promise<BundleVerification> {
  const manifestPath = join(dir, BUNDLE_FILES.MANIFEST);
  const manifest = JSON.parse(readFileSync(manifestPath, 'utf8')) as BundleManifest;
  assertBundleId(manifest, manifestPath);
  const records = parseEventsJsonl(readFileSync(join(dir, BUNDLE_FILES.EVENTS), 'utf8'));
  const publicKeyPemText = readFileSync(join(dir, BUNDLE_FILES.PUBLIC_KEY), 'utf8');
  const { result, pinnedPublicKeyHex } = await verifyManifestAgainst(
    manifest,
    records,
    publicKeyPemText,
    pinOpts,
  );
  return {
    result,
    source: `bundle ${dir}`,
    pinnedPublicKeyHex,
    unsignedMetadata: unsignedMetadataOf(manifest),
  };
}

async function verifyBundleFromZip(
  zipPath: string,
  buf: Buffer,
  pinOpts: BundlePinOpts,
): Promise<BundleVerification> {
  const entries = readZipEntries(buf, BUNDLE_REQUIRED_FILES);
  const missing = BUNDLE_REQUIRED_FILES.filter((name) => !entries.has(name));
  if (missing.length > 0) {
    err(
      `${zipPath} is not a valid evidence bundle (missing ${missing.join(', ')} — ` +
        'expected the .zip produced by `mcp-recorder export`)',
    );
  }
  const manifest = JSON.parse(entries.get(BUNDLE_FILES.MANIFEST)!.toString('utf8')) as BundleManifest;
  assertBundleId(manifest, `${zipPath} (${BUNDLE_FILES.MANIFEST})`);
  const records = parseEventsJsonl(entries.get(BUNDLE_FILES.EVENTS)!.toString('utf8'));
  const publicKeyPemText = entries.get(BUNDLE_FILES.PUBLIC_KEY)!.toString('utf8');
  const { result, pinnedPublicKeyHex } = await verifyManifestAgainst(
    manifest,
    records,
    publicKeyPemText,
    pinOpts,
  );
  return {
    result,
    source: `bundle ${zipPath}`,
    pinnedPublicKeyHex,
    unsignedMetadata: unsignedMetadataOf(manifest),
  };
}

/**
 * Read a bundle for `verify --bundle PATH`: either form `export` produces —
 * a plain directory, or the default `.zip` (sniffed by its `PK` magic, not
 * by file extension, so a renamed bundle still works). Anything else gets a
 * helpful error instead of the raw ENOTDIR/ENOENT a fs call would throw.
 */
async function verifyBundleDir(
  bundlePath: string,
  pinOpts: BundlePinOpts = {},
): Promise<BundleVerification> {
  const resolved = resolve(bundlePath);
  let stat;
  try {
    stat = statSync(resolved);
  } catch {
    err(`--bundle ${resolved} does not exist`);
  }
  if (stat.isDirectory()) return verifyBundleFromDir(resolved, pinOpts);
  if (stat.isFile()) {
    const buf = readFileSync(resolved);
    if (buf.length >= 4 && buf[0] === 0x50 && buf[1] === 0x4b /* 'PK' */) {
      return verifyBundleFromZip(resolved, buf, pinOpts);
    }
    err(
      `--bundle ${resolved} is not a recognized evidence bundle ` +
        '(expected a directory or a .zip produced by `mcp-recorder export`)',
    );
  }
  err(`--bundle ${resolved} is neither a file nor a directory`);
}

/**
 * Resolve `verify`'s store-mode pin (explicit --public-key, else this data
 * dir's own identity.pub, else none) and run verifyStore against it. Shared
 * by cmdVerify and cmdUi's integrity banner so the two always agree — before
 * this was factored out, `ui` called verifyStore(store) with no pin and no
 * --allow-unsigned at all, so it could show green for a chain `verify`
 * itself rejects.
 */
async function resolveStoreVerify(
  store: EvidenceStore,
  config: RecorderConfig,
  opts: { explicitPublicKeyHex: string | undefined; allowUnsigned: boolean },
): Promise<{ result: VerifyResult; pinned: PinnedKey | undefined }> {
  let expectedPublicKeyHex = opts.explicitPublicKeyHex;
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
  const verifyOpts: VerifyOpts = { allowUnsigned: opts.allowUnsigned };
  if (expectedPublicKeyHex !== undefined) verifyOpts.expectedPublicKeyHex = expectedPublicKeyHex;
  const result = await verifyStore(store, verifyOpts);
  const pinned =
    expectedPublicKeyHex !== undefined ? { hex: expectedPublicKeyHex, source: pinSource } : undefined;
  return { result, pinned };
}

async function cmdVerify(flags: Flags): Promise<void> {
  const allowUnsigned = flags['allow-unsigned'] === true;
  const publicKeyFlag = asStr(flags['public-key']);
  const explicitPublicKeyHex =
    publicKeyFlag !== undefined ? resolvePublicKeyArg(publicKeyFlag) : undefined;

  guardStdoutEpipe();
  let result: VerifyResult;
  let source: string;
  let pinned: PinnedKey | undefined;
  let unsignedMetadata: UnsignedBundleMetadata | undefined;

  const bundle = asStr(flags.bundle);
  if (bundle !== undefined) {
    const bundleResult = await verifyBundleDir(bundle, {
      ...(explicitPublicKeyHex !== undefined ? { expectedPublicKeyHex: explicitPublicKeyHex } : {}),
      allowUnsigned,
    });
    result = bundleResult.result;
    source = bundleResult.source;
    unsignedMetadata = bundleResult.unsignedMetadata;
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
    const store = openConfiguredStore(config, { readOnly: true });
    try {
      const resolved = await resolveStoreVerify(store, config, { explicitPublicKeyHex, allowUnsigned });
      result = resolved.result;
      pinned = resolved.pinned;
      source = `store ${store.path} (${store.backend})`;
    } finally {
      store.close();
    }
  }

  // Set the exit code BEFORE printing: printVerifyHuman/JSON.stringify below
  // can fail partway through with EPIPE (e.g. `verify | head -1`), and
  // guardStdoutEpipe's handler exits with process.exitCode — an exit code
  // set only after a successful print would never take effect on that path,
  // silently turning a FAIL into an apparent success.
  if (!result.ok) process.exitCode = 1;

  if (flags.json === true) {
    const payload =
      pinned !== undefined
        ? { ...result, pinned_public_key: pinned.hex, pinned_public_key_source: pinned.source }
        : { ...result, pinned_public_key: null, unpinned: true };
    out(JSON.stringify(payload, null, 2));
  } else {
    printVerifyHuman(result, source, pinned, unsignedMetadata);
  }
}

async function cmdQuery(flags: Flags, positionals: string[]): Promise<void> {
  guardStdoutEpipe();
  const needle = positionals[0] ?? err('query: missing <needle> argument');
  const config = resolveConfig({ flags, env: process.env });
  const store = openConfiguredStore(config, { readOnly: true });
  try {
    const sessionId = resolveSessionId(store, asStr(flags.session));
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
  guardStdoutEpipe();
  const config = resolveConfig({ flags, env: process.env });
  const store = openConfiguredStore(config, { readOnly: true });
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
  guardStdoutEpipe();
  const config = resolveConfig({ flags, env: process.env });
  const store = openConfiguredStore(config, { readOnly: true });
  try {
    const sessionId = resolveSessionId(store, asStr(flags.session));
    const outFile = asStr(flags.out);
    // Route through the SAME pin resolution `verify` uses (identity.pub by
    // default, or --public-key / --allow-unsigned if given) so the integrity
    // banner never shows green for a chain `mcp-recorder verify` rejects.
    const publicKeyFlag = asStr(flags['public-key']);
    const explicitPublicKeyHex =
      publicKeyFlag !== undefined ? resolvePublicKeyArg(publicKeyFlag) : undefined;
    const allowUnsigned = flags['allow-unsigned'] === true;
    const { result: verify } = await resolveStoreVerify(store, config, {
      explicitPublicKeyHex,
      allowUnsigned,
    });
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
    diag(`replay UI at ${ui.url} (Ctrl-C to stop)`);
    if (flags['no-open'] !== true) tryOpenBrowser(ui.url);
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
  guardStdoutEpipe();
  const config = resolveConfig({ flags, env: process.env });
  const store = openConfiguredStore(config, { readOnly: true });
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
    const sessionId = resolveSessionId(store, asStr(flags.session));
    // loadExisting, NOT load: export must sign with the key that actually
    // produced the chain. Minting a fresh one here (as record's Signer.load
    // does) would sign evidence with an identity that never touched it, and
    // silently repoint identity.pub out from under the next `verify` — see
    // Signer.loadExisting's doc comment.
    const signer = await Signer.loadExisting(config.dataDir);

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

/* --------------------------------- setup ---------------------------------
 * `mcp-recorder setup` rewrites a client config's `mcpServers` entries to run
 * behind this recorder. cli.ts owns every filesystem side effect and exit
 * code; src/setup/wrap.ts decides *what* the new JSON should look like
 * (pure functions over parsed JSON) and src/setup/io.ts provides the
 * backup/sidecar/atomic-write primitives. See src/setup/wrap.ts's WrapPlan
 * doc comment for the wrapped/skipped/alreadyWrapped shape mirrored below.
 */

/**
 * Absolute path to THIS install's dist/cli.js, for `setup --wrapper local`.
 * `import.meta.url` names wherever this file is actually running from —
 * `dist/cli.js` once built, or `src/cli.ts` under tsx (as the test suite
 * runs it) — so resolving through the package root one level up, rather
 * than trusting the self path verbatim, lands on the same spawnable
 * `dist/cli.js` either way. That file must exist (a real install always
 * ships dist/; a dev checkout needs `npm run build` first) since it is what
 * setup writes into the client's config to be spawned later.
 */
function resolveLocalWrapperPath(): string {
  const selfPath = fileURLToPath(import.meta.url);
  const packageRoot = resolve(dirname(selfPath), '..');
  return join(packageRoot, 'dist', 'cli.js');
}

function parseNameList(v: string | undefined): Set<string> | undefined {
  if (v === undefined) return undefined;
  const names = v
    .split(',')
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
  return names.length > 0 ? new Set(names) : undefined;
}

interface SetupJsonResult {
  config: string;
  backup: string | null;
  wrapped: string[];
  skipped: SkipEntry[];
  already_wrapped: string[];
  /** Same notices the human output prints (e.g. which env var names a
   * `--wrapper wsl` entry forwards via WSLENV, or a bridged server's
   * one-time OAuth pre-authorization tip). */
  notes: string[];
  /** Server names materialized this run via `--bridge NAME=URL` (an
   * unwrapped `npx -y mcp-remote URL` entry, then wrapped like any other
   * stdio server — see {@link bridgeEntry}). */
  bridged: string[];
}

function printSetupHuman(configPath: string, backup: string | null, plan: WrapPlan, dryRun: boolean): void {
  out(`config: ${configPath}`);
  if (dryRun) out('(dry run — nothing written)');
  if (plan.wrapped.length > 0) {
    out('');
    out(`wrapped ${plan.wrapped.length} server(s):`);
    for (const name of plan.wrapped) {
      const entry = plan.next[name]!;
      out(`  ${name}: ${entry.command} ${(entry.args ?? []).map((a) => JSON.stringify(a)).join(' ')}`);
    }
  } else {
    out('');
    out('nothing to wrap');
  }
  if (plan.alreadyWrapped.length > 0) {
    out('');
    out(`already wrapped, left alone: ${plan.alreadyWrapped.join(', ')}`);
  }
  if (plan.notes.length > 0) {
    out('');
    for (const n of plan.notes) out(`note: ${n}`);
  }
  if (plan.skipped.length > 0) {
    out('');
    out('skipped:');
    for (const s of plan.skipped) out(`  ${s.name}: ${s.reason}`);
  }
  if (backup !== null) {
    out('');
    out(`backup: ${backup}`);
  }
  if (!dryRun && plan.wrapped.length > 0) {
    out('');
    out('Fully quit and restart your MCP client to pick up this change');
    out('(Claude Desktop: quit from the menu bar / tray icon — closing the window is not enough).');
    out('Then check the first recording with:');
    out('  mcp-recorder sessions');
    out('  mcp-recorder ui');
  }
}

function printSetupResult(
  configPath: string,
  backup: string | null,
  plan: WrapPlan,
  jsonOut: boolean,
  dryRun: boolean,
  bridged: readonly string[] = [],
): void {
  if (jsonOut) {
    const payload: SetupJsonResult = {
      config: configPath,
      backup,
      wrapped: plan.wrapped,
      skipped: plan.skipped,
      already_wrapped: plan.alreadyWrapped,
      notes: plan.notes,
      bridged: [...bridged],
    };
    out(JSON.stringify(payload, null, 2));
    return;
  }
  printSetupHuman(configPath, backup, plan, dryRun);
}

interface UndoOutcome {
  restored: string[];
  skipped: SkipEntry[];
  usedSidecar: boolean;
}

function printUndoResult(
  configPath: string,
  backup: string | null,
  outcome: UndoOutcome,
  jsonOut: boolean,
  dryRun: boolean,
): void {
  if (jsonOut) {
    out(
      JSON.stringify(
        {
          config: configPath,
          backup,
          restored: outcome.restored,
          skipped: outcome.skipped,
          used_sidecar: outcome.usedSidecar,
        },
        null,
        2,
      ),
    );
    return;
  }
  out(`config: ${configPath}`);
  if (dryRun) out('(dry run — nothing written)');
  out(
    outcome.usedSidecar
      ? 'restoring from the sidecar (exact original entries):'
      : 'no sidecar found — structurally unwrapping recorder entries:',
  );
  if (outcome.restored.length > 0) {
    for (const name of outcome.restored) out(`  ${name}`);
  } else {
    out('  nothing to restore');
  }
  if (outcome.skipped.length > 0) {
    out('');
    out('skipped:');
    for (const s of outcome.skipped) out(`  ${s.name}: ${s.reason}`);
  }
  if (backup !== null) {
    out('');
    out(`backup: ${backup}`);
  }
}

/**
 * `setup --undo`: restore the entries this tool wrapped. Prefers the sidecar
 * (`<config>.mcp-recorder-setup.json`) for an exact, byte-for-byte restore of
 * what was there before; falls back to structurally stripping a recognizable
 * wrapper prefix when the sidecar is missing (see structuralUnwrap).
 */
function runSetupUndo(
  configPath: string,
  root: Record<string, unknown>,
  servers: McpServersMap,
  indent: string,
  eol: '\n' | '\r\n',
  dryRun: boolean,
  jsonOut: boolean,
): void {
  let sidecar: SetupSidecar | undefined;
  try {
    sidecar = readSidecarStrict(configPath);
  } catch (cause) {
    const msg = cause instanceof Error ? cause.message : String(cause);
    diag(`error: ${sidecarPath(configPath)} exists but is not valid JSON: ${msg}`);
    process.exitCode = 2;
    return;
  }

  const next: McpServersMap = { ...servers };
  const restored: string[] = [];
  const skipped: SkipEntry[] = [];

  if (sidecar !== undefined) {
    for (const [name, original] of Object.entries(sidecar.wrapped)) {
      if (!(name in next)) {
        skipped.push({ name, reason: 'not present in current config' });
        continue;
      }
      next[name] = original;
      restored.push(name);
    }
  } else {
    for (const [name, entry] of Object.entries(servers)) {
      const original = structuralUnwrap(entry);
      if (original === undefined) continue;
      next[name] = original;
      restored.push(name);
    }
  }

  const outcome: UndoOutcome = { restored, skipped, usedSidecar: sidecar !== undefined };

  if (dryRun || restored.length === 0) {
    printUndoResult(configPath, null, outcome, jsonOut, dryRun);
    return;
  }

  const backup = writeBackup(configPath);
  root.mcpServers = next;
  writeJsonAtomic(configPath, root, indent, eol);
  if (sidecar !== undefined) removeSidecar(configPath);

  printUndoResult(configPath, backup, outcome, jsonOut, false);
}

async function cmdSetup(flags: Flags): Promise<void> {
  guardStdoutEpipe();

  const clientFlag = asStr(flags['client']);
  if (clientFlag !== undefined && !isClientKind(clientFlag)) {
    err(`setup: invalid --client '${clientFlag}' (expected ${CLIENT_KINDS.join(', ')})`);
  }
  const client = clientFlag as ClientKind | undefined;

  const wrapperFlagRaw = asStr(flags['wrapper']);
  if (
    wrapperFlagRaw !== undefined &&
    wrapperFlagRaw !== 'local' &&
    wrapperFlagRaw !== 'npx' &&
    wrapperFlagRaw !== 'wsl'
  ) {
    err(`setup: invalid --wrapper '${wrapperFlagRaw}' (expected 'local', 'npx' or 'wsl')`);
  }
  const explicitWrapper = wrapperFlagRaw as WrapperChoice | undefined;

  const dataDir = asStr(flags['data-dir']);
  const dryRun = flags['dry-run'] === true;
  const isUndo = flags.undo === true;
  const jsonOut = flags.json === true;
  const only = parseNameList(asStr(flags['only']));
  const except = parseNameList(asStr(flags['except']));

  let bridgeSpecs: BridgeSpec[];
  try {
    bridgeSpecs = parseBridgeSpecs(asStrArr(flags['bridge']));
  } catch (cause) {
    err(cause instanceof Error ? cause.message : String(cause));
  }

  // Cheap (env vars + one /proc/version read, no process spawned) — safe to
  // always compute, unlike windowsHomeCandidates() below which may shell
  // out to cmd.exe and is only invoked lazily, when actually needed.
  const wslInfo = detectWsl(process.env, (p) => readFileSync(p, 'utf8'));

  let resolved: ReturnType<typeof resolveClientConfigPath>;
  try {
    resolved = resolveClientConfigPath(client, asStr(flags['config']), process.cwd(), {
      inWsl: wslInfo.inWsl,
      homeCandidates: () => windowsHomeCandidates(),
    });
  } catch (cause) {
    err(cause instanceof Error ? cause.message : String(cause));
  }
  const configPath = resolved.path;
  if (resolved.note !== undefined) diag(resolved.note);

  if (!existsSync(configPath)) {
    diag(`error: config file not found at ${configPath}`);
    process.exitCode = 1;
    return;
  }

  let raw: string;
  let parsed: unknown;
  try {
    raw = readFileSync(configPath, 'utf8');
    parsed = JSON.parse(stripBom(raw));
  } catch (cause) {
    const msg = cause instanceof Error ? cause.message : String(cause);
    diag(`error: ${configPath} is not valid JSON: ${msg}`);
    process.exitCode = 2;
    return;
  }
  if (raw.charCodeAt(0) === 0xfeff) {
    diag(`note: ${configPath} starts with a UTF-8 BOM (common on Windows) — parsed fine, rewritten without one`);
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    diag(`error: ${configPath} does not contain a JSON object`);
    process.exitCode = 2;
    return;
  }
  const root = parsed as Record<string, unknown>;
  const serversRaw = root['mcpServers'];
  const servers: McpServersMap =
    typeof serversRaw === 'object' && serversRaw !== null && !Array.isArray(serversRaw)
      ? (serversRaw as McpServersMap)
      : {};
  const indent = detectIndent(raw);
  const eol = detectEol(raw);

  if (isUndo) {
    runSetupUndo(configPath, root, servers, indent, eol, dryRun, jsonOut);
    return;
  }

  const localWrapperPath = resolveLocalWrapperPath();

  const wrapper = chooseWrapper(explicitWrapper, wslInfo.inWsl, configPath);
  if (explicitWrapper === undefined && wrapper === 'wsl') {
    diag(
      `auto-selected --wrapper wsl: running inside WSL and ${configPath} is a Windows-side config ` +
        '(under /mnt/...) — a Linux node path would not be runnable by that client (pass --wrapper to override)',
    );
  }
  if (explicitWrapper === 'local' && isWindowsMountPath(configPath)) {
    diag(
      `warning: --wrapper local writes a Linux node path into a Windows-side config (${configPath}); ` +
        'the Windows client will not be able to launch it — did you mean --wrapper wsl?',
    );
  }

  const wrapOpts: WrapOpts = { wrapper, localWrapperPath };
  if (dataDir !== undefined) wrapOpts.dataDir = dataDir;
  if (only !== undefined) wrapOpts.only = only;
  if (except !== undefined) wrapOpts.except = except;
  if (wslInfo.distro !== undefined) wrapOpts.wslDistro = wslInfo.distro;

  // --bridge NAME=URL[,...]: materialize each remote MCP connector as a
  // LOCAL, unwrapped `npx -y mcp-remote URL` entry in `servers` BEFORE
  // planWrap runs, so the normal wrap logic below wraps it like any other
  // stdio server — the sidecar then records this unwrapped mcp-remote entry
  // as the "original", and `--undo` restores exactly that (it removes the
  // recorder, not the bridge; delete the entry by hand to remove the
  // bridge too). A name that already exists and isn't this exact bridge
  // entry — nor already wrapped (a previous `--bridge` run, or by pure
  // coincidence a different server this tool already wrapped) — is a
  // conflict: never silently replaced.
  const bridgedNames: string[] = [];
  for (const spec of bridgeSpecs) {
    const existing = servers[spec.name];
    const isConflict =
      existing !== undefined &&
      !isSameBridgeEntry(existing, spec.url) &&
      !isAlreadyWrapped(existing, localWrapperPath);
    if (isConflict) {
      err(
        `setup: --bridge ${spec.name}=${spec.url}: a server named '${spec.name}' already exists in ` +
          `${configPath} and is not the same bridge entry — remove or rename it first, ` +
          'this tool never silently replaces an existing entry',
      );
    }
    if (existing === undefined) servers[spec.name] = bridgeEntry(spec.url);
    bridgedNames.push(spec.name);
  }

  const plan = planWrap(servers, wrapOpts);
  for (const spec of bridgeSpecs) {
    plan.notes.push(
      `first launch of ${spec.name} opens an OAuth flow in your browser; to pre-authorize from a ` +
        `terminal run: npx -y mcp-remote ${spec.url} (tokens are cached under ~/.mcp-auth)`,
    );
  }

  if (dryRun) {
    printSetupResult(configPath, null, plan, jsonOut, true, bridgedNames);
    return;
  }

  if (plan.wrapped.length === 0) {
    // Idempotent: every candidate was already wrapped (or filtered/skipped)
    // — report it, but never touch the file (no new backup, no sidecar).
    printSetupResult(configPath, null, plan, jsonOut, false, bridgedNames);
    return;
  }

  // Validate any existing sidecar BEFORE writing anything, so a corrupt
  // sidecar aborts cleanly (exit 2, config untouched) instead of partially
  // applying the wrap.
  let existingSidecar: SetupSidecar;
  try {
    existingSidecar = readSidecarStrict(configPath) ?? { version: 1, wrapped: {} };
  } catch (cause) {
    const msg = cause instanceof Error ? cause.message : String(cause);
    diag(`error: ${sidecarPath(configPath)} exists but is not valid JSON: ${msg}`);
    process.exitCode = 2;
    return;
  }
  for (const name of plan.wrapped) {
    if (!(name in existingSidecar.wrapped)) existingSidecar.wrapped[name] = plan.originals[name]!;
  }

  const backup = writeBackup(configPath);
  root.mcpServers = plan.next;
  writeJsonAtomic(configPath, root, indent, eol);
  writeSidecarAtomic(configPath, existingSidecar, indent);

  printSetupResult(configPath, backup, plan, jsonOut, false, bridgedNames);
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
    case 'setup':
      return cmdSetup(flags);
  }
}

main().catch((cause: unknown) => {
  const msg = cause instanceof Error ? cause.message : String(cause);
  diag(`error: ${msg}`);
  process.exit(2);
});
