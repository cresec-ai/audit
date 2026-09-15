/**
 * Config resolution: flag > env > default. Produces the RecorderConfig the
 * CLI hands to every other module.
 *
 * Two entry points, because record/http and the inspection subcommands have
 * opposite failure needs:
 *
 *   - `resolveConfig()` is STRICT: an invalid --redact/--store value throws.
 *     Used by verify/query/sessions/ui/export, which have no wrapped-server
 *     traffic to protect, so failing loudly (exit 2) is correct.
 *   - `resolveConfigLenient()` NEVER throws: an invalid --redact/--store
 *     flag or env value is reported as a warning and replaced with its safe
 *     default (allowlist redaction, automatic store backend). Used by
 *     record/http, where nothing about recording configuration may prevent
 *     the wrapped server from being spawned (fail-open).
 *
 * Neither function creates the data directory anymore — see `ensureDataDir`.
 * Record/http create it inside their fail-open init path (a bad --data-dir
 * degrades to pure passthrough there instead of throwing); the strict
 * inspection commands create it via whichever store/signer they open.
 */

import { chmodSync, mkdirSync, statSync } from 'node:fs';
import { homedir } from 'node:os';
import { join, resolve } from 'node:path';
import { ENV } from './types.js';
import type { RecorderConfig } from './types.js';

export interface ResolveConfigOpts {
  flags: Record<string, string | boolean | undefined>;
  env: NodeJS.ProcessEnv;
}

export interface LenientConfigResult {
  config: RecorderConfig;
  /** Invalid flag/env values that were ignored in favor of a safe default. */
  warnings: string[];
}

function asString(v: string | boolean | undefined): string | undefined {
  return typeof v === 'string' && v !== '' ? v : undefined;
}

function pick(
  flag: string | boolean | undefined,
  envValue: string | undefined,
): string | undefined {
  const f = asString(flag);
  if (f !== undefined) return f;
  if (envValue !== undefined && envValue !== '') return envValue;
  return undefined;
}

/** Ensure the data directory exists with private (0o700) permissions — it
 * holds the ed25519 signing key. */
export function ensureDataDir(dataDir: string): void {
  mkdirSync(dataDir, { recursive: true, mode: 0o700 });
  // mkdirSync never changes the mode of a directory that already exists (an
  // earlier inspection command, or the user, may have created it under a
  // wider umask), and this directory holds the private signing key and the
  // evidence — tighten it. Best effort: chmod fails on a dir we do not own.
  try {
    if ((statSync(dataDir).mode & 0o077) !== 0) chmodSync(dataDir, 0o700);
  } catch {
    /* best effort */
  }
}

interface CommonFields {
  dataDir: string;
  disabled: boolean;
  serverName?: string;
  identityLabel?: string;
}

function resolveCommon(opts: ResolveConfigOpts): CommonFields {
  const { flags, env } = opts;
  const dataDirRaw =
    pick(flags['data-dir'], env[ENV.DATA_DIR]) ?? join(homedir(), '.mcp-recorder');
  const out: CommonFields = {
    dataDir: resolve(dataDirRaw),
    disabled: env[ENV.DISABLE] === '1',
  };
  const serverName = asString(flags['name']);
  if (serverName !== undefined) out.serverName = serverName;
  const identityLabel = asString(flags['identity']);
  if (identityLabel !== undefined) out.identityLabel = identityLabel;
  return out;
}

export function resolveConfig(opts: ResolveConfigOpts): RecorderConfig {
  const { flags, env } = opts;
  const common = resolveCommon(opts);

  const storeRaw = pick(flags['store'], env[ENV.STORE]);
  let storeBackend: 'sqlite' | 'jsonl' | undefined;
  if (storeRaw !== undefined) {
    if (storeRaw !== 'sqlite' && storeRaw !== 'jsonl') {
      throw new Error(
        `invalid store backend '${storeRaw}' (expected 'sqlite' or 'jsonl')`,
      );
    }
    storeBackend = storeRaw;
  }

  const redactRaw = pick(flags['redact'], env[ENV.REDACT]) ?? 'allowlist';
  if (redactRaw !== 'allowlist' && redactRaw !== 'off') {
    throw new Error(
      `invalid redact mode '${redactRaw}' (expected 'allowlist' or 'off')`,
    );
  }

  const config: RecorderConfig = {
    dataDir: common.dataDir,
    redactMode: redactRaw,
    disabled: common.disabled,
  };
  if (storeBackend !== undefined) config.storeBackend = storeBackend;
  if (common.serverName !== undefined) config.serverName = common.serverName;
  if (common.identityLabel !== undefined) config.identityLabel = common.identityLabel;
  return config;
}

/** Same resolution as `resolveConfig`, but fail-open: never throws. */
export function resolveConfigLenient(opts: ResolveConfigOpts): LenientConfigResult {
  const { flags, env } = opts;
  const common = resolveCommon(opts);
  const warnings: string[] = [];

  const storeRaw = pick(flags['store'], env[ENV.STORE]);
  let storeBackend: 'sqlite' | 'jsonl' | undefined;
  if (storeRaw !== undefined) {
    if (storeRaw !== 'sqlite' && storeRaw !== 'jsonl') {
      warnings.push(
        `invalid store backend '${storeRaw}' (expected 'sqlite' or 'jsonl'); using automatic selection`,
      );
    } else {
      storeBackend = storeRaw;
    }
  }

  const redactRaw = pick(flags['redact'], env[ENV.REDACT]) ?? 'allowlist';
  let redactMode: 'allowlist' | 'off';
  if (redactRaw === 'allowlist' || redactRaw === 'off') {
    redactMode = redactRaw;
  } else {
    warnings.push(
      `invalid redact mode '${redactRaw}' (expected 'allowlist' or 'off'); using 'allowlist'`,
    );
    redactMode = 'allowlist';
  }

  const config: RecorderConfig = {
    dataDir: common.dataDir,
    redactMode,
    disabled: common.disabled,
  };
  if (storeBackend !== undefined) config.storeBackend = storeBackend;
  if (common.serverName !== undefined) config.serverName = common.serverName;
  if (common.identityLabel !== undefined) config.identityLabel = common.identityLabel;
  return { config, warnings };
}
