/**
 * Config resolution: flag > env > default. Produces the RecorderConfig the
 * CLI hands to every other module, and ensures the data directory exists
 * (0o700 — it holds a private signing key).
 */

import { mkdirSync } from 'node:fs';
import { homedir } from 'node:os';
import { join, resolve } from 'node:path';
import { ENV } from './types.js';
import type { RecorderConfig } from './types.js';

export interface ResolveConfigOpts {
  flags: Record<string, string | boolean | undefined>;
  env: NodeJS.ProcessEnv;
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

export function resolveConfig(opts: ResolveConfigOpts): RecorderConfig {
  const { flags, env } = opts;

  const dataDirRaw =
    pick(flags['data-dir'], env[ENV.DATA_DIR]) ?? join(homedir(), '.mcp-recorder');
  const dataDir = resolve(dataDirRaw);
  mkdirSync(dataDir, { recursive: true, mode: 0o700 });

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
    dataDir,
    redactMode: redactRaw,
    disabled: env[ENV.DISABLE] === '1',
  };
  if (storeBackend !== undefined) config.storeBackend = storeBackend;
  const serverName = asString(flags['name']);
  if (serverName !== undefined) config.serverName = serverName;
  const identityLabel = asString(flags['identity']);
  if (identityLabel !== undefined) config.identityLabel = identityLabel;
  return config;
}
