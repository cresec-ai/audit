/**
 * Layer 1 of the two-layer auth model: the bearer token, and nothing else.
 *
 * The token answers exactly one question — "may this connection write to
 * tenant T at all". It is NOT what authenticates content; that is the
 * install's ed25519 key (layer 2, in ingest.ts), and the receiver files
 * records under the KEY, never under the token. A stolen token therefore
 * buys spam, a cursor read and some rate limit; it buys no cross-install
 * write, no forgery and no deletion. Collapsing the two layers (e.g. an
 * HMAC derived from the token) is the mistake this file exists not to make.
 *
 * Tokens are compared by SHA-256 digest with `timingSafeEqual`, and every
 * configured token is compared even after a match, so the comparison does
 * not leak which entry matched by timing.
 */

import { createHash, timingSafeEqual } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { Buffer } from 'node:buffer';
import { HEX64 } from './protocol.js';

export type EnrolmentMode = 'pinned' | 'tofu';

export interface TokenConfig {
  /** Stable id used in logs and rejection records. Never the secret. */
  id: string;
  tenant: string;
  /**
   * SHA-256 hex of the bearer token. Preferred: the receiver never needs the
   * token itself, only the ability to recognise it.
   */
  token_sha256?: string;
  /** The raw bearer token. Convenience for a reference deployment only. */
  token?: string;
  /**
   * 'pinned'  — only the keys listed below may write for this tenant.
   *             Unknown key -> 403. The right default for a managed fleet.
   * 'tofu'    — the first key seen on this token is bound to it; later keys
   *             are accepted but flagged `new_identity` and do not count as
   *             attested until an operator acknowledges them.
   */
  enrolment: EnrolmentMode;
  /** 64-hex ed25519 public keys, for `pinned`. */
  keys?: string[];
}

export interface AuthConfig {
  tokens: TokenConfig[];
  /**
   * Where the config came from, for the startup banner. 'file' | 'env' |
   * 'none'.
   */
  source: 'file' | 'env' | 'none';
}

export const TOKENS_FILE = 'tokens.json';

/** Env fallback so `a customer could actually run it` needs zero files. */
export const ENV = {
  TOKEN: 'MCPR_RECEIVER_TOKEN',
  TENANT: 'MCPR_RECEIVER_TENANT',
  ENROLMENT: 'MCPR_RECEIVER_ENROLMENT',
  KEYS: 'MCPR_RECEIVER_KEYS',
} as const;

function sha256(value: string): Buffer {
  return createHash('sha256').update(value, 'utf8').digest();
}

function normalizeToken(entry: TokenConfig, index: number): TokenConfig {
  const id = entry.id ?? `token-${index + 1}`;
  const tenant = entry.tenant ?? 'default';
  const enrolment: EnrolmentMode = entry.enrolment === 'tofu' ? 'tofu' : 'pinned';
  const keys = (entry.keys ?? []).map((k) => k.trim().toLowerCase());
  for (const key of keys) {
    if (!HEX64.test(key)) {
      throw new Error(`tokens.json: ${id} lists a key that is not 64-hex: ${key}`);
    }
  }
  let digestHex = entry.token_sha256?.trim().toLowerCase();
  if (digestHex === undefined && entry.token !== undefined) {
    digestHex = sha256(entry.token).toString('hex');
  }
  if (digestHex === undefined || !HEX64.test(digestHex)) {
    throw new Error(`tokens.json: ${id} needs a 'token' or a 64-hex 'token_sha256'`);
  }
  if (enrolment === 'pinned' && keys.length === 0) {
    throw new Error(
      `tokens.json: ${id} is 'pinned' but lists no keys — it could never accept anything. ` +
        "Add the install's identity.pub, or set \"enrolment\": \"tofu\".",
    );
  }
  const out: TokenConfig = { id, tenant, enrolment, token_sha256: digestHex, keys };
  return out;
}

/**
 * Resolve the ingest tokens: `<data-dir>/tokens.json` when present, else the
 * single-tenant env form, else nothing (every POST then gets 401, which is
 * the correct posture for a receiver nobody has configured).
 */
export function loadAuthConfig(dataDir: string, env: NodeJS.ProcessEnv = process.env): AuthConfig {
  const path = join(dataDir, TOKENS_FILE);
  if (existsSync(path)) {
    let parsed: unknown;
    try {
      parsed = JSON.parse(readFileSync(path, 'utf8'));
    } catch (err) {
      throw new Error(`${path} is not valid JSON: ${(err as Error).message}`);
    }
    const raw = (parsed as { tokens?: TokenConfig[] })?.tokens;
    if (!Array.isArray(raw)) throw new Error(`${path} must be {"tokens": [...]}`);
    return { tokens: raw.map(normalizeToken), source: 'file' };
  }

  const token = env[ENV.TOKEN];
  if (token !== undefined && token !== '') {
    const keys = (env[ENV.KEYS] ?? '')
      .split(',')
      .map((k) => k.trim().toLowerCase())
      .filter((k) => k !== '');
    const enrolment: EnrolmentMode =
      env[ENV.ENROLMENT] === 'pinned' ? 'pinned' : keys.length > 0 ? 'pinned' : 'tofu';
    return {
      tokens: [
        normalizeToken(
          {
            id: 'env',
            tenant: env[ENV.TENANT] ?? 'default',
            token,
            enrolment,
            keys,
          },
          0,
        ),
      ],
      source: 'env',
    };
  }

  return { tokens: [], source: 'none' };
}

/** Extract the bearer credential, or undefined when the header is absent/malformed. */
export function bearer(header: string | undefined): string | undefined {
  if (header === undefined) return undefined;
  const match = /^Bearer[ \t]+(.+)$/i.exec(header.trim());
  if (match === null) return undefined;
  const value = match[1]!.trim();
  return value === '' ? undefined : value;
}

/**
 * Constant-time-ish lookup: hash the presented token once, then compare
 * against every configured digest with `timingSafeEqual`, without an early
 * return.
 */
export function authenticate(config: AuthConfig, presented: string | undefined): TokenConfig | undefined {
  if (presented === undefined) return undefined;
  const digest = sha256(presented);
  let matched: TokenConfig | undefined;
  for (const entry of config.tokens) {
    const expected = Buffer.from(entry.token_sha256!, 'hex');
    if (expected.length === digest.length && timingSafeEqual(expected, digest)) {
      matched ??= entry;
    }
  }
  return matched;
}

/** Same comparison for the single operator token (read-only endpoints). */
export function matchesOperatorToken(expected: string, presented: string | undefined): boolean {
  if (presented === undefined) return false;
  const a = sha256(expected);
  const b = sha256(presented);
  return timingSafeEqual(a, b);
}
