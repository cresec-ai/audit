/**
 * Sink configuration: flag > env > default, exactly like src/config.ts.
 *
 * SETTING `MCP_RECORDER_SINK` IS THE ENTIRE OPT-IN. Absent, there is no
 * sink, no shipper, and behaviour is byte-identical to a build without this
 * module. There is deliberately no second `..._ENABLED` switch.
 *
 * Resolution NEVER throws. A malformed URL, a plain-http non-loopback sink
 * or an unreadable token file is a warning and a DISABLED sink — never a
 * failed proxy start. That is the same posture `resolveConfigLenient`
 * already takes for an invalid `--redact`, and for the same reason: nothing
 * about recording configuration may prevent the wrapped server from running.
 *
 * Two variables, not one. A combined `https://token@host/` form was
 * rejected: userinfo in a URL leaks into process listings, shell history and
 * error strings.
 */

import { readFileSync } from 'node:fs';
import { ENV } from '../types.js';

export interface SinkConfig {
  /** Base URL, normalised: origin + path, no trailing slash. */
  url: string;
  /** Bearer token, or undefined when the operator configured none. */
  token?: string;
}

export interface SinkResolution {
  /** Undefined means "no sink configured" — the default, and a no-op. */
  sink?: SinkConfig;
  /** Invalid values that were ignored; the caller prints them via its diag. */
  warnings: string[];
}

export interface ResolveSinkOpts {
  flags?: Record<string, string | boolean | string[] | undefined>;
  env: NodeJS.ProcessEnv;
}

function asString(v: string | boolean | string[] | undefined): string | undefined {
  return typeof v === 'string' && v !== '' ? v : undefined;
}

function pick(
  flag: string | boolean | string[] | undefined,
  envValue: string | undefined,
): string | undefined {
  const f = asString(flag);
  if (f !== undefined) return f;
  if (envValue !== undefined && envValue !== '') return envValue;
  return undefined;
}

/** Loopback is the ONE place plain http is tolerated (tests, a local relay). */
function isLoopbackHost(hostname: string): boolean {
  const h = hostname.toLowerCase().replace(/^\[|\]$/g, '');
  if (h === 'localhost' || h === '::1' || h === '0:0:0:0:0:0:0:1') return true;
  return /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(h);
}

/**
 * Normalise a sink base URL. Returns the normalised string, or an error
 * message explaining why the sink is disabled. `https://` only; certificate
 * verification is NEVER disabled anywhere in this module — the corporate-CA
 * and agent-proxy cases are handled with NODE_EXTRA_CA_CERTS, which node
 * reads on its own.
 */
export function normalizeSinkUrl(raw: string): { url: string } | { error: string } {
  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    return { error: `invalid ${ENV.SINK} URL '${raw}'` };
  }
  if (parsed.username !== '' || parsed.password !== '') {
    return {
      error:
        `${ENV.SINK} must not carry userinfo (it leaks into process listings and logs) — ` +
        `use ${ENV.SINK_TOKEN} for the bearer token`,
    };
  }
  if (parsed.protocol === 'http:') {
    if (!isLoopbackHost(parsed.hostname)) {
      return {
        error:
          `refusing plain http sink '${parsed.protocol}//${parsed.host}' — ` +
          'use https:// (loopback is the only exception)',
      };
    }
  } else if (parsed.protocol !== 'https:') {
    return { error: `unsupported ${ENV.SINK} scheme '${parsed.protocol}' (expected https:)` };
  }
  parsed.hash = '';
  parsed.search = '';
  const path = parsed.pathname.replace(/\/+$/, '');
  return { url: `${parsed.protocol}//${parsed.host}${path}` };
}

/**
 * Resolve the sink from flags + env. Never throws; every failure mode is a
 * warning plus a disabled sink.
 */
export function resolveSinkConfig(opts: ResolveSinkOpts): SinkResolution {
  const flags = opts.flags ?? {};
  const env = opts.env;
  const warnings: string[] = [];

  const rawUrl = pick(flags['sink'], env[ENV.SINK]);
  if (rawUrl === undefined) return { warnings };

  const normalized = normalizeSinkUrl(rawUrl);
  if ('error' in normalized) {
    warnings.push(`${normalized.error}; evidence sink disabled`);
    return { warnings };
  }

  const sink: SinkConfig = { url: normalized.url };

  const inlineToken = pick(flags['token'], env[ENV.SINK_TOKEN]);
  const tokenFile = pick(flags['token-file'], env[ENV.SINK_TOKEN_FILE]);
  if (inlineToken !== undefined) {
    sink.token = inlineToken;
    if (tokenFile !== undefined) {
      warnings.push(
        `both ${ENV.SINK_TOKEN} and ${ENV.SINK_TOKEN_FILE} are set; using the inline token`,
      );
    }
  } else if (tokenFile !== undefined) {
    try {
      const text = readFileSync(tokenFile, 'utf8').trim();
      if (text === '') {
        warnings.push(`sink token file ${tokenFile} is empty; shipping without Authorization`);
      } else {
        sink.token = text;
      }
    } catch (cause) {
      const msg = cause instanceof Error ? cause.message : String(cause);
      warnings.push(`cannot read sink token file ${tokenFile} (${msg}); shipping without Authorization`);
    }
  } else {
    warnings.push(
      `${ENV.SINK} is set but no token (${ENV.SINK_TOKEN} / ${ENV.SINK_TOKEN_FILE}); ` +
        'shipping without Authorization — the receiver will most likely answer 401',
    );
  }

  return { sink, warnings };
}
