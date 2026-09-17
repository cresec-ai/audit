/**
 * Policy file loader: bytes -> parsed document -> validated, normalized
 * `Policy`, plus the sha256 of the exact file bytes (the `policy_hash`
 * stamped on events).
 *
 * `.json` is parsed with JSON.parse; everything else (`.yaml`, `.yml`, and
 * any other extension — YAML is a superset of JSON) with the `yaml` package
 * using the YAML 1.2 core schema, duplicate keys rejected, `<<` merge keys
 * disabled and a low alias cap. Values that are not JSON-plain (`!!binary`,
 * `!!set`, `.nan`, `.inf`, ...) are rejected after parsing so a policy can
 * never contain anything JSON.stringify would mangle.
 *
 * Failures are `PolicyLoadError` (unreadable / unparseable / bad root) or its
 * subclass `PolicyValidationError` (schema / semantic errors, with the error
 * list attached). Both name the file path in their message.
 */

import { readFileSync } from 'node:fs';
import { extname } from 'node:path';
import { parse as parseYaml } from 'yaml';
import { sha256Hex } from '../chain/hash.js';
import type { Sha256Ref } from '../schema/events.js';
import type { Policy } from './types.js';
import { formatPolicyErrors, validatePolicyObject } from './validate.js';
import type { PolicyError } from './validate.js';

export type PolicySource = 'yaml' | 'json';

export interface LoadedPolicy {
  policy: Policy;
  /** `sha256:<64 hex>` of the exact file bytes. */
  hash: Sha256Ref;
  /** `policy.name`, when set. */
  name?: string;
  source: PolicySource;
  /** The path as given to `loadPolicyFile`. */
  path: string;
}

export class PolicyLoadError extends Error {
  readonly path: string;
  constructor(path: string, detail: string) {
    super(`${path}: ${detail}`);
    this.name = 'PolicyLoadError';
    this.path = path;
  }
}

export class PolicyValidationError extends PolicyLoadError {
  readonly errors: readonly PolicyError[];
  constructor(path: string, errors: readonly PolicyError[]) {
    super(path, `invalid policy (${errors.length} error${errors.length === 1 ? '' : 's'})\n${formatPolicyErrors(errors)}`);
    this.name = 'PolicyValidationError';
    this.errors = errors;
  }
}

/** Max aliases a YAML document may expand; policies never need many. */
const MAX_ALIASES = 100;

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && Object.getPrototypeOf(v) === Object.prototype;
}

/**
 * Ensure a parsed tree contains only JSON values (null, finite number,
 * string, boolean, array, plain object). Returns a pointer + reason for the
 * first offender, or undefined.
 */
export function findNonJsonValue(value: unknown, path = ''): { path: string; reason: string } | undefined {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return undefined;
  if (typeof value === 'number') {
    return Number.isFinite(value) ? undefined : { path, reason: `non-finite number ${String(value)}` };
  }
  if (Array.isArray(value)) {
    for (let i = 0; i < value.length; i++) {
      const bad = findNonJsonValue(value[i], `${path}/${i}`);
      if (bad !== undefined) return bad;
    }
    return undefined;
  }
  if (isPlainObject(value)) {
    for (const [k, v] of Object.entries(value)) {
      const bad = findNonJsonValue(v, `${path}/${k.replace(/~/g, '~0').replace(/\//g, '~1')}`);
      if (bad !== undefined) return bad;
    }
    return undefined;
  }
  const kind =
    value === undefined
      ? 'undefined'
      : typeof value === 'object'
        ? (Object.getPrototypeOf(value)?.constructor?.name as string | undefined) ?? 'object'
        : typeof value;
  return { path, reason: `unsupported value of type ${kind} (only JSON values are allowed)` };
}

export function sourceForPath(path: string): PolicySource {
  return extname(path).toLowerCase() === '.json' ? 'json' : 'yaml';
}

/** Parse policy text as YAML or JSON into a JSON-plain object root. Throws PolicyLoadError. */
export function parsePolicyText(text: string, source: PolicySource, path: string): Record<string, unknown> {
  let doc: unknown;
  try {
    doc =
      source === 'json'
        ? JSON.parse(text)
        : parseYaml(text, {
            schema: 'core',
            version: '1.2',
            uniqueKeys: true,
            merge: false,
            maxAliasCount: MAX_ALIASES,
            prettyErrors: true,
          });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    throw new PolicyLoadError(path, `${source === 'json' ? 'JSON' : 'YAML'} parse error: ${msg}`);
  }
  if (!isPlainObject(doc)) {
    const got = doc === null || doc === undefined ? 'empty document' : Array.isArray(doc) ? 'array' : typeof doc;
    throw new PolicyLoadError(path, `policy root must be a mapping/object, got ${got}`);
  }
  const bad = findNonJsonValue(doc);
  if (bad !== undefined) throw new PolicyLoadError(path, `${bad.path || '/'}: ${bad.reason}`);
  return doc;
}

/**
 * Read, parse, validate and normalize a policy file. Throws
 * `PolicyLoadError` / `PolicyValidationError`; never returns a partially
 * valid policy.
 */
export function loadPolicyFile(path: string): LoadedPolicy {
  let bytes: Buffer;
  try {
    bytes = readFileSync(path);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    throw new PolicyLoadError(path, `cannot read policy file: ${msg}`);
  }
  const source = sourceForPath(path);
  const doc = parsePolicyText(bytes.toString('utf8'), source, path);
  const result = validatePolicyObject(doc);
  if (!result.ok) throw new PolicyValidationError(path, result.errors);
  const out: LoadedPolicy = { policy: result.policy, hash: 'sha256:' + sha256Hex(bytes), source, path };
  if (result.policy.name !== undefined) out.name = result.policy.name;
  return out;
}
