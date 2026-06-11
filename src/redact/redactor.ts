/**
 * Edge redaction — M1's trust gate.
 *
 * Every JSON tree that crosses the proxy is scrubbed here before it can land
 * in the evidence store. Structure is preserved; string leaves are replaced
 * by `RedactedRef`s (unsalted SHA-256 + length) unless the policy explicitly
 * allows them through. `scrub()` NEVER throws — a redaction failure must
 * degrade to "hash more", never to "record less" or "break traffic".
 */

import { sha256Ref } from '../chain/hash.js';
import type { RedactedRef, Scrubbed, Sha256Ref } from '../schema/events.js';
import type { RedactionPolicy, RedactorLike } from '../types.js';

/** Literal stored (hashed) for function/symbol leaves. */
const UNSERIALIZABLE = '[unserializable]';
/** Literal stored (hashed) when JSON.stringify of a subtree throws. */
const CIRCULAR = '[circular]';

/**
 * Charset a string must satisfy to pass the allowlist: word chars plus a
 * small set of structural punctuation (paths, mime types, method names, ...).
 */
const STRUCTURAL_CHARSET = /^[\w .,@()\/:+#-]*$/;

/**
 * Secret shapes hashed in EVERY mode. None of these carry the /g flag on
 * purpose: a sticky lastIndex across .test() calls silently skips matches.
 */
const ALWAYS_PATTERNS: RegExp[] = [
  // AWS access key ids
  /\b(AKIA|ASIA)[0-9A-Z]{16}\b/,
  // JWTs (three dot-separated base64url segments starting "eyJ")
  /\beyJ[\w-]{10,}\.[\w-]{10,}\.[\w-]{10,}\b/,
  // PEM private key blocks
  /-----BEGIN [A-Z ]+PRIVATE KEY-----/,
  // OpenAI-style keys
  /\bsk-[A-Za-z0-9_-]{10,}\b/,
  // GitHub tokens (ghp_, gho_, ghu_, ghs_, ghr_)
  /\bgh[pousr]_[A-Za-z0-9]{20,}\b/,
  // Slack tokens
  /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/,
  // Bearer auth headers
  /\bBearer\s+[A-Za-z0-9._~+\/=-]{16,}/i,
  // Long hex blobs (>= 32 hex chars: digests, session ids, raw keys)
  /\b[0-9a-fA-F]{32,}\b/,
  // Long base64 blobs (>= 40 chars)
  /\b[A-Za-z0-9+\/]{40,}={0,2}\b/,
  // password-ish assignments ("password=...", "api_key: ...")
  /\b(password|passwd|secret|token|api[_-]?key)\b\s*[:=]\s*\S+/i,
];

export const DEFAULT_POLICY: RedactionPolicy = {
  mode: 'allowlist',
  allowKeys: [
    'type',
    'name',
    'kind',
    'method',
    'mimeType',
    'role',
    'protocolVersion',
    'level',
    'status',
    'tool',
    'code',
  ],
  maxAllowedStringLen: 64,
  alwaysPatterns: ALWAYS_PATTERNS,
  maxDepth: 32,
};

/**
 * True when the string matches any secret-shaped pattern. Used by the proxy
 * to fingerprint env credentials. Defensive about /g lastIndex even though
 * the defaults never use it.
 */
export function looksSecret(
  s: string,
  patterns: RegExp[] = DEFAULT_POLICY.alwaysPatterns,
): boolean {
  for (const re of patterns) {
    re.lastIndex = 0;
    if (re.test(s)) return true;
  }
  return false;
}

export class Redactor implements RedactorLike {
  private readonly policy: RedactionPolicy;
  private readonly allowKeySet: Set<string>;

  constructor(policy?: Partial<RedactionPolicy>) {
    this.policy = {
      ...DEFAULT_POLICY,
      ...policy,
      // Clone arrays so callers mutating their input cannot mutate ours.
      allowKeys: [...(policy?.allowKeys ?? DEFAULT_POLICY.allowKeys)],
      alwaysPatterns: [...(policy?.alwaysPatterns ?? DEFAULT_POLICY.alwaysPatterns)],
    };
    this.allowKeySet = new Set(this.policy.allowKeys);
  }

  get mode(): RedactionPolicy['mode'] {
    return this.policy.mode;
  }

  /** sha256:<hex> of the exact string — matches RedactedRef.ref format. */
  hashString(value: string): Sha256Ref {
    return sha256Ref(value);
  }

  /** Redact a JSON tree per policy. Never throws; worst case returns a ref. */
  scrub(value: unknown): Scrubbed {
    try {
      return this.walk(value, undefined, 0, new Set());
    } catch {
      // Should be unreachable; absolute backstop so scrub can never throw.
      return this.stringifyRef(value);
    }
  }

  /* ------------------------------ internals ----------------------------- */

  private walk(
    value: unknown,
    key: string | undefined,
    depth: number,
    ancestors: Set<object>,
  ): Scrubbed {
    if (value === null || value === undefined) return null;
    switch (typeof value) {
      case 'number':
      case 'boolean':
        return value;
      case 'string':
        return this.scrubString(value, key);
      case 'bigint':
        return this.scrubString(String(value), key);
      case 'function':
      case 'symbol':
        return this.refOf(UNSERIALIZABLE);
      case 'object':
        break;
      default:
        // Future exotic typeof values: refuse to guess, hash a marker.
        return this.refOf(UNSERIALIZABLE);
    }

    const obj = value as object;
    if (depth > this.policy.maxDepth || ancestors.has(obj)) {
      // Too deep, or a true cycle: collapse the whole subtree to a ref.
      return this.stringifyRef(obj);
    }

    ancestors.add(obj);
    try {
      if (Array.isArray(obj)) {
        const out: Scrubbed[] = [];
        for (const el of obj) {
          // Array elements have no object key → never allow-listed.
          out.push(this.walk(el, undefined, depth + 1, ancestors));
        }
        return out;
      }
      const rec = obj as Record<string, unknown>;
      const out: { [k: string]: Scrubbed } = {};
      for (const k of Object.keys(rec)) {
        out[k] = this.walk(rec[k], k, depth + 1, ancestors);
      }
      return out;
    } finally {
      ancestors.delete(obj);
    }
  }

  private scrubString(v: string, key: string | undefined): Scrubbed {
    // alwaysPatterns fire in EVERY mode.
    if (looksSecret(v, this.policy.alwaysPatterns)) return this.refOf(v);
    if (this.policy.mode === 'off') return v;
    // allowlist mode: a string passes only when ALL gates hold.
    if (
      key !== undefined &&
      this.allowKeySet.has(key) &&
      v.length <= this.policy.maxAllowedStringLen &&
      STRUCTURAL_CHARSET.test(v)
    ) {
      return v;
    }
    return this.refOf(v);
  }

  private refOf(original: string): RedactedRef {
    return { redacted: true, ref: this.hashString(original), len: original.length };
  }

  /** Collapse an arbitrary value to the ref of its JSON serialization. */
  private stringifyRef(value: unknown): RedactedRef {
    let s: string;
    try {
      const j = JSON.stringify(value);
      s = typeof j === 'string' ? j : CIRCULAR;
    } catch {
      s = CIRCULAR; // circular structure, bigint, throwing toJSON, ...
    }
    return this.refOf(s);
  }
}
