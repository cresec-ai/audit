/**
 * Gateway boundary filter — server -> client tools/call results.
 *
 * Pure, transport-agnostic functions the stdio gateway applies to the PARSED
 * JSON-RPC response of a `tools/call` before the bytes reach the client:
 *  - secret-shaped values, located with the recorder's own `alwaysPatterns`
 *    (see `defaultSecretPatterns()`), so "secret" means exactly the same
 *    thing here as it does for `secret_refs` in the evidence store;
 *  - suspected prompt-injection markers (`./injection.js`).
 * Each family gets a policy action (`redact` | `block` | `flag` | `off`).
 *
 * Invariants:
 *  - `applyBoundary()` NEVER throws and NEVER mutates its input; a changed
 *    message is a fresh tree that shares only untouched subtrees.
 *  - Only `result.content[*].text` (type "text") and
 *    `result.content[*].resource.text` are scanned. Everything else in the
 *    result (images, blobs, structuredContent, meta) is forwarded verbatim.
 *  - Redaction markers carry only the sha256 prefix of the removed token,
 *    never the token; `secret_refs` carry full refs computed the same way
 *    as `Redactor.hashString`, so `query` can still find a leaked value the
 *    model never saw.
 *  - Precedence when secrets and injection ask for different actions:
 *    block > redact > flag.
 * Also home of the exact human-readable strings a denied/held call gets
 * back (pinned by tests — keep them short and stable).
 */

import type { BoundaryConfig, BoundaryMode } from '../policy/types.js';
import { DEFAULT_POLICY } from '../redact/redactor.js';
import { findInjectionSpans, matchSpans, mergeSpans, type Span } from './injection.js';

/* -------------------------------------------------------------------- */
/* Types                                                                  */
/* -------------------------------------------------------------------- */

/** Per-family action (`mcp.boundary.secrets` / `.injection`), from the policy types. */
export type BoundaryAction = BoundaryMode;
/** `mcp.boundary` section of a normalized policy.yaml v1. */
export type { BoundaryConfig };

/** What happened to one tools/call result, recorded as `gateway.boundary`. */
export interface BoundaryReport {
  /** false when skipped: oversize, both scanners off, or internal error. */
  scanned: boolean;
  action: 'none' | 'redact' | 'block' | 'flag';
  /** Distinct (merged) secret-shaped regions found across all scanned text. */
  secrets_found: number;
  /** Distinct (merged) injection markers found across all scanned text. */
  injection_found: number;
  /** `sha256:<hex>` of each secret token found (deduped, at most 8). */
  secret_refs?: string[];
  /** Present only when the filter hit an internal error (never thrown). */
  error?: string;
}

export interface BoundaryOutcome {
  /** The message the client should receive (the input itself when unchanged). */
  message: unknown;
  changed: boolean;
  report: BoundaryReport;
}

export interface BoundaryDeps {
  /** The recorder's `alwaysPatterns` (or a test double). */
  secretPatterns: readonly RegExp[];
  /** `Redactor.hashString` — produces `sha256:<hex>`. */
  hashString(s: string): string;
}

export interface BoundaryOptions {
  /** Byte length of the raw upstream line, compared with `max_scan_bytes`. */
  rawBytes?: number;
}

/** Cap on `secret_refs`, matching the redactor's `MAX_SECRET_REFS`. */
export const MAX_SECRET_REFS = 8;
/** Number of hex characters of the token hash kept in a redaction marker. */
export const MARKER_HASH_HEX = 16;
/** Text a redacted injection span is replaced with. */
export const INJECTION_MARKER = '[gateway: suspected prompt injection removed]';

/* -------------------------------------------------------------------- */
/* Span primitives                                                        */
/* -------------------------------------------------------------------- */

/** The recorder's secret-shape patterns (same array the `Redactor` uses). */
export function defaultSecretPatterns(): readonly RegExp[] {
  return DEFAULT_POLICY.alwaysPatterns;
}

/** Stable span id for the pattern at `index`. */
function secretId(index: number): string {
  return `secret:${index}`;
}

/** Every raw per-pattern match (may overlap), in pattern order. */
function rawSecretSpans(text: string, patterns: readonly RegExp[]): Span[] {
  const out: Span[] = [];
  patterns.forEach((re, i) => {
    for (const s of matchSpans(re, text, secretId(i))) out.push(s);
  });
  return out;
}

/**
 * Locate secret-shaped tokens in `text`. Returns merged, sorted,
 * non-overlapping spans whose `id` is `secret:<pattern index>` of the
 * earliest contributing pattern. Never throws on non-string input.
 */
export function findSecretSpans(text: string, patterns: readonly RegExp[]): Span[] {
  if (typeof text !== 'string' || text.length === 0) return [];
  return mergeSpans(rawSecretSpans(text, patterns));
}

/**
 * Rebuild `text` with every span replaced by `replacer(span, matched)`.
 * Spans are sorted first; a span overlapping an earlier one is skipped and
 * out-of-range spans are clamped, so any input is safe.
 */
export function redactSpans(
  text: string,
  spans: readonly Span[],
  replacer: (span: Span, matched: string) => string,
): string {
  if (spans.length === 0) return text;
  const sorted = [...spans].sort((a, b) => a.start - b.start || b.end - a.end);
  let out = '';
  let cursor = 0;
  for (const s of sorted) {
    const start = Math.max(0, Math.min(text.length, s.start));
    const end = Math.max(start, Math.min(text.length, s.end));
    if (start < cursor || end === start) continue;
    out += text.slice(cursor, start) + replacer(s, text.slice(start, end));
    cursor = end;
  }
  return out + text.slice(cursor);
}

/* -------------------------------------------------------------------- */
/* applyBoundary                                                          */
/* -------------------------------------------------------------------- */

type Kind = 'secret' | 'injection';

interface Region extends Span {
  kind: Kind;
}

/** One scannable string inside `result.content`. */
interface Slot {
  index: number;
  /** 'text' => content[i].text ; 'resource' => content[i].resource.text */
  where: 'text' | 'resource';
  text: string;
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/** Collect the text slots of a tools/call result; [] when the shape is off. */
function collectSlots(result: unknown): Slot[] {
  if (!isRecord(result)) return [];
  const content = result['content'];
  if (!Array.isArray(content)) return [];
  const slots: Slot[] = [];
  content.forEach((item, index) => {
    if (!isRecord(item)) return;
    if (item['type'] === 'text' && typeof item['text'] === 'string') {
      slots.push({ index, where: 'text', text: item['text'] });
    }
    const resource = item['resource'];
    if (isRecord(resource) && typeof resource['text'] === 'string') {
      slots.push({ index, where: 'resource', text: resource['text'] });
    }
  });
  return slots;
}

/**
 * Union of secret and injection spans for one slot. Overlapping regions
 * collapse into one; a region touching a secret is treated as a secret
 * (its marker hides the bytes, which is the stronger outcome).
 */
function unionRegions(secrets: readonly Span[], injections: readonly Span[]): Region[] {
  const all: Region[] = [
    ...secrets.map((s) => ({ ...s, kind: 'secret' as const })),
    ...injections.map((s) => ({ ...s, kind: 'injection' as const })),
  ].sort((a, b) => a.start - b.start || b.end - a.end);
  const out: Region[] = [];
  for (const r of all) {
    const last = out[out.length - 1];
    if (last !== undefined && r.start < last.end) {
      if (r.end > last.end) last.end = r.end;
      if (r.kind === 'secret') last.kind = 'secret';
    } else {
      out.push({ ...r });
    }
  }
  return out;
}

/** `[redacted:sha256:<16 hex>]` for one secret token. */
function secretMarker(token: string, hashString: (s: string) => string): string {
  const ref = hashString(token);
  const hex = ref.startsWith('sha256:') ? ref.slice('sha256:'.length) : ref;
  return `[redacted:sha256:${hex.slice(0, MARKER_HASH_HEX)}]`;
}

/** Copy-on-write: a new message whose result.content[index] text is `text`. */
function withSlotText(message: Record<string, unknown>, slot: Slot, text: string): Record<string, unknown> {
  const result = message['result'] as Record<string, unknown>;
  const content = [...(result['content'] as unknown[])];
  const item = { ...(content[slot.index] as Record<string, unknown>) };
  if (slot.where === 'text') {
    item['text'] = text;
  } else {
    item['resource'] = { ...(item['resource'] as Record<string, unknown>), text };
  }
  content[slot.index] = item;
  return { ...message, result: { ...result, content } };
}

/** The message with its whole `result` replaced by an isError text result. */
function blockedMessage(message: Record<string, unknown>, text: string): Record<string, unknown> {
  return { ...message, result: { content: [{ type: 'text', text }], isError: true } };
}

function plural(n: number, noun: string): string {
  return `${n} ${noun}${n === 1 ? '' : 's'}`;
}

/** The exact isError text of a blocked result (pinned by tests). */
export function blockedText(secrets: number, injections: number): string {
  return (
    'mcp-recorder gateway: tool result blocked by policy ' +
    `(${plural(secrets, 'secret-shaped value')}, ${plural(injections, 'injection marker')})`
  );
}

/** The exact isError text of a result blocked for exceeding max_scan_bytes. */
export function oversizeBlockedText(rawBytes: number, maxScanBytes: number): string {
  return (
    'mcp-recorder gateway: tool result blocked by policy ' +
    `(result of ${rawBytes} bytes exceeds max_scan_bytes ${maxScanBytes})`
  );
}

function unchanged(message: unknown, report: BoundaryReport): BoundaryOutcome {
  return { message, changed: false, report };
}

/**
 * Apply the boundary policy to a parsed tools/call response. See the module
 * header for the contract. `message` is returned as-is (same reference)
 * whenever nothing had to change.
 */
export function applyBoundary(
  message: unknown,
  config: BoundaryConfig,
  deps: BoundaryDeps,
  opts: BoundaryOptions = {},
): BoundaryOutcome {
  const base: BoundaryReport = { scanned: false, action: 'none', secrets_found: 0, injection_found: 0 };
  try {
    return applyBoundaryUnsafe(message, config, deps, opts, base);
  } catch (err) {
    const msg = err instanceof Error ? `${err.name}: ${err.message}` : String(err);
    return unchanged(message, { ...base, error: msg });
  }
}

function applyBoundaryUnsafe(
  message: unknown,
  config: BoundaryConfig,
  deps: BoundaryDeps,
  opts: BoundaryOptions,
  base: BoundaryReport,
): BoundaryOutcome {
  // Only a response carrying a `result` is ever touched: an error response
  // or a non-object is forwarded verbatim (nothing the model reads is there).
  if (!isRecord(message) || !('result' in message)) return unchanged(message, base);

  const maxScan = Number(config.max_scan_bytes);
  if (typeof opts.rawBytes === 'number' && Number.isFinite(maxScan) && opts.rawBytes > maxScan) {
    if (config.on_oversize === 'block') {
      return {
        message: blockedMessage(message, oversizeBlockedText(opts.rawBytes, maxScan)),
        changed: true,
        report: { ...base, action: 'block' },
      };
    }
    return unchanged(message, { ...base, action: 'flag' });
  }

  const scanSecrets = config.secrets !== 'off';
  const scanInjection = config.injection !== 'off';
  if (!scanSecrets && !scanInjection) return unchanged(message, base);

  const slots = collectSlots(message['result']);
  const perSlot: { slot: Slot; secrets: Span[]; injections: Span[] }[] = [];
  const refs: string[] = [];
  const seenRefs = new Set<string>();
  let secretsFound = 0;
  let injectionFound = 0;

  for (const slot of slots) {
    const raw = scanSecrets ? rawSecretSpans(slot.text, deps.secretPatterns) : [];
    const secrets = mergeSpans(raw);
    const injections = scanInjection ? findInjectionSpans(slot.text) : [];
    secretsFound += secrets.length;
    injectionFound += injections.length;
    for (const s of raw) {
      if (refs.length >= MAX_SECRET_REFS) break;
      const ref = deps.hashString(slot.text.slice(s.start, s.end));
      if (!seenRefs.has(ref)) {
        seenRefs.add(ref);
        refs.push(ref);
      }
    }
    if (secrets.length > 0 || injections.length > 0) perSlot.push({ slot, secrets, injections });
  }

  const report: BoundaryReport = {
    ...base,
    scanned: true,
    secrets_found: secretsFound,
    injection_found: injectionFound,
  };
  if (refs.length > 0) report.secret_refs = refs;

  const secretAction: BoundaryAction | 'none' = secretsFound > 0 ? config.secrets : 'none';
  const injectionAction: BoundaryAction | 'none' = injectionFound > 0 ? config.injection : 'none';

  if (secretAction === 'block' || injectionAction === 'block') {
    return {
      message: blockedMessage(message, blockedText(secretsFound, injectionFound)),
      changed: true,
      report: { ...report, action: 'block' },
    };
  }

  const redactSecrets = secretAction === 'redact';
  const redactInjection = injectionAction === 'redact';
  if (!redactSecrets && !redactInjection) {
    const flagged = secretAction === 'flag' || injectionAction === 'flag';
    return unchanged(message, { ...report, action: flagged ? 'flag' : 'none' });
  }

  let out: Record<string, unknown> = message;
  for (const { slot, secrets, injections } of perSlot) {
    const regions = unionRegions(redactSecrets ? secrets : [], redactInjection ? injections : []);
    if (regions.length === 0) continue;
    const text = redactSpans(slot.text, regions, (span, matched) =>
      (span as Region).kind === 'secret' ? secretMarker(matched, deps.hashString) : INJECTION_MARKER,
    );
    out = withSlotText(out, slot, text);
  }
  return { message: out, changed: out !== message, report: { ...report, action: 'redact' } };
}

/* -------------------------------------------------------------------- */
/* Denied-call synthesis                                                  */
/* -------------------------------------------------------------------- */

/** Outcome of a hold that ended without the call being forwarded. */
export type DeniedHoldOutcome = 'denied' | 'timeout' | 'cancelled' | 'session_end';

export interface DeniedTextInput {
  tool: string;
  /** Absent when the policy default action applied. */
  ruleId?: string;
  reason?: string;
  /** Present for hold outcomes; names the hold in the text. */
  approvalId?: string;
  outcome?: DeniedHoldOutcome;
}

const OUTCOME_PHRASE: Record<DeniedHoldOutcome, string> = {
  denied: 'was denied',
  timeout: 'timed out',
  cancelled: 'was cancelled',
  session_end: 'was abandoned at session end',
};

/**
 * The text the model sees for a call the gateway did not forward:
 *   mcp-recorder gateway: tools/call "<tool>" denied by policy rule "<rule>": <reason>
 *   mcp-recorder gateway: tools/call "<tool>" denied by policy default
 *   mcp-recorder gateway: tools/call "<tool>" denied by policy rule "<rule>" (hold <id> timed out): <reason>
 */
export function deniedText(input: DeniedTextInput): string {
  const by = input.ruleId !== undefined ? `policy rule "${input.ruleId}"` : 'policy default';
  let text = `mcp-recorder gateway: tools/call "${input.tool}" denied by ${by}`;
  if (input.approvalId !== undefined) {
    const phrase = input.outcome !== undefined ? OUTCOME_PHRASE[input.outcome] : 'was not approved';
    text += ` (hold ${input.approvalId} ${phrase})`;
  }
  if (input.reason !== undefined && input.reason !== '') text += `: ${input.reason}`;
  return text;
}

/** JSON-RPC response carrying a tool-execution error (MCP `isError`). */
export function synthesizeDeniedResult(
  id: string | number,
  text: string,
): { jsonrpc: '2.0'; id: string | number; result: { content: { type: 'text'; text: string }[]; isError: true } } {
  return { jsonrpc: '2.0', id, result: { content: [{ type: 'text', text }], isError: true } };
}
