/**
 * Gateway boundary filter — server -> client tools/call results.
 *
 * Pure, transport-agnostic functions the stdio gateway applies to the PARSED
 * JSON-RPC response of a `tools/call` before the bytes reach the client:
 *  - secret-shaped values, located with a NARROWED subset of the recorder's
 *    own `alwaysPatterns` (see `boundarySecretPatterns()`);
 *  - suspected prompt-injection markers (`./injection.js`).
 * Each family gets a policy action (`redact` | `block` | `flag` | `off`).
 *
 * Storage redaction and the boundary filter are deliberately NOT the same
 * set. Storage hashes anything that could be a secret — a miss there is
 * irreversible evidence loss, and a false positive costs nothing but a hash.
 * The boundary REWRITES what the model reads, so a false positive costs real
 * tool output: the generic "long hex run" and "long base64 blob" shapes match
 * git SHAs, sha256 checksums, dashless UUIDs, Docker digests and inline
 * images, and are excluded here. `secret_refs` in the evidence store keep
 * their full, wider meaning.
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
 *  - Every boundary pattern IS one of the recorder's `alwaysPatterns` (the
 *    same RegExp object, selected by source); the boundary can only ever be
 *    a subset of what storage redaction already hashes.
 *  - Precedence when secrets and injection ask for different actions:
 *    block > redact > flag.
 * Also home of the exact human-readable strings a denied/held call gets
 * back (pinned by tests — keep them short and stable).
 */
import { DEFAULT_POLICY } from '../redact/redactor.js';
import { findInjectionSpans, matchSpans, mergeSpans } from './injection.js';
/** Cap on `secret_refs`, matching the redactor's `MAX_SECRET_REFS`. */
export const MAX_SECRET_REFS = 8;
/** Number of hex characters of the token hash kept in a redaction marker. */
export const MARKER_HASH_HEX = 16;
/** Text a redacted injection span is replaced with. */
export const INJECTION_MARKER = '[gateway: suspected prompt injection removed]';
/**
 * The secret families the BOUNDARY filter may rewrite: provider-prefixed
 * credentials, JWTs, PEM private-key blocks and explicit secret assignments.
 * Every entry names a pattern that also lives in the recorder's
 * `alwaysPatterns`; the generic long-hex and long-base64 shapes are
 * deliberately absent (see the module header).
 */
export const BOUNDARY_SECRET_FAMILIES = [
    {
        id: 'aws-access-key-id',
        re: /\b(AKIA|ASIA)[0-9A-Z]{16}\b/,
        note: 'AKIA/ASIA + 16 upper-case alphanumerics is an AWS key id and nothing else.',
    },
    {
        id: 'jwt',
        re: /\beyJ[\w-]{10,}\.[\w-]{10,}\.[\w-]{10,}\b/,
        note: 'Three base64url segments whose first decodes to a `{"` JSON header (`eyJ`).',
    },
    {
        id: 'pem-private-key',
        re: /-----BEGIN [A-Z ]+PRIVATE KEY-----/,
        note: 'A PEM private-key armour line is never ordinary tool output.',
    },
    {
        id: 'sk-prefixed-api-key',
        re: /\bsk-[A-Za-z0-9_-]{10,}\b/,
        note: 'OpenAI `sk-...` and Anthropic `sk-ant-...` keys.',
    },
    {
        id: 'github-token',
        re: /\bgh[pousr]_[A-Za-z0-9]{20,}\b/,
        note: 'GitHub `ghp_`/`gho_`/`ghu_`/`ghs_`/`ghr_` tokens.',
    },
    {
        id: 'slack-token',
        re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/,
        note: 'Slack `xoxb-`/`xoxp-`/`xoxa-`/`xoxr-`/`xoxs-` tokens.',
    },
    {
        id: 'bearer-header',
        re: /\bBearer\s+[A-Za-z0-9._~+/=-]{16,}/i,
        note: 'An Authorization bearer value: the keyword makes it a credential by construction.',
    },
    {
        id: 'secret-assignment',
        re: /\b(password|passwd|secret|token|api[_-]?key)\b\s*[:=]\s*\S+/i,
        note: '`password=`, `passwd:`, `secret=`, `token:`, `api_key=` with a value.',
    },
];
const BOUNDARY_SOURCES = new Set(BOUNDARY_SECRET_FAMILIES.map((f) => f.re.source));
/**
 * The recorder's own RegExp objects for the families above, in the
 * recorder's order. Computed once: the returned array is the same reference
 * every call, and its entries are identical to the storage patterns (so no
 * `lastIndex` state is introduced and `boundary ⊆ storage` is an identity,
 * not a copy).
 */
const BOUNDARY_PATTERNS = Object.freeze(DEFAULT_POLICY.alwaysPatterns.filter((re) => BOUNDARY_SOURCES.has(re.source)));
/**
 * The secret-shape patterns the BOUNDARY filter runs — the high-confidence
 * subset of the recorder's `alwaysPatterns` described by
 * `BOUNDARY_SECRET_FAMILIES`. Generic long-hex (git SHAs, sha256 checksums,
 * dashless UUIDs) and generic base64 (inline images, Docker digests) are NOT
 * here; they still hash in the evidence store.
 */
export function boundarySecretPatterns() {
    return BOUNDARY_PATTERNS;
}
/** Stable span id for the pattern at `index`. */
function secretId(index) {
    return `secret:${index}`;
}
/** Every raw per-pattern match (may overlap), in pattern order. */
function rawSecretSpans(text, patterns) {
    const out = [];
    patterns.forEach((re, i) => {
        for (const s of matchSpans(re, text, secretId(i)))
            out.push(s);
    });
    return out;
}
/**
 * Locate secret-shaped tokens in `text`. Returns merged, sorted,
 * non-overlapping spans whose `id` is `secret:<pattern index>` of the
 * earliest contributing pattern. Never throws on non-string input.
 */
export function findSecretSpans(text, patterns) {
    if (typeof text !== 'string' || text.length === 0)
        return [];
    return mergeSpans(rawSecretSpans(text, patterns));
}
/**
 * Rebuild `text` with every span replaced by `replacer(span, matched)`.
 * Spans are sorted first; a span overlapping an earlier one is skipped and
 * out-of-range spans are clamped, so any input is safe.
 */
export function redactSpans(text, spans, replacer) {
    if (spans.length === 0)
        return text;
    const sorted = [...spans].sort((a, b) => a.start - b.start || b.end - a.end);
    let out = '';
    let cursor = 0;
    for (const s of sorted) {
        const start = Math.max(0, Math.min(text.length, s.start));
        const end = Math.max(start, Math.min(text.length, s.end));
        if (start < cursor || end === start)
            continue;
        out += text.slice(cursor, start) + replacer(s, text.slice(start, end));
        cursor = end;
    }
    return out + text.slice(cursor);
}
function isRecord(v) {
    return typeof v === 'object' && v !== null && !Array.isArray(v);
}
/** Collect the text slots of a tools/call result; [] when the shape is off. */
function collectSlots(result) {
    if (!isRecord(result))
        return [];
    const content = result['content'];
    if (!Array.isArray(content))
        return [];
    const slots = [];
    content.forEach((item, index) => {
        if (!isRecord(item))
            return;
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
function unionRegions(secrets, injections) {
    const all = [
        ...secrets.map((s) => ({ ...s, kind: 'secret' })),
        ...injections.map((s) => ({ ...s, kind: 'injection' })),
    ].sort((a, b) => a.start - b.start || b.end - a.end);
    const out = [];
    for (const r of all) {
        const last = out[out.length - 1];
        if (last !== undefined && r.start < last.end) {
            if (r.end > last.end)
                last.end = r.end;
            if (r.kind === 'secret')
                last.kind = 'secret';
        }
        else {
            out.push({ ...r });
        }
    }
    return out;
}
/** `[redacted:sha256:<16 hex>]` for one secret token. */
function secretMarker(token, hashString) {
    const ref = hashString(token);
    const hex = ref.startsWith('sha256:') ? ref.slice('sha256:'.length) : ref;
    return `[redacted:sha256:${hex.slice(0, MARKER_HASH_HEX)}]`;
}
/** Copy-on-write: a new message whose result.content[index] text is `text`. */
function withSlotText(message, slot, text) {
    const result = message['result'];
    const content = [...result['content']];
    const item = { ...content[slot.index] };
    if (slot.where === 'text') {
        item['text'] = text;
    }
    else {
        item['resource'] = { ...item['resource'], text };
    }
    content[slot.index] = item;
    return { ...message, result: { ...result, content } };
}
/** The message with its whole `result` replaced by an isError text result. */
function blockedMessage(message, text) {
    return { ...message, result: { content: [{ type: 'text', text }], isError: true } };
}
function plural(n, noun) {
    return `${n} ${noun}${n === 1 ? '' : 's'}`;
}
/** The exact isError text of a blocked result (pinned by tests). */
export function blockedText(secrets, injections) {
    return ('mcp-recorder gateway: tool result blocked by policy ' +
        `(${plural(secrets, 'secret-shaped value')}, ${plural(injections, 'injection marker')})`);
}
/** The exact isError text of a result blocked for exceeding max_scan_bytes. */
export function oversizeBlockedText(rawBytes, maxScanBytes) {
    return ('mcp-recorder gateway: tool result blocked by policy ' +
        `(result of ${rawBytes} bytes exceeds max_scan_bytes ${maxScanBytes})`);
}
function unchanged(message, report) {
    return { message, changed: false, report };
}
/**
 * Apply the boundary policy to a parsed tools/call response. See the module
 * header for the contract. `message` is returned as-is (same reference)
 * whenever nothing had to change.
 */
export function applyBoundary(message, config, deps, opts = {}) {
    const base = { scanned: false, action: 'none', secrets_found: 0, injection_found: 0 };
    try {
        return applyBoundaryUnsafe(message, config, deps, opts, base);
    }
    catch (err) {
        const msg = err instanceof Error ? `${err.name}: ${err.message}` : String(err);
        return unchanged(message, { ...base, error: msg });
    }
}
function applyBoundaryUnsafe(message, config, deps, opts, base) {
    // Only a response carrying a `result` is ever touched: an error response
    // or a non-object is forwarded verbatim (nothing the model reads is there).
    if (!isRecord(message) || !('result' in message))
        return unchanged(message, base);
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
    if (!scanSecrets && !scanInjection)
        return unchanged(message, base);
    const slots = collectSlots(message['result']);
    const perSlot = [];
    const refs = [];
    const seenRefs = new Set();
    let secretsFound = 0;
    let injectionFound = 0;
    for (const slot of slots) {
        const raw = scanSecrets ? rawSecretSpans(slot.text, deps.secretPatterns) : [];
        const secrets = mergeSpans(raw);
        const injections = scanInjection ? findInjectionSpans(slot.text) : [];
        secretsFound += secrets.length;
        injectionFound += injections.length;
        for (const s of raw) {
            if (refs.length >= MAX_SECRET_REFS)
                break;
            const ref = deps.hashString(slot.text.slice(s.start, s.end));
            if (!seenRefs.has(ref)) {
                seenRefs.add(ref);
                refs.push(ref);
            }
        }
        if (secrets.length > 0 || injections.length > 0)
            perSlot.push({ slot, secrets, injections });
    }
    const report = {
        ...base,
        scanned: true,
        secrets_found: secretsFound,
        injection_found: injectionFound,
    };
    if (refs.length > 0)
        report.secret_refs = refs;
    const secretAction = secretsFound > 0 ? config.secrets : 'none';
    const injectionAction = injectionFound > 0 ? config.injection : 'none';
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
    let out = message;
    for (const { slot, secrets, injections } of perSlot) {
        const regions = unionRegions(redactSecrets ? secrets : [], redactInjection ? injections : []);
        if (regions.length === 0)
            continue;
        const text = redactSpans(slot.text, regions, (span, matched) => span.kind === 'secret' ? secretMarker(matched, deps.hashString) : INJECTION_MARKER);
        out = withSlotText(out, slot, text);
    }
    return { message: out, changed: out !== message, report: { ...report, action: 'redact' } };
}
const OUTCOME_PHRASE = {
    denied: 'was denied',
    timeout: 'timed out',
    cancelled: 'was cancelled',
    session_end: 'was abandoned at session end',
};
/**
 * The text the model sees for a call the gateway did not forward:
 *   mcp-recorder gateway: tools/call "<tool>" denied by policy rule "<rule>": <reason>
 *   mcp-recorder gateway: tools/call "<tool>" denied by policy (no rule matched; mcp.default is deny)
 *   mcp-recorder gateway: tools/call "<tool>" denied by policy: policy evaluation error: <detail>
 *   mcp-recorder gateway: tools/call "<tool>" denied by policy rule "<rule>" (hold <id> timed out): <reason>
 *
 * A deny without a rule id says "denied by policy", never "by policy
 * default": an evaluation-error deny or a hold-limit refusal is not the
 * default acting, and the text must not claim it is. The default case is
 * the one with neither a rule nor a reason, and it says so explicitly.
 */
export function deniedText(input) {
    const by = input.ruleId !== undefined ? `policy rule "${input.ruleId}"` : 'policy';
    let text = `mcp-recorder gateway: tools/call "${input.tool}" denied by ${by}`;
    if (input.approvalId !== undefined) {
        const phrase = input.outcome !== undefined ? OUTCOME_PHRASE[input.outcome] : 'was not approved';
        text += ` (hold ${input.approvalId} ${phrase})`;
    }
    const hasReason = input.reason !== undefined && input.reason !== '';
    if (hasReason)
        text += `: ${input.reason}`;
    else if (input.ruleId === undefined && input.approvalId === undefined)
        text += ' (no rule matched; mcp.default is deny)';
    return text;
}
/** JSON-RPC response carrying a tool-execution error (MCP `isError`). */
export function synthesizeDeniedResult(id, text) {
    return { jsonrpc: '2.0', id, result: { content: [{ type: 'text', text }], isError: true } };
}
//# sourceMappingURL=boundary.js.map