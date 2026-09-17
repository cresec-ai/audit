/**
 * Blast-radius query — "what did this value touch?"
 *
 * The store never holds plaintext payloads, only unsalted SHA-256 refs, so a
 * known probe value (a leaked key, a customer email, ...) can be traced by
 * hashing it the exact same way and walking the chain for matching refs.
 *
 * Match locations, in preference order (one match per event):
 *   ref         — a RedactedRef leaf whose ref equals sha256(needle), OR whose
 *                 secret_refs contains sha256(needle) (a token embedded in a
 *                 larger leaf), OR an object KEY that was itself hashed to
 *                 sha256(needle)
 *   result_hash — the event's result_hash equals sha256(needle)
 *   args_hash   — a policy_decision's args_hash equals sha256(needle), i.e.
 *                 the needle is the canonical JSON of the arguments of a call
 *                 the gateway denied or held (gateway mode; those arguments
 *                 exist nowhere else in clear)
 *   credential  — an identity credential fingerprint equals sha256(needle)
 *   name        — tool / method / server.name equals the needle (case-insensitive)
 *   plain       — a plain string leaf contains the needle (case-sensitive)
 *
 * A `ref` miss is not proof of absence: secret_refs only covers tokens that
 * matched a known alwaysPatterns shape, and a plain-string miss is limited
 * to whatever wasn't itself redacted.
 */
import { sha256Ref } from '../chain/hash.js';
/** Lower = stronger evidence; the strongest single location wins per event. */
const PRIORITY = {
    ref: 0,
    result_hash: 1,
    args_hash: 2,
    credential: 3,
    name: 4,
    plain: 5,
};
function isRedactedRef(value) {
    return (typeof value === 'object' &&
        value !== null &&
        !Array.isArray(value) &&
        value.redacted === true &&
        typeof value.ref === 'string' &&
        typeof value.len === 'number');
}
const IDENT_RE = /^[A-Za-z_$][\w$]*$/;
/** Append one key to a JSON-path: `.key` or `['weird.key']`. */
function pathSegment(key) {
    if (IDENT_RE.test(key))
        return '.' + key;
    return "['" + key.replace(/\\/g, '\\\\').replace(/'/g, "\\'") + "']";
}
/** One depth-first pass over the event tree, recording first hits per type. */
function walkTree(value, path, needle, needleHash, hits) {
    if (hits.ref !== undefined && hits.plain !== undefined)
        return;
    if (typeof value === 'string') {
        if (hits.plain === undefined && needle.length > 0 && value.includes(needle)) {
            hits.plain = path;
        }
        return;
    }
    if (value === null || typeof value !== 'object')
        return;
    if (isRedactedRef(value)) {
        // RedactedRefs are atomic leaves: compare the ref, never their fields.
        if (hits.ref === undefined) {
            if (value.ref === needleHash) {
                hits.ref = path;
            }
            else if (Array.isArray(value.secret_refs)) {
                // A secret embedded INSIDE a larger leaf (e.g. "KEY=AKIA...\n"):
                // the whole-leaf ref differs, but a matched token's hash is here.
                const idx = value.secret_refs.indexOf(needleHash);
                if (idx !== -1)
                    hits.ref = `${path}.secret_refs[${idx}]`;
            }
        }
        return;
    }
    if (Array.isArray(value)) {
        for (let i = 0; i < value.length; i++) {
            walkTree(value[i], `${path}[${i}]`, needle, needleHash, hits);
            if (hits.ref !== undefined && hits.plain !== undefined)
                return;
        }
        return;
    }
    const rec = value;
    for (const key of Object.keys(rec)) {
        // An object KEY may itself have been hashed (P1 key redaction): a key
        // that literally equals sha256(needle) means the needle was used as a
        // key at this location, even though it's never a leaf VALUE.
        if (hits.ref === undefined && key === needleHash) {
            hits.ref = path + pathSegment(key) + '#key';
        }
        walkTree(rec[key], path + pathSegment(key), needle, needleHash, hits);
        if (hits.ref !== undefined && hits.plain !== undefined)
            return;
    }
}
/** All match locations found in one event, strongest first. */
function findCandidates(seq, event, needle, needleHash) {
    const candidates = [];
    const hits = {};
    walkTree(event, '$', needle, needleHash, hits);
    if (hits.ref !== undefined)
        candidates.push({ matched_on: 'ref', path: hits.ref });
    if ((event.kind === 'tool_call' || event.kind === 'rpc') &&
        event.result_hash === needleHash) {
        candidates.push({ matched_on: 'result_hash', path: '$.result_hash' });
    }
    // Gateway mode (additive): a denied or held call never reached the server,
    // so its arguments exist only as `args_hash` — sha256 of their canonical
    // JSON — on the policy_decision. That is a plain string field, not a
    // RedactedRef leaf, so the walk above never sees it. Querying the exact
    // canonical-JSON arguments must still name the call that was refused.
    if (event.kind === 'policy_decision' && event.args_hash === needleHash) {
        candidates.push({ matched_on: 'args_hash', path: '$.args_hash' });
    }
    const fingerprints = event.identity.credential_fingerprints;
    if (fingerprints !== undefined) {
        for (let i = 0; i < fingerprints.length; i++) {
            if (fingerprints[i]?.ref === needleHash) {
                candidates.push({
                    matched_on: 'credential',
                    path: `$.identity.credential_fingerprints[${i}].ref`,
                });
                break;
            }
        }
    }
    // Gateway mode (additive): a secret the boundary filter redacted out of a
    // tool result before the model saw it is recorded only as its hash in
    // `gateway.boundary.secret_refs` — plain strings, not a RedactedRef leaf,
    // so the walk above does not see them. A needle that was redacted at the
    // boundary must still trace to the call it was scrubbed from.
    if (event.kind === 'tool_call' && event.gateway?.boundary?.secret_refs !== undefined) {
        const refs = event.gateway.boundary.secret_refs;
        if (Array.isArray(refs)) {
            const idx = refs.indexOf(needleHash);
            if (idx !== -1) {
                candidates.push({ matched_on: 'ref', path: `$.gateway.boundary.secret_refs[${idx}]` });
            }
        }
    }
    // `tool` / `method` stay plain strings by schema (never a RedactedRef), but
    // an over-long or oddly-shaped one is capped at the edge to its own
    // `sha256:<hex>` (structuralString, P0) — the generic RedactedRef walk
    // above never sees this since it isn't an object leaf. Check the raw field
    // against needleHash directly so a blast-radius query for the original
    // (oversized/malformed) name still finds the event that carried it.
    // policy_decision carries `tool` capped exactly like tool_call (gateway mode).
    if ((event.kind === 'tool_call' || event.kind === 'policy_decision') && event.tool === needleHash) {
        candidates.push({ matched_on: 'ref', path: '$.tool' });
    }
    else if ((event.kind === 'rpc' || event.kind === 'notification') &&
        event.method === needleHash) {
        candidates.push({ matched_on: 'ref', path: '$.method' });
    }
    if (needle.length > 0) {
        const lower = needle.toLowerCase();
        const tool = event.kind === 'tool_call' || event.kind === 'policy_decision' ? event.tool : undefined;
        const method = event.kind === 'rpc' || event.kind === 'notification' ? event.method : undefined;
        if (tool !== undefined && tool.toLowerCase() === lower) {
            candidates.push({ matched_on: 'name', path: '$.tool' });
        }
        else if (method !== undefined && method.toLowerCase() === lower) {
            candidates.push({ matched_on: 'name', path: '$.method' });
        }
        else if (event.server.name.toLowerCase() === lower) {
            candidates.push({ matched_on: 'name', path: '$.server.name' });
        }
    }
    if (hits.plain !== undefined)
        candidates.push({ matched_on: 'plain', path: hits.plain });
    candidates.sort((a, b) => PRIORITY[a.matched_on] - PRIORITY[b.matched_on]);
    return candidates.map((c) => toMatch(seq, event, c.matched_on, c.path));
}
function toMatch(seq, event, matchedOn, path) {
    // policy_decision (gateway mode) names the tool the decision was about,
    // exactly like tool_call — so `query` output reads the same for both.
    const name = event.kind === 'tool_call' || event.kind === 'policy_decision'
        ? event.tool
        : event.kind === 'rpc' || event.kind === 'notification'
            ? event.method
            : undefined;
    const match = {
        seq,
        session_id: event.session_id,
        timestamp: event.timestamp,
        kind: event.kind,
        matched_on: matchedOn,
        path,
    };
    if (name !== undefined)
        match.name = name;
    return match;
}
/**
 * Trace a value through the evidence chain. One QueryMatch per touched event
 * (the strongest match location wins); sessions are the distinct sessions
 * touched, newest first.
 */
export function queryStore(store, needle, opts) {
    const needleHash = sha256Ref(needle);
    const matches = [];
    const touchedSessions = new Set();
    const iterateOpts = opts?.sessionId !== undefined ? { sessionId: opts.sessionId } : {};
    for (const record of store.iterate(iterateOpts)) {
        const candidates = findCandidates(record.seq, record.event, needle, needleHash);
        const best = candidates[0];
        if (best === undefined)
            continue;
        matches.push(best);
        touchedSessions.add(record.event.session_id);
    }
    const sessions = store
        .sessions()
        .filter((s) => touchedSessions.has(s.session_id))
        .sort((a, b) => b.started_at.localeCompare(a.started_at));
    return { needle_hash: needleHash, matches, sessions };
}
//# sourceMappingURL=touched.js.map