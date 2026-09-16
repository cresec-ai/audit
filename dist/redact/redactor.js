/**
 * Edge redaction — M1's trust gate.
 *
 * Every JSON tree that crosses the proxy is scrubbed here before it can land
 * in the evidence store. Structure is preserved; string leaves are replaced
 * by `RedactedRef`s (unsalted SHA-256 + length) unless the policy explicitly
 * allows them through. `scrub()` NEVER throws — a redaction failure must
 * degrade to "hash more", never to "record less" or "break traffic".
 *
 * The allowlist is POSITION- and VALUE-aware (P0 fix): a key being allowed
 * is not enough — the value must also belong to a known structural
 * vocabulary (an MCP content `type`, a `role`, a log `level`, ...), and
 * `name` only passes at `tools[*].name` / `prompts[*].name` in list results.
 * Everything else, including a bare `{name: ...}` / `{code: ...}` /
 * `{status: ...}` anywhere else in the tree, is hashed. `code`, `status`,
 * `kind` and `tool` were dropped from the allowlist entirely: no structural
 * vocabulary for them is safe to define, so they always hash.
 *
 * `scrubToolArguments()` goes further still: under a tool_call's
 * `arguments` subtree NOTHING passes, in ANY mode — every string leaf is
 * hashed regardless of key or position. Arguments are the most
 * attacker/user-controlled data the proxy ever sees, so this is a
 * deliberately absolute rule, not merely "whatever the vocabulary allows".
 */
import { sha256Ref } from '../chain/hash.js';
/** Literal stored (hashed) for function/symbol leaves. */
const UNSERIALIZABLE = '[unserializable]';
/** Literal stored (hashed) when JSON.stringify of a subtree throws. */
const CIRCULAR = '[circular]';
/** Cap on a `structuralString` value that may survive un-hashed. */
export const STRUCTURAL_STRING_MAX_LEN = 128;
/** Conservative shape each `StructuralStringKind` must match to survive un-hashed. */
const STRUCTURAL_STRING_SHAPES = {
    identifier: /^[A-Za-z0-9_.:/-]+$/,
    version: /^[A-Za-z0-9_.+-]+$/,
    protocol_version: /^\d{4}-\d{2}-\d{2}$/,
};
/**
 * `stdio.ts`/`http.ts` copy a handful of protocol strings straight off the
 * wire into every event, VERBATIM, with no length or character cap: the
 * `tools/call` tool name (`gen_ai.tool.name`), the JSON-RPC `method`
 * (`mcp.method.name`), the `initialize` handshake's `clientInfo`/
 * `serverInfo` `name`/`version`, and the negotiated `protocolVersion` — plus
 * the identity/server context remembered from that handshake and reused on
 * every later event, and the synthetic `unanswered` events sealed at
 * shutdown (which just replay an already-captured `tool`/`method`). None of
 * these fields are part of a `scrub()`-walked JSON tree (the event schema
 * keeps them as plain top-level strings, e.g. `ToolCallEvent.tool`), so
 * `scrub()`'s length/vocabulary gates never applied to them: a misbehaving
 * or malicious peer could stuff kilobytes of arbitrary text — including
 * payload it wants to smuggle past redaction — into every event through any
 * one of them.
 *
 * `structuralString` closes that: the value is kept AS-IS only when it is at
 * most `STRUCTURAL_STRING_MAX_LEN` (128) characters AND matches `kind`'s
 * conservative shape; otherwise it is replaced by its `sha256:<hex>`
 * reference — computed the exact same way as `Redactor.hashString` (both are
 * `sha256Ref(value)`), so a blast-radius `query` for the original value still
 * finds it. The event schema is frozen: the field stays a plain `string`
 * either way, never a `RedactedRef` object.
 */
export function structuralString(value, kind) {
    if (value.length > STRUCTURAL_STRING_MAX_LEN)
        return sha256Ref(value);
    if (!STRUCTURAL_STRING_SHAPES[kind].test(value))
        return sha256Ref(value);
    return value;
}
/**
 * Charset a string must satisfy to pass under a CUSTOM (non-default) allowed
 * key that has no dedicated structural-vocabulary rule below. Kept only for
 * backward compatibility with callers who extend `allowKeys` via policy
 * overrides; none of the shipped default keys use this fallback.
 */
const STRUCTURAL_CHARSET = /^[\w .,@()/:+#-]*$/;
/** MCP content-block `type` values (text/image/audio/resource/...). */
const CONTENT_TYPES = new Set(['text', 'image', 'audio', 'resource', 'resource_link']);
/** MCP message `role` values. */
const ROLES = new Set(['user', 'assistant']);
/** MCP logging `level` values (RFC 5424 syslog severities). */
const LOG_LEVELS = new Set([
    'debug',
    'info',
    'notice',
    'warning',
    'error',
    'critical',
    'alert',
    'emergency',
]);
const MIME_TYPE_RE = /^[\w.+-]+\/[\w.+-]+$/;
const PROTOCOL_VERSION_RE = /^\d{4}-\d{2}-\d{2}$/;
const METHOD_RE = /^[a-z]+(\/[a-zA-Z_]+)*$/;
/** `name` value shape, valid ONLY at tools[*].name / prompts[*].name. */
const LIST_NAME_RE = /^[\w.-]{1,64}$/;
/** Array keys whose elements' own `name` field may pass (list results). */
const LIST_ARRAY_KEYS = new Set(['tools', 'prompts']);
/** Object-key shape that may survive un-hashed (subject to alwaysPatterns too). */
const KEY_IDENT_RE = /^[A-Za-z_$][\w$-]{0,63}$/;
/** Cap on `RedactedRef.secret_refs` — de-duplicated hashes of tokens matched
 *  by alwaysPatterns INSIDE a larger leaf (not the whole-leaf ref itself). */
const MAX_SECRET_REFS = 8;
/**
 * Secret shapes hashed in EVERY mode. None of these carry the /g flag on
 * purpose: a sticky lastIndex across .test() calls silently skips matches.
 */
const ALWAYS_PATTERNS = [
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
    // GitHub fine-grained PATs. NOT reachable by the `gh[pousr]_` shape above
    // ("github_" has no matching second letter), and not by the generic base64
    // run either (the embedded `_` kills the \b), so before this entry a
    // fine-grained PAT crossed the recorder unhashed.
    //
    // The REAL shape is `github_pat_` + a 22-character base62 identifier + `_`
    // + a 59-character base62 secret, and the pattern spells exactly that. The
    // looser `[A-Za-z0-9_]{22,}` it used to carry put `_` in the character
    // class, so every snake_case identifier that happens to start with the
    // prefix — `github_pat_token_refresh_helper_result`,
    // `github_pat_validation_middleware_options` — was hashed as a credential
    // in the store and rewritten at the boundary. The two halves are fixed
    // length, so nothing here can backtrack.
    //
    // But spelling ONLY that shape made a credential hinge on two exact
    // lengths: a token from a format change, a variant, or a paste that lost a
    // character then matches nothing at all and reaches the store in clear —
    // which is strictly worse than the false positives the narrowing fixed. So
    // a second, defensive arm follows it, keyed on what a token has and an
    // identifier does not: 40+ characters, a digit, AND both letter cases.
    // `github_pat_token_refresh_helper_result` is lower-case with no digit;
    // `GITHUB_PAT_SOMETHING_LONG` has no lower case. A real base62 secret of
    // 81 characters has all three with overwhelming probability. Each lookahead
    // scans the same bounded run once, so this cannot backtrack either.
    //
    // The floor is 40 because a real token carries 82 characters of payload,
    // so no genuine credential is near it. A floor of 24 was tried and
    // reverted: it starts matching `github_pat_Handler2_Options_Result_Cache`,
    // and all it buys is a heavily truncated paste, which is not a working
    // credential. The case and digit tests, not the floor, keep identifiers
    // out.
    /\bgithub_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}\b/,
    /\bgithub_pat_(?=[A-Za-z0-9_]{40,}\b)(?=[A-Za-z0-9_]*[0-9])(?=[A-Za-z0-9_]*[a-z])(?=[A-Za-z0-9_]*[A-Z])[A-Za-z0-9_]+\b/,
    // Slack tokens
    /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/,
    // Bearer auth headers
    /\bBearer\s+[A-Za-z0-9._~+/=-]{16,}/i,
    // Long hex blobs (>= 32 hex chars: digests, session ids, raw keys)
    /\b[0-9a-fA-F]{32,}\b/,
    // Long base64 blobs (>= 40 chars)
    /\b[A-Za-z0-9+/]{40,}={0,2}\b/,
    // Credentials carried in a URL's userinfo ("postgres://user:pass@host/db").
    // Only the `user:pass` is matched, so a redaction keeps the scheme, host
    // and path readable, and the ref is sha256("user:pass") — the same value
    // `scrubArgv` already fingerprints for a DSN on a server's command line.
    //
    // The trailing `(?=@)` alone was not userinfo: ANY `scheme://name:tag@...`
    // reference matched it, and a container image ("oci://redis:7.2@sha256:…")
    // had its name and tag hashed in the store and rewritten at the boundary.
    // What follows the `@` in a real URL is a HOST, so the lookahead now spells
    // one out — a dotted/word host or a bracketed IPv6 literal, an optional
    // numeric port, and then a delimiter. `@sha256:e3b0…` fails it because a
    // digest's `:` is not followed by a port. The lookahead adds no characters
    // to the match, so the span stays exactly `user:pass`.
    /(?<=:\/\/)[^\s:/?#@]{1,128}:[^\s/?#@]{1,128}(?=@(?:\[[0-9A-Fa-f:.]{2,45}\]|[\w.-]{1,255})(?::\d{1,5})?(?![\w.:-]))/,
    // Credential assignments, in two shapes that need DIFFERENT confidence.
    //
    // BARE — the credential keyword IS the whole name ("password=hunter2",
    // "api_key: x", `{"token":"x"}`, "--password=x"). Nothing else is called
    // `password`, so any value is taken at face value. An optional closing
    // quote before the separator is what makes the JSON shape — the single
    // most common one in an MCP tool result — reachable at all: in
    // `{"password": "hunter2"}` the `"` sits between the keyword and the `:`.
    // A leading `-`/`--` is allowed so a `--password=…` flag still matches
    // (the `(?<![\w-])` guard would otherwise reject the dash), and the value
    // may be a quoted string, which keeps the trailing `"}` of a JSON object
    // out of the span.
    /(?<![\w-])-{0,2}(?:password|passwd|secret|token|api[_-]?key)["']?\s*[:=]\s*(?:"[^"\s]+"|'[^'\s]+'|\S+)/i,
    // AFFIXED — the keyword is part of a longer name ("AWS_SECRET_ACCESS_KEY=",
    // "DB_PASSWORD=", "X-Api-Key:"). The leading/trailing `\b` this used to
    // carry made the pattern blind to exactly those: `_` is a word character,
    // so there is no boundary before the `SECRET` in `AWS_SECRET_ACCESS_KEY`
    // nor after it. A bounded, separator-anchored affix is allowed instead,
    // which keeps "secretary_id=5", "tokenizer_count=3" and
    // "passwordless=true" out.
    //
    // But an affix that may be ANY 62 characters also rides ordinary developer
    // output — `MAX_TOKEN_LENGTH = 512`, `access_token_expires_in: 3600`,
    // `secret_scanning_enabled: true` — which is the false-positive class the
    // narrowing exists to prevent, so the VALUE has to look like a credential
    // rather than be any `\S+`: at least 8 characters carrying a digit, or at
    // least 16 characters. Every credential the widening was added for clears
    // that (a 40-character AWS secret key, `hunter2-correct-horse`, a 20-hex
    // API key header) and every counted false positive fails it. The digit
    // lookahead is bounded, so it cannot backtrack superlinearly.
    /(?<![\w-])(?:[A-Za-z0-9_-]{0,62}[_-])?(?:password|passwd|secret|token|api[_-]?key)(?:[_-][A-Za-z0-9_-]{0,62})?["']?\s*[:=]\s*(?:["'](?:(?=[^\s"']{0,255}\d)[^\s"']{8,}|[^\s"']{16,})["']|(?=\S{0,255}\d)\S{8,}|\S{16,})/i,
    // A credential passed as a command-line FLAG whose value is the NEXT
    // argument ("--password hunter2", "--api-key 0123456789abcdef"): the
    // separator is whitespace, so neither assignment shape above can see it.
    // `scrubArgv` already covers this for the wrapped server's own argv via
    // the previous-element flag check; tool RESULTS carry command lines too
    // (shell output, CI logs, `ps` listings). The value must look like a
    // credential — 6+ characters with a digit, or 16+ — and may not start with
    // `<` or `$`, so "--secret-scanning enabled", "--token to authenticate",
    // "--api-key <your-key-here>" and "--token $GITHUB_TOKEN" stay untouched.
    /(?<![\w-])-{1,2}(?:[A-Za-z0-9-]{0,62}-)?(?:password|passwd|secret|token|api-?key)(?:-[A-Za-z0-9-]{0,62})?[ \t]+(?:(?=\S{0,255}\d)[^\s<$]\S{5,}|[^\s<$]\S{15,})/i,
];
export const DEFAULT_POLICY = {
    mode: 'allowlist',
    // 'code', 'status', 'kind', 'tool' were dropped (P0): no structural
    // vocabulary can safely bound their values, so they always hash now.
    allowKeys: ['type', 'name', 'method', 'mimeType', 'role', 'protocolVersion', 'level'],
    maxAllowedStringLen: 64,
    alwaysPatterns: ALWAYS_PATTERNS,
    maxDepth: 32,
};
/**
 * True when the string matches any secret-shaped pattern. Used by the proxy
 * to fingerprint env credentials. Defensive about /g lastIndex even though
 * the defaults never use it.
 */
export function looksSecret(s, patterns = DEFAULT_POLICY.alwaysPatterns) {
    for (const re of patterns) {
        re.lastIndex = 0;
        if (re.test(s))
            return true;
    }
    return false;
}
export class Redactor {
    policy;
    allowKeySet;
    constructor(policy) {
        this.policy = {
            ...DEFAULT_POLICY,
            ...policy,
            // Clone arrays so callers mutating their input cannot mutate ours.
            allowKeys: [...(policy?.allowKeys ?? DEFAULT_POLICY.allowKeys)],
            alwaysPatterns: [...(policy?.alwaysPatterns ?? DEFAULT_POLICY.alwaysPatterns)],
        };
        this.allowKeySet = new Set(this.policy.allowKeys);
    }
    get mode() {
        return this.policy.mode;
    }
    /** sha256:<hex> of the exact string — matches RedactedRef.ref format. */
    hashString(value) {
        return sha256Ref(value);
    }
    /** Redact a JSON tree per policy. Never throws; worst case returns a ref. */
    scrub(value) {
        try {
            return this.walk(value, undefined, 0, new Set(), {});
        }
        catch {
            // Should be unreachable; absolute backstop so scrub can never throw.
            return this.stringifyRef(value);
        }
    }
    /* ------------------------------ internals ----------------------------- */
    walk(value, key, depth, ancestors, ctx) {
        if (value === null || value === undefined)
            return null;
        switch (typeof value) {
            case 'number':
            case 'boolean':
                return value;
            case 'string':
                return this.scrubString(value, key, ctx);
            case 'bigint':
                return this.scrubString(String(value), key, ctx);
            case 'function':
            case 'symbol':
                return this.refOf(UNSERIALIZABLE);
            case 'object':
                break;
            default:
                // Future exotic typeof values: refuse to guess, hash a marker.
                return this.refOf(UNSERIALIZABLE);
        }
        const obj = value;
        if (depth > this.policy.maxDepth || ancestors.has(obj)) {
            // Too deep, or a true cycle: collapse the whole subtree to a ref.
            return this.stringifyRef(obj);
        }
        ancestors.add(obj);
        try {
            if (Array.isArray(obj)) {
                const out = [];
                for (const el of obj) {
                    // Array elements have no object key of their own, but they DO
                    // inherit this array's key as `arrayKey` for one hop (so
                    // tools[*].name can be validated by the element's own walk).
                    out.push(this.walk(el, undefined, depth + 1, ancestors, { arrayKey: key }));
                }
                return out;
            }
            const rec = obj;
            // Object.create(null): a literal `__proto__` key must become a real
            // own property, never silently set the prototype (P2).
            const out = Object.create(null);
            for (const k of Object.keys(rec)) {
                const v = rec[k];
                // arrayKey is only meaningful for a direct string/bigint child (the
                // one place it can still be consumed by scrubString); anything else
                // (a nested object/array) must NOT inherit it further — that would
                // let e.g. tools[*].inputSchema.name pass, which is out of scope.
                const childCtx = typeof v === 'string' || typeof v === 'bigint' ? { arrayKey: ctx.arrayKey } : {};
                out[this.scrubKey(k)] = this.walk(v, k, depth + 1, ancestors, childCtx);
            }
            return out;
        }
        finally {
            ancestors.delete(obj);
        }
    }
    /**
     * Object keys are redacted too (P1): maps keyed by emails, usernames,
     * file paths, header names, or a secret-shaped string must not land in
     * clear, and a hashed key lets `query` find it too.
     */
    scrubKey(k) {
        if (KEY_IDENT_RE.test(k) && !looksSecret(k, this.policy.alwaysPatterns))
            return k;
        return this.hashString(k);
    }
    scrubString(v, key, ctx) {
        // alwaysPatterns fire in EVERY mode.
        if (looksSecret(v, this.policy.alwaysPatterns))
            return this.refOf(v);
        if (this.policy.mode === 'off')
            return v;
        // allowlist mode: a string passes only when ALL gates hold.
        if (key === undefined || !this.allowKeySet.has(key))
            return this.refOf(v);
        if (v.length > this.policy.maxAllowedStringLen)
            return this.refOf(v);
        if (this.passesVocabulary(key, v, ctx))
            return v;
        return this.refOf(v);
    }
    /**
     * Value-side gate for an allow-listed key: the value must belong to a
     * known structural vocabulary, not merely "short and harmless-looking".
     */
    passesVocabulary(key, v, ctx) {
        switch (key) {
            case 'type':
                return CONTENT_TYPES.has(v);
            case 'role':
                return ROLES.has(v);
            case 'level':
                return LOG_LEVELS.has(v);
            case 'mimeType':
                return MIME_TYPE_RE.test(v);
            case 'protocolVersion':
                return PROTOCOL_VERSION_RE.test(v);
            case 'method':
                return METHOD_RE.test(v);
            case 'name':
                // Only tools[*].name / prompts[*].name in list results.
                return ctx.arrayKey !== undefined && LIST_ARRAY_KEYS.has(ctx.arrayKey) && LIST_NAME_RE.test(v);
            default:
                // A custom key added via a policy override: best-effort fallback to
                // the previous generic charset gate (not part of the frozen
                // vocabulary above, which covers every DEFAULT_POLICY key).
                return STRUCTURAL_CHARSET.test(v);
        }
    }
    refOf(original) {
        const ref = this.hashString(original);
        const out = { redacted: true, ref, len: original.length };
        const secretRefs = this.extractSecretRefs(original, ref);
        if (secretRefs !== undefined)
            out.secret_refs = secretRefs;
        return out;
    }
    /**
     * Blast radius miss fix (P1): when alwaysPatterns match tokens EMBEDDED in
     * a larger leaf ("AWS_ACCESS_KEY_ID=AKIA...\n"), record the hash of each
     * matched token too, so `query` can find a credential even when it never
     * appeared as a whole leaf by itself. Capped and de-duplicated; excludes
     * any token whose hash already equals the leaf's own `ref` (no point
     * duplicating the primary ref).
     */
    extractSecretRefs(v, wholeRef) {
        if (v.length < 8)
            return undefined; // shortest pattern is longer than this
        const found = [];
        const seen = new Set([wholeRef]);
        for (const re of this.policy.alwaysPatterns) {
            const flags = re.flags.includes('g') ? re.flags : re.flags + 'g';
            const g = new RegExp(re.source, flags);
            let m;
            while ((m = g.exec(v)) !== null) {
                const token = m[0];
                if (token.length > 0) {
                    const tref = this.hashString(token);
                    if (!seen.has(tref)) {
                        seen.add(tref);
                        found.push(tref);
                        if (found.length >= MAX_SECRET_REFS)
                            return found;
                    }
                }
                else {
                    g.lastIndex++; // never loop forever on a zero-length match
                }
            }
        }
        return found.length > 0 ? found : undefined;
    }
    /** Collapse an arbitrary value to the ref of its JSON serialization. */
    stringifyRef(value) {
        let s;
        try {
            const j = JSON.stringify(value);
            s = typeof j === 'string' ? j : CIRCULAR;
        }
        catch {
            s = CIRCULAR; // circular structure, bigint, throwing toJSON, ...
        }
        return this.refOf(s);
    }
}
/* -------------------------------------------------------------------- */
/* tool_call.arguments lockdown (P0)                                    */
/* -------------------------------------------------------------------- */
/** Exact shape of a genuine `RedactedRef.ref` — matches `Redactor.hashString()`'s output. */
const SHA256_REF_RE = /^sha256:[0-9a-f]{64}$/;
/**
 * Structural check for "already an opaque RedactedRef" — used to avoid
 * re-hashing a ref lockdownStrings has already produced. This is duck-typed
 * (scrubToolArguments must work with any RedactorLike, not just the concrete
 * Redactor class — see its own doc comment), so it does NOT prove the value
 * is trustworthy on its own (P1 fix): in `--redact off`, an attacker-supplied
 * `arguments` object shaped like `{redacted: true, ref: "<anything>", len: N}`
 * used to be accepted at face value and everything under it — siblings,
 * nested plaintext — was left readable. Requiring `ref` to match the EXACT
 * sha256:<hex> shape closes that: any raw string of that shape is itself a
 * >=32-char hex run, which `alwaysPatterns` (the long-hex-blob rule) already
 * hashes in EVERY mode during the `scrub()` pass that runs before this ever
 * sees the tree — so a raw string field can never legitimately have this
 * shape unless it really did come out of a redactor's own hashing.
 */
function isRedactedRefLike(value) {
    return (typeof value === 'object' &&
        value !== null &&
        !Array.isArray(value) &&
        value.redacted === true &&
        typeof value.ref === 'string' &&
        SHA256_REF_RE.test(value.ref) &&
        typeof value.len === 'number');
}
/** Sweep an already-scrubbed tree and hash any surviving plain string leaf.
 *  Object keys were already handled by the first `scrub()` pass; this only
 *  ever touches string VALUES. */
function lockdownStrings(redactor, value) {
    if (typeof value === 'string') {
        return { redacted: true, ref: redactor.hashString(value), len: value.length };
    }
    if (value === null || typeof value !== 'object')
        return value;
    if (isRedactedRefLike(value))
        return value; // already opaque; keep as-is
    if (Array.isArray(value))
        return value.map((el) => lockdownStrings(redactor, el));
    const out = Object.create(null);
    const rec = value;
    for (const k of Object.keys(rec))
        out[k] = lockdownStrings(redactor, rec[k]);
    return out;
}
/**
 * Redact a tool_call's `arguments` tree. Stronger than `scrub()`: under
 * `arguments` NOTHING passes, in ANY mode (including 'off') — every string
 * leaf becomes a RedactedRef regardless of key or position. Arguments are
 * the most attacker/user-controlled data the proxy ever sees (an agent can
 * be tricked into calling a tool with anything as `name`/`code`/`status`/
 * ...), so this is a deliberately absolute rule rather than "whatever the
 * structural vocabulary allows". Implemented as `scrub()` (for its key
 * hashing, secret detection, depth/cycle guards, and secret_refs) plus a
 * sweep that hashes whatever plain strings are still standing — it only
 * needs the public RedactorLike surface, so it works with any RedactorLike.
 */
export function scrubToolArguments(redactor, value) {
    return lockdownStrings(redactor, redactor.scrub(value));
}
/* -------------------------------------------------------------------- */
/* argv scrubbing (P1) — ServerContext.command                           */
/* -------------------------------------------------------------------- */
/**
 * Kept in sync with (but intentionally separate from) stdio.ts's own
 * CREDENTIAL_NAME_RE, which fingerprints env var names — argv flag names
 * use the identical shape.
 */
const CREDENTIAL_FLAG_RE = /(TOKEN|SECRET|PASSW|API[_-]?KEY|CREDENTIAL|AUTH)/i;
/** '--token' / '-t' -> 'token' / 't'; anything else -> undefined. */
function flagName(arg) {
    const m = /^--?([A-Za-z][\w-]*)$/.exec(arg);
    return m?.[1];
}
/** A URL carrying userinfo: strip it, keep scheme+host+path. Undefined if
 *  `s` isn't a URL, or is one without userinfo. `username`/`password` are
 *  exposed separately (P2) alongside the joined `userinfo` so a caller can
 *  fingerprint the password ALONE — a query for just the leaked password,
 *  without the username, must still find it. */
function stripUrlUserinfo(s) {
    let url;
    try {
        url = new URL(s);
    }
    catch {
        return undefined;
    }
    if (!url.username && !url.password)
        return undefined;
    // The URL parser hands back the percent-encoded userinfo; a password with
    // @ : / # ? % or a space must be encoded to be a valid URL at all. Decode
    // so a blast-radius query for the password as the operator knows it
    // matches; the raw form is fingerprinted too when it differs.
    const decode = (s) => {
        try {
            return decodeURIComponent(s);
        }
        catch {
            return s;
        }
    };
    const username = decode(url.username);
    const password = decode(url.password);
    const userinfo = password ? `${username}:${password}` : username;
    const rawUserinfo = url.password ? `${url.username}:${url.password}` : url.username;
    return {
        stripped: `${url.protocol}//${url.host}${url.pathname}`,
        userinfo,
        username,
        password,
        rawUserinfo,
        rawUsername: url.username,
        rawPassword: url.password,
    };
}
/**
 * Wrapped command argv leak fix (P1): `ServerContext.command` is stamped on
 * every event, rendered by replay, and shipped in export bundles, so a raw
 * `argv.join(' ')` leaks `--api-key sk-...`, `--token ...`, and DSNs like
 * `postgres://user:pass@host` verbatim. Scrubs each element:
 *   - looks secret-shaped (looksSecret / alwaysPatterns) -> hashed whole
 *   - is a URL with userinfo -> userinfo stripped, scheme+host+path kept
 *   - is (or follows) a flag whose name looks credential-ish -> hashed whole
 * Every replaced/stripped piece is also recorded as a CredentialFingerprint
 * so a blast-radius `query` for the leaked value still finds it.
 */
export function scrubArgv(argv, redactor) {
    const fingerprints = [];
    const out = [];
    const fingerprint = (name, value) => {
        const ref = redactor.hashString(value);
        fingerprints.push({ name, ref });
        return ref;
    };
    // A url-fingerprinting helper shared by both the `--flag=value` and
    // standalone-element branches below: records the joined `user:pass` AND
    // (P2) the user/password components separately, so a blast-radius query
    // for the password alone — without knowing the username — still finds it.
    //
    // Stripping the userinfo says nothing about the REST of the URL: a
    // credential in the PATH ("https://u:p@hooks.example.com/services/ghp_…")
    // survives it, and `looksSecret` never ran on the element because the
    // strip branch returned first — so the token landed verbatim in
    // `ServerContext.command`, which is stamped on every event, rendered by
    // replay and shipped in export bundles. Re-checking the STRIPPED remainder
    // closes that while keeping the strip's separate userinfo refs and the
    // legible scheme/host for an ordinary DSN.
    const scrubStrippedUrl = (label, stripped) => looksSecret(stripped) ? fingerprint(label, stripped) : stripped;
    const fingerprintUrlHit = (name, hit) => {
        const seen = new Set();
        const once = (value) => {
            if (!value || seen.has(value))
                return;
            seen.add(value);
            fingerprint(name, value);
        };
        once(hit.userinfo);
        once(hit.password);
        once(hit.username);
        // Percent-encoded forms, when they differ, so a search for either matches.
        once(hit.rawUserinfo);
        once(hit.rawPassword);
        once(hit.rawUsername);
    };
    for (let i = 0; i < argv.length; i++) {
        const el = argv[i];
        // --flag=value half — and NAME=value elements without a dash, the way
        // `env DSN=postgres://user:pass@host server` (or a KEY=value before npx)
        // launches a server from a client config: the value half gets the same
        // treatment either way.
        const eq = el.indexOf('=');
        const isFlagAssign = eq > 0 && el.startsWith('-');
        const isEnvAssign = eq > 0 && /^[A-Za-z_][\w.-]*$/.test(el.slice(0, eq));
        if (isFlagAssign || isEnvAssign) {
            const fname = isFlagAssign ? flagName(el.slice(0, eq)) : el.slice(0, eq);
            const value = el.slice(eq + 1);
            const label = fname ?? `argv[${i}]`;
            if (fname !== undefined && CREDENTIAL_FLAG_RE.test(fname)) {
                out.push(el.slice(0, eq + 1) + fingerprint(label, value));
                continue;
            }
            // P1 fix: the flag name alone isn't credential-shaped (`--dsn`,
            // `--url`, `--database-url`, ...), but the VALUE half can still be a
            // bare secret or a URL carrying userinfo — e.g.
            // `--dsn=postgres://user:pass@host` or `--url=https://u:p@host`. The
            // whole-element checks below never fire here because `new URL(el)`
            // throws on a `--flag=...` string, so the value half must be checked
            // on its own, and the `--flag=` prefix re-joined onto the scrubbed
            // result.
            //
            // The URL check runs FIRST. `alwaysPatterns` now carries a
            // url-userinfo shape, so `looksSecret` is true of a DSN too, and
            // whichever branch runs first decides the outcome. Stripping wins on
            // both counts: it fingerprints `user:pass`, the password and the
            // username SEPARATELY (three refs a blast-radius query can hit) where
            // hashing the element whole yields one ref for the entire DSN, and it
            // keeps the scheme/host/path — which carry no credential — legible in
            // `ServerContext.command`. The stripped remainder is then re-checked
            // with `looksSecret` (see `scrubStrippedUrl`), so "wins" never means
            // "skips the secret check".
            const eqUrlHit = stripUrlUserinfo(value);
            if (eqUrlHit !== undefined) {
                fingerprintUrlHit(label, eqUrlHit);
                out.push(el.slice(0, eq + 1) + scrubStrippedUrl(label, eqUrlHit.stripped));
                continue;
            }
            if (looksSecret(value)) {
                out.push(el.slice(0, eq + 1) + fingerprint(label, value));
                continue;
            }
        }
        // A standalone value following a credential-ish flag (previous element).
        const prevName = i > 0 ? flagName(argv[i - 1]) : undefined;
        if (prevName !== undefined && CREDENTIAL_FLAG_RE.test(prevName) && !el.startsWith('-')) {
            out.push(fingerprint(prevName, el));
            continue;
        }
        // Same ordering as the `=` branch above, for the same reason: a URL with
        // userinfo is now `looksSecret`, and the strip is the stronger outcome.
        const urlHit = stripUrlUserinfo(el);
        if (urlHit !== undefined) {
            fingerprintUrlHit(`argv[${i}]`, urlHit);
            out.push(scrubStrippedUrl(`argv[${i}]`, urlHit.stripped));
            continue;
        }
        if (looksSecret(el)) {
            out.push(fingerprint(`argv[${i}]`, el));
            continue;
        }
        out.push(el);
    }
    return { command: out.join(' '), fingerprints };
}
//# sourceMappingURL=redactor.js.map