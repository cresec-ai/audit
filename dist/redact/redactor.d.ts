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
import type { CredentialFingerprint, Scrubbed, Sha256Ref } from '../schema/events.js';
import type { RedactionPolicy, RedactorLike } from '../types.js';
/**
 * Kinds of verbatim protocol string `structuralString` caps. `tool`/`method`
 * and the identifier-shaped fields learned off the wire (clientInfo/
 * serverInfo `name`) share the `identifier` shape; `clientInfo`/`serverInfo`
 * `version` gets its own, looser-on-punctuation `version` shape; MCP's
 * negotiated `protocolVersion` is a strict `YYYY-MM-DD` date string.
 */
export type StructuralStringKind = 'identifier' | 'version' | 'protocol_version';
/** Cap on a `structuralString` value that may survive un-hashed. */
export declare const STRUCTURAL_STRING_MAX_LEN = 128;
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
export declare function structuralString(value: string, kind: StructuralStringKind): string;
export declare const DEFAULT_POLICY: RedactionPolicy;
/**
 * True when the string matches any secret-shaped pattern. Used by the proxy
 * to fingerprint env credentials. Defensive about /g lastIndex even though
 * the defaults never use it.
 */
export declare function looksSecret(s: string, patterns?: RegExp[]): boolean;
export declare class Redactor implements RedactorLike {
    private readonly policy;
    private readonly allowKeySet;
    constructor(policy?: Partial<RedactionPolicy>);
    get mode(): RedactionPolicy['mode'];
    /** sha256:<hex> of the exact string — matches RedactedRef.ref format. */
    hashString(value: string): Sha256Ref;
    /** Redact a JSON tree per policy. Never throws; worst case returns a ref. */
    scrub(value: unknown): Scrubbed;
    private walk;
    /**
     * Object keys are redacted too (P1): maps keyed by emails, usernames,
     * file paths, header names, or a secret-shaped string must not land in
     * clear, and a hashed key lets `query` find it too.
     */
    private scrubKey;
    private scrubString;
    /**
     * Value-side gate for an allow-listed key: the value must belong to a
     * known structural vocabulary, not merely "short and harmless-looking".
     */
    private passesVocabulary;
    private refOf;
    /**
     * Blast radius miss fix (P1): when alwaysPatterns match tokens EMBEDDED in
     * a larger leaf ("AWS_ACCESS_KEY_ID=AKIA...\n"), record the hash of each
     * matched token too, so `query` can find a credential even when it never
     * appeared as a whole leaf by itself. Capped and de-duplicated; excludes
     * any token whose hash already equals the leaf's own `ref` (no point
     * duplicating the primary ref).
     */
    private extractSecretRefs;
    /** Collapse an arbitrary value to the ref of its JSON serialization. */
    private stringifyRef;
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
export declare function scrubToolArguments(redactor: RedactorLike, value: unknown): Scrubbed;
export interface ScrubbedArgv {
    /** argv.join(' ') with secret-looking elements replaced by sha256:<hex>. */
    command: string;
    /** Fingerprints of every replaced/stripped element, so `query` still finds them. */
    fingerprints: CredentialFingerprint[];
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
export declare function scrubArgv(argv: string[], redactor: RedactorLike): ScrubbedArgv;
