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
/**
 * Cap on fingerprints derived from the ENVIRONMENT alone. Deliberately
 * separate from (and lower than) the caller's overall cap, so a wrapped
 * server with dozens of credential-shaped env vars cannot crowd out an
 * argv/URL-derived fingerprint (P2 fix; see `MAX_CREDENTIAL_FINGERPRINTS` in
 * src/proxy/stdio.ts).
 */
export declare const ENV_CREDENTIAL_FINGERPRINT_CAP = 32;
/**
 * Is this environment variable part of the RECORDER's own configuration?
 *
 * Such a variable is never fingerprinted. `identity.credential_fingerprints`
 * exists to answer "which sessions saw this secret" for secrets the AGENT and
 * the wrapped server were exposed to; the recorder's own configuration is not
 * that. `MCP_RECORDER_SINK_TOKEN` is the clearest case and the reason this
 * function exists: it is the transport credential the shipper authenticates
 * to the evidence sink with, the agent never sees it, a blast-radius query
 * for it answers nothing anyone needs — and, before this exclusion, its ref
 * was stamped on EVERY recorded event and then shipped to the receiver that
 * accepts that very token. Refs are unsalted by design (see
 * `Redactor.hashString` / `sha256Ref`), so for a low-entropy token that ref
 * is recoverable by brute force: the sink was being handed a reversible copy
 * of its own bearer token, on every event. `MCP_RECORDER_SINK_TOKEN_FILE` is
 * the same family (its value is where the token lives), and so is anything
 * else added to `ENV` later — which is why this matches the whole namespace
 * rather than a list of names that a future variable would silently escape.
 */
export declare function isRecorderOwnEnvVar(name: string): boolean;
/**
 * THE one place environment variables become `CredentialFingerprint`s.
 *
 * Every recording surface that wants env-derived fingerprints calls this
 * rather than walking `env` itself, so the exclusion above cannot be lost by
 * a new call site: a later filter over the assembled list would be, since
 * nothing forces a new caller through it.
 *
 * Never throws — it is on a fail-open path; a hashing failure degrades to
 * "fewer fingerprints", never to a broken session.
 */
export declare function collectEnvCredentialFingerprints(env: NodeJS.ProcessEnv, redactor: RedactorLike, cap?: number): CredentialFingerprint[];
/**
 * What a brokered value is replaced by, and the ref that stands in for it.
 *
 * A constant, so it is greppable in a store and identical across sessions,
 * and a genuine `sha256:<hex>` so every consumer of `RedactedRef.ref` — the
 * `query` matcher, the replay renderer, the bundle exporter — keeps working
 * on a shape it already understands. It is the hash of a literal, so it
 * discloses nothing: anyone can compute it, which is the point.
 */
export declare const BROKERED_PLACEHOLDER = "[brokered-credential]";
export declare const BROKERED_REF: Sha256Ref;
/**
 * Cap on distinct brokered values held in the exclusion set. One entry per
 * distinct resolved credential per process; a session that legitimately mints
 * more than this many distinct tokens does not exist, and the cap is what
 * makes the set's memory bounded by configuration rather than by traffic.
 * Registration FAILS at the cap rather than evicting: evicting would silently
 * un-protect a credential that is still live, and the broker turns a failed
 * registration into a denial (`exclusion_capacity`).
 */
export declare const MAX_BROKERED_SECRETS = 1024;
/**
 * Remember that `value` is a REAL credential the broker resolved, so that no
 * surface in the recorder ever fingerprints it.
 *
 * WHY THIS EXISTS, and why it is the same shape as `isRecorderOwnEnvVar`.
 * Refs here are unsalted sha256 by design (`Redactor.hashString` / `sha256Ref`),
 * because a blast-radius `query` has to be able to match a known probe value
 * by hashing it the same way. That trade is right for a credential the AGENT
 * already saw. It is exactly wrong for a brokered one: the whole claim of the
 * broker is that the real token is absent from the model's context and from
 * the transcript, so hashing it into the evidence chain would hand anybody
 * holding the chain a brute-forceable copy — and a confirmable one for
 * anybody who already has a candidate. There are at least six surfaces that
 * would do it by default: `scrubToolArguments` on a post-swap message,
 * `RedactedRef.ref`, `RedactedRef.secret_refs` when the token is embedded in
 * a bigger leaf, `collectEnvCredentialFingerprints` on `GITHUB_TOKEN`,
 * `scrubArgv` on a server command line, and the boundary filter's own
 * `secret_refs` when a tool reflects the token back. One test, called from
 * every one of them, is the only shape that survives a new call site being
 * added — a filter applied afterwards to an assembled list would not be.
 *
 * WHAT IT DELIBERATELY FORFEITS. `query <the real token>` will not find the
 * sessions that used it, so blast radius for a brokered credential cannot be
 * answered from a hash. That is the correct trade and it costs less than it
 * looks: the agent never saw the value, and the question is answered better
 * anyway by the credential id and `decision_id` that the broker records for
 * every use — which name the credential, the policy that allowed it and the
 * destination it was allowed to, instead of proving that some hash appeared.
 *
 * Process-local and in memory only: a file of "secrets not to fingerprint"
 * beside the store would be written by the same uid the store is, and would
 * be a list of hashes of live credentials, which is the thing we just refused
 * to write down.
 *
 * Returns false when the set is full; the caller must treat that as a
 * resolution failure and DENY, never as permission to hand the value on.
 */
export declare function registerBrokeredSecret(value: string): boolean;
/** THE exclusion test, by value. */
export declare function isBrokeredSecret(value: string): boolean;
/** THE exclusion test, for a caller that has already hashed the value. */
export declare function isBrokeredRef(ref: Sha256Ref): boolean;
/**
 * THE exclusion test for a string that may merely CONTAIN a brokered
 * credential — `Bearer <token>`, `token=<token>`, a JSON blob quoting it.
 * See `brokeredValues` for why this exists and what it costs.
 */
export declare function containsBrokeredSecret(value: string): boolean;
/** Size of the exclusion set (tests, and the broker's own capacity check). */
export declare function brokeredSecretCount(): number;
/** Drop every registered brokered secret — tests only. */
export declare function forgetBrokeredSecrets(): void;
