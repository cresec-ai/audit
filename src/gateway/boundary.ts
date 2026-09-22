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
 * What the narrowing must NOT do is drop a shape that is a credential and
 * nothing else. Three did: an env-var-shaped assignment
 * (`AWS_SECRET_ACCESS_KEY=...`), a `github_pat_` fine-grained token, and a
 * URL carrying userinfo (`postgres://user:pass@host/db`). All three are back
 * — and since the boundary may only name patterns storage already hashes,
 * all three had to be fixed in `ALWAYS_PATTERNS` first, where the same three
 * shapes were missing (or, for the assignment, blinded by a `\b` that `_`
 * defeats).
 *
 * Nor may the widening that puts them back rewrite ordinary output: an affix
 * of any 62 characters riding the bare keyword made `MAX_TOKEN_LENGTH = 512`
 * and `secret_scanning_enabled: true` "credentials". The assignment shape is
 * therefore TWO families — a permissive BARE one where the keyword is the
 * whole name (which also reaches the JSON shape `{"password": "hunter2"}`,
 * the commonest one in an MCP tool result) and an AFFIXED one that also
 * requires the value to look like a credential — plus a third for a flag
 * whose value is the next argument (`--password hunter2`).
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

import type { BoundaryConfig, BoundaryMode } from '../policy/types.js';
import { SYNTHETIC_PREFIX } from '../broker/protocol.js';
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
  /** `boundarySecretPatterns()` (or a test double). */
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

/**
 * The clause a refusal carries when the OPERATOR decided it: a rule denied
 * the call, `mcp.default` denied it, a human denied the hold (or let it time
 * out / lapse at session end), or the boundary filter blocked the result.
 *
 * An agent that reads a bare refusal plausibly does the wrong thing with it:
 * retries the identical call in a loop, reaches the same effect through a
 * tool the policy does not name (denied `http_post` -> `bash curl`), or
 * decides the tool is broken and gives up without telling anyone. A policy
 * the agent routes around is not a policy. Almost no agent will have
 * `docs/agent-guidance.md` installed, so this line is the only guidance the
 * model is guaranteed to see.
 *
 * It is a directive ("do not retry"), not a prediction ("retrying will
 * fail"): a held call that nobody answered could in principle go through on
 * a second attempt, and the text must not claim otherwise. It is two short
 * sentences because it is appended to the agent's context on every refusal
 * of this kind.
 */
export const POLICY_REFUSAL_GUIDANCE =
  'This is a policy decision by the operator, not a tool failure. ' +
  'Do not retry it or use another tool to get the same effect; report it to the user.';

/**
 * The clause a refusal carries when the gateway FAILED CLOSED: it could not
 * reach a decision, so it refused rather than forward the call unchecked.
 * Nobody decided anything about this call — the policy could not be
 * evaluated, the hold file could not be written, the hold cap was already
 * full, the proxy was shutting down, or a result was too large to scan.
 *
 * This one must NOT forbid a retry. `too many pending holds` clears as soon
 * as a parked hold resolves, and an oversize block clears as soon as the
 * agent asks for less output — a retry is the recovery, and {@link
 * POLICY_REFUSAL_GUIDANCE} would forbid exactly the move that works. The two
 * instructions that still hold are the ones that make the gateway a control
 * rather than a speed bump: do not route around it, and tell the user.
 */
/**
 * The clause for a refusal that RETRYING CANNOT FIX. A call whose arguments
 * are past the `any_arg` scan budget is refused identically every time, so
 * {@link FAIL_CLOSED_REFUSAL_GUIDANCE}'s "You may retry it" sends the model
 * into a loop and the person into believing the recorder is broken. This
 * names the two things that actually work, in the order the model can try
 * them: make the call smaller, or ask the person to raise the budget.
 */
export const UNSCANNABLE_REFUSAL_GUIDANCE =
  'The gateway could not scan arguments this large, so it refused this call rather than allow them unchecked. ' +
  'Retrying the same call will be refused identically: send less in one call, or ask the user to raise ' +
  'mcp.any_arg in their policy. Do not use another tool to get the same effect, and report it to the user.';

export const FAIL_CLOSED_REFUSAL_GUIDANCE =
  'The gateway could not reach a policy decision, so it refused this call rather than allow it unchecked. ' +
  'You may retry it; do not use another tool to get the same effect, and report it to the user.';

/**
 * `text` with one guidance clause on its own line. The newline keeps the
 * refusal's first line byte-for-byte what it was before the clause existed,
 * so the rule id and reason still read exactly as the docs quote them.
 */
function withRefusalGuidance(text: string, failClosed: boolean, errorCode?: string): string {
  if (errorCode === 'arguments-too-large-to-scan') return `${text}\n${UNSCANNABLE_REFUSAL_GUIDANCE}`;
  return `${text}\n${failClosed ? FAIL_CLOSED_REFUSAL_GUIDANCE : POLICY_REFUSAL_GUIDANCE}`;
}

/* -------------------------------------------------------------------- */
/* Span primitives                                                        */
/* -------------------------------------------------------------------- */

/** One high-confidence secret family the boundary filter is allowed to act on. */
export interface BoundarySecretFamily {
  /** Stable, human-readable family name (reports, docs, tests). */
  id: string;
  /**
   * The storage pattern this family selects, written EXACTLY as the recorder
   * declares it in `ALWAYS_PATTERNS`. It is a selector, never the regex that
   * runs: `boundarySecretPatterns()` returns the recorder's own RegExp
   * objects, matched by `source`. A drift between the two lists therefore
   * shows up as a missing family, which the boundary test asserts against.
   */
  re: RegExp;
  /** Why this shape is safe to rewrite in text a coding agent reads. */
  note: string;
}

/**
 * The secret families the BOUNDARY filter may rewrite: provider-prefixed
 * credentials, JWTs, PEM private-key blocks and explicit secret assignments.
 * Every entry names a pattern that also lives in the recorder's
 * `alwaysPatterns`; the generic long-hex and long-base64 shapes are
 * deliberately absent (see the module header).
 */
export const BOUNDARY_SECRET_FAMILIES: readonly BoundarySecretFamily[] = [
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
    re: /-----BEGIN [A-Z ]*PRIVATE KEY-----/,
    note:
      'A PEM private-key armour line is never ordinary tool output. The algorithm prefix is ' +
      'OPTIONAL: PKCS#8, which is what `openssl genpkey` and most modern tooling emit, is ' +
      'plain `-----BEGIN PRIVATE KEY-----`, and requiring a prefix let exactly that one cross.',
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
    id: 'github-fine-grained-pat',
    re: /\bgithub_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}\b/,
    note:
      'The documented fine-grained PAT shape: `github_pat_` + a 22-character base62 id + `_` + ' +
      'a 59-character base62 secret.',
  },
  {
    id: 'github-fine-grained-pat-defensive',
    re: /\bgithub_pat_(?=[A-Za-z0-9_]{40,}\b)(?=[A-Za-z0-9_]*[0-9])(?=[A-Za-z0-9_]*[a-z])(?=[A-Za-z0-9_]*[A-Z])[A-Za-z0-9_]+\b/,
    note:
      'A token that does NOT match the documented lengths exactly — a format change, a variant, ' +
      'a paste that lost a character — must not reach the model in clear on a length ' +
      'technicality. Keyed on what a token has and a snake_case identifier does not: 40+ ' +
      'characters, a digit, and both letter cases.',
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
    id: 'url-userinfo',
    re: /(?<=:\/\/)[^\s:/?#@]{1,128}:[^\s/?#@]{1,128}(?=@(?:\[[0-9A-Fa-f:.]{2,45}\]|[\w.-]{1,255})(?::\d{1,5})?(?![\w.:-]))/,
    note:
      'The `user:pass` of a URL that carries userinfo (`postgres://user:pass@host/db`). ' +
      'Only the userinfo is the span, so the scheme, host and path the model needs stay readable. ' +
      'What follows the `@` must look like a host, so a container reference ' +
      '(`oci://redis:7.2@sha256:…`) is not mistaken for userinfo.',
  },
  {
    id: 'secret-assignment',
    re: /(?<![\w-])-{0,2}(?:password|passwd|secret|token|api[_-]?key)["']?\s*[:=]\s*(?:"[^"\s]+"|'[^'\s]+'|\S+)/i,
    note:
      '`password=`, `passwd:`, `secret=`, `token:`, `api_key=` with a value, where the keyword ' +
      'IS the whole name — including the JSON shape an MCP tool result carries it in ' +
      '(`{"password": "hunter2"}`), where the closing quote sits between the keyword and the ' +
      'separator. Nothing else is called `password`, so any value counts.',
  },
  {
    id: 'secret-assignment-affixed',
    re: /(?<![\w-])(?:[A-Za-z0-9_-]{0,62}[_-])?(?:password|passwd|secret|token|api[_-]?key)(?:[_-][A-Za-z0-9_-]{0,62})?["']?\s*[:=]\s*(?:["'](?:(?=[^\s"']{0,255}\d)[^\s"']{8,}|[^\s"']{16,})["']|(?=\S{0,255}\d)\S{8,}|\S{16,})/i,
    note:
      'The env-var-shaped names that carry a credential (`AWS_SECRET_ACCESS_KEY=`, ' +
      '`DB_PASSWORD=`, `X-Api-Key:`). The affix must be separated from the keyword by `_`/`-` ' +
      'AND the value must look like a credential (8+ characters with a digit, or 16+), so ' +
      '`MAX_TOKEN_LENGTH = 512`, `access_token_expires_in: 3600` and ' +
      '`secret_scanning_enabled: true` are left alone.',
  },
  {
    id: 'secret-assignment-camel',
    re: /(?:(?<![\w-])(?:password|passwd|secret|token|credential)|Password|Passwd|Secret|Token|ApiKey|Credential)(?:[A-Z0-9][A-Za-z0-9]{0,62})?["']?\s*[:=]\s*(?:["'](?:(?=[^\s"']{0,255}\d)[^\s"']{8,}|[^\s"']{16,})["']|(?=\S{0,255}\d)\S{8,}|\S{16,})/,
    note:
      'The same assignment shape in camelCase or PascalCase — the dominant style in real tool ' +
      'output, and invisible to both arms above, which require the affix to be separated by `_` ' +
      'or `-`. `SecretAccessKey`, `SessionToken`, `accessToken`, `refreshToken` and ' +
      '`clientSecret` all reached the model in clear. A capital letter is ONE of the two word ' +
      'boundaries: the keyword may also be lower-case when it STARTS the identifier ' +
      '(`secretAccessKey`, `secretKey`, `passwordHash`, `tokenValue`), which requiring a ' +
      'capital missed entirely. Either way the suffix must start upper-case or with a digit, ' +
      'so `secretary`, `tokens` and `tokenize` are not credentials. `apiKey` needs no ' +
      'lower-case arm here: `api[_-]?key` above already makes its separator optional.',
  },
  {
    id: 'credential-flag-value',
    re: /(?<![\w-])-{1,2}(?:[A-Za-z0-9-]{0,62}-)?(?:password|passwd|secret|token|api-?key)(?:-[A-Za-z0-9-]{0,62})?[ \t]+(?:(?=\S{0,255}\d)[^\s<$]\S{5,}|[^\s<$]\S{15,})/i,
    note:
      'A command line in tool output that passes the credential as the NEXT argument ' +
      '(`--password hunter2`). The value must look like a credential (6+ characters with a ' +
      'digit, or 16+) and may not start with `<` or `$`, which keeps `--secret-scanning ' +
      'enabled`, `--token to authenticate`, `--api-key <your-key-here>` and ' +
      '`--token $GITHUB_TOKEN` out.',
  },
];

const BOUNDARY_SOURCES: ReadonlySet<string> = new Set(
  BOUNDARY_SECRET_FAMILIES.map((f) => f.re.source),
);

/**
 * The recorder's own RegExp objects for the families above, in the
 * recorder's order. Computed once: the returned array is the same reference
 * every call, and its entries are identical to the storage patterns (so no
 * `lastIndex` state is introduced and `boundary ⊆ storage` is an identity,
 * not a copy).
 */
const BOUNDARY_PATTERNS: readonly RegExp[] = Object.freeze(
  DEFAULT_POLICY.alwaysPatterns.filter((re) => BOUNDARY_SOURCES.has(re.source)),
);

/**
 * The secret-shape patterns the BOUNDARY filter runs — the high-confidence
 * subset of the recorder's `alwaysPatterns` described by
 * `BOUNDARY_SECRET_FAMILIES`. Generic long-hex (git SHAs, sha256 checksums,
 * dashless UUIDs) and generic base64 (inline images, Docker digests) are NOT
 * here; they still hash in the evidence store.
 */
export function boundarySecretPatterns(): readonly RegExp[] {
  return BOUNDARY_PATTERNS;
}

/** Stable span id for the pattern at `index`. */
function secretId(index: number): string {
  return `secret:${index}`;
}

/**
 * The sources of the three families whose match is `<name><separator><value>`,
 * taken from the table above so they cannot drift apart. The flag family
 * (`--password hunter2`) is NOT here: it has no separator to split on.
 *
 * Matched by source rather than by index because `findSecretSpans` takes the
 * pattern list as a parameter, so position is not a reliable identity.
 */
const ASSIGNMENT_SOURCES: ReadonlySet<string> = new Set(
  BOUNDARY_SECRET_FAMILIES.filter((f) => f.id.startsWith('secret-assignment')).map((f) => f.re.source),
);

/**
 * The BARE family's source, the one arm that gets the NAME-side rules below.
 *
 * The three assignment arms are not interchangeable. The affixed and camel
 * arms gate the value — 8+ characters with a digit, or 16+ — and that gate
 * is most of what keeps them off source code. The bare arm has no gate at
 * all: `password=` followed by anything. So a rule that reads a value as
 * "too ordinary to be a credential" is sound for the bare arm and unsound
 * for the other two, where every value it sees has already cleared the gate
 * and dropping it can only subtract credentials. Applying the bare arm's
 * rules to all three was a leak: `CLIENT_SECRET=supersecretpassphrase`,
 * `SecretAccessKey: wJalrXUtnFEMIKMDENGbPxRfiCYEXAMPLEKEY` and twelve more
 * shapes reached the model in clear, any of them recoverable by putting one
 * `.` before the keyword (`env.DB_PASSWORD=`, `aws.SecretAccessKey`).
 */
const BARE_ASSIGNMENT_SOURCE: string | undefined = BOUNDARY_SECRET_FAMILIES.find(
  (f) => f.id === 'secret-assignment',
)?.re.source;

/**
 * The value half of an assignment match: everything past the first `:` or
 * `=`. No keyword and no affix contains either character, so the first one
 * in the match IS the separator, whatever family matched and however the
 * name was quoted (`"password": "hunter2"` splits at the `:` after the
 * closing quote).
 */
function assignmentValue(matched: string): string | undefined {
  const at = matched.search(/[:=]/);
  if (at < 0) return undefined;
  return matched.slice(at + 1).replace(/^\s+/, '');
}

/**
 * A value that is a bare word: letters only, no digit, no `-`/`_`/`.`/`/`,
 * optionally followed by the punctuation that ended the token in the source
 * (`string,`, `string):`, `bool;`). This is what a type annotation, a
 * keyword and an identifier look like — `token: string`, `secret = await`,
 * `password = null` — and what a credential almost never looks like.
 *
 * The cost is stated rather than hidden: an UNQUOTED, letters-only,
 * digit-free value in a BARE `password=`/`token:` field is no longer
 * redacted at the boundary. Quoting it (`password: "hunter"`), an affix
 * (`DB_PASSWORD=hunter`), any digit or separator, and every prefix family
 * (`sk-`, `ghp_`, `AKIA`, `Bearer`, JWT, PEM, `xox`) are all unaffected, and
 * storage still hashes it either way.
 */
const BARE_WORD_VALUE = /^[A-Za-z]+\W*$/;

/**
 * The same shape with the trailing punctuation REQUIRED, which is the part
 * that is safe for a gated arm.
 *
 * The affixed arm's affix is optional, so its name language is a strict
 * SUPERSET of the bare arm's: every `password=` the bare arm matches, it
 * matches too. Scoping `BARE_WORD_VALUE` to the bare arm therefore did not
 * scope the rule at all — it deleted it for every value of 16+ characters,
 * because the affixed arm re-added the identical span the moment the value
 * cleared its gate, which any type name that long does. Measured over 1.08
 * million lines of third-party TypeScript: 119 lines corrupted that the
 * previous tree delivered intact, `declare function isCommaToken(token:
 * CommentOrToken): token is CommaToken$1;` among them — the canonical shape
 * the whole filter was written for.
 *
 * What makes the trailing punctuation the right discriminator is that a
 * CREDENTIAL ENDS THE FIELD. `CLIENT_SECRET=supersecretpassphrase` stops at
 * the passphrase; `token: CommentOrToken):` stops at the syntax of the code
 * around it, and `Token = isClosingBraceToken;` at its statement's
 * semicolon. So a letters-only value followed by punctuation is an
 * annotation and a letters-only value followed by nothing is a passphrase.
 *
 * The cost is one shape, stated rather than hidden: a letters-only
 * credential with a trailing separator in an AFFIXED field
 * (`DB_PASSWORD=supersecretpassphrase.`) is no longer redacted at the
 * boundary. Storage still hashes it.
 */
const TYPE_ANNOTATION_VALUE = /^[A-Za-z]+\W+$/;

/**
 * How much of a value the shape rules look at. A type name, a keyword and a
 * placeholder are all short; past this the value is a blob, and a blob in a
 * field called `password` is a credential, so the cap fails towards
 * redacting. It also bounds the per-match cost: the first draft of
 * `hasCallOrIndex` was the regex `/[A-Za-z_$][A-Za-z0-9_$]*\s*[([]/`, which
 * restarts at every position and took 4.8 s on 60 KiB — a backtracking
 * blowup on the forwarding path, which is the thing this filter exists to
 * keep out of the gateway.
 */
const SHAPE_CAP = 512;

/**
 * Punctuation that separates an EXPRESSION from an opaque credential. A call
 * in real code carries at least one of these — the argument's quotes, a
 * member `.`, a comma, the statement's `;`, a template's `${}`, or the space
 * around an operator. A passphrase is one unbroken run of characters.
 */
const CODE_PUNCTUATION = /[.,;'"`${}\s]/;

/**
 * The value without its own surrounding quotes, for the expression test
 * ONLY.
 *
 * `CODE_PUNCTUATION` contains `"` and `'`, so a quoted value was punctuated
 * by its own delimiters and the bracket rule below fired on every one of
 * them. That made the whole "a bracket must CLOSE the value" refinement
 * inapplicable to JSON and YAML — which is most of what a tool result is —
 * and `{"db":{"password":"Tr0ub4dor(3)andmore"}}` went to the model in
 * clear while its unquoted twin was redacted.
 */
function unquotedValue(value: string): string {
  const q = value[0];
  const closes = value.length >= 2 && value[value.length - 1] === q;
  return (q === '"' || q === "'") && closes ? value.slice(1, -1) : value;
}

/**
 * True when `value` contains an identifier immediately followed by a call or
 * an index (`decode(url.password);`, `m[0];`). Written as a scan rather than
 * a regex so it is linear: each `(`/`[` walks back over its own run of
 * spaces and nothing else.
 *
 * A bracket alone is not enough, because a passphrase may contain one:
 * `DB_PASSWORD=Tr0ub4dor(3)andmore` read as a call expression and was
 * delivered in clear. So a value with no code punctuation anywhere is a
 * call only if a bracket CLOSES it — `getSecret()` — and not if the bracket
 * is embedded in a longer run, which is a credential with a paren in it.
 * The residual is the exact shape where the two are indistinguishable
 * without a parser: an unquoted, punctuation-free value that ends at its own
 * closing bracket (`password=Tr0ub4dor(3)`). It stays on the code side
 * because `secret_key = loadFromEnvironment()` is the commoner line, and
 * storage hashes the value either way.
 */
function hasCallOrIndex(value: string): boolean {
  const punctuated = CODE_PUNCTUATION.test(value);
  for (let i = 1; i < value.length; i++) {
    const c = value[i];
    if (c !== '(' && c !== '[') continue;
    let j = i - 1;
    while (j >= 0 && (value[j] === ' ' || value[j] === '\t')) j--;
    if (j < 0 || !/[A-Za-z0-9_$]/.test(value[j] as string)) continue;
    if (punctuated || /[)\]]$/.test(value)) return true;
  }
  return false;
}

/** A shell or template placeholder rather than a value: `${x}`, `$(x)`, `$VAR`, `<your-key>`. */
const PLACEHOLDER_VALUE = /^(?:\$[{(]|\$[A-Z_][A-Za-z0-9_]*\W*$|<)/;

/**
 * True when the VALUE of an assignment match is a fragment of source code
 * rather than a credential. Applies to every assignment arm.
 *
 * These three rules read the value alone and none of them can mistake a
 * credential for code on its own terms: a credential is a literal, so it is
 * not a `${...}` reference, not pure punctuation, and not an expression.
 * They are what lets `const password = decode(url.password);` cross — a line
 * the AFFIXED arm matches too, because its optional affix means a bare
 * `password` is in its language as well, and `decode(url.password);` is 21
 * characters, which clears the arm's value gate.
 */
export function isCodeShapedValue(matched: string): boolean {
  const value = assignmentValue(matched);
  if (value === undefined) return false; // a shape this function cannot split stays a match
  const inner = unquotedValue(value);
  // A placeholder is one whether or not the format quoted it:
  // `password = "${VAULT_SECRET}"` is a template reference, not a secret.
  if (PLACEHOLDER_VALUE.test(value) || PLACEHOLDER_VALUE.test(inner)) return true;
  if (!/[A-Za-z0-9]/.test(value)) return true; // `…`, a stray backtick, punctuation only
  // A type annotation or an identifier, ended by the code around it.
  if (value.length <= SHAPE_CAP && TYPE_ANNOTATION_VALUE.test(value)) return true;
  const head = inner.length > SHAPE_CAP ? inner.slice(0, SHAPE_CAP) : inner;
  // A template literal or an expression: code, where a credential is a literal.
  return head.includes('`') || hasCallOrIndex(head);
}

/**
 * True when a BARE-family match is a fragment of source code rather than a
 * credential: `isCodeShapedValue` plus two rules that are sound ONLY for the
 * bare arm.
 *
 * The bare family takes ANY value on purpose: a field whose whole name is
 * `password` carries a credential whatever it looks like, and a value gate
 * like the affixed family's would drop `{"password": "hunter2"}`, the
 * commonest shape in a tool result. That premise holds for configuration and
 * command output and fails for SOURCE CODE — the main thing an agent reads
 * through a filesystem server. `function f(token: string, ...)` is an
 * assignment by this pattern's reading, and because the value is `\S+` the
 * span swallows the type after it, so the model is handed
 * `function f([redacted:sha256:…] ...)` instead of the code it asked for.
 * Measured over this repository's own sources before the fix: 21 files, 188
 * lines rewritten.
 *
 * The ONE extra rule here is the one that needs the missing value gate to be
 * safe: an unterminated one-word value is an identifier or a type
 * (`password = None`, `token: string`), where for a gated arm it is a
 * passphrase (`CLIENT_SECRET=supersecretpassphrase`). A one-word value that
 * IS terminated by punctuation is code for every arm — see
 * {@link TYPE_ANNOTATION_VALUE}.
 *
 * A member-access rule used to sit beside it, reading a `.` before the
 * keyword as `clean.password = ''`. It is gone, and its removal was
 * measured: over 1,081,257 lines of installed third-party source it
 * prevented exactly ONE rewrite (a doc comment reading
 * `* myURL.password = '123';`), because the value rules already catch real
 * member assignments — `self.password = get_password()` is an expression,
 * `this.password = undefined` and `obj.token = t` are bare words,
 * `clean.password = ''` is punctuation only. Against that one line it cost a
 * whole leak class, because a `.` before the keyword is a KEY SEPARATOR in
 * every config format there is: `env.password=hunter2` and
 * `config.token=abc123`, both too short for the gated arms to see, were
 * delivered in clear.
 *
 * This runs at the BOUNDARY only. The storage pattern keeps the permissive
 * `\S+`, because the two directions fail differently: hashing a type
 * annotation costs readability in the evidence store, while narrowing what
 * storage matches would let a password containing `,` or `)` match in PART
 * and leave the rest of it in the store in clear. So the boundary drops
 * matches rather than the pattern being changed, and `boundary ⊆ storage`
 * still holds — now strictly.
 */
export function isCodeShapedAssignment(matched: string): boolean {
  if (isCodeShapedValue(matched)) return true;
  const value = assignmentValue(matched);
  if (value === undefined) return false;
  return value.length <= SHAPE_CAP && BARE_WORD_VALUE.test(value);
}

/** Every raw per-pattern match (may overlap), in pattern order. */
function rawSecretSpans(text: string, patterns: readonly RegExp[]): Span[] {
  const out: Span[] = [];
  patterns.forEach((re, i) => {
    const assignment = ASSIGNMENT_SOURCES.has(re.source);
    const bare = re.source === BARE_ASSIGNMENT_SOURCE;
    for (const s of matchSpans(re, text, secretId(i))) {
      if (!assignment) {
        out.push(s);
        continue;
      }
      const matched = text.slice(s.start, s.end);
      if (bare ? isCodeShapedAssignment(matched) : isCodeShapedValue(matched)) continue;
      out.push(s);
    }
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


/**
 * Where synthetic placeholders sit in a string. Used to keep the secret
 * scanner off them; see the call site for why that is the right behaviour.
 */
function syntheticOccurrences(text: string): Span[] {
  const out: Span[] = [];
  const prefix = SYNTHETIC_PREFIX;
  let from = 0;
  for (;;) {
    const at = text.indexOf(prefix, from);
    if (at === -1) break;
    let end = at + prefix.length;
    while (end < text.length && /[A-Za-z0-9_-]/.test(text[end] as string)) end++;
    out.push({ start: at, end, id: 'synthetic' });
    from = end;
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

/**
 * The exact isError text of a blocked result (pinned by tests).
 *
 * Unlike a deny, this withheld a RESULT: the call already ran on the server
 * and whatever it did is done. {@link POLICY_REFUSAL_GUIDANCE} still belongs
 * here — the operator's `mcp.boundary` setting decided this, and re-running
 * a side-effecting tool to get the same bytes back, or reading the same
 * content through a tool the policy does not name, are the two moves the
 * boundary exists to stop.
 */
export function blockedText(secrets: number, injections: number): string {
  return withRefusalGuidance(
    'mcp-recorder gateway: tool result blocked by policy ' +
      `(${plural(secrets, 'secret-shaped value')}, ${plural(injections, 'injection marker')})`,
    false,
  );
}

/**
 * The exact isError text of a result blocked for exceeding max_scan_bytes.
 *
 * This carries {@link FAIL_CLOSED_REFUSAL_GUIDANCE}, not the policy-decision
 * clause. Nothing about the call or its content was judged: the line was too
 * large to scan, so `on_oversize` blocked it unread — the definition of
 * failing closed. Asking for less output (a page, a byte range, a narrower
 * filter) is the correct recovery, and the fail-closed clause permits
 * exactly that while still refusing the one move that would defeat the
 * boundary: reading the same bytes through a tool that is not scanned.
 */
export function oversizeBlockedText(rawBytes: number, maxScanBytes: number): string {
  return withRefusalGuidance(
    'mcp-recorder gateway: tool result blocked by policy ' +
      `(result of ${rawBytes} bytes exceeds max_scan_bytes ${maxScanBytes})`,
    true,
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
    // A synthetic is not a secret — it is the placeholder that exists so a real
    // one never gets here, and off this machine it is inert. Redacting it
    // would hide the single most useful thing a reader can check: that what
    // came back is the synthetic and NOT the credential. Synthetics are
    // high-entropy, so the generic patterns match them (and often match only
    // PART of one, which is why this works on overlap rather than on the
    // span's own text).
    const syntheticSpans = syntheticOccurrences(slot.text);
    const raw = (scanSecrets ? rawSecretSpans(slot.text, deps.secretPatterns) : []).filter(
      (span) => !syntheticSpans.some((syn) => span.start < syn.end && syn.start < span.end),
    );
    const secrets = mergeSpans(raw);
    // The operator's budget, not a second hidden one: `max_scan_bytes` has
    // already been enforced on the whole line above, so this never truncates
    // a slot that got this far — and `scanned: true` stays true.
    const injections = scanInjection ? findInjectionSpans(slot.text, maxScan) : [];
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
  /**
   * Absent when no rule matched: the policy default applied, the policy could
   * not be evaluated (fail-closed, `reason` says so), or the proxy refused
   * the call itself (hold limit, `reason` says so).
   */
  ruleId?: string;
  reason?: string;
  /** Present for hold outcomes; names the hold in the text. */
  approvalId?: string;
  outcome?: DeniedHoldOutcome;
  /**
   * True when the gateway FAILED CLOSED rather than the operator deciding:
   * the policy could not be evaluated, the hold file could not be written,
   * the hold cap was full, or the proxy was already shutting down. It
   * selects {@link FAIL_CLOSED_REFUSAL_GUIDANCE} over
   * {@link POLICY_REFUSAL_GUIDANCE} and nothing else — the first line is
   * unchanged, so every text the docs quote still reads exactly as before.
   * The caller must set it explicitly; `deniedText` never guesses it from
   * the reason string, which is free-form and comes from the policy file.
   */
  failClosed?: boolean;
  /**
   * The stable code for a fail-closed refusal (the policy engine's
   * `Decision.errorCode`). It selects a guidance clause whose remedy is the
   * real one for that class — today only `arguments-too-large-to-scan`,
   * whose {@link UNSCANNABLE_REFUSAL_GUIDANCE} replaces an invitation to
   * retry a call that cannot succeed. It changes NOTHING about the first
   * line, so every refusal the docs quote still reads exactly as before.
   */
  errorCode?: string;
}

const OUTCOME_PHRASE: Record<DeniedHoldOutcome, string> = {
  denied: 'was denied',
  timeout: 'timed out',
  cancelled: 'was cancelled',
  session_end: 'was abandoned at session end',
};

/**
 * The text the model sees for a call the gateway did not forward. The first
 * line is the refusal itself:
 *   mcp-recorder gateway: tools/call "<tool>" denied by policy rule "<rule>": <reason>
 *   mcp-recorder gateway: tools/call "<tool>" denied by policy (no rule matched; mcp.default is deny)
 *   mcp-recorder gateway: tools/call "<tool>" denied by policy: policy evaluation error: <detail>
 *   mcp-recorder gateway: tools/call "<tool>" denied by policy rule "<rule>" (hold <id> timed out): <reason>
 * and one guidance clause follows on a second line.
 *
 * A deny without a rule id says "denied by policy", never "by policy
 * default": an evaluation-error deny or a hold-limit refusal is not the
 * default acting, and the text must not claim it is. The default case is
 * the one with neither a rule nor a reason, and it says so explicitly.
 *
 * WHICH clause is not a property of the text: a refusal the operator decided
 * (a rule deny, an `mcp.default` deny, a hold denied / timed out / abandoned
 * at session end) gets {@link POLICY_REFUSAL_GUIDANCE}, and one where the
 * gateway failed closed instead (`failClosed`) gets
 * {@link FAIL_CLOSED_REFUSAL_GUIDANCE}, which does not forbid the retry that
 * is often the fix. `failClosed` wins over the outcome: a hold REFUSED
 * because the session was already closing reads `session_end` too, but
 * nobody decided it.
 *
 * The one outcome that gets NO clause is `cancelled`: there the CLIENT
 * withdrew its own request with `notifications/cancelled` and the gateway
 * merely stopped waiting. Nothing was refused, the caller already knows
 * (per MCP it should ignore this response entirely), and its own reason for
 * cancelling may well make a fresh attempt correct — so either clause would
 * be untrue.
 */
export function deniedText(input: DeniedTextInput): string {
  const by = input.ruleId !== undefined ? `policy rule "${input.ruleId}"` : 'policy';
  let text = `mcp-recorder gateway: tools/call "${input.tool}" denied by ${by}`;
  if (input.approvalId !== undefined) {
    const phrase = input.outcome !== undefined ? OUTCOME_PHRASE[input.outcome] : 'was not approved';
    text += ` (hold ${input.approvalId} ${phrase})`;
  }
  const hasReason = input.reason !== undefined && input.reason !== '';
  if (hasReason) text += `: ${input.reason}`;
  else if (input.ruleId === undefined && input.approvalId === undefined) text += ' (no rule matched; mcp.default is deny)';
  if (input.outcome === 'cancelled') return text;
  return withRefusalGuidance(text, input.failClosed === true, input.errorCode);
}

/** JSON-RPC response carrying a tool-execution error (MCP `isError`). */
export function synthesizeDeniedResult(
  id: string | number,
  text: string,
): { jsonrpc: '2.0'; id: string | number; result: { content: { type: 'text'; text: string }[]; isError: true } } {
  return { jsonrpc: '2.0', id, result: { content: [{ type: 'text', text }], isError: true } };
}
