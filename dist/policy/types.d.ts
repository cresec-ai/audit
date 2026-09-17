/**
 * policy.yaml v1 — TypeScript types and defaults.
 *
 * Two families of types live here:
 *
 * - `*Input` types describe the document as an author writes it (after JSON
 *   Schema validation, see `validate.ts`): optional fields may be absent and
 *   `tool` / `host` / `path` may be a single glob or a list.
 * - The plain types (`Policy`, `McpRule`, ...) describe the NORMALIZED form
 *   produced by `normalizePolicy()`: every default is filled in, single globs
 *   are coerced to one-element arrays and every rule carries an id. The
 *   engine (`engine.ts`) and the Rego compiler (`rego.ts`) consume only the
 *   normalized form, so they never have to think about defaults.
 *
 * Invariants: normalized policies are JSON-plain (no RegExp, no functions,
 * no class instances) so they can be logged, hashed and round-tripped
 * through JSON without surprises. Nothing here pre-compiles globs or
 * regexes — that is the engine's job, with its own bounded caches.
 */
export type Action = 'allow' | 'hold' | 'deny';
export type OnTimeout = 'deny' | 'allow';
export type BoundaryMode = 'redact' | 'block' | 'flag' | 'off';
export type OnOversize = 'flag' | 'block';
/** A glob or a non-empty list of globs, as written in the file. */
export type GlobOrList = string | string[];
export interface McpMatchInput {
    server?: GlobOrList;
    tool: GlobOrList;
    args?: Record<string, string>;
    max_args_bytes?: number;
}
export interface McpRuleInput {
    id?: string;
    match: McpMatchInput;
    action: Action;
    reason?: string;
}
export interface HoldConfigInput {
    timeout_ms?: number;
    on_timeout?: OnTimeout;
}
export interface BoundaryConfigInput {
    secrets?: BoundaryMode;
    injection?: BoundaryMode;
    max_scan_bytes?: number;
    on_oversize?: OnOversize;
}
export interface McpPolicyInput {
    default?: Action;
    rules?: McpRuleInput[];
    hold?: HoldConfigInput;
    boundary?: BoundaryConfigInput;
}
export interface EgressMatchInput {
    host: GlobOrList;
    methods?: string[];
    path?: GlobOrList;
    max_body_bytes?: number;
}
export interface EgressRuleInput {
    id?: string;
    match: EgressMatchInput;
    action: Action;
    reason?: string;
}
export interface EgressPolicyInput {
    default?: Action;
    rules?: EgressRuleInput[];
}
/**
 * Where a real credential is resolved from. `env` / `file` / `exec` resolve
 * on this machine; the other four mint or fetch a token from a provider.
 * The names are NHI's, so a policy written against the local broker means
 * the same thing when the swap is pointed at the Cresec control plane.
 */
export type CredentialSourceType = 'env' | 'file' | 'exec' | 'github-app' | 'aws-sts' | 'vault' | 'clickup';
/**
 * What a declared swap site does. `hold` is deliberately NOT in v1: holding a
 * credential call means resolving the secret only AFTER a human answers, and
 * v1 has no code that does that. An action the file can state and the
 * gateway cannot honour is worse than one the file cannot state.
 */
export type CredentialAction = 'allow' | 'deny';
/**
 * What happens when the credential cannot be resolved. `deny` is the only
 * value the schema admits; the key exists so that the file SAYS so, because
 * the alternative — forwarding the call anyway — forwards the SYNTHETIC to
 * the upstream, which is the one thing a swap must never do.
 */
export type OnUnresolved = 'deny';
/**
 * Where `request.host` of the broker exchange came from. Recorded on the
 * decision, so the chain distinguishes "the destination was checked" from
 * "the destination was not a destination":
 *
 * - `argument` — taken from the call's own arguments and matched against the
 *   site's `allow` globs. The only one that constrains where the credential
 *   actually goes, and the only one worth the words "least privilege".
 * - `declared` — the operator asserted a fixed upstream for a server that
 *   takes no destination argument. Checked against nothing in the call.
 * - `server_name` — no destination at all: the logical server name stands in
 *   for a host, which NHI's contract allows ("the resolved server origin or
 *   server name") and which authorises the TOOL, not the DESTINATION.
 */
export type HostBinding = 'argument' | 'declared' | 'server_name';
/** Where `request.path_template` came from: an argument, or the tool name (the default). */
export type PathBinding = 'argument' | 'tool_name';
export interface EnvCredentialSourceInput {
    type: 'env';
    var: string;
}
export interface FileCredentialSourceInput {
    type: 'file';
    path: string;
    /** Dot-path into the file parsed as JSON; absent means the whole file, trimmed. */
    field?: string;
}
export interface ExecCredentialSourceInput {
    type: 'exec';
    command: string;
    args?: string[];
}
export interface GithubAppCredentialSourceInput {
    type: 'github-app';
    app_id: string;
    installation_id: string;
    private_key_file?: string;
    private_key_env?: string;
    repositories?: string[];
    permissions?: Record<string, string>;
}
export interface AwsStsCredentialSourceInput {
    type: 'aws-sts';
    role_arn: string;
    region?: string;
    session_name?: string;
    duration_seconds?: number;
    external_id?: string;
}
export interface VaultCredentialSourceInput {
    type: 'vault';
    path: string;
    /** Key inside the secret blob. Default "token" — the key NHI's broker reads. */
    field?: string;
    addr?: string;
    namespace?: string;
    token_env?: string;
}
export interface ClickUpCredentialSourceInput {
    type: 'clickup';
    token_env?: string;
    team_id?: string;
}
export type CredentialSourceInput = EnvCredentialSourceInput | FileCredentialSourceInput | ExecCredentialSourceInput | GithubAppCredentialSourceInput | AwsStsCredentialSourceInput | VaultCredentialSourceInput | ClickUpCredentialSourceInput;
/** `host:` as authored — exactly one of the three forms, and never absent. */
export type CredentialHostInput = {
    from_arg: string;
    allow: GlobOrList;
} | {
    fixed: string;
} | {
    from: 'server';
};
/** `path:` as authored. Absent means `{ from: tool }`. */
export type CredentialPathInput = {
    from_arg: string;
    allow: GlobOrList;
} | {
    from: 'tool';
};
export interface CredentialUseInput {
    id?: string;
    server?: GlobOrList;
    tool: GlobOrList;
    /** Dot-path into `params.arguments` where the synthetic stands and the real token is spliced. */
    arg: string;
    host: CredentialHostInput;
    path?: CredentialPathInput;
    action?: CredentialAction;
    reason?: string;
}
export interface CredentialInput {
    id: string;
    provider?: string;
    scopes?: string[];
    source: CredentialSourceInput;
    use: CredentialUseInput[];
    ttl_seconds?: number;
    timeout_ms?: number;
    on_unresolved?: OnUnresolved;
}
export interface EnvCredentialSource {
    type: 'env';
    var: string;
}
export interface FileCredentialSource {
    type: 'file';
    path: string;
    field?: string;
}
export interface ExecCredentialSource {
    type: 'exec';
    command: string;
    args: string[];
}
export interface GithubAppCredentialSource {
    type: 'github-app';
    app_id: string;
    installation_id: string;
    private_key_file?: string;
    private_key_env?: string;
    repositories?: string[];
    permissions?: Record<string, string>;
}
export interface AwsStsCredentialSource {
    type: 'aws-sts';
    role_arn: string;
    region?: string;
    session_name?: string;
    duration_seconds: number;
    external_id?: string;
}
export interface VaultCredentialSource {
    type: 'vault';
    path: string;
    field: string;
    addr?: string;
    namespace?: string;
    token_env?: string;
}
export interface ClickUpCredentialSource {
    type: 'clickup';
    token_env: string;
    team_id?: string;
}
export type CredentialSource = EnvCredentialSource | FileCredentialSource | ExecCredentialSource | GithubAppCredentialSource | AwsStsCredentialSource | VaultCredentialSource | ClickUpCredentialSource;
export type CredentialHost = {
    from: 'argument';
    arg: string;
    allow: string[];
} | {
    from: 'declared';
    host: string;
} | {
    from: 'server_name';
};
export type CredentialPath = {
    from: 'argument';
    arg: string;
    allow: string[];
} | {
    from: 'tool_name';
};
export interface CredentialUse {
    /** `<credential id>/<site id>`; the site id defaults to `use[<index>]`. Unique across the section. */
    id: string;
    /** Globs on the logical server name, delimiter "/". Any one matching is enough. Default ["*"]. */
    server: string[];
    /** Globs on the tool name, delimiter "/". Any one matching is enough. */
    tool: string[];
    /** Dot-path into `params.arguments`: the ONLY place this credential is ever spliced. */
    arg: string;
    host: CredentialHost;
    path: CredentialPath;
    action: CredentialAction;
    reason?: string;
}
export interface Credential {
    id: string;
    /** Informational: which provider the real credential belongs to. Recorded on the decision. */
    provider?: string;
    /** Informational: what the real credential can do. Recorded on the decision, so blast radius is answerable from the chain instead of reconstructed. */
    scopes?: string[];
    source: CredentialSource;
    /** Declared swap sites, in order; the first match decides. */
    use: CredentialUse[];
    /** How long a positive decision may be cached, in seconds. */
    ttl_seconds: number;
    /** Deadline for resolving the source, in milliseconds. Overrunning it denies. */
    timeout_ms: number;
    on_unresolved: OnUnresolved;
}
/** The document shape accepted by the JSON Schema (`docs/policy-schema.json`). */
export interface PolicyInput {
    version: 1;
    name?: string;
    mcp?: McpPolicyInput;
    credentials?: CredentialInput[];
    egress?: EgressPolicyInput;
}
export interface McpMatch {
    /** Globs on the logical server name, delimiter "/". Any one matching is enough. Default ["*"]. */
    server: string[];
    /** Globs on the tool name, delimiter "/". Any one matching is enough. */
    tool: string[];
    /** Dot-path -> RE2-compatible regex. All entries must match. */
    args?: Record<string, string>;
    /** Rule only matches when canonical JSON of args is <= this many bytes. */
    max_args_bytes?: number;
}
export interface McpRule {
    /** Explicit id, or `rule[<index>]` when the author gave none. */
    id: string;
    match: McpMatch;
    action: Action;
    reason?: string;
}
export interface HoldConfig {
    timeout_ms: number;
    on_timeout: OnTimeout;
}
export interface BoundaryConfig {
    secrets: BoundaryMode;
    injection: BoundaryMode;
    max_scan_bytes: number;
    on_oversize: OnOversize;
}
export interface McpPolicy {
    default: Action;
    rules: McpRule[];
    hold: HoldConfig;
    boundary: BoundaryConfig;
}
export interface EgressMatch {
    /** Globs on the host, delimiter ".". Any one matching is enough. */
    host: string[];
    /** Upper-case HTTP methods; absent = any method. */
    methods?: string[];
    /** Globs on the URL path, delimiter "/". Default ["/**"]. */
    path: string[];
    max_body_bytes?: number;
}
export interface EgressRule {
    id: string;
    match: EgressMatch;
    action: Action;
    reason?: string;
}
export interface EgressPolicy {
    default: Action;
    rules: EgressRule[];
}
export interface Policy {
    version: 1;
    name?: string;
    mcp?: McpPolicy;
    /** Declared credentials, in order. Absent = the gateway swaps nothing. */
    credentials?: Credential[];
    egress?: EgressPolicy;
}
export declare const DEFAULTS: {
    readonly mcp: {
        readonly default: Action;
    };
    readonly hold: {
        readonly timeout_ms: 60000;
        readonly on_timeout: OnTimeout;
    };
    readonly boundary: {
        readonly secrets: BoundaryMode;
        readonly injection: BoundaryMode;
        readonly max_scan_bytes: 1048576;
        readonly on_oversize: OnOversize;
    };
    readonly egress: {
        readonly default: Action;
    };
    readonly match: {
        readonly server: "*";
        readonly path: "/**";
    };
    readonly credential: {
        /**
         * How long a positive decision may be cached. 30 s is NHI's
         * `BROKER_DEFAULT_TTL_SECONDS` (apps/api/src/broker/exchange.ts) — the
         * same number the hosted data plane caches for — so the local broker and
         * the remote one bound staleness identically. It is a bound on staleness,
         * not a promise about the token: a revoked credential stays usable at a
         * cached site for up to this many seconds, which is why the docs quote
         * the number instead of calling revocation instant.
         */
        readonly ttl_seconds: 30;
        /**
         * Deadline for resolving one credential, denied on expiry. 5 000 ms is
         * the timeout NHI's own broker client already carries for the same call
         * (`packages/brokerclient/client.go`, `&http.Client{Timeout: 5 *
         * time.Second}`), so swapping a local resolver for the control plane
         * does not change how long a stuck source can hold the proxy thread the
         * client is waiting on.
         */
        readonly timeout_ms: 5000;
        readonly on_unresolved: OnUnresolved;
        readonly action: CredentialAction;
        /** NHI's broker reads `{"token": ...}` out of the vault blob; same key here. */
        readonly vault_field: "token";
        /** AWS's minimum session length: the shortest-lived token STS will mint. */
        readonly aws_duration_seconds: 900;
        readonly clickup_token_env: "CLICKUP_API_TOKEN";
    };
};
/** Range limits enforced by the JSON Schema (`minimum` / `maximum`). */
export declare const LIMITS: {
    readonly hold_timeout_ms: {
        readonly min: 1000;
        readonly max: 3600000;
    };
    readonly max_scan_bytes: {
        readonly min: 4096;
        readonly max: number;
    };
    /** 0 disables the decision cache; the cap keeps a stale allow inside five minutes. */
    readonly credential_ttl_seconds: {
        readonly min: 0;
        readonly max: 300;
    };
    readonly credential_timeout_ms: {
        readonly min: 100;
        readonly max: 30000;
    };
    /** AWS STS: 15 minutes to 12 hours. */
    readonly aws_duration_seconds: {
        readonly min: 900;
        readonly max: 43200;
    };
};
/** Identifier pattern shared by `name` and rule `id`. */
export declare const ID_PATTERN = "^[A-Za-z0-9_.:/-]{1,64}$";
/**
 * A POSIX environment variable name. Narrower than what `execve` permits (no
 * `=`, any other byte goes) because a policy that names a variable no shell
 * can export is a typo, not a feature.
 */
export declare const ENV_VAR_PATTERN = "^[A-Za-z_][A-Za-z0-9_]{0,127}$";
/**
 * A hostname as `host: {fixed: ...}` accepts it: labels of letters, digits
 * and hyphens, optionally with a port. No scheme, no path, no glob — this is
 * the destination the operator asserts, not a pattern to match.
 */
export declare const HOSTNAME_PATTERN = "^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*(:[0-9]{1,5})?$";
/** An IAM role ARN, the one `aws-sts` field where a typo is otherwise invisible until first use. */
export declare const ROLE_ARN_PATTERN = "^arn:aws[a-z-]*:iam::[0-9]{12}:role/.+$";
/**
 * The longest `args` value (UTF-16 units) the local engine will match a regex
 * against. A longer one is UNEVALUABLE: the rule neither matches nor is
 * skipped, and the call is denied (`engine.ts`, `VALUE_TOO_LONG`).
 *
 * 4 KiB, not the 64 KiB of earlier drafts: the local engine matches with V8's
 * BACKTRACKING RegExp, whose worst case grows with the subject length, so the
 * cap is also the bound on how much work one hostile argument can ask for.
 * The value used to be TRUNCATED to the cap, which silently turned a deny into
 * an allow — `"x".repeat(5000) + "rm -rf /"` did not match a `cmd: "rm -rf /"`
 * rule — so the engine now refuses to answer instead. The Rego side matches
 * with RE2 (linear time) and keeps answering for values of any length; within
 * the cap the two engines agree exactly, and beyond it the local one is never
 * more permissive. Documented in `docs/policy.md`.
 */
export declare const REGEX_VALUE_CAP = 4096;
/** Auto-assigned id for a rule without one; brackets keep it outside ID_PATTERN so it can never collide. */
export declare function autoRuleId(index: number): string;
/** Auto-assigned id for a swap site without one, outside ID_PATTERN for the same reason. */
export declare function autoUseId(index: number): string;
/**
 * The id a swap site is known by everywhere else: in the decision, in the
 * chain and as the rule id in the compiled Rego. Composed rather than
 * author-given so that uniqueness across the section follows from two local
 * checks — credential ids are unique, and site ids are unique within their
 * credential — instead of a third global one the author has to keep in their
 * head. `/` is inside `ID_PATTERN`, so a composed id is still a legal
 * identifier.
 */
export declare function credentialUseId(credentialId: string, siteId: string): string;
/**
 * Fill defaults, coerce single globs to lists and assign missing rule ids.
 * Assumes `raw` already passed schema validation (see `validatePolicyObject`).
 * Pure: never mutates its input.
 */
export declare function normalizePolicy(raw: PolicyInput): Policy;
