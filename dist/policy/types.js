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
/* -------------------------------- defaults -------------------------------- */
export const DEFAULTS = {
    mcp: { default: 'allow' },
    hold: { timeout_ms: 60_000, on_timeout: 'deny' },
    boundary: {
        secrets: 'redact',
        injection: 'flag',
        max_scan_bytes: 1_048_576,
        on_oversize: 'flag',
    },
    egress: { default: 'deny' },
    match: { server: '*', path: '/**' },
    credential: {
        /**
         * How long a positive decision may be cached. 30 s is NHI's
         * `BROKER_DEFAULT_TTL_SECONDS` (apps/api/src/broker/exchange.ts) — the
         * same number the hosted data plane caches for — so the local broker and
         * the remote one bound staleness identically. It is a bound on staleness,
         * not a promise about the token: a revoked credential stays usable at a
         * cached site for up to this many seconds, which is why the docs quote
         * the number instead of calling revocation instant.
         */
        ttl_seconds: 30,
        /**
         * Deadline for resolving one credential, denied on expiry. 5 000 ms is
         * the timeout NHI's own broker client already carries for the same call
         * (`packages/brokerclient/client.go`, `&http.Client{Timeout: 5 *
         * time.Second}`), so swapping a local resolver for the control plane
         * does not change how long a stuck source can hold the proxy thread the
         * client is waiting on.
         */
        timeout_ms: 5_000,
        on_unresolved: 'deny',
        action: 'allow',
        /** The class that always needs a grant at the control plane: the safe default for a site whose author said nothing. */
        action_class: 'write',
        /** `target.method` when the site does not say: what a swap site of an MCP tool almost always is. */
        method: 'POST',
        /** `credentials[].broker.timeout_ms`: the same 5 s the local resolver and NHI's client carry. */
        broker_timeout_ms: 5_000,
        /** NHI's broker reads `{"token": ...}` out of the vault blob; same key here. */
        vault_field: 'token',
        /** AWS's minimum session length: the shortest-lived token STS will mint. */
        aws_duration_seconds: 900,
        clickup_token_env: 'CLICKUP_API_TOKEN',
    },
};
/** Range limits enforced by the JSON Schema (`minimum` / `maximum`). */
export const LIMITS = {
    hold_timeout_ms: { min: 1_000, max: 3_600_000 },
    max_scan_bytes: { min: 4_096, max: 64 * 1024 * 1024 },
    /** 0 disables the decision cache; the cap keeps a stale allow inside five minutes. */
    credential_ttl_seconds: { min: 0, max: 300 },
    credential_timeout_ms: { min: 100, max: 30_000 },
    /** AWS STS: 15 minutes to 12 hours. */
    aws_duration_seconds: { min: 900, max: 43_200 },
};
/** Identifier pattern shared by `name` and rule `id`. */
export const ID_PATTERN = '^[A-Za-z0-9_.:/-]{1,64}$';
/**
 * A POSIX environment variable name. Narrower than what `execve` permits (no
 * `=`, any other byte goes) because a policy that names a variable no shell
 * can export is a typo, not a feature.
 */
export const ENV_VAR_PATTERN = '^[A-Za-z_][A-Za-z0-9_]{0,127}$';
/**
 * A hostname as `host: {fixed: ...}` accepts it: labels of letters, digits
 * and hyphens, optionally with a port. No scheme, no path, no glob — this is
 * the destination the operator asserts, not a pattern to match.
 */
export const HOSTNAME_PATTERN = '^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*(:[0-9]{1,5})?$';
/** An IAM role ARN, the one `aws-sts` field where a typo is otherwise invisible until first use. */
export const ROLE_ARN_PATTERN = '^arn:aws[a-z-]*:iam::[0-9]{12}:role/.+$';
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
export const REGEX_VALUE_CAP = 4_096;
/* ------------------------------- normalize -------------------------------- */
function toList(v) {
    return typeof v === 'string' ? [v] : [...v];
}
/** Auto-assigned id for a rule without one; brackets keep it outside ID_PATTERN so it can never collide. */
export function autoRuleId(index) {
    return `rule[${index}]`;
}
/** Auto-assigned id for a swap site without one, outside ID_PATTERN for the same reason. */
export function autoUseId(index) {
    return `use[${index}]`;
}
/**
 * The id a swap site is known by everywhere else: in the decision, in the
 * chain and as the rule id in the compiled Rego. Composed rather than
 * author-given so that uniqueness across the section follows from two local
 * checks — credential ids are unique, and site ids are unique within their
 * credential — instead of a third global one the author has to keep in their
 * head. `/` is inside `ID_PATTERN`, so a composed id is still a legal
 * identifier.
 */
export function credentialUseId(credentialId, siteId) {
    return `${credentialId}/${siteId}`;
}
function normalizeMcpRule(rule, index) {
    const match = {
        server: toList(rule.match.server ?? DEFAULTS.match.server),
        tool: toList(rule.match.tool),
    };
    if (rule.match.args !== undefined)
        match.args = { ...rule.match.args };
    if (rule.match.max_args_bytes !== undefined)
        match.max_args_bytes = rule.match.max_args_bytes;
    const out = { id: rule.id ?? autoRuleId(index), match, action: rule.action };
    if (rule.reason !== undefined)
        out.reason = rule.reason;
    return out;
}
function normalizeEgressRule(rule, index) {
    const match = {
        host: toList(rule.match.host),
        path: toList(rule.match.path ?? DEFAULTS.match.path),
    };
    if (rule.match.methods !== undefined)
        match.methods = [...rule.match.methods];
    if (rule.match.max_body_bytes !== undefined)
        match.max_body_bytes = rule.match.max_body_bytes;
    const out = { id: rule.id ?? autoRuleId(index), match, action: rule.action };
    if (rule.reason !== undefined)
        out.reason = rule.reason;
    return out;
}
function normalizeCredentialSource(source) {
    switch (source.type) {
        case 'env':
            return { type: 'env', var: source.var };
        case 'file': {
            const out = { type: 'file', path: source.path };
            if (source.field !== undefined)
                out.field = source.field;
            return out;
        }
        case 'exec':
            return { type: 'exec', command: source.command, args: [...(source.args ?? [])] };
        case 'github-app': {
            const out = {
                type: 'github-app',
                app_id: source.app_id,
                installation_id: source.installation_id,
            };
            if (source.private_key_file !== undefined)
                out.private_key_file = source.private_key_file;
            if (source.private_key_env !== undefined)
                out.private_key_env = source.private_key_env;
            if (source.repositories !== undefined)
                out.repositories = [...source.repositories];
            if (source.permissions !== undefined)
                out.permissions = { ...source.permissions };
            return out;
        }
        case 'aws-sts': {
            const out = {
                type: 'aws-sts',
                role_arn: source.role_arn,
                duration_seconds: source.duration_seconds ?? DEFAULTS.credential.aws_duration_seconds,
            };
            if (source.region !== undefined)
                out.region = source.region;
            if (source.session_name !== undefined)
                out.session_name = source.session_name;
            if (source.external_id !== undefined)
                out.external_id = source.external_id;
            return out;
        }
        case 'vault': {
            const out = {
                type: 'vault',
                path: source.path,
                field: source.field ?? DEFAULTS.credential.vault_field,
            };
            if (source.addr !== undefined)
                out.addr = source.addr;
            if (source.namespace !== undefined)
                out.namespace = source.namespace;
            if (source.token_env !== undefined)
                out.token_env = source.token_env;
            return out;
        }
        case 'clickup': {
            const out = {
                type: 'clickup',
                token_env: source.token_env ?? DEFAULTS.credential.clickup_token_env,
            };
            if (source.team_id !== undefined)
                out.team_id = source.team_id;
            return out;
        }
    }
}
function normalizeCredentialHost(host) {
    if ('from_arg' in host)
        return { from: 'argument', arg: host.from_arg, allow: toList(host.allow) };
    if ('fixed' in host)
        return { from: 'declared', host: host.fixed };
    return { from: 'server_name' };
}
function normalizeCredentialPath(path) {
    if (path !== undefined && 'from_arg' in path) {
        return { from: 'argument', arg: path.from_arg, allow: toList(path.allow) };
    }
    return { from: 'tool_name' };
}
function normalizeCredentialUse(use, index, credentialId) {
    const out = {
        id: credentialUseId(credentialId, use.id ?? autoUseId(index)),
        server: toList(use.server ?? DEFAULTS.match.server),
        tool: toList(use.tool),
        arg: use.arg,
        host: normalizeCredentialHost(use.host),
        path: normalizeCredentialPath(use.path),
        action: use.action ?? DEFAULTS.credential.action,
        action_class: use.action_class ?? DEFAULTS.credential.action_class,
        method: (use.method ?? DEFAULTS.credential.method).toUpperCase(),
    };
    if (use.reason !== undefined)
        out.reason = use.reason;
    return out;
}
function normalizeRemoteBroker(broker) {
    const out = {
        kind: 'remote',
        url: broker.url,
        token_env: broker.token_env,
        timeout_ms: broker.timeout_ms ?? DEFAULTS.credential.broker_timeout_ms,
    };
    if (broker.tenant !== undefined)
        out.tenant = broker.tenant;
    if (broker.user_env !== undefined)
        out.user_env = broker.user_env;
    if (broker.identity_jwt_env !== undefined)
        out.identity_jwt_env = broker.identity_jwt_env;
    if (broker.tool_id !== undefined)
        out.tool_id = broker.tool_id;
    if (broker.tool_version !== undefined)
        out.tool_version = broker.tool_version;
    return out;
}
function normalizeCredential(credential) {
    const out = {
        id: credential.id,
        use: credential.use.map((use, i) => normalizeCredentialUse(use, i, credential.id)),
        ttl_seconds: credential.ttl_seconds ?? DEFAULTS.credential.ttl_seconds,
        timeout_ms: credential.timeout_ms ?? DEFAULTS.credential.timeout_ms,
        on_unresolved: credential.on_unresolved ?? DEFAULTS.credential.on_unresolved,
    };
    // Validation guarantees exactly one of the two is present.
    if (credential.source !== undefined)
        out.source = normalizeCredentialSource(credential.source);
    if (credential.broker !== undefined)
        out.broker = normalizeRemoteBroker(credential.broker);
    if (credential.synthetic_env !== undefined)
        out.synthetic_env = credential.synthetic_env;
    if (credential.provider !== undefined)
        out.provider = credential.provider;
    if (credential.scopes !== undefined)
        out.scopes = [...credential.scopes];
    return out;
}
/**
 * Fill defaults, coerce single globs to lists and assign missing rule ids.
 * Assumes `raw` already passed schema validation (see `validatePolicyObject`).
 * Pure: never mutates its input.
 */
export function normalizePolicy(raw) {
    const policy = { version: 1 };
    if (raw.name !== undefined)
        policy.name = raw.name;
    if (raw.mcp !== undefined) {
        const m = raw.mcp;
        policy.mcp = {
            default: m.default ?? DEFAULTS.mcp.default,
            rules: (m.rules ?? []).map(normalizeMcpRule),
            hold: {
                timeout_ms: m.hold?.timeout_ms ?? DEFAULTS.hold.timeout_ms,
                on_timeout: m.hold?.on_timeout ?? DEFAULTS.hold.on_timeout,
            },
            boundary: {
                secrets: m.boundary?.secrets ?? DEFAULTS.boundary.secrets,
                injection: m.boundary?.injection ?? DEFAULTS.boundary.injection,
                max_scan_bytes: m.boundary?.max_scan_bytes ?? DEFAULTS.boundary.max_scan_bytes,
                on_oversize: m.boundary?.on_oversize ?? DEFAULTS.boundary.on_oversize,
            },
        };
    }
    if (raw.credentials !== undefined)
        policy.credentials = raw.credentials.map(normalizeCredential);
    if (raw.egress !== undefined) {
        const e = raw.egress;
        policy.egress = {
            default: e.default ?? DEFAULTS.egress.default,
            rules: (e.rules ?? []).map(normalizeEgressRule),
        };
    }
    return policy;
}
//# sourceMappingURL=types.js.map