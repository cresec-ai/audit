/**
 * FROM A POLICY FILE TO A LIVE SWAP — the last mile.
 *
 * Everything else in src/broker/ is reachable only from a test until
 * something builds a broker out of an operator's policy and hands the gateway
 * a `CredentialSwap`. That is what this module does, and it is deliberately
 * the only place the three pieces meet:
 *
 *   policy.credentials[]  ->  CredentialEntry[]      (what LocalBroker resolves)
 *                         ->  CredentialsConfigInput (where the gateway may splice)
 *
 * The two shapes overlap but are not the same, and the split is the point.
 * The gateway knows only about SITES — (server, tool, argument dot-path) — so
 * that a leaked synthetic in some other argument is inert. The broker knows
 * about SOURCES and DESTINATIONS, so that a site which matched still has to
 * satisfy a host rule before a real token is handed back. Neither half can
 * authorise a call on its own.
 *
 * WHERE THE SYNTHETIC COMES FROM. The policy deliberately does not carry it.
 * A policy file is meant to be readable evidence of the rules — shareable,
 * diffable, committed — and a file full of raw synthetics is a file full of
 * values that are redeemable on this machine. So each credential's synthetic
 * is supplied out of band, in the environment, under a name derived from its
 * id:
 *
 *   credential id "github-issues"  ->  MCP_RECORDER_SYNTHETIC_GITHUB_ISSUES
 *
 * That variable is set in the AGENT's environment (it is what the agent
 * holds) and in the recorder's, because the recorder is the agent's child.
 * `mcp-recorder credentials issue <id>` mints one in NHI's format.
 *
 * The pepper is per process and never persisted. It can be, because the raw
 * synthetic is supplied on every start: the broker hashes it at construction
 * with the same pepper it hashes incoming requests with, so the binding holds
 * for the life of the process and nothing on disk is worth stealing. A
 * persisted pepper would be one more file on the agent's side of the boundary.
 *
 * WHAT THIS DOES NOT DO. It does not make the credential confidential from
 * the agent. On a single-uid developer machine the agent can read the same
 * environment and the same policy this function reads. What it buys is that
 * the real credential is absent from the model's context, absent from the
 * transcript and absent from the evidence chain, and that every use of it is
 * a recorded, policy-checked decision. docs/pov.md carries the full claim.
 */

import { randomUUID } from 'node:crypto';
import type { Credential, CredentialHost, CredentialPath, CredentialSource, Policy, RemoteBrokerSetting } from '../policy/types.js';
import { CredentialSwap, normalizeCredentialsConfig, type CredentialSiteInput } from '../gateway/credentials.js';
import type { IdentityJwtClaims } from '../identity/actor.js';
import { LocalBroker, type CredentialEntry } from './local.js';
import { registerBrokeredSecret } from '../redact/redactor.js';
import type { CredentialSourceSpec } from './sources.js';
import type { Broker, BrokerExchangeHint, BrokerExchangeRequest, BrokerExchangeResponse } from './protocol.js';
import { denyResponse, mintPepper, newDecisionId } from './protocol.js';
import { RemoteBroker, type RemoteBrokerOptions, type UserTokenConfig, type UserTokenCredential } from './remote.js';

/** Raised when a policy expresses something the local broker cannot resolve. */
export class CredentialWiringError extends Error {}

/**
 * One `Broker` over two: a credential whose policy entry carries `broker:
 * { kind: remote }` is answered by the control plane, every other one by
 * the local resolver. Routing is by the SITE's credential id (the hint the
 * swap engine passes), never by the synthetic — the remote path is keyed on
 * (user, connector, tool, action class, target), which are properties of
 * the declared site, and a request that arrives with no hint at all cannot
 * name a remote credential and falls to the local broker, which knows
 * nothing about it and denies `unknown_synthetic`.
 */
export class CompositeBroker implements Broker {
  readonly #local: Broker | undefined;
  readonly #remote: Broker | undefined;
  readonly #remoteIds: ReadonlySet<string>;

  constructor(local: Broker | undefined, remote: Broker | undefined, remoteCredentialIds: Iterable<string>) {
    this.#local = local;
    this.#remote = remote;
    this.#remoteIds = new Set(remoteCredentialIds);
  }

  exchange(req: BrokerExchangeRequest, hint?: BrokerExchangeHint): Promise<BrokerExchangeResponse> {
    const remote = hint !== undefined && this.#remoteIds.has(hint.credential) ? this.#remote : undefined;
    const broker = remote ?? this.#local;
    if (broker === undefined) return Promise.resolve(denyResponse(newDecisionId(), 'unknown_synthetic'));
    return broker.exchange(req, hint);
  }
}


/**
 * Every environment variable a credential source reads from.
 *
 * Needed because the two exclusions run at different times. `LocalBroker`
 * registers a resolved token the moment before it hands it over, which is
 * correct for anything the broker returns — but env-var credential
 * fingerprinting happens once, at SESSION START, long before any tool call
 * has caused a resolution. A `source: { type: env, var: GITHUB_TOKEN }` would
 * therefore be hashed into `identity.credential_fingerprints` on the very
 * first event, and an unsalted ref of a real token is a brute-forceable copy
 * of it — the exact leak brokering exists to prevent.
 *
 * So the wiring registers these eagerly, before the recorder opens. It is a
 * superset by design: a variable named here is excluded whether or not a swap
 * ever fires.
 */
function sourceEnvVars(cred: Credential): string[] {
  const src = cred.source;
  if (src === undefined) {
    // A remote credential names one secret in the environment: the internal
    // token the control plane is called with. It travels in a header, never
    // in an argument, but it is a real bearer credential all the same.
    if (cred.broker === undefined) return [];
    // The identity JWT is a bearer too (it authenticates the person to the
    // control plane's user routes), and JWT-shaped values are exactly what
    // env fingerprinting hashes.
    return cred.broker.identity_jwt_env === undefined ? [cred.broker.token_env] : [cred.broker.token_env, cred.broker.identity_jwt_env];
  }
  switch (src.type) {
    case 'env':
      return [src.var];
    case 'vault':
      return src.token_env !== undefined ? [src.token_env] : [];
    case 'clickup':
      return [src.token_env];
    case 'github-app':
      return src.private_key_env !== undefined ? [src.private_key_env] : [];
    case 'aws-sts':
      // Not named in the policy (see sourceSpecOf): the long-lived pair is
      // read from the conventional environment, so that is what to exclude.
      return ['AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN'];
    case 'file':
    case 'exec':
      return [];
  }
}

/**
 * Register the real credentials a policy points at, so that nothing hashes
 * them. Returns the variables it could not register because the exclusion set
 * was full — a condition the caller must treat as fatal rather than continue
 * through, since past that point a real token can reach the chain.
 */
export function registerPolicyEnvSecrets(credentials: readonly Credential[], env: NodeJS.ProcessEnv): string[] {
  const refused: string[] = [];
  for (const cred of credentials) {
    for (const name of sourceEnvVars(cred)) {
      const value = env[name];
      if (value === undefined || value === '') continue;
      if (!registerBrokeredSecret(value)) refused.push(name);
    }
  }
  return refused;
}

/** The variable a credential's synthetic is read from, declared or derived. */
function envVarFor(credentials: readonly Credential[], id: string): string {
  const cred = credentials.find((c) => c.id === id);
  return cred?.synthetic_env ?? syntheticEnvVar(id);
}

/** Environment variable carrying the synthetic bound to a credential id. */
export function syntheticEnvVar(credentialId: string): string {
  return `MCP_RECORDER_SYNTHETIC_${credentialId.toUpperCase().replace(/[^A-Z0-9]+/g, '_')}`;
}

/**
 * Policy source -> broker source.
 *
 * The two vocabularies are close but not identical, because they were written
 * for different jobs: the policy names a source the way an operator writes it
 * (`token_env: VAULT_TOKEN`), the broker names it the way it resolves it (a
 * nested source that yields the token). Where the policy can express
 * something the broker cannot resolve, this THROWS rather than quietly
 * dropping it — a credential that silently loses a constraint is the shape of
 * bug this whole feature exists to avoid.
 */
function sourceSpecOf(cred: Credential): CredentialSourceSpec {
  const at = `credential "${cred.id}"`;
  if (cred.source === undefined) throw new CredentialWiringError(`${at}: has no local source`);
  const src: CredentialSource = cred.source;
  switch (src.type) {
    case 'env':
      return { type: 'env', var: src.var };
    case 'file':
      if (src.field !== undefined) {
        throw new CredentialWiringError(
          `${at}: source.field is not supported by the local file source — it reads the whole file. ` +
            'Point `path` at a file holding only the secret, or use an `exec` source that extracts the field.',
        );
      }
      return { type: 'file', path: src.path };
    case 'exec':
      return { type: 'exec', command: src.command, args: [...src.args] };
    case 'github-app': {
      // The broker resolves the PEM through an ordinary source, so the two
      // policy spellings collapse onto one thing.
      const key: CredentialSourceSpec | undefined =
        src.private_key_file !== undefined
          ? { type: 'file', path: src.private_key_file }
          : src.private_key_env !== undefined
            ? { type: 'env', var: src.private_key_env }
            : undefined;
      if (key === undefined) {
        throw new CredentialWiringError(`${at}: github-app needs private_key_file or private_key_env`);
      }
      return {
        type: 'github-app',
        app_id: src.app_id,
        installation_id: src.installation_id,
        private_key: key,
        ...(src.repositories !== undefined ? { repositories: [...src.repositories] } : {}),
        ...(src.permissions !== undefined ? { permissions: { ...src.permissions } } : {}),
      };
    }
    case 'aws-sts': {
      if (src.external_id !== undefined) {
        throw new CredentialWiringError(
          `${at}: aws-sts external_id is not supported by the local broker — it is an AssumeRole ` +
            'parameter the local resolver does not send, and honouring it silently would weaken the call.',
        );
      }
      // The base credentials are not in the policy on purpose: they are the
      // long-lived pair, and a policy file is shareable evidence of rules.
      // The conventional environment is the only place to read them from.
      return {
        type: 'aws-sts',
        role_arn: src.role_arn,
        access_key_id: { type: 'env', var: 'AWS_ACCESS_KEY_ID' },
        secret_access_key: { type: 'env', var: 'AWS_SECRET_ACCESS_KEY' },
        session_token: { type: 'env', var: 'AWS_SESSION_TOKEN' },
        ...(src.region !== undefined ? { region: src.region } : {}),
        ...(src.session_name !== undefined ? { session_name: src.session_name } : {}),
        duration_seconds: src.duration_seconds,
      };
    }
    case 'vault': {
      if (src.addr === undefined || src.addr === '') {
        throw new CredentialWiringError(`${at}: vault source needs addr (the OpenBao/Vault address)`);
      }
      if (src.token_env === undefined || src.token_env === '') {
        throw new CredentialWiringError(`${at}: vault source needs token_env naming the variable holding its token`);
      }
      return {
        type: 'vault',
        addr: src.addr,
        path: src.path,
        field: src.field,
        token: { type: 'env', var: src.token_env },
        ...(src.namespace !== undefined ? { namespace: src.namespace } : {}),
      };
    }
    case 'clickup':
      // `team_id` plays no part in resolving a token, so it is not carried:
      // it scopes what the token is used FOR, which is the `use` sites' job.
      return { type: 'clickup', token: { type: 'env', var: src.token_env } };
  }
}

/** Policy host binding -> the gateway's site fields. */
function hostFieldsOf(host: CredentialHost): Pick<CredentialSiteInput, 'host_from' | 'host_arg' | 'host_fixed' | 'allow_host'> {
  switch (host.from) {
    case 'argument':
      return { host_from: 'arg', host_arg: host.arg, allow_host: [...host.allow] };
    case 'declared':
      return { host_from: 'fixed', host_fixed: host.host, allow_host: [host.host] };
    case 'server_name':
      // The server name IS the destination for a stdio server with one fixed
      // upstream. The decision records that, so a reader can tell "the host
      // was checked" from "the host was the server name".
      return { host_from: 'server', allow_host: ['*'] };
  }
}

/** Policy path binding -> the gateway's site fields. */
function pathFieldsOf(path: CredentialPath): Pick<CredentialSiteInput, 'path_arg' | 'allow_path'> {
  return path.from === 'argument' ? { path_arg: path.arg, allow_path: [...path.allow] } : {};
}

/** Policy host binding -> the broker's field binding. */
function hostBindingOf(host: CredentialHost): CredentialEntry['sites'][number]['host_from'] {
  return host.from === 'argument' ? { kind: 'argument', arg: host.arg } : { kind: 'server' };
}

/**
 * The swap sites the gateway may splice at. `deny` sites are carried through
 * rather than dropped: the gateway has to see a carve-out to refuse at it, and
 * a site the gateway cannot see is one the broker would only hear about after
 * the splice had already happened.
 */
function sitesOf(credentials: readonly Credential[]): CredentialSiteInput[] {
  const sites: CredentialSiteInput[] = [];
  for (const cred of credentials) {
    for (const use of cred.use) {
      sites.push({
        id: use.id,
        credential: cred.id,
        server: use.server,
        tool: use.tool,
        arg: use.arg,
        ...hostFieldsOf(use.host),
        ...pathFieldsOf(use.path),
      });
    }
  }
  return sites;
}

/**
 * Destination rules for one credential, from its allow-sites. A deny site
 * contributes no destination — it exists to refuse, not to authorise — so a
 * credential whose sites are all denies ends up with an empty `allow`, which
 * LocalBroker rejects at construction. That is the right outcome: a credential
 * that can never be used is a misconfiguration, said at startup rather than as
 * a deny on every call.
 */
function allowRulesOf(cred: Credential): CredentialEntry['allow'] {
  const rules: CredentialEntry['allow'] = [];
  for (const use of cred.use) {
    if (use.action !== 'allow') continue;
    const host = use.host;
    const hosts = host.from === 'argument' ? [...host.allow] : host.from === 'declared' ? [host.host] : ['*'];
    const path = use.path;
    rules.push({
      host: hosts,
      ...(path.from === 'argument' ? { path_template: [...path.allow] } : {}),
    });
  }
  return rules;
}

export interface CredentialSwapWiring {
  swap: CredentialSwap;
  /** Credential ids with no synthetic in the environment; reported, not fatal. */
  unbound: string[];
}

export interface WireOptions {
  policy: Policy;
  env: NodeJS.ProcessEnv;
  /** Identity the broker knows this proxy by. Ephemeral unless supplied. */
  dataPlaneInstanceId?: string;
  /**
   * The identity JWT's claims (`--identity-jwt`, or the env var a remote
   * credential's `identity_jwt_env` names — see `identityJwtFromPolicy`).
   * Supplies `user_id`, the tenant and the tool claim of every per-user
   * token request; without it those come from `user_env`, `tenant` and
   * `tool_id`/`tool_version` on the `broker` block, and a remote credential
   * that has neither is a wiring error (exit 2), not a silent deny.
   */
  identity?: IdentityJwtClaims;
  /**
   * The compact JWS the claims came from. Needed only for a JOB token
   * (`kind: job`, `run_as: owner`): user-token.md requires `job_token` when
   * `run_as = owner`, and identity-jwt.md says the job token IS the identity
   * JWT with `kind: job` — so it is sent as given. Never recorded.
   */
  identityJwt?: string;
  /** Transport seam for the remote broker (tests inject; production gets `sinkFetch`). */
  remoteFetch?: RemoteBrokerOptions['fetch'];
  /** Operator diagnostics; the caller routes these to stderr. */
  warn?: (line: string) => void;
}

/**
 * The env var, if any, a policy says holds the identity JWT: the first
 * remote credential's `identity_jwt_env`. Read by the CLI BEFORE wiring, so
 * the same claims stamp the actor on every event and key the token requests.
 */
export function identityJwtEnvFromPolicy(policy: Policy): string | undefined {
  for (const cred of policy.credentials ?? []) {
    if (cred.broker?.identity_jwt_env !== undefined) return cred.broker.identity_jwt_env;
  }
  return undefined;
}

/** Every remote credential must agree on ONE control plane; the first one's settings are the session's. */
function remoteSettingsOf(remote: readonly Credential[]): RemoteBrokerSetting {
  const first = remote[0]?.broker as RemoteBrokerSetting;
  for (const cred of remote) {
    const b = cred.broker as RemoteBrokerSetting;
    if (b.url !== first.url || b.token_env !== first.token_env) {
      throw new CredentialWiringError(
        `credential "${cred.id}": every remote credential must name the same control plane (url and token_env) — ` +
          `"${remote[0]?.id ?? ''}" names ${first.url} / $${first.token_env}`,
      );
    }
  }
  return first;
}

/**
 * The per-user token configuration for a session: who, through what, for
 * which tenant. The identity JWT wins over the policy's static settings
 * (user-token.md, "The audit RemoteBroker mapping": `user_id` = `sub` of
 * `--identity-jwt`, else `$<user_env>`; `tool` = the JWT claim, else
 * `tool_id`/`tool_version`; tenant = `tenant_id` claim, else `tenant`).
 */
function userTokenConfigOf(
  remote: readonly Credential[],
  setting: RemoteBrokerSetting,
  opts: WireOptions,
): UserTokenConfig {
  const claims = opts.identity;
  const at = `credential "${remote[0]?.id ?? ''}" (broker)`;
  let userId: string;
  if (claims !== undefined) userId = claims.sub;
  else if (setting.user_env !== undefined) {
    const v = opts.env[setting.user_env];
    if (v === undefined || v === '') throw new CredentialWiringError(`${at}: $${setting.user_env} (user_env) is not set and no identity JWT was given`);
    userId = v.trim();
  } else {
    throw new CredentialWiringError(`${at}: no user: give --identity-jwt (or identity_jwt_env) or set user_env`);
  }
  const tenant = claims?.tenant_id ?? setting.tenant;
  if (tenant === undefined || tenant === '') {
    throw new CredentialWiringError(`${at}: no tenant: give --identity-jwt (or identity_jwt_env) or set broker.tenant`);
  }
  let tool: { id: string; version: string };
  if (claims !== undefined) tool = { id: claims.tool.id, version: claims.tool.version };
  else if (setting.tool_id !== undefined && setting.tool_version !== undefined) tool = { id: setting.tool_id, version: setting.tool_version };
  else throw new CredentialWiringError(`${at}: no tool: give --identity-jwt (or identity_jwt_env) or set broker.tool_id and tool_version`);

  const credentials: Record<string, UserTokenCredential> = {};
  for (const cred of remote) {
    const varName = cred.synthetic_env ?? syntheticEnvVar(cred.id);
    const synthetic = opts.env[varName] ?? '';
    const sites: UserTokenCredential['sites'] = {};
    for (const use of cred.use) {
      if (use.action !== 'allow') continue;
      sites[use.id] = { action_class: use.action_class, method: use.method };
    }
    credentials[cred.id] = { synthetic, connector: cred.provider ?? '', sites };
  }
  const out: UserTokenConfig = { tenant, userId, tool, runAs: claims?.run_as ?? 'user', credentials };
  if (claims?.kind === 'job' || claims?.run_as === 'owner') {
    // A job token runs as the tool's owner and the control plane requires
    // the token itself on every request (`job_token`, "required when
    // run_as = owner"). Without the raw JWS every call would be a 400
    // (`invalid_request`) reported as a broker_error deny; say so at start.
    if (opts.identityJwt === undefined || opts.identityJwt === '') {
      throw new CredentialWiringError(`${at}: the identity JWT is a job token (kind ${claims.kind}, run_as ${claims.run_as}) but its raw form was not supplied to send as job_token`);
    }
    if (claims.kind !== 'job' || claims.run_as !== 'owner') {
      throw new CredentialWiringError(`${at}: identity JWT has kind ${claims.kind} with run_as ${claims.run_as}; a job token is kind job with run_as owner (identity-jwt.md)`);
    }
    out.runAs = 'owner';
    out.jobToken = opts.identityJwt;
  }
  return out;
}

/**
 * Build the swap for a policy, or `undefined` when there is nothing to build.
 *
 * `undefined` means the proxy behaves exactly as it did before credential
 * brokering existed — that is the property worth protecting, so the bar for
 * returning a swap is high: the policy must declare credentials AND at least
 * one of them must have a synthetic bound in the environment. A policy that
 * declares credentials whose synthetics are all absent is a live
 * misconfiguration; it warns loudly and swaps nothing, because the
 * alternative is a gateway that silently forwards synthetics to an upstream
 * that rejects them and leaves the operator reading tool errors.
 *
 * Throws only on a config the broker itself rejects (an unusable site, a
 * credential with no reachable destination). Gateway mode is the one
 * deliberate exception to fail-open, and a credentials section that cannot
 * be turned into a broker is exactly that case: the caller exits 2 rather
 * than running with enforcement the operator believes is on.
 */
export function credentialSwapFromPolicy(opts: WireOptions): CredentialSwapWiring | undefined {
  const credentials = opts.policy.credentials;
  if (credentials === undefined || credentials.length === 0) return undefined;

  const warn = opts.warn ?? ((): void => undefined);

  // BEFORE anything else, and before the recorder opens: a real credential
  // this policy points at must never be fingerprintable, and session_start
  // fingerprints the environment before any swap could have registered one.
  const refused = registerPolicyEnvSecrets(credentials, opts.env);
  if (refused.length > 0) {
    throw new CredentialWiringError(
      `the brokered-secret exclusion set is full; cannot guarantee ${refused.join(', ')} stays out of the ` +
        'evidence chain. Refusing to start rather than hash a real credential into a chain whose refs are unsalted.',
    );
  }

  const entries: CredentialEntry[] = [];
  const unbound: string[] = [];
  const remote: Credential[] = [];

  for (const cred of credentials) {
    // An explicitly named variable beats the derived one: a policy that says
    // which variable carries its synthetic is self-documenting, and the
    // derived default only has to work for the operator who did not say.
    const varName = cred.synthetic_env ?? syntheticEnvVar(cred.id);
    const raw = opts.env[varName];
    if (raw === undefined || raw === '') {
      unbound.push(cred.id);
      continue;
    }
    if (cred.broker !== undefined) {
      // Resolved by the control plane: no local entry, and the internal
      // token it is called with must be present — an absent token is a
      // misconfiguration said at startup, not a deny on every call.
      const token = opts.env[cred.broker.token_env];
      if (token === undefined || token === '') {
        throw new CredentialWiringError(
          `credential "${cred.id}": $${cred.broker.token_env} (broker.token_env) is not set — the control plane cannot be called`,
        );
      }
      remote.push(cred);
      continue;
    }
    entries.push({
      id: cred.id,
      ...(cred.provider !== undefined ? { provider: cred.provider } : {}),
      ...(cred.scopes !== undefined ? { scopes: [...cred.scopes] } : {}),
      synthetic: raw,
      source: sourceSpecOf(cred),
      sites: cred.use.map((use) => ({
        id: use.id,
        server: [...use.server],
        tool: [...use.tool],
        arg: use.arg,
        host_from: hostBindingOf(use.host),
        ...(use.path.from === 'argument' ? { path_from: { kind: 'argument' as const, arg: use.path.arg } } : {}),
      })),
      allow: allowRulesOf(cred),
      ttl_seconds: cred.ttl_seconds,
    });
  }

  for (const id of unbound) {
    warn(
      `credentials: "${id}" declares swap sites but ${envVarFor(credentials, id)} is not set — ` +
        'nothing will be swapped for it (run `mcp-recorder credentials issue ' +
        `${id}\` and put the value in the agent's environment)`,
    );
  }
  if (entries.length === 0 && remote.length === 0) {
    warn('credentials: no synthetic is bound in this environment — the gateway will swap nothing');
    return undefined;
  }

  const dataPlaneInstanceId = opts.dataPlaneInstanceId ?? randomUUID();
  const local: Broker | undefined =
    entries.length === 0
      ? undefined
      : new LocalBroker({
          credentials: entries,
          pepper: mintPepper(),
          warn,
        });
  let remoteBroker: Broker | undefined;
  if (remote.length > 0) {
    const setting = remoteSettingsOf(remote);
    const userToken = userTokenConfigOf(remote, setting, opts);
    remoteBroker = new RemoteBroker({
      baseUrl: setting.url,
      dataPlaneInstanceId,
      authToken: opts.env[setting.token_env] as string,
      timeoutMs: setting.timeout_ms,
      userToken,
      ...(opts.remoteFetch !== undefined ? { fetch: opts.remoteFetch } : {}),
      warn,
    });
    warn(
      `credentials: ${remote.map((c) => `"${c.id}"`).join(', ')} resolved by the control plane at ${setting.url}` +
        ` (user ${userToken.userId}, tool ${userToken.tool.id}@${userToken.tool.version})`,
    );
  }
  // One broker when only one kind is present, so the local-only path is
  // exactly what it was before remote brokering existed.
  const broker: Broker =
    remoteBroker !== undefined && local !== undefined
      ? new CompositeBroker(local, remoteBroker, remote.map((c) => c.id))
      : remoteBroker !== undefined
        ? new CompositeBroker(undefined, remoteBroker, remote.map((c) => c.id))
        : (local as Broker);
  const swap = new CredentialSwap({
    broker,
    config: normalizeCredentialsConfig({ sites: sitesOf(credentials) }),
    dataPlaneInstanceId,
  });
  return { swap, unbound };
}
