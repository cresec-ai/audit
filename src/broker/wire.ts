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
import type { Credential, CredentialHost, CredentialPath, CredentialSource, Policy } from '../policy/types.js';
import { CredentialSwap, normalizeCredentialsConfig, type CredentialSiteInput } from '../gateway/credentials.js';
import { LocalBroker, type CredentialEntry } from './local.js';
import { registerBrokeredSecret } from '../redact/redactor.js';
import type { CredentialSourceSpec } from './sources.js';
import { mintPepper } from './protocol.js';

/** Raised when a policy expresses something the local broker cannot resolve. */
export class CredentialWiringError extends Error {}


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
  const src: CredentialSource = cred.source;
  const at = `credential "${cred.id}"`;
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
  /** Operator diagnostics; the caller routes these to stderr. */
  warn?: (line: string) => void;
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
  if (entries.length === 0) {
    warn('credentials: no synthetic is bound in this environment — the gateway will swap nothing');
    return undefined;
  }

  const broker = new LocalBroker({
    credentials: entries,
    pepper: mintPepper(),
    warn,
  });
  const swap = new CredentialSwap({
    broker,
    config: normalizeCredentialsConfig({ sites: sitesOf(credentials) }),
    dataPlaneInstanceId: opts.dataPlaneInstanceId ?? randomUUID(),
  });
  return { swap, unbound };
}
