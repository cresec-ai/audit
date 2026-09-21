/**
 * LocalBroker — NHI's exchange, resolved on this machine.
 *
 * It answers the same two JSON objects NHI's `/broker/exchange` answers, in
 * the same order of checks (synthetic -> credential -> policy -> resolve ->
 * decide), and differs only in where each answer comes from: a config array
 * instead of postgres, glob rules instead of OPA, a {@link CredentialSource}
 * instead of OpenBao. Swapping it for {@link RemoteBroker} is a config change
 * because nothing above it knows which one it holds.
 *
 * THE FOUR THINGS THIS FILE IS CAREFUL ABOUT
 *
 * 1. FAIL CLOSED, ALWAYS. Every path that cannot produce an authorised real
 *    credential returns a DENIAL — never the request unmodified, never the
 *    synthetic passed through, never a partial answer. `exchange()` does not
 *    throw: a throw on the forwarding path is an ambiguous outcome, and the
 *    caller would have to decide what an exception means about
 *    authorisation. There is exactly one return shape for "no", and it
 *    carries a code.
 *
 * 2. THE DESTINATION IS PART OF THE DECISION. A rule that constrains only the
 *    tool authorises `http_post` to attacker.example exactly as happily as to
 *    api.github.com, and the agent chooses the argument. So every credential
 *    MUST carry at least one rule with a non-empty `host`, the validator
 *    refuses one that does not, and the decision record says whether that
 *    host came from the CALL's own arguments or was the static server name —
 *    "host was checked" and "host was assumed" must not read alike in a log.
 *    NHI's OPA input carries `host` and `path_template` separately for the
 *    same reason (exchange.ts, step 6).
 *
 * 3. THE CACHE IS KEYED ON THE WHOLE TUPLE. NHI's data plane caches a
 *    positive decision for 30 s and busts it over NATS. A local cache keyed
 *    on the synthetic alone would turn one allow for `github/create_issue`
 *    into 30 s of allow for `github/delete_repo`, so the key is
 *    (synthetic hash, method, host, path_template) and it holds the RESOLVED
 *    VALUE only. The policy is re-evaluated on EVERY call, cache hit or not:
 *    it is a handful of anchored globs, measured at ~1.5 us for a three-rule
 *    credential inside a ~10 us cache-hit exchange (Node 22, this repo's
 *    CI-class hardware), where the rest is one HMAC and one UUID. There is
 *    nothing worth saving by caching a verdict, and a verdict cached under
 *    any key is the same bug wearing a different hat.
 *
 * 4. THE REAL VALUE NEVER BECOMES A REF. Before a resolved credential is
 *    returned it is registered with `registerBrokeredSecret`, so every
 *    fingerprinting surface in the recorder excludes it. Registration is a
 *    precondition of returning, not a step afterwards: if it fails the call
 *    is DENIED (`exclusion_capacity`). The decision record carries the
 *    credential's id, label, provider and scopes and never its value — and
 *    never the synthetic either, because a synthetic is redeemable on this
 *    machine and the id answers every question the value would.
 */

import { Buffer } from 'node:buffer';
import { canonicalJson, sha256Hex } from '../chain/hash.js';
import { globMatch } from '../policy/glob.js';
import { registerBrokeredSecret } from '../redact/redactor.js';
import type {
  Broker,
  BrokerExchangeHint,
  BrokerExchangeRequest,
  BrokerExchangeResponse,
  DenyReason,
} from './protocol.js';
import {
  BROKER_DEFAULT_TTL_SECONDS,
  denyResponse,
  hashSynthetic,
  isSyntheticShaped,
  newDecisionId,
  syntheticHashesEqual,
} from './protocol.js';
import type { CredentialSource, CredentialSourceSpec, SourceSeams } from './sources.js';
import {
  CredentialSourceError,
  SOURCE_DEADLINE_MS,
  defaultSeams,
  makeSource,
  sourceKinds,
} from './sources.js';

/* -------------------------------------------------------------------- */
/* config                                                               */
/* -------------------------------------------------------------------- */

/**
 * Where a swap-site's `host` / `path_template` are taken from.
 *
 * `argument` is the only binding worth having for a generic egress tool: the
 * `url` of an `http_post`, the `repo` of a GitHub tool. `server` is the
 * honest fallback for a stdio server that talks to one fixed upstream — the
 * decision then records `host_binding: "server"` so the chain distinguishes a
 * host that was checked from a host that was the server's name.
 */
export type FieldBinding = { kind: 'argument'; arg: string } | { kind: 'server' } | { kind: 'tool' };

/**
 * A declared swap site: the ONE place a synthetic may be replaced.
 *
 * The swap is destination-bound, never value-bound. Replacing the synthetic
 * "wherever it appears" is defeated by any tool that returns its input — an
 * `echo`, a `create_issue` whose body the agent reads back, a malformed call
 * whose error quotes the offending argument — and the real token comes back
 * in the model's context, which is the one place this design exists to keep
 * it out of. An undeclared site therefore receives the SYNTHETIC and the
 * upstream rejects it, which is the correct outcome and a visible one.
 *
 * This type lives here rather than in the policy so that the broker, which
 * has to authorise a call, and the gateway, which has to perform the swap,
 * agree on one vocabulary — the same dot-paths `McpMatch.args` already uses.
 */
export interface CredentialSwapSite {
  /** Stable id for the decision record; defaults to `<server>/<tool>#<arg>`. */
  id?: string;
  /** Globs on the logical server name, delimiter "/". */
  server: string[];
  /** Globs on the tool name, delimiter "/". */
  tool: string[];
  /** Dot-path under `params.arguments` holding the synthetic. */
  arg: string;
  /** Where `request.host` comes from for a call at this site. */
  host_from: FieldBinding;
  /** Where `request.path_template` comes from. Defaults to the tool name. */
  path_from?: FieldBinding;
}

/** What a credential is allowed to be used FOR. At least one, each with a host. */
export interface CredentialRule {
  /** Globs on `request.method`, delimiter "/". Default: any. */
  method?: string[];
  /** Globs on `request.host`, delimiter ".". REQUIRED and non-empty. */
  host: string[];
  /** Globs on `request.path_template`, delimiter "/". Default: any. */
  path_template?: string[];
}

export interface CredentialEntry {
  /** Stable id recorded on every decision. Not a secret. */
  id: string;
  /** Human label, e.g. "github ci token (issues only)". */
  label?: string;
  /** Provider key, e.g. "github". Recorded so blast radius is answerable. */
  provider?: string;
  /** What the REAL credential can do. Recorded, never enforced by us. */
  scopes?: string[];
  status?: 'active' | 'revoked' | 'disabled';
  /**
   * HMAC-SHA256(synthetic, pepper), hex. This is what a config file should
   * carry: NHI stores the hash and shows the raw value once, and the same
   * argument holds locally — a config full of raw synthetics is a config full
   * of values that are redeemable on this machine.
   */
  synthetic_hash?: string;
  /**
   * The raw synthetic, for the laptop case where nothing has minted one yet.
   * Hashed at construction and dropped; still, prefer `synthetic_hash`.
   */
  synthetic?: string;
  source: CredentialSourceSpec;
  /** Declared swap sites. The gateway may swap at these and nowhere else. */
  sites: CredentialSwapSite[];
  /** Destination constraints. Empty or host-less is a validation error. */
  allow: CredentialRule[];
  /** Cap the TTL below the 30 s default. Never raises it. */
  ttl_seconds?: number;
}

/**
 * The trust the operator has in the files that name all of the above.
 *
 * `configWritableByUs` comes from `assessConfigTrust`. When it is true, an
 * `exec` source is refused — `exec` is arbitrary code execution by
 * configuration, running as the recorder, on every brokered call — unless the
 * operator explicitly opts in for the single-uid laptop case. The hashes are
 * stamped on every decision record so that a mid-session edit is EVIDENT in a
 * tamper-evident chain. Evident, not impossible: anything that can write
 * these files controls the swap, and only an OS boundary or the hosted
 * control plane changes that.
 */
export interface ConfigTrust {
  configWritableByUs: boolean;
  allowExecFromWritableConfig?: boolean;
  /** sha256 of the normalized policy document. */
  policy_hash?: string;
  /** sha256 of the normalized credentials config; computed here when absent. */
  config_hash?: string;
}

/** Local-only context the caller knows and the wire shape has no field for. */
export interface ExchangeContext {
  /** Which declared site produced this call. */
  site_id?: string;
  /** How `request.host` was obtained. Recorded, so an assumption reads as one. */
  host_binding?: 'argument' | 'server';
}

/**
 * What the recorder writes as a `broker.decision` event. Never the real
 * token, never the synthetic — an id and a decision id, per invariant 4.
 */
export interface BrokerDecisionRecord {
  decision_id: string;
  allowed: boolean;
  deny_reason?: DenyReason;
  credential_id?: string;
  credential_label?: string;
  provider?: string;
  scopes?: string[];
  source_kind?: string;
  site_id?: string;
  host_binding: 'argument' | 'server' | 'unknown';
  request: { method: string; host: string; path_template: string };
  cache: 'hit' | 'miss' | 'none';
  ttl_seconds: number;
  policy_hash?: string;
  config_hash?: string;
}

export interface LocalBrokerOptions {
  credentials: CredentialEntry[];
  /** Local pepper for the synthetic HMAC — NHI's per-tenant pepper, locally. */
  pepper: Buffer;
  seams?: SourceSeams;
  /** Source factory override. Tests inject fakes here; nothing else should. */
  makeSource?: (spec: CredentialSourceSpec, seams: SourceSeams) => CredentialSource;
  now?: () => number;
  /** Cap on a positive decision's TTL. Defaults to NHI's 30 s. */
  ttlSeconds?: number;
  configTrust?: ConfigTrust;
  /** Called once per exchange, allow or deny. Must not throw; see `exchange`. */
  onDecision?: (record: BrokerDecisionRecord) => void;
  /** Operator-facing diagnostics. Defaults to stderr. */
  warn?: (line: string) => void;
}

/**
 * How long a source stays unhealthy after it overruns its deadline.
 *
 * The point is not to punish the source, it is that a brokered call sits on
 * the forwarding path: paying a 5 s timeout on every call to a black-holed
 * OpenBao turns one dead dependency into a client that thinks the MCP server
 * has hung. After one overrun the next calls deny at the cost of an ordinary
 * exchange (~8 us, measured) until the window passes, then one call probes
 * again.
 */
export const SOURCE_UNHEALTHY_MS = 30_000;

/**
 * Cap on cached resolutions.
 *
 * The cache key is the full tuple, which is the right key and also an
 * unbounded one: a rule allowing `*.github.com` allows an unbounded number of
 * distinct hosts, and the agent writes the host. Without a cap, a loop of
 * allowed calls to invented subdomains grows a map of live tokens for as long
 * as it runs. 256 is well past any real session's working set (a session uses
 * a handful of destinations) and eviction costs only a re-resolution, never a
 * weaker decision — the policy is re-evaluated on every call regardless.
 */
export const MAX_DECISION_CACHE = 256;

/* -------------------------------------------------------------------- */
/* validation                                                           */
/* -------------------------------------------------------------------- */

/**
 * Problems that make a credential entry unusable. Returned rather than
 * thrown so a policy validator can report every one of them at once.
 *
 * The host rule is the one to read twice: a swap site with no host
 * constraint is a full-privilege credential with extra steps, so it is an
 * ERROR and not a permissive default. "Least privilege" is not claimable
 * from a policy that constrains the tool and leaves the destination to the
 * agent.
 */
export function validateCredentialEntry(entry: CredentialEntry): string[] {
  const problems: string[] = [];
  const at = `credential ${entry.id || '<unnamed>'}`;
  if (!entry.id) problems.push('credential has no id');
  if (entry.synthetic_hash === undefined && entry.synthetic === undefined) {
    problems.push(`${at}: needs synthetic_hash (preferred) or synthetic`);
  }
  if (entry.synthetic_hash !== undefined && !/^[0-9a-f]{64}$/.test(entry.synthetic_hash)) {
    problems.push(`${at}: synthetic_hash must be 64 lowercase hex characters`);
  }
  if (!Array.isArray(entry.sites) || entry.sites.length === 0) {
    problems.push(`${at}: needs at least one swap site`);
  }
  for (const site of entry.sites ?? []) {
    if (!site.arg) problems.push(`${at}: a swap site has no arg dot-path`);
    if (!site.tool || site.tool.length === 0) problems.push(`${at}: swap site ${site.arg} has no tool glob`);
    if (!site.server || site.server.length === 0) {
      problems.push(`${at}: swap site ${site.arg} has no server glob`);
    }
    if (site.host_from === undefined) {
      problems.push(`${at}: swap site ${site.arg} must declare host_from (argument or server)`);
    } else if (site.host_from.kind === 'argument' && !site.host_from.arg) {
      problems.push(`${at}: swap site ${site.arg} has host_from.kind=argument with no arg`);
    }
  }
  if (!Array.isArray(entry.allow) || entry.allow.length === 0) {
    problems.push(`${at}: needs at least one allow rule, each constraining host`);
  }
  for (const rule of entry.allow ?? []) {
    if (!Array.isArray(rule.host) || rule.host.length === 0) {
      problems.push(
        `${at}: an allow rule has no host constraint — a swap site with an unconstrained host is a full-privilege credential`,
      );
    }
    for (const h of rule.host ?? []) {
      if (h === '**' || h === '*') {
        problems.push(`${at}: host "${h}" constrains nothing; name the destinations`);
      }
    }
  }
  return problems;
}

/** Validate a whole credentials map, including duplicate ids and synthetics. */
export function validateCredentials(entries: CredentialEntry[]): string[] {
  const problems: string[] = [];
  const seenIds = new Set<string>();
  const seenHashes = new Set<string>();
  for (const entry of entries) {
    if (entry.id) {
      if (seenIds.has(entry.id)) problems.push(`duplicate credential id ${entry.id}`);
      seenIds.add(entry.id);
    }
    // Two credentials behind one synthetic would make "which credential does
    // this synthetic redeem" a question about array order, and the answer
    // would decide which real secret leaves the machine. Refuse it. (Hashes
    // only: the raw-`synthetic` form is hashed at construction, so the same
    // value written two ways is caught there as the same hash.)
    if (entry.synthetic_hash !== undefined) {
      if (seenHashes.has(entry.synthetic_hash)) {
        problems.push(`two credentials share one synthetic (${entry.id})`);
      }
      seenHashes.add(entry.synthetic_hash);
    }
    problems.push(...validateCredentialEntry(entry));
  }
  return problems;
}

/** sha256 over the canonical JSON of the credentials config, for the chain. */
export function credentialsConfigHash(entries: CredentialEntry[]): string {
  // Canonical JSON so key order in the YAML cannot change the hash, and the
  // raw `synthetic` (when a laptop config carries one) is dropped first: the
  // hash is stamped on events, and a hash whose input includes a redeemable
  // value is a confirmation oracle for that value.
  const stripped = entries.map((e) => {
    const rest: Record<string, unknown> = { ...e };
    delete rest.synthetic;
    return rest;
  });
  return sha256Hex(canonicalJson(stripped));
}

/* -------------------------------------------------------------------- */
/* the broker                                                           */
/* -------------------------------------------------------------------- */

interface PreparedEntry {
  entry: CredentialEntry;
  hash: Buffer;
  source: CredentialSource;
  sourceKind: string;
  /** Set when the entry may never resolve (an exec source under a writable config). */
  blocked?: DenyReason;
}

interface CacheSlot {
  value: string;
  expiresAtMs: number;
}

interface SourceHealth {
  unhealthyUntilMs: number;
}

export class LocalBroker implements Broker {
  readonly #entries: PreparedEntry[];
  readonly #pepper: Buffer;
  readonly #seams: SourceSeams;
  readonly #now: () => number;
  readonly #ttlSeconds: number;
  readonly #trust: ConfigTrust;
  readonly #configHash: string;
  readonly #onDecision?: (record: BrokerDecisionRecord) => void;
  readonly #warn: (line: string) => void;
  readonly #cache = new Map<string, CacheSlot>();
  readonly #health = new Map<string, SourceHealth>();

  constructor(opts: LocalBrokerOptions) {
    const problems = validateCredentials(opts.credentials);
    if (problems.length > 0) {
      // Construction is the last moment a misconfiguration can be loud. A
      // broker built from an invalid config would deny every call at runtime
      // with a code that says nothing about the config being wrong.
      throw new Error(`mcp-recorder: invalid broker credentials:\n  ${problems.join('\n  ')}`);
    }

    this.#pepper = opts.pepper;
    this.#seams = opts.seams ?? defaultSeams();
    this.#now = opts.now ?? (() => Date.now());
    this.#ttlSeconds = opts.ttlSeconds ?? BROKER_DEFAULT_TTL_SECONDS;
    this.#trust = opts.configTrust ?? { configWritableByUs: true };
    this.#configHash = this.#trust.config_hash ?? credentialsConfigHash(opts.credentials);
    this.#onDecision = opts.onDecision;
    this.#warn =
      opts.warn ??
      ((line: string): void => {
        process.stderr.write(`mcp-recorder: ${line}\n`);
      });

    const factory = opts.makeSource ?? makeSource;
    const execRefused =
      this.#trust.configWritableByUs && this.#trust.allowExecFromWritableConfig !== true;

    this.#entries = opts.credentials.map((entry) => {
      const hash =
        entry.synthetic_hash !== undefined
          ? Buffer.from(entry.synthetic_hash, 'hex')
          : hashSynthetic(entry.synthetic as string, opts.pepper);
      const kinds = sourceKinds(entry.source);
      const usesExec = kinds.includes('exec');
      if (usesExec && execRefused) {
        // Refused, not merely warned about: the config that names the command
        // is writable by the uid the agent runs as, so `exec` there is a
        // standing offer of code execution as the recorder. The opt-in exists
        // because the single-user laptop is a real deployment, not because
        // the risk is theoretical.
        this.#warn(
          `broker: credential ${entry.id} uses an exec source while the broker config is writable by this uid — refusing it. ` +
            `Make the config root-owned, or opt in explicitly.`,
        );
      }
      return {
        entry,
        hash,
        source: factory(entry.source, this.#seams),
        sourceKind: entry.source.type,
        ...(usesExec && execRefused ? { blocked: 'source_untrusted_config' as DenyReason } : {}),
      };
    });

    if (this.#trust.configWritableByUs) {
      this.#warn(
        'broker: the policy/broker config is writable by this uid, so credential brokering here is a context and ' +
          'audit control, not a confidentiality one — anything that can write those files aims the credential. ' +
          'Both config hashes are stamped on every decision, so a change is evident in the chain.',
      );
    }
  }

  /**
   * One exchange. Mirrors NHI's handler step for step, and NEVER throws: a
   * throw would leave the caller deciding what an exception means about
   * authorisation, and the answer has to be "no" in one shape only.
   */
  async exchange(
    req: BrokerExchangeRequest,
    // The gateway passes a `BrokerExchangeHint` (which site asked); the
    // local broker resolves by synthetic and reads only its own fields.
    ctx: ExchangeContext & Partial<BrokerExchangeHint> = {},
  ): Promise<BrokerExchangeResponse> {
    const decisionId = newDecisionId();
    try {
      return await this.#exchange(req, ctx, decisionId);
    } catch (err) {
      // Nothing below is expected to throw; this is the backstop that keeps
      // invariant 1 true whatever happens inside it.
      this.#warn(`broker: exchange failed: ${err instanceof Error ? err.message : String(err)}`);
      this.#emit({
        decision_id: decisionId,
        allowed: false,
        deny_reason: 'broker_error',
        host_binding: ctx.host_binding ?? 'unknown',
        request: summarize(req),
        cache: 'none',
        ttl_seconds: 0,
        ...(ctx.site_id !== undefined ? { site_id: ctx.site_id } : {}),
        ...this.#hashes(),
      });
      return denyResponse(decisionId, 'broker_error');
    }
  }

  async #exchange(
    req: BrokerExchangeRequest,
    ctx: ExchangeContext,
    decisionId: string,
  ): Promise<BrokerExchangeResponse> {
    const request = summarize(req);
    const hostBinding = ctx.host_binding ?? 'unknown';
    const deny = (
      reason: DenyReason,
      prepared?: PreparedEntry,
      cache: 'hit' | 'miss' | 'none' = 'none',
    ): BrokerExchangeResponse => {
      this.#emit({
        decision_id: decisionId,
        allowed: false,
        deny_reason: reason,
        host_binding: hostBinding,
        request,
        cache,
        ttl_seconds: 0,
        ...(ctx.site_id !== undefined ? { site_id: ctx.site_id } : {}),
        ...(prepared !== undefined ? describe(prepared) : {}),
        ...this.#hashes(),
      });
      return denyResponse(decisionId, reason);
    };

    // 1. Resolve the synthetic. Shape and membership answer the same code:
    //    a distinct "malformed" reason is a free hint towards a valid one.
    if (typeof req.synthetic !== 'string' || !isSyntheticShaped(req.synthetic)) {
      return deny('unknown_synthetic');
    }
    const incoming = hashSynthetic(req.synthetic, this.#pepper);
    let prepared: PreparedEntry | undefined;
    for (const candidate of this.#entries) {
      // No early exit: every entry is compared, and each comparison is
      // constant-time (NHI's `syntheticHashesEqual`). The number of entries
      // is in the operator's config and is not a secret; the values are.
      if (syntheticHashesEqual(candidate.hash, incoming)) prepared = candidate;
    }
    if (prepared === undefined) return deny('unknown_synthetic');

    const entry = prepared.entry;
    const status = entry.status ?? 'active';
    if (status === 'revoked') return deny('synthetic_revoked', prepared);
    if (status !== 'active') return deny('synthetic_disabled', prepared);
    if (prepared.blocked !== undefined) return deny(prepared.blocked, prepared);

    // 2. Authorise the DESTINATION, not just the tool. Re-evaluated on every
    //    call, cache hit included — see the header, point 3.
    const verdict = matchRules(entry.allow, request);
    if (verdict !== undefined) return deny(verdict, prepared);

    // 3. Resolve — from the tuple-keyed cache, or from the source under a
    //    deadline. Anything unresolvable DENIES; nothing here can fall
    //    through to "forward anyway".
    const cacheKey = tupleKey(prepared.hash, request);
    const nowMs = this.#now();
    const slot = this.#cache.get(cacheKey);
    let value: string;
    let expiresAtMs: number;
    let cache: 'hit' | 'miss';
    if (slot !== undefined && slot.expiresAtMs > nowMs) {
      value = slot.value;
      expiresAtMs = slot.expiresAtMs;
      cache = 'hit';
    } else {
      cache = 'miss';
      const health = this.#health.get(entry.id);
      if (health !== undefined && health.unhealthyUntilMs > nowMs) {
        // Deny at once rather than pay the timeout again. The client sees a
        // refusal in microseconds instead of a server that looks hung.
        return deny('source_unhealthy', prepared, cache);
      }
      let resolved: { value: string; expiresAtMs?: number };
      try {
        resolved = await this.#resolve(prepared);
      } catch (err) {
        const code = err instanceof CredentialSourceError ? err.code : 'source_unavailable';
        const detail = err instanceof CredentialSourceError ? err.detail : errText(err);
        this.#warn(`broker: credential ${entry.id} did not resolve (${code}): ${detail ?? 'no detail'}`);
        if (code === 'source_timeout') {
          this.#health.set(entry.id, { unhealthyUntilMs: nowMs + SOURCE_UNHEALTHY_MS });
        }
        return deny(code, prepared, cache);
      }
      if (resolved.value === '') return deny('source_empty', prepared, cache);

      // The value becomes un-fingerprintable BEFORE it can be returned. A
      // failure here is a denial, never a hand-over: see header point 4.
      if (!registerBrokeredSecret(resolved.value)) {
        this.#warn(`broker: brokered-secret exclusion set is full; refusing to hand out ${entry.id}`);
        return deny('exclusion_capacity', prepared, cache);
      }

      const ttlCapSeconds = Math.min(this.#ttlSeconds, entry.ttl_seconds ?? this.#ttlSeconds);
      expiresAtMs = nowMs + ttlCapSeconds * 1000;
      if (resolved.expiresAtMs !== undefined && resolved.expiresAtMs < expiresAtMs) {
        // The provider's own expiry wins when it is sooner: an STS session of
        // 900 s is not the bound here, but a 5-second-old one is.
        expiresAtMs = resolved.expiresAtMs;
      }
      value = resolved.value;
      this.#health.delete(entry.id);
      this.#remember(cacheKey, { value, expiresAtMs }, nowMs);
    }

    const ttlSeconds = Math.max(0, Math.floor((expiresAtMs - nowMs) / 1000));
    if (ttlSeconds === 0) {
      // Expired between the cap and here (a provider expiry in the past, or a
      // clock jump). Fail closed rather than hand out a token with no life.
      this.#cache.delete(cacheKey);
      return deny('source_unavailable', prepared, cache);
    }

    this.#emit({
      decision_id: decisionId,
      allowed: true,
      host_binding: hostBinding,
      request,
      cache,
      ttl_seconds: ttlSeconds,
      ...(ctx.site_id !== undefined ? { site_id: ctx.site_id } : {}),
      ...describe(prepared),
      ...this.#hashes(),
    });
    return { real_token: value, ttl_seconds: ttlSeconds, decision_id: decisionId };
  }

  /**
   * Every declared swap site, so the gateway can bind the swap to a site.
   *
   * Copies, not references: these objects decide where a credential may be
   * substituted, and a caller that mutated one would be editing the policy at
   * runtime without touching the config the decision records hash.
   */
  sites(): Array<{ credential_id: string; site: CredentialSwapSite }> {
    return this.#entries.flatMap((p) =>
      p.entry.sites.map((site) => ({
        credential_id: p.entry.id,
        site: structuredClone(site),
      })),
    );
  }

  /** Drop every cached resolution — a rotation, a revocation, or a test. */
  invalidate(): void {
    this.#cache.clear();
  }

  /* ----------------------------- internals ---------------------------- */

  /**
   * Resolve under a hard deadline.
   *
   * The precedent is `match.args` regexes, which run on a worker thread with
   * a 25 ms deadline because the proxy is single-threaded and a hostile
   * pattern would freeze all traffic. A source cannot be moved off the thread
   * — it IS I/O — but the same rule applies to the outcome: overrunning the
   * budget denies THIS call and marks the source unhealthy, it never waits
   * indefinitely and it never falls through to an allow.
   */
  async #resolve(prepared: PreparedEntry): Promise<{ value: string; expiresAtMs?: number }> {
    const kind = prepared.entry.source.type;
    const deadlineMs = SOURCE_DEADLINE_MS[kind];
    let timer: NodeJS.Timeout | undefined;
    try {
      return await Promise.race([
        prepared.source.resolve(),
        new Promise<never>((_resolve, reject) => {
          timer = setTimeout(
            () => reject(new CredentialSourceError('source_timeout', `${kind} exceeded ${String(deadlineMs)}ms`)),
            deadlineMs,
          );
          timer.unref?.();
        }),
      ]);
    } finally {
      if (timer !== undefined) clearTimeout(timer);
    }
  }

  /**
   * Cache a resolution, dropping what has expired and then the oldest entry
   * if the map is still at its cap. `Map` iteration is insertion order, so
   * "oldest" here is oldest-inserted rather than least-recently-used — the
   * difference does not matter for a map whose entries all expire within
   * `BROKER_DEFAULT_TTL_SECONDS` anyway.
   */
  #remember(key: string, slot: CacheSlot, nowMs: number): void {
    if (this.#cache.size >= MAX_DECISION_CACHE) {
      for (const [k, v] of this.#cache) {
        if (v.expiresAtMs <= nowMs) this.#cache.delete(k);
      }
      while (this.#cache.size >= MAX_DECISION_CACHE) {
        const oldest = this.#cache.keys().next();
        if (oldest.done) break;
        this.#cache.delete(oldest.value);
      }
    }
    this.#cache.set(key, slot);
  }

  #hashes(): { policy_hash?: string; config_hash?: string } {
    return {
      ...(this.#trust.policy_hash !== undefined ? { policy_hash: this.#trust.policy_hash } : {}),
      config_hash: this.#configHash,
    };
  }

  /** Recording is fail-OPEN: a sink that throws must not turn into a deny. */
  #emit(record: BrokerDecisionRecord): void {
    if (this.#onDecision === undefined) return;
    try {
      this.#onDecision(record);
    } catch (err) {
      this.#warn(`broker: decision sink threw: ${err instanceof Error ? err.message : String(err)}`);
    }
  }
}

/* -------------------------------------------------------------------- */
/* helpers                                                              */
/* -------------------------------------------------------------------- */

function summarize(req: BrokerExchangeRequest): {
  method: string;
  host: string;
  path_template: string;
} {
  const r = req.request ?? { method: '', host: '', path_template: '' };
  return {
    method: typeof r.method === 'string' ? r.method : '',
    host: typeof r.host === 'string' ? r.host : '',
    path_template: typeof r.path_template === 'string' ? r.path_template : '',
  };
}

function describe(prepared: PreparedEntry): Partial<BrokerDecisionRecord> {
  const e = prepared.entry;
  return {
    credential_id: e.id,
    ...(e.label !== undefined ? { credential_label: e.label } : {}),
    ...(e.provider !== undefined ? { provider: e.provider } : {}),
    ...(e.scopes !== undefined ? { scopes: e.scopes } : {}),
    source_kind: prepared.sourceKind,
  };
}

/**
 * First rule that matches wins, as everywhere else in this codebase; nothing
 * matching is a deny. Returns the deny CODE, or undefined when allowed.
 *
 * The code names the field that failed on the LAST rule tried, which is the
 * one an operator wants when a single rule is the obvious intended one. Globs
 * come from `policy/glob.ts` — the same matcher the engine and the emitted
 * Rego share, so a credential rule cannot read a glob differently from the
 * rule that allowed the tool call in the first place.
 */
export function matchRules(
  rules: CredentialRule[],
  request: { method: string; host: string; path_template: string },
): DenyReason | undefined {
  let last: DenyReason = 'denied_by_policy';
  for (const rule of rules) {
    if (!Array.isArray(rule.host) || rule.host.length === 0) {
      // Defence in depth: the validator refuses this at load, so reaching it
      // means a caller built rules by hand. It denies, it does not default.
      last = 'no_host_constraint';
      continue;
    }
    if (rule.method !== undefined && rule.method.length > 0) {
      if (!rule.method.some((g) => globMatch(g, '/', request.method))) {
        last = 'method_not_permitted';
        continue;
      }
    }
    if (!rule.host.some((g) => globMatch(g, '.', request.host))) {
      last = 'host_not_permitted';
      continue;
    }
    if (rule.path_template !== undefined && rule.path_template.length > 0) {
      if (!rule.path_template.some((g) => globMatch(g, '/', request.path_template))) {
        last = 'path_not_permitted';
        continue;
      }
    }
    return undefined;
  }
  return last;
}

/**
 * The cache key: the full tuple, never the synthetic alone.
 *
 * Built from the synthetic's HASH rather than its value so the key material
 * in memory is not itself redeemable, and joined with NUL so a host of
 * "a\0b" cannot impersonate a different tuple.
 */
function tupleKey(
  hash: Buffer,
  request: { method: string; host: string; path_template: string },
): string {
  return [hash.toString('hex'), request.method, request.host, request.path_template].join('\u0000');
}

function errText(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}
