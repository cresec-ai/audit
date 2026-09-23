/**
 * Credential swap — the gateway half of the broker path.
 *
 * WHAT THIS IS. A declared site in the policy's `credentials` section says
 * "the argument at this dot-path, of this tool, on this server, holds a
 * synthetic placeholder". On an outbound `tools/call` the gateway exchanges
 * that placeholder for a real token at `broker.exchange()` — NHI's
 * `/broker/exchange` wire shape, byte for byte (see
 * apps/api/src/routes/broker.ts in cresec-ai/nhi) — and splices the real
 * token into the outbound bytes. On the way back it replaces any occurrence
 * of that token with the synthetic again, before the client sees it.
 *
 * WHAT IT BUYS, STATED HONESTLY. The real credential is absent from the
 * model's context and from the transcript, and every use of it is a recorded,
 * policy-checked decision carrying a decision id that can be revoked. It is
 * NOT hidden from anything that can run code as the same OS user: on a
 * single-uid developer machine the agent can read the broker config and the
 * source it names (an env var, a file, an `exec`), so the swap is a context
 * and audit control there, and a confidentiality control only when the
 * resolver runs as a principal the agent is not. Nothing in this file should
 * be read as claiming otherwise.
 *
 * THE SWAP IS DESTINATION-BOUND, NEVER VALUE-BOUND. It fires at declared
 * (server, tool, dot-path) sites and nowhere else — NOT wherever the
 * synthetic string happens to appear. That is the control that stops the
 * obvious attack on a value-bound swap: ask a tool to hand the argument
 * back (`http_post(body=<synthetic>)`, an echo tool, an error message that
 * quotes the offending argument) and read the real token out of the result.
 * An echo tool is not a declared site, so it receives the synthetic and the
 * upstream rejects it. {@link TokenScrubber} is the seatbelt for the case
 * where a DECLARED site's server reflects the token anyway; it is defeated
 * by any encoding transform (base64, splitting the value across two fields,
 * one character per line), which is why destination binding is the control
 * and the scrub is not.
 *
 * AND THE DESTINATION IS PART OF THE DECISION. `request.host` /
 * `request.path_template` are derived from the CALL's own arguments (the
 * `url` argument of a generic egress tool), not from the static server
 * identity, because authorising `http_post` without authorising where it
 * posts to authorises `http_post` to attacker.example just as happily as to
 * api.github.com. A site must declare `allow_host`; one that does not is a
 * configuration error, refused at load (see {@link normalizeCredentialsConfig}).
 * Where the upstream genuinely is fixed (a stdio server that talks to one
 * place) a site may say `host_from: server`, and the decision then records
 * `host_source: server_name` so the chain distinguishes "the host was
 * checked" from "the host was the server's name".
 *
 * WHAT NEVER HAPPENS HERE. The resolved token is never hashed, never
 * fingerprinted, never logged and never put in a diagnostic: refs are
 * unsalted sha256 by design (`Redactor.hashString`), so a ref of a real
 * token is a brute-forceable copy of it — the same reasoning as
 * `isRecorderOwnEnvVar` in ../redact/redactor.ts, one layer down. Deny
 * reasons are CODES only, exactly as NHI's exchange.ts returns them
 * (`unknown_synthetic`, `vault_missing_token`), never the underlying error
 * text, a command line or a response body. What IS recorded is which
 * credential was used (its label) and under which `decision_id`.
 */

import { SYNTHETIC_PREFIX, type Broker, type BrokerExchangeRequest } from '../broker/index.js';
import { dotPathSegments, getPath } from '../policy/engine.js';
import { globMatch } from '../policy/glob.js';
import { structuralString } from '../redact/redactor.js';
import type { Attributes } from '../schema/events.js';

/* -------------------------------------------------------------------- */
/* Constants                                                              */
/* -------------------------------------------------------------------- */

/**
 * How long ONE `broker.exchange()` may take before the gateway gives up and
 * denies the call.
 *
 * 5 s, the same bound NHI's own client carries (`packages/brokerclient`'s
 * default `&http.Client{Timeout: 5 * time.Second}`), so a local resolver and
 * the hosted control plane behave alike from the proxy's side. The deadline
 * exists because enforcement is fail-closed AND on the forwarding path: an
 * `exec` source that hangs or a dead OpenBao would otherwise stall the
 * thread the client is waiting on, and the client would see a hung MCP
 * server instead of a refusal. Expiry denies; it never forwards.
 */
export const BROKER_EXCHANGE_DEADLINE_MS = 5_000;

/**
 * Most credential swaps the gateway will have in flight at once. Beyond this
 * a swap is refused (fail-closed), the way `MAX_HOLDS` bounds parked holds:
 * each in-flight swap pins a request id and a timer, and a client that opens
 * them faster than the broker answers must not be able to grow either
 * without limit.
 */
export const MAX_INFLIGHT_SWAPS = 64;

/** Most resolved tokens held for the reverse scrub at once. */
export const MAX_LIVE_TOKENS = 32;

/**
 * Floor on how long a resolved token stays in the scrub table after the
 * exchange that produced it.
 *
 * 30 s, matching `BROKER_DEFAULT_TTL_SECONDS` in NHI's exchange.ts — the TTL
 * its data plane caches a positive decision for. The scrub must outlive the
 * call that used the token (a slow tool answers late, and a server can echo
 * the value in a later notification), and the token is redeemable upstream
 * for at least its own TTL anyway, so this window costs nothing that the
 * credential's own validity has not already granted. It is still residency:
 * the value sits in this process's heap for the window, and JS strings
 * cannot be reliably zeroed, so the claim is SHORT residency, not erasure.
 */
export const SCRUB_MIN_RETENTION_MS = 30_000;

/** Ceiling on the same window, so a broker returning a huge TTL cannot pin a token for the session. */
export const SCRUB_MAX_RETENTION_MS = 300_000;

/**
 * Deny codes this module decides for itself. Everything else comes back from
 * the broker in `deny_reason` and is passed through, shape-checked (see
 * {@link sanitizeDenyCode}) so a remote broker cannot write prose into the
 * text an agent reads.
 */
export const SWAP_DENY = {
  /** The exchange did not answer inside {@link BROKER_EXCHANGE_DEADLINE_MS}. */
  timeout: 'broker_timeout',
  /** `exchange()` threw or answered with a shape that is not the contract. */
  unavailable: 'broker_unavailable',
  /** 200 without a `real_token`: nothing to swap in, so nothing is forwarded. */
  noToken: 'broker_no_token',
  /** The site derives the destination from an argument, and that argument is missing or not a URL/host. */
  hostUnderivable: 'host_underivable',
  /** The derived host is not in the site's `allow_host`. */
  hostNotAllowed: 'host_not_allowed',
  /** The derived path is not in the site's `allow_path`. */
  pathNotAllowed: 'path_not_allowed',
  /** Two placeholders in one argument: no issuance produces that, so it is refused rather than guessed at. */
  multiplePlaceholders: 'multiple_placeholders',
  /**
   * A declared site matched the call, its argument did not resolve to a
   * string, and a synthetic is sitting somewhere else in the arguments.
   *
   * Dogfood 7 found this the hard way. Claude Code sent `headers` as a JSON
   * STRING rather than a nested object (the fixture's schema left the
   * property untyped), so `headers.Authorization` resolved to nothing, the
   * site was not engaged, and the call was forwarded AS WRITTEN — synthetic
   * and all — with no swap, no deny and no log line. The operator believed
   * brokering was on; the placeholder went to the upstream. That is dogfood
   * 4's failure shape (a control that does nothing, with no symptom) inside
   * the broker, and it is why this code exists.
   */
  siteArgUnresolved: 'site_arg_unresolved',
  /** A declared site was hit by a batch element; a batch has no place to park the async exchange. */
  inBatch: 'swap_in_batch',
  /** A declared site was hit by a `tools/call` NOTIFICATION; nothing can be answered on it. */
  onNotification: 'swap_on_notification',
  /** {@link MAX_INFLIGHT_SWAPS} already in flight. */
  tooMany: 'too_many_swaps',
  /** The session ended while the exchange was in flight. */
  sessionEnd: 'session_end',
} as const;

/**
 * Deny codes that mean the gateway could not LEARN a decision, as opposed to
 * a decision having been taken. They pick `FAIL_CLOSED_REFUSAL_GUIDANCE`
 * over `POLICY_REFUSAL_GUIDANCE` in the text the model reads: telling an
 * agent "the operator refused this" when in truth OpenBao was unreachable
 * inverts what happened, and the retry that is often the right fix is only
 * permitted by the fail-closed clause. `vault_missing_token` is NHI's own
 * code for the same class and is listed for that reason.
 */
const RESOLUTION_FAILURE_CODES: ReadonlySet<string> = new Set([
  // The control plane could not be asked, or could not produce the token
  // it decided to give (user-token.md, 503). C1 (cresec-ai/nhi
  // docs/decisions.md, invariant 8; recorded in
  // https://github.com/cresec-ai/nhi/pull/10, not yet merged) makes that a
  // fail-closed refusal with no cached fallback. Nobody decided "no": the refusal must read as
  // retryable, not as the operator's policy.
  'control_plane_unavailable',
  'vault_unavailable',
  'connector_unavailable',
  'broker_unreachable',
  SWAP_DENY.timeout,
  SWAP_DENY.unavailable,
  SWAP_DENY.noToken,
  SWAP_DENY.multiplePlaceholders,
  SWAP_DENY.siteArgUnresolved,
  SWAP_DENY.inBatch,
  SWAP_DENY.onNotification,
  SWAP_DENY.tooMany,
  SWAP_DENY.sessionEnd,
  'vault_missing_token',
  'source_unavailable',
  'source_timeout',
  'resolve_failed',
]);

/** A deny code shape: lower-case identifier, so nothing a broker returns becomes prose in the model's context. */
const DENY_CODE_SHAPE = /^[a-z][a-z0-9_]{0,63}$/;

/** Bare host (with optional port) for a site whose destination argument is not a full URL. */
const BARE_HOST = /^[A-Za-z0-9._-]{1,253}(?::[0-9]{1,5})?$/;

/**
 * The synthetic as it appears inside an argument. NHI mints
 * `cresec_synth_v1_<base64url(32 bytes)>` (43 characters of payload); the
 * bound here is generous on both sides so a future issuance format does not
 * silently stop being recognised — the swap is bound to the declared SITE,
 * not to this pattern, so the pattern only has to find the token inside a
 * leaf like `"Bearer cresec_synth_v1_..."`.
 */
function syntheticPattern(): RegExp {
  const prefix = SYNTHETIC_PREFIX.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return new RegExp(prefix + '[A-Za-z0-9_-]{8,256}', 'g');
}

/* -------------------------------------------------------------------- */
/* Config                                                                 */
/* -------------------------------------------------------------------- */

/** A glob or a non-empty list of globs, as the policy author writes it. */
export type GlobOrList = string | string[];

/** Where a site's destination comes from. `server` = the MCP server's own name. */
/**
 * Where the destination comes from. `fixed` exists because a policy may
 * declare the host outright (`host: { fixed: api.stripe.com }`) for a server
 * whose upstream is not named in any argument — without it such a site has no
 * expressible destination, and a site with no destination constraint is the
 * failure the red team named: authorising a tool without authorising where it
 * points.
 */
export type HostFrom = 'arg' | 'server' | 'fixed';

/** One declared swap site, as authored. */
export interface CredentialSiteInput {
  id?: string;
  /**
   * The credential's LABEL in the broker config. Never a source, a path or a
   * command: the config names where a secret lives, the policy names only
   * which one, and a CALL names neither.
   */
  credential: string;
  server?: GlobOrList;
  tool: GlobOrList;
  /** Dot-path of the argument holding the synthetic, in `McpMatch.args` vocabulary. */
  arg: string;
  /** Default `arg`: derive the destination from a call argument. */
  host_from?: HostFrom;
  /** Dot-path of the argument the host (and by default the path) is derived from. */
  host_arg?: string;
  /** The destination itself, when `host_from` is "fixed". */
  host_fixed?: string;
  /** Dot-path of the argument the path template is derived from, when it is not `host_arg`. */
  path_arg?: string;
  /** REQUIRED. Globs on the derived host, `.` delimiter — the destination constraint. */
  allow_host: GlobOrList;
  /** Globs on the derived path template, `/` delimiter. Absent = any path. */
  allow_path?: GlobOrList;
}

export interface CredentialsConfigInput {
  sites: CredentialSiteInput[];
  /**
   * sha256 of the normalized policy and broker config, stamped on every
   * decision so a mid-session edit of either is EVIDENT in the chain. It
   * cannot be prevented on a machine where the agent's uid can write those
   * files; the chain is tamper-evident, which is the property to lean on.
   */
  config_hash?: string;
}

/** Normalized site: every default filled in, every glob a list. */
export interface CredentialSite {
  id: string;
  credential: string;
  server: string[];
  tool: string[];
  arg: string;
  argSegments: (string | number)[];
  hostFrom: HostFrom;
  /** Set only when `hostFrom` is "fixed". */
  hostFixed?: string;
  hostArg?: string;
  pathArg?: string;
  allowHost: string[];
  allowPath?: string[];
}

export interface CredentialsConfig {
  sites: CredentialSite[];
  config_hash?: string;
}

export class CredentialsConfigError extends Error {}

function toList(v: GlobOrList): string[] {
  return typeof v === 'string' ? [v] : [...v];
}

function nonEmptyGlobs(v: GlobOrList | undefined, what: string, siteId: string): string[] {
  const list = v === undefined ? [] : toList(v);
  if (list.length === 0 || list.some((g) => typeof g !== 'string' || g === '')) {
    throw new CredentialsConfigError(`credentials site "${siteId}": ${what} must be a non-empty glob or list of globs`);
  }
  return list;
}

/**
 * Validate and normalize the `credentials` section.
 *
 * Throws rather than degrading: a site the gateway cannot read exactly is a
 * site that would otherwise swap a real credential somewhere nobody meant,
 * and enforcement fails closed. The two refusals worth naming:
 *
 *  - **no `allow_host`** — a swap site with an unconstrained destination is
 *    a full-privilege credential with extra steps: the policy would authorise
 *    the TOOL and leave the agent to choose where it points. It is a
 *    configuration error, not a default-allow.
 *  - **`host_from: arg` with no `host_arg`** — same hole, reached by leaving
 *    the derivation unsaid.
 */
export function normalizeCredentialsConfig(input: CredentialsConfigInput): CredentialsConfig {
  const sites: CredentialSite[] = (input.sites ?? []).map((raw, index) => {
    const id = raw.id ?? `credential[${index}]`;
    if (typeof raw.credential !== 'string' || raw.credential === '') {
      throw new CredentialsConfigError(`credentials site "${id}": credential (the label in the broker config) is required`);
    }
    if (typeof raw.arg !== 'string' || raw.arg === '') {
      throw new CredentialsConfigError(`credentials site "${id}": arg (the dot-path holding the synthetic) is required`);
    }
    const hostFrom: HostFrom = raw.host_from ?? 'arg';
    if (hostFrom !== 'arg' && hostFrom !== 'server' && hostFrom !== 'fixed') {
      throw new CredentialsConfigError(`credentials site "${id}": host_from must be "arg", "server" or "fixed"`);
    }
    if (hostFrom === 'fixed' && (typeof raw.host_fixed !== 'string' || raw.host_fixed === '')) {
      throw new CredentialsConfigError(`credentials site "${id}": host_fixed is required when host_from is "fixed"`);
    }
    if (hostFrom === 'arg' && (typeof raw.host_arg !== 'string' || raw.host_arg === '')) {
      throw new CredentialsConfigError(
        `credentials site "${id}": host_arg is required unless host_from is "server"` +
          ' — the destination must come from the call, or be declared fixed',
      );
    }
    const site: CredentialSite = {
      id,
      credential: raw.credential,
      server: nonEmptyGlobs(raw.server ?? '*', 'server', id),
      tool: nonEmptyGlobs(raw.tool, 'tool', id),
      arg: raw.arg,
      argSegments: dotPathSegments(raw.arg),
      hostFrom,
      allowHost: nonEmptyGlobs(raw.allow_host, 'allow_host', id),
    };
    if (raw.host_arg !== undefined) site.hostArg = raw.host_arg;
    if (raw.host_fixed !== undefined) site.hostFixed = raw.host_fixed;
    if (raw.path_arg !== undefined) site.pathArg = raw.path_arg;
    if (raw.allow_path !== undefined) site.allowPath = nonEmptyGlobs(raw.allow_path, 'allow_path', id);
    return site;
  });
  const out: CredentialsConfig = { sites };
  if (input.config_hash !== undefined) out.config_hash = input.config_hash;
  return out;
}

/* -------------------------------------------------------------------- */
/* Planning (synchronous, pure)                                           */
/* -------------------------------------------------------------------- */

/** One swap the gateway intends to perform, decided from the parsed message alone. */
export interface PlannedSwap {
  site: CredentialSite;
  /** Path from the MESSAGE root to the leaf, e.g. ['params','arguments','headers','Authorization']. */
  path: (string | number)[];
  /** The leaf exactly as the client wrote it. */
  leaf: string;
  /** The synthetic token inside that leaf. */
  synthetic: string;
  host: string;
  hostSource: 'argument' | 'server_name' | 'declared';
  pathTemplate: string;
  /** Set when the destination already fails the site's own constraint: a deny decided before any exchange. */
  refusal?: string;
}

export interface PlanInput {
  server: string;
  tool: string;
  /** `params.arguments` of the parsed request — the SAME object the policy was evaluated against. */
  args: unknown;
}

/**
 * A plan entry that refuses before any exchange, for a caller that could not
 * plan at all. It exists so the "we could not work out what to do" path lands
 * in the same deny the rest of the module produces, rather than in a throw
 * somebody has to remember to catch.
 */
export function unplannableSwap(code: string): PlannedSwap {
  return {
    site: {
      id: 'unplannable',
      credential: '',
      server: [],
      tool: [],
      arg: '',
      argSegments: [],
      hostFrom: 'server',
      allowHost: [],
    },
    path: [],
    leaf: '',
    synthetic: '',
    host: '',
    hostSource: 'server_name',
    pathTemplate: '',
    refusal: code,
  };
}

/** Derive host and path template from one argument value. */
function deriveDestination(value: unknown): { host: string; pathTemplate: string } | undefined {
  if (typeof value !== 'string' || value === '') return undefined;
  try {
    const url = new URL(value);
    // `url.host` keeps a non-default port (api.example:8443) and drops the
    // default one, which is what an author writing allow_host expects to
    // match. Hostnames are case-insensitive and globs here are not, so the
    // comparison is done on the lower-cased form.
    return { host: url.host.toLowerCase(), pathTemplate: url.pathname || '/' };
  } catch {
    /* not a URL: fall through to the bare-host reading */
  }
  if (BARE_HOST.test(value)) return { host: value.toLowerCase(), pathTemplate: '/' };
  return undefined;
}

function siteMatches(site: CredentialSite, input: PlanInput): boolean {
  if (!site.server.some((g) => globMatch(g, '/', input.server))) return false;
  return site.tool.some((g) => globMatch(g, '/', input.tool));
}

/**
 * Is there a synthetic ANYWHERE in these arguments?
 *
 * Only ever asked about a call whose declared site failed to resolve, to tell
 * two very different things apart: a call that simply carries no credential
 * (ordinary traffic; forward it) and a call that carries one the gateway
 * could not reach (the silent no-op; refuse it). Serialising the arguments is
 * acceptable here because it happens on a path that is already about to
 * refuse or forward a single call, never on every call.
 */
function argsCarryASynthetic(args: unknown): boolean {
  if (args === undefined || args === null) return false;
  try {
    return JSON.stringify(args)?.includes(SYNTHETIC_PREFIX) === true;
  } catch {
    // Circular or otherwise unserialisable: assume the worst, because the
    // question is only asked when a declared site already failed to resolve.
    return true;
  }
}

/**
 * The swaps a call asks for: one per declared site whose argument actually
 * carries a synthetic. A site that matches the tool but whose argument holds
 * something else is simply not engaged — the call is ordinary traffic and is
 * forwarded as written.
 *
 * Everything here reads the ONE parsed object the policy was evaluated
 * against. Deriving the destination from a re-parse, or finding the
 * placeholder by searching the raw line, is how the two halves end up acting
 * on different things — `spliceRewrittenLine` in ../proxy/stdio.ts exists
 * because this codebase already learned that lesson once.
 */
export function planSwaps(config: CredentialsConfig, input: PlanInput): PlannedSwap[] {
  const out: PlannedSwap[] = [];
  for (const site of config.sites) {
    if (!siteMatches(site, input)) continue;
    const leaf = getPath(input.args, site.arg);
    if (typeof leaf !== 'string') {
      // The site matched this tool, so the operator declared that this call
      // carries a credential at this path — and it does not. If a synthetic
      // is elsewhere in the arguments, the placeholder is about to be
      // forwarded to the upstream while the operator believes it was
      // swapped. Refuse instead: the call would have failed at the upstream
      // anyway, and a refusal is the only version of that with a symptom.
      if (argsCarryASynthetic(input.args)) {
        out.push({
          site,
          path: ['params', 'arguments', ...site.argSegments],
          leaf: '',
          synthetic: '',
          host: '',
          hostSource:
            site.hostFrom === 'server' ? 'server_name' : site.hostFrom === 'fixed' ? 'declared' : 'argument',
          pathTemplate: '',
          refusal: SWAP_DENY.siteArgUnresolved,
        });
      }
      continue;
    }
    const found = leaf.match(syntheticPattern());
    if (found === null || found.length === 0) continue;
    // Exactly one placeholder per site, and it must be the whole leaf or a
    // substring of it (`"Bearer <synthetic>"`). Two in one leaf is not a
    // shape any issuance produces, so it is refused rather than guessed at.
    const synthetic = found[0] as string;
    const planned: PlannedSwap = {
      site,
      path: ['params', 'arguments', ...site.argSegments],
      leaf,
      synthetic,
      host: '',
      hostSource:
        site.hostFrom === 'server' ? 'server_name' : site.hostFrom === 'fixed' ? 'declared' : 'argument',
      pathTemplate: '',
    };
    if (found.length > 1) {
      planned.refusal = SWAP_DENY.multiplePlaceholders;
    }
    if (site.hostFrom === 'server') {
      planned.host = input.server.toLowerCase();
      planned.pathTemplate = input.tool;
    } else if (site.hostFrom === 'fixed') {
      // Declared by the operator, so nothing about the call can move it. The
      // allow_host check below still runs: it is the same list, so it passes,
      // and leaving it in means there is exactly one place a destination is
      // approved rather than two code paths to keep in agreement.
      planned.host = (site.hostFixed as string).toLowerCase();
      planned.pathTemplate = site.pathArg === undefined ? input.tool : '';
      if (site.pathArg !== undefined) {
        planned.pathTemplate = deriveDestination(getPath(input.args, site.pathArg))?.pathTemplate ?? '';
      }
    } else {
      const derived = deriveDestination(getPath(input.args, site.hostArg as string));
      if (derived === undefined) {
        planned.refusal = planned.refusal ?? SWAP_DENY.hostUnderivable;
        planned.host = '';
        planned.pathTemplate = '';
      } else {
        planned.host = derived.host;
        planned.pathTemplate =
          site.pathArg === undefined
            ? derived.pathTemplate
            : (deriveDestination(getPath(input.args, site.pathArg))?.pathTemplate ?? derived.pathTemplate);
      }
    }
    if (planned.refusal === undefined) {
      // The gateway's own floor under the broker's decision. OPA sees `host`
      // and `path_template` too and may refuse for its own reasons; this
      // check is what makes the destination part of the decision even when
      // the broker behind the seam ignores it.
      if (!site.allowHost.some((g) => globMatch(g, '.', planned.host))) {
        planned.refusal = SWAP_DENY.hostNotAllowed;
      } else if (site.allowPath !== undefined && !site.allowPath.some((g) => globMatch(g, '/', planned.pathTemplate))) {
        planned.refusal = SWAP_DENY.pathNotAllowed;
      }
    }
    out.push(planned);
  }
  return out;
}

/* -------------------------------------------------------------------- */
/* The reverse scrub                                                      */
/* -------------------------------------------------------------------- */

interface LiveToken {
  token: string;
  synthetic: string;
  expiresAt: number;
}

/**
 * The server->client seatbelt: for as long as a decision is live, every
 * occurrence of its real token in anything coming back is replaced by the
 * synthetic before the client sees it.
 *
 * It runs over the WHOLE message, not the two text fields the boundary
 * filter scans, because `structuredContent`, `_meta` and resource blobs are
 * otherwise forwarded verbatim — and it can, because unlike the boundary's
 * secret-SHAPED families this is one exact high-entropy needle.
 *
 * It is defeated by any encoding transform: base64, the value split across
 * two fields, a tool that returns it one character per line. Destination
 * binding is the control; this is the seatbelt.
 */
export class TokenScrubber {
  private readonly live: LiveToken[] = [];

  /** Hold `token` for the lifetime of its decision. */
  retain(token: string, synthetic: string, ttlSeconds: number, now: number = Date.now()): void {
    if (token === '' || token === synthetic) return;
    this.sweep(now);
    const ttlMs = Math.min(
      SCRUB_MAX_RETENTION_MS,
      Math.max(SCRUB_MIN_RETENTION_MS, Number.isFinite(ttlSeconds) ? ttlSeconds * 1000 : 0),
    );
    const existing = this.live.find((t) => t.token === token);
    if (existing !== undefined) {
      existing.expiresAt = Math.max(existing.expiresAt, now + ttlMs);
      existing.synthetic = synthetic;
      return;
    }
    // Bounded: the oldest expiry goes first, so a session that swaps many
    // credentials keeps the most recently used ones covered rather than
    // growing the table without limit.
    if (this.live.length >= MAX_LIVE_TOKENS) {
      let oldest = 0;
      for (let i = 1; i < this.live.length; i++) {
        if ((this.live[i] as LiveToken).expiresAt < (this.live[oldest] as LiveToken).expiresAt) oldest = i;
      }
      this.live.splice(oldest, 1);
    }
    this.live.push({ token, synthetic, expiresAt: now + ttlMs });
  }

  /** Drop everything whose retention window has passed. */
  sweep(now: number = Date.now()): void {
    for (let i = this.live.length - 1; i >= 0; i--) {
      if ((this.live[i] as LiveToken).expiresAt <= now) this.live.splice(i, 1);
    }
  }

  /** Forget every token immediately (session end). */
  clear(): void {
    this.live.length = 0;
  }

  /** True when at least one token is live; the cheap gate before any scan. */
  active(now: number = Date.now()): boolean {
    this.sweep(now);
    return this.live.length > 0;
  }

  /**
   * Cheap needle test over raw text. One `includes` per live token beats
   * walking a parsed tree for the overwhelmingly common case of a result
   * that does not contain one.
   */
  mightContain(text: string, now: number = Date.now()): boolean {
    this.sweep(now);
    return this.live.some((t) => text.includes(t.token));
  }

  /** Replace every live token in `text` with its synthetic. */
  scrubText(text: string, now: number = Date.now()): string {
    this.sweep(now);
    let out = text;
    // Longest first: one token that is a prefix of another must not eat the
    // longer one's bytes and leave a tail of the real value behind.
    for (const t of [...this.live].sort((a, b) => b.token.length - a.token.length)) {
      if (out.includes(t.token)) out = out.split(t.token).join(t.synthetic);
    }
    return out;
  }

  /**
   * Copy-on-write scrub of a parsed message. Untouched subtrees come back BY
   * REFERENCE, which is what lets `spliceRewrittenLine` put the original
   * bytes of everything else back on the wire and rewrite only the spans
   * that changed.
   *
   * Object KEYS are scrubbed too: a server that answers `{"<token>": 1}`
   * would otherwise hand the value straight to the model.
   */
  scrubMessage(message: unknown, now: number = Date.now()): { message: unknown; changed: boolean } {
    this.sweep(now);
    if (this.live.length === 0) return { message, changed: false };
    let changed = false;
    const walk = (v: unknown, depth: number): unknown => {
      if (depth > 256) return v; // same bound the hashers use; a deeper tree is not one a server really sends
      if (typeof v === 'string') {
        const s = this.scrubText(v, now);
        if (s !== v) changed = true;
        return s;
      }
      if (Array.isArray(v)) {
        let touched = false;
        const out = v.map((x) => {
          const y = walk(x, depth + 1);
          if (y !== x) touched = true;
          return y;
        });
        return touched ? out : v;
      }
      if (typeof v === 'object' && v !== null) {
        let touched = false;
        const out: Record<string, unknown> = {};
        for (const [k, val] of Object.entries(v as Record<string, unknown>)) {
          const nk = this.scrubText(k, now);
          const nv = walk(val, depth + 1);
          if (nk !== k || nv !== val) touched = true;
          out[nk] = nv;
        }
        if (touched) changed = true;
        return touched ? out : v;
      }
      return v;
    };
    const out = walk(message, 0);
    return { message: out, changed };
  }

  /**
   * Last-resort byte sweep at the single point where bytes leave for the
   * client. The structural scrub above is the one that matters — it runs
   * before the result is hashed into an event — but this catches the paths
   * that never become a parsed message: an unparseable server line, a line
   * the gateway forwarded verbatim, bytes written by another layer.
   *
   * It cannot catch a token split across two chunks of an OVERSIZED line,
   * which the splitter streams through as it arrives; that is the same class
   * of gap as the encoding transforms above, and is documented rather than
   * papered over.
   */
  scrubBytes(bytes: Buffer, now: number = Date.now()): Buffer {
    this.sweep(now);
    if (this.live.length === 0) return bytes;
    const text = bytes.toString('utf8');
    const scrubbed = this.scrubText(text, now);
    return scrubbed === text ? bytes : Buffer.from(scrubbed, 'utf8');
  }
}

/* -------------------------------------------------------------------- */
/* Exchange                                                               */
/* -------------------------------------------------------------------- */

export interface ExchangeContext {
  /** Logical MCP server name — the `server` the policy matched on. */
  server: string;
  /** Tool name, which is what `path_template` carries for a fixed-upstream site. */
  tool: string;
  /** MCP client name/version from `initialize`, mapped onto `user_agent`. */
  userAgent?: string;
}

/** What one exchange decided, for the diagnostics and the event attributes. */
export interface SwapDecision {
  siteId: string;
  credential: string;
  decisionId: string;
  host: string;
  hostSource: 'argument' | 'server_name' | 'declared';
  pathTemplate: string;
  ttlSeconds: number;
  denyCode?: string;
}

export type SwapOutcome =
  | { kind: 'allow'; message: unknown; decisions: SwapDecision[]; attributes: Attributes }
  | { kind: 'deny'; code: string; failClosed: boolean; decisions: SwapDecision[]; attributes: Attributes };

export interface CredentialSwapDeps {
  broker: Broker;
  config: CredentialsConfig;
  /** Identity the broker knows this proxy by; NHI resolves it to a tenant. */
  dataPlaneInstanceId: string;
  scrubber?: TokenScrubber;
  deadlineMs?: number;
  now?: () => number;
}

/** Shape-check a code off the broker before it reaches a refusal message or an event. */
function sanitizeDenyCode(reason: unknown): string {
  return typeof reason === 'string' && DENY_CODE_SHAPE.test(reason) ? reason : 'denied_by_policy';
}

/** True when a deny means "no decision was reached", not "the answer was no". */
export function isResolutionFailure(code: string): boolean {
  return RESOLUTION_FAILURE_CODES.has(code);
}

/** Copy-on-write write of one leaf, sharing every untouched subtree by reference. */
function replaceAt(root: unknown, path: readonly (string | number)[], value: string): unknown {
  if (path.length === 0) return value;
  const [head, ...rest] = path;
  if (typeof head === 'number') {
    if (!Array.isArray(root) || head >= root.length) return root;
    const out = [...root];
    out[head] = replaceAt(root[head], rest, value);
    return out;
  }
  if (typeof root !== 'object' || root === null || Array.isArray(root)) return root;
  const obj = root as Record<string, unknown>;
  if (!Object.prototype.hasOwnProperty.call(obj, head as string)) return root;
  return { ...obj, [head as string]: replaceAt(obj[head as string], rest, value) };
}

/**
 * The swap engine. One per session; holds the live-token table the reverse
 * scrub reads.
 */
export class CredentialSwap {
  readonly scrubber: TokenScrubber;
  private readonly broker: Broker;
  private readonly config: CredentialsConfig;
  private readonly dataPlaneInstanceId: string;
  private readonly deadlineMs: number;
  private readonly now: () => number;

  constructor(deps: CredentialSwapDeps) {
    this.broker = deps.broker;
    this.config = deps.config;
    this.dataPlaneInstanceId = deps.dataPlaneInstanceId;
    this.deadlineMs = deps.deadlineMs ?? BROKER_EXCHANGE_DEADLINE_MS;
    this.now = deps.now ?? Date.now;
    this.scrubber = deps.scrubber ?? new TokenScrubber();
  }

  /** Declared sites this call engages. Empty = ordinary traffic, forwarded as written. */
  plan(input: PlanInput): PlannedSwap[] {
    return planSwaps(this.config, input);
  }

  /** True when the config declares any site at all (lets the caller skip the walk entirely). */
  get hasSites(): boolean {
    return this.config.sites.length > 0;
  }

  /**
   * Exchange every planned synthetic and return the message to forward.
   *
   * NEVER resolves to the original message on failure: invariant 1 says a
   * broker that cannot authorise a call denies it, and the synthetic must
   * never travel on to the upstream. The two ways out of here are a message
   * with the real tokens spliced in, and a deny.
   *
   * Never rejects: a throw from `exchange()` becomes `broker_unavailable`,
   * so the caller has one shape to handle on the forwarding path.
   */
  async exchange(message: unknown, plan: readonly PlannedSwap[], ctx: ExchangeContext): Promise<SwapOutcome> {
    const decisions: SwapDecision[] = [];
    let out = message;
    for (const planned of plan) {
      const decision: SwapDecision = {
        siteId: planned.site.id,
        credential: planned.site.credential,
        decisionId: '',
        host: planned.host,
        hostSource: planned.hostSource,
        pathTemplate: planned.pathTemplate,
        ttlSeconds: 0,
      };
      if (planned.refusal !== undefined) {
        decision.denyCode = planned.refusal;
        decisions.push(decision);
        return this.deny(planned.refusal, decisions);
      }
      const req: BrokerExchangeRequest = {
        synthetic: planned.synthetic,
        data_plane_instance_id: this.dataPlaneInstanceId,
        request: {
          // MCP's mapping onto the wire's request summary, as the contract
          // fixes it: the JSON-RPC method, the destination this call is
          // actually aimed at, and the tool name as the path template when
          // the upstream is the server itself.
          method: 'tools/call',
          host: planned.host,
          path_template: planned.pathTemplate,
        },
      };
      if (ctx.userAgent !== undefined && ctx.userAgent !== '') req.request.user_agent = ctx.userAgent;

      let res;
      try {
        res = await this.withDeadline(
          this.broker.exchange(req, { credential: planned.site.credential, site: planned.site.id }),
        );
      } catch (err) {
        // CODES only: the underlying message may quote a command line, a
        // vault path with a token in it, or an upstream 401 body.
        const code = err instanceof DeadlineError ? SWAP_DENY.timeout : SWAP_DENY.unavailable;
        decision.denyCode = code;
        decisions.push(decision);
        return this.deny(code, decisions);
      }
      decision.decisionId = typeof res?.decision_id === 'string' ? res.decision_id : '';
      if (res === null || typeof res !== 'object') {
        decision.denyCode = SWAP_DENY.unavailable;
        decisions.push(decision);
        return this.deny(SWAP_DENY.unavailable, decisions);
      }
      if (res.denied === true || typeof res.real_token !== 'string' || res.real_token === '') {
        const code = res.denied === true ? sanitizeDenyCode(res.deny_reason) : SWAP_DENY.noToken;
        decision.denyCode = code;
        decisions.push(decision);
        return this.deny(code, decisions);
      }
      decision.ttlSeconds = typeof res.ttl_seconds === 'number' && Number.isFinite(res.ttl_seconds) ? res.ttl_seconds : 0;
      decisions.push(decision);
      this.scrubber.retain(res.real_token, planned.synthetic, decision.ttlSeconds, this.now());
      // Splice the real value into a COPY: `message` is the object the tap
      // records from, and it keeps the synthetic. Record-then-swap is the
      // pipeline order, not a check a later edit can forget.
      out = replaceAt(out, planned.path, planned.leaf.split(planned.synthetic).join(res.real_token));
    }
    return { kind: 'allow', message: out, decisions, attributes: swapAttributes(decisions, this.config) };
  }

  private deny(code: string, decisions: SwapDecision[]): SwapOutcome {
    return {
      kind: 'deny',
      code,
      failClosed: isResolutionFailure(code),
      decisions,
      attributes: { ...swapAttributes(decisions, this.config), 'cresec.credential.deny_reason': code },
    };
  }

  private withDeadline<T>(p: Promise<T>): Promise<T> {
    return new Promise<T>((resolve, reject) => {
      // unref'd: a proxy that is shutting down must not be held open for the
      // remainder of a deadline nobody is waiting on any more.
      const timer = setTimeout(() => reject(new DeadlineError()), this.deadlineMs);
      timer.unref?.();
      p.then(
        (v) => {
          clearTimeout(timer);
          resolve(v);
        },
        (err: unknown) => {
          clearTimeout(timer);
          reject(err instanceof Error ? err : new Error('broker exchange failed'));
        },
      );
    });
  }
}

class DeadlineError extends Error {}

/**
 * The decision, as event attributes. Everything here is an id, a label or a
 * destination — never the resolved value, and never a hash of it, because a
 * ref of a real token is a brute-forceable copy of it. `attributes` is an
 * open map on the frozen v1 schema, so this adds no field to any event type.
 */
export function swapAttributes(decisions: readonly SwapDecision[], config?: CredentialsConfig): Attributes {
  if (decisions.length === 0) return {};
  const join = (xs: string[]): string => structuralString(xs.filter((x) => x !== '').join(','), 'identifier');
  const attributes: Attributes = {
    'cresec.credential.id': join(decisions.map((d) => d.credential)),
    'cresec.credential.site': join(decisions.map((d) => d.siteId)),
    'cresec.credential.host': join(decisions.map((d) => d.host)),
    'cresec.credential.host_source': join(decisions.map((d) => d.hostSource)),
    'cresec.credential.path_template': join(decisions.map((d) => d.pathTemplate)),
  };
  const ids = decisions.map((d) => d.decisionId).filter((d) => d !== '');
  if (ids.length > 0) attributes['cresec.broker.decision_id'] = join(ids);
  const ttl = decisions.reduce((acc, d) => Math.max(acc, d.ttlSeconds), 0);
  if (ttl > 0) attributes['cresec.broker.ttl_seconds'] = ttl;
  // Both hashes on every decision: a policy or broker-config edit mid-session
  // cannot be prevented where the agent's uid can write those files, but it
  // is EVIDENT in a tamper-evident chain that records what was in force.
  if (config?.config_hash !== undefined) attributes['cresec.credential.config_hash'] = config.config_hash;
  return attributes;
}

/** The refusal reason an agent reads. A CODE, never the underlying error. */
export function swapDenyReason(code: string): string {
  return `credential broker denied the swap (${code})`;
}
