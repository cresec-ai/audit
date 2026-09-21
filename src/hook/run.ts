/**
 * `mcp-recorder hook` — turn one Claude Code hook invocation into a
 * recorded, redacted evidence-chain event.
 *
 * HOOK CONTRACT (verified against the current docs — cite these, not memory,
 * if this ever needs re-checking):
 *   https://code.claude.com/docs/en/hooks
 *   https://code.claude.com/docs/en/hooks#posttoolusefailure-input
 *   https://code.claude.com/docs/en/hooks-guide
 * Claude Code spawns a fresh process per hook event and feeds it exactly one
 * JSON object on stdin. Every event carries `session_id`, `transcript_path`,
 * `cwd`, `hook_event_name`. PreToolUse/PostToolUse/PostToolUseFailure add
 * `tool_name`, `tool_input`, `tool_use_id`. PostToolUse fires ONLY for a
 * tool call that succeeded and adds `tool_response` (string | object); a
 * call that failed fires PostToolUseFailure INSTEAD, which carries no
 * `tool_response` but `error` (a string whose format depends on the tool)
 * and an optional `is_interrupt` boolean (true when the failure reached
 * Claude Code as an abort — the running tool was cancelled — rather than as
 * an error the tool reported). SessionEnd adds `reason`: one of
 * 'clear'|'resume'|'logout'|'prompt_input_exit'|'other'. Stop (end of an
 * agent turn, recorded as a 'claude-code/stop' notification) has no
 * `reason` field at all. MCP tools are named `mcp__<server>__<tool>` (see
 * src/hook/names.ts); built-ins (Bash, Edit, ...) carry no such prefix.
 *
 * A PreToolUse hook DENIES the call by printing this on stdout and exiting 0:
 *   {"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"..."}}
 * (exit 2 also blocks — using stderr as the reason instead of the JSON — but
 * this command never uses exit 2; see the fail-open note below). ALLOWING is
 * exit 0 with nothing on stdout at all — printing anything else on an allow
 * would be misread as the hook's own decision output.
 *
 * FAIL-OPEN, ALWAYS: this command must never become the reason a tool call
 * is blocked or an agent turn fails. `runHook` never throws and always
 * resolves; any internal error (malformed stdin, a store that can't open, a
 * broken policy file, ...) is swallowed and treated as "allow, record
 * nothing" — this module never asks the caller to exit non-zero. The one
 * intentional exception to "never blocks" is the policy engine: a `deny`
 * rule is a deliberate, operator-configured decision, not a failure.
 */

import { hostname as osHostname, userInfo } from 'node:os';
import { randomUUID } from 'node:crypto';

import { setupProxyRecording } from '../capture/setup.js';
import { canonicalJson, sha256Hex, sha256Ref } from '../chain/hash.js';
import { scrubArgv, scrubToolArguments } from '../redact/redactor.js';
import { SCHEMA } from '../schema/events.js';
import type {
  AnyEvent,
  Attributes,
  IdentityContext,
  ServerContext,
  NotificationEvent,
  SessionEndEvent,
  SessionStartEvent,
  Sha256Ref,
  ToolCallEvent,
} from '../schema/events.js';
import type { RecorderConfig } from '../types.js';
import { resolveServerOrigin } from './mcp-config.js';
import { hostAliasToolName, parseToolName } from './names.js';
import { evaluatePolicy, loadPolicy } from './policy.js';
import { claimSessionStart, markPending, sweepStalePending, takePending } from './state.js';
import { stampActor, type ActorStamp } from '../identity/stamp.js';

/** sha256:<hex> of canonical `null` — result_hash for a PreToolUse marker
 *  (no result exists yet). */
const NULL_RESULT_HASH = sha256Ref(canonicalJson(null));

export interface HookOpts {
  config: RecorderConfig;
  /** Absolute path to a policy file, or undefined for "no policy" (allow all). */
  policyPath?: string;
  /** Logical client name stamped as server.name (`--client`; default 'claude-code'). */
  clientName: string;
  /** Record built-in (non-mcp__) tool calls too, not just MCP ones. */
  allTools: boolean;
  proxyVersion: string;
  /** Additive: the ADR 012 actor claim (`--identity-jwt`), stamped on every event's identity block. */
  actor?: ActorStamp;
}

export interface HookResult {
  /** Always 0 — see the file-level fail-open note. */
  exitCode: 0;
  /** JSON to print on stdout verbatim (a PreToolUse deny) — undefined means
   *  "print nothing", the allow case. */
  stdout?: string;
}

const ALLOW: HookResult = { exitCode: 0 };

interface HookInput {
  session_id?: unknown;
  cwd?: unknown;
  hook_event_name?: unknown;
  tool_name?: unknown;
  tool_input?: unknown;
  tool_use_id?: unknown;
  tool_response?: unknown;
  /** PostToolUseFailure only: the error text (a payload string — hashed, never stored). */
  error?: unknown;
  /** PostToolUseFailure only: true when the call was aborted rather than erroring. */
  is_interrupt?: unknown;
  reason?: unknown;
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function round2(n: number): number {
  return Math.round(n * 100) / 100;
}

function diagStderr(msg: string): void {
  try {
    process.stderr.write(`[mcp-recorder] ${msg}\n`);
  } catch {
    /* even diagnostics are fail-open */
  }
}

/** Fallback request_id when the hook input carries no `tool_use_id` (older
 *  Claude Code versions): stable per (session, tool, exact input), so a
 *  PostToolUse for the very same call still lands on the same id as its
 *  PreToolUse. No per-call nonce is available in this shape, unlike
 *  `tool_use_id` — that's the whole reason `tool_use_id` is preferred. */
function computeFallbackRequestId(sessionId: string, toolName: string, toolInput: unknown): string {
  return sha256Hex(`${sessionId}\0${toolName}\0${canonicalJson(toolInput ?? null)}`);
}

/** Best-effort "was this an error" read of a PostToolUse `tool_response`:
 *  the MCP CallToolResult convention (`{content: [...], isError: true}`),
 *  mirroring stdio.ts's own `rawResult.isError === true` check. A response
 *  that isn't shaped like that (a plain string, most built-in tools) is
 *  never treated as an error here — this is a detection, not a guarantee. */
function detectIsError(toolResponse: unknown): boolean {
  return isPlainObject(toolResponse) && toolResponse.isError === true;
}

/**
 * SessionEndEvent.reason is a frozen closed union
 * ('child_exit'|'stdin_closed'|'signal'|'error') with no member for any of
 * Claude Code's own SessionEnd reasons, and Stop carries no reason at all.
 * Additive-only means picking the closest EXISTING value rather than
 * inventing a new one; the true origin is recorded separately via the
 * additive `source: 'hook'` field `base()` sets below. 'logout' (the user
 * closed the CLI) reads closest to 'stdin_closed'; everything else
 * (clear/resume/prompt_input_exit/other, and Stop's no-reason case) reads
 * closest to a normal, non-erroring 'child_exit'.
 */
function mapSessionEndReason(hookReason: string | undefined): SessionEndEvent['reason'] {
  return hookReason === 'logout' ? 'stdin_closed' : 'child_exit';
}

/**
 * Turn boundaries (Stop) and session end are the natural moments to garbage
 * collect pending markers whose post half never came — see
 * `sweepStalePending` in src/hook/state.ts for how a marker outlives its
 * call. Fail-open: the sweep itself ignores every per-file error, and even
 * an unexpected throw here only ever reaches stderr.
 */
function sweepPendingMarkers(dataDir: string): void {
  try {
    sweepStalePending(dataDir);
  } catch (cause) {
    diagStderr(`pending-marker sweep failed: ${cause instanceof Error ? cause.message : String(cause)}`);
  }
}

export async function runHook(stdinText: string, opts: HookOpts): Promise<HookResult> {
  try {
    let raw: unknown;
    try {
      raw = JSON.parse(stdinText);
    } catch {
      return ALLOW; // malformed/empty stdin: fail-open, record nothing
    }
    if (!isPlainObject(raw)) return ALLOW;
    const input = raw as HookInput;

    const eventName = typeof input.hook_event_name === 'string' ? input.hook_event_name : undefined;
    const sessionId =
      typeof input.session_id === 'string' && input.session_id.length > 0 ? input.session_id : undefined;
    if (eventName === undefined || sessionId === undefined) return ALLOW;

    const isToolEvent =
      eventName === 'PreToolUse' || eventName === 'PostToolUse' || eventName === 'PostToolUseFailure';
    const isEndEvent = eventName === 'SessionEnd';
    const isStopEvent = eventName === 'Stop';
    if (!isToolEvent && !isEndEvent && !isStopEvent) return ALLOW; // an event this command doesn't handle

    const toolName = typeof input.tool_name === 'string' ? input.tool_name : undefined;
    if (isToolEvent && toolName === undefined) return ALLOW;

    const parsed = toolName !== undefined ? parseToolName(toolName) : undefined;
    if (isToolEvent && parsed !== undefined && !parsed.isMcp && !opts.allTools) {
      return ALLOW; // built-in tool, --all-tools not set: not recorded, policy not evaluated
    }

    // Where the MCP server actually is, from the config file Claude Code was
    // started with (src/hook/mcp-config.ts). In a cloud session the hosted
    // connectors are named by opaque UUIDs (mcp__47d587b8-…__clickup_get_list),
    // and that file is the only place a connector maps to a vendor endpoint.
    // The TOOL name goes in as well as the segment: the config key and the
    // tool-name segment are NOT always the same convention (dogfood 4 had a
    // UUID-keyed file and friendly tool names, so the key lookup missed and
    // nothing resolved), and `opts.tool` lets resolution fall back to the one
    // entry that declares this exact tool. The resolved URL is stamped as the
    // additive `server.url`; the host also forms the policy alias
    // `mcp__<host>__<tool>`, which is tested against DENY rules only (that
    // file is writable by the agent under policy — see the TRUST note in
    // mcp-config.ts and `evaluatePolicy`). `server.name` stays what Claude
    // Code calls the server, so it matches Claude Code's own matchers and
    // transcripts. Fail-open: `{}` when nothing resolves, and no alias for a
    // host that is not a plausible dotted hostname (`hostAliasToolName`).
    const origin =
      parsed !== undefined && parsed.isMcp ? resolveServerOrigin(parsed.server, { tool: parsed.tool }) : {};
    const policyAlias =
      parsed !== undefined && parsed.isMcp && origin.host !== undefined
        ? hostAliasToolName(origin.host, parsed.tool)
        : undefined;

    /* -------------------------- recording setup -------------------------- */
    let setup: Awaited<ReturnType<typeof setupProxyRecording>>;
    try {
      setup = await setupProxyRecording(opts.config, diagStderr, { surface: 'hook' });
    } catch {
      return ALLOW; // recording could not initialize: still allow, fail-open
    }

    /* ------------------------------ identity ------------------------------ */
    let osUser = '';
    let host = '';
    try {
      osUser = userInfo().username;
    } catch {
      /* keep empty */
    }
    try {
      host = osHostname();
    } catch {
      /* keep empty */
    }
    const fingerprint = sha256Ref(
      `${osUser}\0${host}\0${opts.config.identityLabel ?? ''}\0${opts.clientName}`,
    );
    const identity: IdentityContext = { fingerprint };
    if (osUser) identity.os_user = osUser;
    if (host) identity.hostname = host;
    if (opts.config.identityLabel) identity.label = opts.config.identityLabel;
    if (opts.actor !== undefined) stampActor(identity, opts.actor);

    // Scrubbed like argv (AGENTS.md: no readable payload strings reach the
    // store) even though this particular string is a local constant, never
    // attacker/remote controlled — defense in depth, and it costs nothing.
    const scrubbedCommand = scrubArgv([`hook:${opts.clientName}`], setup.redactor).command;
    // Session-level events (session_start, session_end, the Stop
    // notification) carry the client's own ServerContext and nothing else:
    // `url` is "where the server named by server.name is", and the server
    // named here is claude-code itself, so it never carries a vendor URL
    // (every tool_call event does).
    const baseServer: ServerContext = { name: opts.clientName, command: scrubbedCommand, transport: 'stdio' };

    const base = (kind: AnyEvent['kind'], attributes: Attributes, server: ServerContext = baseServer) => ({
      schema: SCHEMA,
      event_id: randomUUID(),
      session_id: sessionId,
      timestamp: new Date().toISOString(),
      kind,
      identity,
      server,
      attributes,
      source: 'hook' as const,
    });

    let result: HookResult = ALLOW;
    try {
      const firstEventOfSession = claimSessionStart(opts.config.dataDir, sessionId);
      if (firstEventOfSession) {
        const cwd = typeof input.cwd === 'string' ? input.cwd : process.cwd();
        const sessionStart: SessionStartEvent = {
          ...base('session_start', { 'rpc.system': 'hook' }),
          kind: 'session_start',
          proxy_version: opts.proxyVersion,
          cwd,
          redaction_mode: setup.redactor.mode,
        };
        setup.recorder.record(sessionStart);
      }

      if (isStopEvent) {
        // Stop fires at the end of EVERY agent turn, not at session end, so it
        // must not fake a terminal session_end (a session has exactly one).
        // It is still worth a turn-boundary marker in the chain: a
        // notification-kind event, the closest existing shape (a
        // client-originated message with no request id). params carries only
        // the boolean Claude Code sends (stop_hook_active), scrubbed like any
        // payload.
        const stopParams = { stop_hook_active: (input as { stop_hook_active?: unknown }).stop_hook_active === true };
        const turnEnd: NotificationEvent = {
          ...base('notification', { 'mcp.method.name': 'claude-code/stop', 'rpc.system': 'hook' }),
          kind: 'notification',
          method: 'claude-code/stop',
          direction: 'client_to_server',
          params: setup.redactor.scrub(stopParams),
        };
        setup.recorder.record(turnEnd);
        sweepPendingMarkers(opts.config.dataDir);
      } else if (isEndEvent) {
        const hookReason = typeof input.reason === 'string' ? input.reason : undefined;
        const stats = setup.stats();
        const sessionEnd: SessionEndEvent = {
          ...base('session_end', { 'rpc.system': 'hook' }),
          kind: 'session_end',
          reason: mapSessionEndReason(hookReason),
          child_exit_code: null,
          events_recorded: stats.written,
          events_dropped: stats.dropped,
        };
        setup.recorder.record(sessionEnd);
        sweepPendingMarkers(opts.config.dataDir);
      } else {
        // isToolEvent, with toolName/parsed both guaranteed defined by the
        // early filtering above.
        const server: ServerContext = { ...baseServer, name: parsed!.server };
        if (origin.url !== undefined) server.url = origin.url;
        const requestId =
          typeof input.tool_use_id === 'string' && input.tool_use_id.length > 0
            ? input.tool_use_id
            : computeFallbackRequestId(sessionId, toolName!, input.tool_input);

        if (eventName === 'PreToolUse') {
          const { policy, warning, unusable } = loadPolicy(opts.policyPath);
          if (warning !== undefined) diagStderr(warning);
          // A policy that cannot be evaluated denies. See `unusable` in
          // ./policy.ts for why this is the one place the hook is not
          // fail-open, and why denying is recoverable.
          const decision = unusable === true
            ? { decision: 'deny' as const, reason: 'the policy file could not be loaded, so nothing can be evaluated' }
            : evaluatePolicy(policy, toolName!, policyAlias);
          const isDenied = decision.decision === 'deny';

          const attributes: Attributes = {
            'gen_ai.operation.name': 'execute_tool',
            'gen_ai.tool.name': parsed!.tool,
            'gen_ai.tool.call.id': String(requestId),
            'mcp.method.name': 'tools/call',
            'rpc.system': 'hook',
          };
          if (isDenied) attributes['error.type'] = 'policy_denied';

          const toolCall: ToolCallEvent = {
            ...base('tool_call', attributes, server),
            kind: 'tool_call',
            tool: parsed!.tool,
            request_id: requestId,
            args: scrubToolArguments(setup.redactor, input.tool_input ?? {}),
            result_hash: NULL_RESULT_HASH,
            result: null,
            is_error: isDenied,
            duration_ms: 0,
            phase: 'pre',
          };
          if (isDenied) {
            toolCall.error = {
              type: 'policy_denied',
              message_ref: setup.redactor.hashString(decision.reason ?? 'denied by policy'),
            };
          } else {
            try {
              markPending(opts.config.dataDir, String(requestId), Date.now());
            } catch (cause) {
              diagStderr(
                `could not persist pending marker for ${String(requestId)}: ` +
                  (cause instanceof Error ? cause.message : String(cause)),
              );
            }
          }
          setup.recorder.record(toolCall);

          if (isDenied) {
            const reasonText = `mcp-recorder policy: ${decision.reason ?? 'denied by policy'}`;
            result = {
              exitCode: 0,
              stdout: JSON.stringify({
                hookSpecificOutput: {
                  hookEventName: 'PreToolUse',
                  permissionDecision: 'deny',
                  permissionDecisionReason: reasonText,
                },
              }),
            };
          }
        } else {
          // PostToolUse (the call succeeded: `tool_response` is its result)
          // or PostToolUseFailure (it failed: no `tool_response`, an `error`
          // string instead). Both are the POST phase of the same call — one
          // event sharing the PreToolUse event's request_id and closing the
          // pending marker PreToolUse left behind for duration_ms. Claude
          // Code fires exactly one of the two per call, so ignoring the
          // failure half (as cloud dogfood 3 caught) leaves a failed call as
          // a lone `pre` event with is_error false and a marker nobody takes.
          const isFailure = eventName === 'PostToolUseFailure';
          let t0: number | undefined;
          try {
            t0 = takePending(opts.config.dataDir, String(requestId));
          } catch {
            t0 = undefined;
          }
          const durationMs = t0 !== undefined ? round2(Math.max(0, Date.now() - t0)) : 0;

          // A failure carries no tool_response by contract; should one ever
          // appear anyway it is deliberately not read, so a failure's result
          // is always recorded exactly as an absent response (canonical null).
          const rawResult = isFailure ? undefined : input.tool_response;
          const failureType: 'tool_error' | 'interrupted' | undefined = !isFailure
            ? undefined
            : input.is_interrupt === true
              ? 'interrupted'
              : 'tool_error';
          const errorType = failureType ?? (detectIsError(rawResult) ? 'tool_error' : undefined);

          // The error text is payload: it reaches the store only as its
          // sha256 ref, hashed exactly like every redacted leaf
          // (Redactor.hashString is sha256Ref), so a known error text can be
          // matched against it by hashing it the same way. A non-string
          // `error` (never per the docs, but fail-open) is canonicalized
          // then hashed.
          let messageRef: Sha256Ref | undefined;
          if (isFailure && input.error !== undefined) {
            const errorText = typeof input.error === 'string' ? input.error : canonicalJson(input.error);
            messageRef = setup.redactor.hashString(errorText);
          }

          const attributes: Attributes = {
            'gen_ai.operation.name': 'execute_tool',
            'gen_ai.tool.name': parsed!.tool,
            'gen_ai.tool.call.id': String(requestId),
            'mcp.method.name': 'tools/call',
            'rpc.system': 'hook',
          };
          if (errorType !== undefined) attributes['error.type'] = errorType;

          const toolCall: ToolCallEvent = {
            ...base('tool_call', attributes, server),
            kind: 'tool_call',
            tool: parsed!.tool,
            request_id: requestId,
            args: scrubToolArguments(setup.redactor, input.tool_input ?? {}),
            result_hash: sha256Ref(canonicalJson(rawResult ?? null)),
            result: setup.redactor.scrub(rawResult ?? null),
            is_error: errorType !== undefined,
            duration_ms: durationMs,
            phase: 'post',
          };
          if (failureType !== undefined) {
            const error: NonNullable<ToolCallEvent['error']> = { type: failureType };
            if (messageRef !== undefined) error.message_ref = messageRef;
            toolCall.error = error;
          }
          setup.recorder.record(toolCall);
        }
      }
    } finally {
      try {
        await setup.recorder.close();
      } catch {
        /* fail-open */
      }
    }
    return result;
  } catch {
    return ALLOW;
  }
}
