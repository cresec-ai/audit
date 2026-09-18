/**
 * `mcp-recorder hook` — turns Claude Code PreToolUse/PostToolUse/PostToolUseFailure/SessionEnd/
 * Stop hook invocations into recorded, redacted evidence-chain events, with
 * an allow/deny policy. Drives the real CLI (spawned fresh per hook event,
 * same as Claude Code does) and inspects the resulting store, exactly like
 * test/cli.test.ts and test/setup.test.ts do for the commands they cover.
 */
import type { ChildProcess } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, utimesSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { Readable } from 'node:stream';
import { fileURLToPath } from 'node:url';
import { afterEach, describe, expect, it } from 'vitest';
import { spawnTsx } from './helpers/tsx.js';
import { canonicalJson, sha256Ref } from '../src/chain/hash.js';
import { openStoreReadOnly } from '../src/store/index.js';
import type { AnyEvent, NotificationEvent, SessionEndEvent, SessionStartEvent, ToolCallEvent } from '../src/schema/events.js';

const ROOT = fileURLToPath(new URL('..', import.meta.url));

/* -------------------------------- helpers -------------------------------- */

const cleanups: Array<() => void> = [];
afterEach(() => {
  while (cleanups.length > 0) {
    try {
      cleanups.pop()!();
    } catch {
      /* best-effort teardown */
    }
  }
});

function tmpDir(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  cleanups.push(() => rmSync(dir, { recursive: true, force: true }));
  return dir;
}

interface CliResult {
  code: number | null;
  stdout: string;
  stderr: string;
}

function collect(stream: Readable | null): () => string {
  let text = '';
  stream?.setEncoding('utf8');
  stream?.on('data', (chunk: string) => {
    text += chunk;
  });
  return () => text;
}

function waitExit(child: ChildProcess): Promise<number | null> {
  return new Promise((resolvePromise) => child.once('close', (code) => resolvePromise(code)));
}

/** Fixture shaped exactly like a cloud session's /tmp/mcp-config-<session>.json
 *  (cloud dogfood 3, step 5), with fake ids — see test/fixtures/mcp-config. */
const CLOUD_MCP_CONFIG = join(ROOT, 'test', 'fixtures', 'mcp-config', 'cloud-session.json');
/** The other convention: a config keyed by FRIENDLY connector name, with
 *  friendly tool names — a local session, and the cloud session this test was
 *  written in. Whether the key or the tool-name segment is the UUID varies
 *  per session, so both shapes are exercised end to end. */
const FRIENDLY_MCP_CONFIG = join(ROOT, 'test', 'fixtures', 'mcp-config', 'friendly-session.json');
/** A path that does not exist: "no MCP config file at all". Every test runs
 *  with this unless it says otherwise, so the hook's default lookup of the
 *  host's own /tmp/mcp-config-*.json (this suite may itself run inside a
 *  cloud session) can never leak into an assertion. */
const NO_MCP_CONFIG = join(ROOT, 'test', 'fixtures', 'mcp-config', 'does-not-exist.json');

function spawnCli(args: string[], env: Record<string, string | undefined> = {}): ChildProcess {
  const child = spawnTsx(['src/cli.ts', ...args], {
    cwd: ROOT,
    env: { ...process.env, MCP_RECORDER_DISABLE: undefined, MCP_RECORDER_MCP_CONFIG: NO_MCP_CONFIG, ...env },
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  cleanups.push(() => {
    if (child.exitCode === null) child.kill('SIGKILL');
  });
  return child;
}

/** Run the CLI with no stdin input (verify/query/sessions/hook install). */
async function runCli(args: string[]): Promise<CliResult> {
  const child = spawnCli(args);
  const stdout = collect(child.stdout);
  const stderr = collect(child.stderr);
  child.stdin?.end();
  const code = await waitExit(child);
  return { code, stdout: stdout(), stderr: stderr() };
}

/** Run `mcp-recorder hook <args>`, feeding `stdinText` on stdin. */
async function runHook(
  args: string[],
  stdinText: string,
  env: Record<string, string | undefined> = {},
): Promise<CliResult> {
  const child = spawnCli(['hook', ...args], env);
  const stdout = collect(child.stdout);
  const stderr = collect(child.stderr);
  child.stdin!.write(stdinText);
  child.stdin!.end();
  const code = await waitExit(child);
  return { code, stdout: stdout(), stderr: stderr() };
}

function readEvents(dataDir: string): AnyEvent[] {
  const store = openStoreReadOnly({ dataDir, backend: 'jsonl' });
  try {
    return [...store.iterate()].map((r) => r.event);
  } finally {
    store.close();
  }
}

let sessionCounter = 0;
/** A fresh, deterministic-enough UUID-shaped session id per test. */
function freshSessionId(): string {
  sessionCounter++;
  return `10000000-0000-4000-8000-${sessionCounter.toString(16).padStart(12, '0')}`;
}

function preToolUseInput(opts: {
  sessionId: string;
  toolName: string;
  toolInput: unknown;
  toolUseId: string;
  cwd?: string;
}): string {
  return JSON.stringify({
    session_id: opts.sessionId,
    transcript_path: '/tmp/transcript.jsonl',
    cwd: opts.cwd ?? '/tmp',
    hook_event_name: 'PreToolUse',
    tool_name: opts.toolName,
    tool_input: opts.toolInput,
    tool_use_id: opts.toolUseId,
  });
}

function postToolUseInput(opts: {
  sessionId: string;
  toolName: string;
  toolInput: unknown;
  toolUseId: string;
  toolResponse: unknown;
}): string {
  return JSON.stringify({
    session_id: opts.sessionId,
    transcript_path: '/tmp/transcript.jsonl',
    cwd: '/tmp',
    hook_event_name: 'PostToolUse',
    tool_name: opts.toolName,
    tool_input: opts.toolInput,
    tool_use_id: opts.toolUseId,
    tool_response: opts.toolResponse,
  });
}

/** PostToolUseFailure carries `error` (string) and `is_interrupt` instead
 *  of `tool_response` — https://code.claude.com/docs/en/hooks#posttoolusefailure-input */
function postToolUseFailureInput(opts: {
  sessionId: string;
  toolName: string;
  toolInput: unknown;
  toolUseId: string;
  error: string;
  isInterrupt?: boolean;
}): string {
  return JSON.stringify({
    session_id: opts.sessionId,
    transcript_path: '/tmp/transcript.jsonl',
    cwd: '/tmp',
    permission_mode: 'default',
    hook_event_name: 'PostToolUseFailure',
    tool_name: opts.toolName,
    tool_input: opts.toolInput,
    tool_use_id: opts.toolUseId,
    error: opts.error,
    is_interrupt: opts.isInterrupt ?? false,
    duration_ms: 4187,
  });
}

/* ---------------------------------- tests --------------------------------- */

describe('mcp-recorder hook', () => {
  it('PreToolUse (allow): no stdout, exit 0, records a tool_call with hashed args and no verbatim strings', async () => {
    const dataDir = tmpDir('mcp-hook-allow-');
    const sessionId = freshSessionId();
    const plaintext = 'do-not-leak-this-argument-value';

    const result = await runHook(
      ['--data-dir', dataDir, '--store', 'jsonl'],
      preToolUseInput({
        sessionId,
        toolName: 'mcp__ClickUp__clickup_get_task',
        toolInput: { task_id: 'abc123', note: plaintext },
        toolUseId: 'toolu_allow_1',
      }),
    );

    expect(result.code).toBe(0);
    expect(result.stdout).toBe('');

    const events = readEvents(dataDir);
    expect(events.map((e) => e.kind)).toEqual(['session_start', 'tool_call']);

    const sessionStart = events[0] as SessionStartEvent;
    expect(sessionStart.session_id).toBe(sessionId);
    expect(sessionStart.source).toBe('hook');
    expect(sessionStart.server.name).toBe('claude-code');

    const toolCall = events[1] as ToolCallEvent;
    expect(toolCall.session_id).toBe(sessionId);
    expect(toolCall.source).toBe('hook');
    expect(toolCall.phase).toBe('pre');
    expect(toolCall.tool).toBe('clickup_get_task'); // mcp__ prefix stripped
    expect(toolCall.server.name).toBe('ClickUp'); // split out as the MCP server
    expect(toolCall.request_id).toBe('toolu_allow_1');
    expect(toolCall.is_error).toBe(false);
    expect(toolCall.result).toBeNull();

    // No verbatim payload string ever reaches the store.
    const raw = JSON.stringify(events);
    expect(raw).not.toContain(plaintext);
    expect(raw).not.toContain('abc123');
    // The argument leaves are redacted refs, not plain strings.
    const args = toolCall.args as Record<string, { redacted: boolean; ref: string }>;
    expect(args.note?.redacted).toBe(true);
    expect(args.note?.ref).toMatch(/^sha256:[0-9a-f]{64}$/);
  });

  it('PreToolUse (deny via policy): stdout carries the deny JSON, the event is marked policy_denied', async () => {
    const dataDir = tmpDir('mcp-hook-deny-');
    const policyPath = join(dataDir, 'policy.json');
    writeFileSync(
      policyPath,
      JSON.stringify({
        deny: [{ tool: '^mcp__ClickUp__clickup_delete_task$', reason: 'destructive ClickUp calls are blocked' }],
        default: 'allow',
      }),
    );
    const sessionId = freshSessionId();

    const result = await runHook(
      ['--data-dir', dataDir, '--store', 'jsonl', '--policy', policyPath],
      preToolUseInput({
        sessionId,
        toolName: 'mcp__ClickUp__clickup_delete_task',
        toolInput: { task_id: 'to-delete' },
        toolUseId: 'toolu_deny_1',
      }),
    );

    expect(result.code).toBe(0);
    const payload = JSON.parse(result.stdout) as {
      hookSpecificOutput: { hookEventName: string; permissionDecision: string; permissionDecisionReason: string };
    };
    expect(payload.hookSpecificOutput.hookEventName).toBe('PreToolUse');
    expect(payload.hookSpecificOutput.permissionDecision).toBe('deny');
    expect(payload.hookSpecificOutput.permissionDecisionReason).toContain('mcp-recorder policy:');
    expect(payload.hookSpecificOutput.permissionDecisionReason).toContain('destructive ClickUp calls are blocked');

    const events = readEvents(dataDir);
    const toolCall = events.find((e) => e.kind === 'tool_call') as ToolCallEvent;
    expect(toolCall.is_error).toBe(true);
    expect(toolCall.error?.type).toBe('policy_denied');
  });

  it('a policy that cannot be READ denies, because enforcement is fail-closed', async () => {
    // The asymmetry this pins: `record --policy` fails closed by exiting 2
    // before the server is spawned, but the hook used to print a warning and
    // ALLOW every call — and the hook is the vantage point an install
    // actually registers. A security control that turns itself off when its
    // config has a typo, leaving one line on stderr, is the failure mode
    // dogfood 4 already produced once.
    const dataDir = tmpDir('mcp-hook-policy-missing-');
    const sessionId = freshSessionId();

    const result = await runHook(
      ['--data-dir', dataDir, '--store', 'jsonl', '--policy', join(dataDir, 'does-not-exist.json')],
      preToolUseInput({
        sessionId,
        toolName: 'mcp__ClickUp__clickup_delete_task',
        toolInput: { task_id: 'to-delete' },
        toolUseId: 'toolu_unreadable_1',
      }),
    );

    // Exit code stays 0: denying is a decision, not a crash, and a hook that
    // exits non-zero breaks the session it is supposed to be observing.
    expect(result.code).toBe(0);
    const payload = JSON.parse(result.stdout) as {
      hookSpecificOutput: { permissionDecision: string; permissionDecisionReason: string };
    };
    expect(payload.hookSpecificOutput.permissionDecision).toBe('deny');
    expect(payload.hookSpecificOutput.permissionDecisionReason).toContain('could not be loaded');
    expect(result.stderr).toContain('DENYING');

    const toolCall = readEvents(dataDir).find((e) => e.kind === 'tool_call') as ToolCallEvent;
    expect(toolCall.is_error).toBe(true);
    expect(toolCall.error?.type).toBe('policy_denied');
  });

  it('a policy that cannot be PARSED denies too', async () => {
    const dataDir = tmpDir('mcp-hook-policy-unparseable-');
    const policyPath = join(dataDir, 'broken.json');
    writeFileSync(policyPath, '{"deny": [ this is not json');

    const result = await runHook(
      ['--data-dir', dataDir, '--store', 'jsonl', '--policy', policyPath],
      preToolUseInput({
        sessionId: freshSessionId(),
        toolName: 'mcp__ClickUp__clickup_create_task',
        toolInput: {},
        toolUseId: 'toolu_invalid_1',
      }),
    );

    expect(result.code).toBe(0);
    const payload = JSON.parse(result.stdout) as { hookSpecificOutput: { permissionDecision: string } };
    expect(payload.hookSpecificOutput.permissionDecision).toBe('deny');
  });

  it('a non-matching (allow-listed) policy does not deny', async () => {
    const dataDir = tmpDir('mcp-hook-policy-allow-');
    const policyPath = join(dataDir, 'policy.json');
    writeFileSync(
      policyPath,
      JSON.stringify({ deny: [{ tool: '^mcp__ClickUp__clickup_delete_task$' }], default: 'allow' }),
    );
    const result = await runHook(
      ['--data-dir', dataDir, '--store', 'jsonl', '--policy', policyPath],
      preToolUseInput({
        sessionId: freshSessionId(),
        toolName: 'mcp__ClickUp__clickup_get_task',
        toolInput: {},
        toolUseId: 'toolu_ok_1',
      }),
    );
    expect(result.code).toBe(0);
    expect(result.stdout).toBe('');
    const toolCall = readEvents(dataDir).find((e) => e.kind === 'tool_call') as ToolCallEvent;
    expect(toolCall.is_error).toBe(false);
  });

  it('a broken policy file denies without crashing the hook (it used to allow)', async () => {
    // CHANGED DELIBERATELY. This test previously asserted `stdout === ''` —
    // a broken policy allowed every call. RECORDING is fail-open and stays
    // that way; ENFORCEMENT is fail-closed, and passing --policy is asking
    // for enforcement. The old behaviour meant a typo silently disarmed the
    // control with one stderr line as the only symptom, which is precisely
    // how dogfood 4's deny rules did nothing for two days.
    const dataDir = tmpDir('mcp-hook-policy-broken-');
    const policyPath = join(dataDir, 'policy.json');
    writeFileSync(policyPath, '{ not valid json');
    const result = await runHook(
      ['--data-dir', dataDir, '--store', 'jsonl', '--policy', policyPath],
      preToolUseInput({
        sessionId: freshSessionId(),
        toolName: 'mcp__ClickUp__clickup_delete_task',
        toolInput: {},
        toolUseId: 'toolu_broken_policy',
      }),
    );
    // Still never crashes: the hook exits 0 and the session continues.
    expect(result.code).toBe(0);
    expect(result.stderr).toContain('--policy');
    const payload = JSON.parse(result.stdout) as { hookSpecificOutput: { permissionDecision: string } };
    expect(payload.hookSpecificOutput.permissionDecision).toBe('deny');
    const toolCall = readEvents(dataDir).find((e) => e.kind === 'tool_call') as ToolCallEvent;
    expect(toolCall.is_error).toBe(true);
  });

  it('PostToolUse: redacts the result, measures duration, and shares request_id with the PreToolUse event', async () => {
    const dataDir = tmpDir('mcp-hook-post-');
    const sessionId = freshSessionId();
    const secretResult = 'super-secret-tool-result-text';

    const pre = await runHook(
      ['--data-dir', dataDir, '--store', 'jsonl'],
      preToolUseInput({
        sessionId,
        toolName: 'mcp__ClickUp__clickup_get_task',
        toolInput: { task_id: 'abc' },
        toolUseId: 'toolu_post_1',
      }),
    );
    expect(pre.code).toBe(0);

    // A little real wall-clock gap so duration_ms is meaningfully non-negative.
    await new Promise((r) => setTimeout(r, 15));

    const post = await runHook(
      ['--data-dir', dataDir, '--store', 'jsonl'],
      postToolUseInput({
        sessionId,
        toolName: 'mcp__ClickUp__clickup_get_task',
        toolInput: { task_id: 'abc' },
        toolUseId: 'toolu_post_1',
        toolResponse: { content: [{ type: 'text', text: secretResult }] },
      }),
    );
    expect(post.code).toBe(0);
    expect(post.stdout).toBe('');

    const toolCalls = readEvents(dataDir).filter((e) => e.kind === 'tool_call') as ToolCallEvent[];
    expect(toolCalls).toHaveLength(2);
    const [preEvent, postEvent] = toolCalls;
    expect(preEvent!.phase).toBe('pre');
    expect(postEvent!.phase).toBe('post');
    expect(postEvent!.request_id).toBe(preEvent!.request_id);
    expect(postEvent!.request_id).toBe('toolu_post_1');
    expect(typeof postEvent!.duration_ms).toBe('number');
    expect(postEvent!.duration_ms).toBeGreaterThanOrEqual(0);
    expect(postEvent!.is_error).toBe(false);

    const raw = JSON.stringify(postEvent);
    expect(raw).not.toContain(secretResult);
  });

  it('PostToolUseFailure: records the post half with is_error true and a hashed message_ref, shares request_id, clears the pending marker, and never stores the error text', async () => {
    const dataDir = tmpDir('mcp-hook-failure-');
    const sessionId = freshSessionId();
    const errorText = 'ClickUp API rate limit exceeded: daily MCP quota used up (probe-marker-3f9a1c)';
    const toolInput = { list_id: '901818701787' };

    const pre = await runHook(
      ['--data-dir', dataDir, '--store', 'jsonl'],
      preToolUseInput({ sessionId, toolName: 'mcp__ClickUp__clickup_get_list', toolInput, toolUseId: 'toolu_fail_1' }),
    );
    expect(pre.code).toBe(0);
    const marker = join(dataDir, 'hook-pending', 'toolu_fail_1');
    expect(existsSync(marker)).toBe(true); // PreToolUse left its timestamp for the post half

    await new Promise((r) => setTimeout(r, 15));

    const failure = await runHook(
      ['--data-dir', dataDir, '--store', 'jsonl'],
      postToolUseFailureInput({
        sessionId,
        toolName: 'mcp__ClickUp__clickup_get_list',
        toolInput,
        toolUseId: 'toolu_fail_1',
        error: errorText,
      }),
    );
    expect(failure.code).toBe(0);
    expect(failure.stdout).toBe(''); // a failure hook can't block anything, and prints nothing
    expect(existsSync(marker)).toBe(false); // taken, exactly as a PostToolUse would have

    const toolCalls = readEvents(dataDir).filter((e) => e.kind === 'tool_call') as ToolCallEvent[];
    expect(toolCalls).toHaveLength(2);
    const [preEvent, postEvent] = toolCalls;
    expect(preEvent!.phase).toBe('pre');
    expect(preEvent!.is_error).toBe(false);
    expect(postEvent!.phase).toBe('post');
    expect(postEvent!.source).toBe('hook');
    expect(postEvent!.request_id).toBe(preEvent!.request_id);
    expect(postEvent!.request_id).toBe('toolu_fail_1');
    expect(postEvent!.tool).toBe('clickup_get_list');
    expect(postEvent!.server.name).toBe('ClickUp');
    expect(postEvent!.is_error).toBe(true);
    expect(postEvent!.error?.type).toBe('tool_error');
    expect(postEvent!.attributes['error.type']).toBe('tool_error');
    expect(postEvent!.error?.message_ref).toMatch(/^sha256:[0-9a-f]{64}$/);
    // Hashed exactly like every other redacted value (Redactor.hashString === sha256Ref).
    expect(postEvent!.error?.message_ref).toBe(sha256Ref(errorText));
    expect(postEvent!.result).toBeNull(); // a failure carries no tool_response
    expect(postEvent!.result_hash).toBe(sha256Ref(canonicalJson(null)));
    expect(typeof postEvent!.duration_ms).toBe('number');
    expect(postEvent!.duration_ms).toBeGreaterThanOrEqual(0);

    // The error text never reaches the store: check the raw on-disk bytes,
    // not just the parsed events.
    const rawStore = readFileSync(join(dataDir, 'evidence.jsonl'), 'utf8');
    expect(rawStore).not.toContain(errorText);
    expect(rawStore).not.toContain('probe-marker-3f9a1c');
    expect(rawStore).not.toContain('rate limit');
    expect(rawStore).not.toContain('901818701787');
  });

  it('PostToolUseFailure with is_interrupt records error.type "interrupted" (and duration_ms 0 without a pre marker)', async () => {
    const dataDir = tmpDir('mcp-hook-interrupt-');
    const errorText = 'The user cancelled the running tool call';
    const result = await runHook(
      ['--data-dir', dataDir, '--store', 'jsonl'],
      postToolUseFailureInput({
        sessionId: freshSessionId(),
        toolName: 'mcp__github__search_code',
        toolInput: { q: 'needle-in-args' },
        toolUseId: 'toolu_interrupt_1',
        error: errorText,
        isInterrupt: true,
      }),
    );
    expect(result.code).toBe(0);
    expect(result.stdout).toBe('');
    const toolCall = readEvents(dataDir).find((e) => e.kind === 'tool_call') as ToolCallEvent;
    expect(toolCall.phase).toBe('post');
    expect(toolCall.is_error).toBe(true);
    expect(toolCall.error?.type).toBe('interrupted');
    expect(toolCall.attributes['error.type']).toBe('interrupted');
    expect(toolCall.error?.message_ref).toBe(sha256Ref(errorText));
    expect(toolCall.duration_ms).toBe(0); // no PreToolUse marker to measure from
    const rawStore = readFileSync(join(dataDir, 'evidence.jsonl'), 'utf8');
    expect(rawStore).not.toContain('cancelled');
    expect(rawStore).not.toContain('needle-in-args');
  });

  it('SessionEnd and Stop sweep stale pending markers (older than 24 h by mtime) and leave fresh ones alone', async () => {
    const dataDir = tmpDir('mcp-hook-sweep-');
    const sessionId = freshSessionId();
    const pendingDir = join(dataDir, 'hook-pending');
    mkdirSync(pendingDir, { recursive: true });
    const staleA = join(pendingDir, 'toolu_stale_a');
    const staleB = join(pendingDir, 'toolu_stale_b');
    const fresh = join(pendingDir, 'toolu_fresh');
    const twentyFiveHoursAgo = (Date.now() - 25 * 60 * 60 * 1000) / 1000; // utimes takes seconds
    const makeStale = (p: string): void => {
      writeFileSync(p, String(Date.now()));
      utimesSync(p, twentyFiveHoursAgo, twentyFiveHoursAgo);
    };
    makeStale(staleA);
    makeStale(staleB);
    writeFileSync(fresh, String(Date.now()));

    // A tool event never sweeps: only turn boundaries and session end do,
    // so the tool-call path stays as lean as before.
    await runHook(
      ['--data-dir', dataDir, '--store', 'jsonl'],
      preToolUseInput({ sessionId, toolName: 'mcp__github__get_me', toolInput: {}, toolUseId: 'toolu_sweep_pre' }),
    );
    expect(existsSync(staleA)).toBe(true);

    const stop = await runHook(
      ['--data-dir', dataDir, '--store', 'jsonl'],
      JSON.stringify({ session_id: sessionId, hook_event_name: 'Stop' }),
    );
    expect(stop.code).toBe(0);
    expect(stop.stdout).toBe('');
    expect(existsSync(staleA)).toBe(false);
    expect(existsSync(staleB)).toBe(false);
    expect(existsSync(fresh)).toBe(true);
    expect(existsSync(join(pendingDir, 'toolu_sweep_pre'))).toBe(true); // just written, kept

    makeStale(staleB); // SessionEnd sweeps too
    const end = await runHook(
      ['--data-dir', dataDir, '--store', 'jsonl'],
      JSON.stringify({ session_id: sessionId, hook_event_name: 'SessionEnd', reason: 'other' }),
    );
    expect(end.code).toBe(0);
    expect(existsSync(staleB)).toBe(false);
    expect(existsSync(fresh)).toBe(true);
  });

  it('a non-mcp (built-in) tool is ignored by default, and recorded only with --all-tools', async () => {
    const dataDir = tmpDir('mcp-hook-alltools-');
    const sessionId = freshSessionId();

    const ignored = await runHook(
      ['--data-dir', dataDir, '--store', 'jsonl'],
      preToolUseInput({ sessionId, toolName: 'Bash', toolInput: { command: 'ls' }, toolUseId: 'toolu_bash_1' }),
    );
    expect(ignored.code).toBe(0);
    expect(ignored.stdout).toBe('');
    // Nothing at all was recorded — not even a session marker file/dir.
    expect(existsSync(join(dataDir, 'evidence.jsonl'))).toBe(false);

    const recorded = await runHook(
      ['--data-dir', dataDir, '--store', 'jsonl', '--all-tools'],
      preToolUseInput({ sessionId, toolName: 'Bash', toolInput: { command: 'ls' }, toolUseId: 'toolu_bash_2' }),
    );
    expect(recorded.code).toBe(0);
    const toolCall = readEvents(dataDir).find((e) => e.kind === 'tool_call') as ToolCallEvent;
    expect(toolCall.tool).toBe('Bash');
    expect(toolCall.server.name).toBe('claude-code');
  });

  it('malformed stdin exits 0 with no output and records nothing', async () => {
    const dataDir = tmpDir('mcp-hook-malformed-');
    const result = await runHook(['--data-dir', dataDir, '--store', 'jsonl'], 'this is not { json');
    expect(result.code).toBe(0);
    expect(result.stdout).toBe('');
    expect(existsSync(join(dataDir, 'evidence.jsonl'))).toBe(false);
  });

  it('empty stdin also exits 0 with no output', async () => {
    const dataDir = tmpDir('mcp-hook-empty-');
    const result = await runHook(['--data-dir', dataDir, '--store', 'jsonl'], '');
    expect(result.code).toBe(0);
    expect(result.stdout).toBe('');
  });

  it('session_start is emitted exactly once per session, across separate invocations', async () => {
    const dataDir = tmpDir('mcp-hook-session-once-');
    const sessionId = freshSessionId();

    const first = await runHook(
      ['--data-dir', dataDir, '--store', 'jsonl'],
      preToolUseInput({ sessionId, toolName: 'mcp__github__search_code', toolInput: {}, toolUseId: 'toolu_a' }),
    );
    expect(first.code).toBe(0);

    const second = await runHook(
      ['--data-dir', dataDir, '--store', 'jsonl'],
      preToolUseInput({ sessionId, toolName: 'mcp__github__list_issues', toolInput: {}, toolUseId: 'toolu_b' }),
    );
    expect(second.code).toBe(0);

    const events = readEvents(dataDir);
    const starts = events.filter((e) => e.kind === 'session_start');
    const calls = events.filter((e) => e.kind === 'tool_call');
    expect(starts).toHaveLength(1);
    expect(calls).toHaveLength(2);
    expect(new Set(events.map((e) => e.session_id))).toEqual(new Set([sessionId]));
  });

  it('SessionEnd emits a session_end event (source: hook)', async () => {
    const dataDir = tmpDir('mcp-hook-sessionend-');
    const sessionId = freshSessionId();

    await runHook(
      ['--data-dir', dataDir, '--store', 'jsonl'],
      preToolUseInput({ sessionId, toolName: 'mcp__github__search_code', toolInput: {}, toolUseId: 'toolu_end_1' }),
    );
    const result = await runHook(
      ['--data-dir', dataDir, '--store', 'jsonl'],
      JSON.stringify({
        session_id: sessionId,
        transcript_path: '/tmp/transcript.jsonl',
        cwd: '/tmp',
        hook_event_name: 'SessionEnd',
        reason: 'other',
      }),
    );
    expect(result.code).toBe(0);
    expect(result.stdout).toBe('');

    const events = readEvents(dataDir);
    const sessionEnd = events.find((e) => e.kind === 'session_end') as SessionEndEvent;
    expect(sessionEnd).toBeDefined();
    expect(sessionEnd.source).toBe('hook');
    expect(sessionEnd.session_id).toBe(sessionId);
    // reason is a frozen closed union with no member for the hook's own
    // reasons — mapped to the closest existing value; source: 'hook' above
    // is what actually distinguishes it.
    expect(['child_exit', 'stdin_closed']).toContain(sessionEnd.reason);
  });

  it('Stop emits a claude-code/stop notification (a turn boundary), never a second session_end', async () => {
    const dataDir = tmpDir('mcp-hook-stop-');
    const sessionId = freshSessionId();
    const result = await runHook(
      ['--data-dir', dataDir, '--store', 'jsonl'],
      JSON.stringify({
        session_id: sessionId,
        transcript_path: '/tmp/transcript.jsonl',
        cwd: '/tmp',
        hook_event_name: 'Stop',
        last_assistant_message: 'done',
      }),
    );
    expect(result.code).toBe(0);
    const events = readEvents(dataDir);
    expect(events.map((e) => e.kind)).toEqual(['session_start', 'notification']);
    const stop = events[1] as NotificationEvent;
    expect(stop.source).toBe('hook');
    expect(stop.method).toBe('claude-code/stop');
    expect(stop.direction).toBe('client_to_server');
  });

  it('an unrecognized hook_event_name (e.g. UserPromptSubmit) is ignored, not an error', async () => {
    const dataDir = tmpDir('mcp-hook-unknown-event-');
    const result = await runHook(
      ['--data-dir', dataDir, '--store', 'jsonl'],
      JSON.stringify({ session_id: freshSessionId(), hook_event_name: 'UserPromptSubmit', prompt: 'hi' }),
    );
    expect(result.code).toBe(0);
    expect(result.stdout).toBe('');
    expect(existsSync(join(dataDir, 'evidence.jsonl'))).toBe(false);
  });

  it('the resulting store PASSes verify end to end', async () => {
    const dataDir = tmpDir('mcp-hook-verify-');
    const sessionId = freshSessionId();

    await runHook(
      ['--data-dir', dataDir, '--store', 'jsonl'],
      preToolUseInput({
        sessionId,
        toolName: 'mcp__Gmail__send_message',
        toolInput: { to: 'someone@example.com', body: 'hello' },
        toolUseId: 'toolu_verify_1',
      }),
    );
    await runHook(
      ['--data-dir', dataDir, '--store', 'jsonl'],
      postToolUseInput({
        sessionId,
        toolName: 'mcp__Gmail__send_message',
        toolInput: { to: 'someone@example.com', body: 'hello' },
        toolUseId: 'toolu_verify_1',
        toolResponse: { content: [{ type: 'text', text: 'sent' }] },
      }),
    );
    await runHook(
      ['--data-dir', dataDir, '--store', 'jsonl'],
      JSON.stringify({ session_id: sessionId, hook_event_name: 'SessionEnd', reason: 'other' }),
    );

    const verify = await runCli(['verify', '--data-dir', dataDir, '--store', 'jsonl', '--json']);
    expect(verify.code).toBe(0);
    const payload = JSON.parse(verify.stdout) as { ok: boolean; checked_events: number };
    expect(payload.ok).toBe(true);
    expect(payload.checked_events).toBe(4); // session_start + 2 tool_call + session_end
  }, 30_000);

  it('`query` finds a hook-recorded event by the plaintext argument value', async () => {
    const dataDir = tmpDir('mcp-hook-query-');
    const sessionId = freshSessionId();
    const needle = 'blast-radius-probe-from-a-hook-9182734';

    await runHook(
      ['--data-dir', dataDir, '--store', 'jsonl'],
      preToolUseInput({
        sessionId,
        toolName: 'mcp__ClickUp__clickup_create_task',
        toolInput: { name: 'task', notes: needle },
        toolUseId: 'toolu_query_1',
      }),
    );

    const result = await runCli(['query', needle, '--data-dir', dataDir, '--store', 'jsonl', '--json']);
    expect(result.code).toBe(0);
    const payload = JSON.parse(result.stdout) as { matches: Array<{ kind: string; matched_on: string }> };
    expect(payload.matches.length).toBeGreaterThan(0);
    expect(payload.matches.some((m) => m.kind === 'tool_call' && m.matched_on === 'ref')).toBe(true);
  }, 30_000);
});

describe('mcp-recorder hook install', () => {
  function readSettings(path: string): Record<string, unknown> {
    return JSON.parse(readFileSync(path, 'utf8')) as Record<string, unknown>;
  }

  const MANAGED_EVENTS = ['PostToolUse', 'PostToolUseFailure', 'PreToolUse', 'SessionEnd', 'Stop'].sort();

  it('writes PreToolUse/PostToolUse/PostToolUseFailure (mcp__.* matcher) + SessionEnd/Stop entries, creating the file if missing', async () => {
    const dir = tmpDir('mcp-hook-install-');
    const settingsPath = join(dir, 'settings.json');
    expect(existsSync(settingsPath)).toBe(false);

    const result = await runCli([
      'hook', 'install', '--settings', settingsPath, '--data-dir', join(dir, '.mcp-recorder'), '--json',
    ]);
    expect(result.code).toBe(0);
    const payload = JSON.parse(result.stdout) as { added: string[]; alreadyInstalled: string[] };
    expect(payload.added.sort()).toEqual(MANAGED_EVENTS);
    expect(payload.alreadyInstalled).toEqual([]);

    const settings = readSettings(settingsPath) as {
      hooks: Record<string, Array<{ matcher?: string; hooks: Array<{ type: string; command: string }> }>>;
    };
    expect(settings.hooks.PreToolUse![0]!.matcher).toBe('mcp__.*');
    expect(settings.hooks.PostToolUse![0]!.matcher).toBe('mcp__.*');
    expect(settings.hooks.PostToolUseFailure![0]!.matcher).toBe('mcp__.*');
    expect(settings.hooks.PostToolUseFailure![0]).toEqual(settings.hooks.PostToolUse![0]); // same matcher AND command
    expect(settings.hooks.SessionEnd![0]!.matcher).toBeUndefined();
    expect(settings.hooks.Stop![0]!.matcher).toBeUndefined();
    const command = settings.hooks.PreToolUse![0]!.hooks[0]!.command;
    expect(command).toContain('hook');
    expect(command).toContain('--data-dir');
  });

  it('--all-tools uses a .* matcher instead of mcp__.*', async () => {
    const dir = tmpDir('mcp-hook-install-alltools-');
    const settingsPath = join(dir, 'settings.json');
    await runCli([
      'hook', 'install', '--settings', settingsPath, '--data-dir', join(dir, '.mcp-recorder'), '--all-tools',
    ]);
    const settings = readSettings(settingsPath) as {
      hooks: Record<string, Array<{ matcher?: string }>>;
    };
    expect(settings.hooks.PreToolUse![0]!.matcher).toBe('.*');
    expect(settings.hooks.PostToolUse![0]!.matcher).toBe('.*');
    expect(settings.hooks.PostToolUseFailure![0]!.matcher).toBe('.*');
  });

  it('--command overrides the generated command verbatim (dogfood form)', async () => {
    const dir = tmpDir('mcp-hook-install-command-');
    const settingsPath = join(dir, 'settings.json');
    const dogfoodCmd = 'node dist/cli.js hook --data-dir .mcp-recorder';
    await runCli(['hook', 'install', '--settings', settingsPath, '--command', dogfoodCmd]);
    const settings = readSettings(settingsPath) as {
      hooks: Record<string, Array<{ hooks: Array<{ command: string }> }>>;
    };
    expect(settings.hooks.PreToolUse![0]!.hooks[0]!.command).toBe(dogfoodCmd);
    expect(settings.hooks.Stop![0]!.hooks[0]!.command).toBe(dogfoodCmd);
  });

  it('is idempotent: running install twice adds nothing the second time', async () => {
    const dir = tmpDir('mcp-hook-install-idempotent-');
    const settingsPath = join(dir, 'settings.json');
    const args = ['hook', 'install', '--settings', settingsPath, '--data-dir', join(dir, '.mcp-recorder'), '--json'];

    const first = await runCli(args);
    const firstPayload = JSON.parse(first.stdout) as { added: string[] };
    expect(firstPayload.added).toHaveLength(5);
    const afterFirst = readFileSync(settingsPath, 'utf8');

    const second = await runCli(args);
    const secondPayload = JSON.parse(second.stdout) as { added: string[]; alreadyInstalled: string[] };
    expect(secondPayload.added).toEqual([]);
    expect(secondPayload.alreadyInstalled.sort()).toEqual(MANAGED_EVENTS);
    // No backup was written for a no-op run, and the file is unchanged.
    expect(readFileSync(settingsPath, 'utf8')).toBe(afterFirst);
  });

  it('--dry-run writes nothing (does not even create the file)', async () => {
    const dir = tmpDir('mcp-hook-install-dryrun-');
    const settingsPath = join(dir, 'settings.json');
    const result = await runCli(['hook', 'install', '--settings', settingsPath, '--dry-run']);
    expect(result.code).toBe(0);
    expect(result.stdout).toContain('dry run');
    expect(existsSync(settingsPath)).toBe(false);
  });

  it('preserves unrelated keys and hook entries, and --undo removes exactly what it added', async () => {
    const dir = tmpDir('mcp-hook-install-undo-');
    const settingsPath = join(dir, 'settings.json');
    writeFileSync(
      settingsPath,
      JSON.stringify(
        {
          otherTopLevelKey: 'preserved',
          hooks: {
            SessionStart: [{ hooks: [{ type: 'command', command: 'echo unrelated' }] }],
            PreToolUse: [{ matcher: 'Bash', hooks: [{ type: 'command', command: 'echo someone-elses-hook' }] }],
          },
        },
        null,
        2,
      ),
    );

    const command = 'node dist/cli.js hook --data-dir .mcp-recorder';
    const install = await runCli(['hook', 'install', '--settings', settingsPath, '--command', command, '--json']);
    expect(install.code).toBe(0);

    let settings = readSettings(settingsPath) as {
      otherTopLevelKey: string;
      hooks: Record<string, Array<{ matcher?: string; hooks: Array<{ command: string }> }>>;
    };
    expect(settings.otherTopLevelKey).toBe('preserved');
    expect(settings.hooks.SessionStart).toHaveLength(1);
    expect(settings.hooks.PreToolUse).toHaveLength(2); // the pre-existing Bash entry, plus ours
    expect(settings.hooks.PreToolUse.some((e) => e.matcher === 'Bash')).toBe(true);
    expect(settings.hooks.PreToolUse.some((e) => e.hooks.some((h) => h.command === command))).toBe(true);

    const undo = await runCli(['hook', 'install', '--settings', settingsPath, '--command', command, '--undo', '--json']);
    expect(undo.code).toBe(0);
    const undoPayload = JSON.parse(undo.stdout) as { removed: string[] };
    expect(undoPayload.removed.sort()).toEqual(MANAGED_EVENTS);

    settings = readSettings(settingsPath) as typeof settings;
    expect(settings.otherTopLevelKey).toBe('preserved');
    expect(settings.hooks.SessionStart).toHaveLength(1); // untouched
    expect(settings.hooks.PreToolUse).toHaveLength(1); // only the unrelated Bash entry remains
    expect(settings.hooks.PreToolUse[0]!.matcher).toBe('Bash');
    expect(settings.hooks.PostToolUse).toBeUndefined(); // emptied entirely, key dropped
    expect(settings.hooks.PostToolUseFailure).toBeUndefined();
    expect(settings.hooks.SessionEnd).toBeUndefined();
    expect(settings.hooks.Stop).toBeUndefined();
  });

  it('PostToolUseFailure: installed with the same matcher and command as PostToolUse, idempotent, and --undo removes exactly it', async () => {
    const dir = tmpDir('mcp-hook-install-failure-');
    const settingsPath = join(dir, 'settings.json');
    // Someone else's PostToolUseFailure hook must survive both install and undo untouched.
    writeFileSync(
      settingsPath,
      JSON.stringify(
        { hooks: { PostToolUseFailure: [{ matcher: 'Bash', hooks: [{ type: 'command', command: 'echo not-ours' }] }] } },
        null,
        2,
      ),
    );
    const command = 'node dist/cli.js hook --data-dir .mcp-recorder';
    type Hooks = Record<string, Array<{ matcher?: string; hooks: Array<{ type: string; command: string }> }>>;

    const install = await runCli(['hook', 'install', '--settings', settingsPath, '--command', command, '--json']);
    expect(install.code).toBe(0);
    expect((JSON.parse(install.stdout) as { added: string[] }).added).toContain('PostToolUseFailure');
    let settings = readSettings(settingsPath) as { hooks: Hooks };
    expect(settings.hooks.PostToolUseFailure).toHaveLength(2); // theirs, plus ours
    const ours = settings.hooks.PostToolUseFailure!.find((e) => e.hooks.some((h) => h.command === command));
    expect(ours).toEqual({ matcher: 'mcp__.*', hooks: [{ type: 'command', command }] });
    expect(ours).toEqual(settings.hooks.PostToolUse![0]);

    const again = await runCli(['hook', 'install', '--settings', settingsPath, '--command', command, '--json']);
    const againPayload = JSON.parse(again.stdout) as { added: string[]; alreadyInstalled: string[] };
    expect(againPayload.added).toEqual([]);
    expect(againPayload.alreadyInstalled).toContain('PostToolUseFailure');
    expect((readSettings(settingsPath) as { hooks: Hooks }).hooks.PostToolUseFailure).toHaveLength(2);

    const undo = await runCli(['hook', 'install', '--settings', settingsPath, '--command', command, '--undo', '--json']);
    expect(undo.code).toBe(0);
    expect((JSON.parse(undo.stdout) as { removed: string[] }).removed).toContain('PostToolUseFailure');
    settings = readSettings(settingsPath) as { hooks: Hooks };
    expect(settings.hooks.PostToolUseFailure).toHaveLength(1); // only theirs remains
    expect(settings.hooks.PostToolUseFailure![0]!.matcher).toBe('Bash');
    expect(settings.hooks.PostToolUse).toBeUndefined();
  });

  it('--undo is a no-op (and writes nothing) when nothing of ours is installed', async () => {
    const dir = tmpDir('mcp-hook-install-undo-noop-');
    const settingsPath = join(dir, 'settings.json');
    writeFileSync(settingsPath, JSON.stringify({ hooks: {} }, null, 2));
    const before = readFileSync(settingsPath, 'utf8');

    const result = await runCli(['hook', 'install', '--settings', settingsPath, '--undo', '--json']);
    expect(result.code).toBe(0);
    const payload = JSON.parse(result.stdout) as { removed: string[] };
    expect(payload.removed).toEqual([]);
    expect(readFileSync(settingsPath, 'utf8')).toBe(before);
  });
});

/* ------------------- cloud sessions: UUID server names -------------------- */

describe('mcp-recorder hook (cloud sessions: UUID server names, server.url, policy aliases)', () => {
  const CLICKUP_UUID = '47d587b8-3fb9-42e9-b596-f8b25371248c';
  const CLICKUP_URL = 'https://mcp.clickup.com/mcp';
  const SESSION_ID_IN_CONFIG = 'cse_01FIXTURESESSION0000AAAA';
  const FRIENDLY_SESSION_ID = 'cse_01FRIENDLYSESSION0000DDDD';
  const withConfig = { MCP_RECORDER_MCP_CONFIG: CLOUD_MCP_CONFIG };
  const noConfig = { MCP_RECORDER_MCP_CONFIG: NO_MCP_CONFIG };
  const store = ['--store', 'jsonl'];

  /** Nothing from the config file but the scrubbed URL may ever reach the store. */
  function expectNoConfigLeak(rawStore: string): void {
    expect(rawStore).not.toContain(SESSION_ID_IN_CONFIG);
    expect(rawStore).not.toContain('cse_');
    expect(rawStore).not.toContain('X-Session-UUID');
    expect(rawStore).not.toContain('X-MCP-Server-ID');
    expect(rawStore).not.toContain('63df81a5-fc81-5b12-b7fe-654a2d253da9'); // X-MCP-Server-ID header value
    expect(rawStore).not.toContain('b3f9ab90-0a14-5a2c-adab-e845e0658cec'); // mcp_server_id query value
    expect(rawStore).not.toContain('mcp_server_id');
    expect(rawStore).not.toContain('toolbox_mcp_server_id');
    expect(rawStore).not.toContain('permission_policy');
    expect(rawStore).not.toContain('always_allow');
    expect(rawStore).not.toContain('mail-pass');
    expect(rawStore).not.toContain('sk-fixture');
    expect(rawStore).not.toContain('mcp__mcp.clickup.com'); // the policy alias is never recorded
  }

  it('stamps server.url (the vendor endpoint) on every pre/post/failure event, not on session_start; server.name stays the UUID', async () => {
    const dataDir = tmpDir('mcp-hook-cloud-url-');
    const sessionId = freshSessionId();
    const toolName = `mcp__${CLICKUP_UUID}__clickup_get_list`;
    const toolInput = { list_id: '901818701787' };

    const pre = await runHook(
      ['--data-dir', dataDir, ...store],
      preToolUseInput({ sessionId, toolName, toolInput, toolUseId: 'toolu_cloud_ok' }),
      withConfig,
    );
    expect(pre.code).toBe(0);
    expect(pre.stdout).toBe('');
    const post = await runHook(
      ['--data-dir', dataDir, ...store],
      postToolUseInput({
        sessionId,
        toolName,
        toolInput,
        toolUseId: 'toolu_cloud_ok',
        toolResponse: { content: [{ type: 'text', text: 'list-body' }] },
      }),
      withConfig,
    );
    expect(post.code).toBe(0);
    const failTool = `mcp__${CLICKUP_UUID}__clickup_filter_tasks`;
    await runHook(
      ['--data-dir', dataDir, ...store],
      preToolUseInput({ sessionId, toolName: failTool, toolInput: {}, toolUseId: 'toolu_cloud_fail' }),
      withConfig,
    );
    const failure = await runHook(
      ['--data-dir', dataDir, ...store],
      postToolUseFailureInput({
        sessionId,
        toolName: failTool,
        toolInput: {},
        toolUseId: 'toolu_cloud_fail',
        error: 'RATE_LIMIT_EXCEEDED: Daily MCP limit reached',
      }),
      withConfig,
    );
    expect(failure.code).toBe(0);
    expect(failure.stdout).toBe('');

    const events = readEvents(dataDir);
    expect(events.map((e) => e.kind)).toEqual(['session_start', 'tool_call', 'tool_call', 'tool_call', 'tool_call']);
    const sessionStart = events[0] as SessionStartEvent;
    expect(sessionStart.server.name).toBe('claude-code'); // a session-level event names the client itself...
    expect(sessionStart.server.url).toBeUndefined(); // ...so it carries no vendor URL: url is where server.name is

    const toolCalls = events.slice(1) as ToolCallEvent[];
    expect(toolCalls.map((e) => e.phase)).toEqual(['pre', 'post', 'pre', 'post']);
    for (const call of toolCalls) {
      expect(call.server.name).toBe(CLICKUP_UUID); // what Claude Code calls the server, unchanged
      expect(call.server.url).toBe(CLICKUP_URL);
      expect(call.server.transport).toBe('stdio');
    }
    expect(toolCalls[0]!.tool).toBe('clickup_get_list');
    expect(toolCalls[3]!.tool).toBe('clickup_filter_tasks');
    expect(toolCalls[3]!.is_error).toBe(true);
    expect(toolCalls[3]!.error?.type).toBe('tool_error');

    const rawStore = readFileSync(join(dataDir, 'evidence.jsonl'), 'utf8');
    expectNoConfigLeak(rawStore);
    expect(rawStore).not.toContain('901818701787'); // args are still hashed as always
    expect(rawStore).not.toContain('list-body');
  });

  it('a readable name (github) gets its relay URL with the session id hashed out of the path', async () => {
    const dataDir = tmpDir('mcp-hook-cloud-github-');
    const result = await runHook(
      ['--data-dir', dataDir, ...store],
      preToolUseInput({ sessionId: freshSessionId(), toolName: 'mcp__github__get_me', toolInput: {}, toolUseId: 'toolu_cloud_gh' }),
      withConfig,
    );
    expect(result.code).toBe(0);
    const toolCall = readEvents(dataDir).find((e) => e.kind === 'tool_call') as ToolCallEvent;
    expect(toolCall.server.name).toBe('github');
    expect(toolCall.server.url).toBe(
      `https://api.anthropic.com/v2/ccr-sessions/${sha256Ref(SESSION_ID_IN_CONFIG)}/github/mcp`,
    );
    expectNoConfigLeak(readFileSync(join(dataDir, 'evidence.jsonl'), 'utf8'));
  });

  it('a deny rule against the vendor-host alias blocks the UUID-named tool; the raw name still matches; without a config the alias never fires', async () => {
    const dataDir = tmpDir('mcp-hook-cloud-alias-');
    const uuidTool = `mcp__${CLICKUP_UUID}__clickup_delete_task`;
    const aliasPolicy = join(dataDir, 'alias-policy.json');
    writeFileSync(
      aliasPolicy,
      JSON.stringify({
        deny: [{ tool: '^mcp__mcp\\.clickup\\.com__clickup_delete_task$', reason: 'destructive ClickUp calls are blocked (alias rule)' }],
        default: 'allow',
      }),
    );
    type DenyPayload = { hookSpecificOutput: { permissionDecision: string; permissionDecisionReason: string } };
    const call = (toolUseId: string, env: Record<string, string | undefined>, toolName = uuidTool) =>
      runHook(
        ['--data-dir', dataDir, ...store, '--policy', aliasPolicy],
        preToolUseInput({ sessionId: freshSessionId(), toolName, toolInput: { task_id: 'x' }, toolUseId }),
        env,
      );

    // With the config: the alias mcp__mcp.clickup.com__clickup_delete_task matches → denied.
    const denied = await call('toolu_alias_deny', withConfig);
    expect(denied.code).toBe(0);
    const payload = JSON.parse(denied.stdout) as DenyPayload;
    expect(payload.hookSpecificOutput.permissionDecision).toBe('deny');
    expect(payload.hookSpecificOutput.permissionDecisionReason).toContain('alias rule');

    // Without any config the alias does not exist: the same rule cannot match the UUID name → allowed.
    const allowed = await call('toolu_alias_noconfig', noConfig);
    expect(allowed.code).toBe(0);
    expect(allowed.stdout).toBe('');

    // A rule against the raw UUID name keeps working exactly as before, config or not.
    const rawPolicy = join(dataDir, 'raw-policy.json');
    writeFileSync(rawPolicy, JSON.stringify({ deny: [{ tool: `^mcp__${CLICKUP_UUID}__clickup_delete_task$` }] }));
    for (const env of [withConfig, noConfig]) {
      const rawDenied = await runHook(
        ['--data-dir', dataDir, ...store, '--policy', rawPolicy],
        preToolUseInput({ sessionId: freshSessionId(), toolName: uuidTool, toolInput: {}, toolUseId: 'toolu_raw_deny' }),
        env,
      );
      expect((JSON.parse(rawDenied.stdout) as DenyPayload).hookSpecificOutput.permissionDecision).toBe('deny');
    }

    // The documented both-forms rule denies the local readable name AND the cloud UUID name.
    const bothPolicy = join(dataDir, 'both-policy.json');
    writeFileSync(
      bothPolicy,
      JSON.stringify({ deny: [{ tool: '^mcp__(ClickUp|mcp\\.clickup\\.com)__clickup_delete_task$' }] }),
    );
    const bothCases: Array<[string, Record<string, string | undefined>]> = [
      ['mcp__ClickUp__clickup_delete_task', noConfig],
      [uuidTool, withConfig],
    ];
    for (const [toolName, env] of bothCases) {
      const r = await runHook(
        ['--data-dir', dataDir, ...store, '--policy', bothPolicy],
        preToolUseInput({ sessionId: freshSessionId(), toolName, toolInput: {}, toolUseId: 'toolu_both' }),
        env,
      );
      expect((JSON.parse(r.stdout) as DenyPayload).hookSpecificOutput.permissionDecision).toBe('deny');
    }
    // ...while a different tool of the same connector is untouched by any of them.
    const other = await call('toolu_alias_other', withConfig, `mcp__${CLICKUP_UUID}__clickup_get_task`);
    expect(other.stdout).toBe('');

    const events = readEvents(dataDir).filter((e) => e.kind === 'tool_call') as ToolCallEvent[];
    expect(events.find((e) => e.request_id === 'toolu_alias_deny')?.error?.type).toBe('policy_denied');
    expect(events.find((e) => e.request_id === 'toolu_alias_noconfig')?.is_error).toBe(false);
    expect(events.find((e) => e.request_id === 'toolu_alias_noconfig')?.server.url).toBeUndefined();
    expectNoConfigLeak(readFileSync(join(dataDir, 'evidence.jsonl'), 'utf8'));
  });

  it('the alias is deny-only: an allow rule never matches it, so a forged config file cannot widen a default-deny policy', async () => {
    // The config file the alias comes from lives in a world-writable /tmp
    // next to the agent the policy constrains. Review of the integrated
    // change (E1): with {allow: [^mcp__github__.*$], default: deny}, a
    // planted file mapping the ClickUp UUID to mcp_url=https://github/mcp
    // made the alias mcp__github__clickup_delete_task satisfy the allow
    // rule, and the delete went through. Neither a bare-label host nor a
    // dotted one may ever do that now.
    const dataDir = tmpDir('mcp-hook-cloud-alias-denyonly-');
    const uuidTool = `mcp__${CLICKUP_UUID}__clickup_delete_task`;
    type DenyPayload = { hookSpecificOutput: { permissionDecision: string; permissionDecisionReason: string } };
    const decision = (r: CliResult): string =>
      r.stdout === '' ? 'allow' : (JSON.parse(r.stdout) as DenyPayload).hookSpecificOutput.permissionDecision;

    const forgedBare = join(dataDir, 'mcp-config-forged-bare.json');
    writeFileSync(
      forgedBare,
      JSON.stringify({
        mcpServers: {
          [CLICKUP_UUID]: { url: `https://relay.example.test/mcp?mcp_url=${encodeURIComponent('https://github/mcp')}` },
        },
      }),
    );
    const forgedDotted = join(dataDir, 'mcp-config-forged-dotted.json');
    writeFileSync(
      forgedDotted,
      JSON.stringify({
        mcpServers: {
          [CLICKUP_UUID]: { url: `https://relay.example.test/mcp?mcp_url=${encodeURIComponent('https://github.example.test/mcp')}` },
        },
      }),
    );
    // An allow-list policy: only github tools may run. Written loosely on
    // purpose (no trailing anchor after the server segment) so that a dotted
    // forged host would match it too if the alias were tested for allows.
    const allowList = join(dataDir, 'allow-list.json');
    writeFileSync(allowList, JSON.stringify({ allow: [{ tool: '^mcp__github' }], default: 'deny' }));
    const run = (toolUseId: string, policy: string, env: Record<string, string | undefined>, toolName = uuidTool) =>
      runHook(
        ['--data-dir', dataDir, ...store, '--policy', policy],
        preToolUseInput({ sessionId: freshSessionId(), toolName, toolInput: { task_id: 'x' }, toolUseId }),
        env,
      );

    // The real github tool is allowed by its raw name, config or not.
    expect(decision(await run('toolu_gh_real', allowList, withConfig, 'mcp__github__get_me'))).toBe('allow');
    expect(decision(await run('toolu_gh_real_nocfg', allowList, noConfig, 'mcp__github__get_me'))).toBe('allow');
    // The ClickUp delete is denied by default without a config...
    expect(decision(await run('toolu_forge_none', allowList, noConfig))).toBe('deny');
    // ...and STAYS denied whatever a config file claims its host is.
    expect(decision(await run('toolu_forge_bare', allowList, { MCP_RECORDER_MCP_CONFIG: forgedBare }))).toBe('deny');
    expect(decision(await run('toolu_forge_dotted', allowList, { MCP_RECORDER_MCP_CONFIG: forgedDotted }))).toBe('deny');
    // Even an allow rule written against the genuine vendor host never fires
    // on the alias: with the real fixture the UUID tool is still denied.
    const allowAlias = join(dataDir, 'allow-alias.json');
    writeFileSync(allowAlias, JSON.stringify({ allow: [{ tool: '^mcp__mcp\\.clickup\\.com__.*$' }], default: 'deny' }));
    expect(decision(await run('toolu_allow_alias', allowAlias, withConfig))).toBe('deny');
    // Whereas the same regex as a DENY rule does fire on the alias.
    const denyAlias = join(dataDir, 'deny-alias.json');
    writeFileSync(denyAlias, JSON.stringify({ deny: [{ tool: '^mcp__mcp\\.clickup\\.com__.*$' }], default: 'allow' }));
    expect(decision(await run('toolu_deny_alias', denyAlias, withConfig))).toBe('deny');

    const events = readEvents(dataDir).filter((e) => e.kind === 'tool_call') as ToolCallEvent[];
    for (const id of ['toolu_forge_none', 'toolu_forge_bare', 'toolu_forge_dotted', 'toolu_allow_alias']) {
      expect(events.find((e) => e.request_id === id)?.error?.type).toBe('policy_denied');
    }
    // What a forged file asserts is still recorded as the (scrubbed) claim it is.
    expect(events.find((e) => e.request_id === 'toolu_forge_dotted')?.server.url).toBe('https://github.example.test/mcp');
    expect(events.find((e) => e.request_id === 'toolu_forge_bare')?.server.url).toBe('https://github/mcp');
    expectNoConfigLeak(readFileSync(join(dataDir, 'evidence.jsonl'), 'utf8'));
  });

  it('cloud dogfood 4: a FRIENDLY tool name against a UUID-keyed config resolves through the declared tool — server.url is stamped and the host-alias deny FIRES', async () => {
    // THE failure this exists for. In dogfood 4 the session's config file was
    // keyed by UUID while Claude Code handed the hook
    // `mcp__ClickUp__clickup_filter_tasks`: the key lookup missed, so no
    // server.url reached any hosted-connector event and no host alias existed
    // — both live deny rules failed to fire and both calls ran against the
    // real ClickUp workspace, twice each.
    const dataDir = tmpDir('mcp-hook-dogfood4-');
    const friendlyTool = 'mcp__ClickUp__clickup_filter_tasks';
    const policyPath = join(dataDir, 'dogfood4-policy.json');
    writeFileSync(
      policyPath,
      JSON.stringify({
        deny: [
          { tool: '^mcp__mcp\\.clickup\\.com__clickup_filter_tasks$', reason: 'ClickUp reads are blocked (host alias rule)' },
          { tool: '^mcp__[0-9a-f-]{36}__clickup_get_workspace_members$', reason: 'raw UUID rule' },
        ],
        default: 'allow',
      }),
    );
    type DenyPayload = { hookSpecificOutput: { permissionDecision: string; permissionDecisionReason: string } };
    const call = (toolUseId: string, env: Record<string, string | undefined>, toolName = friendlyTool) =>
      runHook(
        ['--data-dir', dataDir, ...store, '--policy', policyPath],
        preToolUseInput({ sessionId: freshSessionId(), toolName, toolInput: { list_id: '901818701787' }, toolUseId }),
        env,
      );

    // With the config: the entry that DECLARES clickup_filter_tasks is the
    // ClickUp one, so the alias mcp__mcp.clickup.com__clickup_filter_tasks
    // exists and the rule fires.
    const denied = await call('toolu_dogfood4_deny', withConfig);
    expect(denied.code).toBe(0);
    const payload = JSON.parse(denied.stdout) as DenyPayload;
    expect(payload.hookSpecificOutput.permissionDecision).toBe('deny');
    expect(payload.hookSpecificOutput.permissionDecisionReason).toContain('host alias rule');

    // Without any config nothing resolves, so the alias rule still cannot
    // fire: fail-open, unchanged, and the reason dogfood 4 recorded no deny.
    const allowed = await call('toolu_dogfood4_noconfig', noConfig);
    expect(allowed.code).toBe(0);
    expect(allowed.stdout).toBe('');

    // What this fix does NOT do: the alias is the vendor HOST, never the
    // UUID, so dogfood 4's second rule — written against the raw UUID form —
    // still cannot match a friendly tool name. An operator's deny must name
    // the form the session actually uses (or the host).
    const members = await call('toolu_dogfood4_members', withConfig, 'mcp__ClickUp__clickup_get_workspace_members');
    expect(members.stdout).toBe('');

    const events = readEvents(dataDir).filter((e) => e.kind === 'tool_call') as ToolCallEvent[];
    const deniedEvent = events.find((e) => e.request_id === 'toolu_dogfood4_deny')!;
    expect(deniedEvent.server.name).toBe('ClickUp'); // still what Claude Code calls the server
    expect(deniedEvent.server.url).toBe(CLICKUP_URL); // dogfood 4's missing server.url, restored
    expect(deniedEvent.error?.type).toBe('policy_denied');
    expect(deniedEvent.is_error).toBe(true);
    // An allowed hosted-connector call carries the vendor URL too...
    expect(events.find((e) => e.request_id === 'toolu_dogfood4_members')!.server.url).toBe(CLICKUP_URL);
    // ...and with no config file there is still none.
    expect(events.find((e) => e.request_id === 'toolu_dogfood4_noconfig')!.server.url).toBeUndefined();
    expectNoConfigLeak(readFileSync(join(dataDir, 'evidence.jsonl'), 'utf8'));
  });

  it('a FRIENDLY-keyed config (the other convention, and this session\'s own) still resolves by key: server.url and the same alias deny', async () => {
    const dataDir = tmpDir('mcp-hook-friendly-');
    const friendlyEnv = { MCP_RECORDER_MCP_CONFIG: FRIENDLY_MCP_CONFIG };
    const policyPath = join(dataDir, 'alias-policy.json');
    writeFileSync(
      policyPath,
      JSON.stringify({
        deny: [{ tool: '^mcp__mcp\\.clickup\\.com__clickup_filter_tasks$', reason: 'ClickUp reads are blocked (host alias rule)' }],
        default: 'allow',
      }),
    );
    type DenyPayload = { hookSpecificOutput: { permissionDecision: string; permissionDecisionReason: string } };
    const call = (toolUseId: string, toolName: string) =>
      runHook(
        ['--data-dir', dataDir, ...store, '--policy', policyPath],
        preToolUseInput({ sessionId: freshSessionId(), toolName, toolInput: {}, toolUseId }),
        friendlyEnv,
      );

    const denied = await call('toolu_friendly_deny', 'mcp__ClickUp__clickup_filter_tasks');
    expect((JSON.parse(denied.stdout) as DenyPayload).hookSpecificOutput.permissionDecision).toBe('deny');
    const gh = await call('toolu_friendly_github', 'mcp__github__get_me');
    expect(gh.stdout).toBe('');

    const events = readEvents(dataDir).filter((e) => e.kind === 'tool_call') as ToolCallEvent[];
    const clickup = events.find((e) => e.request_id === 'toolu_friendly_deny')!;
    expect(clickup.server.name).toBe('ClickUp');
    expect(clickup.server.url).toBe(CLICKUP_URL);
    expect(clickup.error?.type).toBe('policy_denied');
    // `github` here has `tools: null` and no mcp_url: the key route gives it
    // its relay URL, with the session id hashed out of the path.
    const github = events.find((e) => e.request_id === 'toolu_friendly_github')!;
    expect(github.server.url).toBe(
      `https://api.anthropic.com/v2/ccr-sessions/${sha256Ref(FRIENDLY_SESSION_ID)}/github/mcp`,
    );
    const rawStore = readFileSync(join(dataDir, 'evidence.jsonl'), 'utf8');
    expect(rawStore).not.toContain(FRIENDLY_SESSION_ID);
    expect(rawStore).not.toContain('cse_');
    expect(rawStore).not.toContain('X-Session-UUID');
    expect(rawStore).not.toContain('permission_policy');
    expect(rawStore).not.toContain('mcp__mcp.clickup.com'); // the alias is never recorded
  });

  it('the declared-tool route is deny-only too: a forged file that claims a tool for another vendor never satisfies an allow rule', async () => {
    // Route 2 reads the same world-writable file route 1 does, so it must
    // keep the same property (E1): a planted file may add a deny or make one
    // miss, never turn a deny into an allow.
    const dataDir = tmpDir('mcp-hook-declared-denyonly-');
    const forgedTool = 'mcp__ClickUp__clickup_delete_task';
    const forged = join(dataDir, 'mcp-config-forged-declared.json');
    writeFileSync(
      forged,
      JSON.stringify({
        mcpServers: {
          'aaaaaaaa-0000-4000-8000-000000000001': {
            url: `https://relay.example.test/mcp?mcp_url=${encodeURIComponent('https://github.example.test/mcp')}`,
            tools: [{ name: 'clickup_delete_task', permission_policy: 'always_allow' }],
          },
        },
      }),
    );
    const forgedEnv = { MCP_RECORDER_MCP_CONFIG: forged };
    type DenyPayload = { hookSpecificOutput: { permissionDecision: string } };
    const decision = (r: CliResult): string =>
      r.stdout === '' ? 'allow' : (JSON.parse(r.stdout) as DenyPayload).hookSpecificOutput.permissionDecision;
    const run = (toolUseId: string, policy: string) =>
      runHook(
        ['--data-dir', dataDir, ...store, '--policy', policy],
        preToolUseInput({ sessionId: freshSessionId(), toolName: forgedTool, toolInput: { task_id: 'x' }, toolUseId }),
        forgedEnv,
      );

    // The forged file really does resolve this call through its declared
    // tool — a DENY written against the host it claims fires...
    const denyForged = join(dataDir, 'deny-forged.json');
    writeFileSync(denyForged, JSON.stringify({ deny: [{ tool: '^mcp__github\\.example\\.test__clickup_delete_task$' }], default: 'allow' }));
    expect(decision(await run('toolu_declared_deny', denyForged))).toBe('deny');
    // ...and that same resolution still cannot admit it under an allow-list
    // (written loosely, so a dotted forged host would match if allows ever
    // tested the alias).
    const allowList = join(dataDir, 'allow-list.json');
    writeFileSync(allowList, JSON.stringify({ allow: [{ tool: '^mcp__github' }], default: 'deny' }));
    expect(decision(await run('toolu_declared_allow', allowList))).toBe('deny');
    // An allow rule written against the genuine host of a genuine file is no
    // different: the alias never satisfies an allow.
    const allowAlias = join(dataDir, 'allow-alias.json');
    writeFileSync(allowAlias, JSON.stringify({ allow: [{ tool: '^mcp__mcp\\.clickup\\.com__.*$' }], default: 'deny' }));
    const real = await runHook(
      ['--data-dir', dataDir, ...store, '--policy', allowAlias],
      preToolUseInput({
        sessionId: freshSessionId(),
        toolName: 'mcp__ClickUp__clickup_filter_tasks',
        toolInput: {},
        toolUseId: 'toolu_declared_allow_real',
      }),
      withConfig,
    );
    expect(decision(real)).toBe('deny');

    const events = readEvents(dataDir).filter((e) => e.kind === 'tool_call') as ToolCallEvent[];
    for (const id of ['toolu_declared_allow', 'toolu_declared_allow_real']) {
      expect(events.find((e) => e.request_id === id)?.error?.type).toBe('policy_denied');
    }
    // What the forged file asserts is still recorded as the (scrubbed) claim it is.
    expect(events.find((e) => e.request_id === 'toolu_declared_allow')?.server.url).toBe('https://github.example.test/mcp');
  });

  it('a policy deny still exits 0 when the stdout reader is gone (EPIPE is swallowed, fail-open)', async () => {
    // Review of the integrated change (E7): the deny JSON is the one thing
    // the hook prints; with the reader gone the write raised an unhandled
    // EPIPE and the hook exited 1 — a non-zero exit from a hook.
    const dataDir = tmpDir('mcp-hook-epipe-');
    const denyAll = join(dataDir, 'deny-all.json');
    writeFileSync(denyAll, JSON.stringify({ deny: [{ tool: '.*', reason: 'everything is denied' }] }));
    const child = spawnCli(['hook', '--data-dir', dataDir, ...store, '--policy', denyAll], noConfig);
    const stderr = collect(child.stderr);
    child.stdin!.write(preToolUseInput({ sessionId: freshSessionId(), toolName: 'mcp__x__y', toolInput: {}, toolUseId: 'toolu_epipe' }));
    child.stdin!.end();
    child.stdout!.destroy(); // the reader goes away before the hook prints its deny
    const code = await waitExit(child);
    expect(code).toBe(0);
    expect(stderr()).not.toContain('EPIPE');
    expect(stderr()).not.toContain('Unhandled');
    // The deny itself was still recorded.
    const denied = readEvents(dataDir).find((e) => e.kind === 'tool_call') as ToolCallEvent;
    expect(denied.error?.type).toBe('policy_denied');
  });

  it('a missing or malformed MCP_RECORDER_MCP_CONFIG is fail-open: allowed and recorded, just without server.url; comma-separated paths are tried in order', async () => {
    const dataDir = tmpDir('mcp-hook-cloud-failopen-');
    const toolName = `mcp__${CLICKUP_UUID}__clickup_get_list`;
    const malformed = join(ROOT, 'test', 'fixtures', 'mcp-config', 'malformed.json');

    const broken = await runHook(
      ['--data-dir', dataDir, ...store],
      preToolUseInput({ sessionId: freshSessionId(), toolName, toolInput: {}, toolUseId: 'toolu_cfg_malformed' }),
      { MCP_RECORDER_MCP_CONFIG: malformed },
    );
    expect(broken.code).toBe(0);
    expect(broken.stdout).toBe('');

    const resolved = await runHook(
      ['--data-dir', dataDir, ...store],
      preToolUseInput({ sessionId: freshSessionId(), toolName, toolInput: {}, toolUseId: 'toolu_cfg_list' }),
      { MCP_RECORDER_MCP_CONFIG: `${NO_MCP_CONFIG},${malformed},${CLOUD_MCP_CONFIG}` },
    );
    expect(resolved.code).toBe(0);

    const events = readEvents(dataDir).filter((e) => e.kind === 'tool_call') as ToolCallEvent[];
    const fromMalformed = events.find((e) => e.request_id === 'toolu_cfg_malformed')!;
    expect(fromMalformed.server.name).toBe(CLICKUP_UUID);
    expect(fromMalformed.server.url).toBeUndefined();
    expect(fromMalformed.is_error).toBe(false);
    const fromList = events.find((e) => e.request_id === 'toolu_cfg_list')!;
    expect(fromList.server.url).toBe(CLICKUP_URL);
    expectNoConfigLeak(readFileSync(join(dataDir, 'evidence.jsonl'), 'utf8'));
  });
});
