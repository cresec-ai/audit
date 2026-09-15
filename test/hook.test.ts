/**
 * `mcp-recorder hook` — turns Claude Code PreToolUse/PostToolUse/SessionEnd/
 * Stop hook invocations into recorded, redacted evidence-chain events, with
 * an allow/deny policy. Drives the real CLI (spawned fresh per hook event,
 * same as Claude Code does) and inspects the resulting store, exactly like
 * test/cli.test.ts and test/setup.test.ts do for the commands they cover.
 */
import type { ChildProcess } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { Readable } from 'node:stream';
import { fileURLToPath } from 'node:url';
import { afterEach, describe, expect, it } from 'vitest';
import { spawnTsx } from './helpers/tsx.js';
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

function spawnCli(args: string[]): ChildProcess {
  const child = spawnTsx(['src/cli.ts', ...args], {
    cwd: ROOT,
    env: { ...process.env, MCP_RECORDER_DISABLE: undefined },
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
async function runHook(args: string[], stdinText: string): Promise<CliResult> {
  const child = spawnCli(['hook', ...args]);
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

  it('a broken policy file is fail-open (allows, warns on stderr, never crashes the hook)', async () => {
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
    expect(result.code).toBe(0);
    expect(result.stdout).toBe(''); // no deny — a broken policy fails open to allow
    expect(result.stderr).toContain('--policy');
    const toolCall = readEvents(dataDir).find((e) => e.kind === 'tool_call') as ToolCallEvent;
    expect(toolCall.is_error).toBe(false);
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

  it('writes PreToolUse/PostToolUse (mcp__.* matcher) + SessionEnd/Stop entries, creating the file if missing', async () => {
    const dir = tmpDir('mcp-hook-install-');
    const settingsPath = join(dir, 'settings.json');
    expect(existsSync(settingsPath)).toBe(false);

    const result = await runCli([
      'hook', 'install', '--settings', settingsPath, '--data-dir', join(dir, '.mcp-recorder'), '--json',
    ]);
    expect(result.code).toBe(0);
    const payload = JSON.parse(result.stdout) as { added: string[]; alreadyInstalled: string[] };
    expect(payload.added.sort()).toEqual(['PostToolUse', 'PreToolUse', 'SessionEnd', 'Stop'].sort());
    expect(payload.alreadyInstalled).toEqual([]);

    const settings = readSettings(settingsPath) as {
      hooks: Record<string, Array<{ matcher?: string; hooks: Array<{ type: string; command: string }> }>>;
    };
    expect(settings.hooks.PreToolUse![0]!.matcher).toBe('mcp__.*');
    expect(settings.hooks.PostToolUse![0]!.matcher).toBe('mcp__.*');
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
    expect(firstPayload.added).toHaveLength(4);
    const afterFirst = readFileSync(settingsPath, 'utf8');

    const second = await runCli(args);
    const secondPayload = JSON.parse(second.stdout) as { added: string[]; alreadyInstalled: string[] };
    expect(secondPayload.added).toEqual([]);
    expect(secondPayload.alreadyInstalled.sort()).toEqual(['PostToolUse', 'PreToolUse', 'SessionEnd', 'Stop'].sort());
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
    expect(undoPayload.removed.sort()).toEqual(['PostToolUse', 'PreToolUse', 'SessionEnd', 'Stop'].sort());

    settings = readSettings(settingsPath) as typeof settings;
    expect(settings.otherTopLevelKey).toBe('preserved');
    expect(settings.hooks.SessionStart).toHaveLength(1); // untouched
    expect(settings.hooks.PreToolUse).toHaveLength(1); // only the unrelated Bash entry remains
    expect(settings.hooks.PreToolUse[0]!.matcher).toBe('Bash');
    expect(settings.hooks.PostToolUse).toBeUndefined(); // emptied entirely, key dropped
    expect(settings.hooks.SessionEnd).toBeUndefined();
    expect(settings.hooks.Stop).toBeUndefined();
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
