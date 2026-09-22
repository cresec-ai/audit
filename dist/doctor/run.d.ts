/**
 * `mcp-recorder doctor` — is enforcement ACTUALLY in force, right now, for
 * the client that is actually running?
 *
 * This command exists to detect an ABSENCE. Cloud dogfood 4 ended with a
 * 62-event signed bundle, a passing chain, two live connector calls against a
 * real workspace, and ZERO policy decisions — because the client's config
 * keys and its `mcp__<segment>__<tool>` names disagreed and both deny rules
 * matched nothing. Nothing reported an error, because nothing had gone wrong;
 * something had simply failed to happen. Every existing command was happy.
 *
 * THE GOVERNING RULE: never report success on an absence. Every check is
 * tri-state — OK / FAIL / INCOMPLETE — and a check that could not be
 * performed is INCOMPLETE and is never folded into OK. A policy that loads,
 * validates and matches nothing is a FAIL, not a pass.
 *
 * Exit codes: 0 everything passed, 1 at least one FAIL, 3 no failures but at
 * least one INCOMPLETE (additive; never treat it as a pass), 2 doctor could
 * not run at all (the CLI's existing meaning).
 *
 * NOT ON THE FORWARDING PATH. `doctor` is its own subcommand in its own
 * process. Its probe (C5) spawns recorder processes of its own with their own
 * throwaway `--data-dir`; it never attaches to a live proxy, never writes to
 * the real data directory, and only ever pushes calls the policy has ALREADY
 * said it denies — so the wrapped server never sees them.
 */
import type { LoadedPolicy } from '../policy/load.js';
import type { CompiledPolicy } from '../hook/policy.js';
import type { McpServersMap, ServerEntry } from '../setup/wrap.js';
import type { ToolSpelling } from './spellings.js';
export type CheckStatus = 'OK' | 'FAIL' | 'INCOMPLETE';
export interface DoctorCheck {
    /** `C1` … `C6`. Stable; `--json` consumers key on it. */
    id: string;
    /** Short name, e.g. `wiring`. */
    title: string;
    status: CheckStatus;
    /**
     * A stable machine label for a specific condition inside a check, when one
     * caller needs to tell it apart from the check's other outcomes. Today the
     * only value is `stale-session`, which `protect` discounts: `protect` WRITES
     * `.claude/settings.json`, so from inside a live Claude Code session that
     * FAIL is the unavoidable, correct consequence of a successful install and
     * the remedy is the restart line `protect` already prints.
     */
    code?: string;
    /** One line, printed beside the status. */
    summary: string;
    /** Indented lines printed under the summary; the remedy is the last one. */
    detail: string[];
}
/** `stale-session`: see {@link DoctorCheck.code}. */
export declare const STALE_SESSION_CODE = "stale-session";
export interface DoctorReport {
    verdict: 'ok' | 'fail' | 'incomplete';
    config?: string;
    policy?: {
        path: string;
        hash: string;
        rules: number;
    };
    hook_policy?: {
        path: string;
        deny_rules: number;
    };
    checks: DoctorCheck[];
    /** Discovered tool names, per server / connector. */
    tools: Record<string, string[]>;
    /**
     * The keys of `tools` that are GATEWAY-leg stdio servers, as opposed to
     * hosted connectors reached through the hook. The two legs carry different
     * policies, so anything that picks a tool to say something about has to
     * know which leg could act on it.
     */
    gateway_servers: string[];
    coverage: {
        denied: number;
        held: number;
        allowed: number;
    };
    /** stdio servers in the client config, and how many of them enforce a policy. */
    stdio: {
        total: number;
        enforcing: number;
    };
    /** Anthropic-hosted connectors found in the client's MCP config. */
    connectors: number;
}
export interface DoctorOptions {
    /** The client config file to inspect. Required: doctor never guesses. */
    configPath: string;
    /** `.claude/settings.json` for the hook checks; undefined skips C2/C3's hook half. */
    settingsPath?: string;
    /** The real evidence directory, for C6. */
    dataDir: string;
    /** Absolute path to this install's `cli.js`, for recognising wrapped entries and for the probe. */
    cliPath: string;
    /** C5. Default true; `--no-probe` turns it off (and C5 is then INCOMPLETE, never OK). */
    probe: boolean;
    /**
     * Which client is being checked, when it is known. It changes only what C2
     * SAYS: Claude Code has a hook and can therefore be missing one, while
     * Claude Desktop and Cursor have no hook mechanism at all, so telling their
     * users to install one is advice they cannot take.
     */
    client?: string;
    env: NodeJS.ProcessEnv;
    /** Per-child budget for discovery and probe spawns. */
    timeoutMs?: number;
}
/** One Anthropic-hosted connector as the client's MCP config declares it. */
export interface ConnectorEntry {
    configKey: string;
    tools: string[];
    host?: string;
    friendly?: string;
}
/**
 * Hosted connectors and their declared tools, read from the MCP config the
 * client was started with (`MCP_RECORDER_MCP_CONFIG`, else
 * `/tmp/mcp-config-*.json`). Nothing is spawned: the `tools[]` array is
 * already there.
 *
 * Deliberately tolerant — this file is world-writable in a cloud session and
 * the hook module already treats it as an untrusted claim. A file that does
 * not parse contributes nothing and is not an error.
 */
export declare function connectorsFromConfigs(env: NodeJS.ProcessEnv): ConnectorEntry[];
/** A wrapped entry's state, as C1 reads it. */
interface WiringEntry {
    name: string;
    entry: ServerEntry;
    wrapped: boolean;
    policyPath?: string;
    /** The wrapped server's own command, when it could be recovered. */
    inner?: ServerEntry;
    problem?: string;
}
/**
 * Which data directory a wrapped entry's own arguments select, so that
 * `--protect` can be resolved to the file it will actually enforce. The
 * entry's `--data-dir` wins, then its `env`, then the directory doctor
 * itself resolved — the same order `resolveConfig` uses inside the recorder.
 */
export declare function entryDataDir(entry: ServerEntry, fallback: string): string;
/**
 * `dataDir` is doctor's own evidence directory, used as the fallback when a
 * wrapped entry does not name one. It is only ever consulted for a
 * `--protect` entry, whose policy path is `<that data dir>/policy.starter.yaml`
 * and nothing else — a `--protect` entry DOES enforce, and reporting it as
 * "recording only" would send the person to `mcp-recorder protect`, which
 * rewrites the very config a hand edit exists to keep.
 */
export declare function readWiring(servers: McpServersMap, cliPath: string, dataDir: string): WiringEntry[];
interface HookWiring {
    installed: boolean;
    matcher?: string;
    policyPath?: string;
    problem?: string;
    /** settings.json mtime, for the session-snapshot trap. */
    mtimeMs?: number;
}
export declare function readHookWiring(settingsPath: string, cliPath: string): HookWiring;
/** How a rule fared against one tool's spellings. */
interface SpellingVerdict {
    ruleIndex: number;
    ruleSource: string;
    tool: string;
    matched: ToolSpelling[];
    missed: ToolSpelling[];
}
/**
 * C3. For each deny rule and each tool, a rule that matches SOME spellings
 * and not others is anchored to a segment the client chooses — the
 * dogfood-4 shape. A rule that matches none of a tool's spellings simply does
 * not govern that tool and is not reported.
 */
export declare function checkSpellings(hookPolicy: CompiledPolicy, tools: Array<{
    configKey: string;
    tool: string;
    host?: string;
    friendly?: string;
}>): SpellingVerdict[];
export interface CoverageRow {
    server: string;
    tool: string;
    action: 'allow' | 'hold' | 'deny';
    ruleId?: string;
    leg: 'gateway' | 'hook';
}
/** C4. Every discovered tool, evaluated against the policy that governs its leg. */
export declare function coverage(policy: LoadedPolicy | undefined, hookPolicy: CompiledPolicy | null, stdio: Array<{
    server: string;
    tools: string[];
}>, connectors: ConnectorEntry[]): CoverageRow[];
/** C5's chosen probe: a call this policy ALREADY says it denies. */
export interface ProbePlan {
    server: string;
    tool: string;
    args: Record<string, unknown>;
    ruleId: string;
    inner: ServerEntry;
}
export declare function planProbe(policy: LoadedPolicy, policyPath: string, dataDir: string, stdio: Array<{
    server: string;
    tools: string[];
    inner?: ServerEntry;
}>): ProbePlan | undefined;
/** What one probe run observed, as C5 reads it. */
export interface ProbeObservation {
    /** The spawned proxy answered `tools/call` with `isError: true`. */
    callIsError?: boolean;
    /** The refusal text named the rule that decided it. */
    named: boolean;
    /** `policy_decision` events that reached the throwaway chain. */
    decisions: number;
    /** Set when the probe server could not be driven at all — INCOMPLETE, never FAIL. */
    error?: string;
}
/**
 * C5's verdict, as a pure function of what the probe observed.
 *
 * Extracted so that every way the probe can be wrong has a test of its own.
 * ALL THREE conjuncts are load-bearing and none of them is redundant:
 *
 *   callIsError   the client got a refusal at all;
 *   named         the refusal names the RULE, so it was this policy that
 *                 decided and not, say, the server erroring on its own;
 *   decisions>0   the refusal reached the signed chain. This is the dogfood-4
 *                 conjunct: that run ended with live calls, a passing chain
 *                 and ZERO policy decisions, so a probe that checks only the
 *                 refusal text would have called it a pass.
 *
 * A probe that denied without recording is a FAIL, not an OK with a smaller
 * number — the event IS the proof, and it is the artifact a dogfood run is
 * measured by.
 */
export declare function probeVerdict(plan: ProbePlan, obs: ProbeObservation): DoctorCheck;
/**
 * The config files a LIVE Claude Code session is using, whose mtimes mean
 * something. `MCP_RECORDER_MCP_CONFIG` names a file the operator manages, not
 * one a session wrote, so comparing mtimes against it would turn an ordinary
 * fixture into a permanent, unfixable FAIL — it yields nothing.
 */
export declare function liveSessionConfigPaths(env: NodeJS.ProcessEnv): string[];
/**
 * The session-snapshot trap: Claude Code captures its hooks when the session
 * BEGINS, so a hook installed after a live session started is not in force
 * for it, and the symptom is a false negative that looks exactly like the
 * product failing. The settings file being NEWER than a running session's
 * config is that condition.
 *
 * Extracted and pure because the live half of it reads a hardcoded glob under
 * `/tmp` that a test must not write into — and because this is the check that
 * makes `protect` exit non-zero on every successful first run performed from
 * inside a session, so both directions have to be pinned.
 */
export declare function sessionSnapshotIsStale(settingsPath: string, livePaths: readonly string[]): boolean;
export declare function runDoctor(opts: DoctorOptions): Promise<DoctorReport>;
/** 0 ok / 1 at least one FAIL / 3 no FAIL but at least one INCOMPLETE. */
export declare function doctorExitCode(report: DoctorReport): number;
/**
 * The human report. The last line is the verdict, because that is the line a
 * person reads, and it counts INCOMPLETE separately — folding it into "OK"
 * is exactly the reporting bug this command exists to fix.
 */
export declare function renderDoctor(report: DoctorReport): string[];
/**
 * The one-paragraph verdict `protect` prints last. Deliberately the same
 * numbers as the full report: a person who runs `protect` and a person who
 * runs `doctor` must not be told different things.
 */
export declare function doctorVerdictLines(report: DoctorReport): string[];
export {};
