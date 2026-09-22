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
import { spawn } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { evaluateMcp } from '../policy/engine.js';
import { loadPolicyFile } from '../policy/load.js';
import { evaluatePolicy, loadPolicy } from '../hook/policy.js';
import { candidateConfigPaths, readConfigText, simpleGlob } from '../hook/mcp-config.js';
import { starterPolicyPath } from '../policy/starter.js';
import { isAlreadyWrapped, recorderPolicyArg, recorderPrefixArgs, structuralUnwrap } from '../setup/wrap.js';
import { openStoreReadOnly } from '../store/index.js';
import { stripBom } from '../setup/io.js';
import { ENV } from '../types.js';
import { verifyStore } from '../verify/verify.js';
import { PROBE_CONNECTOR_TOOLS, anchoredSegment, friendlyName, toolSpellings } from './spellings.js';
/** `stale-session`: see {@link DoctorCheck.code}. */
export const STALE_SESSION_CODE = 'stale-session';
const DEFAULT_TIMEOUT_MS = 10_000;
const PROTOCOL_VERSION = '2025-06-18';
/**
 * Speak just enough MCP over stdio to learn a server's tool names, and
 * optionally push one `tools/call` through it.
 *
 * Never throws: every failure comes back as `error`, because a server that
 * will not start is an INCOMPLETE check, not a crashed doctor.
 */
async function stdioSession(command, args, opts) {
    return new Promise((resolveResult) => {
        let child;
        try {
            child = spawn(command, [...args], {
                stdio: ['pipe', 'pipe', 'pipe'],
                ...(opts.env !== undefined ? { env: opts.env } : {}),
                ...(opts.cwd !== undefined ? { cwd: opts.cwd } : {}),
            });
        }
        catch (cause) {
            resolveResult({ error: cause instanceof Error ? cause.message : String(cause) });
            return;
        }
        const out = {};
        let buf = '';
        let settled = false;
        let resolved = false;
        const done = (extra) => {
            if (resolved)
                return;
            resolved = true;
            try {
                child.kill('SIGKILL');
            }
            catch {
                /* already gone */
            }
            resolveResult({ ...out, ...extra });
        };
        const finish = (extra) => {
            if (settled)
                return;
            settled = true;
            clearTimeout(timer);
            if (opts.graceful !== true) {
                done(extra);
                return;
            }
            try {
                child.stdin?.end();
            }
            catch {
                /* already closed */
            }
            child.once('exit', () => done(extra));
            const grace = setTimeout(() => done(extra), opts.timeoutMs);
            grace.unref?.();
        };
        const timer = setTimeout(() => finish({ error: `no answer within ${opts.timeoutMs} ms` }), opts.timeoutMs);
        timer.unref?.();
        const send = (msg) => {
            try {
                child.stdin?.write(JSON.stringify(msg) + '\n');
            }
            catch {
                finish({ error: 'the server closed its stdin' });
            }
        };
        child.on('error', (e) => finish({ error: e.message }));
        child.on('exit', (code, signal) => finish(out.tools === undefined ? { error: `exited with ${signal ?? code} before answering` } : {}));
        child.stderr?.resume(); // drained, never read: a chatty server must not fill its pipe
        child.stdout?.setEncoding('utf8');
        child.stdout?.on('data', (chunk) => {
            buf += chunk;
            let nl;
            while ((nl = buf.indexOf('\n')) !== -1) {
                const line = buf.slice(0, nl).trim();
                buf = buf.slice(nl + 1);
                if (line === '')
                    continue;
                let msg;
                try {
                    msg = JSON.parse(line);
                }
                catch {
                    continue; // a server that prints noise on stdout is its own problem
                }
                if (msg.id === 1) {
                    send({ jsonrpc: '2.0', method: 'notifications/initialized' });
                    send({ jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} });
                    continue;
                }
                if (msg.id === 2) {
                    const result = msg.result;
                    out.tools = (result?.tools ?? [])
                        .map((t) => t.name)
                        .filter((n) => typeof n === 'string' && n.length > 0);
                    if (opts.call === undefined) {
                        finish();
                        return;
                    }
                    send({ jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: opts.call.name, arguments: opts.call.arguments } });
                    continue;
                }
                if (msg.id === 3) {
                    const result = msg.result;
                    out.callIsError = result?.isError === true;
                    out.callText = (result?.content ?? [])
                        .map((c) => (typeof c.text === 'string' ? c.text : ''))
                        .join('\n');
                    finish();
                    return;
                }
            }
        });
        send({
            jsonrpc: '2.0',
            id: 1,
            method: 'initialize',
            params: { protocolVersion: PROTOCOL_VERSION, capabilities: {}, clientInfo: { name: 'mcp-recorder-doctor', version: '1' } },
        });
    });
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
export function connectorsFromConfigs(env) {
    const out = [];
    for (const path of candidateConfigPaths(env, simpleGlob)) {
        let text;
        try {
            // `readConfigText` throws on a missing or unreadable path — its
            // contract is that callers skip. Doctor must not exit 2 because an
            // operator pointed MCP_RECORDER_MCP_CONFIG at a file that is not there.
            text = readConfigText(path);
        }
        catch {
            continue;
        }
        if (text === undefined)
            continue;
        let parsed;
        try {
            parsed = JSON.parse(text);
        }
        catch {
            continue;
        }
        const servers = parsed.mcpServers;
        if (typeof servers !== 'object' || servers === null || Array.isArray(servers))
            continue;
        for (const [configKey, raw] of Object.entries(servers)) {
            if (typeof raw !== 'object' || raw === null)
                continue;
            const entry = raw;
            const tools = Array.isArray(entry.tools)
                ? entry.tools
                    .map((t) => (typeof t === 'object' && t !== null ? t.name : undefined))
                    .filter((n) => typeof n === 'string' && n.length > 0)
                : [];
            const host = hostOf(entry.url);
            const friendly = friendlyName(configKey, host);
            out.push({
                configKey,
                tools,
                ...(host !== undefined ? { host } : {}),
                ...(friendly !== undefined ? { friendly } : {}),
            });
        }
    }
    return out;
}
/** The vendor host a relay URL points at (`mcp_url`), else the URL's own host. */
function hostOf(url) {
    if (typeof url !== 'string')
        return undefined;
    try {
        const u = new URL(url);
        const vendor = u.searchParams.get('mcp_url');
        if (vendor !== null) {
            try {
                return new URL(vendor).hostname;
            }
            catch {
                /* fall through to the relay's own host */
            }
        }
        return u.hostname;
    }
    catch {
        return undefined;
    }
}
/* --------------------------------- checks --------------------------------- */
function ok(id, title, summary, detail = []) {
    return { id, title, status: 'OK', summary, detail };
}
function fail(id, title, summary, detail) {
    return { id, title, status: 'FAIL', summary, detail };
}
function incomplete(id, title, summary, detail) {
    return { id, title, status: 'INCOMPLETE', summary, detail };
}
/**
 * Which data directory a wrapped entry's own arguments select, so that
 * `--protect` can be resolved to the file it will actually enforce. The
 * entry's `--data-dir` wins, then its `env`, then the directory doctor
 * itself resolved — the same order `resolveConfig` uses inside the recorder.
 */
export function entryDataDir(entry, fallback) {
    const head = recorderPrefixArgs(entry) ?? [];
    const pairIdx = head.indexOf('--data-dir');
    if (pairIdx !== -1) {
        const value = head[pairIdx + 1];
        if (value !== undefined && !value.startsWith('-'))
            return value;
    }
    const eq = head.find((a) => a.startsWith('--data-dir='));
    if (eq !== undefined)
        return eq.slice('--data-dir='.length);
    const fromEnv = entry.env?.[ENV.DATA_DIR];
    if (typeof fromEnv === 'string' && fromEnv !== '')
        return fromEnv;
    return fallback;
}
/**
 * `dataDir` is doctor's own evidence directory, used as the fallback when a
 * wrapped entry does not name one. It is only ever consulted for a
 * `--protect` entry, whose policy path is `<that data dir>/policy.starter.yaml`
 * and nothing else — a `--protect` entry DOES enforce, and reporting it as
 * "recording only" would send the person to `mcp-recorder protect`, which
 * rewrites the very config a hand edit exists to keep.
 */
export function readWiring(servers, cliPath, dataDir) {
    return Object.entries(servers).map(([name, entry]) => {
        if (typeof entry !== 'object' || entry === null) {
            return { name, entry: {}, wrapped: false, problem: 'not a JSON object' };
        }
        if (typeof entry.command !== 'string' || entry.command === '') {
            return { name, entry, wrapped: false, problem: 'not a stdio server (no "command") — no local proxy can see it' };
        }
        const wrapped = isAlreadyWrapped(entry, cliPath);
        if (!wrapped) {
            return { name, entry, wrapped: false, problem: 'not wrapped at all — the client launches this server directly' };
        }
        // `--protect` is `--policy <data-dir>/policy.starter.yaml` and nothing
        // else (cli.ts `resolvePolicyPath`). It is the documented shape for a
        // hand-edited client config, so it has to read back as ENFORCING —
        // otherwise C1 fails on a config that genuinely denies, C4 scores that
        // server's tools as allowed, and C5 finds no policy to probe.
        const protect = (recorderPrefixArgs(entry) ?? []).includes('--protect');
        const policyPath = protect ? starterPolicyPath(entryDataDir(entry, dataDir)) : recorderPolicyArg(entry);
        const inner = structuralUnwrap(entry);
        const out = { name, entry, wrapped: true };
        if (policyPath !== undefined)
            out.policyPath = policyPath;
        if (inner !== undefined)
            out.inner = inner;
        if (policyPath === undefined)
            out.problem = 'wrapped, but with no --policy — recording only, nothing is enforced';
        else if (!existsSync(policyPath))
            out.problem = protect
                ? `--protect names ${policyPath}, which is not there — every launch of this server exits 2. Fix: mcp-recorder protect (it is the only thing that writes one)`
                : `--policy ${policyPath} does not exist — every launch of this server exits 2`;
        const disable = entry.env?.[ENV.DISABLE];
        if (disable === '1') {
            out.problem = `env ${ENV.DISABLE}=1 is set on this entry — the kill switch is on; neither recording nor the gateway runs`;
        }
        return out;
    });
}
export function readHookWiring(settingsPath, cliPath) {
    if (!existsSync(settingsPath))
        return { installed: false, problem: `no hook settings at ${settingsPath}` };
    let root;
    try {
        root = JSON.parse(stripBom(readFileSync(settingsPath, 'utf8')));
    }
    catch (cause) {
        return { installed: false, problem: `${settingsPath} is not valid JSON: ${cause instanceof Error ? cause.message : String(cause)}` };
    }
    const hooks = root['hooks'];
    const pre = typeof hooks === 'object' && hooks !== null ? hooks['PreToolUse'] : undefined;
    if (!Array.isArray(pre))
        return { installed: false, problem: 'no PreToolUse hook is installed' };
    for (const group of pre) {
        if (typeof group !== 'object' || group === null)
            continue;
        const g = group;
        const entries = Array.isArray(g.hooks) ? g.hooks : [];
        for (const h of entries) {
            const command = typeof h === 'object' && h !== null ? h.command : undefined;
            if (typeof command !== 'string')
                continue;
            if (!command.includes('mcp-recorder') && !command.includes(cliPath) && !command.includes('cli.js'))
                continue;
            const m = /--policy[= ]("([^"]+)"|'([^']+)'|(\S+))/.exec(command);
            const policyPath = m?.[2] ?? m?.[3] ?? m?.[4];
            const out = { installed: true };
            if (typeof g.matcher === 'string')
                out.matcher = g.matcher;
            if (policyPath !== undefined)
                out.policyPath = policyPath.replace(/^["']|["']$/g, '');
            else
                out.problem = 'the PreToolUse hook is installed but carries no --policy — it records, it does not enforce';
            return out;
        }
    }
    return { installed: false, problem: 'a PreToolUse hook exists, but none of its commands runs this recorder' };
}
/**
 * C3. For each deny rule and each tool, a rule that matches SOME spellings
 * and not others is anchored to a segment the client chooses — the
 * dogfood-4 shape. A rule that matches none of a tool's spellings simply does
 * not govern that tool and is not reported.
 */
export function checkSpellings(hookPolicy, tools) {
    const out = [];
    hookPolicy.deny.forEach((rule, ruleIndex) => {
        for (const t of tools) {
            const spellings = toolSpellings(t);
            const matched = [];
            const missed = [];
            for (const s of spellings) {
                // A fresh RegExp per test: a rule regex authored with /g would carry
                // lastIndex across calls and answer differently the second time.
                if (new RegExp(rule.tool.source, rule.tool.flags.replace(/[gy]/g, '')).test(s.name))
                    matched.push(s);
                else
                    missed.push(s);
            }
            if (matched.length === 0)
                continue;
            out.push({ ruleIndex, ruleSource: rule.tool.source, tool: t.tool, matched, missed });
        }
    });
    return out;
}
/** C4. Every discovered tool, evaluated against the policy that governs its leg. */
export function coverage(policy, hookPolicy, stdio, connectors) {
    const rows = [];
    for (const s of stdio) {
        for (const tool of s.tools) {
            if (policy === undefined) {
                rows.push({ server: s.server, tool, action: 'allow', leg: 'gateway' });
                continue;
            }
            // Empty arguments: this is a question about the NAME rules, asked
            // without inventing a payload. An argument rule that would have
            // denied a real call simply does not count towards coverage here,
            // which is the conservative direction for a check whose job is to
            // fail when the policy matches nothing.
            const d = evaluateMcp(policy.policy, { server: s.server, tool, args: {}, argsBytes: 2 });
            rows.push({
                server: s.server,
                tool,
                action: d.action,
                ...(d.ruleId !== undefined ? { ruleId: d.ruleId } : {}),
                leg: 'gateway',
            });
        }
    }
    for (const c of connectors) {
        for (const tool of c.tools) {
            const spellings = toolSpellings({ configKey: c.configKey, tool, ...(c.host !== undefined ? { host: c.host } : {}) });
            // The action this tool gets under the spelling the client actually
            // used is unknown, so a tool counts as denied when the rules deny it
            // under EVERY spelling — the only claim doctor can make honestly.
            const decisions = spellings.map((s) => evaluatePolicy(hookPolicy, s.name).decision);
            const denied = decisions.every((d) => d === 'deny');
            rows.push({ server: c.configKey, tool, action: denied ? 'deny' : 'allow', leg: 'hook' });
        }
    }
    return rows;
}
/**
 * Candidate arguments for the probe, tried in order. Each is only ever SENT
 * on a call the local engine has already decided to deny, so the wrapped
 * server never sees it: a denied request is not forwarded.
 */
function probeArgumentCandidates(policyPath, dataDir) {
    return [
        {},
        { path: policyPath },
        { path: dataDir },
        { path: join(dataDir, '.env') },
        { command: 'rm -rf / --no-preserve-root' },
    ];
}
export function planProbe(policy, policyPath, dataDir, stdio) {
    for (const s of stdio) {
        if (s.inner === undefined || typeof s.inner.command !== 'string')
            continue;
        for (const tool of s.tools) {
            for (const args of probeArgumentCandidates(policyPath, dataDir)) {
                const d = evaluateMcp(policy.policy, { server: s.server, tool, args, argsBytes: JSON.stringify(args).length });
                if (d.action === 'deny' && d.ruleId !== undefined) {
                    return { server: s.server, tool, args, ruleId: d.ruleId, inner: s.inner };
                }
            }
        }
    }
    return undefined;
}
/** Count `policy_decision` events in a throwaway store. The event is the proof. */
function decisionsIn(dataDir) {
    try {
        // The probe always records jsonl, so the backend is named rather than
        // sniffed: a store opened as sqlite over a jsonl dir reads zero events,
        // which would look exactly like the absence this check exists to find.
        const store = openStoreReadOnly({ dataDir, backend: 'jsonl' });
        try {
            let n = 0;
            for (const rec of store.iterate())
                if (rec.event.kind === 'policy_decision')
                    n++;
            return n;
        }
        finally {
            store.close();
        }
    }
    catch {
        return 0;
    }
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
export function probeVerdict(plan, obs) {
    if (obs.callIsError === true && obs.named && obs.decisions > 0) {
        return ok('C5', 'probe', `live deny fired on ${plan.server}/${plan.tool} (rule ${plan.ruleId})`, [
            `  the refusal named the rule, and ${obs.decisions} policy_decision event(s) landed in the chain`,
        ]);
    }
    if (obs.error !== undefined) {
        return incomplete('C5', 'probe', `the probe server could not be driven: ${obs.error}`, ['  Nothing was proved live.']);
    }
    return fail('C5', 'probe', `a call this policy denies was NOT refused on ${plan.server}/${plan.tool}`, [
        `  expected: an isError result naming rule ${plan.ruleId}, and a policy_decision event`,
        `  got:      isError=${String(obs.callIsError)}, rule named=${String(obs.named)}, policy_decision events=${obs.decisions}`,
        ...(obs.callIsError === true && obs.named
            ? [
                '  The call WAS refused and the refusal named the rule — but nothing reached the',
                '  chain, so there is no evidence it happened. That is the dogfood-4 shape exactly.',
            ]
            : [
                '  The policy is loaded and matches nothing that reaches the wire. This is the',
                '  absence dogfood 4 ended in: a healthy chain holding zero decisions.',
            ]),
    ]);
}
/** Poll a throwaway store until a `policy_decision` lands, or the budget runs out. */
async function waitForDecision(dataDir, budgetMs) {
    const deadline = Date.now() + budgetMs;
    for (;;) {
        const n = decisionsIn(dataDir);
        if (n > 0 || Date.now() >= deadline)
            return n;
        await new Promise((r) => setTimeout(r, 50));
    }
}
/**
 * The config files a LIVE Claude Code session is using, whose mtimes mean
 * something. `MCP_RECORDER_MCP_CONFIG` names a file the operator manages, not
 * one a session wrote, so comparing mtimes against it would turn an ordinary
 * fixture into a permanent, unfixable FAIL — it yields nothing.
 */
export function liveSessionConfigPaths(env) {
    const pointed = env[ENV.MCP_CONFIG];
    return pointed === undefined || pointed === '' ? candidateConfigPaths(env, simpleGlob) : [];
}
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
export function sessionSnapshotIsStale(settingsPath, livePaths) {
    return livePaths.some((p) => {
        try {
            return statSync(settingsPath).mtimeMs > statSync(p).mtimeMs;
        }
        catch {
            return false;
        }
    });
}
export async function runDoctor(opts) {
    const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    const checks = [];
    const report = {
        verdict: 'ok',
        config: opts.configPath,
        checks,
        tools: {},
        gateway_servers: [],
        coverage: { denied: 0, held: 0, allowed: 0 },
        stdio: { total: 0, enforcing: 0 },
        connectors: 0,
    };
    /* --- config + policy ------------------------------------------------- */
    let servers = {};
    let configProblem;
    try {
        const parsed = JSON.parse(stripBom(readFileSync(opts.configPath, 'utf8')));
        const raw = parsed['mcpServers'];
        if (typeof raw === 'object' && raw !== null && !Array.isArray(raw))
            servers = raw;
    }
    catch (cause) {
        configProblem = cause instanceof Error ? cause.message : String(cause);
    }
    const wiring = readWiring(servers, opts.cliPath, opts.dataDir);
    const enforcing = wiring.filter((w) => w.wrapped && w.policyPath !== undefined && w.problem === undefined);
    report.stdio = { total: wiring.length, enforcing: enforcing.length };
    const policyPath = enforcing[0]?.policyPath;
    let policy;
    let policyProblem;
    if (policyPath !== undefined) {
        try {
            policy = loadPolicyFile(policyPath);
            report.policy = { path: policyPath, hash: policy.hash, rules: policy.policy.mcp?.rules.length ?? 0 };
        }
        catch (cause) {
            policyProblem = cause instanceof Error ? cause.message : String(cause);
        }
    }
    /* --- C1 wiring ------------------------------------------------------- */
    {
        const detail = [];
        const killSwitch = opts.env[ENV.DISABLE] === '1';
        for (const w of wiring) {
            detail.push(`  ${w.name.padEnd(16)} ${w.problem ?? `wrapped, enforcing ${w.policyPath ?? '(none)'}`}`);
        }
        if (killSwitch) {
            detail.push(`  environment ${ENV.DISABLE}=1 is set — the kill switch is on; with it set, neither recording nor`, '              the gateway runs, whatever the config says');
        }
        if (configProblem !== undefined) {
            checks.push(fail('C1', 'wiring', `${opts.configPath} could not be read: ${configProblem}`, ['  Fix: point --config at the client config file you want checked']));
        }
        else if (Object.keys(servers).length === 0) {
            checks.push(incomplete('C1', 'wiring', `${opts.configPath} declares no mcpServers — there is nothing to enforce over`, detail));
        }
        else if (killSwitch || enforcing.length === 0) {
            detail.push('', `  Fix: mcp-recorder protect --client <your client>${killSwitch ? `\n       and unset ${ENV.DISABLE}` : ''}`);
            checks.push(fail('C1', 'wiring', 'enforcement is NOT in force', detail));
        }
        else if (policyProblem !== undefined) {
            checks.push(fail('C1', 'wiring', `the policy in the config could not be loaded: ${policyProblem}`, detail));
        }
        else if (enforcing.length < wiring.length) {
            detail.push('', '  Fix: mcp-recorder protect --client <your client>   (it reaches every entry)');
            checks.push(fail('C1', 'wiring', `${enforcing.length} of ${wiring.length} servers are enforcing a policy`, detail));
        }
        else {
            checks.push(ok('C1', 'wiring', `${enforcing.length}/${wiring.length} stdio servers wrapped, all enforcing this policy`, detail));
        }
    }
    /* --- C2 hook wiring -------------------------------------------------- */
    let hookPolicy = null;
    let hookPolicyPath;
    {
        if (opts.settingsPath === undefined) {
            const noHookMechanism = opts.client !== undefined && opts.client !== 'claude-code';
            checks.push(incomplete('C2', 'hook', noHookMechanism
                ? `${opts.client} has no hook mechanism, so hosted connectors cannot be gated here at all`
                : 'no Claude Code settings file was given, so the hook leg was not checked', noHookMechanism
                ? [
                    '  The Anthropic-hosted connectors (ClickUp, Gmail, Drive, ...) never touch this',
                    '  machine, and this client offers nothing that could see them. That is a real gap,',
                    '  not a misconfiguration, so this is INCOMPLETE rather than FAIL — there is no fix',
                    '  to apply here. Claude Code sessions on the same account CAN be covered.',
                ]
                : [
                    '  The hook is the ONLY visibility into Anthropic-hosted connectors; without it,',
                    '  ClickUp, Gmail and Drive calls are ungoverned and unrecorded.',
                    '  Fix: mcp-recorder doctor --client claude-code, or --settings PATH',
                ]));
        }
        else {
            const hw = readHookWiring(opts.settingsPath, opts.cliPath);
            hookPolicyPath = hw.policyPath;
            if (hw.policyPath !== undefined) {
                const loaded = loadPolicy(hw.policyPath);
                hookPolicy = loaded.policy;
                if (loaded.warning !== undefined)
                    hw.problem = loaded.warning;
                if (hookPolicy !== null)
                    report.hook_policy = { path: hw.policyPath, deny_rules: hookPolicy.deny.length };
            }
            // The session-snapshot trap: Claude Code captures its hooks when the
            // session begins, so a hook installed after a live session started is
            // NOT in force for it, and the symptom is a false negative that looks
            // exactly like the product failing.
            //
            // Only the DEFAULT glob counts. `/tmp/mcp-config-<session>.json` is
            // written by a live session and its mtime therefore means something;
            // a path the operator pointed MCP_RECORDER_MCP_CONFIG at is a file they
            // manage, and comparing mtimes against it turns an ordinary fixture
            // into a permanent, unfixable FAIL.
            const staleSession = sessionSnapshotIsStale(opts.settingsPath, liveSessionConfigPaths(opts.env));
            if (hw.problem !== undefined || !hw.installed) {
                checks.push(fail('C2', 'hook', hw.problem ?? 'no PreToolUse hook running this recorder', [
                    '  Hosted connectors (ClickUp, Gmail, Drive, ...) are invisible to any local proxy.',
                    '  Fix: mcp-recorder protect --client claude-code',
                ]));
            }
            else if (staleSession) {
                checks.push({
                    ...fail('C2', 'hook', 'a session that began BEFORE this hook was installed is still running', [
                        '  Claude Code snapshots its hooks at session start, so the policy is not in force',
                        '  for that session and every call it makes is ungoverned — with no error anywhere.',
                        '  Fix: fully quit and restart the client (closing the window is not enough)',
                    ]),
                    code: STALE_SESSION_CODE,
                });
            }
            else {
                checks.push(ok('C2', 'hook', `PreToolUse installed, matcher ${hw.matcher ?? '(none)'}, policy ${hw.policyPath ?? '(none)'}`, []));
            }
        }
    }
    /* --- discovery ------------------------------------------------------- */
    const connectors = connectorsFromConfigs(opts.env);
    report.connectors = connectors.length;
    const stdioServers = [];
    for (const w of wiring) {
        if (w.inner === undefined || typeof w.inner.command !== 'string')
            continue;
        const r = await stdioSession(w.inner.command, (w.inner.args ?? []), {
            timeoutMs,
            ...(w.inner.env !== undefined ? { env: { ...opts.env, ...w.inner.env } } : {}),
            ...(typeof w.inner.cwd === 'string' ? { cwd: w.inner.cwd } : {}),
        });
        stdioServers.push({
            server: w.name,
            tools: r.tools ?? [],
            inner: w.inner,
            ...(r.error !== undefined ? { error: r.error } : {}),
        });
        report.tools[w.name] = r.tools ?? [];
        report.gateway_servers.push(w.name);
    }
    for (const c of connectors)
        report.tools[c.configKey] = c.tools;
    /* --- C3 name spellings ----------------------------------------------- */
    {
        const real = connectors.flatMap((c) => c.tools.map((tool) => ({ configKey: c.configKey, tool, ...(c.host !== undefined ? { host: c.host } : {}) })));
        const usingProbeVocabulary = real.length === 0;
        const tools = usingProbeVocabulary
            ? PROBE_CONNECTOR_TOOLS.map((tool) => ({ configKey: 'connector', tool, host: 'mcp.example.com' }))
            : real;
        if (hookPolicy === null) {
            checks.push(incomplete('C3', 'name spellings', 'no hook policy is loaded, so no deny rule could be checked', [
                opts.client !== undefined && opts.client !== 'claude-code'
                    ? `  ${opts.client} has no hook leg; this check is about hosted connectors only.`
                    : '  Fix: mcp-recorder protect --client claude-code',
            ]));
        }
        else if (hookPolicy.deny.length === 0) {
            checks.push(fail('C3', 'name spellings', 'the hook policy has no deny rules at all', [
                '  A hook policy that denies nothing records hosted connector calls and governs none.',
                `  Fix: add deny rules to ${hookPolicyPath ?? 'the hook policy'}, or run mcp-recorder protect`,
            ]));
        }
        else {
            const verdicts = checkSpellings(hookPolicy, tools);
            // TWO ways a rule can be anchored, and doctor needs both.
            //
            // SYNTACTIC: the rule's regex NAMES a segment. This needs no
            // vocabulary and catches the rule even when doctor cannot construct
            // the spelling it was written for — cloud dogfood 4 saw `ClickUp`
            // where the vendor host reads `clickup`, and no rule for turning one
            // into the other is trustworthy, so a purely behavioural check would
            // have reported that rule as fine.
            //
            // BEHAVIOURAL: the rule matches some spellings of a tool and misses
            // others. This catches an anchor the syntactic check cannot see (a
            // narrow character class, a partial wildcard) and, when it fires, it
            // can SHOW the person the exact names their rule would miss.
            const behavioural = new Map();
            for (const v of verdicts)
                if (v.missed.length > 0 && !behavioural.has(v.ruleIndex))
                    behavioural.set(v.ruleIndex, v);
            const syntactic = new Map();
            hookPolicy.deny.forEach((rule, i) => {
                const segment = anchoredSegment(rule.tool.source);
                if (segment !== undefined)
                    syntactic.set(i, segment);
            });
            const anchoredRules = [...new Set([...syntactic.keys(), ...behavioural.keys()])].sort((a, b) => a - b);
            // A rule that governs none of the discovered tools is NOT a failure: a
            // rule for a tool you do not have is a rule for a tool you do not have.
            // It is worth saying, because it looks the same as one that stopped
            // matching.
            const governing = new Set(verdicts.map((v) => v.ruleIndex));
            const governsNothing = hookPolicy.deny
                .map((rule, i) => ({ i, source: rule.tool.source }))
                .filter((r) => !governing.has(r.i));
            const spellingsPerTool = toolSpellings(tools[0] ?? { configKey: 'connector', tool: 'x' }).length;
            if (anchoredRules.length > 0) {
                const detail = [];
                for (const i of anchoredRules) {
                    const source = hookPolicy.deny[i]?.tool.source ?? '';
                    detail.push(`  rule ${i}  /${source}/`);
                    const segment = syntactic.get(i);
                    if (segment !== undefined) {
                        detail.push(`    anchored to the segment "${segment}", which the CLIENT chooses, not you`);
                    }
                    const v = behavioural.get(i);
                    if (v !== undefined) {
                        for (const m of v.matched)
                            detail.push(`    matches      ${m.name}`);
                        for (const m of v.missed)
                            detail.push(`    MISSES       ${m.name}   (${m.origin})`);
                    }
                    detail.push('');
                }
                detail.push('  The <server> segment is chosen by the client, not by you, and it has differed', '  between two sessions a day apart and between two surfaces of one machine at the', '  same time. A rule anchored to one spelling stops matching when it changes,', '  silently, with no error anywhere: cloud dogfood 4 ended with two live connector', '  calls against a real workspace and a 62-event signed bundle holding ZERO policy', '  decisions, for exactly this reason.', '', '  Fix: leave the segment open —  ^mcp__.*__<tool>$');
                checks.push(fail('C3', 'name spellings', `${anchoredRules.length} of ${hookPolicy.deny.length} deny rules are anchored to a server segment`, detail));
            }
            else if (usingProbeVocabulary) {
                checks.push(incomplete('C3', 'name spellings', `${hookPolicy.deny.length} deny rules are segment-open, but no live MCP config was found`, [
                    `  Checked against a built-in probe vocabulary (${PROBE_CONNECTOR_TOOLS.length} names), not your real one:`,
                    '  no /tmp/mcp-config-*.json exists and MCP_RECORDER_MCP_CONFIG is unset, which is the',
                    '  ordinary local case. The rules are open; whether they match YOUR connectors is unchecked.',
                    ...(governsNothing.length > 0
                        ? [`  ${governsNothing.length} rule(s) matched none of the probe names, which may be fine or may be the absence:`, ...governsNothing.map((r) => `    /${r.source}/`)]
                        : []),
                    '  Fix: run this again from the session you want checked, or set MCP_RECORDER_MCP_CONFIG',
                ]));
            }
            else {
                checks.push(ok('C3', 'name spellings', `${hookPolicy.deny.length} deny rules x ${spellingsPerTool} spellings x ${tools.length} connector tools — all match`, 
                // Not a failure: a rule for a tool you do not have is a rule for
                // a tool you do not have. It is worth SAYING, because it is also
                // what a rule that no longer matches anything looks like.
                governsNothing.length === 0
                    ? []
                    : [
                        `  ${governsNothing.length} rule(s) govern none of your tools (they are open, they just match nothing you have):`,
                        ...governsNothing.map((r) => `    /${r.source}/`),
                    ]));
            }
        }
    }
    /* --- C4 coverage ------------------------------------------------------ */
    {
        const rows = coverage(policy, hookPolicy, stdioServers, connectors);
        const denied = rows.filter((r) => r.action === 'deny');
        const held = rows.filter((r) => r.action === 'hold');
        report.coverage = { denied: denied.length, held: held.length, allowed: rows.length - denied.length - held.length };
        const unenumerated = stdioServers.filter((s) => s.error !== undefined);
        const detail = [
            `  ${String(denied.length).padStart(3)} denied   ${denied.map((r) => r.tool).slice(0, 8).join(' ')}`,
            `  ${String(held.length).padStart(3)} held     ${held.map((r) => r.tool).slice(0, 8).join(' ')}`,
            `  ${String(report.coverage.allowed).padStart(3)} allowed`,
        ];
        if (rows.length === 0) {
            checks.push(incomplete('C4', 'coverage', `${unenumerated.length || 'all'} of ${stdioServers.length} servers could not be enumerated — no tools were discovered at all`, [
                ...unenumerated.map((s) => `  ${s.server}  ${s.error ?? ''} — no tool list, so this server's coverage is UNKNOWN.`),
                '  It is not "fine"; it is unchecked.',
            ]));
        }
        else if (denied.length + held.length === 0) {
            checks.push(fail('C4', 'coverage', `${rows.length} tools discovered; 0 denied, 0 held, ${rows.length} allowed`, [
                '  The policy loads, validates and is in force, and it matches NONE of the tools your',
                '  servers actually expose. Every call will be allowed and the evidence chain will look',
                '  completely healthy. This is the failure that does not report itself.',
                '',
                "  Your servers' tool names:",
                ...Object.entries(report.tools).map(([server, tools]) => `    ${server.padEnd(14)} ${tools.slice(0, 10).join(' ')}`),
                '',
                `  Fix: your rules use names your servers do not. Compare that list with the tool globs`,
                `       in ${policyPath ?? 'your policy'}, or run  mcp-recorder protect`,
            ]));
        }
        else if (unenumerated.length > 0) {
            checks.push(incomplete('C4', 'coverage', `${unenumerated.length} of ${stdioServers.length} servers could not be enumerated`, [
                ...unenumerated.map((s) => `  ${s.server}  ${s.error ?? ''} — no tool list, so this server's coverage is UNKNOWN.`),
                '  It is not "fine"; it is unchecked.',
                ...detail,
            ]));
        }
        else {
            checks.push(ok('C4', 'coverage', `${rows.length} tools discovered (${stdioServers.length} servers, ${connectors.length} connectors)`, detail));
        }
    }
    /* --- C5 probe --------------------------------------------------------- */
    {
        if (!opts.probe) {
            checks.push(incomplete('C5', 'probe', '--no-probe: no live call was pushed through the real code path', [
                '  C1-C4 read configuration. Only the probe proves a deny actually FIRES.',
            ]));
        }
        else if (policy === undefined || policyPath === undefined) {
            checks.push(incomplete('C5', 'probe', 'no gateway policy is in force, so there was nothing to probe', []));
        }
        else {
            const plan = planProbe(policy, policyPath, opts.dataDir, stdioServers);
            if (plan === undefined) {
                checks.push(incomplete('C5', 'probe', 'no discovered tool is denied by this policy on a call with no side effects', [
                    '  The probe only ever sends a call the policy has ALREADY decided to deny, so the',
                    '  server never sees it. None could be constructed here, so nothing was proved live.',
                ]));
            }
            else {
                const tmp = mkdtempSync(join(tmpdir(), 'mcp-recorder-doctor-'));
                try {
                    const r = await stdioSession(process.execPath, [
                        opts.cliPath,
                        'record',
                        '--data-dir',
                        tmp,
                        '--store',
                        'jsonl',
                        '--policy',
                        policyPath,
                        '--',
                        plan.inner.command,
                        ...(plan.inner.args ?? []),
                    ], { timeoutMs, env: { ...opts.env, [ENV.DISABLE]: '' }, call: { name: plan.tool, arguments: plan.args }, graceful: true });
                    const named = (r.callText ?? '').includes(plan.ruleId);
                    // Wait for the DECISION to reach the chain, not for the process to
                    // die. Recording is fail-open and therefore asynchronous: the
                    // refusal reaches the client before the event reaches the store, so
                    // reading the store the instant the answer arrives finds nothing and
                    // reports the very absence it is looking for.
                    const decisions = await waitForDecision(tmp, timeoutMs);
                    checks.push(probeVerdict(plan, {
                        ...(r.callIsError !== undefined ? { callIsError: r.callIsError } : {}),
                        named,
                        decisions,
                        ...(r.error !== undefined ? { error: r.error } : {}),
                    }));
                }
                finally {
                    rmSync(tmp, { recursive: true, force: true });
                }
            }
        }
    }
    /* --- C6 chain --------------------------------------------------------- */
    {
        try {
            const store = openStoreReadOnly({ dataDir: opts.dataDir });
            try {
                const result = await verifyStore(store, { allowUnsigned: true });
                let decisions = 0;
                for (const rec of store.iterate())
                    if (rec.event.kind === 'policy_decision')
                        decisions++;
                const sessions = store.sessions().length;
                const summary = `${result.ok ? 'PASS' : 'FAIL'}, ${result.checked_events} events, ${decisions} policy decisions, ${sessions} session(s)`;
                checks.push(result.ok
                    ? ok('C6', 'chain', summary, decisions === 0 ? ['  no decisions recorded yet — that is a fact, not a pass'] : [])
                    : fail('C6', 'chain', summary, result.problems.slice(0, 5).map((pr) => `  ${pr.type} at seq ${pr.seq}: ${pr.detail}`)));
            }
            finally {
                store.close();
            }
        }
        catch (cause) {
            checks.push(incomplete('C6', 'chain', `the evidence directory could not be read: ${cause instanceof Error ? cause.message : String(cause)}`, [
                `  ${opts.dataDir}`,
            ]));
        }
    }
    report.verdict = checks.some((c) => c.status === 'FAIL')
        ? 'fail'
        : checks.some((c) => c.status === 'INCOMPLETE')
            ? 'incomplete'
            : 'ok';
    return report;
}
/** 0 ok / 1 at least one FAIL / 3 no FAIL but at least one INCOMPLETE. */
export function doctorExitCode(report) {
    if (report.verdict === 'fail')
        return 1;
    if (report.verdict === 'incomplete')
        return 3;
    return 0;
}
/**
 * The human report. The last line is the verdict, because that is the line a
 * person reads, and it counts INCOMPLETE separately — folding it into "OK"
 * is exactly the reporting bug this command exists to fix.
 */
export function renderDoctor(report) {
    const lines = [];
    if (report.config !== undefined)
        lines.push(`config: ${report.config}`);
    if (report.policy !== undefined) {
        lines.push(`policy: ${report.policy.path}  (${report.policy.hash.slice(0, 15)}…, ${report.policy.rules} mcp rules)`);
    }
    if (report.hook_policy !== undefined) {
        lines.push(`hook:   ${report.hook_policy.path}  (${report.hook_policy.deny_rules} deny rules)`);
    }
    lines.push('');
    for (const c of report.checks) {
        lines.push(`${c.status.padEnd(10)} ${c.id} ${c.title.padEnd(15)} ${c.summary}`);
        for (const d of c.detail)
            lines.push(d);
        if (c.detail.length > 0)
            lines.push('');
    }
    const okCount = report.checks.filter((c) => c.status === 'OK').length;
    const failCount = report.checks.filter((c) => c.status === 'FAIL').length;
    const incCount = report.checks.filter((c) => c.status === 'INCOMPLETE').length;
    lines.push(`doctor: ${okCount} checks OK, ${failCount} failed, ${incCount} incomplete`);
    return lines;
}
/**
 * The one-paragraph verdict `protect` prints last. Deliberately the same
 * numbers as the full report: a person who runs `protect` and a person who
 * runs `doctor` must not be told different things.
 */
export function doctorVerdictLines(report) {
    const okCount = report.checks.filter((c) => c.status === 'OK').length;
    const failCount = report.checks.filter((c) => c.status === 'FAIL').length;
    const incCount = report.checks.filter((c) => c.status === 'INCOMPLETE').length;
    const total = report.coverage.denied + report.coverage.held + report.coverage.allowed;
    const spellings = report.checks.find((c) => c.id === 'C3');
    return [
        `doctor: ${okCount} checks OK, ${failCount} failed, ${incCount} incomplete`,
        `  enforcement is in force for ${report.stdio.enforcing} of ${report.stdio.total} stdio servers and ${report.connectors} connector(s)`,
        `  ${total} tools discovered; ${report.coverage.denied} denied, ${report.coverage.held} held, ${report.coverage.allowed} allowed`,
        ...(report.coverage.held > 0
            ? ['    a held call STOPS the agent until you answer it; unanswered, it stalls and is then refused']
            : []),
        `  ${spellings?.status === 'OK' ? 'every deny rule matches on every tool-name spelling this client could choose' : `name spellings: ${spellings?.status ?? 'not checked'} — ${spellings?.summary ?? ''}`}`,
    ];
}
//# sourceMappingURL=run.js.map