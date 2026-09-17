/**
 * Policy file loader: bytes -> parsed document -> validated, normalized
 * `Policy`, plus the sha256 of the exact file bytes (the `policy_hash`
 * stamped on events).
 *
 * `.json` is parsed with JSON.parse; everything else (`.yaml`, `.yml`, and
 * any other extension — YAML is a superset of JSON) with the `yaml` package
 * using the YAML 1.2 core schema, duplicate keys rejected, `<<` merge keys
 * disabled and a low alias cap. Values that are not JSON-plain (`!!binary`,
 * `!!set`, `.nan`, `.inf`, ...) are rejected after parsing so a policy can
 * never contain anything JSON.stringify would mangle.
 *
 * Failures are `PolicyLoadError` (unreadable / unparseable / bad root) or its
 * subclass `PolicyValidationError` (schema / semantic errors, with the error
 * list attached). Both name the file path in their message.
 *
 * A loaded policy also carries `trust`: whether the uid running this process
 * can write the file it came from. That is not a property of the document, so
 * it is never a validation error; it is what an ENFORCING caller needs before
 * it resolves a credential source named by that file
 * (see {@link credentialTrustProblems}).
 */
import { readFileSync, statSync } from 'node:fs';
import { extname } from 'node:path';
import { parse as parseYaml } from 'yaml';
import { sha256Hex } from '../chain/hash.js';
import { formatPolicyErrors, validatePolicyObject } from './validate.js';
export class PolicyLoadError extends Error {
    path;
    constructor(path, detail) {
        super(`${path}: ${detail}`);
        this.name = 'PolicyLoadError';
        this.path = path;
    }
}
export class PolicyValidationError extends PolicyLoadError {
    errors;
    constructor(path, errors) {
        super(path, `invalid policy (${errors.length} error${errors.length === 1 ? '' : 's'})\n${formatPolicyErrors(errors)}`);
        this.name = 'PolicyValidationError';
        this.errors = errors;
    }
}
/**
 * Decide writability from stat facts alone — injected rather than read, so
 * the table of cases is testable without chmod games or a second uid.
 *
 * Anything unknown is treated as writable: on Windows there are no POSIX
 * mode bits to read, and guessing "safe" there would turn a control into a
 * decoration.
 */
export function fileTrustFrom(owner, me) {
    if (owner === undefined)
        return { writableByThisUid: true, detail: 'the policy file could not be stat()ed' };
    if (me === undefined) {
        return {
            writableByThisUid: true,
            detail: 'this platform reports no uid or mode bits, so the recorder cannot tell who may write the policy',
        };
    }
    const mode = owner.mode & 0o777;
    if (me.uid === 0)
        return { writableByThisUid: true, detail: 'the recorder runs as root, which ignores the mode bits' };
    if ((mode & 0o002) !== 0)
        return { writableByThisUid: true, detail: `the policy file is world-writable (mode ${mode.toString(8).padStart(4, '0')})` };
    if ((mode & 0o020) !== 0 && (me.gid === owner.gid || me.groups.includes(owner.gid))) {
        return { writableByThisUid: true, detail: `the policy file is group-writable by a group this process is in (mode ${mode.toString(8).padStart(4, '0')})` };
    }
    if ((mode & 0o200) !== 0 && owner.uid === me.uid) {
        return { writableByThisUid: true, detail: 'the policy file is owned by the uid running the recorder, which is also the uid the agent runs as' };
    }
    return { writableByThisUid: false, detail: `the policy file is not writable by uid ${me.uid} (mode ${mode.toString(8).padStart(4, '0')}, owner uid ${owner.uid})` };
}
/** This process's uid/gid/groups, or undefined where the platform has none. */
export function processIdentity() {
    if (typeof process.getuid !== 'function' || typeof process.getgid !== 'function')
        return undefined;
    let groups = [];
    try {
        groups = process.getgroups?.() ?? [];
    }
    catch {
        groups = []; // getgroups can fail on a stripped-down container; treat it as "no extra groups"
    }
    return { uid: process.getuid(), gid: process.getgid(), groups };
}
/** `fileTrustFrom` against the real filesystem. Never throws. */
export function policyFileTrust(path) {
    let owner;
    try {
        const st = statSync(path);
        owner = { uid: st.uid, gid: st.gid, mode: st.mode };
    }
    catch {
        owner = undefined;
    }
    return fileTrustFrom(owner, processIdentity());
}
/**
 * Why this policy's credential sources must not be resolved from a file this
 * uid can write — one message per offending credential, empty when there is
 * nothing to say.
 *
 * Only `exec` is refused. The difference is not that `env` and `file` are
 * safe (an attacker who can edit the policy can point either at whatever they
 * like); it is that `exec` runs a command of their choosing AS THE RECORDER
 * on every call, so a writable policy is a shell rather than a redirection.
 * Callers that enforce — the gateway, the broker — refuse the source and say
 * this on stderr; `policy validate` reports the document, not the machine it
 * happens to be sitting on, so it does not fail on this.
 */
export function credentialTrustProblems(policy, trust) {
    if (!trust.writableByThisUid)
        return [];
    const out = [];
    for (const credential of policy.credentials ?? []) {
        if (credential.source.type !== 'exec')
            continue;
        out.push(`credential ${JSON.stringify(credential.id)} resolves through an \`exec\` source, but ${trust.detail} — ` +
            'anything that can write the policy can choose the command it runs, as the recorder, on every call');
    }
    return out;
}
/** Max aliases a YAML document may expand; policies never need many. */
const MAX_ALIASES = 100;
function isPlainObject(v) {
    return typeof v === 'object' && v !== null && Object.getPrototypeOf(v) === Object.prototype;
}
/**
 * Ensure a parsed tree contains only JSON values (null, finite number,
 * string, boolean, array, plain object). Returns a pointer + reason for the
 * first offender, or undefined.
 */
export function findNonJsonValue(value, path = '') {
    if (value === null || typeof value === 'string' || typeof value === 'boolean')
        return undefined;
    if (typeof value === 'number') {
        return Number.isFinite(value) ? undefined : { path, reason: `non-finite number ${String(value)}` };
    }
    if (Array.isArray(value)) {
        for (let i = 0; i < value.length; i++) {
            const bad = findNonJsonValue(value[i], `${path}/${i}`);
            if (bad !== undefined)
                return bad;
        }
        return undefined;
    }
    if (isPlainObject(value)) {
        for (const [k, v] of Object.entries(value)) {
            const bad = findNonJsonValue(v, `${path}/${k.replace(/~/g, '~0').replace(/\//g, '~1')}`);
            if (bad !== undefined)
                return bad;
        }
        return undefined;
    }
    const kind = value === undefined
        ? 'undefined'
        : typeof value === 'object'
            ? Object.getPrototypeOf(value)?.constructor?.name ?? 'object'
            : typeof value;
    return { path, reason: `unsupported value of type ${kind} (only JSON values are allowed)` };
}
export function sourceForPath(path) {
    return extname(path).toLowerCase() === '.json' ? 'json' : 'yaml';
}
/** Parse policy text as YAML or JSON into a JSON-plain object root. Throws PolicyLoadError. */
export function parsePolicyText(text, source, path) {
    let doc;
    try {
        doc =
            source === 'json'
                ? JSON.parse(text)
                : parseYaml(text, {
                    schema: 'core',
                    version: '1.2',
                    uniqueKeys: true,
                    merge: false,
                    maxAliasCount: MAX_ALIASES,
                    prettyErrors: true,
                });
    }
    catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        throw new PolicyLoadError(path, `${source === 'json' ? 'JSON' : 'YAML'} parse error: ${msg}`);
    }
    if (!isPlainObject(doc)) {
        const got = doc === null || doc === undefined ? 'empty document' : Array.isArray(doc) ? 'array' : typeof doc;
        throw new PolicyLoadError(path, `policy root must be a mapping/object, got ${got}`);
    }
    const bad = findNonJsonValue(doc);
    if (bad !== undefined)
        throw new PolicyLoadError(path, `${bad.path || '/'}: ${bad.reason}`);
    return doc;
}
/**
 * Read, parse, validate and normalize a policy file. Throws
 * `PolicyLoadError` / `PolicyValidationError`; never returns a partially
 * valid policy.
 */
export function loadPolicyFile(path) {
    let bytes;
    try {
        bytes = readFileSync(path);
    }
    catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        throw new PolicyLoadError(path, `cannot read policy file: ${msg}`);
    }
    const source = sourceForPath(path);
    const doc = parsePolicyText(bytes.toString('utf8'), source, path);
    const result = validatePolicyObject(doc);
    if (!result.ok)
        throw new PolicyValidationError(path, result.errors);
    const out = {
        policy: result.policy,
        hash: 'sha256:' + sha256Hex(bytes),
        source,
        path,
        trust: policyFileTrust(path),
    };
    if (result.policy.name !== undefined)
        out.name = result.policy.name;
    return out;
}
//# sourceMappingURL=load.js.map