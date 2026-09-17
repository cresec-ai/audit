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
import type { Sha256Ref } from '../schema/events.js';
import type { Policy } from './types.js';
import type { PolicyError } from './validate.js';
export type PolicySource = 'yaml' | 'json';
export interface LoadedPolicy {
    policy: Policy;
    /** `sha256:<64 hex>` of the exact file bytes. */
    hash: Sha256Ref;
    /** `policy.name`, when set. */
    name?: string;
    source: PolicySource;
    /** The path as given to `loadPolicyFile`. */
    path: string;
    /**
     * What the filesystem says about the file. Optional so that a caller which
     * builds a `LoadedPolicy` by hand (the CLI reads bytes itself, to separate
     * "unreadable" from "invalid") is not forced to supply it.
     */
    trust?: PolicyFileTrust;
}
export declare class PolicyLoadError extends Error {
    readonly path: string;
    constructor(path: string, detail: string);
}
export declare class PolicyValidationError extends PolicyLoadError {
    readonly errors: readonly PolicyError[];
    constructor(path: string, errors: readonly PolicyError[]);
}
/**
 * Whether the uid running this process can WRITE the policy file, and why.
 *
 * This matters only for the `credentials` section, and it matters a lot
 * there. A policy that can be rewritten is a policy that can be aimed: an
 * attacker who can edit it adds a swap site pointing at a host they control,
 * or widens an existing site's host glob, and an `exec` source is arbitrary
 * code execution by configuration, running as the recorder, on every call.
 * No exploit is needed — the agent already writes files.
 *
 * The honest scope: on a single-uid developer machine this is ADVISORY.
 * The recorder runs as the same uid as the agent, so a file the recorder can
 * read the agent can read, and a file the agent can write the recorder
 * believes. What the check is worth is the case where someone has actually
 * separated the two (a root-owned policy, or the hosted control plane), plus
 * the startup noise that tells a developer they have not. The tamper-evident
 * property is the one to lean on: the file's sha256 is on every event, so a
 * mid-session edit is EVIDENT in the chain even where it cannot be prevented.
 */
export interface PolicyFileTrust {
    writableByThisUid: boolean;
    /** One line naming why, for a warning or an error message. */
    detail: string;
}
/** Owner and mode of a file, as `statSync` reports them. */
export interface FileOwnership {
    uid: number;
    gid: number;
    /** `st_mode`; only the low permission bits are read. */
    mode: number;
}
/** The identity the current process runs under. `undefined` on a platform without uids. */
export interface ProcessIdentity {
    uid: number;
    gid: number;
    groups: readonly number[];
}
/**
 * Decide writability from stat facts alone — injected rather than read, so
 * the table of cases is testable without chmod games or a second uid.
 *
 * Anything unknown is treated as writable: on Windows there are no POSIX
 * mode bits to read, and guessing "safe" there would turn a control into a
 * decoration.
 */
export declare function fileTrustFrom(owner: FileOwnership | undefined, me: ProcessIdentity | undefined): PolicyFileTrust;
/** This process's uid/gid/groups, or undefined where the platform has none. */
export declare function processIdentity(): ProcessIdentity | undefined;
/** `fileTrustFrom` against the real filesystem. Never throws. */
export declare function policyFileTrust(path: string): PolicyFileTrust;
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
export declare function credentialTrustProblems(policy: Policy, trust: PolicyFileTrust): string[];
/**
 * Ensure a parsed tree contains only JSON values (null, finite number,
 * string, boolean, array, plain object). Returns a pointer + reason for the
 * first offender, or undefined.
 */
export declare function findNonJsonValue(value: unknown, path?: string): {
    path: string;
    reason: string;
} | undefined;
export declare function sourceForPath(path: string): PolicySource;
/** Parse policy text as YAML or JSON into a JSON-plain object root. Throws PolicyLoadError. */
export declare function parsePolicyText(text: string, source: PolicySource, path: string): Record<string, unknown>;
/**
 * Read, parse, validate and normalize a policy file. Throws
 * `PolicyLoadError` / `PolicyValidationError`; never returns a partially
 * valid policy.
 */
export declare function loadPolicyFile(path: string): LoadedPolicy;
