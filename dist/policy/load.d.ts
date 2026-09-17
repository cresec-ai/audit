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
