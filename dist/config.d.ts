/**
 * Config resolution: flag > env > default. Produces the RecorderConfig the
 * CLI hands to every other module.
 *
 * Two entry points, because record/http and the inspection subcommands have
 * opposite failure needs:
 *
 *   - `resolveConfig()` is STRICT: an invalid --redact/--store value throws.
 *     Used by verify/query/sessions/ui/export, which have no wrapped-server
 *     traffic to protect, so failing loudly (exit 2) is correct.
 *   - `resolveConfigLenient()` NEVER throws: an invalid --redact/--store
 *     flag or env value is reported as a warning and replaced with its safe
 *     default (allowlist redaction, automatic store backend). Used by
 *     record/http, where nothing about recording configuration may prevent
 *     the wrapped server from being spawned (fail-open).
 *
 * Neither function creates the data directory anymore — see `ensureDataDir`.
 * Record/http create it inside their fail-open init path (a bad --data-dir
 * degrades to pure passthrough there instead of throwing); the strict
 * inspection commands create it via whichever store/signer they open.
 */
import type { RecorderConfig } from './types.js';
export interface ResolveConfigOpts {
    flags: Record<string, string | boolean | undefined>;
    env: NodeJS.ProcessEnv;
}
export interface LenientConfigResult {
    config: RecorderConfig;
    /** Invalid flag/env values that were ignored in favor of a safe default. */
    warnings: string[];
}
/** Ensure the data directory exists with private (0o700) permissions — it
 * holds the ed25519 signing key. */
export declare function ensureDataDir(dataDir: string): void;
export declare function resolveConfig(opts: ResolveConfigOpts): RecorderConfig;
/** Same resolution as `resolveConfig`, but fail-open: never throws. */
export declare function resolveConfigLenient(opts: ResolveConfigOpts): LenientConfigResult;
