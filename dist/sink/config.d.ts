/**
 * Sink configuration: flag > env > default, exactly like src/config.ts.
 *
 * SETTING `MCP_RECORDER_SINK` IS THE ENTIRE OPT-IN. Absent, there is no
 * sink, no shipper, and behaviour is byte-identical to a build without this
 * module. There is deliberately no second `..._ENABLED` switch.
 *
 * Resolution NEVER throws. A malformed URL, a plain-http non-loopback sink
 * or an unreadable token file is a warning and a DISABLED sink — never a
 * failed proxy start. That is the same posture `resolveConfigLenient`
 * already takes for an invalid `--redact`, and for the same reason: nothing
 * about recording configuration may prevent the wrapped server from running.
 *
 * Two variables, not one. A combined `https://token@host/` form was
 * rejected: userinfo in a URL leaks into process listings, shell history and
 * error strings.
 */
export interface SinkConfig {
    /** Base URL, normalised: origin + path, no trailing slash. */
    url: string;
    /** Bearer token, or undefined when the operator configured none. */
    token?: string;
}
export interface SinkResolution {
    /** Undefined means "no sink configured" — the default, and a no-op. */
    sink?: SinkConfig;
    /** Invalid values that were ignored; the caller prints them via its diag. */
    warnings: string[];
}
export interface ResolveSinkOpts {
    flags?: Record<string, string | boolean | string[] | undefined>;
    env: NodeJS.ProcessEnv;
}
/**
 * Normalise a sink base URL. Returns the normalised string, or an error
 * message explaining why the sink is disabled. `https://` only; certificate
 * verification is NEVER disabled anywhere in this module — the corporate-CA
 * and agent-proxy cases are handled with NODE_EXTRA_CA_CERTS, which node
 * reads on its own.
 */
export declare function normalizeSinkUrl(raw: string): {
    url: string;
} | {
    error: string;
};
/**
 * Resolve the sink from flags + env. Never throws; every failure mode is a
 * warning plus a disabled sink.
 */
export declare function resolveSinkConfig(opts: ResolveSinkOpts): SinkResolution;
