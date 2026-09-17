/**
 * Gateway mode wiring contract between the CLI and the stdio proxy.
 *
 * `runStdioProxy` receives a `GatewayOptions` ONLY when the operator passed
 * `--policy` (or MCP_RECORDER_POLICY); when the field is absent the proxy is
 * the plain byte-for-byte, fail-open recorder. Kept in its own module so the
 * CLI, the proxy and the tests share one definition without importing each
 * other's internals.
 */
export {};
//# sourceMappingURL=options.js.map