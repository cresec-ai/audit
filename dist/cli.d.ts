#!/usr/bin/env node
/**
 * mcp-recorder CLI — subcommand dispatch.
 *
 * record / http modes NEVER print to stdout (stdout is the MCP wire);
 * diagnostics go to stderr prefixed "[mcp-recorder]". Inspection commands
 * (verify/query/sessions) print human or --json output on stdout.
 *
 * Exit codes: 0 ok (record/http: the wrapped server's code), 1 verification
 * failed / nothing to export, 2 usage or unexpected error.
 */
export {};
