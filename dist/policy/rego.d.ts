/**
 * Compile a normalized policy into an OPA bundle directory (nhi style):
 *
 *   .manifest                    {"revision": "<policy sha256 hex>", "roots": ["cresec/gateway"]}
 *   cresec/gateway/mcp.rego      package cresec.gateway.mcp     (always)
 *   cresec/gateway/egress.rego   package cresec.gateway.egress  (only when `egress` is present)
 *
 * Output is deterministic (same policy + options => identical bytes), uses
 * tabs like `opa fmt`, `import rego.v1`, and emits every string literal via
 * JSON.stringify (Rego string syntax accepts JSON escapes). Each rule body
 * mirrors `engine.ts` predicate for predicate:
 *
 *   glob.match(pattern, ["/"], input.server)         server / tool / path
 *   glob.match(pattern, ["."], input.host)           host
 *   some p in [...]; glob.match(p, ...)              lists with more than one glob
 *   v0 := object.get(input.args, ["a", 0, "c"], null); v0 != null;
 *   type_name(v0) in {"string", "number", "boolean"}; regex.match(re, sprintf("%v", [v0]))
 *   input.args_bytes <= N / input.body_bytes <= N
 *   input.method in ["GET", "HEAD"]
 *
 * `rule_matches` is the set of matching rule indexes and `first_match` its
 * minimum, so "first match wins" is expressed by index, exactly like the TS
 * engine. `rules[i].reason` is always present ("" when unset) so `decision`
 * is never undefined.
 */
import type { Policy } from './types.js';
export interface CompileOptions {
    /** `sha256:<hex>` (or bare 64-hex) of the policy file bytes; becomes the bundle revision. */
    policyHash: string;
    policyName?: string;
    toolVersion: string;
}
export interface RegoBundle {
    /** Published path (relative, "/"-separated) -> file contents. */
    files: Record<string, string>;
}
export declare const MANIFEST_PATH = ".manifest";
export declare const MCP_REGO_PATH = "cresec/gateway/mcp.rego";
export declare const EGRESS_REGO_PATH = "cresec/gateway/egress.rego";
export declare const BUNDLE_ROOTS: readonly string[];
/** Canonical write order for bundle files. */
export declare const BUNDLE_FILE_ORDER: readonly string[];
/** The bundle's file paths in canonical order (known files first, then any others sorted). */
export declare function bundleFileOrder(files: Record<string, string>): string[];
/** Strip an optional `sha256:` prefix and require 64 lowercase hex. */
export declare function policyRevision(policyHash: string): string;
/** Render `cresec/gateway/mcp.rego`. A policy without `mcp` compiles to the documented default (allow, no rules). */
export declare function renderMcpModule(policy: Policy, opts: CompileOptions): string;
/** Render `cresec/gateway/egress.rego`; throws when the policy has no `egress` section. */
export declare function renderEgressModule(policy: Policy, opts: CompileOptions): string;
/** Compile a normalized policy into an OPA bundle (in-memory file map). */
export declare function compileToRego(policy: Policy, opts: CompileOptions): RegoBundle;
