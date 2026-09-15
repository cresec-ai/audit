/**
 * Compile a normalized policy into an OPA bundle directory laid out like the
 * Cresec control plane (sibling packages to `cresec.broker`, one `decision`
 * object rule each; distinct basenames because the Helm ConfigMap flattens
 * by basename):
 *
 *   .manifest                {"revision": "<policy sha256 hex>", "roots": ["cresec/mcp", "cresec/egress"]}
 *   cresec/mcp/tool.rego     package cresec.mcp     (always)
 *   cresec/egress/http.rego  package cresec.egress  (only when `egress` is present; then and only then
 *                                                    "cresec/egress" is listed in the manifest roots)
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
 *
 * The `decision` object is a superset of the broker's, so a consumer that
 * only knows `allow` / `deny_reason` (and fails closed on a missing `allow`)
 * can evaluate `data.cresec.mcp.decision` or `data.cresec.egress.decision`
 * unchanged:
 *
 *   {"allow": <action == "allow">, "action": "allow"|"hold"|"deny", "rule_id": "...",
 *    "reason": "...", "matched": bool, "deny_reason": "..."}
 *
 * `deny_reason` is "" when the action is allow; otherwise "rule <id>: <reason>"
 * ("rule <id>" when the rule has no reason) for a matched rule and
 * "default <action>" when no rule matched and the section default applies.
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
export declare const MCP_REGO_PATH = "cresec/mcp/tool.rego";
export declare const EGRESS_REGO_PATH = "cresec/egress/http.rego";
/** Manifest root of the MCP module (always present). */
export declare const MCP_ROOT = "cresec/mcp";
/** Manifest root of the egress module (listed only when `cresec/egress/http.rego` is emitted). */
export declare const EGRESS_ROOT = "cresec/egress";
/** The `.manifest` roots for a policy: `["cresec/mcp"]`, plus `"cresec/egress"` when it has an egress section. */
export declare function bundleRoots(policy: Policy): string[];
/** Canonical write order for bundle files. */
export declare const BUNDLE_FILE_ORDER: readonly string[];
/** The bundle's file paths in canonical order (known files first, then any others sorted). */
export declare function bundleFileOrder(files: Record<string, string>): string[];
/** Strip an optional `sha256:` prefix and require 64 lowercase hex. */
export declare function policyRevision(policyHash: string): string;
/** The documented decision shape (comment in every module header). */
export declare const DECISION_SHAPE = "{\"allow\": bool, \"action\": \"allow\"|\"hold\"|\"deny\", \"rule_id\": \"...\", \"reason\": \"...\", \"matched\": bool, \"deny_reason\": \"...\"}";
/** Render `cresec/mcp/tool.rego`. A policy without `mcp` compiles to the documented default (allow, no rules). */
export declare function renderMcpModule(policy: Policy, opts: CompileOptions): string;
/** Render `cresec/egress/http.rego`; throws when the policy has no `egress` section. */
export declare function renderEgressModule(policy: Policy, opts: CompileOptions): string;
/** Compile a normalized policy into an OPA bundle (in-memory file map). */
export declare function compileToRego(policy: Policy, opts: CompileOptions): RegoBundle;
