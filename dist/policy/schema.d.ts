/**
 * The policy.yaml v1 JSON Schema as a TypeScript constant.
 *
 * `docs/policy-schema.json` is the published copy of this object (byte-for-
 * byte `JSON.stringify(POLICY_SCHEMA, null, 2) + "\n"`); a test asserts the
 * two never drift. The constant is the runtime source of truth because the
 * package ships `dist/` without `docs/`, so the validator must not read the
 * JSON file from disk. Only keywords from `jsonschema.ts`'s
 * `SUPPORTED_KEYWORDS` may appear here.
 */
import type { JsonSchema } from './jsonschema.js';
export declare const POLICY_SCHEMA_ID = "https://cresec.ai/schemas/agent-policy.v1.json";
export declare const POLICY_SCHEMA: JsonSchema;
