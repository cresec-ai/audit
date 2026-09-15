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
import { ID_PATTERN, LIMITS } from './types.js';

export const POLICY_SCHEMA_ID = 'https://cresec.ai/schemas/agent-policy.v1.json';

const ACTION: JsonSchema = { type: 'string', enum: ['allow', 'hold', 'deny'] };

export const POLICY_SCHEMA: JsonSchema = {
  $schema: 'https://json-schema.org/draft/2020-12/schema',
  $id: POLICY_SCHEMA_ID,
  title: 'mcp-recorder agent policy v1',
  description:
    'policy.yaml v1: MCP tool-call policy (enforced by mcp-recorder gateway mode) and HTTP egress policy (validated and compiled to Rego only). Rules are ordered; the first matching rule wins.',
  type: 'object',
  additionalProperties: false,
  required: ['version'],
  anyOf: [{ required: ['mcp'] }, { required: ['egress'] }],
  properties: {
    version: { const: 1, description: 'Schema version. Always the literal 1.' },
    name: { $ref: '#/$defs/identifier', description: 'Optional policy identifier, stamped on events.' },
    mcp: { $ref: '#/$defs/mcpPolicy' },
    egress: { $ref: '#/$defs/egressPolicy' },
  },
  $defs: {
    identifier: { type: 'string', pattern: ID_PATTERN },
    action: ACTION,
    glob: {
      type: 'string',
      minLength: 1,
      description:
        'Glob: "*" = any run without the delimiter, "**" = any run, "?" = one non-delimiter character; everything else literal. Case-sensitive.',
    },
    globOrList: {
      anyOf: [{ $ref: '#/$defs/glob' }, { type: 'array', minItems: 1, items: { $ref: '#/$defs/glob' } }],
    },
    mcpPolicy: {
      type: 'object',
      additionalProperties: false,
      properties: {
        default: { $ref: '#/$defs/action', description: 'Action when no rule matches. Default "allow".' },
        rules: { type: 'array', items: { $ref: '#/$defs/mcpRule' } },
        hold: { $ref: '#/$defs/hold' },
        boundary: { $ref: '#/$defs/boundary' },
      },
    },
    mcpRule: {
      type: 'object',
      additionalProperties: false,
      required: ['match', 'action'],
      properties: {
        id: { $ref: '#/$defs/identifier', description: 'Default "rule[<index>]".' },
        match: { $ref: '#/$defs/mcpMatch' },
        action: { $ref: '#/$defs/action' },
        reason: { type: 'string', description: 'Shown to the model on deny / hold-denied.' },
      },
    },
    mcpMatch: {
      type: 'object',
      additionalProperties: false,
      required: ['tool'],
      properties: {
        server: { $ref: '#/$defs/glob', description: 'Glob on the logical server name (delimiter "/"). Default "*".' },
        tool: { $ref: '#/$defs/globOrList', description: 'Glob or list of globs on the tool name (delimiter "/").' },
        args: {
          type: 'object',
          description:
            'Dot-path (a.b.0.c) -> RE2-compatible regex. Every value must be a string regex; all entries must match. A missing path never matches.',
        },
        max_args_bytes: {
          type: 'integer',
          minimum: 0,
          description: 'Rule only matches when the canonical JSON of args is at most this many bytes.',
        },
      },
    },
    hold: {
      type: 'object',
      additionalProperties: false,
      properties: {
        timeout_ms: { type: 'integer', minimum: LIMITS.hold_timeout_ms.min, maximum: LIMITS.hold_timeout_ms.max },
        on_timeout: { type: 'string', enum: ['deny', 'allow'] },
      },
    },
    boundary: {
      type: 'object',
      additionalProperties: false,
      properties: {
        secrets: { $ref: '#/$defs/boundaryMode' },
        injection: { $ref: '#/$defs/boundaryMode' },
        max_scan_bytes: { type: 'integer', minimum: LIMITS.max_scan_bytes.min, maximum: LIMITS.max_scan_bytes.max },
        on_oversize: { type: 'string', enum: ['flag', 'block'] },
      },
    },
    boundaryMode: { type: 'string', enum: ['redact', 'block', 'flag', 'off'] },
    egressPolicy: {
      type: 'object',
      additionalProperties: false,
      properties: {
        default: { $ref: '#/$defs/action', description: 'Action when no rule matches. Default "deny".' },
        rules: { type: 'array', items: { $ref: '#/$defs/egressRule' } },
      },
    },
    egressRule: {
      type: 'object',
      additionalProperties: false,
      required: ['match', 'action'],
      properties: {
        id: { $ref: '#/$defs/identifier' },
        match: { $ref: '#/$defs/egressMatch' },
        action: { $ref: '#/$defs/action' },
        reason: { type: 'string' },
      },
    },
    egressMatch: {
      type: 'object',
      additionalProperties: false,
      required: ['host'],
      properties: {
        host: { $ref: '#/$defs/globOrList', description: 'Glob or list of globs on the host (delimiter ".").' },
        methods: {
          type: 'array',
          minItems: 1,
          items: { type: 'string', pattern: '^[A-Z]{1,16}$' },
          description: 'Upper-case HTTP methods. Absent = any method.',
        },
        path: { $ref: '#/$defs/globOrList', description: 'Glob or list of globs on the path (delimiter "/"). Default "/**".' },
        max_body_bytes: { type: 'integer', minimum: 0 },
      },
    },
  },
};
