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
import { ENV_VAR_PATTERN, HOSTNAME_PATTERN, ID_PATTERN, LIMITS, ROLE_ARN_PATTERN } from './types.js';

export const POLICY_SCHEMA_ID = 'https://cresec.ai/schemas/agent-policy.v1.json';

const ACTION: JsonSchema = { type: 'string', enum: ['allow', 'hold', 'deny'] };

export const POLICY_SCHEMA: JsonSchema = {
  $schema: 'https://json-schema.org/draft/2020-12/schema',
  $id: POLICY_SCHEMA_ID,
  title: 'mcp-recorder agent policy v1',
  description:
    'policy.yaml v1: MCP tool-call policy and credential-broker policy (both enforced by mcp-recorder gateway mode) plus HTTP egress policy (validated and compiled to Rego only). Rules are ordered; the first matching rule wins.',
  type: 'object',
  additionalProperties: false,
  required: ['version'],
  anyOf: [{ required: ['mcp'] }, { required: ['credentials'] }, { required: ['egress'] }],
  properties: {
    version: { const: 1, description: 'Schema version. Always the literal 1.' },
    name: { $ref: '#/$defs/identifier', description: 'Optional policy identifier, stamped on events.' },
    mcp: { $ref: '#/$defs/mcpPolicy' },
    credentials: {
      type: 'array',
      minItems: 1,
      items: { $ref: '#/$defs/credential' },
      description:
        'Credentials the gateway may swap a synthetic for, and the declared sites where it may do so. A use site not listed here is never swapped.',
    },
    egress: { $ref: '#/$defs/egressPolicy' },
  },
  $defs: {
    identifier: { type: 'string', pattern: ID_PATTERN },
    action: ACTION,
    glob: {
      type: 'string',
      minLength: 1,
      description:
        'Glob: "*" = any run without the delimiter, "**" = any run; everything else literal. Case-sensitive. The "?" wildcard is not supported in v1.',
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
        reason: { type: 'string', maxLength: 512, description: 'Shown to the model on deny / hold-denied.' },
      },
    },
    mcpMatch: {
      type: 'object',
      additionalProperties: false,
      required: ['tool'],
      properties: {
        server: {
          $ref: '#/$defs/globOrList',
          description: 'Glob or list of globs on the logical server name (delimiter "/"). Default "*".',
        },
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
    credentialAction: {
      type: 'string',
      enum: ['allow', 'deny'],
      description:
        'What a matching swap site does. "hold" is not available in v1: nothing resolves a credential after an approval, and an action the gateway cannot honour must not be writable.',
    },
    credential: {
      type: 'object',
      additionalProperties: false,
      required: ['id', 'use'],
      description:
        'One credential. Exactly one of "source" (resolved on this machine) or "broker" (resolved by the Cresec control plane per user) is required.',
      properties: {
        id: { $ref: '#/$defs/identifier', description: 'Unique within the section. Recorded on every decision; never the credential value.' },
        provider: {
          $ref: '#/$defs/identifier',
          description:
            'Informational, e.g. "github". Recorded on the decision. For a "broker" credential it is the connector sent to the control plane and is required; validation then holds it to the control plane\'s closed set (salesforce, gmail, workspace, slack, outlook) — a conditional this schema\'s keyword subset cannot express.',
        },
        scopes: {
          type: 'array',
          items: { type: 'string', minLength: 1, maxLength: 128 },
          description:
            'Informational: what the REAL credential can do. Recorded on the decision so blast radius is answerable from the chain rather than reconstructed.',
        },
        source: { $ref: '#/$defs/credentialSource' },
        broker: { $ref: '#/$defs/remoteBroker' },
        use: {
          type: 'array',
          minItems: 1,
          items: { $ref: '#/$defs/credentialUse' },
          description: 'Declared swap sites, in order; the first match decides. A site not declared here is never swapped.',
        },
        ttl_seconds: {
          type: 'integer',
          minimum: LIMITS.credential_ttl_seconds.min,
          maximum: LIMITS.credential_ttl_seconds.max,
          description:
            'How long a positive decision may be cached, keyed on the whole (synthetic, method, host, path_template) tuple. Default 30, matching the control plane. 0 disables the cache.',
        },
        timeout_ms: {
          type: 'integer',
          minimum: LIMITS.credential_timeout_ms.min,
          maximum: LIMITS.credential_timeout_ms.max,
          description: 'Deadline for resolving the source. Overrunning it denies this call. Default 5000.',
        },
        synthetic_env: {
          type: 'string',
          minLength: 1,
          maxLength: 128,
          pattern: '^[A-Za-z_][A-Za-z0-9_]*$',
          description:
            'Environment variable holding the synthetic bound to this credential. Defaults to MCP_RECORDER_SYNTHETIC_<ID>. The synthetic is deliberately not in the policy: a policy file is shareable evidence of the rules, and a file of raw synthetics is a file of values redeemable on this machine.',
        },
        on_unresolved: {
          type: 'string',
          enum: ['deny'],
          description:
            'What happens when the credential cannot be resolved. Only "deny": forwarding the call would forward the synthetic to the upstream.',
        },
      },
    },
    remoteBroker: {
      type: 'object',
      additionalProperties: false,
      required: ['kind', 'url', 'token_env'],
      description:
        'Resolve this credential through the Cresec control plane: POST <url>/v1/broker/user-token per docs/internal/contracts/user-token.md in cresec-ai/nhi. The returned per-user access token is swapped at the declared sites exactly as a local source would be; the control plane\'s decision_id lands on the tool_call and policy_decision events. A 403 is a deny with the control plane\'s reason; a 5xx, a timeout or a connection failure is a deny with reason control_plane_unavailable (fail closed: the credential is absent).',
      properties: {
        kind: { const: 'remote' },
        url: { type: 'string', minLength: 1, maxLength: 2048, description: 'Control plane base URL (https://; http:// only on loopback).' },
        token_env: {
          type: 'string',
          pattern: ENV_VAR_PATTERN,
          description: 'Environment variable holding the internal bearer token (Authorization: Bearer). Named here, never its value.',
        },
        tenant: {
          type: 'string',
          minLength: 1,
          maxLength: 128,
          description: 'Tenant slug or uuid sent as X-Cresec-Tenant. Optional when the identity JWT carries tenant_id.',
        },
        user_env: {
          type: 'string',
          pattern: ENV_VAR_PATTERN,
          description: 'Environment variable holding the user id (uuid) to request tokens for. Optional when --identity-jwt (or identity_jwt_env) supplies sub.',
        },
        identity_jwt_env: {
          type: 'string',
          pattern: ENV_VAR_PATTERN,
          description: 'Environment variable holding the identity JWT itself; an alternative to --identity-jwt PATH. Supplies user_id, tenant and tool, and the actor claim stamped on every event.',
        },
        tool_id: { type: 'string', minLength: 1, maxLength: 128, description: 'Tool registry id (uuid) when no identity JWT supplies the tool claim.' },
        tool_version: { type: 'string', minLength: 1, maxLength: 64, description: 'Tool version when no identity JWT supplies the tool claim.' },
        timeout_ms: {
          type: 'integer',
          minimum: LIMITS.credential_timeout_ms.min,
          maximum: LIMITS.credential_timeout_ms.max,
          description: 'Round-trip budget for the control plane. Default 5000. Overrunning it denies this call (control_plane_unavailable).',
        },
      },
    },
    credentialSource: {
      description: 'Where the real credential is resolved from. Named by the config and only ever by the config — never by the call.',
      oneOf: [
        {
          type: 'object',
          additionalProperties: false,
          required: ['type', 'var'],
          properties: {
            type: { const: 'env' },
            var: { type: 'string', pattern: ENV_VAR_PATTERN, description: 'Environment variable of the recorder process.' },
          },
        },
        {
          type: 'object',
          additionalProperties: false,
          required: ['type', 'path'],
          properties: {
            type: { const: 'file' },
            path: { type: 'string', minLength: 1, description: 'Absolute path. A relative one would resolve against the client process’s working directory.' },
            field: { type: 'string', minLength: 1, description: 'Dot-path into the file parsed as JSON; absent = the whole file, trimmed.' },
          },
        },
        {
          type: 'object',
          additionalProperties: false,
          required: ['type', 'command'],
          properties: {
            type: { const: 'exec' },
            command: { type: 'string', minLength: 1, description: 'Absolute path to the executable. No shell: argv is passed through as written.' },
            args: { type: 'array', items: { type: 'string' } },
          },
        },
        {
          type: 'object',
          additionalProperties: false,
          required: ['type', 'app_id', 'installation_id'],
          properties: {
            type: { const: 'github-app' },
            app_id: { type: 'string', pattern: '^[0-9]{1,20}$' },
            installation_id: { type: 'string', pattern: '^[0-9]{1,20}$' },
            private_key_file: { type: 'string', minLength: 1, description: 'Absolute path to the app private key (PEM). Exactly one of private_key_file / private_key_env.' },
            private_key_env: { type: 'string', pattern: ENV_VAR_PATTERN },
            repositories: { type: 'array', items: { type: 'string', minLength: 1 }, description: 'Narrows the minted installation token to these repositories.' },
            permissions: { type: 'object', description: 'Permission name -> "read" | "write" | "admin". Narrows the minted installation token.' },
          },
        },
        {
          type: 'object',
          additionalProperties: false,
          required: ['type', 'role_arn'],
          properties: {
            type: { const: 'aws-sts' },
            role_arn: { type: 'string', pattern: ROLE_ARN_PATTERN },
            region: { type: 'string', pattern: '^[a-z0-9-]{1,32}$' },
            session_name: { type: 'string', pattern: '^[A-Za-z0-9=,.@_-]{2,64}$' },
            duration_seconds: { type: 'integer', minimum: LIMITS.aws_duration_seconds.min, maximum: LIMITS.aws_duration_seconds.max },
            external_id: { type: 'string', minLength: 2, maxLength: 1224 },
          },
        },
        {
          type: 'object',
          additionalProperties: false,
          required: ['type', 'path'],
          properties: {
            type: { const: 'vault' },
            path: { type: 'string', minLength: 1, description: 'Secret path in OpenBao/Vault.' },
            field: { type: 'string', minLength: 1, description: 'Key inside the secret blob. Default "token" — the key the control plane reads.' },
            addr: { type: 'string', minLength: 1, description: 'Base URL; http(s) only. Absent = the resolver’s own default.' },
            namespace: { type: 'string', minLength: 1 },
            token_env: { type: 'string', pattern: ENV_VAR_PATTERN, description: 'Environment variable holding the vault token.' },
          },
        },
        {
          type: 'object',
          additionalProperties: false,
          required: ['type'],
          properties: {
            type: { const: 'clickup' },
            token_env: { type: 'string', pattern: ENV_VAR_PATTERN, description: 'Default CLICKUP_API_TOKEN.' },
            team_id: { type: 'string', pattern: '^[0-9]{1,20}$' },
          },
        },
      ],
    },
    credentialUse: {
      type: 'object',
      additionalProperties: false,
      required: ['tool', 'arg', 'host'],
      description: 'One declared swap site: (server, tool, argument dot-path) plus the destination the credential is allowed to reach.',
      properties: {
        id: { $ref: '#/$defs/identifier', description: 'Unique within the credential. Default "use[<index>]"; the recorded id is "<credential id>/<this>".' },
        server: { $ref: '#/$defs/globOrList', description: 'Glob or list of globs on the logical server name (delimiter "/"). Default "*".' },
        tool: { $ref: '#/$defs/globOrList', description: 'Glob or list of globs on the tool name (delimiter "/").' },
        arg: {
          type: 'string',
          minLength: 1,
          description:
            'Dot-path (a.b.0.c) into params.arguments. The synthetic is replaced ONLY inside the string at this path, never wherever else it occurs.',
        },
        host: { $ref: '#/$defs/credentialHost' },
        path: { $ref: '#/$defs/credentialPath' },
        action: { $ref: '#/$defs/credentialAction', description: 'Default "allow".' },
        reason: { type: 'string', maxLength: 512, description: 'Shown to the model on a deny; also copied into the compiled Rego.' },
        action_class: {
          type: 'string',
          enum: ['read', 'draft', 'send', 'write'],
          description:
            'The control plane\'s action class for this site (user-token.md). Sent as action_class on the per-user token request of a "broker" credential; informational otherwise. Default "write", the class that always needs a grant.',
        },
        method: {
          type: 'string',
          pattern: '^[A-Za-z]{1,16}$',
          description: 'The HTTP method this site\'s request maps onto (target.method on the per-user token request). Default "POST". Upper-cased.',
        },
      },
    },
    credentialHost: {
      description:
        'Where request.host comes from, and what it must be. Required: a swap site with no host constraint is a full-privilege credential with extra steps.',
      oneOf: [
        {
          type: 'object',
          additionalProperties: false,
          required: ['from_arg', 'allow'],
          properties: {
            from_arg: { type: 'string', minLength: 1, description: 'Dot-path to an argument holding an absolute URL; its hostname is the destination.' },
            allow: { $ref: '#/$defs/globOrList', description: 'Globs on the host (delimiter "."). The call is denied unless one matches.' },
          },
        },
        {
          type: 'object',
          additionalProperties: false,
          required: ['fixed'],
          properties: {
            fixed: {
              type: 'string',
              pattern: HOSTNAME_PATTERN,
              description: 'The upstream this server always talks to, asserted by the operator. Recorded as host_source "declared" — checked against nothing in the call.',
            },
          },
        },
        {
          type: 'object',
          additionalProperties: false,
          required: ['from'],
          properties: {
            from: {
              const: 'server',
              description: 'No destination: the logical server name stands in for the host. Recorded as host_source "server_name", which authorises the tool and not the destination.',
            },
          },
        },
      ],
    },
    credentialPath: {
      description: 'Where request.path_template comes from. Absent = the tool name.',
      oneOf: [
        {
          type: 'object',
          additionalProperties: false,
          required: ['from_arg', 'allow'],
          properties: {
            from_arg: { type: 'string', minLength: 1, description: 'Dot-path to an argument carrying the path or resource being addressed.' },
            allow: { $ref: '#/$defs/globOrList', description: 'Globs on that value (delimiter "/").' },
          },
        },
        {
          type: 'object',
          additionalProperties: false,
          required: ['from'],
          properties: { from: { const: 'tool' } },
        },
      ],
    },
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
        reason: { type: 'string', maxLength: 512 },
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
