import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { afterAll, afterEach, describe, expect, it } from 'vitest';
import { sha256Hex } from '../src/chain/hash.js';
import { spawnTsxSync } from './helpers/tsx.js';
import {
  DEFAULTS,
  GLOB_CACHE_SIZE,
  POLICY_SCHEMA,
  POLICY_SCHEMA_ID,
  PolicyLoadError,
  PolicyValidationError,
  REGEX_DEADLINE_MS,
  REGEX_RETRY_MS,
  REGEX_STARTUP_MS,
  REGEX_VALUE_CAP,
  VALUE_TOO_LONG,
  SUPPORTED_KEYWORDS,
  autoRuleId,
  autoUseId,
  credentialTrustProblems,
  credentialUseId,
  fileTrustFrom,
  policyFileTrust,
  checkCatastrophicShape,
  checkGlob,
  checkProvablyLinear,
  checkRe2Subset,
  clearGlobCache,
  configureRegexGuard,
  coerceScalar,
  collectKeywords,
  compileGlob,
  dotPathSegments,
  evaluateEgress,
  evaluateMcp,
  findNonJsonValue,
  formatPolicyErrors,
  getPath,
  globCacheSize,
  globMatch,
  globToRegExp,
  jsonEqual,
  matchBounded,
  loadPolicyFile,
  normalizePolicy,
  parsePolicyText,
  regexGuardState,
  resetRegexGuard,
  ruleLabel,
  toUnicodeSource,
  warmRegexGuard,
  validateAgainstSchema,
  validatePolicyObject,
} from '../src/policy/index.js';
import type { Credential, JsonSchema, Policy, PolicyError, PolicyInput } from '../src/policy/index.js';

const ROOT = join(__dirname, '..');
const FIXTURES = join(ROOT, 'test', 'fixtures', 'policies');

/* ------------------------------- helpers -------------------------------- */

/** The design document's worked example, as an authored (un-normalized) object. */
function designExample(): PolicyInput {
  return {
    version: 1,
    name: 'laptop-default',
    mcp: {
      default: 'allow',
      rules: [
        {
          id: 'no-exfil',
          match: { server: '*', tool: ['http_post', 'send_*'], args: { url: '^https?://' }, max_args_bytes: 65536 },
          action: 'deny',
          reason: 'no outbound HTTP',
        },
      ],
      hold: { timeout_ms: 60000, on_timeout: 'deny' },
      boundary: { secrets: 'redact', injection: 'flag', max_scan_bytes: 1048576, on_oversize: 'flag' },
    },
    egress: {
      default: 'deny',
      rules: [
        {
          id: 'github-read',
          match: { host: 'api.github.com', methods: ['GET', 'HEAD'], path: '/**', max_body_bytes: 1048576 },
          action: 'allow',
          reason: '...',
        },
      ],
    },
  };
}

/** Deep-clone + apply a mutation to the design example, return validation errors (must fail). */
function errorsFor(mutate: (doc: Record<string, unknown>) => void): PolicyError[] {
  const doc = JSON.parse(JSON.stringify(designExample())) as Record<string, unknown>;
  mutate(doc);
  const result = validatePolicyObject(doc);
  expect(result.ok, `expected validation to fail, got ok for ${JSON.stringify(doc)}`).toBe(false);
  return result.ok ? [] : result.errors;
}

function expectError(errors: PolicyError[], path: string, keyword: string, messagePart?: string | RegExp): void {
  const hit = errors.find((e) => e.path === path && e.keyword === keyword);
  expect(hit, `no error at ${path} (${keyword}) in:\n${formatPolicyErrors(errors)}`).toBeDefined();
  if (messagePart !== undefined) expect(hit!.message).toMatch(messagePart);
}

function mcp(rules: Record<string, unknown>[], extra: Record<string, unknown> = {}): Policy {
  const r = validatePolicyObject({ version: 1, mcp: { rules, ...extra } });
  if (!r.ok) throw new Error(formatPolicyErrors(r.errors));
  return r.policy;
}

function egress(rules: Record<string, unknown>[], extra: Record<string, unknown> = {}): Policy {
  const r = validatePolicyObject({ version: 1, egress: { rules, ...extra } });
  if (!r.ok) throw new Error(formatPolicyErrors(r.errors));
  return r.policy;
}

/* ------------------------------ jsonschema ------------------------------ */

describe('jsonschema: shipped schema', () => {
  const shipped = JSON.parse(readFileSync(join(ROOT, 'docs', 'policy-schema.json'), 'utf8')) as JsonSchema;

  it('docs/policy-schema.json is byte-identical to POLICY_SCHEMA', () => {
    expect(readFileSync(join(ROOT, 'docs', 'policy-schema.json'), 'utf8')).toBe(
      JSON.stringify(POLICY_SCHEMA, null, 2) + '\n',
    );
    expect(shipped.$id).toBe(POLICY_SCHEMA_ID);
    expect(shipped.$schema).toBe('https://json-schema.org/draft/2020-12/schema');
  });

  it('uses only keywords the validator implements', () => {
    const used = collectKeywords(shipped);
    const unsupported = [...used].filter((k) => !SUPPORTED_KEYWORDS.has(k));
    expect(unsupported).toEqual([]);
    // Sanity: the walk actually reached nested schemas.
    expect(used.has('pattern')).toBe(true);
    expect(used.has('$ref')).toBe(true);
    expect(used.has('anyOf')).toBe(true);
    expect(used.has('minimum')).toBe(true);
  });

  it('collectKeywords does not mistake property names or enum values for keywords', () => {
    const used = collectKeywords(shipped);
    for (const notKeyword of ['version', 'mcp', 'credentials', 'egress', 'tool', 'allow', 'hold', 'deny', 'mcpRule']) {
      expect(used.has(notKeyword)).toBe(false);
    }
  });

  it('every $ref resolves and additionalProperties is false on every object schema', () => {
    const defs = shipped.$defs as Record<string, JsonSchema>;
    const walk = (node: unknown, where: string): void => {
      if (typeof node !== 'object' || node === null || Array.isArray(node)) return;
      const s = node as JsonSchema;
      if (typeof s.$ref === 'string') {
        expect(s.$ref.startsWith('#/$defs/'), `${where}: ${s.$ref}`).toBe(true);
        expect(defs[s.$ref.slice('#/$defs/'.length)], `${where}: ${s.$ref}`).toBeDefined();
      }
      // Two schemas are deliberately open: both are maps whose KEYS the
      // author chooses (arg dot-path -> regex, permission name -> level), so
      // there is no property list to close them against.
      const openMaps = ['$.$defs.mcpMatch.properties.args', '$.$defs.credentialSource.oneOf[3].properties.permissions'];
      if (s.type === 'object' && s.$ref === undefined && !openMaps.includes(where)) {
        expect(s.additionalProperties, `${where} lacks additionalProperties:false`).toBe(false);
      }
      for (const [k, v] of Object.entries(s)) {
        if (k === 'properties' || k === '$defs') {
          for (const [pk, pv] of Object.entries(v as Record<string, unknown>)) walk(pv, `${where}.${k}.${pk}`);
        } else if (k === 'items') walk(v, `${where}.items`);
        else if (k === 'anyOf' || k === 'oneOf') (v as unknown[]).forEach((b, i) => walk(b, `${where}.${k}[${i}]`));
      }
    };
    walk(shipped, '$');
  });
});

describe('jsonschema: validator keywords', () => {
  const errs = (schema: JsonSchema, value: unknown) => validateAgainstSchema(schema, value);
  const keywords = (schema: JsonSchema, value: unknown) => errs(schema, value).map((e) => e.keyword);

  it('type: single, integer, array of types', () => {
    expect(errs({ type: 'string' }, 'x')).toEqual([]);
    expect(errs({ type: 'string' }, 1)).toEqual([{ path: '', keyword: 'type', message: 'expected string, got number' }]);
    expect(keywords({ type: 'integer' }, 1.5)).toEqual(['type']);
    expect(keywords({ type: 'integer' }, 2)).toEqual([]);
    expect(keywords({ type: 'number' }, Number.NaN)).toEqual(['type']);
    expect(keywords({ type: ['string', 'null'] }, null)).toEqual([]);
    expect(keywords({ type: ['string', 'null'] }, 3)).toEqual(['type']);
    expect(keywords({ type: 'object' }, [])).toEqual(['type']);
    expect(keywords({ type: 'array' }, {})).toEqual(['type']);
    expect(keywords({ type: 'boolean' }, false)).toEqual([]);
    expect(keywords({ type: 'null' }, undefined)).toEqual(['type']);
  });

  it('enum and const use structural equality', () => {
    expect(keywords({ enum: ['a', 1, { x: [1] }] }, { x: [1] })).toEqual([]);
    expect(keywords({ enum: ['a', 1] }, 'b')).toEqual(['enum']);
    expect(errs({ enum: ['a', 1] }, 'b')[0]!.message).toBe('must be one of "a", 1');
    expect(keywords({ const: 1 }, 1)).toEqual([]);
    expect(keywords({ const: 1 }, '1')).toEqual(['const']);
    expect(jsonEqual({ a: [1, { b: null }] }, { a: [1, { b: null }] })).toBe(true);
    expect(jsonEqual({ a: 1 }, { a: 1, b: 2 })).toBe(false);
    expect(jsonEqual([1, 2], [2, 1])).toBe(false);
  });

  it('properties / required / additionalProperties with JSON-pointer paths', () => {
    const schema: JsonSchema = {
      type: 'object',
      additionalProperties: false,
      required: ['a'],
      properties: { a: { type: 'string' }, 'b/c': { type: 'number' }, 'd~e': { type: 'number' } },
    };
    expect(errs(schema, { a: 'x' })).toEqual([]);
    expect(errs(schema, {})).toEqual([{ path: '', keyword: 'required', message: 'missing required property "a"' }]);
    expect(errs(schema, { a: 'x', z: 1 })).toEqual([
      { path: '/z', keyword: 'additionalProperties', message: 'unknown property "z"' },
    ]);
    expect(errs(schema, { a: 'x', 'b/c': 'no', 'd~e': 'no' }).map((e) => e.path)).toEqual(['/b~1c', '/d~0e']);
  });

  it('items / minItems / maxItems', () => {
    const schema: JsonSchema = { type: 'array', minItems: 1, maxItems: 2, items: { type: 'string' } };
    expect(errs(schema, ['a'])).toEqual([]);
    expect(keywords(schema, [])).toEqual(['minItems']);
    expect(keywords(schema, ['a', 'b', 'c'])).toEqual(['maxItems']);
    expect(errs(schema, ['a', 2])).toEqual([{ path: '/1', keyword: 'type', message: 'expected string, got number' }]);
  });

  it('minimum / maximum only apply to numbers', () => {
    const schema: JsonSchema = { minimum: 1, maximum: 3 };
    expect(keywords(schema, 0)).toEqual(['minimum']);
    expect(keywords(schema, 4)).toEqual(['maximum']);
    expect(keywords(schema, 2)).toEqual([]);
    expect(keywords(schema, 'not a number')).toEqual([]);
  });

  it('pattern / minLength / maxLength count code points', () => {
    const schema: JsonSchema = { type: 'string', pattern: '^[a-z]+$', minLength: 2, maxLength: 3 };
    expect(keywords(schema, 'ab')).toEqual([]);
    expect(keywords(schema, 'a')).toEqual(['minLength']);
    expect(keywords(schema, 'abcd')).toEqual(['maxLength']);
    expect(keywords(schema, 'A1')).toEqual(['pattern']);
    expect(keywords({ type: 'string', maxLength: 2 }, '😀😀')).toEqual([]);
  });

  it('anyOf reports every branch; oneOf rejects zero and multiple matches', () => {
    const schema: JsonSchema = { anyOf: [{ type: 'string' }, { type: 'array', items: { type: 'string' } }] };
    expect(errs(schema, 'x')).toEqual([]);
    expect(errs(schema, ['x'])).toEqual([]);
    const [err] = errs(schema, 5);
    expect(err).toMatchObject({ path: '', keyword: 'anyOf' });
    expect(err!.message).toBe('no alternative matched: (1) expected string, got number; (2) expected array, got number');
    const deep = errs(schema, [1]);
    expect(deep[0]!.message).toContain('(2) expected string, got number (at /0)');

    const one: JsonSchema = { oneOf: [{ type: 'number' }, { minimum: 5 }] };
    expect(keywords(one, 3)).toEqual([]);
    expect(keywords(one, 7)).toEqual(['oneOf']);
    expect(errs(one, 7)[0]!.message).toBe('matches 2 alternatives, expected exactly one');
    expect(keywords(one, 'x')).toEqual([]); // minimum ignores non-numbers => branch 2 matches
    expect(keywords({ oneOf: [{ type: 'number' }, { type: 'boolean' }] }, 'x')).toEqual(['oneOf']);
  });

  it('$ref resolves #/$defs/<name>; anything else throws', () => {
    const schema: JsonSchema = { $ref: '#/$defs/n', $defs: { n: { type: 'number' } } };
    expect(errs(schema, 1)).toEqual([]);
    expect(keywords(schema, 'x')).toEqual(['type']);
    expect(() => errs({ $ref: '#/definitions/x' }, 1)).toThrow(/unsupported \$ref/);
    expect(() => errs({ $ref: '#/$defs/missing', $defs: {} }, 1)).toThrow(/unresolvable \$ref/);
  });

  it('unsupported keywords throw instead of silently passing', () => {
    expect(() => errs({ patternProperties: {} }, {})).toThrow(/unsupported JSON Schema keyword "patternProperties"/);
    expect(() => errs({ type: 'object', properties: { a: { format: 'uri' } } }, { a: 'x' })).toThrow(/"format" at \/a/);
  });
});

/* ------------------------------- validate -------------------------------- */

describe('validatePolicyObject: happy path', () => {
  it('accepts the design example and returns it normalized', () => {
    const r = validatePolicyObject(designExample());
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.policy).toEqual({
      version: 1,
      name: 'laptop-default',
      mcp: {
        default: 'allow',
        rules: [
          {
            id: 'no-exfil',
            match: { server: ['*'], tool: ['http_post', 'send_*'], args: { url: '^https?://' }, max_args_bytes: 65536 },
            action: 'deny',
            reason: 'no outbound HTTP',
          },
        ],
        hold: { timeout_ms: 60000, on_timeout: 'deny' },
        boundary: { secrets: 'redact', injection: 'flag', max_scan_bytes: 1048576, on_oversize: 'flag' },
      },
      egress: {
        default: 'deny',
        rules: [
          {
            id: 'github-read',
            match: { host: ['api.github.com'], methods: ['GET', 'HEAD'], path: ['/**'], max_body_bytes: 1048576 },
            action: 'allow',
            reason: '...',
          },
        ],
      },
    });
  });

  it('accepts a minimal mcp-only and a minimal egress-only document', () => {
    expect(validatePolicyObject({ version: 1, mcp: {} }).ok).toBe(true);
    expect(validatePolicyObject({ version: 1, egress: {} }).ok).toBe(true);
    expect(validatePolicyObject({ version: 1, mcp: { rules: [] }, egress: { rules: [] } }).ok).toBe(true);
  });

  it('accepts boundary values of every numeric range', () => {
    const ok = (mutate: (doc: Record<string, unknown>) => void): boolean => {
      const doc = JSON.parse(JSON.stringify(designExample())) as Record<string, unknown>;
      mutate(doc);
      return validatePolicyObject(doc).ok;
    };
    const hold = (d: Record<string, unknown>) => (d.mcp as { hold: Record<string, unknown> }).hold;
    const boundary = (d: Record<string, unknown>) => (d.mcp as { boundary: Record<string, unknown> }).boundary;
    expect(ok((d) => (hold(d).timeout_ms = 1000))).toBe(true);
    expect(ok((d) => (hold(d).timeout_ms = 3600000))).toBe(true);
    expect(ok((d) => (boundary(d).max_scan_bytes = 4096))).toBe(true);
    expect(ok((d) => (boundary(d).max_scan_bytes = 64 * 1024 * 1024))).toBe(true);
    expect(ok((d) => (d.name = 'a'))).toBe(true);
    expect(ok((d) => (d.name = 'x'.repeat(64)))).toBe(true);
  });
});

describe('validatePolicyObject: error paths', () => {
  type Doc = Record<string, unknown>;
  // Intersected with `Doc` on purpose: half of what these tests do is add a
  // key the schema must REJECT (`mcpOf(d).bogus = 1`), so a closed object
  // type would make the test itself the error rather than the policy.
  const mcpOf = (d: Doc) => d.mcp as Doc & { rules: Doc[]; hold: Doc; boundary: Doc; default: unknown };
  const egressOf = (d: Doc) => d.egress as Doc & { rules: Doc[]; default: unknown };
  const rule0 = (d: Doc) =>
    mcpOf(d).rules[0] as Doc & { match: Doc; action: unknown; id: unknown; reason: unknown };
  const erule0 = (d: Doc) =>
    egressOf(d).rules[0] as Doc & { match: Doc; action: unknown; id: unknown; reason: unknown };

  it('non-object roots', () => {
    for (const raw of [null, undefined, 1, 'x', [], true]) {
      const r = validatePolicyObject(raw);
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.errors[0]).toMatchObject({ path: '', keyword: 'type' });
    }
  });

  it('version: missing, wrong literal', () => {
    expectError(errorsFor((d) => delete d.version), '', 'required', '"version"');
    expectError(errorsFor((d) => (d.version = 2)), '/version', 'const', 'must be 1');
    expectError(errorsFor((d) => (d.version = '1')), '/version', 'const');
  });

  it('name: bad characters, too long, wrong type', () => {
    expectError(errorsFor((d) => (d.name = 'has space')), '/name', 'pattern');
    expectError(errorsFor((d) => (d.name = 'x'.repeat(65))), '/name', 'pattern');
    expectError(errorsFor((d) => (d.name = '')), '/name', 'pattern');
    expectError(errorsFor((d) => (d.name = 7)), '/name', 'type');
  });

  it('unknown top-level and nested keys', () => {
    expectError(errorsFor((d) => (d.extra = 1)), '/extra', 'additionalProperties');
    expectError(errorsFor((d) => (mcpOf(d).bogus = 1)), '/mcp/bogus', 'additionalProperties');
    expectError(errorsFor((d) => (rule0(d).match.tools = 'x')), '/mcp/rules/0/match/tools', 'additionalProperties');
    expectError(errorsFor((d) => (rule0(d).match.max_body_bytes = 1)), '/mcp/rules/0/match/max_body_bytes', 'additionalProperties');
    expectError(errorsFor((d) => (erule0(d).match.max_args_bytes = 1)), '/egress/rules/0/match/max_args_bytes', 'additionalProperties');
  });

  it('at least one of mcp / credentials / egress is required (friendly message)', () => {
    const errors = errorsFor((d) => {
      delete d.mcp;
      delete d.egress;
    });
    expect(errors).toEqual([{ path: '', keyword: 'anyOf', message: 'at least one of "mcp", "credentials" or "egress" is required' }]);
    expect(formatPolicyErrors(errors)).toBe('/: at least one of "mcp", "credentials" or "egress" is required');
  });

  it('mcp section shape', () => {
    expectError(errorsFor((d) => (d.mcp = [])), '/mcp', 'type');
    expectError(errorsFor((d) => (mcpOf(d).default = 'block')), '/mcp/default', 'enum');
    expectError(errorsFor((d) => ((d.mcp as Doc).rules = {})), '/mcp/rules', 'type');
    expectError(errorsFor((d) => ((d.mcp as Doc).rules = ['x'])), '/mcp/rules/0', 'type');
  });

  it('mcp rule: missing match / action, bad action, bad id, bad reason', () => {
    expectError(errorsFor((d) => delete (rule0(d) as Doc).match), '/mcp/rules/0', 'required', '"match"');
    expectError(errorsFor((d) => delete (rule0(d) as Doc).action), '/mcp/rules/0', 'required', '"action"');
    expectError(errorsFor((d) => (rule0(d).action = 'block')), '/mcp/rules/0/action', 'enum');
    expectError(errorsFor((d) => (rule0(d).id = 'bad id!')), '/mcp/rules/0/id', 'pattern');
    expectError(errorsFor((d) => (rule0(d).id = 'rule[0]')), '/mcp/rules/0/id', 'pattern');
    expectError(errorsFor((d) => (rule0(d).reason = 5)), '/mcp/rules/0/reason', 'type');
  });

  it('mcp match.tool: missing, wrong type, empty string, empty list, non-string item', () => {
    expectError(errorsFor((d) => delete rule0(d).match.tool), '/mcp/rules/0/match', 'required', '"tool"');
    expectError(errorsFor((d) => (rule0(d).match.tool = 5)), '/mcp/rules/0/match/tool', 'anyOf');
    expectError(errorsFor((d) => (rule0(d).match.tool = '')), '/mcp/rules/0/match/tool', 'anyOf', 'at least 1 character');
    expectError(errorsFor((d) => (rule0(d).match.tool = [])), '/mcp/rules/0/match/tool', 'anyOf', 'at least 1 item');
    expectError(errorsFor((d) => (rule0(d).match.tool = ['ok', 3])), '/mcp/rules/0/match/tool', 'anyOf', '(at /1)');
  });

  it('globs: blank and OPA-reserved characters are rejected with the element path', () => {
    expectError(errorsFor((d) => (rule0(d).match.tool = ' ')), '/mcp/rules/0/match/tool', 'glob', 'blank');
    expectError(errorsFor((d) => (rule0(d).match.tool = ['a', '\t'])), '/mcp/rules/0/match/tool/1', 'glob', 'blank');
    expectError(errorsFor((d) => (rule0(d).match.tool = ['a', 'x{y,z}'])), '/mcp/rules/0/match/tool/1', 'glob', '"{"');
    expectError(errorsFor((d) => (rule0(d).match.server = '[ab]')), '/mcp/rules/0/match/server', 'glob', '"["');
    expectError(errorsFor((d) => (rule0(d).match.server = 'a\\*')), '/mcp/rules/0/match/server', 'glob', '"\\\\"');
    expectError(errorsFor((d) => (rule0(d).match.server = '')), '/mcp/rules/0/match/server', 'anyOf', 'at least 1 character');
    expectError(errorsFor((d) => (rule0(d).match.server = ['ok', 'a{b}'])), '/mcp/rules/0/match/server/1', 'glob', '"{"');
    expectError(errorsFor((d) => (rule0(d).match.server = [])), '/mcp/rules/0/match/server', 'anyOf', 'at least 1 item');
    expectError(errorsFor((d) => (erule0(d).match.host = ['ok', ' '])), '/egress/rules/0/match/host/1', 'glob');
    expectError(errorsFor((d) => (erule0(d).match.path = '/a/}')), '/egress/rules/0/match/path', 'glob', '"}"');
    expectError(errorsFor((d) => (erule0(d).match.path = ['/a', '/]'])), '/egress/rules/0/match/path/1', 'glob', '"]"');
    expect(checkGlob('*')).toBeUndefined();
    expect(checkGlob('a/**/b')).toBeUndefined();
  });

  it('the "?" wildcard is rejected everywhere: OPA matches it against ASCII only, we do not', () => {
    // Reproduced against OPA 1.20: glob.match("a?b", ["/"], "aéb") is false,
    // while the TS engine's RegExp [^/] matches "é" — so `?` cannot mean one
    // thing in the gateway and another in the compiled Rego.
    expect(checkGlob('a?b')).toMatch(/the \? wildcard is not supported in policy\.yaml v1 \(use \* or \*\*\)/);
    expect(checkGlob('?')).toBeDefined();
    expect(checkGlob('read_?ile')).toBeDefined();
    for (const field of ['tool', 'server'] as const) {
      expectError(errorsFor((d) => (rule0(d).match[field] = 'a?b')), `/mcp/rules/0/match/${field}`, 'glob', /\? wildcard is not supported/);
    }
    expectError(errorsFor((d) => (rule0(d).match.tool = ['ok', 'a?b'])), '/mcp/rules/0/match/tool/1', 'glob', /\? wildcard/);
    expectError(errorsFor((d) => (erule0(d).match.host = 'api?github.com')), '/egress/rules/0/match/host', 'glob', /\? wildcard/);
    expectError(errorsFor((d) => (erule0(d).match.path = ['/a', '/?'])), '/egress/rules/0/match/path/1', 'glob', /\? wildcard/);
    // `*` and `**` are unaffected.
    expect(checkGlob('*')).toBeUndefined();
    expect(checkGlob('**/a/**')).toBeUndefined();
  });

  it('match.server accepts a list of globs (docs/policy.md: glob | glob[])', () => {
    const doc = designExample();
    doc.mcp!.rules![0]!.match.server = ['corp-*', 'fs'];
    const r = validatePolicyObject(doc);
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.policy.mcp!.rules[0]!.match.server).toEqual(['corp-*', 'fs']);
  });

  it('reason is capped at 512 characters in both sections', () => {
    const ok = designExample();
    ok.mcp!.rules![0]!.reason = 'x'.repeat(512);
    ok.egress!.rules![0]!.reason = 'y'.repeat(512);
    expect(validatePolicyObject(ok).ok).toBe(true);
    expectError(errorsFor((d) => (rule0(d).reason = 'x'.repeat(513))), '/mcp/rules/0/reason', 'maxLength', 'at most 512 character(s)');
    expectError(errorsFor((d) => ((erule0(d) as Doc).reason = 'y'.repeat(513))), '/egress/rules/0/reason', 'maxLength', 'at most 512 character(s)');
  });

  it('args: must be an object of dot-path -> regex string', () => {
    expectError(errorsFor((d) => (rule0(d).match.args = 'x')), '/mcp/rules/0/match/args', 'type');
    expectError(errorsFor((d) => (rule0(d).match.args = ['x'])), '/mcp/rules/0/match/args', 'type');
    expectError(errorsFor((d) => (rule0(d).match.args = { url: 1 })), '/mcp/rules/0/match/args/url', 'type', 'got number');
    expectError(errorsFor((d) => (rule0(d).match.args = { url: null })), '/mcp/rules/0/match/args/url', 'type', 'got object');
    expectError(errorsFor((d) => (rule0(d).match.args = { url: ['^x'] })), '/mcp/rules/0/match/args/url', 'type', 'got array');
    expectError(errorsFor((d) => (rule0(d).match.args = { '': '^x' })), '/mcp/rules/0/match/args/', 'dotPath');
    expectError(errorsFor((d) => (rule0(d).match.args = { '.a': '^x' })), '/mcp/rules/0/match/args/.a', 'dotPath');
    expectError(errorsFor((d) => (rule0(d).match.args = { 'a..b': '^x' })), '/mcp/rules/0/match/args/a..b', 'dotPath');
    expectError(errorsFor((d) => (rule0(d).match.args = { 'a.': '^x' })), '/mcp/rules/0/match/args/a.', 'dotPath');
    // Pointer escaping of odd keys.
    expectError(errorsFor((d) => (rule0(d).match.args = { 'a/b': 1 })), '/mcp/rules/0/match/args/a~1b', 'type');
    expectError(errorsFor((d) => (rule0(d).match.args = { 'a~b': 1 })), '/mcp/rules/0/match/args/a~0b', 'type');
  });

  it('args regexes: RE2 subset violations and invalid patterns', () => {
    const bad: Array<[string, RegExp]> = [
      ['a(?=b)', /lookahead "\(\?="/],
      ['a(?!b)', /lookahead "\(\?!"/],
      ['(?<=a)b', /lookbehind "\(\?<="/],
      ['(?<!a)b', /lookbehind "\(\?<!"/],
      ['(a)\\1', /backreference "\\1"/],
      ['(a)(b)\\9', /backreference "\\9"/],
      ['\\Afoo', /"\\A" is not portable/],
      ['foo\\z', /"\\z" is not portable/],
      ['\\p{L}', /"\\p" is not portable/],
      ['\\u0041', /"\\u" is not portable/],
      ['\\Qa.b\\E', /"\\Q" is not portable/],
      ['\\cA', /"\\c" is not portable/],
      ['\\x{41}', /"\\x\{\.\.\.\}" is not supported/],
      ['[[:alpha:]]', /POSIX character classes/],
      ['abc\\', /dangling backslash/],
      ['(unclosed', /invalid regular expression/],
      ['a{2,1}', /invalid regular expression/],
    ];
    for (const [pattern, why] of bad) {
      expect(checkRe2Subset(pattern), pattern).toMatch(why);
      expectError(errorsFor((d) => (rule0(d).match.args = { url: pattern })), '/mcp/rules/0/match/args/url', 'regex', why);
    }
    const good = [
      '^https?://',
      '\\d+\\.\\d+',
      '[a-z_]+[ \\t]*=[ \\t]*"[^"]*"',
      '(?:foo|bar)',
      '(?:foo)+',
      '(?<name>x)',
      '\\x41\\t\\n\\.\\\\',
      '[\\]a]',
      '[^\\]a]',
      'a{2,3}',
      '.*',
      '\\bword\\b',
      '',
    ];
    for (const pattern of good) expect(checkRe2Subset(pattern), pattern).toBeUndefined();
  });

  it('args regexes: named backreferences are rejected like numbered ones', () => {
    for (const pattern of ['(?<n>a)\\k<n>', 'a\\kb', '\\k']) {
      expect(checkRe2Subset(pattern), pattern).toMatch(/named backreference "\\k<name>" is not supported \(RE2 subset\)/);
    }
    expectError(
      errorsFor((d) => (rule0(d).match.args = { url: '(?<n>a)\\k<n>' })),
      '/mcp/rules/0/match/args/url',
      'regex',
      /named backreference/,
    );
    // The named GROUP itself stays allowed; only the back-reference to it is out.
    expect(checkRe2Subset('(?<n>a)')).toBeUndefined();
  });

  it('args regexes: a leading "]" in a character class is rejected (literal in RE2, empty class in JS)', () => {
    const why = /a "\]" directly after "\[" or "\[\^" means a literal "\]" in RE2 but an empty character class in JavaScript/;
    for (const pattern of ['[]a]', '[^]a]', '[]', '[^]', '[]]']) {
      expect(checkRe2Subset(pattern), pattern).toMatch(why);
    }
    expectError(errorsFor((d) => (rule0(d).match.args = { url: '[]a]' })), '/mcp/rules/0/match/args/url', 'regex', why);
    // Escaped, it means the same thing in both engines.
    expect(checkRe2Subset('[\\]a]')).toBeUndefined();
    expect(checkRe2Subset('[^\\]a]')).toBeUndefined();
    expect(checkRe2Subset('[a]]')).toBeUndefined();
  });

  it('args regexes: only whitelisted escapes are accepted', () => {
    // Everything V8 (no `u` flag) and RE2 read identically.
    const allowed = [
      '\\d\\D\\w\\W',
      '\\bword\\B',
      '\\n\\r\\t\\f\\v',
      '\\x41\\xff\\xAB',
      '\\.\\\\\\+\\*\\?\\(\\)\\[\\]\\{\\}\\|\\^\\$\\-\\/\\_\\#\\ ',
      '[\\d\\w\\n\\t\\x41\\-\\]]',
    ];
    for (const pattern of allowed) expect(checkRe2Subset(pattern), pattern).toBeUndefined();

    // \s / \S differ: RE2's is ASCII-only, JavaScript's also matches U+00A0, U+2028, ...
    for (const pattern of ['a\\s+b', '[^\\S]']) {
      const msg = checkRe2Subset(pattern);
      expect(msg, pattern).toMatch(/is not portable between JavaScript and RE2/);
      expect(msg, pattern).toMatch(/RE2's \\s is ASCII-only/);
      expect(msg, pattern).toContain('[ \\t\\r\\n\\f]');
    }

    // Every other backslash-letter / backslash-digit escape is out.
    const rejected = ['\\0', '\\a', '\\e', '\\h', '\\z', '\\A', '\\Z', '\\C', '\\G', '\\U', '\\y', '\\q', '\\g', '\\N', '\\R', '\\X', '\\é'];
    for (const pattern of rejected) {
      expect(checkRe2Subset(`a${pattern}b`), pattern).toMatch(/is not portable between JavaScript and RE2 \(allowed: /);
    }
    expectError(errorsFor((d) => (rule0(d).match.args = { url: '\\0' })), '/mcp/rules/0/match/args/url', 'regex', /"\\0" is not portable/);
    expectError(errorsFor((d) => (rule0(d).match.args = { url: 'a\\s+b' })), '/mcp/rules/0/match/args/url', 'regex', /"\\s" is not portable/);

    // \x needs exactly two hex digits: \x4 and \xZZ are literal "x..." in V8 and an error in RE2.
    for (const pattern of ['\\x4', '\\xZZ', '\\x', '\\x4g']) {
      expect(checkRe2Subset(pattern), pattern).toMatch(/escape "\\x" must be followed by exactly two hex digits/);
    }
    expect(checkRe2Subset('\\x{41}')).toMatch(/"\\x\{\.\.\.\}" is not supported/);

    // \b / \B mean a word boundary outside a class (fine) but backspace / literal "B"
    // inside one, where RE2 refuses the escape altogether.
    for (const pattern of ['[\\b]', '[a\\B]', '[^\\b-x]']) {
      expect(checkRe2Subset(pattern), pattern).toMatch(/inside a character class is not supported/);
    }
  });

  it('args regexes: every "(?" group that is not "(?:" (or a named group) is rejected explicitly, whatever V8 accepts', () => {
    // RE2 accepts inline flags, Node 20 rejects them all, Node 24's V8 accepts the "(?i:...)" modifier form:
    // the validator must decide on its own, before (and independently of) `new RegExp`.
    const flagGroups: Array<[string, string]> = [
      ['(?i)abc', '(?i'],
      ['abc(?i)', '(?i'],
      ['(?s)a.b', '(?s'],
      ['(?m)^a$', '(?m'],
      ['(?U)a*', '(?U'],
      ['(?is)ab', '(?i'],
      ['(?i:abc)', '(?i'],
      ['x(?i:abc)y', '(?i'],
      ['(?s:.)', '(?s'],
      ['(?m:^a)', '(?m'],
      ['(?U:a*)', '(?U'],
      ['(?-i:abc)', '(?-'],
      ['(?i-s:abc)', '(?i'],
      ['(?P<name>x)', '(?P'],
      ['(?#comment)x', '(?#'],
      ['(?>x)', '(?>'],
      ['(?|x)', '(?|'],
      ['(?)', '(?)'],
      ['a(?', '(?'],
      ['[a](?i)b', '(?i'],
    ];
    for (const [pattern, shown] of flagGroups) {
      const why = checkRe2Subset(pattern);
      expect(why, pattern).toMatch(/^group "\(\?.*" is not supported \(RE2 subset\): only "\(\?:" non-capturing groups are allowed/);
      expect(why, pattern).toContain(`group ${JSON.stringify(shown)}`);
      expect(why, pattern).not.toMatch(/invalid regular expression/);
      expectError(errorsFor((d) => (rule0(d).match.args = { url: pattern })), '/mcp/rules/0/match/args/url', 'regex', /only "\(\?:" non-capturing groups/);
    }
    // Inside a character class "(?" is literal in both engines and stays allowed.
    expect(checkRe2Subset('[(?i]+')).toBeUndefined();
    expect(checkRe2Subset('\\(\\?i')).toBeUndefined();
    // Plain non-capturing and named groups are still fine, nested or repeated.
    for (const pattern of ['(?:a(?:b|c))+', '(?<year>[0-9]{4})-(?<m>[0-9]{2})', '(?:x)(?<n>y)(?:z)']) {
      expect(checkRe2Subset(pattern), pattern).toBeUndefined();
    }
    // The lookaround messages keep their own, more specific wording.
    expect(checkRe2Subset('(?=x)')).toMatch(/^lookahead/);
    expect(checkRe2Subset('(?<=x)')).toMatch(/^lookbehind/);
  });

  it('args regexes: repeated groups that are exponential under V8 are rejected (they are linear under RE2)', () => {
    // The reviewer's reproduction: `^(a+)+$` against 29 non-matching characters
    // takes ~14 s in V8 and freezes the single-threaded proxy for all traffic.
    // RE2 (so the compiled Rego) matches all of these in linear time, which is
    // exactly why the pattern has to be refused at validation time here.
    const exponential: Array<[string, RegExp]> = [
      ['^(a+)+$', /ends with the quantified atom "a\+"/],
      ['(a|aa)+', /body contains an alternation/],
      ['(?:foo|bar)+', /body contains an alternation/],
      ['(\\w+[ \\t]?)*', /ends with the quantified atom "\[ \\\\t\]\?"/],
      ['(.*a)*', /trailing "a" can also be matched by "\.\*"/],
      ['([a-z]+foo)*', /trailing "foo" can also be matched by "\[a-z\]\+"/],
      ['(a*)*', /ends with the quantified atom "a\*"/],
      ['(ab?)*', /ends with the quantified atom "b\?"/],
      ['(.+)+', /ends with the quantified atom "\.\+"/],
      ['(a+)+?', /ends with the quantified atom "a\+"/],
      ['(a+){2,}', /ends with the quantified atom "a\+"/],
      ['(a+){3}', /ends with the quantified atom "a\+"/],
      ['(x+\\b)*', /ends with the quantified atom "x\+"/], // a zero-width \b anchors nothing
      ['((?:ab)+c)*', /trailing "c" can also be matched by "\(\?:ab\)\+"/],
    ];
    for (const [pattern, why] of exponential) {
      expect(checkRe2Subset(pattern), pattern).toMatch(why);
      expect(checkRe2Subset(pattern), pattern).toMatch(/JavaScript backtracks exponentially/);
      expect(checkCatastrophicShape(pattern), pattern).toBe(checkRe2Subset(pattern));
      expectError(errorsFor((d) => (rule0(d).match.args = { url: pattern })), '/mcp/rules/0/match/args/url', 'regex', why);
    }
  });

  it('args regexes: repeated groups anchored by a literal the repeat cannot match stay allowed', () => {
    // Each iteration of these ends with something outside the repeated set, so
    // there is exactly one way to split the input and no backtracking to do.
    const linear = [
      '([a-z0-9-]+\\.)*', // the documented hostname shape
      '(\\d{1,3}\\.){3}\\d{1,3}',
      '(?:[a-z]+\\.)+',
      '(a+b)*',
      '(a+b?c)*',
      '(a\\t?b)*',
      '(a+)?', // "?" is not a repetition
      '(a+)', // not repeated at all
      '(.*a)',
      '(?:a(?:b|c))+', // the alternation is not at the repeated group's top level
      '(^|/)(\\.env|id_rsa)$',
      '^(title|body)$',
      '(?<year>[0-9]{4})-(?<m>[0-9]{2})',
    ];
    for (const pattern of linear) {
      expect(checkCatastrophicShape(pattern), pattern).toBeUndefined();
      expect(checkRe2Subset(pattern), pattern).toBeUndefined();
    }
    const ok = designExample();
    ok.mcp!.rules![0]!.match.args = { url: '([a-z0-9-]+\\.)*example\\.com' };
    expect(validatePolicyObject(ok).ok).toBe(true);
    // Unbalanced / invalid patterns are still reported as invalid, not as a shape.
    expect(checkCatastrophicShape('(unclosed')).toBeUndefined();
    expect(checkRe2Subset('(a+)+')).toMatch(/ends with the quantified atom/);
    expect(checkRe2Subset('(a+)+(')).toMatch(/invalid regular expression/);
  });

  it('args regexes: a redundant wrapper group cannot hide an exponential shape', () => {
    // `checkCatastrophicShape` used to inspect only the repeated group's
    // TOP-LEVEL atoms, so one extra pair of parentheses hid every shape it
    // knows: all of these validated with exit 0, and `^((a+))+$` against 30
    // non-matching characters takes 38 s in V8 (measured) where RE2 answers
    // instantly. The analysis now re-enters a trailing group.
    const wrapped: Array<[string, RegExp]> = [
      ['^((a+))+$', /ends with the quantified atom "a\+"/],
      ['^((?:a+))+$', /ends with the quantified atom "a\+"/],
      ['^((a|aa))+$', /body contains an alternation/],
      ['^((a{1,2}))+$', /ends with the quantified atom "a\{1,2\}"/],
      ['^(([a-z]+))+$', /ends with the quantified atom "\[a-z\]\+"/],
      ['^(((a+)))+$', /ends with the quantified atom "a\+"/], // two wrappers deep
      ['(b(.*a))*', /can also be matched by "\.\*"/], // a trailing group is spliced into the body
    ];
    for (const [pattern, why] of wrapped) {
      expect(checkCatastrophicShape(pattern), pattern).toMatch(why);
      // The message names the group as written, wrapper and all.
      expect(checkCatastrophicShape(pattern), pattern).toContain(JSON.stringify(pattern.replace(/^\^|\$$/g, '')));
      expect(checkRe2Subset(pattern), pattern).toBe(checkCatastrophicShape(pattern));
      expectError(errorsFor((d) => (rule0(d).match.args = { url: pattern })), '/mcp/rules/0/match/args/url', 'regex', why);
    }
    // A group whose body has an alternation BEHIND an anchor is not a wrapper:
    // each iteration starts with "a", so the branches are not ambiguous.
    expect(checkCatastrophicShape('(?:a(?:b|c))+')).toBeUndefined();
  });

  it('args regexes: adjacent quantifiers over the same characters are rejected', () => {
    // The second blind spot, with no nesting at all: every way of splitting
    // the input between the two quantifiers is tried. `^[a-z]*[a-z]*[a-z]*x$`
    // validated with exit 0 and takes 8.6 s on a 4096-character value (the
    // most one argument can carry), where RE2 stays linear.
    const adjacent = ['^[a-z]*[a-z]*[a-z]*x$', '\\w+\\w+', '.*.*', '[a-z]+[a-z]*', 'a+a{2,}', '[a-z]+x?[a-z]+', '(?:x[0-9]*\\d+)'];
    for (const pattern of adjacent) {
      const why = checkCatastrophicShape(pattern);
      expect(why, pattern).toMatch(/repeats two adjacent atoms that can match the same characters/);
      expect(why, pattern).toMatch(/make the character sets disjoint or drop one of the quantifiers/);
      expect(checkRe2Subset(pattern), pattern).toBe(why);
      expectError(
        errorsFor((d) => (rule0(d).match.args = { url: pattern })),
        '/mcp/rules/0/match/args/url',
        'regex',
        /two adjacent atoms/,
      );
    }
    // Disjoint sets, a literal that has to be consumed in between, or a
    // quantifier that cannot repeat: all still fine.
    for (const pattern of ['[a-z]+[0-9]*', '^.*secret.*$', '^rm -rf .+$', '\\d+\\.\\d+', '(a+b?c)*', '^https?://', '[a-z]+ ?[0-9]+']) {
      expect(checkCatastrophicShape(pattern), pattern).toBeUndefined();
      expect(checkRe2Subset(pattern), pattern).toBeUndefined();
    }
  });

  it('args regexes: parentheses that are pure concatenation cannot hide adjacent quantifiers', () => {
    // A group with no quantifier and no top-level alternation means exactly
    // what its body means, so `([a-z]+)([a-z]+)([a-z]+)x` IS the
    // `[a-z]*[a-z]*[a-z]*x` shape rejected above. It used to validate with
    // exit 0 because the analysis treated every group as opaque unless the
    // group itself was repeated. Measured on a 4096-character value (the most
    // one argument can carry, `REGEX_VALUE_CAP`): `^([a-z]+)([a-z]+)([a-z]+)x$`
    // takes 8.2 s, the `(?:...)` spelling 8.7 s, `^(\w+)(\w+)(\w+)$` 8.8 s,
    // and a fourth group needs 22 s at 512 characters alone — RE2 answers all
    // of them instantly, which is why they are refused at authoring time.
    const parenthesised: Array<[string, string]> = [
      ['^([a-z]+)([a-z]+)([a-z]+)x$', '([a-z]+)([a-z]+)'],
      ['^(?:[a-z]+)(?:[a-z]+)(?:[a-z]+)x$', '(?:[a-z]+)(?:[a-z]+)'],
      ['^(\\w+)(\\w+)(\\w+)$', '(\\w+)(\\w+)'],
      ['^([a-z]+)([a-z]+)([a-z]+)([a-z]+)x$', '([a-z]+)([a-z]+)'],
      ['^((a+))((a*))b$', '((a+))((a*))'], // wrappers around each one, seen through
      ['^(?<a>[a-z]+)(?<b>[a-z]+)x$', '(?<a>[a-z]+)(?<b>[a-z]+)'],
      ['^([a-z]+)[a-z]+x$', '([a-z]+)[a-z]+'], // one side parenthesised, one side bare
      ['^[a-z]+([a-z]+)x$', '[a-z]+([a-z]+)'],
      ['^(x[a-z]+)([a-z]+y)z$', '[a-z]+[a-z]+'], // a multi-atom body is spliced in, atom by atom
    ];
    for (const [pattern, shown] of parenthesised) {
      const why = checkCatastrophicShape(pattern);
      expect(why, pattern).toMatch(/repeats two adjacent atoms that can match the same characters/);
      // The message quotes the offending piece as the author wrote it.
      expect(why, pattern).toContain(JSON.stringify(shown));
      expect(why, pattern).toMatch(/make the character sets disjoint or drop one of the quantifiers/);
      // The validator, not the matcher, is where this is refused — and both
      // engines see the same policy, so the Rego side never gets the pattern.
      expect(checkRe2Subset(pattern), pattern).toBe(why);
      expectError(
        errorsFor((d) => (rule0(d).match.args = { url: pattern })),
        '/mcp/rules/0/match/args/url',
        'regex',
        /two adjacent atoms/,
      );
    }
    // Parentheses that are NOT pure concatenation stay opaque to this rule: a
    // repeated group is the other family's business (it anchors each iteration
    // with something the repeat cannot match), and an alternation is a choice,
    // not a concatenation. Disjoint classes and an intervening literal are
    // still fine however they are spelled. All of these must keep validating.
    const stillFine = [
      '(\\d{1,3}\\.){3}\\d{1,3}',
      '([a-z0-9-]+\\.)*example\\.com',
      '(?:[a-z]+\\.)+',
      '(^|/)(\\.env|id_rsa)$',
      '(^|/)(\\.env|secrets\\.env|id_rsa|\\.npmrc)$',
      '(?<year>[0-9]{4})-(?<m>[0-9]{2})',
      '([a-z]+)([0-9]+)x',
      '([a-z]+)-([a-z]+)x',
      '(a+b)*',
      '(.*a)',
      '(a+)',
      '(?:a(?:b|c))+',
      '^(title|body)$',
    ];
    for (const pattern of stillFine) {
      expect(checkCatastrophicShape(pattern), pattern).toBeUndefined();
      expect(checkRe2Subset(pattern), pattern).toBeUndefined();
      const ok = designExample();
      ok.mcp!.rules![0]!.match.args = { url: pattern };
      expect(validatePolicyObject(ok).ok, pattern).toBe(true);
    }
    // The shipped example policies are the real over-rejection guard.
    for (const file of ['policy.demo.yaml', 'policy.laptop.yaml']) {
      const parsed = parsePolicyText(readFileSync(join(ROOT, 'docs', 'examples', file), 'utf8'), 'yaml', file);
      expect(validatePolicyObject(parsed).ok, file).toBe(true);
    }
  });

  it('checkProvablyLinear is the fail-closed twin: it PROVES a bound instead of spotting bad shapes', () => {
    // What the runtime guard consults when it has no worker thread. Absence of
    // a known-bad shape is not enough there: a repeated group, too many
    // repeated atoms or too many alternation paths are all refused, even
    // though a policy carrying them still validates.
    for (const pattern of ['^https://', '^https?://', '^.*secret.*$', '^rm -rf .+$', '^(title|body)$', '\\d+\\.\\d+', '^[0-9]{1,2}$', '(^|/)(\\.env|id_rsa)$']) {
      expect(checkProvablyLinear(pattern), pattern).toBeUndefined();
    }
    expect(checkProvablyLinear('([a-z0-9-]+\\.)*')).toMatch(/repeated group .* cannot be proved linear/);
    expect(checkProvablyLinear('^.*a.*b.*$')).toMatch(/3 repeated quantifiers \(more than 2\)/);
    expect(checkProvablyLinear('(unclosed')).toMatch(/could not be parsed/);
    expect(checkProvablyLinear('^((a+))+$')).toMatch(/ends with the quantified atom/);
    expect(checkProvablyLinear('(a|b)(a|b)(a|b)(a|b)(a|b)(a|b)(a|b)')).toMatch(/more than 64 alternation paths/);
    // Everything the validator refuses is refused here too.
    for (const pattern of ['^(a+)+$', '(a|aa)+', '^[a-z]*[a-z]*x$']) {
      expect(checkProvablyLinear(pattern), pattern).toBe(checkCatastrophicShape(pattern));
    }
    // ... and these two are independent: a pattern the validator accepts can
    // still be unprovable, which is a deny only when there is no worker.
    expect(checkCatastrophicShape('([a-z0-9-]+\\.)*')).toBeUndefined();
  });

  it('args regexes: patterns are matched in Unicode mode, and unportable spellings are translated not rejected', () => {
    // The local engine matches with the `u` flag so that it counts runes like
    // RE2 does. `u` also tightens SPELLING, which carries no meaning, so
    // `toUnicodeSource` rewrites those spellings instead of rejecting them:
    // everything the escape whitelist accepts keeps validating.
    const translated: Array<[string, string]> = [
      ['\\-', '\\x2d'],
      ['a\\ b', 'a\\x20b'],
      ['\\#\\_\\@\\:', '\\x23\\x5f\\x40\\x3a'],
      ['a]b', 'a\\]b'],
      ['a{b', 'a\\{b'],
      ['a}b', 'a\\}b'],
      ['[a\\-z]', '[a\\-z]'], // legal under `u` inside a class: left alone
      ['^https?://', '^https?://'],
      ['a{2,3}', 'a{2,3}'],
      ['\\x41\\t\\n\\.\\\\', '\\x41\\t\\n\\.\\\\'],
      ['[\\]a]', '[\\]a]'],
    ];
    for (const [pattern, expected] of translated) {
      expect(toUnicodeSource(pattern), pattern).toBe(expected);
      // The rewrite never changes which strings match.
      const plain = new RegExp(pattern);
      const unicode = new RegExp(toUnicodeSource(pattern), 'u');
      for (const sample of ['', '-', ' ', 'a b', 'a]b', 'a{b', 'a}b', 'az', 'a-z', 'https://x', 'aa', 'aaa', 'A\t\n.\\', ']a', '#_@:']) {
        expect(unicode.test(sample), `${pattern} vs ${JSON.stringify(sample)}`).toBe(plain.test(sample));
      }
    }
    // The whole pinned escape set still validates, and so does the shipped example.
    for (const pattern of ['\\.\\\\\\+\\*\\?\\(\\)\\[\\]\\{\\}\\|\\^\\$\\-\\/\\_\\#\\ ', '[\\d\\w\\n\\t\\x41\\-\\]]', '(^|/)(\\.env|secrets\\.env|id_rsa|\\.npmrc)$']) {
      expect(checkRe2Subset(pattern), pattern).toBeUndefined();
    }
    // A class range RE2 itself refuses ("invalid character class range:
    // `a-\\`", verified against OPA 1.20.2) cannot be translated: rejected.
    for (const pattern of ['[a-\\d]']) {
      expect(checkRe2Subset(pattern), pattern).toMatch(/cannot be matched in Unicode mode/);
      expectError(errorsFor((d) => (rule0(d).match.args = { url: pattern })), '/mcp/rules/0/match/args/url', 'regex', /Unicode mode/);
    }
    // A dash BESIDE a class escape is a different matter: `u` mode calls it
    // an invalid range, and both RE2 and non-`u` JavaScript read it as a
    // literal dash. Verified against OPA 1.20.2: `[\\d-z]` matches "-", "5"
    // and "z" and nothing else. These validated before the engine moved to
    // `u` and validate again, translated rather than refused.
    for (const [pattern, expected] of [
      ['[\\d-z]', '[\\d\\-z]'],
      ['[\\w-x]', '[\\w\\-x]'],
      ['[\\w-.]', '[\\w\\-.]'],
    ] as const) {
      expect(checkRe2Subset(pattern), pattern).toBeUndefined();
      expect(toUnicodeSource(pattern), pattern).toBe(expected);
      const plain = new RegExp(pattern);
      const unicode = new RegExp(toUnicodeSource(pattern), 'u');
      for (const sample of ['-', '5', 'z', 'x', 'm', '.', 'a', '_']) {
        expect(unicode.test(sample), `${pattern} vs ${JSON.stringify(sample)}`).toBe(plain.test(sample));
      }
    }
  });

  it('policy strings with an unpaired surrogate are rejected: Go cannot carry one', () => {
    // OPA reads "\ud800" back as U+FFFD, so the compiled Rego would match on
    // different text than the local engine. Unlike U+FEFF (which the emitter
    // escapes) there is no spelling that survives, so it is refused here.
    expectError(errorsFor((d) => (rule0(d).reason = 'oops \uD800')), '/mcp/rules/0/reason', 'text', /unpaired surrogate \\ud800/);
    expectError(errorsFor((d) => (rule0(d).match.args = { url: '^\uDFFF' })), '/mcp/rules/0/match/args/url', 'regex', /unpaired surrogate/);
    expectError(errorsFor((d) => (rule0(d).match.tool = 'a\uD800b')), '/mcp/rules/0/match/tool', 'glob', /unpaired surrogate/);
    expectError(errorsFor((d) => (erule0(d).reason = '\uDC00')), '/egress/rules/0/reason', 'text', /unpaired surrogate/);
    // A real astral character (a well-formed pair) is fine everywhere.
    const ok = designExample();
    ok.mcp!.rules![0]!.reason = 'no \u{1F600} exfiltration';
    ok.mcp!.rules![0]!.match.args = { url: '^\u{1F600}' };
    expect(validatePolicyObject(ok).ok, formatPolicyErrors(validatePolicyObject(ok).ok ? [] : (validatePolicyObject(ok) as { errors: PolicyError[] }).errors)).toBe(true);
  });

  it('max_args_bytes / max_body_bytes: integer >= 0', () => {
    expectError(errorsFor((d) => (rule0(d).match.max_args_bytes = -1)), '/mcp/rules/0/match/max_args_bytes', 'minimum');
    expectError(errorsFor((d) => (rule0(d).match.max_args_bytes = 1.5)), '/mcp/rules/0/match/max_args_bytes', 'type');
    expectError(errorsFor((d) => (rule0(d).match.max_args_bytes = '1')), '/mcp/rules/0/match/max_args_bytes', 'type');
    expectError(errorsFor((d) => (erule0(d).match.max_body_bytes = -1)), '/egress/rules/0/match/max_body_bytes', 'minimum');
    expectError(errorsFor((d) => (erule0(d).match.max_body_bytes = 0.5)), '/egress/rules/0/match/max_body_bytes', 'type');
  });

  it('duplicate rule ids are per section and name the earlier rule', () => {
    const dupMcp = errorsFor((d) => {
      const r = mcpOf(d).rules;
      r.push({ id: 'other', match: { tool: 'x' }, action: 'allow' }, { id: 'no-exfil', match: { tool: 'y' }, action: 'allow' });
    });
    expect(dupMcp).toEqual([
      { path: '/mcp/rules/2/id', keyword: 'duplicateId', message: 'duplicate rule id "no-exfil" (already used by rule 0)' },
    ]);
    const dupEgress = errorsFor((d) => egressOf(d).rules.push({ id: 'github-read', match: { host: 'x' }, action: 'deny' }));
    expect(dupEgress.map((e) => e.path)).toEqual(['/egress/rules/1/id']);
    // The same id in mcp and egress is fine; unnamed rules never collide.
    const doc = designExample();
    doc.egress!.rules![0]!.id = 'no-exfil';
    doc.mcp!.rules!.push({ match: { tool: 'a' }, action: 'allow' }, { match: { tool: 'b' }, action: 'allow' });
    expect(validatePolicyObject(doc).ok).toBe(true);
  });

  it('hold: timeout range, integer, on_timeout enum, unknown key', () => {
    expectError(errorsFor((d) => (mcpOf(d).hold.timeout_ms = 999)), '/mcp/hold/timeout_ms', 'minimum', '>= 1000');
    expectError(errorsFor((d) => (mcpOf(d).hold.timeout_ms = 3600001)), '/mcp/hold/timeout_ms', 'maximum', '<= 3600000');
    expectError(errorsFor((d) => (mcpOf(d).hold.timeout_ms = 1500.5)), '/mcp/hold/timeout_ms', 'type');
    expectError(errorsFor((d) => (mcpOf(d).hold.timeout_ms = '60000')), '/mcp/hold/timeout_ms', 'type');
    expectError(errorsFor((d) => (mcpOf(d).hold.on_timeout = 'hold')), '/mcp/hold/on_timeout', 'enum');
    expectError(errorsFor((d) => (mcpOf(d).hold.timeout = 1)), '/mcp/hold/timeout', 'additionalProperties');
  });

  it('boundary: enums and scan-size range', () => {
    expectError(errorsFor((d) => (mcpOf(d).boundary.secrets = 'drop')), '/mcp/boundary/secrets', 'enum');
    expectError(errorsFor((d) => (mcpOf(d).boundary.injection = 'yes')), '/mcp/boundary/injection', 'enum');
    expectError(errorsFor((d) => (mcpOf(d).boundary.on_oversize = 'redact')), '/mcp/boundary/on_oversize', 'enum');
    expectError(errorsFor((d) => (mcpOf(d).boundary.max_scan_bytes = 4095)), '/mcp/boundary/max_scan_bytes', 'minimum', '>= 4096');
    expectError(errorsFor((d) => (mcpOf(d).boundary.max_scan_bytes = 64 * 1024 * 1024 + 1)), '/mcp/boundary/max_scan_bytes', 'maximum', '<= 67108864');
    expectError(errorsFor((d) => (mcpOf(d).boundary.max_scan_bytes = 'big')), '/mcp/boundary/max_scan_bytes', 'type');
  });

  it('egress: shape, host required, methods upper-case and non-empty', () => {
    expectError(errorsFor((d) => (d.egress = 'deny')), '/egress', 'type');
    expectError(errorsFor((d) => (egressOf(d).default = 'maybe')), '/egress/default', 'enum');
    expectError(errorsFor((d) => delete erule0(d).match.host), '/egress/rules/0/match', 'required', '"host"');
    expectError(errorsFor((d) => (erule0(d).match.host = 5)), '/egress/rules/0/match/host', 'anyOf');
    expectError(errorsFor((d) => (erule0(d).match.methods = ['get'])), '/egress/rules/0/match/methods/0', 'pattern');
    expectError(errorsFor((d) => (erule0(d).match.methods = ['GET', 'Post'])), '/egress/rules/0/match/methods/1', 'pattern');
    expectError(errorsFor((d) => (erule0(d).match.methods = [])), '/egress/rules/0/match/methods', 'minItems');
    expectError(errorsFor((d) => (erule0(d).match.methods = 'GET')), '/egress/rules/0/match/methods', 'type');
    expectError(errorsFor((d) => (erule0(d).match.path = 7)), '/egress/rules/0/match/path', 'anyOf');
    expectError(errorsFor((d) => (erule0(d).action = 'log')), '/egress/rules/0/action', 'enum');
    expectError(errorsFor((d) => delete (erule0(d) as Doc).action), '/egress/rules/0', 'required');
  });

  it('reports several independent errors at once', () => {
    const errors = errorsFor((d) => {
      d.version = 3;
      rule0(d).action = 'x';
      erule0(d).match.methods = ['get'];
    });
    expect(errors.map((e) => e.path)).toEqual(['/version', '/mcp/rules/0/action', '/egress/rules/0/match/methods/0']);
    expect(formatPolicyErrors(errors).split('\n')).toHaveLength(3);
  });
});

/* ------------------------------- normalize ------------------------------- */

describe('normalizePolicy', () => {
  it('fills every default and assigns rule[<index>] ids', () => {
    const policy = normalizePolicy({
      version: 1,
      mcp: { rules: [{ match: { tool: 'a' }, action: 'allow' }, { id: 'named', match: { tool: ['b', 'c'] }, action: 'hold' }] },
      egress: { rules: [{ match: { host: 'h' }, action: 'deny' }] },
    });
    expect(policy).toEqual({
      version: 1,
      mcp: {
        default: 'allow',
        rules: [
          { id: 'rule[0]', match: { server: ['*'], tool: ['a'] }, action: 'allow' },
          { id: 'named', match: { server: ['*'], tool: ['b', 'c'] }, action: 'hold' },
        ],
        hold: { timeout_ms: 60000, on_timeout: 'deny' },
        boundary: { secrets: 'redact', injection: 'flag', max_scan_bytes: 1048576, on_oversize: 'flag' },
      },
      egress: { default: 'deny', rules: [{ id: 'rule[0]', match: { host: ['h'], path: ['/**'] }, action: 'deny' }] },
    });
    expect(autoRuleId(7)).toBe('rule[7]');
    expect(DEFAULTS.hold.timeout_ms).toBe(60000);
    expect(DEFAULTS.boundary.max_scan_bytes).toBe(1 << 20);
    expect(DEFAULTS.egress.default).toBe('deny');
    expect(DEFAULTS.mcp.default).toBe('allow');
  });

  it('keeps explicit values, omits absent optionals and does not mutate its input', () => {
    const input: PolicyInput = {
      version: 1,
      name: 'n',
      mcp: { default: 'deny', hold: { on_timeout: 'allow' }, boundary: { secrets: 'off' } },
    };
    const snapshot = JSON.stringify(input);
    const policy = normalizePolicy(input);
    expect(JSON.stringify(input)).toBe(snapshot);
    expect(policy.egress).toBeUndefined();
    expect(policy.mcp).toEqual({
      default: 'deny',
      rules: [],
      hold: { timeout_ms: 60000, on_timeout: 'allow' },
      boundary: { secrets: 'off', injection: 'flag', max_scan_bytes: 1048576, on_oversize: 'flag' },
    });
    expect('reason' in policy.mcp!).toBe(false);
    expect(JSON.parse(JSON.stringify(policy))).toEqual(policy); // JSON-plain
  });

  it('copies arrays and args so later edits to the input do not leak', () => {
    const tool = ['a'];
    const args = { x: '^1$' };
    const policy = normalizePolicy({ version: 1, mcp: { rules: [{ match: { tool, args }, action: 'allow' }] } });
    tool.push('b');
    args.x = '^2$';
    expect(policy.mcp!.rules[0]!.match.tool).toEqual(['a']);
    expect(policy.mcp!.rules[0]!.match.args).toEqual({ x: '^1$' });
  });
});

/* --------------------------------- loader -------------------------------- */

describe('loadPolicyFile', () => {
  const dir = mkdtempSync(join(tmpdir(), 'mcp-recorder-policy-'));
  afterAll(() => rmSync(dir, { recursive: true, force: true }));
  const write = (name: string, text: string): string => {
    const p = join(dir, name);
    writeFileSync(p, text);
    return p;
  };

  it('loads the YAML fixture with hash of the exact bytes, name and source', () => {
    const path = join(FIXTURES, 'laptop-default.yaml');
    const loaded = loadPolicyFile(path);
    expect(loaded.source).toBe('yaml');
    expect(loaded.path).toBe(path);
    expect(loaded.name).toBe('laptop-default');
    expect(loaded.hash).toBe('sha256:' + sha256Hex(readFileSync(path)));
    expect(loaded.hash).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(loaded.policy.mcp!.rules.map((r) => r.id)).toEqual(['no-exfil', 'hold-writes']);
    expect(loaded.policy.egress!.rules[0]!.match.methods).toEqual(['GET', 'HEAD']);
  });

  it('loads JSON via JSON.parse and reports source json', () => {
    const loaded = loadPolicyFile(join(FIXTURES, 'empty.json'));
    expect(loaded.source).toBe('json');
    expect(loaded.name).toBe('empty');
    expect(loaded.policy.mcp!.rules).toEqual([]);
    expect(loaded.policy.egress!.default).toBe('deny');
    const bad = write('bad.json', '{"version": 1, "mcp": {},}');
    expect(() => loadPolicyFile(bad)).toThrow(PolicyLoadError);
    expect(() => loadPolicyFile(bad)).toThrow(/bad\.json: JSON parse error/);
  });

  it('omits name when the policy has none; .yml and unknown extensions parse as YAML', () => {
    const yml = write('p.yml', 'version: 1\nmcp:\n  default: deny\n');
    const loaded = loadPolicyFile(yml);
    expect('name' in loaded).toBe(false);
    expect(loaded.source).toBe('yaml');
    expect(loaded.policy.mcp!.default).toBe('deny');
    const txt = write('p.policy', '{"version": 1, "egress": {}}');
    expect(loadPolicyFile(txt).source).toBe('yaml');
    expect(loadPolicyFile(txt).policy.egress!.default).toBe('deny');
  });

  it('every hash differs when a single byte differs (comments count)', () => {
    const a = write('a.yaml', 'version: 1\nmcp: {}\n');
    const b = write('b.yaml', 'version: 1\nmcp: {}\n# c\n');
    expect(loadPolicyFile(a).hash).not.toBe(loadPolicyFile(b).hash);
    expect(loadPolicyFile(a).policy).toEqual(loadPolicyFile(b).policy);
  });

  it('rejects duplicate mapping keys', () => {
    const p = write('dup.yaml', 'version: 1\nmcp: {}\nmcp: {}\n');
    expect(() => loadPolicyFile(p)).toThrow(/dup\.yaml: YAML parse error: Map keys must be unique/);
  });

  it('rejects non-object roots and empty documents', () => {
    expect(() => loadPolicyFile(write('list.yaml', '- a\n- b\n'))).toThrow(/root must be a mapping\/object, got array/);
    expect(() => loadPolicyFile(write('scalar.yaml', '42\n'))).toThrow(/got number/);
    expect(() => loadPolicyFile(write('empty.yaml', ''))).toThrow(/got empty document/);
    expect(() => loadPolicyFile(write('null.yaml', '~\n'))).toThrow(/got empty document/);
    expect(() => loadPolicyFile(write('str.json', '"x"'))).toThrow(/got string/);
    expect(() => loadPolicyFile(write('arr.json', '[]'))).toThrow(/got array/);
  });

  it('rejects YAML syntax errors with the path in the message', () => {
    const p = write('syntax.yaml', 'version: 1\nmcp:\n  rules: [\n');
    expect(() => loadPolicyFile(p)).toThrow(PolicyLoadError);
    expect(() => loadPolicyFile(p)).toThrow(/syntax\.yaml: YAML parse error/);
  });

  it('rejects values that are not JSON (binary, sets, nan, inf)', () => {
    expect(() => loadPolicyFile(write('bin.yaml', 'version: 1\nname: !!binary aGk=\nmcp: {}\n'))).toThrow(/\/name: unsupported value of type Buffer/);
    expect(() => loadPolicyFile(write('set.yaml', 'version: 1\nmcp:\n  rules: !!set {a, b}\n'))).toThrow(/\/mcp\/rules: unsupported value of type Set/);
    expect(() => loadPolicyFile(write('nan.yaml', 'version: .nan\nmcp: {}\n'))).toThrow(/\/version: non-finite number NaN/);
    expect(() => loadPolicyFile(write('inf.yaml', 'version: 1\nmcp:\n  hold:\n    timeout_ms: .inf\n'))).toThrow(/\/mcp\/hold\/timeout_ms: non-finite number Infinity/);
    expect(findNonJsonValue({ a: [1, 'x', null, true, { b: new Date(0) }] })).toEqual({
      path: '/a/4/b',
      reason: 'unsupported value of type Date (only JSON values are allowed)',
    });
    expect(findNonJsonValue({ 'a/b': [undefined] })).toEqual({ path: '/a~1b/0', reason: 'unsupported value of type undefined (only JSON values are allowed)' });
    expect(findNonJsonValue({ a: [1, 'x', null, true, { b: 2 }] })).toBeUndefined();
  });

  it('does not expand << merge keys (the key becomes an unknown property)', () => {
    const p = write('merge.yaml', 'base: &b\n  default: deny\nversion: 1\nmcp:\n  <<: *b\n');
    expect(() => loadPolicyFile(p)).toThrow(PolicyValidationError);
    try {
      loadPolicyFile(p);
    } catch (err) {
      const errors = (err as PolicyValidationError).errors.map((e) => e.path);
      expect(errors).toContain('/base');
      expect(errors).toContain('/mcp/<<');
    }
  });

  it('throws PolicyValidationError (a PolicyLoadError) with the error list for invalid policies', () => {
    const p = write('invalid.yaml', 'version: 1\nmcp:\n  rules:\n    - match: { tool: "" }\n      action: nope\n');
    let caught: unknown;
    try {
      loadPolicyFile(p);
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(PolicyValidationError);
    expect(caught).toBeInstanceOf(PolicyLoadError);
    const e = caught as PolicyValidationError;
    expect(e.path).toBe(p);
    expect(e.errors.map((x) => x.path)).toEqual(['/mcp/rules/0/match/tool', '/mcp/rules/0/action']);
    expect(e.message).toContain('invalid.yaml: invalid policy (2 errors)');
    expect(e.message).toContain('/mcp/rules/0/action: must be one of "allow", "hold", "deny"');
  });

  it('throws PolicyLoadError for a missing file, naming the path', () => {
    const p = join(dir, 'nope.yaml');
    expect(() => loadPolicyFile(p)).toThrow(PolicyLoadError);
    expect(() => loadPolicyFile(p)).toThrow(/nope\.yaml: cannot read policy file: ENOENT/);
  });

  it('parsePolicyText parses inline text for both sources', () => {
    expect(parsePolicyText('version: 1\n', 'yaml', 'x')).toEqual({ version: 1 });
    expect(parsePolicyText('{"version": 1}', 'json', 'x')).toEqual({ version: 1 });
  });
});

/* ------------------------------ credentials ------------------------------- */

type Mutable = Record<string, unknown>;

/** The smallest credentials document that is actually safe: one credential, one destination-bound site. */
function credentialsDoc(): Mutable {
  return {
    version: 1,
    credentials: [
      {
        id: 'github-issues',
        source: { type: 'env', var: 'GITHUB_TOKEN' },
        use: [{ tool: 'http_post', arg: 'headers.Authorization', host: { from_arg: 'url', allow: ['api.github.com'] } }],
      },
    ],
  };
}

/** `mutate` gets the first credential, its first use site and the whole document. */
function credsMutated(mutate: (credential: Mutable, use: Mutable, doc: Mutable) => void): Mutable {
  const doc = credentialsDoc();
  const credential = (doc.credentials as Mutable[])[0] as Mutable;
  const use = (credential.use as Mutable[])[0] as Mutable;
  mutate(credential, use, doc);
  return doc;
}

function credErrors(mutate: (credential: Mutable, use: Mutable, doc: Mutable) => void): PolicyError[] {
  const doc = credsMutated(mutate);
  const result = validatePolicyObject(doc);
  expect(result.ok, `expected validation to fail for ${JSON.stringify(doc)}`).toBe(false);
  return result.ok ? [] : result.errors;
}

function credPolicy(mutate: (credential: Mutable, use: Mutable, doc: Mutable) => void = () => {}): Policy {
  const result = validatePolicyObject(credsMutated(mutate));
  if (!result.ok) throw new Error(formatPolicyErrors(result.errors));
  return result.policy;
}

function firstCredential(mutate: (credential: Mutable, use: Mutable, doc: Mutable) => void = () => {}): Credential {
  return credPolicy(mutate).credentials![0]!;
}

describe('credentials: the section as a whole', () => {
  it('stands on its own at the root, and the anyOf message names all three sections', () => {
    expect(validatePolicyObject(credentialsDoc()).ok).toBe(true);
    const bare = validatePolicyObject({ version: 1 });
    expect(bare.ok).toBe(false);
    if (!bare.ok) expect(bare.errors[0]!.message).toBe('at least one of "mcp", "credentials" or "egress" is required');
  });

  it('rejects an empty list, and unknown keys at every level', () => {
    expectError(credErrors((_c, _u, doc) => (doc.credentials = [])), '/credentials', 'minItems');
    expectError(credErrors((c) => (c.provider_name = 'github')), '/credentials/0/provider_name', 'additionalProperties');
    expectError(credErrors((_c, u) => (u.args = { x: 'y' })), '/credentials/0/use/0/args', 'additionalProperties');
    // A typo in a SOURCE cannot be reported per-key: the source is a
    // discriminated union, so an unknown key means no branch matched.
    expectError(credErrors((c) => ((c.source as Mutable).file = '/tmp/x')), '/credentials/0/source', 'oneOf');
  });

  it('requires an id, a source and at least one use site', () => {
    expectError(credErrors((c) => delete c.id), '/credentials/0', 'required');
    expectError(credErrors((c) => delete c.source), '/credentials/0', 'required');
    expectError(credErrors((c) => (c.use = [])), '/credentials/0/use', 'minItems');
  });

  it('holds is not a credential action in v1, and deny is the only on_unresolved', () => {
    // Both refusals exist because the gateway has no code behind the value:
    // a held credential would have to resolve AFTER the human answers, and
    // "forward anyway" would forward the synthetic to the upstream.
    expectError(credErrors((_c, u) => (u.action = 'hold')), '/credentials/0/use/0/action', 'enum');
    expect(credPolicy((_c, u) => (u.action = 'deny')).credentials![0]!.use[0]!.action).toBe('deny');
    expectError(credErrors((c) => (c.on_unresolved = 'allow')), '/credentials/0/on_unresolved', 'enum');
  });
});

describe('credentials: the destination has to be constrained', () => {
  it('a swap site with no host is a validation error, not a default-allow', () => {
    // The whole point of destination binding: a policy that allows
    // `http_post` with a credential in headers.Authorization and says nothing
    // about where it goes authorises attacker.example exactly as happily as
    // api.github.com, and the destination is the agent's to choose.
    expectError(credErrors((_c, u) => delete u.host), '/credentials/0/use/0', 'required', /"host"/);
  });

  it('accepts exactly the three host forms and nothing in between', () => {
    expect(firstCredential((_c, u) => (u.host = { fixed: 'api.github.com' })).use[0]!.host).toEqual({
      from: 'declared',
      host: 'api.github.com',
    });
    expect(firstCredential((_c, u) => (u.host = { from: 'server' })).use[0]!.host).toEqual({ from: 'server_name' });
    // An argument-derived host without its allow-list is the unconstrained
    // case wearing a different hat, so the schema does not admit it.
    expectError(credErrors((_c, u) => (u.host = { from_arg: 'url' })), '/credentials/0/use/0/host', 'oneOf');
    expectError(credErrors((_c, u) => (u.host = {})), '/credentials/0/use/0/host', 'oneOf');
    expectError(credErrors((_c, u) => (u.host = { from_arg: 'url', allow: ['a.b'], fixed: 'a.b' })), '/credentials/0/use/0/host', 'oneOf');
    expectError(credErrors((_c, u) => (u.host = { from: 'tool' })), '/credentials/0/use/0/host', 'oneOf');
    expectError(credErrors((_c, u) => (u.host = { fixed: 'https://api.github.com/x' })), '/credentials/0/use/0/host', 'oneOf');
  });

  it('will not read the destination out of the argument it is about to overwrite', () => {
    expectError(
      credErrors((_c, u) => ((u.host as Mutable).from_arg = u.arg)),
      '/credentials/0/use/0/host/from_arg',
      'credentialSite',
      /same argument the credential is spliced into/,
    );
  });

  it('runs host, path, server and tool through the SAME glob and dot-path checks as mcp', () => {
    expectError(credErrors((_c, u) => ((u.host as Mutable).allow = ['api.?ithub.com'])), '/credentials/0/use/0/host/allow/0', 'glob', /\? wildcard/);
    expectError(credErrors((_c, u) => (u.tool = ['ok', ' '])), '/credentials/0/use/0/tool/1', 'glob', /empty or blank/);
    expectError(credErrors((_c, u) => (u.server = '{a,b}')), '/credentials/0/use/0/server', 'glob', /reserved/);
    expectError(credErrors((_c, u) => (u.arg = 'headers..Authorization')), '/credentials/0/use/0/arg', 'dotPath');
    expectError(credErrors((_c, u) => ((u.host as Mutable).from_arg = 'a..b')), '/credentials/0/use/0/host/from_arg', 'dotPath');
    expectError(credErrors((_c, u) => (u.path = { from_arg: '.x', allow: ['/**'] })), '/credentials/0/use/0/path/from_arg', 'dotPath');
    expectError(credErrors((_c, u) => (u.path = { from_arg: 'list_id', allow: ['9?1'] })), '/credentials/0/use/0/path/allow/0', 'glob');
  });
});

describe('credentials: sources', () => {
  const sources: Record<string, Mutable> = {
    env: { type: 'env', var: 'GITHUB_TOKEN' },
    file: { type: 'file', path: '/etc/mcp-recorder/stripe.json', field: 'keys.restricted' },
    exec: { type: 'exec', command: '/usr/bin/op', args: ['read', 'op://dev/npm/token'] },
    'github-app': { type: 'github-app', app_id: '12345', installation_id: '67890', private_key_env: 'GH_APP_KEY', permissions: { issues: 'write' } },
    'aws-sts': { type: 'aws-sts', role_arn: 'arn:aws:iam::123456789012:role/mcp-reader', region: 'eu-west-1', duration_seconds: 900 },
    vault: { type: 'vault', path: 'secret/data/db', addr: 'https://openbao.internal:8200', token_env: 'VAULT_TOKEN' },
    clickup: { type: 'clickup', team_id: '9012345678' },
  };

  it('accepts all seven in their minimal valid form', () => {
    for (const [name, source] of Object.entries(sources)) {
      const result = validatePolicyObject(credsMutated((c) => (c.source = source)));
      expect(result.ok, `${name}: ${result.ok ? '' : formatPolicyErrors(result.errors)}`).toBe(true);
    }
    expectError(credErrors((c) => (c.source = { type: 'keychain', account: 'x' })), '/credentials/0/source', 'oneOf');
  });

  it('every path a source names must be absolute', () => {
    // A relative path resolves against the recorder's working directory,
    // which in a stdio deployment is wherever the CLIENT happened to launch.
    expectError(credErrors((c) => (c.source = { type: 'file', path: 'stripe.json' })), '/credentials/0/source/path', 'absolutePath');
    // And a bare command name resolves through PATH, which the agent writes.
    expectError(credErrors((c) => (c.source = { type: 'exec', command: 'op', args: ['read'] })), '/credentials/0/source/command', 'absolutePath');
    expectError(
      credErrors((c) => (c.source = { type: 'github-app', app_id: '1', installation_id: '2', private_key_file: 'key.pem' })),
      '/credentials/0/source/private_key_file',
      'absolutePath',
    );
    for (const absolute of ['/etc/x.json', 'C:\\ProgramData\\x.json', '\\\\host\\share\\x.json']) {
      expect(validatePolicyObject(credsMutated((c) => (c.source = { type: 'file', path: absolute }))).ok, absolute).toBe(true);
    }
  });

  it('checks the per-source fields the schema cannot express', () => {
    expectError(credErrors((c) => (c.source = { type: 'github-app', app_id: '1', installation_id: '2' })), '/credentials/0/source', 'source', /exactly one/);
    expectError(
      credErrors((c) => (c.source = { type: 'github-app', app_id: '1', installation_id: '2', private_key_env: 'K', private_key_file: '/k.pem' })),
      '/credentials/0/source',
      'source',
      /not both/,
    );
    expectError(
      credErrors((c) => (c.source = { type: 'github-app', app_id: '1', installation_id: '2', private_key_env: 'K', permissions: { issues: 'delete' } })),
      '/credentials/0/source/permissions/issues',
      'enum',
    );
    expectError(credErrors((c) => (c.source = { type: 'vault', path: 'p', addr: 'openbao.internal' })), '/credentials/0/source/addr', 'url');
    expectError(credErrors((c) => (c.source = { type: 'vault', path: 'p', addr: 'file:///etc/passwd' })), '/credentials/0/source/addr', 'url');
    expectError(credErrors((c) => (c.source = { type: 'env', var: 'GITHUB-TOKEN' })), '/credentials/0/source', 'oneOf');
    expectError(credErrors((c) => (c.source = { type: 'aws-sts', role_arn: 'mcp-reader' })), '/credentials/0/source', 'oneOf');
    // STS below its own 15-minute floor is a typo, not a shorter token.
    expectError(credErrors((c) => (c.source = { type: 'aws-sts', role_arn: sources['aws-sts']!.role_arn, duration_seconds: 60 })), '/credentials/0/source', 'oneOf');
  });
});

describe('credentials: normalization', () => {
  it('fills the defaults the broker depends on, and quotes where each number comes from', () => {
    const credential = firstCredential();
    expect(credential.ttl_seconds).toBe(30); // NHI's BROKER_DEFAULT_TTL_SECONDS
    expect(credential.timeout_ms).toBe(5000); // NHI's brokerclient HTTP timeout
    expect(credential.on_unresolved).toBe('deny');
    expect(credential.use[0]!.action).toBe('allow');
    expect(credential.use[0]!.server).toEqual(['*']);
    expect(credential.use[0]!.path).toEqual({ from: 'tool_name' });
    expect(DEFAULTS.credential.ttl_seconds).toBe(30);
    expect(DEFAULTS.credential.timeout_ms).toBe(5000);
    // Per-source defaults: the vault key the control plane reads, the
    // shortest session STS will mint, and ClickUp's usual variable.
    expect(firstCredential((c) => (c.source = { type: 'vault', path: 'secret/data/db' })).source).toEqual({
      type: 'vault',
      path: 'secret/data/db',
      field: 'token',
    });
    expect(firstCredential((c) => (c.source = { type: 'aws-sts', role_arn: 'arn:aws:iam::123456789012:role/r' })).source).toEqual({
      type: 'aws-sts',
      role_arn: 'arn:aws:iam::123456789012:role/r',
      duration_seconds: 900,
    });
    expect(firstCredential((c) => (c.source = { type: 'clickup' })).source).toEqual({ type: 'clickup', token_env: 'CLICKUP_API_TOKEN' });
    expect(firstCredential((c) => (c.source = { type: 'exec', command: '/usr/bin/op' })).source).toEqual({ type: 'exec', command: '/usr/bin/op', args: [] });
  });

  it('composes the recorded site id from the credential and the site', () => {
    expect(firstCredential().use[0]!.id).toBe('github-issues/use[0]');
    expect(autoUseId(3)).toBe('use[3]');
    expect(credentialUseId('a', 'b')).toBe('a/b');
    expect(firstCredential((_c, u) => (u.id = 'create-issue')).use[0]!.id).toBe('github-issues/create-issue');
  });

  it('scopes id uniqueness the way the composition does: per credential, per section', () => {
    // Two credentials may both call a site `write` — the composed ids differ.
    const twoCredentials = credPolicy((c, _u, doc) => {
      const second = JSON.parse(JSON.stringify(c)) as Mutable;
      second.id = 'clickup-api';
      ((c.use as Mutable[])[0] as Mutable).id = 'write';
      ((second.use as Mutable[])[0] as Mutable).id = 'write';
      (doc.credentials as Mutable[]).push(second);
    });
    expect(twoCredentials.credentials!.map((c) => c.use[0]!.id)).toEqual(['github-issues/write', 'clickup-api/write']);
    // Within one credential, and within the section, they may not.
    expectError(
      credErrors((c) => {
        const site = JSON.parse(JSON.stringify((c.use as Mutable[])[0])) as Mutable;
        site.id = 'write';
        ((c.use as Mutable[])[0] as Mutable).id = 'write';
        (c.use as Mutable[]).push(site);
      }),
      '/credentials/0/use/1/id',
      'duplicateId',
      /duplicate use site id/,
    );
    expectError(
      credErrors((c, _u, doc) => (doc.credentials as Mutable[]).push(JSON.parse(JSON.stringify(c)) as Mutable)),
      '/credentials/1/id',
      'duplicateId',
      /duplicate credential id/,
    );
    // The mcp/egress pointers did not move when the helper grew a base path.
    const mcpDup = validatePolicyObject({
      version: 1,
      mcp: { rules: [{ id: 'r', match: { tool: 'a' }, action: 'allow' }, { id: 'r', match: { tool: 'b' }, action: 'deny' }] },
    });
    expect(mcpDup.ok).toBe(false);
    if (!mcpDup.ok) expect(mcpDup.errors[0]!.path).toBe('/mcp/rules/1/id');
  });

  it('is pure and JSON-plain, like the rest of the normalized policy', () => {
    const input: PolicyInput = {
      version: 1,
      credentials: [
        {
          id: 'c',
          scopes: ['a'],
          source: { type: 'exec', command: '/bin/true', args: ['x'] },
          use: [{ tool: 't', arg: 'a', host: { from_arg: 'u', allow: ['h'] } }],
        },
      ],
    };
    const snapshot = JSON.stringify(input);
    const policy = normalizePolicy(input);
    input.credentials![0]!.scopes!.push('b');
    (input.credentials![0]!.source as { args: string[] }).args.push('y');
    expect(JSON.stringify(normalizePolicy(JSON.parse(snapshot) as PolicyInput))).toBe(JSON.stringify(policy));
    expect(policy.credentials![0]!.scopes).toEqual(['a']);
    expect((policy.credentials![0]!.source as { args: string[] }).args).toEqual(['x']);
    expect(JSON.parse(JSON.stringify(policy))).toEqual(policy);
  });

  it('loads the credentials fixture end to end', () => {
    const loaded = loadPolicyFile(join(FIXTURES, 'credentials.yaml'));
    expect(loaded.policy.credentials!.map((c) => c.id)).toEqual(['github-issues', 'clickup-api', 'db-readonly', 'npm-publish', 'stripe-readonly']);
    expect(loaded.policy.credentials![0]!.use.map((u) => u.id)).toEqual(['github-issues/no-deletes', 'github-issues/create-issue']);
    expect(loaded.policy.credentials![2]!.ttl_seconds).toBe(0); // 0 means "do not cache the decision"
  });
});

describe('credentials: who may write the policy file', () => {
  const me = { uid: 501, gid: 20, groups: [20, 80] };

  it('reads writability off the mode bits, and fails closed when it cannot read them', () => {
    // Owner-writable and owned by us is the ordinary laptop case, and it is
    // the one that matters: the recorder's uid is the agent's uid.
    expect(fileTrustFrom({ uid: 501, gid: 20, mode: 0o100644 }, me).writableByThisUid).toBe(true);
    expect(fileTrustFrom({ uid: 0, gid: 0, mode: 0o100644 }, me).writableByThisUid).toBe(false);
    expect(fileTrustFrom({ uid: 0, gid: 0, mode: 0o100666 }, me).writableByThisUid).toBe(true);
    expect(fileTrustFrom({ uid: 0, gid: 80, mode: 0o100664 }, me).writableByThisUid).toBe(true); // a group we are in
    expect(fileTrustFrom({ uid: 0, gid: 99, mode: 0o100664 }, me).writableByThisUid).toBe(false);
    expect(fileTrustFrom({ uid: 0, gid: 0, mode: 0o100444 }, { ...me, uid: 0 }).writableByThisUid).toBe(true); // root ignores the bits
    // Unknown is treated as writable on purpose: guessing "safe" on a
    // platform with no mode bits turns a control into a decoration.
    expect(fileTrustFrom({ uid: 501, gid: 20, mode: 0o100444 }, undefined)).toMatchObject({ writableByThisUid: true });
    expect(fileTrustFrom(undefined, me)).toMatchObject({ writableByThisUid: true });
    for (const trust of [fileTrustFrom({ uid: 501, gid: 20, mode: 0o100644 }, me), fileTrustFrom({ uid: 0, gid: 0, mode: 0o100444 }, me)]) {
      expect(trust.detail.length).toBeGreaterThan(0);
    }
  });

  it('names the exec credentials a writable policy must not be trusted to resolve', () => {
    const writable = { writableByThisUid: true, detail: 'the policy file is world-writable (mode 0666)' };
    const sealed = { writableByThisUid: false, detail: 'not writable' };
    const withExec = credPolicy((c) => (c.source = { type: 'exec', command: '/usr/bin/op', args: ['read'] }));
    expect(credentialTrustProblems(withExec, writable)).toHaveLength(1);
    expect(credentialTrustProblems(withExec, writable)[0]).toMatch(/"github-issues".*exec.*world-writable/);
    expect(credentialTrustProblems(withExec, sealed)).toEqual([]);
    // `env` and `file` are not refused: a writable policy can repoint them
    // either way, but only `exec` lets it choose the COMMAND as well.
    expect(credentialTrustProblems(credPolicy(), writable)).toEqual([]);
    expect(credentialTrustProblems({ version: 1 }, writable)).toEqual([]);
  });

  it('loadPolicyFile attaches the trust facts, and validation does not depend on them', () => {
    const loaded = loadPolicyFile(join(FIXTURES, 'credentials.yaml'));
    expect(typeof loaded.trust!.writableByThisUid).toBe('boolean');
    expect(loaded.trust!.detail.length).toBeGreaterThan(0);
    expect(policyFileTrust(join(FIXTURES, 'credentials.yaml'))).toEqual(loaded.trust);
    // A file that is not there at all still answers, fail-closed.
    expect(policyFileTrust(join(FIXTURES, 'no-such-policy.yaml')).writableByThisUid).toBe(true);
  });
});

/* ---------------------------------- glob --------------------------------- */

describe('glob', () => {
  const table: Array<[string, '/' | '.', string, boolean]> = [
    ['*', '/', '', true],
    ['*', '/', 'anything', true],
    ['*', '/', 'a/b', false],
    ['**', '/', '', true],
    ['**', '/', 'a/b/c', true],
    ['?', '/', 'a', true],
    ['?', '/', '', false],
    ['?', '/', '/', false],
    ['a?c', '/', 'abc', true],
    ['a?c', '/', 'a/c', false],
    ['a?c', '/', 'ac', false],
    ['send_*', '/', 'send_mail', true],
    ['send_*', '/', 'send_', true],
    ['send_*', '/', 'send_a/b', false],
    ['send_**', '/', 'send_a/b', true],
    ['search/**', '/', 'search/deep/x', true],
    ['search/**', '/', 'search/', true],
    ['search/**', '/', 'search', false],
    ['search/*', '/', 'search/deep/x', false],
    ['foo**bar', '/', 'foo/x/bar', true],
    ['a.b', '/', 'axb', false],
    ['a.b', '/', 'a.b', true],
    ['a+b(c)', '/', 'a+b(c)', true],
    ['a+b(c)', '/', 'aab(c)', false],
    ['*', '/', 'line\nbreak', true],
    ['*', '/', 'a\n/b', false],
    ['Tool', '/', 'tool', false],
    ['*.github.com', '.', 'api.github.com', true],
    ['*.github.com', '.', 'a.b.github.com', false],
    ['**.github.com', '.', 'a.b.github.com', true],
    ['*.github.com', '.', 'github.com', false],
    ['*.github.com', '.', 'x/y.github.com', true],
    ['api.github.com', '.', 'api.github.com', true],
    ['api?github.com', '.', 'api.github.com', false],
    ['api?github.com', '.', 'apixgithub.com', true],
    ['*.telemetry.*', '.', 'x.telemetry.io', true],
    ['*.telemetry.*', '.', 'x.telemetry.io.net', false],
  ];
  it.each(table)('globMatch(%j, %j, %j) === %s', (glob, delim, s, expected) => {
    expect(globMatch(glob, delim, s)).toBe(expected);
    expect(globToRegExp(glob, delim).test(s)).toBe(expected);
  });

  it('the "?" rows above are dead code: `checkGlob` rejects every glob containing "?"', () => {
    // globToRegExp still gives `?` the "one non-delimiter character" reading
    // (see src/policy/glob.ts) so it can never silently become a literal, but
    // no validated policy can reach it — OPA's `?` is ASCII-only, ours is not.
    for (const glob of ['?', 'a?c', 'api?github.com']) expect(checkGlob(glob), glob).toMatch(/\? wildcard is not supported/);
  });

  it('produces anchored, flag-less, escaped regexes', () => {
    expect(globToRegExp('a.*/**?', '/').source).toBe('^a\\.[^\\/]*\\/[\\s\\S]*[^\\/]$');
    expect(globToRegExp('*.x', '.').source).toBe('^[^\\.]*\\.x$');
    expect(globToRegExp('a', '/').flags).toBe('');
    expect(globToRegExp('$^|[]{}\\', '/').test('$^|[]{}\\')).toBe(true);
  });

  it('collapses a RUN of wildcards: the same language, without the adjacent-quantifier blowup', () => {
    // Translated atom for atom, `"*".repeat(30)` is fifteen adjacent
    // `[\s\S]*` quantifiers: against a 60-character subject (a tool name off
    // the wire, matched on the proxy thread) that took 88 s here. A run
    // accepts exactly what its most permissive member accepts, so it is
    // emitted once.
    expect(globToRegExp('**', '/').source).toBe('^[\\s\\S]*$');
    expect(globToRegExp('***', '/').source).toBe('^[\\s\\S]*$');
    expect(globToRegExp('*'.repeat(30) + 'x', '/').source).toBe('^[\\s\\S]*x$');
    expect(globToRegExp('*', '/').source).toBe('^[^\\/]*$');
    expect(globToRegExp('a*/**b', '/').source).toBe('^a[^\\/]*\\/[\\s\\S]*b$');
    const t0 = Date.now();
    expect(globMatch('*'.repeat(30) + 'x', '/', 'a'.repeat(60))).toBe(false);
    expect(Date.now() - t0).toBeLessThan(500);
    // Collapsing never changes what a glob accepts, with either delimiter.
    const subjects = ['', 'a', 'x', 'ax', 'a/b', 'a/b/c', 'abc/x', 'a.b', 'aaa', 'a/x', 'ab'];
    const pairs: Array<[string, string]> = [
      ['***', '**'],
      ['****', '**'],
      ['a***b', 'a**b'],
      ['a**b', 'a**b'],
      ['*a*', '*a*'],
    ];
    for (const [runGlob, single] of pairs) {
      for (const delim of ['/', '.'] as const) {
        for (const subject of subjects) {
          expect(globMatch(runGlob, delim, subject), `${runGlob} vs ${JSON.stringify(subject)} (${delim})`).toBe(
            globMatch(single, delim, subject),
          );
        }
      }
    }
  });

  it('caches compiled globs with a bounded LRU', () => {
    clearGlobCache();
    const first = compileGlob('first', '/');
    expect(compileGlob('first', '/')).toBe(first);
    expect(compileGlob('first', '.')).not.toBe(first); // delimiter is part of the key
    for (let i = 0; i < GLOB_CACHE_SIZE; i++) globMatch(`g${i}`, '/', 'x');
    expect(globCacheSize()).toBe(GLOB_CACHE_SIZE);
    // 'first' ('/') was touched most recently among the early entries only if re-read; it has been evicted.
    expect(compileGlob('first', '/')).not.toBe(first);
    // A hit refreshes recency: touch g_last, then overflow by one — the oldest (not g_last) goes.
    clearGlobCache();
    const keep = compileGlob('keep', '/');
    for (let i = 0; i < GLOB_CACHE_SIZE - 1; i++) globMatch(`h${i}`, '/', 'x');
    expect(compileGlob('keep', '/')).toBe(keep); // refresh
    globMatch('overflow', '/', 'x');
    expect(compileGlob('keep', '/')).toBe(keep);
    expect(globCacheSize()).toBe(GLOB_CACHE_SIZE);
  });
});

/* --------------------------------- engine -------------------------------- */

describe('evaluateMcp', () => {
  const policy = mcp(
    [
      { id: 'first', match: { tool: 'dup' }, action: 'deny', reason: 'first wins' },
      { id: 'second', match: { tool: 'dup' }, action: 'allow' },
      { id: 'scoped', match: { server: 'corp-*', tool: ['read_*', 'list_*'] }, action: 'hold', reason: 'scoped' },
      { id: 'url', match: { tool: 'http_post', args: { url: '^https://', 'headers.0.name': '^X-' } }, action: 'deny' },
      { id: 'num', match: { tool: 'num', args: { limit: '^[0-9]{1,2}$', flag: '^true$' } }, action: 'deny' },
      { id: 'small', match: { tool: 'sized', max_args_bytes: 100 } }, // action added below
    ].map((r) => ('action' in r ? r : { ...r, action: 'hold' })),
    { default: 'allow' },
  );
  const call = (tool: string, args: unknown = {}, extra: Partial<{ server: string; argsBytes: number }> = {}) =>
    evaluateMcp(policy, { server: extra.server ?? 'srv', tool, args, argsBytes: extra.argsBytes ?? 2 });

  it('first match wins and carries id, index and reason', () => {
    expect(call('dup')).toEqual({ action: 'deny', ruleId: 'first', ruleIndex: 0, reason: 'first wins', matched: true });
    expect(ruleLabel(call('dup'))).toBe('first');
  });

  it('falls back to the section default with matched:false and no rule fields', () => {
    const d = call('unknown_tool');
    expect(d).toEqual({ action: 'allow', matched: false });
    expect(ruleLabel(d)).toBe('default');
    expect(evaluateMcp(mcp([], { default: 'deny' }), { server: 's', tool: 't', args: {}, argsBytes: 2 })).toEqual({
      action: 'deny',
      matched: false,
    });
  });

  it('args: an array (or scalar) `arguments` never matches, whatever the dot-path', () => {
    const p = mcp([{ id: 'idx', match: { tool: 'http_post', args: { '0.url': '^https://' } }, action: 'deny' }]);
    const run = (args: unknown) => evaluateMcp(p, { server: 's', tool: 'http_post', args, argsBytes: 20 });
    // TS used to resolve "0" against the array and deny here while OPA allowed.
    expect(run([{ url: 'https://x' }])).toEqual({ action: 'allow', matched: false });
    expect(run(['https://x'])).toEqual({ action: 'allow', matched: false });
    expect(run('https://x')).toEqual({ action: 'allow', matched: false });
    expect(run(7)).toEqual({ action: 'allow', matched: false });
    expect(run(null)).toEqual({ action: 'allow', matched: false });
    // An object whose key happens to be "0" is not addressable by a numeric segment either.
    expect(run({ '0': { url: 'https://x' } })).toEqual({ action: 'allow', matched: false });
  });

  it('server accepts a list of globs and matches when any entry does', () => {
    const p = mcp([{ id: 'multi', match: { server: ['corp-*', 'fs'], tool: 't' }, action: 'deny' }]);
    const run = (server: string) => evaluateMcp(p, { server, tool: 't', args: {}, argsBytes: 2 });
    expect(run('corp-notes')).toMatchObject({ ruleId: 'multi', action: 'deny' });
    expect(run('fs')).toMatchObject({ ruleId: 'multi' });
    expect(run('other')).toEqual({ action: 'allow', matched: false });
    expect(run('corp-a/b')).toEqual({ action: 'allow', matched: false });
    expect(p.mcp!.rules[0]!.match.server).toEqual(['corp-*', 'fs']);
    // An omitted `server` still normalizes to the documented default.
    expect(mcp([{ match: { tool: 't' }, action: 'deny' }]).mcp!.rules[0]!.match.server).toEqual(['*']);
  });

  it('server glob uses the "/" delimiter and tool lists match any entry', () => {
    expect(call('read_note', {}, { server: 'corp-notes' })).toMatchObject({ ruleId: 'scoped', action: 'hold' });
    expect(call('list_notes', {}, { server: 'corp-notes' })).toMatchObject({ ruleId: 'scoped' });
    expect(call('read_note', {}, { server: 'other' })).toEqual({ action: 'allow', matched: false });
    expect(call('read_note', {}, { server: 'corp-a/b' })).toEqual({ action: 'allow', matched: false });
    expect(call('read_x/y', {}, { server: 'corp-notes' })).toEqual({ action: 'allow', matched: false });
  });

  it('args: every regex must match; object keys and array indexes; missing path never matches', () => {
    const ok = { url: 'https://x', headers: [{ name: 'X-Trace' }] };
    expect(call('http_post', ok)).toMatchObject({ ruleId: 'url', matched: true });
    expect(call('http_post', { ...ok, url: 'http://x' })).toEqual({ action: 'allow', matched: false });
    expect(call('http_post', { url: 'https://x' })).toEqual({ action: 'allow', matched: false }); // headers missing
    expect(call('http_post', { url: 'https://x', headers: [] })).toEqual({ action: 'allow', matched: false });
    expect(call('http_post', { url: 'https://x', headers: [{ name: 'Y' }] })).toEqual({ action: 'allow', matched: false });
    expect(call('http_post', { url: 'https://x', headers: { '0': { name: 'X-1' } } })).toEqual({ action: 'allow', matched: false }); // numeric segment != object key
    expect(call('http_post', { url: 'https://x', headers: [{ name: 'X-1' }, { name: 'nope' }] })).toMatchObject({ ruleId: 'url' });
    expect(call('http_post', null)).toEqual({ action: 'allow', matched: false });
    expect(call('http_post', 'https://x')).toEqual({ action: 'allow', matched: false });
    expect(call('http_post', [{ url: 'https://x' }])).toEqual({ action: 'allow', matched: false });
    expect(call('http_post', undefined)).toEqual({ action: 'allow', matched: false });
  });

  it('args: numbers and booleans are coerced via String(); null/object/array never match', () => {
    expect(call('num', { limit: 42, flag: true })).toMatchObject({ ruleId: 'num' });
    expect(call('num', { limit: '7', flag: 'true' })).toMatchObject({ ruleId: 'num' });
    expect(call('num', { limit: 420, flag: true })).toEqual({ action: 'allow', matched: false });
    expect(call('num', { limit: 42, flag: false })).toEqual({ action: 'allow', matched: false });
    expect(call('num', { limit: null, flag: true })).toEqual({ action: 'allow', matched: false });
    expect(call('num', { limit: { v: 42 }, flag: true })).toEqual({ action: 'allow', matched: false });
    expect(call('num', { limit: [42], flag: true })).toEqual({ action: 'allow', matched: false });
    expect(coerceScalar(1.5)).toBe('1.5');
    expect(coerceScalar(-0)).toBe('0');
    expect(coerceScalar(false)).toBe('false');
    expect(coerceScalar(null)).toBeUndefined();
    expect(coerceScalar({})).toBeUndefined();
    expect(coerceScalar([])).toBeUndefined();
    expect(coerceScalar(undefined)).toBeUndefined();
  });

  it('args: a string longer than 4 KiB is UNEVALUABLE and denies — it is never truncated and matched', () => {
    // Truncating to the cap silently turned a deny into an allow: the tail was
    // cut off before matching, so a padded value did not match the rule that
    // names it and the call was forwarded. RE2 (the Rego side) does not
    // truncate and would have matched, so the local engine must refuse to
    // answer rather than answer differently — enforcement fails closed.
    expect(REGEX_VALUE_CAP).toBe(4_096);
    const p = mcp([{ id: 'tail', match: { tool: 't', args: { s: 'END$' } }, action: 'deny' }]);
    const run = (s: string) => evaluateMcp(p, { server: 's', tool: 't', args: { s }, argsBytes: 1 });
    expect(run('x'.repeat(REGEX_VALUE_CAP - 3) + 'END')).toMatchObject({ ruleId: 'tail' });
    expect(run('x'.repeat(REGEX_VALUE_CAP - 2) + 'END')).toEqual({
      action: 'deny',
      matched: false,
      reason:
        'policy evaluation error: args value at "s" is longer than the 4096-character regex cap and cannot be matched safely (tail)',
      failClosed: true,
    });
    expect(coerceScalar('a'.repeat(REGEX_VALUE_CAP))).toHaveLength(REGEX_VALUE_CAP);
    expect(coerceScalar('a'.repeat(REGEX_VALUE_CAP + 1))).toBe(VALUE_TOO_LONG);

    // The reviewer's reproduction: 5000 characters of padding in front of the
    // payload used to sail straight through the rule that forbids it.
    const shell = mcp([{ id: 'no-rm', match: { tool: 'run_shell', args: { cmd: 'rm -rf /' } }, action: 'deny' }], { default: 'allow' });
    const call = (cmd: string) => evaluateMcp(shell, { server: 's', tool: 'run_shell', args: { cmd }, argsBytes: cmd.length + 10 });
    expect(call('rm -rf /')).toMatchObject({ action: 'deny', ruleId: 'no-rm', matched: true });
    expect(call('x'.repeat(5_000) + 'rm -rf /')).toMatchObject({ action: 'deny', matched: false, failClosed: true });
    // Everything up to the cap still decides normally, padding or not.
    expect(call('x'.repeat(REGEX_VALUE_CAP - 8) + 'rm -rf /')).toMatchObject({ action: 'deny', ruleId: 'no-rm', matched: true });
  });

  it('args: regexes count runes and read "." the way RE2 does (the Rego twin is pinned in policy-rego.test.ts)', () => {
    // Without the `u` flag V8 counts UTF-16 units where RE2 counts runes, so
    // `^.{1,8}$` against five U+1F600 was an ALLOW here and a DENY in OPA
    // (verified against OPA 1.20.2), and `^..$` against one U+1F600 was the
    // reverse. The local engine now matches in Unicode mode.
    const len = mcp([{ id: 'len', match: { tool: 't', args: { s: '^.{1,8}$' } }, action: 'deny' }], { default: 'allow' });
    const two = mcp([{ id: 'two', match: { tool: 't', args: { s: '^..$' } }, action: 'deny' }], { default: 'allow' });
    const dot = mcp([{ id: 'dot', match: { tool: 't', args: { s: '^.*secret.*$' } }, action: 'deny' }], { default: 'allow' });
    const run = (p: Policy, s: string) => evaluateMcp(p, { server: 's', tool: 't', args: { s }, argsBytes: 8 });
    const grin = '\u{1F600}';
    expect(run(len, grin.repeat(5))).toMatchObject({ ruleId: 'len', action: 'deny' }); // 5 runes, not 10 units
    expect(run(len, grin.repeat(9))).toEqual({ action: 'allow', matched: false });
    expect(run(two, grin)).toEqual({ action: 'allow', matched: false }); // one rune, not two units
    expect(run(two, 'ab')).toMatchObject({ ruleId: 'two' });
    // JavaScript's "." excludes \r; the emitted Rego is compiled to agree.
    expect(run(dot, 'my secret')).toMatchObject({ ruleId: 'dot' });
    expect(run(dot, 'my\rsecret')).toEqual({ action: 'allow', matched: false });
  });

  it('getPath / dotPathSegments', () => {
    expect(dotPathSegments('a.b.0.c.01.-1')).toEqual(['a', 'b', 0, 'c', '01', '-1']);
    const tree = { a: { b: [{ c: 'v' }] }, '01': 'k', n: null, arr: [1, 2] };
    expect(getPath(tree, 'a.b.0.c')).toBe('v');
    expect(getPath(tree, 'a.b.1.c')).toBeUndefined();
    expect(getPath(tree, 'a.b.c')).toBeUndefined();
    expect(getPath(tree, '01')).toBe('k');
    expect(getPath(tree, 'n')).toBeNull();
    expect(getPath(tree, 'n.x')).toBeUndefined();
    expect(getPath(tree, 'arr.1')).toBe(2);
    expect(getPath(tree, 'arr.2')).toBeUndefined();
    expect(getPath(tree, 'arr.length')).toBeUndefined();
    expect(getPath(tree, 'toString')).toBeUndefined(); // inherited props are not own keys
    expect(getPath('str', 'length')).toBeUndefined();
    expect(getPath({ a: 1 }, '__proto__')).toBeUndefined();
  });

  it('getPath: a non-object root never resolves, like Rego object.get on a non-object', () => {
    // Rego's object.get(input.args, [0, "url"], null) is UNDEFINED when
    // input.args is an array, so a numeric first segment must not reach into
    // an array root here either. `params.arguments` is an object per MCP.
    expect(getPath([{ url: 'https://x' }], '0.url')).toBeUndefined();
    expect(getPath([1, 2, 3], '0')).toBeUndefined();
    expect(getPath([], '0')).toBeUndefined();
    for (const root of ['str', 7, true, null, undefined]) {
      expect(getPath(root, 'a'), JSON.stringify(root) ?? 'undefined').toBeUndefined();
      expect(getPath(root, '0'), JSON.stringify(root) ?? 'undefined').toBeUndefined();
    }
    // Nested arrays still work; only the ROOT has to be a plain object.
    expect(getPath({ a: [{ b: 'v' }] }, 'a.0.b')).toBe('v');
  });

  it('max_args_bytes is inclusive', () => {
    expect(call('sized', {}, { argsBytes: 100 })).toMatchObject({ ruleId: 'small' });
    expect(call('sized', {}, { argsBytes: 101 })).toEqual({ action: 'allow', matched: false });
    expect(call('sized', {}, { argsBytes: 0 })).toMatchObject({ ruleId: 'small' });
  });

  it('a policy without an mcp section yields the documented default (allow)', () => {
    const p = egress([]);
    expect(evaluateMcp(p, { server: 's', tool: 't', args: {}, argsBytes: 2 })).toEqual({ action: 'allow', matched: false });
  });

  it('never throws: internal errors become a deny with a reason', () => {
    const broken: Policy = {
      version: 1,
      mcp: {
        default: 'allow',
        rules: [{ id: 'bad', match: { server: ['*'], tool: ['t'], args: { a: '(' } }, action: 'allow' }],
        hold: { ...DEFAULTS.hold },
        boundary: { ...DEFAULTS.boundary },
      },
    };
    const d = evaluateMcp(broken, { server: 's', tool: 't', args: { a: 'x' }, argsBytes: 2 });
    expect(d.action).toBe('deny');
    expect(d.matched).toBe(false);
    expect(d.reason).toMatch(/^policy evaluation error: Invalid regular expression/);
    // The marker that tells this deny apart from one a rule or the section
    // default decided: nothing was decided, the gateway failed closed. The
    // proxy reads it to pick the guidance an agent gets (it must not forbid
    // the retry) instead of parsing the reason string.
    expect(d.failClosed).toBe(true);

    const throwing = {
      get a(): string {
        throw new Error('boom');
      },
    };
    const p = mcp([{ match: { tool: 't', args: { a: '^x' } }, action: 'allow' }]);
    expect(evaluateMcp(p, { server: 's', tool: 't', args: throwing, argsBytes: 2 })).toEqual({
      action: 'deny',
      matched: false,
      reason: 'policy evaluation error: boom',
      failClosed: true,
    });
    // A malformed policy object (rules not iterable) is also caught.
    expect(evaluateMcp({ version: 1, mcp: { rules: null } } as unknown as Policy, { server: 's', tool: 't', args: {}, argsBytes: 2 }).action).toBe('deny');
  });

  it('failClosed marks ONLY the fail-closed deny, never a real decision', () => {
    // A rule deny, a default deny and an allow all omit the field entirely:
    // it is additive and optional, so nothing that reads a Decision today
    // sees a change.
    const denied = mcp([{ id: 'no-exfil', match: { tool: 'http_post' }, action: 'deny', reason: 'nope' }]);
    expect(evaluateMcp(denied, { server: 's', tool: 'http_post', args: {}, argsBytes: 2 }).failClosed).toBeUndefined();
    expect(evaluateMcp(denied, { server: 's', tool: 'other', args: {}, argsBytes: 2 }).failClosed).toBeUndefined();
    expect(evaluateMcp(mcp([], { default: 'deny' }), { server: 's', tool: 't', args: {}, argsBytes: 2 }).failClosed).toBeUndefined();
    expect('failClosed' in evaluateMcp(denied, { server: 's', tool: 'http_post', args: {}, argsBytes: 2 })).toBe(false);
  });
});

/* ------------------------- args regex ReDoS guard ------------------------- */

describe('evaluateMcp: args regexes run under a hard deadline', () => {
  // The validator refuses these shapes (see "repeated groups that are
  // exponential under V8"), so every policy here is hand-built: what is under
  // test is the runtime guarantee for a pattern that got in anyway — an older
  // policy, a hand-edited one, or a shape the structural check cannot see.
  function handBuilt(pattern: string, id = 'evil'): Policy {
    return {
      version: 1,
      mcp: {
        default: 'allow',
        rules: [{ id, match: { server: ['*'], tool: ['t'], args: { s: pattern } }, action: 'deny' }],
        hold: { ...DEFAULTS.hold },
        boundary: { ...DEFAULTS.boundary },
      },
    };
  }
  const run = (policy: Policy, value: string) =>
    evaluateMcp(policy, { server: 's', tool: 't', args: { s: value }, argsBytes: value.length + 8 });
  /** ~14 s in V8 at 29 characters, minutes at 32; instant under RE2. */
  const CATASTROPHIC = '^(a+)+$';
  const catastrophicValue = 'a'.repeat(32) + '!';

  afterEach(() => resetRegexGuard());

  it('denies (fail-closed) instead of freezing the thread, naming the rule, and keeps the deadline', () => {
    expect(REGEX_DEADLINE_MS).toBe(25);
    expect(REGEX_STARTUP_MS).toBe(1_000);
    const policy = handBuilt(CATASTROPHIC, 'exfil-guard');
    const t0 = Date.now();
    const decision = run(policy, catastrophicValue);
    const elapsed = Date.now() - t0;
    expect(decision).toEqual({
      action: 'deny',
      matched: false,
      reason: 'policy evaluation error: regex timed out (exfil-guard)',
      // An unevaluable regex is the gateway failing closed, not a decision.
      failClosed: true,
    });
    // Without the guard this call alone is minutes long.
    expect(elapsed).toBeLessThan(5_000);
  });

  it('poisons the pattern: later calls deny immediately and the diagnostic fires once', () => {
    const seen: string[] = [];
    configureRegexGuard({ deadlineMs: 40, onDiag: (m) => seen.push(m) });
    const policy = handBuilt(CATASTROPHIC);
    expect(run(policy, catastrophicValue).action).toBe('deny');
    expect(regexGuardState().poisoned).toBe(1);

    const t0 = Date.now();
    for (let i = 0; i < 5; i++) {
      expect(run(policy, catastrophicValue + i).reason).toBe('policy evaluation error: regex timed out (evil)');
    }
    expect(Date.now() - t0).toBeLessThan(200); // no further 40 ms stalls: the pattern is off
    expect(seen.filter((m) => m.includes('timed out'))).toHaveLength(1);
    expect(seen[0]).toContain(JSON.stringify(CATASTROPHIC));

    // A different pattern still evaluates normally: the worker is recreated.
    const fine = handBuilt('^https://', 'url');
    expect(run(fine, 'https://x')).toMatchObject({ action: 'deny', ruleId: 'url', matched: true });
    expect(run(fine, 'http://x')).toEqual({ action: 'allow', matched: false });
    expect(regexGuardState().worker).toBe(true);
  });

  it('costs a fraction of a millisecond per evaluation once warm', () => {
    expect(warmRegexGuard()).toBe(true);
    const policy = handBuilt('^https://', 'url');
    const rounds = 200;
    const t0 = performance.now();
    for (let i = 0; i < rounds; i++) run(policy, `https://example.com/${i}`);
    const perCall = (performance.now() - t0) / rounds;
    // Measured ~0.06 ms; the bound is loose enough for a loaded CI box but
    // still fails loudly if an evaluation ever becomes millisecond-scale.
    expect(perCall).toBeLessThan(2);
    expect(regexGuardState()).toMatchObject({ worker: true, degraded: false, poisoned: 0 });
  });

  it('arms the backoff when the worker dies on its own, instead of building one per evaluation', async () => {
    // The `error`/`exit` handlers cleared the slot without calling
    // `degrade()`, so `retryAt` stayed in the past and every later
    // evaluation constructed another OS thread — 50 in 25 s, where a healthy
    // backoff expects two. The real worker never dies on its own, which is
    // why this went untested; one that signals ready and then exits
    // reproduces it in a second.
    const seen: string[] = [];
    const dying = [
      "'use strict';",
      "const { workerData } = require('node:worker_threads');",
      'const ctrl = new Int32Array(workerData.sab);',
      'Atomics.store(ctrl, 0, 1);',
      'Atomics.notify(ctrl, 0);',
      'setTimeout(() => process.exit(0), 10);',
    ].join('\n');
    configureRegexGuard({ workerSource: dying, retryMs: 60_000, onDiag: (m) => seen.push(m) });

    expect(warmRegexGuard()).toBe(true); // it hand-shakes fine
    await new Promise((r) => setTimeout(r, 150)); // and then it is gone

    expect(regexGuardState()).toMatchObject({ worker: false, degraded: true, retrying: false });
    expect(seen.filter((m) => m.includes('exited without being asked to'))).toHaveLength(1);

    // Every later evaluation takes the in-thread path for the length of the
    // backoff. No new worker, no new thread, and one diagnostic in total.
    const policy = handBuilt('^https://', 'url');
    for (let i = 0; i < 20; i++) {
      expect(run(policy, `https://example.com/${i}`)).toMatchObject({ action: 'deny', ruleId: 'url' });
    }
    expect(regexGuardState()).toMatchObject({ worker: false, degraded: true, retrying: false });
    expect(seen.filter((m) => m.includes('worker unavailable'))).toHaveLength(1);
  });

  it('falls back to in-thread matching when the worker cannot start, but only for provably linear patterns', () => {
    const seen: string[] = [];
    configureRegexGuard({ startupMs: 0, onDiag: (m) => seen.push(m) }); // no worker can hand-shake in 0 ms
    const fine = handBuilt('^https://', 'url');
    expect(run(fine, 'https://x')).toMatchObject({ action: 'deny', ruleId: 'url' });
    expect(run(fine, 'http://x')).toEqual({ action: 'allow', matched: false });
    expect(regexGuardState()).toMatchObject({ worker: false, degraded: true });
    expect(seen.filter((m) => m.includes('worker unavailable'))).toHaveLength(1);

    // The shapes the structural check knows are exponential are refused
    // outright rather than run on this thread.
    const decision = run(handBuilt(CATASTROPHIC, 'exfil-guard'), catastrophicValue);
    expect(decision.action).toBe('deny');
    expect(decision.reason).toBe(
      'policy evaluation error: regex could not be evaluated safely (guard worker unavailable) (exfil-guard)',
    );
    expect(warmRegexGuard()).toBe(false);
  });

  it('with no worker, a pattern that cannot be PROVED linear denies at once: never allow, never a stall', () => {
    // The reviewer's reproduction, with worker_threads out of reach (Node's
    // own --experimental-permission without --allow-worker produces exactly
    // this): `^((a+))+$` slipped past the old blacklist gate, ran in-thread
    // for 40 s with every other request stuck behind it, and was then
    // ALLOWED. Enforcement may not be turned fail-open by the absence of a
    // worker thread, so an unprovable pattern is refused instead.
    const seen: string[] = [];
    configureRegexGuard({ startupMs: 0, onDiag: (m) => seen.push(m) });
    const wrapped = handBuilt('^((a+))+$', 'exfil-guard');
    const t0 = Date.now();
    const decision = run(wrapped, 'a'.repeat(32) + '!');
    const elapsed = Date.now() - t0;
    expect(decision).toEqual({
      action: 'deny',
      matched: false,
      reason: 'policy evaluation error: regex could not be evaluated safely (guard worker unavailable) (exfil-guard)',
      failClosed: true,
    });
    expect(elapsed).toBeLessThan(1_000); // 40 s before the fix, at 30 characters
    expect(regexGuardState()).toMatchObject({ worker: false, degraded: true });
    expect(seen.filter((m) => m.includes('cannot be proved bounded'))).toHaveLength(1);

    // A shape the VALIDATOR accepts is still refused here when it cannot be
    // proved bounded: no worker means no way to abandon a runaway match.
    expect(checkCatastrophicShape('([a-z0-9-]+\\.)*')).toBeUndefined();
    expect(run(handBuilt('([a-z0-9-]+\\.)*', 'hostname'), 'a-b-c.'.repeat(40) + '!')).toMatchObject({
      action: 'deny',
      failClosed: true,
      reason: 'policy evaluation error: regex could not be evaluated safely (guard worker unavailable) (hostname)',
    });
    // ... while a provably linear one is still evaluated, both ways.
    const fine = handBuilt('^https://', 'url');
    expect(run(fine, 'https://x')).toMatchObject({ action: 'deny', ruleId: 'url', matched: true });
    expect(run(fine, 'http://x')).toEqual({ action: 'allow', matched: false });
  });

  it('with no worker, a quadratic pattern at the value cap is refused BEFORE it runs', () => {
    // This used to be where `^.*x.*y$` on 4 KiB ran uninterruptibly and was
    // only caught afterwards, by the deadline, having already blocked every
    // concurrent call for as long as it took. The cost is knowable up front
    // — two repeated atoms over n characters is n^2 — so the fallback path
    // now answers from the cost rather than from the stopwatch.
    configureRegexGuard({ startupMs: 0 });
    const slow = handBuilt('^.*x.*y$', 'slow');
    expect(checkProvablyLinear('^.*x.*y$')).toBeUndefined(); // the SHAPE is fine
    expect(run(slow, 'x'.repeat(4_000))).toMatchObject({
      action: 'deny',
      failClosed: true,
      reason: 'policy evaluation error: regex could not be evaluated safely (guard worker unavailable) (slow)',
    });
    expect(regexGuardState().poisoned).toBe(0); // nothing ran, so nothing to poison
    // An argument of ordinary size still evaluates: this is a budget on the
    // value, not a ban on the pattern.
    expect(run(slow, 'x'.repeat(100))).toEqual({ action: 'allow', matched: false });
  });

  it('an in-thread match that still overruns the deadline poisons its pattern', () => {
    // The budget above bounds cost that grows with the value; it cannot
    // bound absolute time, because the per-step constant moves with the
    // machine. One repeated atom over a big enough value is linear, passes
    // every gate, and still takes 5 ms. So the deadline check after the
    // match stays, and this is its guarantee: an over-budget match can cost
    // the proxy once and never twice — the answer is thrown away (a
    // fail-closed deny, never an allow) and the pattern is off for the rest
    // of the process.
    configureRegexGuard({ startupMs: 0, deadlineMs: 1 });
    const huge = 'a'.repeat(4_000_000);
    expect(checkProvablyLinear('^.*x$', huge.length)).toBeUndefined(); // cleared, however long
    expect(() => matchBounded('^.*x$', huge)).toThrow(/timed out/);
    expect(regexGuardState().poisoned).toBe(1);
    const t0 = Date.now();
    expect(() => matchBounded('^.*x$', huge)).toThrow(/timed out/);
    expect(Date.now() - t0).toBeLessThan(50); // poisoned: no second over-budget match
  });

  it('the degradation is NOT permanent: one slow handshake does not disable the bounded path for the process', () => {
    // `degrade()` used to latch for the lifetime of the process, so a single
    // slow startup left every args rule on the in-thread path (and every
    // unprovable pattern denied) for good. It is retried now, and a retry
    // never blocks a call: the worker is adopted by a later evaluation.
    expect(REGEX_RETRY_MS).toBe(30_000);
    const sleep = (ms: number): void => {
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
    };
    configureRegexGuard({ startupMs: 0 }); // nothing can hand-shake in 0 ms
    const fine = handBuilt('^https://', 'url');
    expect(run(fine, 'https://x').action).toBe('deny');
    expect(regexGuardState()).toMatchObject({ worker: false, degraded: true });
    const unprovable = handBuilt('^([a-z0-9-]+\\.)*$', 'hostname'); // fine for the validator, unprovable without a worker
    expect(run(unprovable, 'x.').failClosed).toBe(true);

    configureRegexGuard({ startupMs: 5_000, retryMs: 0 }); // retry on the next call
    const deadline = Date.now() + 20_000;
    while (Date.now() < deadline && !regexGuardState().worker) {
      const t0 = Date.now();
      run(fine, 'https://x');
      expect(Date.now() - t0).toBeLessThan(1_000); // a retry never blocks the caller
      sleep(5);
    }
    expect(regexGuardState()).toMatchObject({ worker: true, degraded: false, retrying: false });
    // With the worker back, the pattern that was denied is evaluated again.
    expect(run(unprovable, 'x.')).toMatchObject({ action: 'deny', ruleId: 'hostname', matched: true });
    expect(run(unprovable, '!')).toEqual({ action: 'allow', matched: false });
  }, 30_000);

  it('never keeps the host process alive: a script that evaluates an args rule exits on its own', () => {
    const dir = mkdtempSync(join(tmpdir(), 'mcp-recorder-guard-'));
    try {
      const script = join(dir, 'evaluate.ts');
      const barrel = pathToFileURL(join(ROOT, 'src', 'policy', 'index.ts')).href;
      writeFileSync(
        script,
        [
          `import { evaluateMcp, validatePolicyObject } from ${JSON.stringify(barrel)};`,
          "const r = validatePolicyObject({ version: 1, mcp: { rules: [{ id: 'u', match: { tool: 't', args: { s: '^x' } }, action: 'deny' }] } });",
          "if (!r.ok) throw new Error('policy did not validate');",
          "const d = evaluateMcp(r.policy, { server: 's', tool: 't', args: { s: 'xyz' }, argsBytes: 9 });",
          'console.log(JSON.stringify(d));',
        ].join('\n'),
        'utf8',
      );
      const res = spawnTsxSync([script], { cwd: ROOT, encoding: 'utf8', timeout: 20_000 });
      expect(res.signal, `the process had to be killed: ${res.stderr}`).toBeNull();
      expect(res.status, res.stderr).toBe(0);
      expect(JSON.parse(res.stdout.trim())).toMatchObject({ action: 'deny', ruleId: 'u', matched: true });
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }, 40_000);
});

describe('evaluateEgress', () => {
  const policy = egress(
    [
      { id: 'gh', match: { host: ['api.github.com', '*.githubusercontent.com'], methods: ['GET', 'HEAD'] }, action: 'allow' },
      { id: 'npm', match: { host: 'registry.npmjs.org', methods: ['PUT'], path: '/-/**', max_body_bytes: 4096 }, action: 'hold', reason: 'publish' },
      { id: 'tele', match: { host: '*.telemetry.*', path: ['/v1/*', '/v2/**'] }, action: 'deny' },
    ],
    { default: 'deny' },
  );
  const req = (host: string, method: string, path = '/', bodyBytes = 0) => evaluateEgress(policy, { host, method, path, bodyBytes });

  it('host globs use the "." delimiter and lists match any entry', () => {
    expect(req('api.github.com', 'GET')).toMatchObject({ ruleId: 'gh', ruleIndex: 0, action: 'allow', matched: true });
    expect(req('raw.githubusercontent.com', 'HEAD', '/a/b')).toMatchObject({ ruleId: 'gh' });
    expect(req('a.b.githubusercontent.com', 'GET')).toEqual({ action: 'deny', matched: false });
    expect(req('githubusercontent.com', 'GET')).toEqual({ action: 'deny', matched: false });
  });

  it('methods are exact upper-case matches; absent methods match any', () => {
    expect(req('api.github.com', 'POST')).toEqual({ action: 'deny', matched: false });
    expect(req('api.github.com', 'get')).toEqual({ action: 'deny', matched: false });
    expect(req('x.telemetry.io', 'PATCH', '/v1/a')).toMatchObject({ ruleId: 'tele', action: 'deny', matched: true });
  });

  it('path globs default to "/**" and use the "/" delimiter', () => {
    expect(req('x.telemetry.io', 'GET', '/v1/a')).toMatchObject({ ruleId: 'tele' });
    expect(req('x.telemetry.io', 'GET', '/v1/a/b')).toEqual({ action: 'deny', matched: false });
    expect(req('x.telemetry.io', 'GET', '/v2/a/b')).toMatchObject({ ruleId: 'tele' });
    expect(req('registry.npmjs.org', 'PUT', '/-/pkg/x')).toMatchObject({ ruleId: 'npm', reason: 'publish' });
    expect(req('registry.npmjs.org', 'PUT', '/pkg')).toEqual({ action: 'deny', matched: false });
  });

  it('max_body_bytes is inclusive', () => {
    expect(req('registry.npmjs.org', 'PUT', '/-/x', 4096)).toMatchObject({ ruleId: 'npm' });
    expect(req('registry.npmjs.org', 'PUT', '/-/x', 4097)).toEqual({ action: 'deny', matched: false });
  });

  it('a policy without egress yields the documented default (deny); never throws', () => {
    expect(evaluateEgress(mcp([]), { host: 'h', method: 'GET', path: '/', bodyBytes: 0 })).toEqual({ action: 'deny', matched: false });
    const d = evaluateEgress({ version: 1, egress: { rules: null } } as unknown as Policy, { host: 'h', method: 'GET', path: '/', bodyBytes: 0 });
    expect(d.action).toBe('deny');
    expect(d.reason).toMatch(/^policy evaluation error: /);
    expect(d.failClosed).toBe(true);
    // The documented default deny is a decision, not a fail-closed refusal.
    expect(evaluateEgress(mcp([]), { host: 'h', method: 'GET', path: '/', bodyBytes: 0 }).failClosed).toBeUndefined();
  });
});

/* ---------------- patterns RE2 cannot load (compile-direction) -------------
 * A pattern V8 accepts and RE2 does not compiles into the bundle, passes
 * `opa check --strict`, and then ERRORS when `regex.match` runs. An erroring
 * builtin is `undefined` in Rego, so the rule leaves the decision silently:
 * a deny rule the control plane simply does not have. Both shapes are
 * refused where the author can see why.
 */
describe('checkRe2Subset: shapes that would break RE2 at evaluation time', () => {
  it('rejects a repeat count above RE2 max (1000), keeping 1000 itself', () => {
    expect(checkRe2Subset('^a{1000}$')).toBeUndefined();
    expect(checkRe2Subset('^a{1000,}$')).toBeUndefined();
    expect(checkRe2Subset('^a{1001}$')).toMatch(/above RE2's limit of 1000/);
    expect(checkRe2Subset('^a{2,1001}$')).toMatch(/above RE2's limit of 1000/);
    expect(checkRe2Subset('^a{1001,}$')).toMatch(/above RE2's limit of 1000/);
    // A literal "{" is not a quantifier and stays allowed in both engines.
    expect(checkRe2Subset('[{]{2}')).toBeUndefined();
    expect(checkRe2Subset('a{,3}')).toBeUndefined();
    expect(checkRe2Subset('^\\d{1,3}\\.\\d{1,3}$')).toBeUndefined();
  });

  it('rejects nested repeats whose PRODUCT is above 1000, which is Go’s real rule', () => {
    // The per-count check was only the top level of Go's test.
    // `repeatIsValid` starts from 1000 and integer-divides the budget by
    // each enclosing repeat, so `(?:a{32}x){32}` — 1024 copies of `a`, every
    // count of it well under 1000 — fails to load with the same "invalid
    // repeat count" error, and the rule leaves the OPA decision silently.
    // Measured against the pinned OPA: the boundary is exact.
    expect(checkRe2Subset('^(?:a{31}x){32}$')).toBeUndefined(); // 992
    expect(checkRe2Subset('^(?:a{32}x){32}$')).toMatch(/nested repeat counts multiply/); // 1024
    expect(checkRe2Subset('^(?:a{2}x){500}$')).toBeUndefined();
    expect(checkRe2Subset('^(?:a{2}x){501}$')).toMatch(/nested repeat counts multiply/);
    expect(checkRe2Subset('^(?:a{125}x){8}$')).toBeUndefined();
    expect(checkRe2Subset('^(?:a{125}x){9}$')).toMatch(/nested repeat counts multiply/);
    // Three levels divide twice, exactly as Go does. (Its sibling at {10} is
    // 1000 exactly and clears the budget, but a doubly-nested repeated group
    // is rejected by the catastrophic-shape rule before RE2 ever sees it, so
    // only the budget direction is asserted here.)
    expect(checkRe2Subset('^(?:(?:a{10}x){10}y){11}z$')).toMatch(/nested repeat counts multiply/);
    // An unbounded inner repeat is charged its MINIMUM, which is what Go
    // falls back to when Max is -1.
    expect(checkRe2Subset('^(?:a{2,}x){400}$')).toBeUndefined();
    expect(checkRe2Subset('^(?:a{2,}x){501}$')).toMatch(/nested repeat counts multiply/);
  });

  it('charges the budget to `{n,m}` alone, and to the right nesting', () => {
    // `*`, `+` and `?` are different operators in Go: they do not multiply.
    expect(checkRe2Subset('^(?:a{1000}x)*$')).toBeUndefined();
    expect(checkRe2Subset('^(?:a{1000}x)+$')).toBeUndefined();
    expect(checkRe2Subset('^(?:a{1000}x)?$')).toBeUndefined();
    // Siblings are not nested, so they add rather than multiply.
    expect(checkRe2Subset('^a{1000}b{1000}$')).toBeUndefined();
    expect(checkRe2Subset('^(?:a{1000})(?:b{1000})$')).toBeUndefined();
    // `{0}` has no copies to count, so Go stops descending there.
    expect(checkRe2Subset('^(?:a{1000}x){0}$')).toBeUndefined();
    // A `{` that is not a quantifier, or one inside a class, is neither.
    expect(checkRe2Subset('^(?:[a{1001}]x){2}$')).toBeUndefined();
    expect(checkRe2Subset('^(?:\\{{4}x){250}$')).toBeUndefined();
    expect(checkRe2Subset('^(?:\\{{4}x){251}$')).toMatch(/nested repeat counts multiply/);
  });

  it('rejects a capture-group name RE2 cannot parse, and a duplicate name', () => {
    expect(checkRe2Subset('^(?<ok_1>secret)$')).toBeUndefined();
    expect(checkRe2Subset('^(?<café>secret)$')).toMatch(/not valid in RE2/);
    expect(checkRe2Subset('^(?<$x>secret)$')).toMatch(/not valid in RE2/);
    expect(checkRe2Subset('^(?<x>a)|(?<x>b)$')).toMatch(/used twice/);
  });
});

/* ------------- the shapes the ReDoS checks still let through --------------
 * `policy validate` is the only thing standing between an author's typo and
 * a rule that one client message can brick: a pattern that times out at run
 * time is poisoned for the life of the process, so every later call on that
 * rule denies. These three shapes validated clean and were exponential.
 */
describe('checkCatastrophicShape: a repeated group ending in an ambiguous alternation', () => {
  it.each([
    ['identical branches', '^(?:a(?:b|b))+$'],
    ['a class and the literal it contains', '^(?:a(?:[b]|b))+$'],
    ['one branch a prefix of the other', '^(?:a(?:bc|b))+$'],
    ['wrapped one level deeper', '^(?:x(?:a(?:b|b)))+$'],
  ])('%s is rejected', (_label, pattern) => {
    expect(checkCatastrophicShape(pattern)).toMatch(/alternation whose branches can match the same text/);
    expect(checkRe2Subset(pattern)).toBeDefined();
  });

  it.each([
    ['disjoint branches stay allowed', '^(?:a(?:b|c))+$'],
    ['the documented good example', '^([a-z0-9-]+\\.)*$'],
    ['a dotted-quad', '^(\\d{1,3}\\.){3}\\d{1,3}$'],
  ])('%s', (_label, pattern) => {
    expect(checkCatastrophicShape(pattern)).toBeUndefined();
    expect(checkRe2Subset(pattern)).toBeUndefined();
  });

  it('measures the difference: the rejected shape backtracks, the allowed one does not', () => {
    const bad = /^(?:a(?:b|b))+$/;
    const started = performance.now();
    bad.test('ab'.repeat(24) + 'x');
    const badMs = performance.now() - started;
    const good = /^(?:a(?:b|c))+$/;
    const t2 = performance.now();
    good.test('ab'.repeat(24) + 'x');
    const goodMs = performance.now() - t2;
    expect(badMs).toBeGreaterThan(goodMs * 10);
  });
});

describe('checkCatastrophicShape: an ambiguous alternation anywhere in the body', () => {
  // The rule above only ever looked at the body's LAST atom, and only tested
  // two branches for overlap when each was a single atom. Both neighbours of
  // the shape it rejected were therefore accepted, and each backtracks
  // exponentially: measured at 55 ms on a 61-character non-match, doubling
  // every three characters, against a 4096-character value cap.
  it.each([
    ['one trailing character after it', '^(?:a(?:b|b)c)+$', 'abc'],
    ['nested one group deeper', '^(?:a(?:x(?:b|b))c)+$', 'axbc'],
    ['branches of two atoms that overlap', '^(?:x(?:a[bc]|a[cd]))+$', 'xac'],
    ['a literal overlapping a class', '^(?:x(?:ab|a[bd]))+$', 'xab'],
    ['both at once', '^(?:x(?:a[bc]|a[cd])y)+$', 'xacy'],
  ])('%s is rejected', (_label, pattern, unit) => {
    expect(checkCatastrophicShape(pattern)).toMatch(/alternation whose branches can match the same text/);
    // And the shape really is exponential: doubling the iterations is far
    // worse than doubling the work.
    const re = new RegExp(pattern);
    const time = (n: number): number => {
      const input = unit.repeat(n) + 'X';
      const t = performance.now();
      re.test(input);
      return performance.now() - t;
    };
    time(6); // warm
    const short = Math.max(time(12), 0.01);
    expect(time(18)).toBeGreaterThan(short * 4);
  });

  it.each([
    ['disjoint branches, mid-body', '^(?:x(?:ab|cd))+$'],
    ['classes that share nothing', '^(?:x(?:a[bc]|a[de]))+$'],
    ['branches that differ in their last atom', '^(?:x(?:abc|abd)y)+$'],
    ['a prefix ambiguity the following atoms pin', '^(?:(?:a|ab)c)+$'],
    ['the documented good example', '^([a-z0-9-]+\\.)*$'],
    ['a named-group date', '^(?<year>[0-9]{4})-(?<m>[0-9]{2})$'],
    ['an alternation with no repeat around it', '^(title|body)$'],
  ])('%s stays accepted', (_label, pattern) => {
    expect(checkCatastrophicShape(pattern)).toBeUndefined();
    expect(checkRe2Subset(pattern)).toBeUndefined();
  });

  it('a prefix ambiguity still counts when the alternation ENDS the body', () => {
    // `(?:(?:a|ab))+` is the classic `(a|ab)+`: the next iteration picks up
    // the difference, so the two ways to split the boundary are real. In the
    // middle of a body the following atoms pin it, which is why the
    // same-span rules alone apply there.
    expect(checkCatastrophicShape('^(?:x(?:a|ab))+$')).toMatch(/alternation whose branches can match the same text/);
    expect(checkCatastrophicShape('^(?:x(?:a|ab)c)+$')).toBeUndefined();
  });
});

describe('overlap: an absence of probes is not proof of disjointness', () => {
  it('rejects adjacent repeats over a band no probe used to reach', () => {
    // Two of the five non-ASCII probes were plain ASCII spaces, so the
    // Latin-1 band had none: `[\xa0-\xa5]*[\xa0-\xa5]*` read as disjoint.
    expect(checkCatastrophicShape('^[\\xa0-\\xa5]*[\\xa0-\\xa5]*[\\xa0-\\xa5]*x$')).toMatch(/adjacent atoms/);
    expect(checkCatastrophicShape('^[\\u4e00-\\u4e10]*[\\u4e00-\\u4e10]*x$')).toMatch(/adjacent atoms/);
    // And the ASCII case it always caught.
    expect(checkCatastrophicShape('^[a-z]*[a-z]*[a-z]*x$')).toMatch(/adjacent atoms/);
  });

  it('still lets genuinely disjoint adjacent repeats through', () => {
    expect(checkCatastrophicShape('^[a-z]+[0-9]*$')).toBeUndefined();
    expect(checkCatastrophicShape('^\\d+[a-z]*$')).toBeUndefined();
  });
});

describe('checkProvablyLinear: an optional group has one more path than it has branches', () => {
  it('counts the skip path, so chained optional alternations are not certified', () => {
    // `(?:a|a)?` is three ways to read the same input, not two. Six chained
    // are 729 paths where the product counted 64 and certified them for the
    // in-thread path, which has no deadline to stop them.
    const six = '^' + '(?:a|a)?'.repeat(6) + '$';
    expect(checkRe2Subset(six)).toBeUndefined(); // it still VALIDATES
    expect(checkProvablyLinear(six)).toMatch(/alternation paths/);
  });

  it('leaves ordinary patterns on the in-thread path', () => {
    expect(checkProvablyLinear('^https?://')).toBeUndefined();
    expect(checkProvablyLinear('^rm -rf .+$')).toBeUndefined();
    expect(checkProvablyLinear('^(?:GET|POST|HEAD)$')).toBeUndefined();
  });

  it('refuses a polynomial pattern on a value big enough to make it cost', () => {
    // Two repeated atoms are linear in SHAPE and quadratic in the value:
    // `valueLength^2` steps, uninterruptibly, on the proxy's only thread.
    // The shape question is unchanged — `policy validate` asks it without a
    // value and still accepts these — but the no-worker fallback asks with
    // one and denies rather than block every concurrent call.
    for (const pattern of ['^.*a.*b$', '^[a-z]*x[a-z]*y$', '^.{1,4096}a.{1,4096}b$']) {
      expect(checkProvablyLinear(pattern)).toBeUndefined();
      expect(checkProvablyLinear(pattern, REGEX_VALUE_CAP)).toMatch(/steps on a/);
      // An ordinary-sized argument still runs: this is a budget, not a ban.
      expect(checkProvablyLinear(pattern, 120)).toBeUndefined();
    }
  });

  it('charges the start-position loop an UNANCHORED pattern runs in', () => {
    // One repeat and no `^` is quadratic, not linear: the engine runs the
    // whole pattern again at every starting offset, and that loop multiplies
    // whatever the repeat costs. Measured on a 4000-character non-match,
    // `a.*b` takes 7 ms against `^a.*b$`'s 0.00 ms, and the budget used to
    // certify both.
    for (const pattern of ['a.*b', '[a-z]+z9', '.*x']) {
      expect(checkProvablyLinear(pattern)).toBeUndefined(); // the SHAPE is fine
      expect(checkProvablyLinear(pattern, REGEX_VALUE_CAP)).toMatch(/no `\^` anchor/);
    }
    // Anchored, the same patterns are certified at any length.
    for (const pattern of ['^a.*b$', '^[a-z]+z9', '^.*x']) {
      expect(checkProvablyLinear(pattern, REGEX_VALUE_CAP)).toBeUndefined();
    }
    // A top-level alternation is NOT anchored by one branch: `^a|b` can
    // start anywhere, so it is charged the loop.
    expect(checkProvablyLinear('^a.*b|c', REGEX_VALUE_CAP)).toMatch(/no `\^` anchor/);
    // And a fixed-width pattern has no repeat for the loop to multiply.
    expect(checkProvablyLinear('(?:foo|foobar)barbaz', REGEX_VALUE_CAP)).toBeUndefined();
  });

  it('never refuses a single repeat, however long the value', () => {
    // One repeated atom is genuinely linear, so the value cannot make it
    // expensive and the budget must not fire on it.
    for (const pattern of ['^rm -rf .+$', '^https?://', '^[a-z]+$', '^.*$']) {
      expect(checkProvablyLinear(pattern, REGEX_VALUE_CAP)).toBeUndefined();
    }
  });
});
