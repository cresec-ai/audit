import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { sha256Hex } from '../src/chain/hash.js';
import {
  DEFAULTS,
  GLOB_CACHE_SIZE,
  POLICY_SCHEMA,
  POLICY_SCHEMA_ID,
  PolicyLoadError,
  PolicyValidationError,
  REGEX_VALUE_CAP,
  SUPPORTED_KEYWORDS,
  autoRuleId,
  checkGlob,
  checkRe2Subset,
  clearGlobCache,
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
  loadPolicyFile,
  normalizePolicy,
  parsePolicyText,
  ruleLabel,
  validateAgainstSchema,
  validatePolicyObject,
} from '../src/policy/index.js';
import type { JsonSchema, Policy, PolicyError, PolicyInput } from '../src/policy/index.js';

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
    for (const notKeyword of ['version', 'mcp', 'egress', 'tool', 'allow', 'hold', 'deny', 'mcpRule']) {
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
      if (s.type === 'object' && s.$ref === undefined && where !== '$.$defs.mcpMatch.properties.args') {
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
  const mcpOf = (d: Doc) => d.mcp as { rules: Doc[]; hold: Doc; boundary: Doc; default: unknown };
  const egressOf = (d: Doc) => d.egress as { rules: Doc[]; default: unknown };
  const rule0 = (d: Doc) => mcpOf(d).rules[0] as { match: Doc; action: unknown; id: unknown; reason: unknown };
  const erule0 = (d: Doc) => egressOf(d).rules[0] as { match: Doc; action: unknown; id: unknown };

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

  it('at least one of mcp / egress is required (friendly message)', () => {
    const errors = errorsFor((d) => {
      delete d.mcp;
      delete d.egress;
    });
    expect(errors).toEqual([{ path: '', keyword: 'anyOf', message: 'at least one of "mcp" or "egress" is required' }]);
    expect(formatPolicyErrors(errors)).toBe('/: at least one of "mcp" or "egress" is required');
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
    expectError(errorsFor((d) => (rule0(d).match.server = '')), '/mcp/rules/0/match/server', 'minLength');
    expectError(errorsFor((d) => (rule0(d).match.server = ['a'])), '/mcp/rules/0/match/server', 'type');
    expectError(errorsFor((d) => (erule0(d).match.host = ['ok', ' '])), '/egress/rules/0/match/host/1', 'glob');
    expectError(errorsFor((d) => (erule0(d).match.path = '/a/}')), '/egress/rules/0/match/path', 'glob', '"}"');
    expectError(errorsFor((d) => (erule0(d).match.path = ['/a', '/]'])), '/egress/rules/0/match/path/1', 'glob', '"]"');
    expect(checkGlob('*')).toBeUndefined();
    expect(checkGlob('a/**/b?')).toBeUndefined();
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
      '[a-z_]+\\s*=\\s*"[^"]*"',
      '(?:foo|bar)+',
      '(?<name>x)',
      '\\x41\\t\\n\\.\\\\',
      '[]a]',
      '[^]a]',
      'a{2,3}',
      '.*',
      '\\bword\\b',
      '',
    ];
    for (const pattern of good) expect(checkRe2Subset(pattern), pattern).toBeUndefined();
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
          { id: 'rule[0]', match: { server: '*', tool: ['a'] }, action: 'allow' },
          { id: 'named', match: { server: '*', tool: ['b', 'c'] }, action: 'hold' },
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

  it('produces anchored, flag-less, escaped regexes', () => {
    expect(globToRegExp('a.*/**?', '/').source).toBe('^a\\.[^\\/]*\\/[\\s\\S]*[^\\/]$');
    expect(globToRegExp('*.x', '.').source).toBe('^[^\\.]*\\.x$');
    expect(globToRegExp('a', '/').flags).toBe('');
    expect(globToRegExp('$^|[]{}\\', '/').test('$^|[]{}\\')).toBe(true);
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

  it('args: string values are truncated to 64 KiB before matching', () => {
    const p = mcp([{ id: 'tail', match: { tool: 't', args: { s: 'END$' } }, action: 'deny' }]);
    const run = (s: string) => evaluateMcp(p, { server: 's', tool: 't', args: { s }, argsBytes: 1 });
    expect(run('x'.repeat(REGEX_VALUE_CAP - 3) + 'END')).toMatchObject({ ruleId: 'tail' });
    expect(run('x'.repeat(REGEX_VALUE_CAP - 2) + 'END')).toEqual({ action: 'allow', matched: false });
    expect(coerceScalar('a'.repeat(REGEX_VALUE_CAP + 10))).toHaveLength(REGEX_VALUE_CAP);
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
        rules: [{ id: 'bad', match: { server: '*', tool: ['t'], args: { a: '(' } }, action: 'allow' }],
        hold: { ...DEFAULTS.hold },
        boundary: { ...DEFAULTS.boundary },
      },
    };
    const d = evaluateMcp(broken, { server: 's', tool: 't', args: { a: 'x' }, argsBytes: 2 });
    expect(d.action).toBe('deny');
    expect(d.matched).toBe(false);
    expect(d.reason).toMatch(/^policy evaluation error: Invalid regular expression/);

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
    });
    // A malformed policy object (rules not iterable) is also caught.
    expect(evaluateMcp({ version: 1, mcp: { rules: null } } as unknown as Policy, { server: 's', tool: 't', args: {}, argsBytes: 2 }).action).toBe('deny');
  });
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
  });
});
