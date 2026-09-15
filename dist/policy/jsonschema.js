/**
 * A tiny, dependency-free JSON Schema (draft 2020-12) validator.
 *
 * It implements EXACTLY the keyword subset used by `docs/policy-schema.json`
 * (see `SUPPORTED_KEYWORDS`); any other keyword makes `validateAgainstSchema`
 * throw rather than silently pass, and `collectKeywords()` lets a test pin the
 * shipped schema to that subset. Errors carry an RFC 6901 JSON pointer to the
 * offending value ("" for the root) so callers can print `/mcp/rules/1/...`.
 *
 * Deliberately not a general-purpose validator: no `$ref` beyond
 * `#/$defs/<name>`, no `additionalProperties` schemas (boolean `false` only),
 * no `patternProperties`, no format/annotation semantics beyond ignoring the
 * documentary keywords listed in `ANNOTATION_KEYWORDS`.
 */
/** Keywords that validate; every entry is implemented below. */
export const VALIDATION_KEYWORDS = [
    'type',
    'enum',
    'const',
    'properties',
    'required',
    'additionalProperties',
    'items',
    'minItems',
    'maxItems',
    'minimum',
    'maximum',
    'pattern',
    'minLength',
    'maxLength',
    'anyOf',
    'oneOf',
    '$ref',
];
/** Documentary keywords that are accepted and ignored. */
export const ANNOTATION_KEYWORDS = ['$schema', '$id', '$defs', 'title', 'description'];
export const SUPPORTED_KEYWORDS = new Set([
    ...VALIDATION_KEYWORDS,
    ...ANNOTATION_KEYWORDS,
]);
function isPlainObject(v) {
    return typeof v === 'object' && v !== null && !Array.isArray(v);
}
function isSchema(v) {
    return isPlainObject(v);
}
/** RFC 6901 token escaping. */
export function escapePointerToken(token) {
    return token.replace(/~/g, '~0').replace(/\//g, '~1');
}
function child(path, token) {
    return `${path}/${typeof token === 'number' ? String(token) : escapePointerToken(token)}`;
}
/** Human-readable JSON type of a value ("integer" is reported as "number"). */
export function typeOf(value) {
    if (value === null)
        return 'null';
    if (Array.isArray(value))
        return 'array';
    const t = typeof value;
    if (t === 'string' || t === 'number' || t === 'boolean' || t === 'object')
        return t;
    // undefined / function / symbol / bigint are not JSON; report them as their typeof
    return t;
}
function matchesType(value, type) {
    switch (type) {
        case 'integer':
            return typeof value === 'number' && Number.isInteger(value);
        case 'number':
            return typeof value === 'number' && Number.isFinite(value);
        default:
            return typeOf(value) === type;
    }
}
/** Structural (JSON) equality for `const` / `enum`. */
export function jsonEqual(a, b) {
    if (a === b)
        return true;
    if (Array.isArray(a)) {
        return Array.isArray(b) && a.length === b.length && a.every((x, i) => jsonEqual(x, b[i]));
    }
    if (isPlainObject(a)) {
        if (!isPlainObject(b))
            return false;
        const ka = Object.keys(a);
        const kb = Object.keys(b);
        return ka.length === kb.length && ka.every((k) => k in b && jsonEqual(a[k], b[k]));
    }
    return false;
}
/**
 * Walk a schema and return every keyword it uses, at any depth. Keys under
 * `properties` / `$defs` are property names, not keywords, and are skipped;
 * their values are schemas and are walked.
 */
export function collectKeywords(schema) {
    const out = new Set();
    const walk = (node) => {
        if (!isSchema(node))
            return;
        for (const [key, value] of Object.entries(node)) {
            out.add(key);
            switch (key) {
                case 'properties':
                case '$defs':
                    if (isPlainObject(value))
                        for (const sub of Object.values(value))
                            walk(sub);
                    break;
                case 'items':
                    walk(value);
                    break;
                case 'anyOf':
                case 'oneOf':
                    if (Array.isArray(value))
                        for (const sub of value)
                            walk(sub);
                    break;
                default:
                    // Scalars / enums / patterns: nothing to recurse into.
                    break;
            }
        }
    };
    walk(schema);
    return out;
}
const REGEX_CACHE = new Map();
function compiledPattern(pattern) {
    let re = REGEX_CACHE.get(pattern);
    if (re === undefined) {
        re = new RegExp(pattern);
        REGEX_CACHE.set(pattern, re);
    }
    return re;
}
function resolveRef(ref, root, at) {
    if (typeof ref !== 'string' || !ref.startsWith('#/$defs/')) {
        throw new TypeError(`unsupported $ref ${JSON.stringify(ref)} at ${at || '/'} (only "#/$defs/<name>" is supported)`);
    }
    const name = ref.slice('#/$defs/'.length);
    const defs = root.$defs;
    const target = isPlainObject(defs) ? defs[name] : undefined;
    if (!isSchema(target))
        throw new TypeError(`unresolvable $ref ${JSON.stringify(ref)} at ${at || '/'}`);
    return target;
}
function describe(value) {
    const s = JSON.stringify(value);
    return s === undefined ? String(value) : s.length > 60 ? s.slice(0, 57) + '...' : s;
}
function branchSummary(errors, basePath) {
    const first = errors[0];
    if (first === undefined)
        return 'ok';
    const rel = first.path.slice(basePath.length);
    return rel.length > 0 ? `${first.message} (at ${rel})` : first.message;
}
function validateNode(schema, value, path, root) {
    const errors = [];
    const fail = (keyword, message) => {
        errors.push({ path, message, keyword });
    };
    for (const keyword of Object.keys(schema)) {
        if (!SUPPORTED_KEYWORDS.has(keyword)) {
            throw new TypeError(`unsupported JSON Schema keyword ${JSON.stringify(keyword)} at ${path || '/'}`);
        }
    }
    if ('$ref' in schema) {
        errors.push(...validateNode(resolveRef(schema.$ref, root, path), value, path, root));
    }
    if ('type' in schema) {
        const types = (Array.isArray(schema.type) ? schema.type : [schema.type]);
        if (!types.some((t) => matchesType(value, t))) {
            fail('type', `expected ${types.join(' or ')}, got ${typeOf(value)}`);
            // Further keywords are type-specific; a type mismatch is the root cause.
            return errors;
        }
    }
    if ('const' in schema && !jsonEqual(value, schema.const)) {
        fail('const', `must be ${describe(schema.const)}`);
    }
    if ('enum' in schema) {
        const allowed = schema.enum;
        if (!allowed.some((v) => jsonEqual(value, v))) {
            fail('enum', `must be one of ${allowed.map(describe).join(', ')}`);
        }
    }
    if (typeof value === 'string') {
        if ('minLength' in schema && [...value].length < schema.minLength) {
            fail('minLength', `must be at least ${schema.minLength} character(s) long`);
        }
        if ('maxLength' in schema && [...value].length > schema.maxLength) {
            fail('maxLength', `must be at most ${schema.maxLength} character(s) long`);
        }
        if ('pattern' in schema && !compiledPattern(schema.pattern).test(value)) {
            fail('pattern', `must match pattern ${JSON.stringify(schema.pattern)}`);
        }
    }
    if (typeof value === 'number') {
        if ('minimum' in schema && value < schema.minimum) {
            fail('minimum', `must be >= ${schema.minimum}`);
        }
        if ('maximum' in schema && value > schema.maximum) {
            fail('maximum', `must be <= ${schema.maximum}`);
        }
    }
    if (Array.isArray(value)) {
        if ('minItems' in schema && value.length < schema.minItems) {
            fail('minItems', `must have at least ${schema.minItems} item(s)`);
        }
        if ('maxItems' in schema && value.length > schema.maxItems) {
            fail('maxItems', `must have at most ${schema.maxItems} item(s)`);
        }
        if ('items' in schema && isSchema(schema.items)) {
            value.forEach((item, i) => errors.push(...validateNode(schema.items, item, child(path, i), root)));
        }
    }
    if (isPlainObject(value)) {
        const props = isPlainObject(schema.properties) ? schema.properties : {};
        if ('required' in schema) {
            for (const key of schema.required) {
                if (!Object.prototype.hasOwnProperty.call(value, key)) {
                    fail('required', `missing required property ${JSON.stringify(key)}`);
                }
            }
        }
        for (const [key, sub] of Object.entries(props)) {
            if (Object.prototype.hasOwnProperty.call(value, key) && isSchema(sub)) {
                errors.push(...validateNode(sub, value[key], child(path, key), root));
            }
        }
        if (schema.additionalProperties === false) {
            for (const key of Object.keys(value)) {
                if (!Object.prototype.hasOwnProperty.call(props, key)) {
                    errors.push({
                        path: child(path, key),
                        message: `unknown property ${JSON.stringify(key)}`,
                        keyword: 'additionalProperties',
                    });
                }
            }
        }
    }
    if ('anyOf' in schema) {
        const branches = schema.anyOf;
        const results = branches.map((b) => validateNode(b, value, path, root));
        if (!results.some((r) => r.length === 0)) {
            const summary = results.map((r, i) => `(${i + 1}) ${branchSummary(r, path)}`).join('; ');
            fail('anyOf', `no alternative matched: ${summary}`);
        }
    }
    if ('oneOf' in schema) {
        const branches = schema.oneOf;
        const results = branches.map((b) => validateNode(b, value, path, root));
        const passing = results.filter((r) => r.length === 0).length;
        if (passing === 0) {
            const summary = results.map((r, i) => `(${i + 1}) ${branchSummary(r, path)}`).join('; ');
            fail('oneOf', `no alternative matched: ${summary}`);
        }
        else if (passing > 1) {
            fail('oneOf', `matches ${passing} alternatives, expected exactly one`);
        }
    }
    return errors;
}
/**
 * Validate `value` against `schema`. Returns every error found (empty array
 * = valid). Throws `TypeError` if the schema uses a keyword outside
 * `SUPPORTED_KEYWORDS` or an unresolvable `$ref`.
 */
export function validateAgainstSchema(schema, value) {
    return validateNode(schema, value, '', schema);
}
//# sourceMappingURL=jsonschema.js.map