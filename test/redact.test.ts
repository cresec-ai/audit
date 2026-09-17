import { describe, expect, it } from 'vitest';
import { canonicalJson, sha256Ref } from '../src/chain/hash.js';
import type { RedactedRef, Scrubbed } from '../src/schema/events.js';
import {
  DEFAULT_POLICY,
  Redactor,
  STRUCTURAL_STRING_MAX_LEN,
  looksSecret,
  scrubArgv,
  scrubToolArguments,
  structuralString,
} from '../src/redact/redactor.js';

/* ------------------------------ fixtures ------------------------------ */

const SECRETS = {
  aws: 'AKIAIOSFODNN7EXAMPLE',
  jwt: 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U',
  openai: 'sk-proj-AbCdEfGhIjKlMnOpQrStUvWx',
  github: 'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456',
  hex64: 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef',
  base64: 'QmFzZTY0U2VjcmV0VmFsdWVCYXNlNjRTZWNyZXRWYWx1ZQ==',
  passwordish: 'password=hunter2',
} as const;

/** Secrets planted deep inside realistic-looking tool-call args. */
function plantedTree(): unknown {
  return {
    name: 'deploy_service',
    config: {
      aws: { accessKeyId: SECRETS.aws, region: 'us-east-1' },
      auth: {
        headers: [{ Authorization: `Bearer ${SECRETS.jwt}` }, { 'X-Token': SECRETS.jwt }],
        nested: { deeper: { apiKey: SECRETS.openai, github: SECRETS.github } },
      },
    },
    artifacts: [SECRETS.hex64, { blob: SECRETS.base64 }],
    connection: `host=db.internal ${SECRETS.passwordish}`,
    notes: SECRETS.passwordish,
  };
}

function isRedactedRef(v: Scrubbed): v is RedactedRef {
  return typeof v === 'object' && v !== null && !Array.isArray(v) && (v as RedactedRef).redacted === true;
}

/* -------------------------- secret containment ------------------------ */

describe('secret containment (both modes)', () => {
  for (const mode of ['allowlist', 'off'] as const) {
    it(`mode=${mode}: no planted secret survives scrub`, () => {
      const redactor = new Redactor({ mode });
      const out = JSON.stringify(redactor.scrub(plantedTree()));
      for (const [label, secret] of Object.entries(SECRETS)) {
        expect(out, `secret "${label}" leaked in mode=${mode}`).not.toContain(secret);
        // also guard against partial leakage of the secret body
        expect(out, `tail of "${label}" leaked in mode=${mode}`).not.toContain(secret.slice(4));
      }
    });
  }

  it('off mode passes harmless strings but still hashes secret shapes', () => {
    const redactor = new Redactor({ mode: 'off' });
    const out = redactor.scrub({ greeting: 'hello world', key: SECRETS.aws }) as {
      greeting: Scrubbed;
      key: Scrubbed;
    };
    expect(out.greeting).toBe('hello world');
    expect(isRedactedRef(out.key)).toBe(true);
  });
});

/* --------------------------- allowlist gates -------------------------- */

describe('allowlist mode gates', () => {
  const redactor = new Redactor();

  it('defaults to allowlist mode', () => {
    expect(redactor.mode).toBe('allowlist');
    expect(DEFAULT_POLICY.mode).toBe('allowlist');
  });

  it('dropped keys (code, status, kind, tool) never pass, regardless of value', () => {
    for (const key of ['code', 'status', 'kind', 'tool']) {
      const out = redactor.scrub({ [key]: 'harmless' }) as Record<string, Scrubbed>;
      expect(isRedactedRef(out[key]!), `expected "${key}" to be redacted`).toBe(true);
    }
  });

  it('allow-listed key passes only when the value matches its structural vocabulary', () => {
    expect(redactor.scrub({ type: 'text' })).toEqual({ type: 'text' });
    expect(redactor.scrub({ type: 'resource_link' })).toEqual({ type: 'resource_link' });
    expect(redactor.scrub({ role: 'assistant' })).toEqual({ role: 'assistant' });
    expect(redactor.scrub({ level: 'warning' })).toEqual({ level: 'warning' });
    expect(redactor.scrub({ mimeType: 'text/plain' })).toEqual({ mimeType: 'text/plain' });
    expect(redactor.scrub({ protocolVersion: '2025-03-26' })).toEqual({
      protocolVersion: '2025-03-26',
    });
    expect(redactor.scrub({ method: 'resources/read' })).toEqual({ method: 'resources/read' });
  });

  it('allow-listed key with a value outside the vocabulary is redacted', () => {
    // 'type' is allow-listed, but 'json' is not an MCP content-block type.
    const out = redactor.scrub({ type: 'json' }) as { type: Scrubbed };
    expect(isRedactedRef(out.type)).toBe(true);
    // 'role' only admits user/assistant.
    const role = redactor.scrub({ role: 'system' }) as { role: Scrubbed };
    expect(isRedactedRef(role.role)).toBe(true);
    // 'method' must be lowercase-slash-shaped.
    const method = redactor.scrub({ method: 'Tools/Call' }) as { method: Scrubbed };
    expect(isRedactedRef(method.method)).toBe(true);
  });

  it('a long value longer than maxAllowedStringLen is redacted even if vocabulary-shaped', () => {
    const long = 'a/' + 'b'.repeat(70); // matches METHOD_RE's shape, but far over 64 chars
    expect(long.length).toBeGreaterThan(64);
    const out = redactor.scrub({ method: long }) as { method: Scrubbed };
    expect(isRedactedRef(out.method)).toBe(true);
    const ref = out.method as RedactedRef;
    expect(ref.ref).toBe(sha256Ref(long));
    expect(ref.len).toBe(long.length);
  });

  it('name passes ONLY at tools[*].name / prompts[*].name in list results', () => {
    expect(redactor.scrub({ tools: [{ name: 'read_file' }] })).toEqual({
      tools: [{ name: 'read_file' }],
    });
    expect(redactor.scrub({ prompts: [{ name: 'summarize' }] })).toEqual({
      prompts: [{ name: 'summarize' }],
    });
    // Bare top-level `name` (the P0 leak shape) is NOT a list result.
    const bare = redactor.scrub({ name: 'read_file' }) as { name: Scrubbed };
    expect(isRedactedRef(bare.name)).toBe(true);
    // Nested one hop too far — tools[*].inputSchema.name — must NOT pass.
    const nested = redactor.scrub({
      tools: [{ name: 'read_file', inputSchema: { name: 'not-the-tool-name' } }],
    }) as { tools: Array<{ name: Scrubbed; inputSchema: { name: Scrubbed } }> };
    expect(nested.tools[0]!.name).toBe('read_file');
    expect(isRedactedRef(nested.tools[0]!.inputSchema.name)).toBe(true);
    // An array keyed something else entirely never grants the exemption.
    const wrongArray = redactor.scrub({ items: [{ name: 'read_file' }] }) as {
      items: Array<{ name: Scrubbed }>;
    };
    expect(isRedactedRef(wrongArray.items[0]!.name)).toBe(true);
  });

  it('top-level string has no key and is always redacted', () => {
    const out = redactor.scrub('hello');
    expect(isRedactedRef(out)).toBe(true);
    expect((out as RedactedRef).ref).toBe(sha256Ref('hello'));
  });

  it('array-element strings have no key and are always redacted', () => {
    const out = redactor.scrub({ tools: ['read_file'] }) as { tools: Scrubbed[] };
    expect(isRedactedRef(out.tools[0]!)).toBe(true);
  });

  it('non-allow-listed key is redacted even when the value looks harmless', () => {
    const out = redactor.scrub({ path: '/etc/passwd' }) as { path: Scrubbed };
    expect(isRedactedRef(out.path)).toBe(true);
    const ref = out.path as RedactedRef;
    expect(ref.ref).toBe(sha256Ref('/etc/passwd'));
    expect(ref.len).toBe('/etc/passwd'.length);
  });

  it('non-structural charset is redacted even at a valid tools[*].name position', () => {
    const out = redactor.scrub({ tools: [{ name: 'why? "quotes" & ampersands' }] }) as {
      tools: Array<{ name: Scrubbed }>;
    };
    expect(isRedactedRef(out.tools[0]!.name)).toBe(true);
  });

  it('secret shape under an allow-listed key is still redacted, position notwithstanding', () => {
    const bare = redactor.scrub({ name: SECRETS.aws }) as { name: Scrubbed };
    expect(isRedactedRef(bare.name)).toBe(true);
    const positioned = redactor.scrub({ tools: [{ name: SECRETS.aws }] }) as {
      tools: Array<{ name: Scrubbed }>;
    };
    expect(isRedactedRef(positioned.tools[0]!.name)).toBe(true);
  });
});

/* ----------------------------- primitives ----------------------------- */

describe('non-string leaves', () => {
  const redactor = new Redactor();

  it('numbers, booleans, null pass through; undefined becomes null', () => {
    expect(redactor.scrub({ n: 1.5, b: false, z: null, u: undefined })).toEqual({
      n: 1.5,
      b: false,
      z: null,
      u: null,
    });
    expect(redactor.scrub(undefined)).toBe(null);
  });

  it('bigint is stringified then treated as a string', () => {
    // Even under an allow-listed key, a bigint's digit-only string form
    // never matches any structural vocabulary (role/type/level/...), so it
    // always hashes — there is no key that lets a bare number through.
    const roleOut = redactor.scrub({ role: 42n }) as { role: Scrubbed };
    expect(isRedactedRef(roleOut.role)).toBe(true);
    expect((roleOut.role as RedactedRef).ref).toBe(sha256Ref('42'));
    expect((roleOut.role as RedactedRef).len).toBe(2);

    const out = redactor.scrub({ count: 123n }) as { count: Scrubbed };
    expect(isRedactedRef(out.count)).toBe(true);
    expect((out.count as RedactedRef).ref).toBe(sha256Ref('123'));
    expect((out.count as RedactedRef).len).toBe(3);
  });

  it('function and symbol become the ref of "[unserializable]"', () => {
    const out = redactor.scrub({ fn: () => 1, sym: Symbol('x') }) as {
      fn: Scrubbed;
      sym: Scrubbed;
    };
    for (const v of [out.fn, out.sym]) {
      expect(isRedactedRef(v)).toBe(true);
      expect((v as RedactedRef).ref).toBe(sha256Ref('[unserializable]'));
      expect((v as RedactedRef).len).toBe('[unserializable]'.length);
    }
  });
});

/* ------------------------------ ref shape ----------------------------- */

describe('refs are deterministic sha256Ref of the exact original', () => {
  it('same input → same ref; ref matches sha256Ref; len correct', () => {
    const redactor = new Redactor();
    const secret = 'top secret value with spaces';
    const a = redactor.scrub(secret) as RedactedRef;
    const b = redactor.scrub(secret) as RedactedRef;
    expect(a).toEqual(b);
    expect(a.ref).toBe(sha256Ref(secret));
    expect(a.ref).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(a.len).toBe(secret.length);
    expect(redactor.hashString(secret)).toBe(sha256Ref(secret));
  });
});

/* --------------------------- pathological input ------------------------ */

describe('depth bombs and cycles never throw, never leak', () => {
  it('40-deep nesting is collapsed without leaking the buried secret', () => {
    const secret = 'buried-deep-secret-value';
    let leaf: unknown = secret;
    for (let i = 0; i < 40; i++) leaf = { a: leaf };
    const redactor = new Redactor();
    let out: Scrubbed;
    expect(() => {
      out = redactor.scrub(leaf);
    }).not.toThrow();
    expect(JSON.stringify(out!)).not.toContain(secret);
  });

  it('circular object yields the ref of "[circular]" and leaks nothing', () => {
    const o: Record<string, unknown> = { n: 1, token: SECRETS.aws };
    o.self = o;
    const redactor = new Redactor();
    let out: Scrubbed;
    expect(() => {
      out = redactor.scrub(o);
    }).not.toThrow();
    const obj = out! as { n: Scrubbed; token: Scrubbed; self: Scrubbed };
    expect(obj.n).toBe(1);
    expect(isRedactedRef(obj.token)).toBe(true);
    expect(isRedactedRef(obj.self)).toBe(true);
    expect((obj.self as RedactedRef).ref).toBe(sha256Ref('[circular]'));
    expect(JSON.stringify(out!)).not.toContain(SECRETS.aws);
  });

  it('shared (non-circular) references are scrubbed normally, not flagged circular', () => {
    const shared = { mimeType: 'text/plain' };
    const redactor = new Redactor();
    const out = redactor.scrub({ a: shared, b: shared }) as { a: Scrubbed; b: Scrubbed };
    expect(out.a).toEqual({ mimeType: 'text/plain' });
    expect(out.b).toEqual({ mimeType: 'text/plain' });
  });
});

/* --------------------------- canonicalJson safety ---------------------- */

describe('scrubbed output is JSON-safe for the chain', () => {
  it('canonicalJson() accepts scrubbed trees from both modes', () => {
    for (const mode of ['allowlist', 'off'] as const) {
      const scrubbed = new Redactor({ mode }).scrub(plantedTree());
      const canon = canonicalJson(scrubbed);
      expect(typeof canon).toBe('string');
      for (const secret of Object.values(SECRETS)) {
        expect(canon).not.toContain(secret);
      }
    }
  });

  it('canonicalJson() accepts scrubbed pathological inputs', () => {
    const o: Record<string, unknown> = { fn: () => 1, big: 9n };
    o.loop = o;
    const scrubbed = new Redactor().scrub(o);
    expect(() => canonicalJson(scrubbed)).not.toThrow();
  });
});

/* ------------------------------ looksSecret ---------------------------- */

describe('looksSecret', () => {
  it('flags every planted secret shape', () => {
    for (const secret of Object.values(SECRETS)) {
      expect(looksSecret(secret), `expected looksSecret to flag ${secret}`).toBe(true);
    }
    expect(looksSecret('-----BEGIN RSA PRIVATE KEY-----')).toBe(true);
    expect(looksSecret('xoxb-1234567890-abcdef')).toBe(true);
    expect(looksSecret('Bearer abcdefghijKLMNOP1234')).toBe(true);
  });

  it('does not flag ordinary strings', () => {
    expect(looksSecret('read_file')).toBe(false);
    expect(looksSecret('/etc/passwd')).toBe(false);
    expect(looksSecret('hello world')).toBe(false);
  });

  it('is immune to /g lastIndex state across calls', () => {
    const sticky = [/secret-[0-9]+/g];
    expect(looksSecret('secret-123', sticky)).toBe(true);
    expect(looksSecret('secret-123', sticky)).toBe(true);
    expect(looksSecret('secret-123', sticky)).toBe(true);
  });
});

/* ------------------------------ key redaction --------------------------- */

describe('object keys are redacted too (P1)', () => {
  const redactor = new Redactor();

  it('an identifier-shaped, non-secret key is kept as-is', () => {
    const out = redactor.scrub({ user_id: 'x' }) as Record<string, Scrubbed>;
    expect(Object.keys(out)).toEqual(['user_id']);
  });

  it('a non-identifier key (email, path, header line) is hashed to sha256:<hex>', () => {
    // Hyphenated identifiers (e.g. plain header NAMES) are allowed by the
    // key-shape regex on purpose — '@', '/', ':' and spaces are not.
    for (const key of ['alice@corp.example.com', '/etc/passwd', 'X-My-Header: value']) {
      const out = redactor.scrub({ [key]: 'v' }) as Record<string, Scrubbed>;
      const outKeys = Object.keys(out);
      expect(outKeys).toHaveLength(1);
      expect(outKeys[0]).toBe(sha256Ref(key));
      expect(outKeys[0]).not.toBe(key);
    }
  });

  it('a secret-shaped key is hashed even though it is a valid identifier', () => {
    // AKIA... has no punctuation, so it WOULD pass the identifier regex —
    // alwaysPatterns must still catch it.
    const out = redactor.scrub({ [SECRETS.aws]: true }) as Record<string, Scrubbed>;
    const outKeys = Object.keys(out);
    expect(outKeys).toEqual([sha256Ref(SECRETS.aws)]);
  });

  it('secret-shaped keys are hashed in "off" mode too', () => {
    const off = new Redactor({ mode: 'off' });
    const out = off.scrub({ [SECRETS.aws]: true }) as Record<string, Scrubbed>;
    expect(Object.keys(out)).toEqual([sha256Ref(SECRETS.aws)]);
  });

  it('a literal "__proto__" key survives as a real own property, not the prototype', () => {
    // Simulate a real wire message: JSON.parse uses CreateDataProperty, so
    // __proto__ lands as a genuine own key (unlike an object literal, where
    // `{__proto__: x}` sets the prototype instead — that is a fixture bug,
    // not a Redactor bug, and is NOT what reaches scrub() from the wire).
    const input = JSON.parse('{"__proto__":{"hidden":"value"}}') as unknown;
    expect(Object.prototype.hasOwnProperty.call(input, '__proto__')).toBe(true);

    const out = redactor.scrub(input) as Record<string, Scrubbed>;
    expect(Object.prototype.hasOwnProperty.call(out, '__proto__')).toBe(true);
    expect(Object.getPrototypeOf(out)).toBeNull();

    // And it survives a JSON round-trip (JSON.parse is always safe here).
    const roundTripped = JSON.parse(JSON.stringify(out)) as Record<string, unknown>;
    expect(Object.prototype.hasOwnProperty.call(roundTripped, '__proto__')).toBe(true);
  });

  it('queryStore-style consumers can find a needle used only as a key', () => {
    // redact.test.ts only asserts the redactor's own output shape; the
    // corresponding blast-radius behavior is covered in query.test.ts.
    const out = redactor.scrub({ 'alice@corp.example.com': { role: 'admin' } }) as Record<
      string,
      Scrubbed
    >;
    expect(Object.keys(out)[0]).toBe(sha256Ref('alice@corp.example.com'));
  });
});

/* ------------------------------ secret_refs ------------------------------ */

describe('secret_refs: tokens embedded inside a larger leaf (P1 blast-radius miss)', () => {
  const redactor = new Redactor();

  it('an embedded AWS key produces a secret_refs entry distinct from the whole-leaf ref', () => {
    const leaf = `AWS_ACCESS_KEY_ID=${SECRETS.aws}\n`;
    const out = redactor.scrub({ body: leaf }) as { body: RedactedRef };
    expect(out.body.redacted).toBe(true);
    expect(out.body.ref).toBe(sha256Ref(leaf)); // whole-leaf ref unchanged
    expect(out.body.secret_refs).toBeDefined();
    expect(out.body.secret_refs).toContain(sha256Ref(SECRETS.aws));
  });

  it('a leaf that IS exactly the secret gets no redundant secret_refs entry', () => {
    const out = redactor.scrub({ key: SECRETS.aws }) as { key: RedactedRef };
    expect(out.key.ref).toBe(sha256Ref(SECRETS.aws));
    // The whole-leaf ref already covers this; no redundant secret_refs.
    expect(out.key.secret_refs).toBeUndefined();
  });

  it('multiple distinct embedded tokens are each captured, de-duplicated and capped', () => {
    const leaf = `here is the key: ${SECRETS.aws} and again: ${SECRETS.aws} and also ${SECRETS.github}`;
    const out = redactor.scrub({ text: leaf }) as { text: RedactedRef };
    expect(out.text.secret_refs).toBeDefined();
    const refs = out.text.secret_refs!;
    expect(refs).toContain(sha256Ref(SECRETS.aws));
    expect(refs).toContain(sha256Ref(SECRETS.github));
    // de-duplicated: the repeated AWS key only appears once.
    expect(refs.filter((r) => r === sha256Ref(SECRETS.aws))).toHaveLength(1);
  });

  it('a plain leaf with nothing secret-shaped inside has no secret_refs', () => {
    const out = redactor.scrub({ path: '/etc/passwd' }) as { path: RedactedRef };
    expect(out.path.secret_refs).toBeUndefined();
  });
});

/* --------------------------- scrubToolArguments -------------------------- */

describe('scrubToolArguments: nothing passes under tool_call.arguments (P0)', () => {
  it('hashes every string leaf regardless of key, in allowlist mode', () => {
    const redactor = new Redactor();
    const out = scrubToolArguments(redactor, {
      name: 'John Smith',
      code: 'cat /etc/shadow',
      status: 'fired for misconduct',
      type: 'text', // even a normally-passing vocabulary value is hashed here
      nested: { role: 'user', mimeType: 'text/plain' },
      list: ['a', 'b'],
    }) as Record<string, unknown>;

    function assertAllStringsRedacted(v: unknown): void {
      if (typeof v === 'string') throw new Error('found a raw string leaf: ' + v);
      if (v === null || typeof v !== 'object') return;
      if ((v as RedactedRef).redacted === true) return;
      for (const child of Array.isArray(v) ? v : Object.values(v as object)) {
        assertAllStringsRedacted(child);
      }
    }
    assertAllStringsRedacted(out);

    const name = out.name as RedactedRef;
    expect(name.redacted).toBe(true);
    expect(name.ref).toBe(sha256Ref('John Smith'));
    const nested = out.nested as { role: RedactedRef; mimeType: RedactedRef };
    expect(nested.role.ref).toBe(sha256Ref('user'));
    expect(nested.mimeType.ref).toBe(sha256Ref('text/plain'));
  });

  it('hashes every string leaf even in "off" mode — arguments are always locked', () => {
    const off = new Redactor({ mode: 'off' });
    const out = scrubToolArguments(off, { greeting: 'hello world' }) as {
      greeting: RedactedRef;
    };
    expect(out.greeting.redacted).toBe(true);
    expect(out.greeting.ref).toBe(sha256Ref('hello world'));
  });

  it('object keys are still hashed under arguments, same as scrub()', () => {
    const redactor = new Redactor();
    const out = scrubToolArguments(redactor, {
      'alice@corp.example.com': { role: 'admin' },
    }) as Record<string, unknown>;
    expect(Object.keys(out)).toEqual([sha256Ref('alice@corp.example.com')]);
  });

  it('a secret embedded in an argument still yields secret_refs', () => {
    const redactor = new Redactor();
    const out = scrubToolArguments(redactor, {
      body: `AWS_ACCESS_KEY_ID=${SECRETS.aws}\n`,
    }) as { body: RedactedRef };
    expect(out.body.secret_refs).toContain(sha256Ref(SECRETS.aws));
  });

  it('numbers and booleans still pass through (only strings are locked down)', () => {
    const redactor = new Redactor();
    const out = scrubToolArguments(redactor, { n: 42, b: true, z: null }) as Record<
      string,
      unknown
    >;
    expect(out).toEqual({ n: 42, b: true, z: null });
  });

  /* --- P1: an argument object shaped like a RedactedRef bypasses lockdown
   * in `--redact off`. `lockdownStrings` trusted the SHAPE of an already-
   * scrubbed subtree (`redacted === true` + a string `ref`) as proof it was
   * already opaque and skipped recursing into it. In `off` mode, `scrub()`
   * leaves non-secret-shaped strings verbatim, so an attacker-controlled
   * `arguments` value containing `{redacted: true, ref: "<anything>"}` was
   * treated as an opaque ref and every sibling/nested string under it — and
   * even the attacker's own bogus `ref` string — was stored in the clear. */
  it('a RedactedRef-shaped argument does not smuggle plaintext past lockdown in "off" mode', () => {
    const off = new Redactor({ mode: 'off' });
    const args = {
      redacted: true,
      ref: 'my plaintext password is hunter2',
      len: 3,
      extra: { nested: 'also plaintext ssn 123-45-6789' },
    };
    const out = JSON.stringify(scrubToolArguments(off, args));
    expect(out).not.toContain('my plaintext password is hunter2');
    expect(out).not.toContain('hunter2');
    expect(out).not.toContain('also plaintext ssn 123-45-6789');
    expect(out).not.toContain('123-45-6789');
  });

  it('a RedactedRef-shaped argument does not smuggle plaintext past lockdown in allowlist mode either', () => {
    const allow = new Redactor({ mode: 'allowlist' });
    const args = {
      query: 'SELECT 1',
      meta: { redacted: true, ref: 'x', payload: 'readable customer note' },
    };
    const out = JSON.stringify(scrubToolArguments(allow, args));
    expect(out).not.toContain('readable customer note');
    expect(out).not.toContain('SELECT 1');
  });

  it('a genuine RedactedRef (real sha256:<hex> ref + numeric len) from the redactor\'s own scrub pass is still treated as opaque, not re-hashed', () => {
    const redactor = new Redactor();
    const out = scrubToolArguments(redactor, { note: 'hello world' }) as {
      note: RedactedRef;
    };
    // scrub() -> RedactedRef{redacted:true, ref:sha256Ref('hello world'), len:11}
    // lockdownStrings must recognize this as already-opaque and pass it
    // through unchanged rather than hashing the ref string itself again.
    expect(out.note).toEqual({ redacted: true, ref: sha256Ref('hello world'), len: 11 });
  });
});

/* ------------------------------- scrubArgv -------------------------------- */

describe('scrubArgv: wrapped command argv leak fix (P1)', () => {
  const redactor = new Redactor();

  it('leaves an ordinary argv untouched', () => {
    const argv = ['npx', '-y', '@modelcontextprotocol/server-filesystem', '/Users/me/projects'];
    const out = scrubArgv(argv, redactor);
    expect(out.command).toBe(argv.join(' '));
    expect(out.fingerprints).toEqual([]);
  });

  it('hashes a --flag=value credential half and fingerprints it', () => {
    const out = scrubArgv(['cmd', '--api-key=sk-live-ABCDEFGHIJKLMNOP'], redactor);
    expect(out.command).not.toContain('sk-live-ABCDEFGHIJKLMNOP');
    expect(out.command).toMatch(/^cmd --api-key=sha256:[0-9a-f]{64}$/);
    expect(out.fingerprints).toHaveLength(1);
    expect(out.fingerprints[0]).toEqual({
      name: 'api-key',
      ref: sha256Ref('sk-live-ABCDEFGHIJKLMNOP'),
    });
  });

  it('hashes a standalone value following a --token flag and fingerprints it', () => {
    const out = scrubArgv(['cmd', '--token', 'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456'], redactor);
    expect(out.command).not.toContain('ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456');
    expect(out.command).toBe(`cmd --token ${sha256Ref('ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456')}`);
    expect(out.fingerprints).toEqual([
      { name: 'token', ref: sha256Ref('ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456') },
    ]);
  });

  it('does not consume the next flag as a value when a credential flag has none', () => {
    const out = scrubArgv(['cmd', '--token', '--verbose'], redactor);
    expect(out.command).toBe('cmd --token --verbose');
    expect(out.fingerprints).toEqual([]);
  });

  it('strips userinfo from a DSN-style URL, keeping scheme+host+path', () => {
    const dsn = 'postgres://admin:S3cretPassw0rd@db.internal/prod';
    const out = scrubArgv(['cmd', dsn], redactor);
    expect(out.command).toBe('cmd postgres://db.internal/prod');
    expect(out.command).not.toContain('S3cretPassw0rd');
    // The joined "user:pass" is fingerprinted (unchanged behavior), plus
    // (P2) the password and username separately, so a blast-radius query for
    // the leaked password ALONE — without knowing the username — still
    // finds it.
    expect(out.fingerprints).toEqual([
      { name: 'argv[1]', ref: sha256Ref('admin:S3cretPassw0rd') },
      { name: 'argv[1]', ref: sha256Ref('S3cretPassw0rd') },
      { name: 'argv[1]', ref: sha256Ref('admin') },
    ]);
  });

  it('hashes a whole element that looks secret on its own (no flag involved)', () => {
    const out = scrubArgv(['cmd', SECRETS.aws], redactor);
    expect(out.command).toBe(`cmd ${sha256Ref(SECRETS.aws)}`);
    expect(out.fingerprints).toEqual([{ name: 'argv[1]', ref: sha256Ref(SECRETS.aws) }]);
  });

  it('a blast-radius query can find the leaked value via the fingerprint ref', () => {
    const out = scrubArgv(['cmd', '--password', 'hunter2hunter2'], redactor);
    const needleHash = sha256Ref('hunter2hunter2');
    expect(out.fingerprints.some((f) => f.ref === needleHash)).toBe(true);
  });

  /* --- P1: --flag=value whose FLAG name is not credential-shaped but the
   * VALUE is a secret or a URL carrying userinfo (--dsn=, --url=,
   * --database-url=, ...). Previously the credential-flag-name branch was
   * skipped (flag isn't credential-ish) and the whole-element fallback
   * (looksSecret(el) / stripUrlUserinfo(el)) never matched either, because
   * `new URL('--dsn=postgres://...')` throws on the "--dsn=" prefix — so the
   * element was pushed verbatim, leaking the credential. */
  it('scrubs the value half of --dsn=<url-with-userinfo> even though "dsn" is not credential-shaped', () => {
    const out = scrubArgv(
      ['cmd', '--dsn=postgres://dbuser:S3cretPw@db.internal:5432/app'],
      redactor,
    );
    expect(out.command).not.toContain('S3cretPw');
    expect(out.command).not.toContain('dbuser');
    expect(out.command).toBe('cmd --dsn=postgres://db.internal:5432/app');
    expect(out.fingerprints).toEqual([
      { name: 'dsn', ref: sha256Ref('dbuser:S3cretPw') },
      { name: 'dsn', ref: sha256Ref('S3cretPw') },
      { name: 'dsn', ref: sha256Ref('dbuser') },
    ]);
  });

  it('scrubs the value half of --url=<url-with-userinfo>', () => {
    const out = scrubArgv(['cmd', '--url=https://u:p@host/x'], redactor);
    expect(out.command).toBe('cmd --url=https://host/x');
    expect(out.command).not.toContain('u:p@');
    expect(out.fingerprints.map((f) => f.ref)).toContain(sha256Ref('p'));
  });

  it('scrubs the value half of --database-url=<url-with-userinfo>', () => {
    const out = scrubArgv(
      ['cmd', '--database-url=mysql://root:hunter2hunter2@127.0.0.1/db'],
      redactor,
    );
    expect(out.command).toBe('cmd --database-url=mysql://127.0.0.1/db');
    expect(out.command).not.toContain('hunter2hunter2');
    expect(out.fingerprints.map((f) => f.ref)).toContain(sha256Ref('hunter2hunter2'));
  });

  it('hashes the value half whole when it is secret-shaped rather than a URL (--config=<token>)', () => {
    const out = scrubArgv(['cmd', `--config=${SECRETS.github}`], redactor);
    expect(out.command).not.toContain(SECRETS.github);
    expect(out.command).toBe(`cmd --config=${sha256Ref(SECRETS.github)}`);
    expect(out.fingerprints).toEqual([{ name: 'config', ref: sha256Ref(SECRETS.github) }]);
  });

  it('an ordinary --flag=value with a harmless value is left untouched', () => {
    const out = scrubArgv(['cmd', '--format=json', '--verbose=true'], redactor);
    expect(out.command).toBe('cmd --format=json --verbose=true');
    expect(out.fingerprints).toEqual([]);
  });
});

describe('scrubArgv: NAME=value elements and encoded userinfo', () => {
  it('scrubs a URL with userinfo in an env-style NAME=value element (env DSN=... server)', () => {
    const redactor = new Redactor({ mode: 'allowlist' });
    const { command, fingerprints } = scrubArgv(
      ['env', 'DSN=postgres://dbuser:S3cretPw@db.internal:5432/app', 'server', '--format=json'],
      redactor,
    );
    expect(command).toBe('env DSN=postgres://db.internal:5432/app server --format=json');
    expect(command).not.toContain('S3cretPw');
    expect(fingerprints.map((f) => f.ref)).toContain(redactor.hashString('S3cretPw'));
    expect(fingerprints.every((f) => f.name === 'DSN')).toBe(true);
  });

  it('fingerprints the decoded password (and the raw form) for percent-encoded userinfo', () => {
    const redactor = new Redactor({ mode: 'allowlist' });
    const { command, fingerprints } = scrubArgv(
      ['server', '--dsn=postgres://alice:p%40ss%3Aw0rd@db/app'],
      redactor,
    );
    expect(command).toBe('server --dsn=postgres://db/app');
    const refs = fingerprints.map((f) => f.ref);
    expect(refs).toContain(redactor.hashString('p@ss:w0rd'));
    expect(refs).toContain(redactor.hashString('p%40ss%3Aw0rd'));
    expect(refs).toContain(redactor.hashString('alice:p@ss:w0rd'));
  });
});

/* --- P0: structuralString() caps verbatim protocol strings (tool/method
 * names, clientInfo/serverInfo name+version, protocolVersion) that the
 * proxies stamp on events with no length/vocabulary cap otherwise — see
 * src/proxy/stdio.ts and src/proxy/http.ts for the call sites. */
describe('structuralString (P0: capping verbatim protocol strings)', () => {
  it('keeps a normal identifier (tool/method name) unchanged', () => {
    expect(structuralString('list_issues', 'identifier')).toBe('list_issues');
    expect(structuralString('tools/call', 'identifier')).toBe('tools/call');
    expect(structuralString('notifications/initialized', 'identifier')).toBe(
      'notifications/initialized',
    );
    expect(structuralString('my-tool_v2.final', 'identifier')).toBe('my-tool_v2.final');
  });

  it('keeps a normal version string unchanged', () => {
    expect(structuralString('9.9.9', 'version')).toBe('9.9.9');
    expect(structuralString('1.2.3-beta+build.4', 'version')).toBe('1.2.3-beta+build.4');
  });

  it('keeps a well-formed protocolVersion unchanged', () => {
    expect(structuralString('2024-11-05', 'protocol_version')).toBe('2024-11-05');
  });

  it('hashes an oversized identifier (> 128 chars) to its sha256 ref', () => {
    const huge = 'x'.repeat(5000);
    expect(structuralString(huge, 'identifier')).toBe(sha256Ref(huge));
    // Right at the boundary: exactly MAX_LEN survives, one over does not.
    const atMax = 'a'.repeat(STRUCTURAL_STRING_MAX_LEN);
    expect(structuralString(atMax, 'identifier')).toBe(atMax);
    const overMax = 'a'.repeat(STRUCTURAL_STRING_MAX_LEN + 1);
    expect(structuralString(overMax, 'identifier')).toBe(sha256Ref(overMax));
  });

  it('hashes an identifier containing spaces to its sha256 ref', () => {
    const withSpaces = 'not a valid tool name';
    expect(structuralString(withSpaces, 'identifier')).toBe(sha256Ref(withSpaces));
  });

  it('hashes an identifier containing a newline to its sha256 ref', () => {
    const withNewline = 'bad\nname';
    expect(structuralString(withNewline, 'identifier')).toBe(sha256Ref(withNewline));
  });

  it('hashes a malformed version string to its sha256 ref', () => {
    const badVersion = 'not a version! 🎉';
    expect(structuralString(badVersion, 'version')).toBe(sha256Ref(badVersion));
  });

  it('hashes a malformed protocolVersion (wrong shape) to its sha256 ref', () => {
    for (const bad of ['not-a-date', '2024/11/05', '2024-11-05T00:00:00Z', '', '2024-1-5']) {
      expect(structuralString(bad, 'protocol_version')).toBe(sha256Ref(bad));
    }
  });

  it('the hashed fallback is computed the exact same way as Redactor.hashString, so query can still find the original value', () => {
    const redactor = new Redactor();
    const huge = 'y'.repeat(1000);
    expect(structuralString(huge, 'identifier')).toBe(redactor.hashString(huge));
  });

  it('the field stays a plain string either way, never a RedactedRef object (frozen schema)', () => {
    const huge = 'z'.repeat(1000);
    const kept = structuralString('short_id', 'identifier');
    const hashed = structuralString(huge, 'identifier');
    expect(typeof kept).toBe('string');
    expect(typeof hashed).toBe('string');
    expect(hashed).toMatch(/^sha256:[0-9a-f]{64}$/);
  });
});

/* ---------------------------------------------------------------------- *
 * REGRESSION: a credential carried in a URL PATH reached ServerContext.command
 * ---------------------------------------------------------------------- */

/**
 * `stripUrlUserinfo` runs BEFORE `looksSecret` in both scrubArgv branches,
 * because the strip is the stronger outcome for a DSN (three separate refs,
 * and a legible scheme/host/path). But stripping the userinfo says nothing
 * about the REST of the URL: a token in the PATH survived it, and because
 * the strip branch `continue`d, `looksSecret` never ran on the element —
 * so the token landed verbatim in `ServerContext.command`, which is stamped
 * on every event, rendered by the replay page and shipped in export bundles.
 * That is the no-readable-payloads rule, broken.
 */
describe('scrubArgv: a credential in the URL PATH does not survive the userinfo strip', () => {
  const redactor = new Redactor();

  it('hashes the stripped remainder too when it still looks secret (standalone element)', () => {
    const el = `https://u:p@hooks.example.com/services/${SECRETS.github}`;
    const stripped = `https://hooks.example.com/services/${SECRETS.github}`;
    const out = scrubArgv(['server', el], redactor);

    expect(out.command).not.toContain(SECRETS.github);
    expect(out.command).toBe(`server ${sha256Ref(stripped)}`);
    const refs = out.fingerprints.map((f) => f.ref);
    // The userinfo refs the strip exists for are still recorded separately...
    expect(refs).toContain(sha256Ref('u:p'));
    expect(refs).toContain(sha256Ref('p'));
    expect(refs).toContain(sha256Ref('u'));
    // ...and a blast-radius query for the leaked URL still finds it.
    expect(refs).toContain(sha256Ref(stripped));
  });

  it('hashes the stripped remainder in the --flag=value half', () => {
    const value = 'https://u:p@api.example.com/v1/sk-live-ABCDEFGHIJKLMNOPQR/stream';
    const stripped = 'https://api.example.com/v1/sk-live-ABCDEFGHIJKLMNOPQR/stream';
    const out = scrubArgv(['server', `--endpoint=${value}`], redactor);
    expect(out.command).not.toContain('sk-live-ABCDEFGHIJKLMNOPQR');
    expect(out.command).toBe(`server --endpoint=${sha256Ref(stripped)}`);
    expect(out.fingerprints.map((f) => f.ref)).toContain(sha256Ref(stripped));
  });

  it('hashes the stripped remainder in a NAME=value element', () => {
    const value = `https://u:p@api.example.com/${SECRETS.aws}/ingest`;
    const stripped = `https://api.example.com/${SECRETS.aws}/ingest`;
    const out = scrubArgv(['env', `DSN=${value}`, 'server'], redactor);
    expect(out.command).not.toContain(SECRETS.aws);
    expect(out.command).toBe(`env DSN=${sha256Ref(stripped)} server`);
    expect(out.fingerprints.every((f) => f.name === 'DSN')).toBe(true);
  });

  it('an ordinary DSN still keeps its scheme, host and path legible', () => {
    const out = scrubArgv(['cmd', 'postgres://admin:S3cretPassw0rd@db.internal/prod'], redactor);
    expect(out.command).toBe('cmd postgres://db.internal/prod');
    expect(out.fingerprints.map((f) => f.ref)).not.toContain(
      sha256Ref('postgres://db.internal/prod'),
    );
  });
});

/* ---------------------------------------------------------------------- *
 * REGRESSION: the widened assignment shape rewrote ordinary developer output
 * ---------------------------------------------------------------------- */

/** Ordinary source, config and log lines. None of these is a credential. */
const NOT_ASSIGNMENTS = [
  'const MAX_TOKEN_LENGTH = 512;',
  'token_bucket_size: 100',
  'refresh_token_ttl = 3600',
  '  access_token_expires_in: 3600,',
  'export const DEFAULT_TOKEN_BUDGET = 15000;',
  'reset_token_sent_at: null',
  'csrf-token-header: X-CSRF',
  'INFO  auth_token_cache_hits=42 misses=3',
  'secret_scanning_enabled: true',
  'api_key_id: 7',
  'secretary_id=5',
  'tokenizer_count=3',
  'passwordless=true',
  '--secret-scanning enabled',
  '--token to authenticate',
  '--api-key <your-key-here>',
  '--token $GITHUB_TOKEN',
] as const;

/** Credentials the widening was added for. Every one must still be caught. */
const REAL_ASSIGNMENTS = [
  'AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
  'DB_PASSWORD=hunter2-correct-horse',
  'X-Api-Key: 0123456789abcdefghij',
  'password=hunter2',
  'api_key: abc',
  '{"password": "hunter2-correct-horse"}',
  '{"api_key":"abcdefghijklmnop1234"}',
  "password: 'hunter2-correct-horse'",
  '--password=hunter2',
  'docker login --password hunter2-correct-horse',
] as const;

describe('alwaysPatterns: credential assignments, bare vs affixed', () => {
  it.each(NOT_ASSIGNMENTS)('%s is not a credential', (line) => {
    expect(looksSecret(line)).toBe(false);
  });

  it.each(REAL_ASSIGNMENTS)('%s is still hashed in every mode', (line) => {
    expect(looksSecret(line)).toBe(true);
    for (const mode of ['allowlist', 'off'] as const) {
      const out = JSON.stringify(new Redactor({ mode }).scrub({ v: line }));
      expect(out).not.toContain('hunter2');
      expect(out).not.toContain('wJalrXUtnFEMI');
      expect(out).not.toContain('0123456789abcdefghij');
      expect(out).not.toContain('abcdefghijklmnop1234');
    }
  });

  it('a JSON credential embedded in a larger leaf is caught, value and all', () => {
    const leaf = 'config: {"password": "hunter2-correct-horse", "port": 5432}';
    const out = new Redactor().scrub({ body: leaf }) as { body: RedactedRef };
    expect(JSON.stringify(out)).not.toContain('hunter2');
    expect(out.body.secret_refs).toBeDefined();
  });

  it('everyday developer output is untouched by a real-world corpus', () => {
    const corpus = [
      '  "resolved": "https://registry.npmjs.org/vitest/-/vitest-2.1.9.tgz",',
      'the token docs explain how a token is minted; a password is required',
      'Authorization: Bearer <token>',
      'eyJhbGciOiJIUzI1NiJ9.<payload>.<signature>  # a JWT looks like this',
    ];
    for (const line of corpus) {
      expect(looksSecret(line), line).toBe(false);
    }
  });
});

/* ---------------------------------------------------------------------- *
 * NIT: github_pat_ and the url-userinfo lookbehind
 * ---------------------------------------------------------------------- */

describe('alwaysPatterns: shapes that are the credential and nothing else', () => {
  const realPat =
    'github_pat_11ABCDEFG0aBcDeFgHiJkL_KlMnOpQrStUvWxYz0123456789AbCdEfGhIjKlMnOpQrStUvWxYz0123456';

  it('a real fine-grained PAT (22 + 59) is hashed', () => {
    expect(looksSecret(realPat)).toBe(true);
  });

  it.each([
    'github_pat_token_refresh_helper_result',
    'github_pat_validation_middleware_options',
    'github_pat_scopes_required_for_this_call',
  ])('the snake_case identifier %s is not a PAT', (id) => {
    expect(looksSecret(id)).toBe(false);
  });

  it('a URL that really carries userinfo is still matched', () => {
    expect(looksSecret('postgres://user:pass@host/db')).toBe(true);
    expect(looksSecret('psql redis://u:p@127.0.0.1:6379/0 --list')).toBe(true);
    expect(looksSecret('https://u:p@[2001:db8::1]:8443/x')).toBe(true);
  });

  it.each([
    'oci://redis:7.2@sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    'docker://library/nginx:1.25@sha256:abcdef0123456789abcdef',
  ])('the container/tag reference %s is not userinfo', (ref) => {
    const urlRe = DEFAULT_POLICY.alwaysPatterns.find((r) => r.source.startsWith('(?<=:\\/\\/)'))!;
    expect(new RegExp(urlRe.source).test(ref)).toBe(false);
  });
});
