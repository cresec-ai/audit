import { describe, expect, it } from 'vitest';
import { canonicalJson, sha256Ref } from '../src/chain/hash.js';
import type { RedactedRef, Scrubbed } from '../src/schema/events.js';
import { DEFAULT_POLICY, Redactor, looksSecret } from '../src/redact/redactor.js';

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

  it('allow-listed key with structural short value passes', () => {
    expect(redactor.scrub({ name: 'read_file' })).toEqual({ name: 'read_file' });
  });

  it('allow-listed key with value longer than maxAllowedStringLen is redacted', () => {
    const long = 'word '.repeat(14).trim(); // 69 chars, structural charset, no secret shape
    expect(long.length).toBeGreaterThan(64);
    const out = redactor.scrub({ name: long }) as { name: Scrubbed };
    expect(isRedactedRef(out.name)).toBe(true);
    const ref = out.name as RedactedRef;
    expect(ref.ref).toBe(sha256Ref(long));
    expect(ref.len).toBe(long.length);
  });

  it('top-level string has no key and is always redacted', () => {
    const out = redactor.scrub('hello');
    expect(isRedactedRef(out)).toBe(true);
    expect((out as RedactedRef).ref).toBe(sha256Ref('hello'));
  });

  it('array-element strings have no key and are always redacted', () => {
    const out = redactor.scrub({ name: ['read_file'] }) as { name: Scrubbed[] };
    expect(isRedactedRef(out.name[0]!)).toBe(true);
  });

  it('non-allow-listed key is redacted even when the value looks harmless', () => {
    const out = redactor.scrub({ path: '/etc/passwd' }) as { path: Scrubbed };
    expect(isRedactedRef(out.path)).toBe(true);
    const ref = out.path as RedactedRef;
    expect(ref.ref).toBe(sha256Ref('/etc/passwd'));
    expect(ref.len).toBe('/etc/passwd'.length);
  });

  it('non-structural charset is redacted even under an allow-listed key', () => {
    const out = redactor.scrub({ name: 'why? "quotes" & ampersands' }) as { name: Scrubbed };
    expect(isRedactedRef(out.name)).toBe(true);
  });

  it('secret shape under an allow-listed key is still redacted', () => {
    const out = redactor.scrub({ name: SECRETS.aws }) as { name: Scrubbed };
    expect(isRedactedRef(out.name)).toBe(true);
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
    // 'code' is allow-listed, short, structural → passes as the string form
    expect(redactor.scrub({ code: 42n })).toEqual({ code: '42' });
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
    const shared = { name: 'shared_node' };
    const redactor = new Redactor();
    const out = redactor.scrub({ a: shared, b: shared }) as { a: Scrubbed; b: Scrubbed };
    expect(out.a).toEqual({ name: 'shared_node' });
    expect(out.b).toEqual({ name: 'shared_node' });
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
