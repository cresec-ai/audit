import { describe, expect, it } from 'vitest';
import { requestHash } from '../src/capture/lifecycle.js';
import { canonicalJson, sha256Ref } from '../src/chain/hash.js';

describe('full request fingerprint', () => {
  it('matches frozen canonical JSON, including nested arrays, keys and nulls', () => {
    for (const value of [null, [], {}, { z: [1, null, undefined, { b: true, a: 'private' }], a: undefined }, { z: Infinity }]) {
      expect(requestHash(value)).toBe(sha256Ref(canonicalJson(value)));
    }
  });
  it('never truncates a deeply nested request', () => {
    let a: unknown = 'a'; let b: unknown = 'b';
    for (let i = 0; i < 10000; i++) { a = [a]; b = [b]; }
    expect(requestHash(a)).not.toBe(requestHash(b));
    expect(requestHash(a)).toBe(sha256Ref('['.repeat(10000) + '"a"' + ']'.repeat(10000)));
  });
});
