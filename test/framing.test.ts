import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { LineScanner } from '../src/proxy/framing.js';

const sha = (b: Buffer | string): string => createHash('sha256').update(b).digest('hex');

describe('LineScanner', () => {
  it('emits complete lines from a single chunk', () => {
    const s = new LineScanner();
    const lines = s.push(Buffer.from('{"a":1}\n{"b":2}\n'));
    expect(lines.map((l) => l.text)).toEqual(['{"a":1}', '{"b":2}']);
    expect(lines[0].bytesLen).toBe(7);
    expect(lines[0].lineHashHex).toBe(sha('{"a":1}'));
    expect(lines[0].oversized).toBe(false);
    expect(s.end()).toEqual([]);
  });

  it('reassembles lines split across arbitrary chunk boundaries', () => {
    const s = new LineScanner();
    expect(s.push(Buffer.from('{"meth'))).toEqual([]);
    expect(s.push(Buffer.from('od":"x'))).toEqual([]);
    const lines = s.push(Buffer.from('"}\n'));
    expect(lines).toHaveLength(1);
    expect(lines[0].text).toBe('{"method":"x"}');
    expect(lines[0].bytesLen).toBe(14);
    expect(lines[0].lineHashHex).toBe(sha('{"method":"x"}'));
  });

  it('handles a chunk boundary in the middle of a UTF-8 codepoint', () => {
    const text = '{"msg":"héllo \u{1F600} wörld"}';
    const bytes = Buffer.from(text + '\n', 'utf8');
    // Split inside the 4-byte emoji.
    const emojiStart = bytes.indexOf(Buffer.from('\u{1F600}', 'utf8'));
    const cut = emojiStart + 2;
    const s = new LineScanner();
    expect(s.push(bytes.subarray(0, cut))).toEqual([]);
    const lines = s.push(bytes.subarray(cut));
    expect(lines).toHaveLength(1);
    expect(lines[0].text).toBe(text);
    expect(lines[0].bytesLen).toBe(Buffer.byteLength(text, 'utf8'));
    expect(lines[0].lineHashHex).toBe(sha(Buffer.from(text, 'utf8')));
  });

  it('handles many lines in one chunk and lines spanning many chunks', () => {
    const s = new LineScanner();
    const out: (string | null)[] = [];
    for (const chunk of ['a\nb\nlong', 'line', 'part\nc\n', 'tail']) {
      for (const l of s.push(Buffer.from(chunk))) out.push(l.text);
    }
    for (const l of s.end()) out.push(l.text);
    expect(out).toEqual(['a', 'b', 'longlinepart', 'c', 'tail']);
  });

  it('strips a trailing \\r (CRLF framing)', () => {
    const s = new LineScanner();
    const lines = s.push(Buffer.from('{"a":1}\r\n{"b":2}\r\n'));
    expect(lines.map((l) => l.text)).toEqual(['{"a":1}', '{"b":2}']);
    // Raw bytes (and hash) still cover the \r — only `text` strips it.
    expect(lines[0].bytesLen).toBe(8);
    expect(lines[0].lineHashHex).toBe(sha('{"a":1}\r'));
  });

  it('skips empty lines silently (\\n\\n and bare \\r\\n)', () => {
    const s = new LineScanner();
    const lines = s.push(Buffer.from('\n\r\nx\n\n'));
    expect(lines.map((l) => l.text)).toEqual(['x']);
    expect(s.end()).toEqual([]);
  });

  it('returns non-JSON text verbatim (scanner does not parse)', () => {
    const s = new LineScanner();
    const lines = s.push(Buffer.from('boot: ready\n'));
    expect(lines).toHaveLength(1);
    expect(lines[0].text).toBe('boot: ready');
    expect(lines[0].oversized).toBe(false);
  });

  it('flushes a trailing unterminated line on end()', () => {
    const s = new LineScanner();
    expect(s.push(Buffer.from('no-newline'))).toEqual([]);
    const lines = s.end();
    expect(lines).toHaveLength(1);
    expect(lines[0].text).toBe('no-newline');
    expect(lines[0].lineHashHex).toBe(sha('no-newline'));
    // end() is then exhausted.
    expect(s.end()).toEqual([]);
  });

  it('marks oversized lines but keeps byte count and full-line hash', () => {
    const s = new LineScanner({ maxLineBytes: 1024 });
    const big = Buffer.alloc(5000, 0x61); // 'a' x 5000
    const fed = Buffer.concat([big, Buffer.from('\n{"ok":1}\n')]);
    // Feed in awkward chunk sizes to exercise incremental hashing.
    const lines = [
      ...s.push(fed.subarray(0, 700)),
      ...s.push(fed.subarray(700, 2000)),
      ...s.push(fed.subarray(2000)),
    ];
    expect(lines).toHaveLength(2);
    const [over, ok] = lines;
    expect(over.oversized).toBe(true);
    expect(over.text).toBeNull();
    expect(over.bytesLen).toBe(5000);
    expect(over.lineHashHex).toBe(sha(big));
    expect(ok.oversized).toBe(false);
    expect(ok.text).toBe('{"ok":1}');
  });

  it('recovers to normal lines after an oversized one', () => {
    const s = new LineScanner({ maxLineBytes: 8 });
    const lines = s.push(Buffer.from('aaaaaaaaaaaaaaaa\nsmall\n'));
    expect(lines[0].oversized).toBe(true);
    expect(lines[1]).toMatchObject({ text: 'small', oversized: false });
  });
});
