import { describe, expect, it } from 'vitest';
import { createWriteStream, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import yazl from 'yazl';
import { ZIP_MAX_ENTRY_BYTES, readZipEntries } from '../src/export/unzip.js';

/* ------------------------------- helpers -------------------------------- */

interface Entry {
  name: string;
  data: Buffer;
  compress?: boolean;
}

/** Write a zip with yazl — the same writer `export --out` uses — and read it back. */
async function zipBuffer(entries: readonly Entry[]): Promise<Buffer> {
  const dir = mkdtempSync(join(tmpdir(), 'mcp-rec-unzip-'));
  try {
    const zipPath = join(dir, 'test.zip');
    await new Promise<void>((resolve, reject) => {
      const zf = new yazl.ZipFile();
      for (const e of entries) zf.addBuffer(e.data, e.name, { compress: e.compress ?? true });
      const out = createWriteStream(zipPath);
      out.on('close', () => resolve());
      out.on('error', reject);
      zf.outputStream.on('error', reject);
      zf.outputStream.pipe(out);
      zf.end();
    });
    return readFileSync(zipPath);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

const EVENTS = Buffer.from('{"seq":1,"event":{"kind":"tool_call"}}\n'.repeat(4_000), 'utf8');
const PEM = Buffer.from('-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA\n-----END PUBLIC KEY-----\n');

/* --------------------------------- tests -------------------------------- */

describe('readZipEntries', () => {
  it('round-trips deflated, stored and empty entries written by yazl', async () => {
    const zip = await zipBuffer([
      { name: 'events.jsonl', data: EVENTS },
      { name: 'public_key.pem', data: PEM, compress: false },
      { name: 'empty.txt', data: Buffer.alloc(0) },
    ]);
    const entries = readZipEntries(zip, ['events.jsonl', 'public_key.pem', 'empty.txt']);
    expect([...entries.keys()].sort()).toEqual(['empty.txt', 'events.jsonl', 'public_key.pem']);
    expect(entries.get('events.jsonl')!.equals(EVENTS)).toBe(true);
    expect(entries.get('public_key.pem')!.equals(PEM)).toBe(true);
    expect(entries.get('empty.txt')!.length).toBe(0);
  });

  it('only returns wanted entries; an absent wanted name is simply missing', async () => {
    const zip = await zipBuffer([
      { name: 'events.jsonl', data: EVENTS },
      { name: 'README.txt', data: Buffer.from('hello') },
    ]);
    const entries = readZipEntries(zip, ['events.jsonl', 'manifest.json']);
    expect([...entries.keys()]).toEqual(['events.jsonl']);
    expect(entries.has('README.txt')).toBe(false);
    expect(entries.has('manifest.json')).toBe(false);
  });

  it('rejects input that is not a zip archive', () => {
    expect(() => readZipEntries(Buffer.from('hello'), ['events.jsonl'])).toThrow(
      /not a valid ZIP file/,
    );
    expect(() =>
      readZipEntries(Buffer.from('{"not":"a zip"}\n'.repeat(50), 'utf8'), ['events.jsonl']),
    ).toThrow(/no end-of-central-directory/);
  });

  it('rejects a truncated archive whose central directory survived', async () => {
    const whole = await zipBuffer([{ name: 'events.jsonl', data: EVENTS }]);
    // Keep the first local header and the tail (central directory + EOCD),
    // drop the entry data in between: the declared compressed size now runs
    // past the end of the file.
    const cut = Buffer.concat([whole.subarray(0, 40), whole.subarray(whole.length - 120)]);
    expect(() => readZipEntries(cut, ['events.jsonl'])).toThrow(/malformed ZIP/);
  });

  it('rejects a wanted name that appears twice instead of picking one silently', async () => {
    const zip = await zipBuffer([
      { name: 'events.jsonl', data: EVENTS },
      { name: 'manifest.json', data: Buffer.from('{}') },
      { name: 'events.jsonl', data: Buffer.from('{"seq":1,"event":{"kind":"forged"}}\n') },
    ]);
    expect(() => readZipEntries(zip, ['events.jsonl', 'manifest.json'])).toThrow(
      'malformed ZIP: duplicate entry events.jsonl',
    );
    // Duplicates of entries nobody asked for are not this reader's concern.
    const zip2 = await zipBuffer([
      { name: 'notes.txt', data: Buffer.from('a') },
      { name: 'notes.txt', data: Buffer.from('b') },
      { name: 'manifest.json', data: Buffer.from('{}') },
    ]);
    expect(readZipEntries(zip2, ['manifest.json']).get('manifest.json')!.toString()).toBe('{}');
  });

  it('caps inflation: an entry that inflates past the limit is rejected, not buffered', async () => {
    const oneMiB = 1024 * 1024;
    const zip = await zipBuffer([
      { name: 'events.jsonl', data: Buffer.alloc(oneMiB + 1, 0x41) }, // compresses to ~1 KiB
      { name: 'manifest.json', data: Buffer.from('{}') },
    ]);
    expect(() =>
      readZipEntries(zip, ['events.jsonl', 'manifest.json'], { maxEntryBytes: oneMiB }),
    ).toThrow(/events\.jsonl inflates past the 1 MiB limit of verify --bundle on a \.zip/);
    // Exactly at the limit is fine.
    const ok = readZipEntries(zip, ['events.jsonl'], { maxEntryBytes: oneMiB + 1 });
    expect(ok.get('events.jsonl')!.length).toBe(oneMiB + 1);
    // The production default is the documented 256 MiB.
    expect(ZIP_MAX_ENTRY_BYTES).toBe(256 * oneMiB);
  });

  it('rejects zip64 archives', async () => {
    const zip = await zipBuffer([{ name: 'manifest.json', data: Buffer.from('{}') }]);
    const eocd = zip.lastIndexOf(Buffer.from([0x50, 0x4b, 0x05, 0x06]));
    const zip64 = Buffer.from(zip);
    zip64.writeUInt16LE(0xffff, eocd + 10); // total-entries field carries the zip64 marker
    expect(() => readZipEntries(zip64, ['manifest.json'])).toThrow(/ZIP64/);
  });
});
