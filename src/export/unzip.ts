/* ----------------------------- minimal ZIP reader ----------------------------
 * `export --out FILE.zip` writes bundles with yazl (stored or DEFLATE entries,
 * no zip64, no encryption, single disk — see src/export/bundle.ts). This is
 * just enough of the ZIP format to read one of those back: walk the central
 * directory (authoritative — never trust local headers alone for sizes), then
 * pull each wanted entry's bytes from its local header and inflate if needed.
 * No new dependency: node:zlib's inflateRawSync covers DEFLATE.
 *
 * Extracted from src/cli.ts unchanged in behaviour so it can be unit-tested
 * directly (test/unzip.test.ts); `verify --bundle` on a .zip is its only
 * production caller. Every failure throws a plain Error whose message the CLI
 * prints verbatim as `[mcp-recorder] error: ...` (exit 2).
 */

import { inflateRawSync } from 'node:zlib';

const ZIP_EOCD_SIGNATURE = 0x06054b50;
const ZIP_CENTRAL_DIR_SIGNATURE = 0x02014b50;
const ZIP_LOCAL_HEADER_SIGNATURE = 0x04034b50;
const ZIP_EOCD_SIZE = 22;
const ZIP_MAX_COMMENT = 0xffff;
/** Decompression cap per entry — a bundle's events.jsonl is never near this
 * size; this just bounds a hostile/corrupt DEFLATE stream's blow-up. */
export const ZIP_MAX_ENTRY_BYTES = 256 * 1024 * 1024;

export interface ReadZipOpts {
  /** Per-entry inflate cap in bytes (default ZIP_MAX_ENTRY_BYTES); tests use a small one. */
  maxEntryBytes?: number;
}

function err(msg: string): never {
  throw new Error(msg);
}

/** Scan backward from EOF for the End Of Central Directory record. */
function findZipEndOfCentralDirectory(buf: Buffer): number {
  const scanBack = Math.min(buf.length, ZIP_EOCD_SIZE + ZIP_MAX_COMMENT);
  const floor = buf.length - scanBack;
  for (let i = buf.length - ZIP_EOCD_SIZE; i >= floor; i--) {
    if (buf.readUInt32LE(i) === ZIP_EOCD_SIGNATURE) return i;
  }
  return -1;
}

function inflateZipEntry(
  buf: Buffer,
  localHeaderOffset: number,
  method: number,
  compressedSize: number,
  name: string,
  maxEntryBytes: number,
): Buffer {
  if (
    localHeaderOffset < 0 ||
    localHeaderOffset + 30 > buf.length ||
    buf.readUInt32LE(localHeaderOffset) !== ZIP_LOCAL_HEADER_SIGNATURE
  ) {
    err(`malformed ZIP: bad local file header for ${name}`);
  }
  const nameLen = buf.readUInt16LE(localHeaderOffset + 26);
  const extraLen = buf.readUInt16LE(localHeaderOffset + 28);
  const dataStart = localHeaderOffset + 30 + nameLen + extraLen;
  if (dataStart + compressedSize > buf.length) {
    err(`malformed ZIP: ${name} data runs past the end of the file`);
  }
  const compressed = buf.subarray(dataStart, dataStart + compressedSize);
  if (method === 0) return Buffer.from(compressed);
  if (method === 8) {
    try {
      return inflateRawSync(compressed, { maxOutputLength: maxEntryBytes });
    } catch (cause) {
      const code = (cause as NodeJS.ErrnoException).code;
      if (code === 'ERR_BUFFER_TOO_LARGE' || /larger than/i.test((cause as Error).message)) {
        err(
          `${name} inflates past the ${maxEntryBytes / (1024 * 1024)} MiB limit of verify --bundle on a .zip; ` +
            'extract the archive and run verify --bundle on the directory (or node verify.cjs inside it)',
        );
      }
      err(`malformed ZIP: cannot inflate ${name}: ${(cause as Error).message}`);
    }
  }
  err(`unsupported ZIP compression method ${method} for ${name} (only stored/deflate are supported)`);
}

/**
 * Extract the bytes of each `wanted` entry from a .zip buffer, by name.
 *
 * The central directory is walked in FULL (no early exit once every wanted
 * name has been seen once): a wanted name appearing more than once is a
 * malformed/hostile ZIP, not an ambiguity to resolve silently. Real
 * extractors (`unzip`, Node's own `AdmZip`-style `extractAllTo`) write
 * whichever duplicate-named entry comes LAST; picking any one entry here
 * without checking for a duplicate would let a bundle whose FIRST
 * events.jsonl is genuine and SECOND is forged verify against the genuine
 * copy while extracting the forged one to disk.
 *
 * Entries that are not in `wanted` are skipped (never inflated). A wanted
 * name that is absent is simply missing from the result — the caller decides
 * whether that is an error.
 */
export function readZipEntries(
  buf: Buffer,
  wanted: readonly string[],
  opts: ReadZipOpts = {},
): Map<string, Buffer> {
  const maxEntryBytes = opts.maxEntryBytes ?? ZIP_MAX_ENTRY_BYTES;
  const eocd = findZipEndOfCentralDirectory(buf);
  if (eocd === -1) err('not a valid ZIP file (no end-of-central-directory record found)');
  const totalEntries = buf.readUInt16LE(eocd + 10);
  const centralDirOffset = buf.readUInt32LE(eocd + 16);
  if (totalEntries === 0xffff || centralDirOffset === 0xffffffff) {
    err('ZIP64 bundles are not supported by verify --bundle');
  }

  const wantedSet = new Set(wanted);
  const found = new Map<string, Buffer>();
  let pos = centralDirOffset;
  for (let i = 0; i < totalEntries; i++) {
    if (pos + 46 > buf.length || buf.readUInt32LE(pos) !== ZIP_CENTRAL_DIR_SIGNATURE) {
      err('malformed ZIP central directory');
    }
    const method = buf.readUInt16LE(pos + 10);
    const compressedSize = buf.readUInt32LE(pos + 20);
    const nameLen = buf.readUInt16LE(pos + 28);
    const extraLen = buf.readUInt16LE(pos + 30);
    const commentLen = buf.readUInt16LE(pos + 32);
    const localHeaderOffset = buf.readUInt32LE(pos + 42);
    const name = buf.toString('utf8', pos + 46, pos + 46 + nameLen);
    pos += 46 + nameLen + extraLen + commentLen;

    if (!wantedSet.has(name)) continue;
    if (found.has(name)) err(`malformed ZIP: duplicate entry ${name}`);
    found.set(name, inflateZipEntry(buf, localHeaderOffset, method, compressedSize, name, maxEntryBytes));
  }
  return found;
}
