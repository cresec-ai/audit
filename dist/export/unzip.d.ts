/** Decompression cap per entry — a bundle's events.jsonl is never near this
 * size; this just bounds a hostile/corrupt DEFLATE stream's blow-up. */
export declare const ZIP_MAX_ENTRY_BYTES: number;
export interface ReadZipOpts {
    /** Per-entry inflate cap in bytes (default ZIP_MAX_ENTRY_BYTES); tests use a small one. */
    maxEntryBytes?: number;
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
export declare function readZipEntries(buf: Buffer, wanted: readonly string[], opts?: ReadZipOpts): Map<string, Buffer>;
