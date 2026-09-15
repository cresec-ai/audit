/**
 * MCP stdio framing: one JSON-RPC message per \n-delimited UTF-8 line.
 *
 * LineScanner is a passive, incremental splitter used by the proxy TAP — it
 * never touches the forwarded stream. It handles lines split across arbitrary
 * chunk boundaries (including mid-UTF-8-codepoint, since hashing and length
 * accounting are byte-oriented and decoding happens only on complete lines),
 * multiple lines per chunk, CRLF, empty lines (skipped), and oversized lines
 * (content dropped, byte count + incremental hash kept).
 */
export interface ScannedLine {
    /** Decoded line text (trailing \r stripped); null when oversized. */
    text: string | null;
    oversized: boolean;
    /** Length of the raw line in bytes (no trailing newline). */
    bytesLen: number;
    /** sha256 hex of the raw line bytes (no trailing newline). */
    lineHashHex: string;
    /**
     * The exact bytes of the line as they crossed the wire — including any
     * trailing `\r` and the terminating `\n` (absent only for a trailing
     * unterminated line flushed by `end()`). Present only when the line was
     * not oversized (an oversized line's content is not buffered). Additive:
     * used by gateway mode to forward an untouched line byte-for-byte.
     */
    raw?: Buffer;
}
export declare class LineScanner {
    private readonly maxLineBytes;
    /** Buffered chunks of the current (incomplete) line, while under the cap. */
    private parts;
    /** Bytes seen so far on the current line (including any dropped ones). */
    private bytesLen;
    /** Incremental hash over the raw bytes of the current line. */
    private hash;
    /** Once the cap is exceeded we stop buffering but keep counting/hashing. */
    private oversized;
    constructor(opts?: {
        maxLineBytes?: number;
    });
    /** Feed a chunk; returns every complete line that ended inside it. */
    push(chunk: Buffer): ScannedLine[];
    /** Flush a trailing unterminated line, if any. */
    end(): ScannedLine[];
    /** True while bytes of an incomplete line are buffered (or being counted, when oversized). */
    hasPartialLine(): boolean;
    /** True when the current incomplete line has already exceeded the cap (its content is not buffered). */
    partialLineOversized(): boolean;
    private append;
    /**
     * Emit the buffered line and reset state. Returns null for empty lines.
     * `terminated` says whether a `\n` ended the line (so `raw` includes it).
     */
    private finishLine;
}
