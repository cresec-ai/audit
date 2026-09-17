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
import { createHash } from 'node:crypto';
const DEFAULT_MAX_LINE_BYTES = 32 * 1024 * 1024; // 32 MiB
const NL = 0x0a;
export class LineScanner {
    maxLineBytes;
    /** Buffered chunks of the current (incomplete) line, while under the cap. */
    parts = [];
    /** Bytes seen so far on the current line (including any dropped ones). */
    bytesLen = 0;
    /** Incremental hash over the raw bytes of the current line. */
    hash = null;
    /** Once the cap is exceeded we stop buffering but keep counting/hashing. */
    oversized = false;
    /** First non-whitespace byte of the current line; -1 until one is seen. */
    firstByte = -1;
    constructor(opts) {
        this.maxLineBytes = opts?.maxLineBytes ?? DEFAULT_MAX_LINE_BYTES;
    }
    /** Feed a chunk; returns every complete line that ended inside it. */
    push(chunk) {
        const out = [];
        let start = 0;
        for (;;) {
            const nl = chunk.indexOf(NL, start);
            if (nl === -1) {
                this.append(chunk.subarray(start));
                break;
            }
            this.append(chunk.subarray(start, nl));
            const line = this.finishLine(true);
            if (line !== null)
                out.push(line);
            start = nl + 1;
        }
        return out;
    }
    /** Flush a trailing unterminated line, if any. */
    end() {
        if (this.bytesLen === 0 && !this.oversized)
            return [];
        const line = this.finishLine(false);
        return line === null ? [] : [line];
    }
    /** True while bytes of an incomplete line are buffered (or being counted, when oversized). */
    hasPartialLine() {
        return this.bytesLen > 0 || this.oversized;
    }
    /** True when the current incomplete line has already exceeded the cap (its content is not buffered). */
    partialLineOversized() {
        return this.oversized;
    }
    append(bytes) {
        if (bytes.length === 0)
            return;
        if (this.firstByte === -1) {
            for (const b of bytes) {
                // space, \t, \r (a \n would have ended the line)
                if (b !== 0x20 && b !== 0x09 && b !== 0x0d) {
                    this.firstByte = b;
                    break;
                }
            }
        }
        if (this.hash === null)
            this.hash = createHash('sha256');
        this.hash.update(bytes);
        this.bytesLen += bytes.length;
        if (!this.oversized) {
            if (this.bytesLen > this.maxLineBytes) {
                this.oversized = true;
                this.parts = []; // stop buffering content; counting + hashing continue
            }
            else {
                this.parts.push(bytes);
            }
        }
    }
    /**
     * Emit the buffered line and reset state. Returns null for empty lines.
     * `terminated` says whether a `\n` ended the line (so `raw` includes it).
     */
    finishLine(terminated) {
        const { parts, bytesLen, hash, oversized, firstByte } = this;
        this.parts = [];
        this.bytesLen = 0;
        this.hash = null;
        this.oversized = false;
        this.firstByte = -1;
        if (bytesLen === 0)
            return null; // empty line — skip silently
        const lineHashHex = hash.digest('hex');
        if (oversized) {
            const line = { text: null, oversized: true, bytesLen, lineHashHex };
            if (firstByte !== -1)
                line.firstByte = firstByte;
            return line;
        }
        // One allocation: the line bytes plus room for the terminating '\n'
        // (`raw`); `text` is decoded from the same buffer's line-only view.
        const raw = terminated ? Buffer.concat(parts, bytesLen + 1) : Buffer.concat(parts, bytesLen);
        if (terminated)
            raw[bytesLen] = NL;
        let text = raw.toString('utf8', 0, bytesLen);
        if (text.endsWith('\r'))
            text = text.slice(0, -1);
        if (text.length === 0)
            return null; // bare "\r\n" — also empty
        const line = { text, oversized: false, bytesLen, lineHashHex, raw };
        if (firstByte !== -1)
            line.firstByte = firstByte;
        return line;
    }
}
//# sourceMappingURL=framing.js.map