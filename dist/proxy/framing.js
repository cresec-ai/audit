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
            const line = this.finishLine();
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
        const line = this.finishLine();
        return line === null ? [] : [line];
    }
    append(bytes) {
        if (bytes.length === 0)
            return;
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
    /** Emit the buffered line and reset state. Returns null for empty lines. */
    finishLine() {
        const { parts, bytesLen, hash, oversized } = this;
        this.parts = [];
        this.bytesLen = 0;
        this.hash = null;
        this.oversized = false;
        if (bytesLen === 0)
            return null; // empty line — skip silently
        const lineHashHex = hash.digest('hex');
        if (oversized) {
            return { text: null, oversized: true, bytesLen, lineHashHex };
        }
        let text = Buffer.concat(parts, bytesLen).toString('utf8');
        if (text.endsWith('\r'))
            text = text.slice(0, -1);
        if (text.length === 0)
            return null; // bare "\r\n" — also empty
        return { text, oversized: false, bytesLen, lineHashHex };
    }
}
//# sourceMappingURL=framing.js.map