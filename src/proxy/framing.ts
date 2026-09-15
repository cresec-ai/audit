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

import { createHash, type Hash } from 'node:crypto';

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

const DEFAULT_MAX_LINE_BYTES = 32 * 1024 * 1024; // 32 MiB

const NL = 0x0a;

export class LineScanner {
  private readonly maxLineBytes: number;
  /** Buffered chunks of the current (incomplete) line, while under the cap. */
  private parts: Buffer[] = [];
  /** Bytes seen so far on the current line (including any dropped ones). */
  private bytesLen = 0;
  /** Incremental hash over the raw bytes of the current line. */
  private hash: Hash | null = null;
  /** Once the cap is exceeded we stop buffering but keep counting/hashing. */
  private oversized = false;

  constructor(opts?: { maxLineBytes?: number }) {
    this.maxLineBytes = opts?.maxLineBytes ?? DEFAULT_MAX_LINE_BYTES;
  }

  /** Feed a chunk; returns every complete line that ended inside it. */
  push(chunk: Buffer): ScannedLine[] {
    const out: ScannedLine[] = [];
    let start = 0;
    for (;;) {
      const nl = chunk.indexOf(NL, start);
      if (nl === -1) {
        this.append(chunk.subarray(start));
        break;
      }
      this.append(chunk.subarray(start, nl));
      const line = this.finishLine(true);
      if (line !== null) out.push(line);
      start = nl + 1;
    }
    return out;
  }

  /** Flush a trailing unterminated line, if any. */
  end(): ScannedLine[] {
    if (this.bytesLen === 0 && !this.oversized) return [];
    const line = this.finishLine(false);
    return line === null ? [] : [line];
  }

  /** True while bytes of an incomplete line are buffered (or being counted, when oversized). */
  hasPartialLine(): boolean {
    return this.bytesLen > 0 || this.oversized;
  }

  /** True when the current incomplete line has already exceeded the cap (its content is not buffered). */
  partialLineOversized(): boolean {
    return this.oversized;
  }

  private append(bytes: Buffer): void {
    if (bytes.length === 0) return;
    if (this.hash === null) this.hash = createHash('sha256');
    this.hash.update(bytes);
    this.bytesLen += bytes.length;
    if (!this.oversized) {
      if (this.bytesLen > this.maxLineBytes) {
        this.oversized = true;
        this.parts = []; // stop buffering content; counting + hashing continue
      } else {
        this.parts.push(bytes);
      }
    }
  }

  /**
   * Emit the buffered line and reset state. Returns null for empty lines.
   * `terminated` says whether a `\n` ended the line (so `raw` includes it).
   */
  private finishLine(terminated: boolean): ScannedLine | null {
    const { parts, bytesLen, hash, oversized } = this;
    this.parts = [];
    this.bytesLen = 0;
    this.hash = null;
    this.oversized = false;

    if (bytesLen === 0) return null; // empty line — skip silently

    const lineHashHex = (hash as Hash).digest('hex');
    if (oversized) {
      return { text: null, oversized: true, bytesLen, lineHashHex };
    }
    // One allocation: the line bytes plus room for the terminating '\n'
    // (`raw`); `text` is decoded from the same buffer's line-only view.
    const raw = terminated ? Buffer.concat(parts, bytesLen + 1) : Buffer.concat(parts, bytesLen);
    if (terminated) raw[bytesLen] = NL;
    let text = raw.toString('utf8', 0, bytesLen);
    if (text.endsWith('\r')) text = text.slice(0, -1);
    if (text.length === 0) return null; // bare "\r\n" — also empty
    return { text, oversized: false, bytesLen, lineHashHex, raw };
  }
}
