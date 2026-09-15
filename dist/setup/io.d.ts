/**
 * `mcp-recorder setup` — filesystem plumbing: sniffing a JSON file's
 * indentation, writing atomically (temp file + rename, so a crash or a
 * concurrent read never sees a half-written config), and the timestamped
 * backup / sidecar files that make a wrap safe and reversible.
 */
import type { ServerEntry } from './wrap.js';
export declare const SIDECAR_SUFFIX = ".mcp-recorder-setup.json";
export interface SetupSidecar {
    version: 1;
    /** Original entry for every server name this tool has wrapped, keyed by
     * name — exactly what --undo restores. */
    wrapped: Record<string, ServerEntry>;
}
/** 2 spaces, 4 spaces, or a tab — sniffed from the first indented line.
 * Falls back to 2 spaces when there's nothing to sniff (e.g. minified JSON). */
export declare function detectIndent(raw: string): string;
/** The line ending a JSON file uses, so a rewrite keeps it: Windows-side
 * configs (the ones `setup` finds from WSL) are often CRLF. */
export declare function detectEol(raw: string): '\n' | '\r\n';
export declare function sidecarPath(configPath: string): string;
/** Strip a leading UTF-8 BOM (U+FEFF), if present, before handing text to
 * `JSON.parse` — common on config files written by Windows tools (e.g. a
 * Windows-side client config found from WSL, see src/setup/wsl.ts), which
 * `JSON.parse` otherwise rejects outright. Writes in this module never add
 * one back (`atomicWriteFile`/`writeJsonAtomic` emit plain UTF-8). */
export declare function stripBom(text: string): string;
/** Write atomically: a temp file in the same directory, then rename. */
export declare function atomicWriteFile(path: string, content: string): void;
export declare function writeJsonAtomic(path: string, value: unknown, indent: string, eol?: '\n' | '\r\n'): void;
/**
 * Copy the config to a timestamped backup before touching it. Never
 * overwrites a prior backup — on the (extremely unlikely) same-millisecond
 * collision, a short random suffix is appended instead.
 */
export declare function writeBackup(configPath: string): string;
/** undefined when no sidecar exists; throws (uncaught JSON.parse error) if
 * one exists but isn't valid JSON — callers decide how to report that. */
export declare function readSidecarStrict(configPath: string): SetupSidecar | undefined;
export declare function writeSidecarAtomic(configPath: string, sidecar: SetupSidecar, indent: string): void;
export declare function removeSidecar(configPath: string): void;
