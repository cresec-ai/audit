/**
 * `mcp-recorder setup` — filesystem plumbing: sniffing a JSON file's
 * indentation, writing atomically (temp file + rename, so a crash or a
 * concurrent read never sees a half-written config), and the timestamped
 * backup / sidecar files that make a wrap safe and reversible.
 */
import { randomBytes } from 'node:crypto';
import { copyFileSync, existsSync, readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs';
export const SIDECAR_SUFFIX = '.mcp-recorder-setup.json';
/** 2 spaces, 4 spaces, or a tab — sniffed from the first indented line.
 * Falls back to 2 spaces when there's nothing to sniff (e.g. minified JSON). */
export function detectIndent(raw) {
    const match = /\n([ \t]+)\S/.exec(raw);
    if (match === null)
        return '  ';
    const indent = match[1];
    if (indent.includes('\t'))
        return '\t';
    return indent.length >= 4 ? '    ' : '  ';
}
/** The line ending a JSON file uses, so a rewrite keeps it: Windows-side
 * configs (the ones `setup` finds from WSL) are often CRLF. */
export function detectEol(raw) {
    return raw.includes('\r\n') ? '\r\n' : '\n';
}
export function sidecarPath(configPath) {
    return configPath + SIDECAR_SUFFIX;
}
/** Strip a leading UTF-8 BOM (U+FEFF), if present, before handing text to
 * `JSON.parse` — common on config files written by Windows tools (e.g. a
 * Windows-side client config found from WSL, see src/setup/wsl.ts), which
 * `JSON.parse` otherwise rejects outright. Writes in this module never add
 * one back (`atomicWriteFile`/`writeJsonAtomic` emit plain UTF-8). */
export function stripBom(text) {
    return text.charCodeAt(0) === 0xfeff ? text.slice(1) : text;
}
function backupPathFor(configPath, now) {
    return `${configPath}.bak-${now.toISOString().replace(/:/g, '-')}`;
}
/** Write atomically: a temp file in the same directory, then rename. */
export function atomicWriteFile(path, content) {
    const tmp = `${path}.tmp-${randomBytes(6).toString('hex')}`;
    writeFileSync(tmp, content, 'utf8');
    renameSync(tmp, path);
}
export function writeJsonAtomic(path, value, indent, eol = '\n') {
    atomicWriteFile(path, JSON.stringify(value, null, indent).split('\n').join(eol) + eol);
}
/**
 * Copy the config to a timestamped backup before touching it. Never
 * overwrites a prior backup — on the (extremely unlikely) same-millisecond
 * collision, a short random suffix is appended instead.
 */
export function writeBackup(configPath) {
    let dest = backupPathFor(configPath, new Date());
    if (existsSync(dest))
        dest = `${dest}-${randomBytes(3).toString('hex')}`;
    copyFileSync(configPath, dest);
    return dest;
}
/** undefined when no sidecar exists; throws (uncaught JSON.parse error) if
 * one exists but isn't valid JSON — callers decide how to report that. */
export function readSidecarStrict(configPath) {
    const p = sidecarPath(configPath);
    if (!existsSync(p))
        return undefined;
    return JSON.parse(stripBom(readFileSync(p, 'utf8')));
}
export function writeSidecarAtomic(configPath, sidecar, indent) {
    writeJsonAtomic(sidecarPath(configPath), sidecar, indent);
}
export function removeSidecar(configPath) {
    rmSync(sidecarPath(configPath), { force: true });
}
//# sourceMappingURL=io.js.map