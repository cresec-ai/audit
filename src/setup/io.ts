/**
 * `mcp-recorder setup` — filesystem plumbing: sniffing a JSON file's
 * indentation, writing atomically (temp file + rename, so a crash or a
 * concurrent read never sees a half-written config), and the timestamped
 * backup / sidecar files that make a wrap safe and reversible.
 */

import { randomBytes } from 'node:crypto';
import { copyFileSync, existsSync, readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import type { ServerEntry } from './wrap.js';

export const SIDECAR_SUFFIX = '.mcp-recorder-setup.json';

export interface SetupSidecar {
  version: 1;
  /** Original entry for every server name this tool has wrapped, keyed by
   * name — exactly what --undo restores. */
  wrapped: Record<string, ServerEntry>;
}

/** 2 spaces, 4 spaces, or a tab — sniffed from the first indented line.
 * Falls back to 2 spaces when there's nothing to sniff (e.g. minified JSON). */
export function detectIndent(raw: string): string {
  const match = /\n([ \t]+)\S/.exec(raw);
  if (match === null) return '  ';
  const indent = match[1]!;
  if (indent.includes('\t')) return '\t';
  return indent.length >= 4 ? '    ' : '  ';
}

export function sidecarPath(configPath: string): string {
  return configPath + SIDECAR_SUFFIX;
}

function backupPathFor(configPath: string, now: Date): string {
  return `${configPath}.bak-${now.toISOString().replace(/:/g, '-')}`;
}

/** Write atomically: a temp file in the same directory, then rename. */
export function atomicWriteFile(path: string, content: string): void {
  const tmp = `${path}.tmp-${randomBytes(6).toString('hex')}`;
  writeFileSync(tmp, content, 'utf8');
  renameSync(tmp, path);
}

export function writeJsonAtomic(path: string, value: unknown, indent: string): void {
  atomicWriteFile(path, JSON.stringify(value, null, indent) + '\n');
}

/**
 * Copy the config to a timestamped backup before touching it. Never
 * overwrites a prior backup — on the (extremely unlikely) same-millisecond
 * collision, a short random suffix is appended instead.
 */
export function writeBackup(configPath: string): string {
  let dest = backupPathFor(configPath, new Date());
  if (existsSync(dest)) dest = `${dest}-${randomBytes(3).toString('hex')}`;
  copyFileSync(configPath, dest);
  return dest;
}

/** undefined when no sidecar exists; throws (uncaught JSON.parse error) if
 * one exists but isn't valid JSON — callers decide how to report that. */
export function readSidecarStrict(configPath: string): SetupSidecar | undefined {
  const p = sidecarPath(configPath);
  if (!existsSync(p)) return undefined;
  return JSON.parse(readFileSync(p, 'utf8')) as SetupSidecar;
}

export function writeSidecarAtomic(configPath: string, sidecar: SetupSidecar, indent: string): void {
  writeJsonAtomic(sidecarPath(configPath), sidecar, indent);
}

export function removeSidecar(configPath: string): void {
  rmSync(sidecarPath(configPath), { force: true });
}
