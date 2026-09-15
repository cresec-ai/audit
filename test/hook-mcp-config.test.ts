/**
 * src/hook/mcp-config.ts — resolving a Claude Code MCP server segment (the
 * `<server>` in `mcp__<server>__<tool>`) to its origin from the MCP config
 * file Claude Code was started with. Cloud dogfood 3, surprise 2: in a cloud
 * session the hosted connectors are named by opaque UUIDs, and that file is
 * the only place the UUID maps to a vendor endpoint. Pure unit tests over
 * the fixture files in test/fixtures/mcp-config (shaped exactly like the
 * dogfood's /tmp/mcp-config-<session>.json, with fake ids); the end-to-end
 * hook path is covered in test/hook.test.ts.
 */
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, describe, expect, it } from 'vitest';
import { sha256Ref } from '../src/chain/hash.js';
import {
  CLOUD_MCP_CONFIG_GLOB,
  MCP_CONFIG_MAX_BYTES,
  originFromEntryUrl,
  resolveServerOrigin,
  simpleGlob,
} from '../src/hook/mcp-config.js';

const FIXTURES = fileURLToPath(new URL('./fixtures/mcp-config/', import.meta.url));
const CLOUD = join(FIXTURES, 'cloud-session.json');
const ALT = join(FIXTURES, 'cloud-session-alt.json');
const MALFORMED = join(FIXTURES, 'malformed.json');
const MISSING = join(FIXTURES, 'does-not-exist.json');

const CLICKUP_UUID = '47d587b8-3fb9-42e9-b596-f8b25371248c';
const GMAIL_UUID = 'ce5e992d-730d-4f07-95c8-4ba759ea3e3b';
const SESSION_ID = 'cse_01FIXTURESESSION0000AAAA';

/** Every test names its sources explicitly: never the real environment,
 *  never the real /tmp. */
const noGlob = (): string[] => [];
function fromEnv(value: string | undefined) {
  return { env: { MCP_RECORDER_MCP_CONFIG: value }, glob: noGlob };
}

const cleanups: Array<() => void> = [];
afterEach(() => {
  while (cleanups.length > 0) {
    try {
      cleanups.pop()!();
    } catch {
      /* best-effort teardown */
    }
  }
});
function tmpDir(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  cleanups.push(() => rmSync(dir, { recursive: true, force: true }));
  return dir;
}

describe('resolveServerOrigin', () => {
  it('a UUID entry resolves to the decoded mcp_url (the vendor endpoint) and its host', () => {
    expect(resolveServerOrigin(CLICKUP_UUID, fromEnv(CLOUD))).toEqual({
      url: 'https://mcp.clickup.com/mcp',
      host: 'mcp.clickup.com',
    });
  });

  it('a readable entry without mcp_url (github) resolves to its relay URL, with the session id hashed out of the path', () => {
    const origin = resolveServerOrigin('github', fromEnv(CLOUD));
    expect(origin.host).toBe('api.anthropic.com');
    expect(origin.url).toBe(`https://api.anthropic.com/v2/ccr-sessions/${sha256Ref(SESSION_ID)}/github/mcp`);
    expect(origin.url).not.toContain(SESSION_ID);
    expect(origin.url).not.toContain('cse_');
  });

  it('the vendor URL is scrubbed like the http proxy target: userinfo stripped, query string and fragment dropped', () => {
    const origin = resolveServerOrigin(GMAIL_UUID, fromEnv(CLOUD));
    expect(origin).toEqual({ url: 'https://gmail.mcp.example.test/mcp', host: 'gmail.mcp.example.test' });
    const raw = JSON.stringify(origin);
    expect(raw).not.toContain('mail-user');
    expect(raw).not.toContain('mail-pass');
    expect(raw).not.toContain('api_key');
    expect(raw).not.toContain('sk-fixture');
    expect(raw).not.toContain('frag');
  });

  it('an mcp_url that is not a URL falls back to the entry URL (the relay)', () => {
    const origin = resolveServerOrigin('broken-vendor', fromEnv(CLOUD));
    expect(origin.host).toBe('api.anthropic.com');
    expect(origin.url).toMatch(/^https:\/\/api\.anthropic\.com\/v2\/ccr-sessions\/sha256:[0-9a-f]{64}\/mcp$/);
  });

  it('a stdio entry (no url) and an unknown segment both resolve to {}', () => {
    expect(resolveServerOrigin('corp-notes', fromEnv(CLOUD))).toEqual({});
    expect(resolveServerOrigin('not-in-the-file', fromEnv(CLOUD))).toEqual({});
    expect(resolveServerOrigin('', fromEnv(CLOUD))).toEqual({});
  });

  it('nothing but url and host is ever taken from the file: no headers, no session/server ids, no tool lists', () => {
    for (const segment of [CLICKUP_UUID, GMAIL_UUID, 'github']) {
      const origin = resolveServerOrigin(segment, fromEnv(CLOUD));
      expect(Object.keys(origin).sort()).toEqual(['host', 'url']);
      const raw = JSON.stringify(origin);
      expect(raw).not.toContain(SESSION_ID);
      expect(raw).not.toContain('X-Session-UUID');
      expect(raw).not.toContain('X-MCP-Server-ID');
      expect(raw).not.toContain('63df81a5-fc81-5b12-b7fe-654a2d253da9'); // header value
      expect(raw).not.toContain('b3f9ab90-0a14-5a2c-adab-e845e0658cec'); // mcp_server_id
      expect(raw).not.toContain('toolbox_mcp_server_id');
      expect(raw).not.toContain('permission_policy');
      expect(raw).not.toContain('clickup_delete_task');
    }
  });

  it('a missing file is skipped (fail-open): {}', () => {
    expect(resolveServerOrigin(CLICKUP_UUID, fromEnv(MISSING))).toEqual({});
  });

  it('a malformed file is skipped (fail-open): {} — even though it mentions the segment', () => {
    expect(resolveServerOrigin(CLICKUP_UUID, fromEnv(MALFORMED))).toEqual({});
  });

  it('an oversized file (> 4 MiB) is never parsed; one exactly at the limit still is', () => {
    const dir = tmpDir('mcp-config-size-');
    const head = `{"mcpServers":{"${CLICKUP_UUID}":{"url":"https://mcp.clickup.com/mcp"}},"pad":"`;
    const tail = '"}';
    const atLimit = join(dir, 'at-limit.json');
    writeFileSync(atLimit, head + 'x'.repeat(MCP_CONFIG_MAX_BYTES - head.length - tail.length) + tail);
    const oversized = join(dir, 'oversized.json');
    writeFileSync(oversized, head + 'x'.repeat(MCP_CONFIG_MAX_BYTES + 1 - head.length - tail.length) + tail);

    expect(resolveServerOrigin(CLICKUP_UUID, fromEnv(atLimit)).host).toBe('mcp.clickup.com');
    expect(resolveServerOrigin(CLICKUP_UUID, fromEnv(oversized))).toEqual({});
    // A directory is not a config file either.
    expect(resolveServerOrigin(CLICKUP_UUID, fromEnv(dir))).toEqual({});
  });

  it('MCP_RECORDER_MCP_CONFIG wins over the cloud glob, which is then not consulted at all', () => {
    const globCalls: string[] = [];
    const glob = (pattern: string): string[] => {
      globCalls.push(pattern);
      return [ALT];
    };
    // env set: resolved from the env file (mcp.clickup.com), glob untouched
    expect(resolveServerOrigin(CLICKUP_UUID, { env: { MCP_RECORDER_MCP_CONFIG: CLOUD }, glob }).host).toBe(
      'mcp.clickup.com',
    );
    expect(globCalls).toEqual([]);
    // env unset (or blank): the glob for /tmp/mcp-config-*.json is what's consulted
    expect(resolveServerOrigin(CLICKUP_UUID, { env: {}, glob }).host).toBe('alt.clickup.example.test');
    expect(resolveServerOrigin(CLICKUP_UUID, { env: { MCP_RECORDER_MCP_CONFIG: '  ' }, glob }).host).toBe(
      'alt.clickup.example.test',
    );
    expect(globCalls).toEqual([CLOUD_MCP_CONFIG_GLOB, CLOUD_MCP_CONFIG_GLOB]);
  });

  it('comma-separated MCP_RECORDER_MCP_CONFIG paths are tried in order; the first file holding the segment wins', () => {
    expect(resolveServerOrigin(CLICKUP_UUID, fromEnv(`${MISSING},${CLOUD}`)).host).toBe('mcp.clickup.com');
    expect(resolveServerOrigin(CLICKUP_UUID, fromEnv(`${MALFORMED}, ${ALT}`)).host).toBe('alt.clickup.example.test');
    expect(resolveServerOrigin(CLICKUP_UUID, fromEnv(`${ALT},${CLOUD}`)).host).toBe('alt.clickup.example.test');
    expect(resolveServerOrigin(CLICKUP_UUID, fromEnv(`${CLOUD},${ALT}`)).host).toBe('mcp.clickup.com');
    // A segment only the second file knows still resolves.
    expect(resolveServerOrigin('only-in-alt', fromEnv(`${CLOUD},${ALT}`)).host).toBe('only-in-alt.example.test');
  });

  it('segment lookups are own-property only (a `constructor` segment never resolves through the prototype)', () => {
    const readFile = (): string => '{"mcpServers":{"x":{"url":"https://a.example.test/b"}},"note":"constructor"}';
    expect(resolveServerOrigin('constructor', { env: {}, glob: () => ['whatever'], readFile })).toEqual({});
    expect(resolveServerOrigin('x', { env: {}, glob: () => ['whatever'], readFile }).host).toBe('a.example.test');
  });

  it('never throws: a reader or a glob that throws just yields {}', () => {
    const boom = (): never => {
      throw new Error('boom');
    };
    expect(resolveServerOrigin(CLICKUP_UUID, { env: {}, glob: boom })).toEqual({});
    expect(resolveServerOrigin(CLICKUP_UUID, { env: {}, glob: () => ['x'], readFile: boom })).toEqual({});
    expect(resolveServerOrigin(CLICKUP_UUID, { env: { MCP_RECORDER_MCP_CONFIG: CLOUD }, readFile: boom })).toEqual(
      {},
    );
  });
});

describe('originFromEntryUrl', () => {
  it('non-http(s) schemes yield undefined; opaque path segments (UUIDs, session ids) are hashed in place', () => {
    expect(originFromEntryUrl('ftp://host/x')).toBeUndefined();
    expect(originFromEntryUrl('not a url')).toBeUndefined();
    const origin = originFromEntryUrl(`https://relay.example.test/v1/${CLICKUP_UUID}/${SESSION_ID}/mcp?token=abc#frag`);
    expect(origin).toEqual({
      host: 'relay.example.test',
      url: `https://relay.example.test/v1/${sha256Ref(CLICKUP_UUID)}/${sha256Ref(SESSION_ID)}/mcp`,
    });
  });

  it('an mcp_url with a non-http scheme falls back to the relay URL', () => {
    const origin = originFromEntryUrl('https://relay.example.test/mcp?mcp_url=ftp%3A%2F%2Fvendor.example.test%2Fx');
    expect(origin).toEqual({ host: 'relay.example.test', url: 'https://relay.example.test/mcp' });
  });
});

describe('simpleGlob', () => {
  it('expands a single-star basename pattern (sorted), returns a literal path as-is, and nothing for an unreadable dir', () => {
    const dir = tmpDir('mcp-config-glob-');
    for (const name of ['mcp-config-b.json', 'mcp-config-a.json', 'other.json', 'mcp-config-c.txt', 'mcp-config-']) {
      writeFileSync(join(dir, name), '{}');
    }
    mkdirSync(join(dir, 'mcp-config-dir.json')); // a directory with a matching name is listed too; reading it is what skips it
    expect(simpleGlob(join(dir, 'mcp-config-*.json'))).toEqual([
      join(dir, 'mcp-config-a.json'),
      join(dir, 'mcp-config-b.json'),
      join(dir, 'mcp-config-dir.json'),
    ]);
    expect(simpleGlob(join(dir, 'nope', 'mcp-config-*.json'))).toEqual([]);
    expect(simpleGlob(join(dir, 'literal.json'))).toEqual([join(dir, 'literal.json')]);
    expect(simpleGlob(join(dir, '*', 'x-*.json'))).toEqual([]); // a star in a directory component is unsupported
  });
});
