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
  MAX_ORIGIN_URL_LEN,
  MCP_CONFIG_MAX_BYTES,
  originFromEntryUrl,
  resolveServerOrigin,
  simpleGlob,
} from '../src/hook/mcp-config.js';

const FIXTURES = fileURLToPath(new URL('./fixtures/mcp-config/', import.meta.url));
const CLOUD = join(FIXTURES, 'cloud-session.json');
/** The OTHER convention: a config keyed by FRIENDLY connector name, with
 *  friendly tool names — a local session, and the cloud session this test
 *  was written in (`ClickUp`, `Gmail`, `Claude_Code_Remote`, `github`). */
const FRIENDLY = join(FIXTURES, 'friendly-session.json');
const ALT = join(FIXTURES, 'cloud-session-alt.json');
const MALFORMED = join(FIXTURES, 'malformed.json');
const MISSING = join(FIXTURES, 'does-not-exist.json');

const CLICKUP_UUID = '47d587b8-3fb9-42e9-b596-f8b25371248c';
const GMAIL_UUID = 'ce5e992d-730d-4f07-95c8-4ba759ea3e3b';
const SESSION_ID = 'cse_01FIXTURESESSION0000AAAA';
const FRIENDLY_SESSION_ID = 'cse_01FRIENDLYSESSION0000DDDD';

/** Every test names its sources explicitly: never the real environment,
 *  never the real /tmp. */
const noGlob = (): string[] => [];
function fromEnv(value: string | undefined) {
  return { env: { MCP_RECORDER_MCP_CONFIG: value }, glob: noGlob };
}
/** Resolution as the hook actually asks for it: both halves of
 *  `mcp__<server>__<tool>` (see `parseToolName`). */
function fromEnvTool(value: string | undefined, tool: string) {
  return { env: { MCP_RECORDER_MCP_CONFIG: value }, glob: noGlob, tool };
}
/** One in-memory config file: no real /tmp, no real environment. */
function fromText(text: string, tool: string) {
  return { env: {}, glob: (): string[] => ['config.json'], readFile: (): string => text, tool };
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

/* ---------- route 2: the declared-tool fallback (cloud dogfood 4) --------- */

describe('resolveServerOrigin (declared-tool fallback)', () => {
  it('cloud dogfood 4: a UUID-keyed file resolves a FRIENDLY segment through the entry that declares the tool', () => {
    // Dogfood 4's session: the config was keyed by UUID while Claude Code
    // handed the hook `mcp__ClickUp__clickup_filter_tasks`. The key lookup
    // misses (that much is unchanged)...
    expect(resolveServerOrigin('ClickUp', fromEnv(CLOUD))).toEqual({});
    // ...and the tool name is what maps the call to its vendor.
    expect(resolveServerOrigin('ClickUp', fromEnvTool(CLOUD, 'clickup_filter_tasks'))).toEqual({
      url: 'https://mcp.clickup.com/mcp',
      host: 'mcp.clickup.com',
    });
    // That run's other denied tool, and another connector's tool in the same
    // file, each resolve to their own vendor.
    expect(resolveServerOrigin('ClickUp', fromEnvTool(CLOUD, 'clickup_get_workspace_members')).host).toBe(
      'mcp.clickup.com',
    );
    expect(resolveServerOrigin('Gmail', fromEnvTool(CLOUD, 'send_message')).host).toBe('gmail.mcp.example.test');
    // Still nothing but url and host is taken from the file.
    const origin = resolveServerOrigin('ClickUp', fromEnvTool(CLOUD, 'clickup_filter_tasks'));
    expect(Object.keys(origin).sort()).toEqual(['host', 'url']);
    const raw = JSON.stringify(origin);
    expect(raw).not.toContain(SESSION_ID);
    expect(raw).not.toContain('permission_policy');
    expect(raw).not.toContain('clickup_filter_tasks');
  });

  it('a friendly-keyed file (a local session, and the cloud session this was written in) still resolves by key', () => {
    expect(resolveServerOrigin('ClickUp', fromEnvTool(FRIENDLY, 'clickup_filter_tasks'))).toEqual({
      url: 'https://mcp.clickup.com/mcp',
      host: 'mcp.clickup.com',
    });
    expect(resolveServerOrigin('Gmail', fromEnvTool(FRIENDLY, 'send_message')).host).toBe('gmail.mcp.example.test');
    expect(resolveServerOrigin('Claude_Code_Remote', fromEnvTool(FRIENDLY, 'create_session')).host).toBe(
      'ccr.mcp.example.test',
    );
    // `github` carries `tools: null` and no `mcp_url`: the key route still
    // gives it its relay URL, and route 2 can never match it.
    expect(resolveServerOrigin('github', fromEnvTool(FRIENDLY, 'get_me')).url).toBe(
      `https://api.anthropic.com/v2/ccr-sessions/${sha256Ref(FRIENDLY_SESSION_ID)}/github/mcp`,
    );
    expect(resolveServerOrigin('whatever', fromEnvTool(FRIENDLY, 'get_me'))).toEqual({});
    // The key stays authoritative when the two routes disagree: `a` is keyed
    // by the segment, `b` declares the tool.
    const text = JSON.stringify({
      mcpServers: {
        a: { url: 'https://by-key.example.test/mcp' },
        b: { url: 'https://by-tool.example.test/mcp', tools: [{ name: 't' }] },
      },
    });
    expect(resolveServerOrigin('a', fromText(text, 't')).host).toBe('by-key.example.test');
    // ...including when the keyed entry has no usable URL of its own: an
    // entry Claude Code names IS the server, so there is nothing to fall
    // back to for it.
    const stdioKeyed = JSON.stringify({
      mcpServers: {
        a: { command: 'npx', type: 'stdio', tools: [{ name: 't' }] },
        b: { url: 'https://by-tool.example.test/mcp', tools: [{ name: 't' }] },
      },
    });
    expect(resolveServerOrigin('a', fromText(stdioKeyed, 't'))).toEqual({});
  });

  it('a tool TWO entries declare, and a tool NO entry declares, both resolve to nothing', () => {
    const twice = JSON.stringify({
      mcpServers: {
        one: { url: 'https://one.example.test/mcp', tools: [{ name: 'shared_tool' }] },
        two: { url: 'https://two.example.test/mcp', tools: [{ name: 'shared_tool' }] },
      },
    });
    expect(resolveServerOrigin('ClickUp', fromText(twice, 'shared_tool'))).toEqual({});
    // Ambiguity is counted over DECLARATIONS, not over usable URLs: a file
    // cannot resolve its own ambiguity by leaving a `url` off one of them.
    const twiceOneUrl = JSON.stringify({
      mcpServers: {
        one: { url: 'https://one.example.test/mcp', tools: [{ name: 'shared_tool' }] },
        two: { tools: [{ name: 'shared_tool' }] },
      },
    });
    expect(resolveServerOrigin('ClickUp', fromText(twiceOneUrl, 'shared_tool'))).toEqual({});
    // Nobody declares it: nothing — never "the first entry".
    expect(resolveServerOrigin('ClickUp', fromText(twice, 'other_tool'))).toEqual({});
    expect(resolveServerOrigin('ClickUp', fromEnvTool(CLOUD, 'not_a_declared_tool'))).toEqual({});
    // A declared tool whose entry has no usable URL: no url, no alias.
    const stdio = JSON.stringify({
      mcpServers: { 'corp-notes': { command: 'npx', type: 'stdio', tools: [{ name: 'read_note' }] } },
    });
    expect(resolveServerOrigin('corp-notes-renamed', fromText(stdio, 'read_note'))).toEqual({});
  });

  it('`tools: null` and every malformed `tools` shape resolve to nothing, without throwing', () => {
    const shapes: unknown[] = [
      null,
      undefined,
      'clickup_filter_tasks',
      42,
      { name: 'clickup_filter_tasks' },
      [null, 'clickup_filter_tasks', 42, []],
      [{ name: 42 }, { name: null }, { nome: 'clickup_filter_tasks' }, {}],
    ];
    for (const tools of shapes) {
      const text = JSON.stringify({ mcpServers: { anything: { url: 'https://wrong.example.test/mcp', tools } } });
      expect(resolveServerOrigin('ClickUp', fromText(text, 'clickup_filter_tasks'))).toEqual({});
    }
    // A declaration with no own `name` never inherits one from the prototype
    // chain, so no prototype-named tool can ever match it.
    const empty = JSON.stringify({ mcpServers: { anything: { url: 'https://wrong.example.test/mcp', tools: [{}] } } });
    for (const tool of ['__proto__', 'constructor', 'toString', 'valueOf', 'hasOwnProperty']) {
      expect(resolveServerOrigin('ClickUp', fromText(empty, tool))).toEqual({});
    }
    // A `__proto__` NAME is just a string, and it matches nothing else.
    const proto = JSON.stringify({
      mcpServers: { anything: { url: 'https://wrong.example.test/mcp', tools: [{ name: '__proto__' }] } },
    });
    for (const tool of ['clickup_filter_tasks', 'constructor', 'toString']) {
      expect(resolveServerOrigin('ClickUp', fromText(proto, tool))).toEqual({});
    }
  });

  it('the exact key wins over a declared-tool match even when the match sits in an EARLIER file', () => {
    // /tmp holds one mcp-config-<session>.json per live session, so several
    // files can match the glob: another session's file must never out-rank
    // this session's key.
    const byTool = JSON.stringify({
      mcpServers: { 'other-session-uuid': { url: 'https://other.example.test/mcp', tools: [{ name: 'shared_tool' }] } },
    });
    const byKey = JSON.stringify({ mcpServers: { ClickUp: { url: 'https://mine.example.test/mcp' } } });
    const files: Record<string, string> = { '/first.json': byTool, '/second.json': byKey };
    const opts = {
      env: {},
      glob: (): string[] => Object.keys(files),
      readFile: (p: string): string | undefined => files[p],
      tool: 'shared_tool',
    };
    expect(resolveServerOrigin('ClickUp', opts).host).toBe('mine.example.test');
    // With no file keying the segment at all, the fallback resolves — in file order.
    delete files['/second.json'];
    expect(resolveServerOrigin('ClickUp', opts).host).toBe('other.example.test');
  });

  it('never throws through the fallback either: a throwing reader, a truncated file or an empty tool yields {}', () => {
    const boom = (): never => {
      throw new Error('boom');
    };
    const tool = 'clickup_filter_tasks';
    expect(resolveServerOrigin('ClickUp', { env: {}, glob: () => ['x'], readFile: boom, tool })).toEqual({});
    expect(resolveServerOrigin('ClickUp', { env: {}, glob: boom, tool })).toEqual({});
    expect(resolveServerOrigin('ClickUp', fromEnvTool(MALFORMED, tool))).toEqual({});
    expect(resolveServerOrigin('ClickUp', fromEnvTool(MISSING, tool))).toEqual({});
    const truncated = `{"mcpServers":{"a":{"url":"https://x.example.test/mcp","tools":[{"name":"${tool}"}]`;
    expect(resolveServerOrigin('ClickUp', fromText(truncated, tool))).toEqual({});
    expect(resolveServerOrigin('ClickUp', fromText('{"mcpServers":[]}', tool))).toEqual({});
    expect(resolveServerOrigin('ClickUp', fromText('null', tool))).toEqual({});
    // Neither half of the name may be empty.
    expect(resolveServerOrigin('', fromEnvTool(CLOUD, tool))).toEqual({});
    expect(resolveServerOrigin('ClickUp', fromEnvTool(CLOUD, ''))).toEqual({});
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

  it('a path segment that is not a short vocabulary token is hashed: no readable text from the (agent-writable) file reaches the store', () => {
    const free = 'readable-free-text-readable-free-text-readable-free-text';
    const origin = originFromEntryUrl(`https://relay.example.test/mcp?mcp_url=${encodeURIComponent(`https://vendor.example.test/v2/${free}/some%20words/end`)}`);
    expect(origin).toEqual({
      host: 'vendor.example.test',
      url: `https://vendor.example.test/v2/${sha256Ref(free)}/${sha256Ref('some%20words')}/end`,
    });
    // Vocabulary tokens (short, [A-Za-z0-9._-]) survive: that is what the real relay paths are made of.
    expect(originFromEntryUrl('https://api.anthropic.com/v2/ccr-sessions/x/github/mcp')?.url).toBe(
      'https://api.anthropic.com/v2/ccr-sessions/x/github/mcp',
    );
    // The 32-char boundary, with a token that is not hex-shaped (a 32+ hex
    // run is already a "digest" to looksSecret and hashed on that ground).
    const at32 = 'segment-'.repeat(4);
    expect(at32).toHaveLength(32);
    expect(originFromEntryUrl(`https://h.example/${at32}`)?.url).toBe(`https://h.example/${at32}`);
    expect(originFromEntryUrl(`https://h.example/${at32}s`)?.url).toBe(`https://h.example/${sha256Ref(`${at32}s`)}`);
  });

  it('a scrubbed URL over the length cap is not usable at all — url and host go together (no url, no alias) — and an oversized mcp_url falls back to the relay', () => {
    const longHost = `${'h'.repeat(MAX_ORIGIN_URL_LEN)}.example`;
    expect(originFromEntryUrl(`https://${longHost}/mcp`)).toBeUndefined();
    // Hashing keeps it in step: sha256 refs are 71 chars each, so enough
    // free-text segments push a short URL past the cap after scrubbing.
    const manySegments = Array.from({ length: 40 }, (_, i) => `free text segment ${i}`).map(encodeURIComponent).join('/');
    expect(originFromEntryUrl(`https://h.example/${manySegments}`)).toBeUndefined();
    const relay = `https://relay.example.test/mcp?mcp_url=${encodeURIComponent(`https://${longHost}/mcp`)}`;
    expect(originFromEntryUrl(relay)).toEqual({ host: 'relay.example.test', url: 'https://relay.example.test/mcp' });
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
