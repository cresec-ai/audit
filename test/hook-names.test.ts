/**
 * src/hook/names.ts — splitting a Claude Code hook `tool_name` and building
 * the policy alias. The alias host rule matters for policy safety: the host
 * comes from an agent-writable file (see src/hook/mcp-config.ts, TRUST), so
 * an alias must never be able to spell a raw `mcp__<server>__<tool>` name.
 */
import { describe, expect, it } from 'vitest';
import { POLICY_ALIAS_HOST_MAX_LEN, hostAliasToolName, parseToolName } from '../src/hook/names.js';

describe('parseToolName', () => {
  it('splits mcp__<server>__<tool> at the first "__" and leaves built-ins whole', () => {
    expect(parseToolName('mcp__ClickUp__clickup_get_task')).toEqual({
      isMcp: true,
      server: 'ClickUp',
      tool: 'clickup_get_task',
    });
    expect(parseToolName('mcp__47d587b8-3fb9-42e9-b596-f8b25371248c__clickup_get_list')).toEqual({
      isMcp: true,
      server: '47d587b8-3fb9-42e9-b596-f8b25371248c',
      tool: 'clickup_get_list',
    });
    expect(parseToolName('mcp__plugin_my-plugin_db__query')).toEqual({ isMcp: true, server: 'plugin_my-plugin_db', tool: 'query' });
    expect(parseToolName('Bash')).toEqual({ isMcp: false, server: 'claude-code', tool: 'Bash' });
  });
});

describe('hostAliasToolName', () => {
  it('builds the alias for a plausible dotted hostname', () => {
    expect(hostAliasToolName('mcp.clickup.com', 'clickup_get_list')).toBe('mcp__mcp.clickup.com__clickup_get_list');
    expect(hostAliasToolName('api.anthropic.com', 'get_me')).toBe('mcp__api.anthropic.com__get_me');
    expect(hostAliasToolName('xn--bcher-kva.example', 't')).toBe('mcp__xn--bcher-kva.example__t'); // an IDN, punycoded by URL parsing
    expect(hostAliasToolName('127.0.0.1', 't')).toBe('mcp__127.0.0.1__t');
  });

  it('refuses a host that could collide with the raw mcp__<server>__<tool> grammar: a bare label, or anything with "_" / "__"', () => {
    // A forged mcp_url of https://github/mcp would otherwise alias a ClickUp
    // UUID tool to mcp__github__clickup_delete_task (review E1).
    expect(hostAliasToolName('github', 'clickup_delete_task')).toBeUndefined();
    expect(hostAliasToolName('localhost', 't')).toBeUndefined();
    // ...and https://github__pull_request_read/mcp would spell a second "__"
    // into the alias (review E1b).
    expect(hostAliasToolName('github__pull_request_read', 'clickup_delete_task')).toBeUndefined();
    expect(hostAliasToolName('my_host.example', 't')).toBeUndefined();
    expect(hostAliasToolName('a__b.example', 't')).toBeUndefined();
  });

  it('refuses uppercase, empty labels, IPv6 literals, and hosts over the DNS length limit', () => {
    expect(hostAliasToolName('MCP.clickup.com', 't')).toBeUndefined();
    expect(hostAliasToolName('.example', 't')).toBeUndefined();
    expect(hostAliasToolName('example.', 't')).toBeUndefined();
    expect(hostAliasToolName('a..b', 't')).toBeUndefined();
    expect(hostAliasToolName('[::1]', 't')).toBeUndefined();
    expect(hostAliasToolName('', 't')).toBeUndefined();
    const longest = `${'a'.repeat(POLICY_ALIAS_HOST_MAX_LEN - 8)}.example`;
    expect(longest).toHaveLength(POLICY_ALIAS_HOST_MAX_LEN);
    expect(hostAliasToolName(longest, 't')).toBe(`mcp__${longest}__t`);
    expect(hostAliasToolName(`a${longest}`, 't')).toBeUndefined();
  });

  it('is linear on a pathological host (no catastrophic backtracking)', () => {
    const t0 = Date.now();
    expect(hostAliasToolName(`${'a.'.repeat(50_000)}a_`, 't')).toBeUndefined();
    expect(hostAliasToolName('a'.repeat(300_000), 't')).toBeUndefined();
    expect(Date.now() - t0).toBeLessThan(2_000);
  });
});
