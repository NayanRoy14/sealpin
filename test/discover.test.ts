import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { discoverClaudeDesktop } from '../src/discover/claude-desktop.js';
import { discoverClaudeCode } from '../src/discover/claude-code.js';
import { discoverCursor } from '../src/discover/cursor.js';
import { discoverServers } from '../src/discover/index.js';
import { normalize } from '../src/discover/normalize.js';

const FIXTURES = join(__dirname, 'fixtures', 'configs');

describe('normalize', () => {
  it('fills in defaults for missing args/env', () => {
    const raw = { mcpServers: { foo: { command: 'bar' } } };
    const result = normalize(raw, 'claude-desktop', '/fake/path.json');
    expect(result).toEqual([
      { name: 'foo', command: 'bar', args: [], env: {}, client: 'claude-desktop', configPath: '/fake/path.json' },
    ]);
  });

  it('rejects a config missing the command field', () => {
    const raw = { mcpServers: { foo: {} } };
    expect(() => normalize(raw, 'claude-desktop', '/fake/path.json')).toThrow();
  });
});

describe('discoverClaudeDesktop', () => {
  it('parses a fixture config into normalized servers', async () => {
    const servers = await discoverClaudeDesktop(join(FIXTURES, 'claude-desktop.json'));
    expect(servers).toHaveLength(2);
    const filesystem = servers.find((s) => s.name === 'filesystem');
    expect(filesystem?.client).toBe('claude-desktop');
    expect(filesystem?.args).toContain('@modelcontextprotocol/server-filesystem');
    const github = servers.find((s) => s.name === 'github');
    expect(github?.env['GITHUB_TOKEN']).toBe('ghp_examplenotreal');
  });

  it('returns an empty array when the config file does not exist', async () => {
    const servers = await discoverClaudeDesktop(join(FIXTURES, 'does-not-exist.json'));
    expect(servers).toEqual([]);
  });
});

const NO_USER_CONFIG = join(FIXTURES, 'does-not-exist.json');

describe('discoverClaudeCode', () => {
  it('reads .mcp.json from the given project directory', async () => {
    const servers = await discoverClaudeCode(join(FIXTURES, 'claude-code'), NO_USER_CONFIG);
    expect(servers).toHaveLength(1);
    expect(servers[0]?.name).toBe('linear');
    expect(servers[0]?.client).toBe('claude-code');
  });

  it('returns an empty array when no .mcp.json is present', async () => {
    const servers = await discoverClaudeCode(FIXTURES, NO_USER_CONFIG);
    expect(servers).toEqual([]);
  });
});

describe('discoverCursor', () => {
  it('reads .cursor/mcp.json from the given project directory', async () => {
    const servers = await discoverCursor(join(FIXTURES, 'cursor-project'), NO_USER_CONFIG);
    expect(servers).toHaveLength(1);
    expect(servers[0]?.name).toBe('postgres');
    expect(servers[0]?.client).toBe('cursor');
    expect(servers[0]?.env['DATABASE_URL']).toBeDefined();
  });
});

describe('discoverServers resilience', () => {
  it('isolates a malformed config: warns and still returns other clients servers', async () => {
    const cwd = join(__dirname, 'fixtures', 'resilience'); // has a malformed .mcp.json and a valid .cursor/mcp.json
    const warnings: string[] = [];
    const servers = await discoverServers({ cwd, onWarn: (client, msg) => warnings.push(`${client}: ${msg}`) });

    // the malformed claude-code config is reported...
    expect(warnings.some((w) => w.startsWith('claude-code:'))).toBe(true);
    // ...but the valid cursor config is still discovered
    expect(servers.some((s) => s.name === 'valid-cursor-server')).toBe(true);
  });
});
