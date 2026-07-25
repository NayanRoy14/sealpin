import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { LocalSourceResolver } from '../src/resolve/index.js';
import { scanServers } from '../src/scan/index.js';
import { server } from './helpers.js';

const SOURCE_FIXTURES = join(__dirname, 'fixtures', 'source');

describe('LocalSourceResolver', () => {
  it('resolves an explicit --source-dir and reads package.json + files', async () => {
    const resolver = new LocalSourceResolver({ dir: join(SOURCE_FIXTURES, 'malicious') });
    const src = await resolver.resolve(server({ name: 'x' }));
    expect(src).not.toBeNull();
    expect((src?.packageJson as { name?: string })?.name).toBe('mcp-server-malicious-example');
    expect(src?.files.some((f) => f.relPath === 'index.js')).toBe(true);
  });

  it('auto-detects source root from a local-path server arg', async () => {
    const resolver = new LocalSourceResolver({ cwd: join(SOURCE_FIXTURES, 'malicious') });
    const src = await resolver.resolve(server({ command: 'node', args: ['./index.js'] }));
    expect(src).not.toBeNull();
    expect(src?.files.some((f) => f.relPath === 'index.js')).toBe(true);
  });

  it('returns null for a registry-only server with no local path', async () => {
    const resolver = new LocalSourceResolver();
    const src = await resolver.resolve(server({ command: 'npx', args: ['-y', 'some-remote-pkg'] }));
    expect(src).toBeNull();
  });

  it('never treats a filesystem-root argument as source (regression)', async () => {
    // A filesystem server's "/" arg is its operating target, not its code. It
    // must not cause the whole drive to be scanned as source.
    const resolver = new LocalSourceResolver();
    const src = await resolver.resolve(
      server({ command: 'npx', args: ['-y', '@modelcontextprotocol/server-filesystem', '/'] }),
    );
    expect(src).toBeNull();
  });

  it('does not treat an arbitrary data directory (no package.json) as source', async () => {
    // The fixtures root has no package.json of its own.
    const resolver = new LocalSourceResolver();
    const src = await resolver.resolve(server({ command: 'node', args: [SOURCE_FIXTURES] }));
    expect(src).toBeNull();
  });
});

describe('scan with source resolver', () => {
  it('flags the full malicious fixture across the source rule pack', async () => {
    const servers = [server({ name: 'evil', command: 'node', args: ['index.js'] })];
    const resolver = new LocalSourceResolver({ dir: join(SOURCE_FIXTURES, 'malicious') });
    const summary = await scanServers(servers, { sourceResolver: resolver });

    const ids = new Set(summary.findings.map((f) => f.ruleId));
    expect(ids).toContain('MCP-S002'); // postinstall
    expect(ids).toContain('MCP-S003'); // command injection
    expect(ids).toContain('MCP-S004'); // env capture
    expect(ids).toContain('MCP-S005'); // egress
    expect(ids).toContain('MCP-S006'); // eval
  });

  it('produces no source findings for the clean fixture', async () => {
    const servers = [server({ name: 'good', command: 'node', args: ['index.js'] })];
    const resolver = new LocalSourceResolver({ dir: join(SOURCE_FIXTURES, 'clean') });
    const summary = await scanServers(servers, { sourceResolver: resolver });

    const sourceFindings = summary.findings.filter((f) => f.ruleId.startsWith('MCP-S'));
    expect(sourceFindings).toEqual([]);
  });
});
