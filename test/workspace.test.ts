import { describe, expect, it } from 'vitest';
import { analyzeWorkspace } from '../src/capabilities/index.js';
import type { ScanContext } from '../src/types/rule.js';
import { manifest, server, tool } from './helpers.js';

const CFG = 'shared-config.json';

/** Build a ScanContext for a server in the shared context. */
function ctx(name: string, tools: Parameters<typeof tool>[] | ReturnType<typeof tool>[], cfg: Partial<Parameters<typeof server>[0]> = {}): ScanContext {
  const s = server({ name, configPath: CFG, ...cfg });
  const m = manifest(name, tools as ReturnType<typeof tool>[]);
  return { server: s, manifest: m, workspace: [m] };
}

const webServer = () => ctx('web-search', [tool('fetch', 'Fetch a URL and return its contents.')]);
const fsRootServer = () => ctx('filesystem', [], { command: 'npx', args: ['-y', '@modelcontextprotocol/server-filesystem', '/'] });
const mailServer = () => ctx('mailer', [tool('send_email', 'Send an email to a recipient.')]);
const shellServer = () => ctx('shell', [], { command: 'npx', args: ['mcp-server-shell'] });
const calcServer = () => ctx('calc', [tool('add', 'Add two numbers.')]);

function ids(findings: { ruleId: string }[]): Set<string> {
  return new Set(findings.map((f) => f.ruleId));
}

describe('MCP-X001 lethal trifecta', () => {
  it('fires when untrusted-content + private-data + exfil servers share a context', () => {
    const findings = analyzeWorkspace([webServer(), fsRootServer(), mailServer()]);
    expect(ids(findings)).toContain('MCP-X001');
    const x1 = findings.find((f) => f.ruleId === 'MCP-X001');
    // names the untrusted-content entry point and the private-data server
    expect(x1?.message).toContain('web-search');
    expect(x1?.message).toContain('filesystem');
  });

  it('does NOT fire without an untrusted-content source', () => {
    // private data + exfil, but nothing ingesting untrusted content
    const findings = analyzeWorkspace([fsRootServer(), mailServer(), calcServer()]);
    expect(ids(findings)).not.toContain('MCP-X001');
  });

  it('does NOT fire for a lone benign server', () => {
    expect(analyzeWorkspace([calcServer()])).toEqual([]);
  });

  it('does NOT fire across servers in different config contexts', () => {
    const web = ctx('web-search', [tool('fetch', 'Fetch a URL.')], { configPath: 'a.json' });
    const fs = ctx('filesystem', [], { configPath: 'b.json', command: 'npx', args: ['@modelcontextprotocol/server-filesystem', '/'] });
    const mail = ctx('mailer', [tool('send_email', 'Send email.')], { configPath: 'c.json' });
    expect(ids(analyzeWorkspace([web, fs, mail]))).not.toContain('MCP-X001');
  });
});

describe('MCP-X002 untrusted content reaches exec', () => {
  it('fires when an untrusted-content server and a shell server share a context', () => {
    const findings = analyzeWorkspace([webServer(), shellServer()]);
    expect(ids(findings)).toContain('MCP-X002');
  });

  it('does NOT fire without a command-execution capability', () => {
    expect(ids(analyzeWorkspace([webServer(), calcServer()]))).not.toContain('MCP-X002');
  });
});

describe('MCP-X003 confused deputy', () => {
  it('fires for a single server that ingests untrusted content and holds a credential', () => {
    const agent = ctx('agent', [tool('fetch', 'Fetch a URL and return contents.')], { env: { API_TOKEN: 'sk-' + 'a'.repeat(24) } });
    expect(ids(analyzeWorkspace([agent]))).toContain('MCP-X003');
  });

  it('does NOT fire when untrusted content and credential are on different servers', () => {
    const web = ctx('web', [tool('fetch', 'Fetch a URL.')]);
    const gh = ctx('github', [], { env: { GITHUB_TOKEN: 'ghp_' + 'a'.repeat(36) } });
    expect(ids(analyzeWorkspace([web, gh]))).not.toContain('MCP-X003');
  });
});
