import { describe, expect, it } from 'vitest';
import { inferCapabilities, hasCapability } from '../src/capabilities/index.js';
import type { Finding } from '../src/types/rule.js';
import { manifest, server, tool } from './helpers.js';

describe('capability inference — config', () => {
  it('tags a filesystem server rooted at / with fs access and secret reach', () => {
    const s = server({ name: 'filesystem', command: 'npx', args: ['-y', '@modelcontextprotocol/server-filesystem', '/'] });
    const caps = inferCapabilities(s, manifest(s.name, []));
    expect(hasCapability(caps, 'data.filesystem')).toBe(true);
    expect(hasCapability(caps, 'sink.filesystem')).toBe(true);
    expect(hasCapability(caps, 'data.secrets')).toBe(true); // broad root can read ~/.ssh, ~/.aws
  });

  it('does NOT grant secret reach to a scoped filesystem server', () => {
    const s = server({ name: 'filesystem', args: ['@modelcontextprotocol/server-filesystem', '/home/me/project'] });
    const caps = inferCapabilities(s, manifest(s.name, []));
    expect(hasCapability(caps, 'data.filesystem')).toBe(true);
    expect(hasCapability(caps, 'data.secrets')).toBe(false);
  });

  it('tags a shell server as exec', () => {
    const s = server({ name: 'shell', command: 'npx', args: ['mcp-server-shell'] });
    expect(hasCapability(inferCapabilities(s, manifest(s.name, [])), 'exec')).toBe(true);
  });

  it('tags a token in env as a secret with provenance', () => {
    const s = server({ name: 'github', env: { GITHUB_TOKEN: 'ghp_' + 'a'.repeat(36) } });
    const caps = inferCapabilities(s, manifest(s.name, []));
    expect(hasCapability(caps, 'data.secrets')).toBe(true);
    const ev = caps.evidence.find((e) => e.capability === 'data.secrets');
    expect(ev?.via).toBe('env');
    expect(ev?.detail).toBe('GITHUB_TOKEN');
  });

  it('tags a private-data-store server from its name', () => {
    const s = server({ name: 'notion', args: ['-y', '@notionhq/notion-mcp-server'] });
    expect(hasCapability(inferCapabilities(s, manifest(s.name, [])), 'data.private')).toBe(true);
  });

  it('tags a web/search server as untrusted content and egress', () => {
    const s = server({ name: 'brave-search', args: ['-y', '@brave/brave-search-mcp-server'] });
    const caps = inferCapabilities(s, manifest(s.name, []));
    expect(hasCapability(caps, 'content.untrusted')).toBe(true);
    expect(hasCapability(caps, 'sink.egress')).toBe(true);
  });
});

describe('capability inference — manifest tools', () => {
  it('infers fetch tools as untrusted content + egress', () => {
    const s = server({ name: 'x' });
    const m = manifest('x', [tool('fetch', 'Fetch a URL and return its contents.')]);
    const caps = inferCapabilities(s, m);
    expect(hasCapability(caps, 'content.untrusted')).toBe(true);
    expect(hasCapability(caps, 'sink.egress')).toBe(true);
  });

  it('infers a send_email tool as a messaging exfil channel', () => {
    const s = server({ name: 'x' });
    const caps = inferCapabilities(s, manifest('x', [tool('send_email', 'Send an email.')]));
    expect(hasCapability(caps, 'sink.messaging')).toBe(true);
  });

  it('respects the open-world annotation', () => {
    const s = server({ name: 'x' });
    const m = manifest('x', [tool('act', 'Do a thing.', { annotations: { openWorldHint: true } })]);
    const caps = inferCapabilities(s, m);
    expect(hasCapability(caps, 'content.untrusted')).toBe(true);
    expect(hasCapability(caps, 'sink.egress')).toBe(true);
  });

  it('leaves a benign local-only tool without dangerous capabilities', () => {
    const s = server({ name: 'calc' });
    const caps = inferCapabilities(s, manifest('calc', [tool('add', 'Add two numbers.')]));
    expect(caps.capabilities.size).toBe(0);
  });
});

describe('capability inference — findings reinforcement', () => {
  it('derives exec from a command-injection finding and secrets from a plaintext-secret finding', () => {
    const s = server({ name: 'x' });
    const findings: Finding[] = [
      { ruleId: 'MCP-S003', server: 'x', message: '', evidence: '', rationale: '', remediation: '' },
      { ruleId: 'MCP-C003', server: 'x', message: '', evidence: '', rationale: '', remediation: '' },
    ];
    const caps = inferCapabilities(s, manifest('x', []), findings);
    expect(hasCapability(caps, 'exec')).toBe(true);
    expect(hasCapability(caps, 'data.secrets')).toBe(true);
    expect(caps.evidence.some((e) => e.via === 'finding' && e.detail === 'MCP-S003')).toBe(true);
  });
});
