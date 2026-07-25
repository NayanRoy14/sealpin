import { describe, expect, it } from 'vitest';
import { renderCapabilityGraph, renderSarif } from '../src/report/index.js';
import { analyzeWorkspace } from '../src/capabilities/index.js';
import type { ScanContext } from '../src/types/rule.js';
import { manifest, server, tool } from './helpers.js';

const CFG = 'claude_desktop_config.json';
function ctx(name: string, tools: ReturnType<typeof tool>[], cfg: Partial<Parameters<typeof server>[0]> = {}): ScanContext {
  const s = server({ name, configPath: CFG, ...cfg });
  const m = manifest(name, tools);
  return { server: s, manifest: m, workspace: [m] };
}

const trifectaContexts = (): ScanContext[] => [
  ctx('web-search', [tool('fetch', 'Fetch a URL and return contents.')]),
  ctx('filesystem', [], { command: 'npx', args: ['-y', '@modelcontextprotocol/server-filesystem', '/'] }),
];

describe('renderCapabilityGraph', () => {
  it('emits a mermaid flowchart with server nodes and role classes', () => {
    const g = renderCapabilityGraph(trifectaContexts());
    expect(g).toContain('```mermaid');
    expect(g).toContain('flowchart LR');
    expect(g).toContain('web-search');
    expect(g).toContain('filesystem');
    expect(g).toContain(':::untrusted');
    expect(g).toContain('classDef untrusted');
  });

  it('draws the trifecta attack path as highlighted edges', () => {
    const g = renderCapabilityGraph(trifectaContexts());
    expect(g).toContain('injection'); // untrusted -> private edge label
    expect(g).toContain('exfiltrate'); // private -> exfil edge label
  });

  it('draws the untrusted → RCE edge when a shell server is present', () => {
    const contexts = [ctx('web', [tool('fetch', 'Fetch a URL.')]), ctx('shell', [], { command: 'npx', args: ['mcp-server-shell'] })];
    expect(renderCapabilityGraph(contexts)).toContain('RCE');
  });

  it('handles an empty workspace', () => {
    expect(renderCapabilityGraph([])).toContain('no servers discovered');
  });
});

describe('SARIF related-locations for cross-server findings', () => {
  it('emits relatedLocations naming each contributing server', () => {
    const findings = analyzeWorkspace(trifectaContexts());
    const x1 = findings.find((f) => f.ruleId === 'MCP-X001')!;
    expect(x1.related?.length).toBeGreaterThanOrEqual(3);

    const sarif = JSON.parse(renderSarif({ serversScanned: 2, serversWithManifest: 0, findings: [x1] }));
    const result = sarif.runs[0].results[0];
    expect(result.relatedLocations.length).toBeGreaterThanOrEqual(3);
    const names = result.relatedLocations.flatMap((l: { logicalLocations: { name: string }[] }) => l.logicalLocations.map((x) => x.name));
    expect(names).toContain('web-search');
    expect(names).toContain('filesystem');
  });
});
