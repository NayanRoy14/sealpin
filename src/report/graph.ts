import { basename } from 'node:path';
import type { ScanContext, Finding } from '../types/rule.js';
import { inferCapabilities } from '../capabilities/infer.js';
import { CAPABILITY_LEG, type Capability, type CapabilitySet, type TrifectaLeg } from '../capabilities/types.js';

const SHORT: Record<Capability, string> = {
  'data.secrets': 'secrets',
  'data.filesystem': 'fs',
  'data.private': 'private',
  'content.untrusted': 'untrusted',
  'sink.egress': 'egress',
  'sink.messaging': 'messaging',
  'sink.filesystem': 'writes',
  exec: 'exec',
};

function role(set: CapabilitySet): 'untrusted' | 'exec' | 'exfil' | 'private' | 'benign' {
  const c = set.capabilities;
  if (c.has('content.untrusted')) return 'untrusted';
  if (c.has('exec')) return 'exec';
  if ([...c].some((x) => CAPABILITY_LEG[x] === 'exfil')) return 'exfil';
  if ([...c].some((x) => CAPABILITY_LEG[x] === 'private-data')) return 'private';
  return 'benign';
}

function withLeg(caps: CapabilitySet[], leg: TrifectaLeg): CapabilitySet[] {
  return caps.filter((c) => [...c.capabilities].some((x) => CAPABILITY_LEG[x] === leg));
}

function esc(s: string): string {
  return s.replace(/"/g, "'").replace(/`/g, '');
}

/**
 * Renders the scanned servers as a mermaid attack-graph: servers are nodes
 * coloured by role, grouped by the config context they share, with the
 * dangerous composition paths (lethal trifecta, untrusted→exec) drawn as
 * highlighted edges. Output is a fenced ```mermaid block that renders on
 * GitHub, in markdown viewers, and in artifacts.
 */
export function renderCapabilityGraph(contexts: ScanContext[], findings: Finding[] = []): string {
  if (contexts.length === 0) return '```mermaid\nflowchart LR\n  empty["no servers discovered"]\n```';

  const byContext = new Map<string, ScanContext[]>();
  for (const ctx of contexts) {
    const key = ctx.server.configPath;
    const list = byContext.get(key);
    if (list) list.push(ctx);
    else byContext.set(key, [ctx]);
  }

  const lines: string[] = ['```mermaid', 'flowchart LR'];
  const id = new Map<CapabilitySet, string>();
  let n = 0;
  let ctxIdx = 0;

  for (const [configPath, group] of byContext) {
    const caps = group.map((ctx) =>
      inferCapabilities(ctx.server, ctx.manifest, findings.filter((f) => f.server === ctx.server.name)),
    );
    lines.push(`  subgraph ctx${ctxIdx}["${esc(basename(configPath))}"]`);
    for (const set of caps) {
      const nodeId = `n${n++}`;
      id.set(set, nodeId);
      const tags = [...set.capabilities].map((c) => SHORT[c]).join(' · ') || 'no notable capabilities';
      lines.push(`    ${nodeId}["${esc(set.server)}<br/>${tags}"]:::${role(set)}`);
    }
    lines.push('  end');

    const priv = withLeg(caps, 'private-data');
    const untrusted = withLeg(caps, 'untrusted-content');
    const exfil = withLeg(caps, 'exfil');
    const execS = caps.filter((c) => c.capabilities.has('exec'));

    if (priv.length && untrusted.length && exfil.length) {
      lines.push(`  ${id.get(untrusted[0]!)} -. "1 · injection" .-> ${id.get(priv[0]!)}`);
      lines.push(`  ${id.get(priv[0]!)} == "2 · exfiltrate" ==> ${id.get(exfil[0]!)}`);
    }
    if (untrusted.length && execS.length) {
      lines.push(`  ${id.get(untrusted[0]!)} == "injection → RCE" ==> ${id.get(execS[0]!)}`);
    }
    ctxIdx++;
  }

  lines.push('  classDef untrusted fill:#7c2d12,stroke:#f97316,color:#fff');
  lines.push('  classDef private fill:#7f1d1d,stroke:#ef4444,color:#fff');
  lines.push('  classDef exfil fill:#4c1d95,stroke:#a855f7,color:#fff');
  lines.push('  classDef exec fill:#450a0a,stroke:#dc2626,color:#fff');
  lines.push('  classDef benign fill:#1f2937,stroke:#4b5563,color:#e5e7eb');
  lines.push('```');
  return lines.join('\n');
}
