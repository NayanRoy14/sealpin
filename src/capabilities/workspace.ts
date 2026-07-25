import type { ScanContext, Finding, Severity, Confidence, RuleCategory } from '../types/rule.js';
import { makeFinding, snippet } from '../rules/util.js';
import { inferCapabilities } from './infer.js';
import { CAPABILITY_LEG, type Capability, type CapabilitySet, type TrifectaLeg } from './types.js';

export interface WorkspaceRuleMeta {
  id: string;
  severity: Severity;
  confidence: Confidence;
  category: RuleCategory;
  title: string;
  attack: string;
  summary: string;
}

/** Composition-level rules. Not per-server; emitted by analyzeWorkspace. */
export const WORKSPACE_RULES: readonly WorkspaceRuleMeta[] = [
  {
    id: 'MCP-X001',
    severity: 'high',
    confidence: 'possible',
    category: 'capability',
    title: 'Lethal-trifecta exposure',
    attack: 'A1/A6 composition',
    summary:
      'Servers loaded in the same agent context together provide all three legs of the lethal trifecta — access to private data, exposure to untrusted content, and an outbound channel — so a prompt injection in the untrusted content could read private data and exfiltrate it.',
  },
  {
    id: 'MCP-X002',
    severity: 'critical',
    confidence: 'possible',
    category: 'capability',
    title: 'Untrusted content reaches command execution',
    attack: 'A7 composition',
    summary:
      'An untrusted-content server and a command-execution capability share one agent context, so a prompt injection in the untrusted content could drive arbitrary code execution.',
  },
  {
    id: 'MCP-X003',
    severity: 'high',
    confidence: 'possible',
    category: 'capability',
    title: 'Confused deputy (untrusted content + stored credential)',
    attack: 'A9 Confused deputy',
    summary:
      'A single server both ingests untrusted content and holds a stored credential, so injected content could drive actions that spend that credential.',
  },
];

function serversWithLeg(caps: CapabilitySet[], leg: TrifectaLeg): CapabilitySet[] {
  return caps.filter((c) => [...c.capabilities].some((cap) => CAPABILITY_LEG[cap] === leg));
}

function firstLegCap(set: CapabilitySet, leg: TrifectaLeg): { capability: Capability; reason: string } {
  for (const cap of set.capabilities) {
    if (CAPABILITY_LEG[cap] === leg) {
      const ev = set.evidence.find((e) => e.capability === cap);
      return { capability: cap, reason: ev?.reason ?? cap };
    }
  }
  return { capability: 'exec', reason: '' }; // unreachable given callers check the leg exists
}

/**
 * Cross-server (composition-level) analysis. Servers sharing a config file are
 * loaded into one model context and therefore compose; this looks for dangerous
 * capability combinations across each such context.
 */
export function analyzeWorkspace(contexts: ScanContext[], findings: Finding[] = []): Finding[] {
  const byContext = new Map<string, ScanContext[]>();
  for (const ctx of contexts) {
    const key = ctx.server.configPath;
    const list = byContext.get(key);
    if (list) list.push(ctx);
    else byContext.set(key, [ctx]);
  }

  const out: Finding[] = [];
  for (const [configPath, group] of byContext) {
    const caps = group.map((ctx) =>
      inferCapabilities(ctx.server, ctx.manifest, findings.filter((f) => f.server === ctx.server.name)),
    );
    out.push(...detectTrifecta(configPath, caps));
    out.push(...detectUntrustedExec(configPath, caps));
    out.push(...detectConfusedDeputy(configPath, caps));
  }
  return out;
}

function detectTrifecta(configPath: string, caps: CapabilitySet[]): Finding[] {
  const priv = serversWithLeg(caps, 'private-data');
  const untrusted = serversWithLeg(caps, 'untrusted-content');
  const exfil = serversWithLeg(caps, 'exfil');
  if (priv.length === 0 || untrusted.length === 0 || exfil.length === 0) return [];

  const u = untrusted[0]!;
  const p = priv[0]!;
  const e = exfil[0]!;
  const pCap = firstLegCap(p, 'private-data');
  const eCap = firstLegCap(e, 'exfil');

  return [
    makeFinding('MCP-X001', u.server, {
      location: { file: configPath },
      message:
        `Lethal-trifecta exposure in this context: "${u.server}" ingests untrusted external content, ` +
        `"${p.server}" can access private data (${pCap.capability}), and "${e.server}" can send data outbound (${eCap.capability}). ` +
        `A prompt injection in the untrusted content could read the private data and exfiltrate it.`,
      evidence: snippet(`untrusted: ${u.server} · private: ${p.server} (${pCap.reason}) · exfil: ${e.server} (${eCap.reason})`),
      rationale:
        'The "lethal trifecta" — private-data access, exposure to untrusted content, and an outbound channel in one agent context — is the canonical way an agent is hijacked: attacker text hidden in the untrusted content instructs the model to read secrets and send them out. Each server may be individually reasonable; the danger is the combination.',
      remediation:
        'Do not co-load untrusted-content, private-data, and exfiltration-capable servers in one agent context. Split them across separate agents/sessions, or remove the outbound/untrusted capability that is not needed.',
    }),
  ];
}

function detectUntrustedExec(configPath: string, caps: CapabilitySet[]): Finding[] {
  const untrusted = serversWithLeg(caps, 'untrusted-content');
  const execServers = caps.filter((c) => c.capabilities.has('exec'));
  if (untrusted.length === 0 || execServers.length === 0) return [];

  const u = untrusted[0]!;
  const x = execServers[0]!;
  return [
    makeFinding('MCP-X002', u.server, {
      location: { file: configPath },
      message:
        `"${u.server}" ingests untrusted external content and "${x.server}" can execute commands, in the same agent context. ` +
        `A prompt injection in the untrusted content could achieve remote code execution.`,
      evidence: snippet(`untrusted: ${u.server} · exec: ${x.server}`),
      rationale:
        'Untrusted content flowing into a context that also has command execution is a direct path from prompt injection to remote code execution on the host.',
      remediation:
        'Never co-load an untrusted-content server with a command-execution server. If execution is required, gate it behind an allowlist and isolate it from untrusted input.',
    }),
  ];
}

function detectConfusedDeputy(configPath: string, caps: CapabilitySet[]): Finding[] {
  const out: Finding[] = [];
  for (const c of caps) {
    if (c.capabilities.has('data.secrets') && c.capabilities.has('content.untrusted')) {
      const credEv = c.evidence.find((e) => e.capability === 'data.secrets');
      out.push(
        makeFinding('MCP-X003', c.server, {
          location: { file: configPath },
          message: `"${c.server}" both ingests untrusted content and holds a stored credential; injected content could drive actions that spend the credential (confused deputy).`,
          evidence: snippet(`untrusted content + credential (${credEv?.reason ?? 'stored secret'})`),
          rationale:
            'A confused deputy holds a privileged credential that any of its tools can spend. When the same server also ingests untrusted content, that content can steer which privileged action runs — using the credential on the attacker\'s behalf.',
          remediation: 'Separate untrusted-content intake from credential-bearing tools, and scope the credential to the minimum each tool needs.',
        }),
      );
    }
  }
  return out;
}
