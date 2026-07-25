import type { Finding, ScanContext, Severity } from '../types/rule.js';
import { severityOf } from '../rules/index.js';
import { color } from './color.js';

const SEVERITY_STYLE: Record<Severity, (s: string) => string> = {
  critical: (s) => color.bold(color.red(s)),
  high: (s) => color.red(s),
  medium: (s) => color.yellow(s),
  low: (s) => color.blue(s),
  info: (s) => color.gray(s),
};

function badge(sev: Severity): string {
  return SEVERITY_STYLE[sev](sev.toUpperCase().padEnd(8));
}

export interface ReportSummary {
  serversScanned: number;
  serversWithManifest: number;
  findings: Finding[];
  /** The scan contexts, for the capability graph (--graph). Ignored by text/JSON/SARIF. */
  contexts?: ScanContext[];
}

export function renderText(summary: ReportSummary): string {
  const { findings } = summary;
  const lines: string[] = [];

  lines.push(color.bold('sealpin scan'));
  lines.push(
    color.dim(
      `${summary.serversScanned} server(s) scanned · ${summary.serversWithManifest} with tool manifest · ${findings.length} finding(s)`,
    ),
  );
  lines.push('');

  if (findings.length === 0) {
    lines.push(color.green('✓ No findings.'));
    return lines.join('\n');
  }

  for (const f of findings) {
    const sev = severityOf(f.ruleId);
    const loc = f.location?.tool
      ? color.cyan(`${f.server} › ${f.location.tool}`)
      : color.cyan(f.server);
    lines.push(`${badge(sev)} ${color.bold(f.ruleId)}  ${loc}`);
    lines.push(`  ${f.message}`);
    lines.push(`  ${color.gray('evidence:')}    ${f.evidence}`);
    lines.push(`  ${color.gray('why:')}         ${f.rationale}`);
    lines.push(`  ${color.gray('remediation:')} ${f.remediation}`);
    lines.push('');
  }

  lines.push(renderCounts(findings));
  return lines.join('\n');
}

function renderCounts(findings: Finding[]): string {
  const counts = new Map<Severity, number>();
  for (const f of findings) {
    const sev = severityOf(f.ruleId);
    counts.set(sev, (counts.get(sev) ?? 0) + 1);
  }
  const parts: string[] = [];
  for (const sev of ['critical', 'high', 'medium', 'low', 'info'] as Severity[]) {
    const n = counts.get(sev);
    if (n) parts.push(SEVERITY_STYLE[sev](`${n} ${sev}`));
  }
  return color.bold('Summary: ') + parts.join(color.gray(' · '));
}
