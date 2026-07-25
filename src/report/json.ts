import type { Finding } from '../types/rule.js';
import { severityOf } from '../rules/index.js';
import type { ReportSummary } from './text.js';

export function renderJson(summary: ReportSummary): string {
  return JSON.stringify(
    {
      tool: 'sealpin',
      version: 1,
      serversScanned: summary.serversScanned,
      serversWithManifest: summary.serversWithManifest,
      findings: summary.findings.map((f: Finding) => ({
        ruleId: f.ruleId,
        severity: severityOf(f.ruleId),
        server: f.server,
        location: f.location ?? null,
        message: f.message,
        evidence: f.evidence,
        rationale: f.rationale,
        remediation: f.remediation,
      })),
    },
    null,
    2,
  );
}
